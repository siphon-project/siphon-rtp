//! A 500-seat forwarding room end to end on the UDP-loopback datapath: 500 phones are seated, one
//! talks for a second of 20 ms frames, and every other phone must receive every frame, byte for byte.
//!
//! This is the integration-style counterpart of `benches/forward_fanout_bench.rs`: it adds the
//! mailbox, the actor's sequential `send` per receiver and the kernel's loopback delivery to the
//! room's own fan-out cost. The elapsed time of the talk is printed with `--nocapture` and recorded in
//! `docs/cookbook/forwarding.md`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{sdp, ClientId, Engine};
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_proto::{CmdResult, Command};
use tokio::net::UdpSocket;

const CLIENT: ClientId = ClientId(1);
const ROOM: &str = "group-500";
const SEATS: usize = 500;
const FRAMES: u16 = 50;
const PAYLOAD: [u8; 62] = [0x5A; 62];

fn offer(address: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n\
         a=rtcp-mux\r\n",
        ip = address.ip(),
        port = address.port()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_hundred_seats_each_hear_every_frame_of_the_source() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine.register_client(CLIENT);

    let mut phones = Vec::with_capacity(SEATS);
    for index in 0..SEATS {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let answer = engine
            .handle(
                CLIENT,
                Command::ForwardJoin {
                    conference_id: ROOM.into(),
                    from_tag: format!("seat-{index}"),
                    sdp: offer(address),
                    profile: Default::default(),
                },
            )
            .await;
        let CmdResult::Ok {
            sdp: Some(text), ..
        } = answer
        else {
            panic!("seat {index} was refused: {answer:?}");
        };
        phones.push((socket, sdp::parse(&text).unwrap().remote_rtp));
    }
    let chosen = engine
        .handle(
            CLIENT,
            Command::ForwardSetSource {
                conference_id: ROOM.into(),
                from_tag: Some("seat-0".into()),
            },
        )
        .await;
    assert!(matches!(chosen, CmdResult::Ok { .. }));

    // Every listener counts the frames it receives; the talker must hear none.
    let mut listeners = Vec::new();
    let mut phones = phones.into_iter();
    let (talker, talker_port) = phones.next().unwrap();
    for (socket, _) in phones {
        listeners.push(tokio::spawn(async move {
            let mut received = 0u16;
            let mut buffer = [0u8; 2048];
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while received < FRAMES {
                let Ok(Ok((length, _))) =
                    tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
                else {
                    break;
                };
                if (64..=95).contains(&(buffer[1] & 0x7f)) {
                    continue; // RTCP
                }
                let packet = RtpPacket::parse(&buffer[..length]).unwrap();
                assert_eq!(packet.payload, PAYLOAD, "payload forwarded unchanged");
                received += 1;
            }
            received
        }));
    }

    let started = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    for frame in 0..FRAMES {
        ticker.tick().await;
        let header = RtpHeader {
            marker: frame == 0,
            payload_type: 96,
            sequence: frame,
            timestamp: u32::from(frame) * 320,
            ssrc: 0xA0A0_A0A0,
        };
        let mut datagram = vec![0u8; 12 + PAYLOAD.len()];
        write_packet(&header, &PAYLOAD, &mut datagram).unwrap();
        talker.send_to(&datagram, talker_port).await.unwrap();
    }
    let mut complete = 0;
    for listener in listeners {
        if listener.await.unwrap() == FRAMES {
            complete += 1;
        }
    }
    let elapsed = started.elapsed();
    eprintln!(
        "forward 500 seats: {FRAMES} frames x {} receivers in {elapsed:?} ({} datagrams)",
        SEATS - 1,
        usize::from(FRAMES) * (SEATS - 1)
    );
    assert_eq!(
        complete,
        SEATS - 1,
        "every listener received every frame of the source"
    );
    assert_eq!(engine.conference().forward().seat_count(), SEATS);
}
