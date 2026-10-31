//! Forwarding rooms end to end on the UDP-loopback datapath: phones are `UdpSocket`s, the engine
//! answers their offers, and the chosen source's RTP comes out of every other seat unchanged on that
//! seat's own stream.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_srtp::leg::SecureLeg;

const ROOM: &str = "group-1";
/// How long a phone waits for a packet that should arrive.
const SHORT: Duration = Duration::from_secs(2);
/// How long a phone waits to be sure a packet does not arrive.
const NEGATIVE: Duration = Duration::from_millis(250);

fn engine_with_dispatcher() -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine
}

/// An AMR-WB offer for a phone at `rtp`, on payload type `payload_type`.
fn amr_wb_sdp(rtp: SocketAddr, payload_type: u8, fmtp: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {payload_type}\r\na=rtpmap:{payload_type} AMR-WB/16000\r\n\
         a=fmtp:{payload_type} {fmtp}\r\na=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port()
    )
}

async fn join_with(engine: &Engine<UdpLoopbackDatapath>, tag: &str, sdp: String) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

/// A phone seated in the room on AMR-WB octet-aligned `payload_type`; returns it with the engine
/// port it talks to.
async fn seat(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    payload_type: u8,
) -> (UdpSocket, SocketAddr) {
    let (socket, addr) = phone().await;
    let answer = join_with(engine, tag, amr_wb_sdp(addr, payload_type, "octet-align=1")).await;
    let engine_port = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer")
        .remote_rtp;
    (socket, engine_port)
}

async fn set_source(engine: &Engine<UdpLoopbackDatapath>, tag: Option<&str>) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardSetSource {
                conference_id: ROOM.into(),
                from_tag: tag.map(str::to_string),
            },
        )
        .await
}

fn media(payload_type: u8, sequence: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let header = RtpHeader {
        marker: false,
        payload_type,
        sequence,
        timestamp,
        ssrc,
    };
    let mut buffer = vec![0u8; 12 + payload.len()];
    write_packet(&header, payload, &mut buffer).expect("write");
    buffer
}

/// One RTP datagram off `phone`, or `None` when none arrives in `window`. RTCP is skipped.
async fn recv_rtp(phone: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, phone.recv_from(&mut buffer)).await
    {
        if length >= 2 && !(64..=95).contains(&(buffer[1] & 0x7f)) {
            return Some(buffer[..length].to_vec());
        }
    }
    None
}

struct Heard {
    marker: bool,
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    payload: Vec<u8>,
}

async fn hear(phone: &UdpSocket) -> Heard {
    let datagram = recv_rtp(phone, SHORT).await.expect("a forwarded packet");
    let packet = RtpPacket::parse(&datagram).expect("rtp");
    Heard {
        marker: packet.marker,
        payload_type: packet.payload_type,
        sequence: packet.sequence,
        timestamp: packet.timestamp,
        ssrc: packet.ssrc,
        payload: packet.payload.to_vec(),
    }
}

fn started_events(events: &flume::Receiver<Event>) -> Vec<String> {
    events
        .try_iter()
        .filter_map(|event| match event {
            Event::ForwardSourceStarted {
                conference_id,
                from_tag,
            } => {
                assert_eq!(conference_id, ROOM);
                Some(from_tag)
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn the_source_reaches_every_other_seat_byte_identical_and_never_itself() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    let (phone_b, _) = seat(&engine, "b", 111).await;
    let (phone_c, _) = seat(&engine, "c", 96).await;
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());

    let payload = [0xF1, 0x23, 0x45, 0x67, 0x89, 0xAB];
    for index in 0..3u16 {
        phone_a
            .send_to(
                &media(
                    96,
                    500 + index,
                    16_000 + u32::from(index) * 320,
                    0xA0A0_A0A0,
                    &payload,
                ),
                port_a,
            )
            .await
            .expect("send");
    }
    let mut ssrcs = Vec::new();
    for (phone, expected_payload_type) in [(&phone_b, 111u8), (&phone_c, 96u8)] {
        let mut previous: Option<Heard> = None;
        for _ in 0..3 {
            let heard = hear(phone).await;
            assert_eq!(heard.payload, payload, "the payload is forwarded unchanged");
            assert_eq!(
                heard.payload_type, expected_payload_type,
                "the receiver's own payload type"
            );
            assert_ne!(heard.ssrc, 0xA0A0_A0A0, "the source's SSRC never leaks");
            if let Some(previous) = previous {
                assert_eq!(heard.ssrc, previous.ssrc, "one stable SSRC per receiver");
                assert_eq!(heard.sequence, previous.sequence.wrapping_add(1));
                assert_eq!(heard.timestamp.wrapping_sub(previous.timestamp), 320);
                assert!(!heard.marker);
            } else {
                assert!(heard.marker, "a talk spurt starts with the marker");
            }
            previous = Some(heard);
        }
        ssrcs.push(previous.expect("heard").ssrc);
    }
    assert_ne!(ssrcs[0], ssrcs[1], "each receiver has its own stream");
    assert!(
        recv_rtp(&phone_a, NEGATIVE).await.is_none(),
        "the source never hears itself"
    );
    assert_eq!(started_events(&events), vec!["a".to_string()]);
}

#[tokio::test]
async fn a_source_change_keeps_each_receivers_stream_continuous() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    let (phone_b, port_b) = seat(&engine, "b", 96).await;
    let (phone_c, _) = seat(&engine, "c", 96).await;

    // a talks, then b, then a again; each talker keeps its own sequence line and SSRC.
    let mut next_a = 100u16;
    let mut next_b = 9000u16;
    let mut heard_c: Vec<Heard> = Vec::new();
    let mut heard_a: Vec<Heard> = Vec::new();
    let mut heard_b: Vec<Heard> = Vec::new();
    for (talker, ssrc) in [
        ("a", 0xA0A0_A0A0u32),
        ("b", 0xB0B0_B0B0),
        ("a", 0xA0A0_A0A0),
    ] {
        assert_eq!(set_source(&engine, Some(talker)).await, ok_empty());
        for _ in 0..3 {
            let (phone, port, next) = if talker == "a" {
                (&phone_a, port_a, &mut next_a)
            } else {
                (&phone_b, port_b, &mut next_b)
            };
            phone
                .send_to(
                    &media(96, *next, u32::from(*next) * 320, ssrc, &[*next as u8]),
                    port,
                )
                .await
                .expect("send");
            *next += 1;
            heard_c.push(hear(&phone_c).await);
            if talker == "a" {
                heard_b.push(hear(&phone_b).await);
            } else {
                heard_a.push(hear(&phone_a).await);
            }
        }
    }
    for stream in [&heard_c, &heard_a, &heard_b] {
        for (index, heard) in stream.iter().enumerate() {
            if index > 0 {
                let previous = &stream[index - 1];
                assert_eq!(heard.ssrc, previous.ssrc, "one SSRC for the whole call");
                assert_eq!(heard.sequence, previous.sequence.wrapping_add(1));
                assert!((heard.timestamp.wrapping_sub(previous.timestamp) as i32) > 0);
            }
        }
    }
    // c heard three runs: the marker is on the first packet of each and only there.
    let c_markers: Vec<bool> = heard_c.iter().map(|heard| heard.marker).collect();
    assert_eq!(
        c_markers,
        [true, false, false, true, false, false, true, false, false]
    );
    // a and b each heard the runs they were not part of.
    assert_eq!(
        heard_a.iter().map(|heard| heard.marker).collect::<Vec<_>>(),
        [true, false, false]
    );
    assert_eq!(
        heard_b.iter().map(|heard| heard.marker).collect::<Vec<_>>(),
        [true, false, false, true, false, false]
    );
    assert_eq!(
        started_events(&events),
        vec!["a".to_string(), "b".to_string(), "a".to_string()],
        "exactly one source-started event per change"
    );
}

#[tokio::test]
async fn packets_from_a_seat_that_is_not_the_source_are_dropped() {
    let engine = engine_with_dispatcher();
    let (phone_a, _) = seat(&engine, "a", 96).await;
    let (phone_b, port_b) = seat(&engine, "b", 96).await;
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());
    phone_b
        .send_to(&media(96, 1, 0, 0xB0B0_B0B0, &[1, 2, 3]), port_b)
        .await
        .expect("send");
    assert!(recv_rtp(&phone_a, NEGATIVE).await.is_none());
    let tag = engine
        .conference()
        .forward()
        .seat_endpoint(ROOM, "b")
        .expect("seated");
    let stats = engine.datapath().stats(tag).expect("stats");
    assert_eq!(
        stats.packets_dropped, 1,
        "counted, and visible in the stats"
    );
}

#[tokio::test]
async fn no_source_means_nothing_is_forwarded_until_one_is_chosen() {
    let engine = engine_with_dispatcher();
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    let (phone_b, _) = seat(&engine, "b", 96).await;
    phone_a
        .send_to(&media(96, 1, 0, 0xA0A0_A0A0, &[1]), port_a)
        .await
        .expect("send");
    assert!(recv_rtp(&phone_b, NEGATIVE).await.is_none());
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());
    phone_a
        .send_to(&media(96, 2, 320, 0xA0A0_A0A0, &[2]), port_a)
        .await
        .expect("send");
    assert_eq!(hear(&phone_b).await.payload, [2]);
    assert_eq!(set_source(&engine, None).await, ok_empty());
    phone_a
        .send_to(&media(96, 3, 640, 0xA0A0_A0A0, &[3]), port_a)
        .await
        .expect("send");
    assert!(recv_rtp(&phone_b, NEGATIVE).await.is_none());
}

#[tokio::test]
async fn a_source_that_leaves_stops_the_forwarding() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (phone_b, port_b) = seat(&engine, "b", 96).await;
    let (phone_c, _) = seat(&engine, "c", 96).await;
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());
    assert_eq!(
        engine
            .handle(
                CLIENT,
                Command::ForwardLeave {
                    conference_id: ROOM.into(),
                    from_tag: "a".into()
                }
            )
            .await,
        ok_empty()
    );
    // b is not the source just because a left.
    phone_b
        .send_to(&media(96, 1, 0, 0xB0B0_B0B0, &[1]), port_b)
        .await
        .expect("send");
    assert!(recv_rtp(&phone_c, NEGATIVE).await.is_none());
    assert_eq!(set_source(&engine, Some("b")).await, ok_empty());
    phone_b
        .send_to(&media(96, 2, 320, 0xB0B0_B0B0, &[2]), port_b)
        .await
        .expect("send");
    assert_eq!(hear(&phone_c).await.payload, [2]);
}

#[tokio::test]
async fn the_last_leave_ends_the_room_and_frees_its_endpoints() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_phone_b, _) = seat(&engine, "b", 96).await;
    let endpoint = engine
        .conference()
        .forward()
        .seat_endpoint(ROOM, "a")
        .expect("seated");
    assert_eq!(engine.conference().forward().room_count(), 1);
    for tag in ["a", "b"] {
        let result = engine
            .handle(
                CLIENT,
                Command::ForwardLeave {
                    conference_id: ROOM.into(),
                    from_tag: tag.into(),
                },
            )
            .await;
        assert_eq!(result, ok_empty());
    }
    assert_eq!(engine.conference().forward().room_count(), 0);
    assert!(!engine.conference().forward().owns(endpoint));
    assert!(
        engine.datapath().stats(endpoint).is_none(),
        "endpoint freed"
    );
    assert!(engine.endpoint_calls.is_empty());
    let again = engine
        .handle(
            CLIENT,
            Command::ForwardLeave {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
            },
        )
        .await;
    assert_eq!(
        again,
        CmdResult::Error {
            reason: "forward_leave: no such forwarding room seat".into()
        }
    );
}

#[tokio::test]
async fn an_unknown_source_tag_and_an_unknown_room_are_refused() {
    let engine = engine_with_dispatcher();
    assert_eq!(
        set_source(&engine, Some("a")).await,
        CmdResult::Error {
            reason: format!("forward_set_source: unknown forwarding room: {ROOM}")
        }
    );
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    assert_eq!(
        set_source(&engine, Some("ghost")).await,
        CmdResult::Error {
            reason: "forward_set_source: no seat ghost in this room".into()
        }
    );
}

#[tokio::test]
async fn a_forwarding_room_takes_no_scope() {
    let engine = engine_with_dispatcher();
    let result = engine
        .handle_scoped(
            CLIENT,
            Some("tenant-a"),
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp: amr_wb_sdp("127.0.0.1:4000".parse().expect("addr"), 96, "octet-align=1"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Error { .. }), "{result:?}");
    assert_eq!(engine.conference().forward().room_count(), 0);
}

#[tokio::test]
async fn a_draining_node_admits_no_new_forwarding_seat() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    assert_eq!(engine.handle(CLIENT, Command::Drain).await, ok_empty());
    let (_, addr) = phone().await;
    let result = join_with(&engine, "b", amr_wb_sdp(addr, 96, "octet-align=1")).await;
    assert_eq!(
        result,
        CmdResult::Error {
            reason: "node is draining; not accepting new sessions".into()
        }
    );
    // A seat already in the room still works.
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());
}

#[tokio::test]
async fn a_seat_in_a_codec_nobody_can_transcode_is_refused_and_leaves_nothing_allocated() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_, addr) = phone().await;
    // A codec the engine has neither a decoder nor an encoder for can be neither forwarded to the
    // room's seats nor transcoded.
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 77\r\na=rtpmap:77 speex/8000\r\na=rtcp-mux\r\n",
        ip = addr.ip(),
        port = addr.port()
    );
    let result = join_with(&engine, "b", offer).await;
    let CmdResult::Error { reason } = result else {
        panic!("expected a refusal");
    };
    assert!(
        reason.contains("the room carries AMR-WB/16000 (octet-aligned)"),
        "{reason}"
    );
    assert!(reason.contains("cannot be transcoded"), "{reason}");
    assert!(reason.contains("SPEEX/8000 payload type 77"), "{reason}");
    assert_eq!(engine.conference().forward().seat_count(), 1);
    assert_eq!(
        engine.endpoint_calls.len(),
        1,
        "the refused seat holds nothing"
    );
}

#[tokio::test]
async fn a_codec_this_build_cannot_transcode_still_forwards() {
    // AMR-WB needs the `amr` feature to encode or decode; the room needs neither.
    let engine = engine_with_dispatcher();
    let (_, addr) = phone().await;
    let answer = join_with(&engine, "a", amr_wb_sdp(addr, 96, "octet-align=1")).await;
    let text = ok_sdp_text(&answer);
    assert!(text.contains("a=rtpmap:96 AMR-WB/16000"), "{text}");
    assert!(text.contains("octet-align=1"), "{text}");
}

#[tokio::test]
async fn a_forwarding_room_and_a_mixing_conference_do_not_share_an_id() {
    let engine = engine_with_dispatcher();
    let (_phone_a, _) = seat(&engine, "a", 96).await;
    let (_, addr) = phone().await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: ROOM.into(),
                from_tag: "m".into(),
                sdp: sdp_for(addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert_eq!(
        joined,
        CmdResult::Error {
            reason: format!("conference_join: {ROOM} is a forwarding room; use forward_join")
        }
    );
    let (_, addr) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "mix".into(),
                from_tag: "m".into(),
                sdp: sdp_for(addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: "mix".into(),
                from_tag: "a".into(),
                sdp: amr_wb_sdp(addr, 96, "octet-align=1"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert_eq!(
        result,
        CmdResult::Error {
            reason: "forward_join: mix is a mixing conference; use conference_join".into()
        }
    );
}

#[tokio::test]
async fn node_info_advertises_the_forwarding_room() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(node.features.iter().any(|name| name == "forward_room"));
}

#[tokio::test]
async fn a_quiet_seat_is_reported_once_and_never_freed() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    let (_phone_b, _) = seat(&engine, "b", 96).await;
    // Both are quiet for 40 ticks of the logical clock, past a 30-tick media timeout.
    engine.datapath().advance_clock(40);
    assert_eq!(engine.scan_inactive_forward_seats(30), 2);
    let mut reported: Vec<String> = events
        .try_iter()
        .filter_map(|event| match event {
            Event::ForwardSeatInactive {
                conference_id,
                from_tag,
            } => {
                assert_eq!(conference_id, ROOM);
                Some(from_tag)
            }
            _ => None,
        })
        .collect();
    reported.sort();
    assert_eq!(reported, ["a", "b"]);
    assert_eq!(engine.scan_inactive_forward_seats(30), 0, "raised once");
    assert_eq!(engine.conference().forward().seat_count(), 2, "never freed");
    // a is heard from again (RTCP counts as much as RTP), so it is armed again; b is still quiet.
    let mut report = [0u8; 28];
    let length =
        siphon_rtp_media::rtcp::write_sender_report(0xA0A0_A0A0, 0, 0, 0, 0, &[], &mut report)
            .expect("sr");
    phone_a
        .send_to(&report[..length], port_a)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.datapath().advance_clock(40);
    assert_eq!(engine.scan_inactive_forward_seats(30), 1, "only a re-armed");
}

/// A secure phone: an SDES-SRTP offer, and the SRTP state to talk to the engine with.
async fn secure_seat(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    key_line: &str,
) -> (UdpSocket, SocketAddr, SecureLeg) {
    let (socket, addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n\
         a=rtcp-mux\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key_line}\r\n",
        ip = addr.ip(),
        port = addr.port()
    );
    let phone_key = sdp::parse(&offer).expect("offer").crypto[0].key;
    let answer = sdp::parse(&ok_sdp_text(&join_with(engine, tag, offer).await)).expect("answer");
    let engine_key = answer.crypto[0].key;
    (
        socket,
        answer.remote_rtp,
        SecureLeg::new(&phone_key, &engine_key),
    )
}

#[tokio::test]
async fn secure_seats_are_decrypted_on_ingress_and_encrypted_per_receiver() {
    let engine = engine_with_dispatcher();
    let (phone_a, port_a, mut leg_a) =
        secure_seat(&engine, "a", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd").await;
    let (phone_b, _, mut leg_b) =
        secure_seat(&engine, "b", "HRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA").await;
    let (phone_c, _) = seat(&engine, "c", 96).await;
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());

    let mut protected = Vec::new();
    leg_a
        .protect(&media(96, 1, 0, 0xA0A0_A0A0, &[7, 7, 7]), &mut protected)
        .expect("protect");
    phone_a.send_to(&protected, port_a).await.expect("send");

    // The plain seat gets the cleartext payload; the secure seat gets SRTP that only its key opens.
    assert_eq!(hear(&phone_c).await.payload, [7, 7, 7]);
    let datagram = recv_rtp(&phone_b, SHORT).await.expect("srtp for b");
    assert!(
        RtpPacket::parse(&datagram).map_or(true, |packet| packet.payload != [7, 7, 7]),
        "not in the clear"
    );
    let mut clear = Vec::new();
    leg_b
        .unprotect(&datagram, &mut clear)
        .expect("b's key opens it");
    assert_eq!(RtpPacket::parse(&clear).expect("rtp").payload, [7, 7, 7]);

    // A forged packet from the source's address is dropped before it is forwarded.
    phone_a
        .send_to(&media(96, 2, 320, 0xA0A0_A0A0, &[9, 9, 9]), port_a)
        .await
        .expect("send");
    assert!(recv_rtp(&phone_c, NEGATIVE).await.is_none());
}

#[tokio::test]
async fn a_nated_seat_is_gated_on_and_sent_to_its_received_from_address() {
    let engine = engine_with_dispatcher();
    // The phone signals a private address and sends from the loopback address the proxy saw.
    let (phone_n, addr_n) = phone().await;
    let offer = amr_wb_sdp(
        SocketAddr::from(([10, 0, 0, 7], addr_n.port())),
        96,
        "octet-align=1",
    );
    let answer = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "n".into(),
                sdp: offer,
                profile: ProfileFlags {
                    received_from: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    ..Default::default()
                },
            },
        )
        .await;
    let port_n = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer")
        .remote_rtp;
    let (phone_a, port_a) = seat(&engine, "a", 96).await;
    assert_eq!(set_source(&engine, Some("a")).await, ok_empty());
    phone_a
        .send_to(&media(96, 1, 0, 0xA0A0_A0A0, &[5]), port_a)
        .await
        .expect("send");
    assert_eq!(
        hear(&phone_n).await.payload,
        [5],
        "sent to the post-NAT address"
    );
    // And its own packets are admitted from that address.
    assert_eq!(set_source(&engine, Some("n")).await, ok_empty());
    phone_n
        .send_to(&media(96, 1, 0, 0xCDCD_CDCD, &[6]), port_n)
        .await
        .expect("send");
    assert_eq!(hear(&phone_a).await.payload, [6]);
}

mod dial_out;
