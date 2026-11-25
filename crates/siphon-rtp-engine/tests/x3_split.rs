//! Lawful interception (ETSI TS 103 221-2 X3) of a split call over the real delivery path: the
//! command is accepted on a call that is split, and the Mediation Function, behind mutual TLS, is
//! given what is on each wire. While split, `to_target` is the bot's audio the target's leg is played
//! and `from_target` is the target's own voice; the other party's voice, which the target no longer
//! hears, is not delivered as audio the target heard. After the detach `to_target` is the other party
//! again. The PDU sequence counter of the one delivery connection rises by one throughout.
//!
//! The call shapes, the re-offer, the restore and the end are covered against a live engine in
//! `engine/tests/x3_split.rs`; this is the one that goes through `attach_x3`, the TLS connection and
//! the PDU framing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::x3_mdf::{acceptor, attribute, pki, SHORT};
use futures_util::{SinkExt, StreamExt};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::{Decoder, Encoder};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_li::attributes::attribute_type;
use siphon_rtp_li::inbound::InboundHeader;
use siphon_rtp_li::{PayloadDirection, HEADER_LEN};
use siphon_rtp_proto::{
    CmdResult, Command, ProfileFlags, WsSplitAttach, WsSplitDetach, X3TargetLeg, Xid,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
const A_TONE: f32 = 600.0;
const B_TONE: f32 = 1_400.0;
const TO_A_TONE: f32 = 1_000.0;
const TO_B_TONE: f32 = 2_000.0;

fn tone(frequency: f32, frame: usize, rate: f32, samples: usize) -> Vec<i16> {
    (0..samples)
        .map(|index| {
            let at = (frame * samples + index) as f32;
            ((at * frequency * std::f32::consts::TAU / rate).sin() * 8_000.0) as i16
        })
        .collect()
}

fn power(samples: &[i16], frequency: f32) -> f64 {
    let coefficient = 2.0 * (std::f32::consts::TAU * frequency / 8_000.0).cos();
    let (mut previous, mut before) = (0.0f64, 0.0f64);
    for &sample in samples {
        let next = f64::from(sample) + f64::from(coefficient) * previous - before;
        before = previous;
        previous = next;
    }
    (previous * previous + before * before - f64::from(coefficient) * previous * before)
        / (samples.len().max(1) as f64).powi(2)
}

/// The audio of RTP packets, G.711 µ-law.
fn pcm(packets: &[&Vec<u8>]) -> Vec<i16> {
    let mut decoder = G711::ulaw();
    let mut samples = Vec::new();
    let mut frame = [0i16; 1024];
    for packet in packets {
        let count = decoder.decode(&packet[12..], &mut frame).expect("decode");
        samples.extend_from_slice(&frame[..count]);
    }
    samples
}

#[track_caller]
fn assert_only(samples: &[i16], wanted: f32, who: &str) {
    assert!(samples.len() >= 1_600, "{who}: {} samples", samples.len());
    let wanted_power = power(samples, wanted);
    assert!(
        wanted_power > 1_000.0,
        "{who}: no {wanted} Hz ({wanted_power})"
    );
    for other in [A_TONE, B_TONE, TO_A_TONE, TO_B_TONE]
        .into_iter()
        .filter(|tone| *tone != wanted)
    {
        let leaked = power(samples, other);
        assert!(
            leaked * 100.0 < wanted_power,
            "{who}: {other} Hz leaked at {leaked} against {wanted_power}"
        );
    }
}

/// A bot that plays its two channels back as constant tones, one 20 ms frame per 20 ms.
async fn bot() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind bot");
    let uri = format!("ws://{}/split", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let socket = tokio_tungstenite::accept_async(stream).await.expect("ws");
        let (mut sink, mut source) = socket.split();
        let mut ticker = tokio::time::interval(Duration::from_millis(20));
        let mut sent = 0usize;
        loop {
            tokio::select! {
                incoming = source.next() => if !matches!(incoming, Some(Ok(_))) { break },
                _ = ticker.tick() => {
                    let mut bytes = Vec::with_capacity(320 * 4);
                    let left = tone(TO_A_TONE, sent, 16_000.0, 320);
                    let right = tone(TO_B_TONE, sent, 16_000.0, 320);
                    for index in 0..320 {
                        bytes.extend_from_slice(&left[index].to_le_bytes());
                        bytes.extend_from_slice(&right[index].to_le_bytes());
                    }
                    sent += 1;
                    if sink.send(Message::binary(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    uri
}

fn sdp(address: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = address.ip(),
        port = address.port(),
    )
}

fn engine_address(result: &CmdResult) -> SocketAddr {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => siphon_rtp_engine::sdp::parse(text).expect("sdp").remote_rtp,
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

/// One PDU of the delivery: direction, the connection's sequence counter and the RTP packet.
type Delivered = (u16, u32, Vec<u8>);

/// Read PDUs off the delivery connection until it closes, into `into`.
fn collect(
    mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    into: Arc<Mutex<Vec<Delivered>>>,
) {
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            while let Ok(header) = InboundHeader::parse(&buffer) {
                let total = header.total_len().expect("length");
                if buffer.len() < total {
                    break;
                }
                let attributes = buffer[HEADER_LEN..header.header_length as usize].to_vec();
                let payload = buffer[header.header_length as usize..total].to_vec();
                if let Some(sequence) = attribute(&attributes, attribute_type::SEQUENCE_NUMBER) {
                    into.lock().expect("lock").push((
                        header.payload_direction,
                        u32::from_be_bytes([sequence[0], sequence[1], sequence[2], sequence[3]]),
                        payload,
                    ));
                }
                buffer.drain(..total);
            }
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    });
}

async fn drive(
    a: &UdpSocket,
    b: &UdpSocket,
    to_a: SocketAddr,
    to_b: SocketAddr,
    frame: &mut usize,
    frames: usize,
) {
    for _ in 0..frames {
        for (socket, to, frequency, ssrc) in [
            (a, to_a, A_TONE, 0x0A0A_0A0Au32),
            (b, to_b, B_TONE, 0x0B0B_0B0Bu32),
        ] {
            let mut payload = [0u8; 160];
            G711::ulaw()
                .encode(&tone(frequency, *frame, 8_000.0, 160), &mut payload)
                .expect("encode");
            let mut packet = vec![0x80, 0x00];
            packet.extend_from_slice(&(*frame as u16).to_be_bytes());
            packet.extend_from_slice(&((*frame as u32) * 160).to_be_bytes());
            packet.extend_from_slice(&ssrc.to_be_bytes());
            packet.extend_from_slice(&payload);
            socket.send_to(&packet, to).await.expect("send");
        }
        *frame += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn split_by_direction(delivered: &[Delivered], from: usize) -> (Vec<&Vec<u8>>, Vec<&Vec<u8>>) {
    let to_target = PayloadDirection::ToTarget.to_u16();
    let from_target = PayloadDirection::FromTarget.to_u16();
    let rest = &delivered[from.min(delivered.len())..];
    (
        rest.iter()
            .filter(|(d, _, _)| *d == to_target)
            .map(|(_, _, p)| p)
            .collect(),
        rest.iter()
            .filter(|(d, _, _)| *d == from_target)
            .map(|(_, _, p)| p)
            .collect(),
    )
}

async fn run(target: X3TargetLeg, attach_x3_before_split: bool) {
    let pki = pki();
    let mdf = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
    let engine = Engine::new(Datapath::new()).with_x3(pki.config.clone());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let _events = engine.register_client(CLIENT);
    let phone_a = UdpSocket::bind("127.0.0.2:0").await.expect("a");
    let phone_b = UdpSocket::bind("127.0.0.3:0").await.expect("b");
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "x3-split".into(),
                from_tag: "tag-a".into(),
                sdp: sdp(phone_a.local_addr().expect("a")),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let to_b = engine_address(&offered);
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "x3-split".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp(phone_b.local_addr().expect("b")),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let to_a = engine_address(&answered);

    let attach_x3 = || {
        engine.handle(
            CLIENT,
            Command::AttachX3 {
                call_id: "x3-split".into(),
                from_tag: "tag-a".into(),
                delivery: mdf.local_addr().expect("mdf").to_string(),
                xid: XID_TEXT.parse::<Xid>().expect("xid"),
                correlation_id: common::x3_mdf::CORRELATION_ID,
                target_leg: target,
            },
        )
    };
    let attach_split = |uri: String| {
        engine.handle(
            CLIENT,
            Command::AttachWsSplit(WsSplitAttach {
                call_id: "x3-split".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                sample_rate: None,
                offerer_profile: None,
                answerer_profile: None,
            }),
        )
    };
    let mut frame = 0usize;
    if attach_x3_before_split {
        let attached = attach_x3().await;
        assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
        drive(&phone_a, &phone_b, to_a, to_b, &mut frame, 5).await;
    }
    let split = attach_split(bot().await).await;
    assert!(matches!(split, CmdResult::Ok { .. }), "{split:?}");
    if !attach_x3_before_split {
        let attached = attach_x3().await;
        assert!(
            matches!(attached, CmdResult::Ok { .. }),
            "an interception is not refused on a split call: {attached:?}"
        );
    }
    let acceptor = acceptor(&pki);
    let (stream, _) = timeout(SHORT, mdf.accept())
        .await
        .expect("connect")
        .expect("accept");
    let tls = timeout(SHORT, acceptor.accept(stream))
        .await
        .expect("tls")
        .expect("handshake");
    let delivered = Arc::new(Mutex::new(Vec::new()));
    collect(tls, delivered.clone());

    let target_is_caller = matches!(target, X3TargetLeg::Caller);
    let (own, bot_tone, other) = if target_is_caller {
        (A_TONE, TO_A_TONE, B_TONE)
    } else {
        (B_TONE, TO_B_TONE, A_TONE)
    };

    drive(&phone_a, &phone_b, to_a, to_b, &mut frame, 20).await;
    let mark = delivered.lock().expect("lock").len();
    drive(&phone_a, &phone_b, to_a, to_b, &mut frame, 40).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let delivered = delivered.lock().expect("lock");
        let (to_target, from_target) = split_by_direction(&delivered, mark);
        assert_only(
            &pcm(&to_target),
            bot_tone,
            "to_target while split: what the target hears is the bot",
        );
        assert_only(
            &pcm(&from_target),
            own,
            "from_target while split: the target's own voice",
        );
    }

    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsSplit(WsSplitDetach {
                call_id: "x3-split".into(),
                from_tag: "tag-a".into(),
            }),
        )
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    drive(&phone_a, &phone_b, to_a, to_b, &mut frame, 10).await;
    let mark = delivered.lock().expect("lock").len();
    drive(&phone_a, &phone_b, to_a, to_b, &mut frame, 40).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let delivered = delivered.lock().expect("lock");
    let (to_target, from_target) = split_by_direction(&delivered, mark);
    assert_only(
        &pcm(&to_target),
        other,
        "to_target after the detach: the other party again",
    );
    assert_only(&pcm(&from_target), own, "from_target after the detach");
    // One connection, one counter, no gap and no repeat, across the attach and the detach.
    for pair in delivered.windows(2) {
        assert_eq!(
            pair[1].1,
            pair[0].1 + 1,
            "the delivery's sequence counter never skips or repeats"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_on_a_call_split_before_the_warrant_delivers_the_wire_to_an_offerer_target() {
    run(X3TargetLeg::Caller, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x3_on_a_call_split_before_the_warrant_delivers_the_wire_to_an_answerer_target() {
    run(X3TargetLeg::Callee, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_under_interception_that_is_then_split_delivers_the_wire_to_an_offerer_target() {
    run(X3TargetLeg::Caller, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_under_interception_that_is_then_split_delivers_the_wire_to_an_answerer_target() {
    run(X3TargetLeg::Callee, true).await;
}
