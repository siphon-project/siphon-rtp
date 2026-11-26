//! `offer_local` through the public control API, over the UDP-loopback datapath: the engine offers,
//! the caller's answer completes the call, a prompt reaches the caller, a takeover WebSocket hears
//! the caller, and a lawful interception attached at the offer delivers from the answer on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::x3_mdf::{
    acceptor, from_target, pki, rtp_from, to_target, Mdf, PduStream, Phone, Pki, Tls,
    CORRELATION_ID, SHORT,
};
use futures_util::StreamExt;
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{
    CmdResult, Command, Event, PlayMediaSource, ProfileFlags, X3EndReason, X3TargetLeg, Xid,
};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
const CALLER_TAG: &str = "tag-a";
const CALLER_SSRC: u32 = 0x0A0A_0A0A;

fn engine() -> Engine<Datapath> {
    let engine = Engine::new(Datapath::new());
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

/// µ-law only, with RTCP multiplexed, so a caller's answer is one short section.
fn profile() -> ProfileFlags {
    ProfileFlags {
        flags: vec!["codec-strip-all".into(), "codec-except-PCMU".into()],
        rtcp_mux: vec!["offer".into()],
        ..Default::default()
    }
}

fn caller_answer(address: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na=sendrecv\r\n",
        ip = address.ip(),
        port = address.port(),
    )
}

async fn offer_local(engine: &Engine<Datapath>, call: &str, profile: ProfileFlags) -> SocketAddr {
    let result = engine
        .handle(
            CLIENT,
            Command::OfferLocal {
                call_id: call.into(),
                from_tag: CALLER_TAG.into(),
                profile,
            },
        )
        .await;
    match result {
        CmdResult::Ok { sdp: Some(sdp), .. } => {
            siphon_rtp_engine::sdp::parse(&sdp)
                .expect("the engine's offer parses")
                .remote_rtp
        }
        other => panic!("offer_local failed: {other:?}"),
    }
}

async fn answer(engine: &Engine<Datapath>, call: &str, sdp: String) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call.into(),
                from_tag: CALLER_TAG.into(),
                to_tag: "tag-b".into(),
                sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

async fn play_tone(engine: &Engine<Datapath>, call: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: call.into(),
                from_tag: CALLER_TAG.into(),
                source: PlayMediaSource::Tone {
                    tone: "425/400".into(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prompt_reaches_the_caller_after_the_acks_answer() {
    let engine = engine();
    let caller = Phone::new().await;
    let toward_engine = offer_local(&engine, "ivr", profile()).await;
    // The prompt is refused until the caller has answered.
    assert!(matches!(
        play_tone(&engine, "ivr").await,
        CmdResult::Error { .. }
    ));
    let completed = answer(&engine, "ivr", caller_answer(caller.address)).await;
    assert!(matches!(completed, CmdResult::Ok { .. }), "{completed:?}");
    assert!(matches!(
        play_tone(&engine, "ivr").await,
        CmdResult::Ok { .. }
    ));
    let mut heard = Vec::new();
    for _ in 0..40 {
        heard.extend(caller.drain_rtp().await);
        if !heard.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!heard.is_empty(), "the prompt reached the caller");
    assert_eq!(heard[0][1] & 0x7f, 0, "in the codec the caller answered");
    let _ = toward_engine;
}

/// A WebSocket server that republishes every frame it receives.
async fn ws_server() -> (String, flume::Receiver<Message>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ws");
    let addr = listener.local_addr().expect("ws addr");
    let (frames_tx, frames_rx) = flume::unbounded::<Message>();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        let (_sink, mut source) = socket.split();
        while let Some(Ok(message)) = source.next().await {
            if frames_tx.send(message).is_err() {
                break;
            }
        }
    });
    (format!("ws://{addr}/stream"), frames_rx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_websocket_receives_the_callers_audio_once_the_offer_is_answered() {
    let (ws_uri, frames) = ws_server().await;
    let engine = engine();
    let caller = Phone::new().await;
    let mut takeover = profile();
    takeover.ws_uri = Some(ws_uri);
    let toward_engine = offer_local(&engine, "bot", takeover).await;
    let completed = answer(&engine, "bot", caller_answer(caller.address)).await;
    assert!(matches!(completed, CmdResult::Ok { .. }), "{completed:?}");
    let mut audio = None;
    for sequence in 1..=100u16 {
        caller
            .send(&rtp_from(CALLER_SSRC, sequence), toward_engine)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Ok(message) = frames.try_recv() {
            if let Message::Binary(bytes) = message {
                audio = Some(bytes.len());
            }
        }
        if audio.is_some() {
            break;
        }
    }
    assert_eq!(audio, Some(320), "8 kHz / 20 ms of L16 PCM from the caller");
}

struct Rig {
    engine: Engine<Datapath>,
    pki: Pki,
    listener: TcpListener,
    events: flume::Receiver<Event>,
}

impl Rig {
    async fn new() -> Self {
        let pki = pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
        let engine = Engine::new(Datapath::new()).with_x3(pki.config.clone());
        tokio::spawn(run_redirect_dispatcher(
            engine.datapath().rx(),
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        let (_generation, events) = engine.register_client_generation(CLIENT);
        Self {
            engine,
            pki,
            listener,
            events,
        }
    }

    async fn attach(&self, call: &str) -> CmdResult {
        self.engine
            .handle(
                CLIENT,
                Command::AttachX3 {
                    call_id: call.into(),
                    from_tag: CALLER_TAG.into(),
                    delivery: self.listener.local_addr().expect("mdf addr").to_string(),
                    xid: XID_TEXT.parse::<Xid>().expect("xid"),
                    correlation_id: CORRELATION_ID,
                    target_leg: X3TargetLeg::Caller,
                },
            )
            .await
    }

    async fn accept(&self) -> Mdf {
        let acceptor = acceptor(&self.pki);
        let (stream, _) = timeout(SHORT, self.listener.accept())
            .await
            .expect("the engine connects to the mediation function")
            .expect("accept");
        let tls: Tls = timeout(SHORT, acceptor.accept(stream))
            .await
            .expect("no timeout")
            .expect("mutual TLS handshake");
        Mdf {
            stream: PduStream::new(tls),
            next_sequence: 0,
            seen: Vec::new(),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interception_attached_at_the_offer_delivers_from_the_answer_on() {
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    let toward_engine = offer_local(&rig.engine, "tap", profile()).await;

    // Attached at the INVITE, before there is a media path: accepted, and the delivery connection
    // is up at once.
    let attached = rig.attach("tap").await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

    // What the caller sends before it has answered goes nowhere: it is not in the interception.
    for sequence in 1..=5u16 {
        caller
            .send(&rtp_from(CALLER_SSRC, sequence), toward_engine)
            .await;
    }
    let completed = answer(&rig.engine, "tap", caller_answer(caller.address)).await;
    assert!(matches!(completed, CmdResult::Ok { .. }), "{completed:?}");
    assert!(matches!(
        play_tone(&rig.engine, "tap").await,
        CmdResult::Ok { .. }
    ));

    let mut sent = Vec::new();
    for sequence in 100..125u16 {
        let packet = rtp_from(CALLER_SSRC, sequence);
        caller.send(&packet, toward_engine).await;
        sent.push(packet);
        tokio::time::sleep(Duration::from_millis(20)).await;
        caller.drain_rtp().await;
    }
    mdf.read_until(|read| {
        read.iter()
            .filter(|(direction, _)| *direction == from_target())
            .count()
            >= sent.len()
            && read.iter().any(|(direction, _)| *direction == to_target())
    })
    .await;
    let from: Vec<Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == from_target())
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_eq!(
        from[..sent.len()],
        sent[..],
        "what the caller sent after the answer, once each and in order, and nothing from before it"
    );
    assert!(
        mdf.seen
            .iter()
            .any(|(direction, _)| *direction == to_target()),
        "what the engine sent the caller is delivered too"
    );
    let ended: Vec<_> = rig
        .events
        .try_iter()
        .filter(|event| matches!(event, Event::X3Ended { reason, .. } if *reason != X3EndReason::CallEnded))
        .collect();
    assert!(ended.is_empty(), "still attached: {ended:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interception_on_an_offer_that_is_deleted_unanswered_ends_with_the_call() {
    let rig = Rig::new().await;
    offer_local(&rig.engine, "gone", profile()).await;
    let attached = rig.attach("gone").await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let _mdf = rig.accept().await;
    let deleted = rig
        .engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "gone".into(),
                from_tag: CALLER_TAG.into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    let mut ended = false;
    for _ in 0..50 {
        ended |= rig.events.try_iter().any(|event| {
            matches!(
                event,
                Event::X3Ended {
                    reason: X3EndReason::CallEnded,
                    ..
                }
            )
        });
        if ended {
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(ended, "the interception ends with the call, loudly");
}
