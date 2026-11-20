//! Lawful interception (ETSI TS 103 221-2 X3) of an engine-answered single-leg call
//! (`answer_local`).
//!
//! The call has one RTP party, the caller, and the engine is its far side: it plays prompts, idles
//! on comfort noise and answers the caller itself. That one party is the target whatever the
//! warrant's `target_leg` says (there is nobody else on the call): what the caller sent is
//! `from_target`, and what the engine sent it (the prompt, the comfort noise, exactly the RTP that
//! left the socket, in plaintext) is `to_target`. The interception belongs to the call, so it
//! carries across a re-answer and across `offer_far` growing the call into a relay: same delivery
//! connection, same Correlation ID, unbroken PDU sequence.
//!
//! These tests drive the real engine over the UDP-loopback datapath against a stub Mediation
//! Function behind mutual TLS.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::x3_mdf::{
    acceptor, from_target, pki, plain_sdp, rtp_from, rtp_sequence, ssrc_of, to_target, Mdf,
    PduStream, Phone, Pki, Tls, CORRELATION_ID, SHORT,
};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{
    CmdResult, Command, Event, PlayMediaSource, ProfileFlags, X3EndReason, X3TargetLeg, Xid,
};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use siphon_rtp_srtp::SrtpContext;
use tokio::net::TcpListener;
use tokio::time::timeout;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
const CALLER_SSRC: u32 = 0x0A0A_0A0A;
const CALLEE_SSRC: u32 = 0x0B0B_0B0B;
const FROM_TAG: &str = "tag-a";

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

    async fn send(&self, command: Command) -> CmdResult {
        self.engine.handle(CLIENT, command).await
    }

    fn sdp_of(result: &CmdResult) -> &str {
        match result {
            CmdResult::Ok {
                sdp: Some(text), ..
            } => text,
            other => panic!("expected Ok with sdp, got {other:?}"),
        }
    }

    fn engine_address(result: &CmdResult) -> SocketAddr {
        siphon_rtp_engine::sdp::parse(Self::sdp_of(result))
            .expect("parse the engine's sdp")
            .remote_rtp
    }

    /// `answer_local` for `from_tag` on `call`: the engine address the caller sends to, and the
    /// whole result.
    async fn answer_local_as(
        &self,
        call: &str,
        from_tag: &str,
        sdp: String,
        profile: ProfileFlags,
    ) -> (SocketAddr, CmdResult) {
        let result = self
            .send(Command::AnswerLocal {
                call_id: call.into(),
                from_tag: from_tag.into(),
                sdp,
                profile,
            })
            .await;
        (Self::engine_address(&result), result)
    }

    async fn answer_local(&self, call: &str, phone: &Phone) -> SocketAddr {
        self.answer_local_as(
            call,
            FROM_TAG,
            plain_sdp(phone.address, "sendrecv"),
            ProfileFlags::default(),
        )
        .await
        .0
    }

    fn attach_command(&self, call: &str, target_leg: X3TargetLeg) -> Command {
        Command::AttachX3 {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
            delivery: self.listener.local_addr().expect("mdf addr").to_string(),
            xid: XID_TEXT.parse::<Xid>().expect("xid"),
            correlation_id: CORRELATION_ID,
            target_leg,
        }
    }

    async fn attach(&self, call: &str) -> CmdResult {
        self.attach_as(call, X3TargetLeg::Caller).await
    }

    async fn attach_as(&self, call: &str, target_leg: X3TargetLeg) -> CmdResult {
        self.send(self.attach_command(call, target_leg)).await
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

    async fn second_connection(&self) -> bool {
        timeout(Duration::from_millis(300), self.listener.accept())
            .await
            .is_ok()
    }

    fn drained_events(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }

    async fn play_tone(&self, call: &str, tone: &str) -> CmdResult {
        self.send(Command::PlayMedia {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
            source: PlayMediaSource::Tone { tone: tone.into() },
            repeat_times: None,
            start_pos_ms: None,
            duration_ms: None,
            overlay: false,
            gain_decibels: None,
            to_tag: None,
        })
        .await
    }

    async fn delete(&self, call: &str) {
        self.send(Command::Delete {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
            to_tag: None,
        })
        .await;
    }
}

fn x3_ends(events: Vec<Event>) -> Vec<(X3EndReason, u64)> {
    events
        .into_iter()
        .filter_map(|event| match event {
            Event::X3Ended {
                reason, delivered, ..
            } => Some((reason, delivered)),
            _ => None,
        })
        .collect()
}

fn count(seen: &[(u16, Vec<u8>)], direction: u16) -> usize {
    seen.iter().filter(|(read, _)| *read == direction).count()
}

/// The caller sends `frames` 20 ms frames of its own stream, starting at `first`, and everything the
/// engine sent it meanwhile is returned.
async fn caller_talks(
    caller: &Phone,
    toward: SocketAddr,
    first: u16,
    frames: u16,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut sent = Vec::new();
    let mut heard = Vec::new();
    for sequence in first..first + frames {
        let packet = rtp_from(CALLER_SSRC, sequence);
        caller.send(&packet, toward).await;
        sent.push(packet);
        tokio::time::sleep(Duration::from_millis(20)).await;
        heard.extend(caller.drain_rtp().await);
    }
    (sent, heard)
}

/// Every datagram of `heard` that the interception could have seen must be in `delivered` byte for
/// byte: from the first one delivered on its stream (SSRC) up to the last. What the engine sent
/// before the taps went on (an attach lands after the first comfort-noise frames, and a rebuilt
/// pipeline sends its first frame a moment before its taps are put back) is not owed.
fn assert_heard_was_delivered(heard: &[Vec<u8>], delivered: &[Vec<u8>]) {
    assert!(
        !delivered.is_empty(),
        "something was delivered toward the target"
    );
    assert!(!heard.is_empty(), "the engine really sent the caller media");
    let range_of = |ssrc: u32| {
        let sequences: Vec<u16> = delivered
            .iter()
            .filter(|packet| ssrc_of(packet) == ssrc)
            .map(|packet| rtp_sequence(packet))
            .collect();
        Some((*sequences.iter().min()?, *sequences.iter().max()?))
    };
    let mut checked = 0;
    for packet in heard {
        let Some((first, last)) = range_of(ssrc_of(packet)) else {
            continue;
        };
        if (first..=last).contains(&rtp_sequence(packet)) {
            checked += 1;
            assert!(
                delivered.contains(packet),
                "to_target is exactly the RTP the engine sent: sequence {} missing",
                rtp_sequence(packet)
            );
        }
    }
    assert!(checked > 5, "enough of the egress was compared ({checked})");
}

/// The warrant names `target_leg`; the engine answering the call stands in for the callee, so with
/// the caller as the target its ingress is `from_target` and the engine's egress `to_target`, and
/// with the callee as the target the two mirror (TS 103 221-2 §5.2.6).
async fn single_leg_both_ways(target_leg: X3TargetLeg) {
    let (caller_direction, engine_direction) = match target_leg {
        X3TargetLeg::Caller => (from_target(), to_target()),
        X3TargetLeg::Callee => (to_target(), from_target()),
    };
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    let toward_engine = rig.answer_local("ivr", &caller).await;

    let attached = rig.attach_as("ivr", target_leg).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

    // A prompt, so the egress is not only comfort noise.
    let played = rig.play_tone("ivr", "425/400").await;
    assert!(matches!(played, CmdResult::Ok { .. }), "{played:?}");
    let (sent, heard) = caller_talks(&caller, toward_engine, 1, 25).await;

    mdf.read_until(|read| {
        count(read, caller_direction) >= sent.len()
            && count(read, engine_direction) >= heard.len() + 2
    })
    .await;

    let delivered_from: Vec<Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == caller_direction)
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_eq!(
        delivered_from[..sent.len()],
        sent[..],
        "the caller's ingress is what it sent, once each, in order, in the caller's direction"
    );
    let delivered_to: Vec<Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == engine_direction)
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_heard_was_delivered(&heard, &delivered_to);
    assert!(!rig.second_connection().await, "one delivery connection");
    assert!(x3_ends(rig.drained_events()).is_empty(), "still attached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_local_leg_is_delivered_both_ways_with_the_prompt_as_sent() {
    single_leg_both_ways(X3TargetLeg::Caller).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callee_target_on_an_answer_local_leg_mirrors_the_directions() {
    single_leg_both_ways(X3TargetLeg::Callee).await;
}

fn savp_offer(address: SocketAddr, crypto: &CryptoAttribute) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na=sendrecv\r\n\
         a={crypto}\r\n",
        ip = address.ip(),
        port = address.port(),
        crypto = crypto.to_attribute_value(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_answer_local_leg_is_delivered_as_plaintext_never_ciphertext() {
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    let caller_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let (toward_engine, answered) = rig
        .answer_local_as(
            "secure",
            FROM_TAG,
            savp_offer(caller.address, &caller_key),
            ProfileFlags::default(),
        )
        .await;
    let engine_key = *siphon_rtp_engine::sdp::parse(Rig::sdp_of(&answered))
        .expect("answer")
        .crypto
        .first()
        .expect("engine a=crypto");

    let attached = rig.attach("secure").await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;
    let played = rig.play_tone("secure", "425/400").await;
    assert!(matches!(played, CmdResult::Ok { .. }), "{played:?}");

    let mut caller_encrypt = SrtpContext::from_key_material(&caller_key.key);
    let mut caller_decrypt = SrtpContext::from_key_material(&engine_key.key);
    let mut sent_plaintext = Vec::new();
    let mut heard_plaintext = Vec::new();
    let mut buffer = [0u8; 2048];
    for sequence in 1..=25u16 {
        let plaintext = rtp_from(CALLER_SSRC, sequence);
        let mut sealed = Vec::new();
        caller_encrypt
            .protect(&plaintext, &mut sealed)
            .expect("protect");
        assert_ne!(sealed, plaintext, "the caller really encrypts");
        caller.send(&sealed, toward_engine).await;
        sent_plaintext.push(plaintext);
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Ok(Ok((length, _))) = timeout(
            Duration::from_millis(1),
            caller.socket.recv_from(&mut buffer),
        )
        .await
        {
            if (64..=95).contains(&(buffer[1] & 0x7f)) {
                continue;
            }
            let mut clear = Vec::new();
            if caller_decrypt
                .unprotect(&buffer[..length], &mut clear)
                .is_ok()
            {
                heard_plaintext.push(clear);
            }
        }
    }
    mdf.read_until(|read| {
        count(read, from_target()) >= sent_plaintext.len()
            && count(read, to_target()) >= heard_plaintext.len() + 2
    })
    .await;
    for (direction, payload) in &mdf.seen {
        if *direction == from_target() {
            assert!(
                sent_plaintext.contains(payload),
                "from_target is the caller's plaintext RTP, not the SRTP it sent"
            );
        }
    }
    let delivered_to: Vec<Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == to_target())
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_heard_was_delivered(&heard_plaintext, &delivered_to);
}

/// The directions stay the warrant's through `offer_far`: the caller's ingress keeps its direction
/// when the far party answers and takes the callee side over, whose own ingress is the other one.
async fn grow_keeps_the_directions(target_leg: X3TargetLeg) {
    let (caller_direction, callee_direction) = match target_leg {
        X3TargetLeg::Caller => (from_target(), to_target()),
        X3TargetLeg::Callee => (to_target(), from_target()),
    };
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    let callee = Phone::new().await;
    let toward_caller_leg = rig.answer_local("grow", &caller).await;
    let attached = rig.attach_as("grow", target_leg).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

    // The single-leg taps carry on while the far leg is only offered.
    let (sent_before, _) = caller_talks(&caller, toward_caller_leg, 1, 10).await;
    let offered = rig
        .send(Command::OfferFar {
            call_id: "grow".into(),
            from_tag: FROM_TAG.into(),
            profile: ProfileFlags::default(),
        })
        .await;
    let toward_callee_leg = Rig::engine_address(&offered);
    let (sent_pending, _) = caller_talks(&caller, toward_caller_leg, 11, 10).await;

    let answered = rig
        .send(Command::Answer {
            call_id: "grow".into(),
            from_tag: FROM_TAG.into(),
            to_tag: "tag-b".into(),
            sdp: plain_sdp(callee.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");

    // Two-party now, each packet delivered once, in the direction the warrant implies.
    let mut sent_caller = Vec::new();
    let mut sent_callee = Vec::new();
    for sequence in 21..41u16 {
        let from_caller = rtp_from(CALLER_SSRC, sequence);
        let from_callee = rtp_from(CALLEE_SSRC, sequence);
        caller.send(&from_caller, toward_caller_leg).await;
        callee.send(&from_callee, toward_callee_leg).await;
        sent_caller.push(from_caller);
        sent_callee.push(from_callee);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let total_single_leg = sent_before.len() + sent_pending.len();
    mdf.read_until(|read| {
        let caller_rtp = read
            .iter()
            .filter(|(_, payload)| ssrc_of(payload) == CALLER_SSRC)
            .count();
        let callee_rtp = read
            .iter()
            .filter(|(_, payload)| ssrc_of(payload) == CALLEE_SSRC)
            .count();
        caller_rtp >= total_single_leg + sent_caller.len() && callee_rtp >= sent_callee.len()
    })
    .await;
    // Exactly once each, in the direction the warrant implies.
    for packet in sent_before.iter().chain(&sent_pending) {
        let seen = mdf
            .seen
            .iter()
            .filter(|(direction, payload)| *direction == caller_direction && payload == packet)
            .count();
        assert_eq!(
            seen, 1,
            "a single-leg caller packet is delivered once, as the caller"
        );
    }
    for packet in &sent_caller {
        let seen = mdf
            .seen
            .iter()
            .filter(|(direction, payload)| *direction == caller_direction && payload == packet)
            .count();
        assert_eq!(
            seen, 1,
            "the grown call's caller packet keeps its direction"
        );
    }
    for packet in &sent_callee {
        let seen = mdf
            .seen
            .iter()
            .filter(|(direction, payload)| *direction == callee_direction && payload == packet)
            .count();
        assert_eq!(seen, 1, "the callee packet is the other direction, once");
    }
    assert!(!rig.second_connection().await, "same delivery connection");
    assert!(
        x3_ends(rig.drained_events()).is_empty(),
        "offer_far does not end the interception"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_far_after_the_attach_keeps_the_delivery_with_the_caller_as_target() {
    grow_keeps_the_directions(X3TargetLeg::Caller).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_far_after_the_attach_keeps_the_delivery_with_the_callee_as_target() {
    grow_keeps_the_directions(X3TargetLeg::Callee).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_leg_deleted_after_the_attach_puts_the_single_leg_taps_back() {
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    let callee = Phone::new().await;
    let toward_caller_leg = rig.answer_local("back", &caller).await;
    assert!(matches!(rig.attach("back").await, CmdResult::Ok { .. }));
    let mut mdf = rig.accept().await;
    let offered = rig
        .send(Command::OfferFar {
            call_id: "back".into(),
            from_tag: FROM_TAG.into(),
            profile: ProfileFlags::default(),
        })
        .await;
    assert!(matches!(offered, CmdResult::Ok { .. }), "{offered:?}");
    rig.send(Command::Answer {
        call_id: "back".into(),
        from_tag: FROM_TAG.into(),
        to_tag: "tag-b".into(),
        sdp: plain_sdp(callee.address, "sendrecv"),
        profile: ProfileFlags::default(),
    })
    .await;
    let deleted = rig
        .send(Command::Delete {
            call_id: "back".into(),
            from_tag: FROM_TAG.into(),
            to_tag: Some("tag-b".into()),
        })
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");

    // The caller is back on the local pipeline: its packets are from_target again and the
    // engine's egress is to_target again.
    let (sent, heard) = caller_talks(&caller, toward_caller_leg, 1, 15).await;
    mdf.read_until(|read| {
        count(read, from_target()) >= sent.len() && count(read, to_target()) >= heard.len() + 2
    })
    .await;
    let delivered_to: Vec<Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == to_target())
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_heard_was_delivered(&heard, &delivered_to);
    assert!(x3_ends(rig.drained_events()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_answer_of_the_same_dialog_keeps_the_interception() {
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    let first = rig.answer_local("again", &caller).await;
    assert!(matches!(rig.attach("again").await, CmdResult::Ok { .. }));
    let mut mdf = rig.accept().await;
    let (sent_first, _) = caller_talks(&caller, first, 1, 8).await;

    // The controller answers the same dialog again (a new offer on an engine-answered call).
    let second = rig.answer_local("again", &caller).await;
    let (sent_second, heard) = caller_talks(&caller, second, 100, 12).await;

    mdf.read_until(|read| {
        count(read, from_target()) >= sent_first.len() + sent_second.len()
            && count(read, to_target()) >= heard.len() + 2
    })
    .await;
    let delivered_from: Vec<&Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == from_target())
        .map(|(_, payload)| payload)
        .collect();
    for packet in sent_first.iter().chain(&sent_second) {
        assert!(
            delivered_from.contains(&packet),
            "the caller's packet {} was delivered across the re-answer",
            rtp_sequence(packet)
        );
    }
    assert!(!rig.second_connection().await, "same delivery connection");
    assert!(
        x3_ends(rig.drained_events()).is_empty(),
        "a re-answer of the same dialog is not the end of the interception"
    );
    rig.delete("again").await;
    let ends = x3_ends(rig.drained_events());
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].0, X3EndReason::CallEnded);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_answer_that_is_a_different_dialog_ends_the_interception_loudly() {
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    rig.answer_local("other", &caller).await;
    assert!(matches!(rig.attach("other").await, CmdResult::Ok { .. }));
    let _mdf = rig.accept().await;

    let (_, result) = rig
        .answer_local_as(
            "other",
            "another-tag",
            plain_sdp(caller.address, "sendrecv"),
            ProfileFlags::default(),
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    let ends = x3_ends(rig.drained_events());
    assert_eq!(ends.len(), 1, "exactly one x3_ended: {ends:?}");
    assert_eq!(ends[0].0, X3EndReason::CallEnded);
}

/// A WebSocket server that accepts every connection and reads it to its end.
async fn ws_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ws");
    let address = listener.local_addr().expect("ws addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await {
                    use futures_util::StreamExt;
                    while let Some(Ok(_)) = socket.next().await {}
                }
            });
        }
    });
    address
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ws_takeover_call_and_an_echo_call_still_refuse_the_attach() {
    let rig = Rig::new().await;
    let server = ws_server().await;
    let bot = Phone::new().await;
    let (_, taken) = rig
        .answer_local_as(
            "bot",
            FROM_TAG,
            plain_sdp(bot.address, "sendrecv"),
            ProfileFlags {
                ws_uri: Some(format!("ws://{server}/agent")),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(taken, CmdResult::Ok { .. }), "{taken:?}");
    match rig.attach("bot").await {
        CmdResult::Error { reason } => {
            assert!(reason.contains("WebSocket-takeover"), "{reason}");
        }
        other => panic!("a ws_uri takeover has no media in the pipeline to tap: {other:?}"),
    }

    let echoing = Phone::new().await;
    rig.answer_local("echo", &echoing).await;
    let enabled = rig
        .send(Command::Echo {
            call_id: "echo".into(),
            from_tag: FROM_TAG.into(),
            to_tag: None,
            enabled: true,
        })
        .await;
    assert!(matches!(enabled, CmdResult::Ok { .. }), "{enabled:?}");
    match rig.attach("echo").await {
        CmdResult::Error { reason } => assert!(reason.contains("echo"), "{reason}"),
        other => panic!("an echo call bypasses the tap and must be refused: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_and_a_ws_bridge_on_an_intercepted_single_leg_call_are_refused_not_deaf() {
    let rig = Rig::new().await;
    let server = ws_server().await;
    let caller = Phone::new().await;
    let toward_engine = rig.answer_local("guarded", &caller).await;
    assert!(matches!(rig.attach("guarded").await, CmdResult::Ok { .. }));
    let mut mdf = rig.accept().await;

    let echo = rig
        .send(Command::Echo {
            call_id: "guarded".into(),
            from_tag: FROM_TAG.into(),
            to_tag: None,
            enabled: true,
        })
        .await;
    match echo {
        CmdResult::Error { reason } => assert!(reason.contains("lawful-interception"), "{reason}"),
        other => panic!("echo bypasses the tap, so it is refused while intercepted: {other:?}"),
    }
    let bridge = rig
        .send(Command::AttachWsBridge {
            call_id: "guarded".into(),
            from_tag: FROM_TAG.into(),
            ws_uri: format!("ws://{server}/agent"),
            profile: None,
        })
        .await;
    assert!(matches!(bridge, CmdResult::Error { .. }), "{bridge:?}");

    // Nothing changed for the delivery: the caller is still intercepted both ways.
    let (sent, heard) = caller_talks(&caller, toward_engine, 1, 12).await;
    mdf.read_until(|read| {
        count(read, from_target()) >= sent.len() && count(read, to_target()) >= heard.len() + 2
    })
    .await;
    assert!(x3_ends(rig.drained_events()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_two_party_call_still_delivers_each_packet_once() {
    let rig = Rig::new().await;
    let caller = Phone::new().await;
    let callee = Phone::new().await;
    let offer = rig
        .send(Command::Offer {
            call_id: "two".into(),
            from_tag: FROM_TAG.into(),
            sdp: plain_sdp(caller.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    let toward_callee_leg = Rig::engine_address(&offer);
    let answer = rig
        .send(Command::Answer {
            call_id: "two".into(),
            from_tag: FROM_TAG.into(),
            to_tag: "tag-b".into(),
            sdp: plain_sdp(callee.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    let toward_caller_leg = Rig::engine_address(&answer);
    assert!(matches!(
        rig.send(rig.attach_command("two", X3TargetLeg::Caller))
            .await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    let mut sent = Vec::new();
    for sequence in 1..=20u16 {
        let from_caller = rtp_from(CALLER_SSRC, sequence);
        let from_callee = rtp_from(CALLEE_SSRC, sequence);
        caller.send(&from_caller, toward_caller_leg).await;
        callee.send(&from_callee, toward_callee_leg).await;
        sent.push(from_caller);
        sent.push(from_callee);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    mdf.read_until(|read| read.len() >= sent.len()).await;
    // Grace for a duplicate to show up.
    tokio::time::sleep(Duration::from_millis(200)).await;
    while let Some(pdu) = mdf.stream.next_within(Duration::from_millis(50)).await {
        mdf.check(&pdu);
    }
    assert_eq!(mdf.seen.len(), sent.len(), "no packet is delivered twice");
    for packet in &sent {
        assert_eq!(
            mdf.seen
                .iter()
                .filter(|(_, payload)| payload == packet)
                .count(),
            1
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_info_advertises_single_leg_interception_only_with_x3() {
    let features = |result: CmdResult| match result {
        CmdResult::NodeInfo { node } => node.features,
        other => panic!("node_info answers a node: {other:?}"),
    };
    let rig = Rig::new().await;
    assert!(features(rig.send(Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_single_leg"));
    let bare = Engine::new(Datapath::new());
    assert!(!features(bare.handle(CLIENT, Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_single_leg"));
}

/// A WebRTC-shaped caller (`UDP/TLS/RTP/SAVPF`, `actpass`) answered by the engine: the engine is the
/// DTLS client and the caller the server. Returns the engine address, the caller's keyed leg and the
/// caller's phone, once the real handshake completed.
async fn dtls_caller(
    rig: &Rig,
    call: &str,
) -> (
    SocketAddr,
    siphon_rtp_srtp::leg::SecureLeg,
    std::sync::Arc<tokio::net::UdpSocket>,
) {
    use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, DtlsSession, Fingerprint};
    let socket = std::sync::Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind caller"),
    );
    let caller = socket.local_addr().expect("caller addr");
    let certificate = DtlsCertificate::generate().expect("caller cert");
    let fingerprint = certificate.fingerprint();
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let (toward_engine, answered) = rig
        .answer_local_as(
            call,
            FROM_TAG,
            format!(
                "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                 m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                 a=rtcp-mux\r\na=sendrecv\r\na=setup:actpass\r\na=fingerprint:{hash} {hex}\r\n",
                ip = caller.ip(),
                port = caller.port(),
                hash = fingerprint.hash_function,
            ),
            ProfileFlags::default(),
        )
        .await;
    let engine_fingerprint = siphon_rtp_engine::sdp::parse(Rig::sdp_of(&answered))
        .expect("answer")
        .fingerprint
        .expect("the engine's fingerprint");
    let mut session = DtlsSession::new(
        &certificate,
        DtlsRole::Server,
        Fingerprint::new(
            engine_fingerprint.hash_function.clone(),
            engine_fingerprint.bytes.clone(),
        ),
        Duration::from_millis(200),
    )
    .expect("caller session");
    let mut buffer = [0u8; 2048];
    let deadline = std::time::Instant::now() + SHORT;
    while std::time::Instant::now() < deadline && !session.is_keyed() {
        let now = std::time::Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        let wait = session.poll_timeout().map_or(remaining, |at| {
            at.saturating_duration_since(now).min(remaining)
        });
        match timeout(wait, socket.recv_from(&mut buffer)).await {
            Ok(Ok((length, _))) => {
                session
                    .handle_datagram(std::time::Instant::now(), &buffer[..length])
                    .expect("the caller accepts the record");
            }
            _ => session
                .handle_timeout(std::time::Instant::now())
                .expect("caller timer"),
        }
        while let Some(record) = session.poll_transmit() {
            socket
                .send_to(&record, toward_engine)
                .await
                .expect("caller send");
        }
    }
    let leg = session
        .keying()
        .map(|keying| keying.to_secure_leg())
        .expect("the DTLS handshake completed");
    (toward_engine, leg, socket)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dtls_answer_local_leg_is_delivered_as_plaintext_never_ciphertext() {
    let rig = Rig::new().await;
    let (toward_engine, mut caller_leg, socket) = dtls_caller(&rig, "dtls").await;
    let attached = rig.attach("dtls").await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;
    let played = rig.play_tone("dtls", "425/400").await;
    assert!(matches!(played, CmdResult::Ok { .. }), "{played:?}");

    let mut sent_plaintext = Vec::new();
    let mut heard_plaintext = Vec::new();
    let mut buffer = [0u8; 2048];
    for sequence in 1..=25u16 {
        let plaintext = rtp_from(CALLER_SSRC, sequence);
        let mut sealed = Vec::new();
        caller_leg
            .protect(&plaintext, &mut sealed)
            .expect("protect");
        assert_ne!(sealed, plaintext, "the caller really encrypts");
        socket.send_to(&sealed, toward_engine).await.expect("send");
        sent_plaintext.push(plaintext);
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Ok(Ok((length, _))) =
            timeout(Duration::from_millis(1), socket.recv_from(&mut buffer)).await
        {
            // DTLS records and RTCP fail the unprotect and are skipped.
            let mut clear = Vec::new();
            if caller_leg.unprotect(&buffer[..length], &mut clear).is_ok()
                && !(64..=95).contains(&(clear[1] & 0x7f))
            {
                heard_plaintext.push(clear);
            }
        }
    }
    mdf.read_until(|read| {
        count(read, from_target()) >= sent_plaintext.len()
            && count(read, to_target()) >= heard_plaintext.len() + 2
    })
    .await;
    let delivered_from: Vec<Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == from_target())
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_eq!(
        delivered_from[..sent_plaintext.len()],
        sent_plaintext[..],
        "from_target is the caller's plaintext RTP, not the SRTP it sent"
    );
    let delivered_to: Vec<Vec<u8>> = mdf
        .seen
        .iter()
        .filter(|(direction, _)| *direction == to_target())
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_heard_was_delivered(&heard_plaintext, &delivered_to);
}
