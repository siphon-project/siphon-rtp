//! Lawful interception (ETSI TS 103 221-2 X3) of a WebSocket-takeover call (`ws_uri`).
//!
//! The WebSocket server stands in for the callee, so the directions are the single-leg ones: with
//! the caller as the target, what the caller sent is `from_target` and what the engine sent it (the
//! bot's audio and the idle comfort noise, exactly the plaintext RTP that left the socket) is
//! `to_target`; with the callee as the target the two mirror (§5.2.6). The interception belongs to
//! the call: it follows the leg onto a bridge and off it again, across a re-point and a re-answer,
//! on one delivery connection with one Correlation ID and an unbroken PDU sequence (the stub
//! Mediation Function checks all three on every PDU it reads).
//!
//! These tests drive the real engine over the UDP-loopback datapath against a stub Mediation
//! Function behind mutual TLS and a loopback WebSocket bot.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::x3_mdf::{
    acceptor, assert_new_streams_delivered_from_first, from_target, pki, plain_sdp, rtp_from,
    rtp_sequence, ssrc_of, to_target, Mdf, PduStream, Phone, Pki, Tls, CORRELATION_ID, SHORT,
};
use futures_util::{SinkExt, StreamExt};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command, Event, ProfileFlags, X3EndReason, X3TargetLeg, Xid};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use siphon_rtp_srtp::SrtpContext;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
const CALLER_SSRC: u32 = 0x0A0A_0A0A;
const CALLEE_SSRC: u32 = 0x0B0B_0B0B;
const FROM_TAG: &str = "tag-a";

/// A WebSocket bot: replies with `reply_frames` frames of tone to the first uplink audio it hears,
/// and closes the connection when told to.
struct Bot {
    uri: String,
    close: flume::Sender<()>,
}

async fn bot(reply_frames: usize) -> Bot {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind bot");
    let address = listener.local_addr().expect("bot addr");
    let (close, closing) = flume::bounded::<()>(1);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let closing = closing.clone();
            tokio::spawn(async move {
                let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = socket.split();
                let mut replied = false;
                loop {
                    tokio::select! {
                        _ = closing.recv_async() => {
                            let _ = sink.send(Message::Close(None)).await;
                            return;
                        }
                        message = source.next() => match message {
                            Some(Ok(Message::Binary(_))) if !replied => {
                                replied = true;
                                for index in 0..reply_frames {
                                    let magnitude = 2000 + 100 * index as i16;
                                    let mut audio = Vec::with_capacity(320);
                                    for sample in 0..160 {
                                        let value = if (sample / 8) % 2 == 0 { magnitude } else { -magnitude };
                                        audio.extend_from_slice(&value.to_le_bytes());
                                    }
                                    if sink.send(Message::Binary(audio.into())).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Some(Ok(_)) => {}
                            _ => return,
                        }
                    }
                }
            });
        }
    });
    Bot {
        uri: format!("ws://{address}/agent"),
        close,
    }
}

struct Rig {
    engine: Engine<Datapath>,
    pki: Pki,
    listener: TcpListener,
    second_listener: TcpListener,
    events: flume::Receiver<Event>,
}

impl Rig {
    async fn new() -> Self {
        let pki = pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
        let second_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
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
            second_listener,
            events,
        }
    }

    async fn send(&self, command: Command) -> CmdResult {
        self.engine.handle(CLIENT, command).await
    }

    fn engine_address(result: &CmdResult) -> SocketAddr {
        match result {
            CmdResult::Ok {
                sdp: Some(text), ..
            } => {
                siphon_rtp_engine::sdp::parse(text)
                    .expect("parse the engine's sdp")
                    .remote_rtp
            }
            other => panic!("expected Ok with sdp, got {other:?}"),
        }
    }

    fn sdp_of(result: &CmdResult) -> &str {
        match result {
            CmdResult::Ok {
                sdp: Some(text), ..
            } => text,
            other => panic!("expected Ok with sdp, got {other:?}"),
        }
    }

    async fn answer_local_as(
        &self,
        call: &str,
        sdp: String,
        profile: ProfileFlags,
    ) -> (SocketAddr, CmdResult) {
        let result = self
            .send(Command::AnswerLocal {
                call_id: call.into(),
                from_tag: FROM_TAG.into(),
                sdp,
                profile,
            })
            .await;
        (Self::engine_address(&result), result)
    }

    /// `answer_local` of a plain caller, into the bot's WebSocket when `bot` is given.
    async fn answer_local(&self, call: &str, phone: &Phone, bot: Option<&Bot>) -> SocketAddr {
        self.answer_local_as(call, plain_sdp(phone.address, "sendrecv"), profile_for(bot))
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

    async fn attach(&self, call: &str, target_leg: X3TargetLeg) -> CmdResult {
        self.send(self.attach_command(call, target_leg)).await
    }

    async fn attach_second(&self, call: &str, target_leg: X3TargetLeg) -> CmdResult {
        self.send(Command::AttachX3 {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
            delivery: self
                .second_listener
                .local_addr()
                .expect("mdf addr")
                .to_string(),
            xid: "1f0e0d0c-0b0a-4908-8706-050403020100"
                .parse::<Xid>()
                .expect("xid"),
            correlation_id: CORRELATION_ID,
            target_leg,
        })
        .await
    }

    async fn accept(&self) -> Mdf {
        self.accept_on(&self.listener).await
    }

    async fn accept_second(&self) -> Mdf {
        self.accept_on(&self.second_listener).await
    }

    async fn accept_on(&self, listener: &TcpListener) -> Mdf {
        let acceptor = acceptor(&self.pki);
        let (stream, _) = timeout(SHORT, listener.accept())
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

    async fn attach_bridge(&self, call: &str, bot: &Bot) -> CmdResult {
        self.send(Command::AttachWsBridge {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
            ws_uri: bot.uri.clone(),
            profile: None,
        })
        .await
    }

    async fn detach_bridge(&self, call: &str) -> CmdResult {
        self.send(Command::DetachWsBridge {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
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

fn profile_for(bot: Option<&Bot>) -> ProfileFlags {
    ProfileFlags {
        ws_uri: bot.map(|bot| bot.uri.clone()),
        ..Default::default()
    }
}

fn x3_ends(events: Vec<Event>) -> Vec<X3EndReason> {
    events
        .into_iter()
        .filter_map(|event| match event {
            Event::X3Ended { reason, .. } => Some(reason),
            _ => None,
        })
        .collect()
}

fn count(seen: &[(u16, Vec<u8>)], direction: u16) -> usize {
    seen.iter().filter(|(read, _)| *read == direction).count()
}

fn payloads(mdf: &Mdf, direction: u16) -> Vec<Vec<u8>> {
    mdf.seen
        .iter()
        .filter(|(read, _)| *read == direction)
        .map(|(_, payload)| payload.clone())
        .collect()
}

/// `sender` sends `frames` 20 ms frames of `ssrc`'s stream toward `toward`, starting at `first`;
/// everything `listener` heard meanwhile is returned with what was sent.
async fn talk(
    sender: &Phone,
    listener: &Phone,
    toward: SocketAddr,
    ssrc: u32,
    first: u16,
    frames: u16,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut sent = Vec::new();
    let mut heard = Vec::new();
    for sequence in first..first + frames {
        let packet = rtp_from(ssrc, sequence);
        sender.send(&packet, toward).await;
        sent.push(packet);
        tokio::time::sleep(Duration::from_millis(20)).await;
        heard.extend(listener.drain_rtp().await);
    }
    (sent, heard)
}

/// What the engine sent `heard` must be in `delivered` byte for byte, from the first datagram
/// delivered on each stream to the last (what left before the taps went on, or after they came off,
/// is not owed). A bridge or pipeline built under an interception owes its first frame too:
/// [`assert_new_streams_delivered_from_first`].
fn assert_heard_was_delivered(heard: &[Vec<u8>], delivered: &[Vec<u8>]) {
    assert!(!delivered.is_empty(), "something was delivered");
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
                "to_target is exactly the RTP the engine sent: sequence {} of {:08x} missing",
                rtp_sequence(packet),
                ssrc_of(packet)
            );
        }
    }
    assert!(checked > 5, "enough of the egress was compared ({checked})");
}

/// Every packet of `sent` is among `delivered`, once.
fn assert_all_delivered_once(sent: &[Vec<u8>], delivered: &[Vec<u8>], what: &str) {
    for packet in sent {
        assert_eq!(
            delivered.iter().filter(|seen| *seen == packet).count(),
            1,
            "{what}: sequence {} of {:08x} is delivered exactly once",
            rtp_sequence(packet),
            ssrc_of(packet)
        );
    }
}

async fn answer_local_ws_both_ways(target_leg: X3TargetLeg) {
    let (caller_direction, engine_direction) = match target_leg {
        X3TargetLeg::Caller => (from_target(), to_target()),
        X3TargetLeg::Callee => (to_target(), from_target()),
    };
    let rig = Rig::new().await;
    let bot = bot(10).await;
    let caller = Phone::new().await;
    let toward_engine = rig.answer_local("bot", &caller, Some(&bot)).await;

    let attached = rig.attach("bot", target_leg).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

    let (sent, heard) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 1, 25).await;
    mdf.read_until(|read| {
        count(read, caller_direction) >= sent.len() && count(read, engine_direction) >= heard.len()
    })
    .await;

    let delivered_from = payloads(&mdf, caller_direction);
    assert_eq!(
        delivered_from[..sent.len()],
        sent[..],
        "the caller's ingress is what it sent, once each, in order, in the caller's direction"
    );
    assert_heard_was_delivered(&heard, &payloads(&mdf, engine_direction));
    assert!(!rig.second_connection().await, "one delivery connection");
    assert!(x3_ends(rig.drained_events()).is_empty(), "still attached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ws_takeover_call_is_delivered_both_ways_with_the_bot_audio_as_sent() {
    answer_local_ws_both_ways(X3TargetLeg::Caller).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callee_target_on_a_ws_takeover_call_mirrors_the_directions() {
    answer_local_ws_both_ways(X3TargetLeg::Callee).await;
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
async fn a_secure_ws_takeover_call_is_delivered_as_plaintext_never_ciphertext() {
    let rig = Rig::new().await;
    let bot = bot(10).await;
    let caller = Phone::new().await;
    let caller_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let (toward_engine, answered) = rig
        .answer_local_as(
            "secure",
            savp_offer(caller.address, &caller_key),
            profile_for(Some(&bot)),
        )
        .await;
    let engine_key = *siphon_rtp_engine::sdp::parse(Rig::sdp_of(&answered))
        .expect("answer")
        .crypto
        .first()
        .expect("engine a=crypto");
    let attached = rig.attach("secure", X3TargetLeg::Caller).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

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
            && count(read, to_target()) >= heard_plaintext.len()
    })
    .await;
    for packet in payloads(&mdf, from_target()) {
        assert!(
            sent_plaintext.contains(&packet),
            "from_target is the caller's plaintext RTP, not the SRTP it sent"
        );
    }
    assert_heard_was_delivered(&heard_plaintext, &payloads(&mdf, to_target()));
}

/// A WebRTC-shaped caller (`UDP/TLS/RTP/SAVPF`) answered by the engine into the bot's WebSocket, once
/// the real DTLS handshake completed.
async fn dtls_caller(
    rig: &Rig,
    call: &str,
    bot: &Bot,
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
            format!(
                "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                 m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
                 a=rtcp-mux\r\na=sendrecv\r\na=setup:actpass\r\na=fingerprint:{hash} {hex}\r\n",
                ip = caller.ip(),
                port = caller.port(),
                hash = fingerprint.hash_function,
            ),
            profile_for(Some(bot)),
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
async fn a_dtls_ws_takeover_call_is_delivered_as_plaintext_never_ciphertext() {
    let rig = Rig::new().await;
    let bot = bot(10).await;
    let (toward_engine, mut caller_leg, socket) = dtls_caller(&rig, "dtls", &bot).await;
    let attached = rig.attach("dtls", X3TargetLeg::Caller).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

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
            && count(read, to_target()) >= heard_plaintext.len()
    })
    .await;
    assert_eq!(
        payloads(&mdf, from_target())[..sent_plaintext.len()],
        sent_plaintext[..],
        "from_target is the caller's plaintext RTP, not the SRTP it sent"
    );
    assert_heard_was_delivered(&heard_plaintext, &payloads(&mdf, to_target()));
}

/// The latent gap: an interception attached at the offer, on a call whose answer then names `ws_uri`,
/// stayed attached with no taps and no `x3_ended`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interception_attached_at_the_offer_is_delivered_once_the_answer_names_ws_uri() {
    let rig = Rig::new().await;
    let bot = bot(10).await;
    let caller = Phone::new().await;
    let callee = Phone::new().await;
    let offer = rig
        .send(Command::Offer {
            call_id: "late".into(),
            from_tag: FROM_TAG.into(),
            sdp: plain_sdp(caller.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "{offer:?}");
    let attached = rig.attach("late", X3TargetLeg::Caller).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;
    let answer = rig
        .send(Command::Answer {
            call_id: "late".into(),
            from_tag: FROM_TAG.into(),
            to_tag: "tag-b".into(),
            sdp: plain_sdp(callee.address, "sendrecv"),
            profile: profile_for(Some(&bot)),
        })
        .await;
    let toward_engine = Rig::engine_address(&answer);

    let (sent, heard) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 1, 25).await;
    mdf.read_until(|read| {
        count(read, from_target()) >= sent.len() && count(read, to_target()) >= heard.len()
    })
    .await;
    assert_eq!(payloads(&mdf, from_target())[..sent.len()], sent[..]);
    assert_heard_was_delivered(&heard, &payloads(&mdf, to_target()));
    // Nothing was sent to the caller before the answer, so every stream it heard was begun by the
    // bridge built under the interception, and its first frame is owed.
    assert_new_streams_delivered_from_first(&heard, &[], &payloads(&mdf, to_target()));
    assert!(x3_ends(rig.drained_events()).is_empty(), "still attached");
}

/// A bridge taken over a relay, re-pointed, detached back and the call re-answered keeps the one
/// delivery: same connection, same CID, contiguous sequence (the stub checks each PDU).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_intercepted_relay_taken_over_re_pointed_and_detached_keeps_one_delivery() {
    let rig = Rig::new().await;
    let (first, second) = (bot(5).await, bot(5).await);
    let caller = Phone::new().await;
    let callee = Phone::new().await;
    let offer = rig
        .send(Command::Offer {
            call_id: "relay".into(),
            from_tag: FROM_TAG.into(),
            sdp: plain_sdp(caller.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    let toward_callee_leg = Rig::engine_address(&offer);
    let answer = rig
        .send(Command::Answer {
            call_id: "relay".into(),
            from_tag: FROM_TAG.into(),
            to_tag: "tag-b".into(),
            sdp: plain_sdp(callee.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    let toward_caller_leg = Rig::engine_address(&answer);
    assert!(matches!(
        rig.attach("relay", X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;

    let mut caller_sent = Vec::new();
    let mut callee_sent = Vec::new();
    // On the relay.
    let (sent, _) = talk(&caller, &callee, toward_caller_leg, CALLER_SSRC, 1, 6).await;
    caller_sent.extend(sent);
    let (sent, _) = talk(&callee, &caller, toward_callee_leg, CALLEE_SSRC, 1, 6).await;
    callee_sent.extend(sent);

    // Taken over: the interception moves onto the bridge.
    let taken = rig.attach_bridge("relay", &first).await;
    assert!(matches!(taken, CmdResult::Ok { .. }), "{taken:?}");
    let (sent, _) = talk(&caller, &caller, toward_caller_leg, CALLER_SSRC, 7, 6).await;
    caller_sent.extend(sent);

    // Re-pointed: the taps ride the leg, not the connection.
    let moved = rig.attach_bridge("relay", &second).await;
    assert!(matches!(moved, CmdResult::Ok { .. }), "{moved:?}");
    let (sent, _) = talk(&caller, &caller, toward_caller_leg, CALLER_SSRC, 13, 6).await;
    caller_sent.extend(sent);

    // Detached: the relay is back and the taps are on it again.
    let detached = rig.detach_bridge("relay").await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    let (sent, _) = talk(&caller, &callee, toward_caller_leg, CALLER_SSRC, 19, 6).await;
    caller_sent.extend(sent);
    let (sent, _) = talk(&callee, &caller, toward_callee_leg, CALLEE_SSRC, 7, 6).await;
    callee_sent.extend(sent);

    mdf.read_until(|read| {
        let from_callee = read
            .iter()
            .filter(|(direction, payload)| {
                *direction == to_target() && ssrc_of(payload) == CALLEE_SSRC
            })
            .count();
        count(read, from_target()) >= caller_sent.len() && from_callee >= callee_sent.len()
    })
    .await;
    assert_all_delivered_once(
        &caller_sent,
        &payloads(&mdf, from_target()),
        "the caller's media",
    );
    let delivered_to = payloads(&mdf, to_target());
    for packet in &callee_sent {
        assert!(
            delivered_to.contains(packet),
            "the callee's relayed packet {} is delivered",
            rtp_sequence(packet)
        );
    }
    assert!(!rig.second_connection().await, "one delivery connection");
    assert!(x3_ends(rig.drained_events()).is_empty(), "never ended");
    rig.delete("relay").await;
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![X3EndReason::CallEnded],
        "ended once, at the delete"
    );
}

/// The same for the engine's own anchor: the bot joins an answered call, is re-pointed and leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_intercepted_anchor_taken_over_re_pointed_and_detached_keeps_one_delivery() {
    let rig = Rig::new().await;
    let (first, second) = (bot(5).await, bot(5).await);
    let caller = Phone::new().await;
    let toward_engine = rig.answer_local("anchor", &caller, None).await;
    assert!(matches!(
        rig.attach("anchor", X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;

    let mut caller_sent = Vec::new();
    let mut heard_all = Vec::new();
    let mut phase = |sent: Vec<Vec<u8>>, heard: Vec<Vec<u8>>| {
        caller_sent.extend(sent);
        heard_all.extend(heard);
    };
    let (sent, heard) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 1, 8).await;
    phase(sent, heard);
    let taken = rig.attach_bridge("anchor", &first).await;
    assert!(matches!(taken, CmdResult::Ok { .. }), "{taken:?}");
    let (sent, heard) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 9, 8).await;
    phase(sent, heard);
    let moved = rig.attach_bridge("anchor", &second).await;
    assert!(matches!(moved, CmdResult::Ok { .. }), "{moved:?}");
    let (sent, heard) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 17, 8).await;
    phase(sent, heard);
    let detached = rig.detach_bridge("anchor").await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    let (sent, heard) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 25, 8).await;
    phase(sent, heard);

    mdf.read_until(|read| count(read, from_target()) >= caller_sent.len())
        .await;
    assert_all_delivered_once(
        &caller_sent,
        &payloads(&mdf, from_target()),
        "the caller's media",
    );
    assert_heard_was_delivered(&heard_all, &payloads(&mdf, to_target()));
    assert!(!rig.second_connection().await, "one delivery connection");
    assert!(x3_ends(rig.drained_events()).is_empty(), "never ended");
}

/// A re-answer of the same dialog into a `ws_uri` is the hand-over, not the end of the interception.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_answer_into_a_ws_takeover_keeps_the_interception() {
    let rig = Rig::new().await;
    let bot = bot(5).await;
    let caller = Phone::new().await;
    let first = rig.answer_local("again", &caller, None).await;
    assert!(matches!(
        rig.attach("again", X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    let (sent_first, heard_first) = talk(&caller, &caller, first, CALLER_SSRC, 1, 8).await;

    let second = rig.answer_local("again", &caller, Some(&bot)).await;
    let (sent_second, heard) = talk(&caller, &caller, second, CALLER_SSRC, 100, 12).await;

    mdf.read_until(|read| {
        count(read, from_target()) >= sent_first.len() + sent_second.len()
            && count(read, to_target()) >= heard.len()
    })
    .await;
    let delivered_from = payloads(&mdf, from_target());
    assert_all_delivered_once(&sent_first, &delivered_from, "before the re-answer");
    assert_all_delivered_once(&sent_second, &delivered_from, "after the re-answer");
    // The bridge's comfort idle is the first thing it sends: tapped from its first frame.
    assert_new_streams_delivered_from_first(&heard, &heard_first, &payloads(&mdf, to_target()));
    assert!(!rig.second_connection().await, "same delivery connection");
    assert!(
        x3_ends(rig.drained_events()).is_empty(),
        "a re-answer of the same dialog is not the end of the interception"
    );
    rig.delete("again").await;
    assert_eq!(x3_ends(rig.drained_events()), vec![X3EndReason::CallEnded]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_deliveries_on_a_ws_takeover_call_each_get_both_directions() {
    let rig = Rig::new().await;
    let bot = bot(10).await;
    let caller = Phone::new().await;
    let toward_engine = rig.answer_local("two", &caller, Some(&bot)).await;
    assert!(matches!(
        rig.attach("two", X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    let mut first = rig.accept().await;
    assert!(matches!(
        rig.attach_second("two", X3TargetLeg::Callee).await,
        CmdResult::Ok { .. }
    ));
    let mut second = rig.accept_second().await;

    let (sent, heard) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 1, 25).await;
    first
        .read_until(|read| {
            count(read, from_target()) >= sent.len() && count(read, to_target()) >= heard.len()
        })
        .await;
    second
        .read_until(|read| {
            count(read, to_target()) >= sent.len() && count(read, from_target()) >= heard.len()
        })
        .await;
    assert_eq!(payloads(&first, from_target())[..sent.len()], sent[..]);
    assert_heard_was_delivered(&heard, &payloads(&first, to_target()));
    assert_eq!(
        payloads(&second, to_target())[..sent.len()],
        sent[..],
        "the callee-target warrant mirrors the directions"
    );
    assert_heard_was_delivered(&heard, &payloads(&second, from_target()));
}

/// The server ending the bridge leaves the call up and the session attached; the delete ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridge_ended_by_the_server_leaves_the_interception_until_the_delete() {
    let rig = Rig::new().await;
    let bot = bot(3).await;
    let caller = Phone::new().await;
    let toward_engine = rig.answer_local("ended", &caller, Some(&bot)).await;
    assert!(matches!(
        rig.attach("ended", X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    let (sent, _) = talk(&caller, &caller, toward_engine, CALLER_SSRC, 1, 6).await;

    bot.close.send(()).expect("close the bot");
    let deadline = tokio::time::Instant::now() + SHORT;
    let mut bridge_ended = false;
    while !bridge_ended && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        bridge_ended = rig
            .drained_events()
            .iter()
            .any(|event| matches!(event, Event::WsBridgeEnded { .. }));
    }
    assert!(bridge_ended, "the bridge reported its end");
    mdf.read_until(|read| count(read, from_target()) >= sent.len())
        .await;
    assert!(
        x3_ends(rig.drained_events()).is_empty(),
        "the session stays while the call is up"
    );
    rig.delete("ended").await;
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![X3EndReason::CallEnded],
        "x3_ended call_ended at the delete, no earlier end"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_info_advertises_ws_takeover_interception_only_with_x3() {
    let features = |result: CmdResult| match result {
        CmdResult::NodeInfo { node } => node.features,
        other => panic!("node_info answers a node: {other:?}"),
    };
    let rig = Rig::new().await;
    assert!(features(rig.send(Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_ws_takeover"));
    let bare = Engine::new(Datapath::new());
    assert!(!features(bare.handle(CLIENT, Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_ws_takeover"));
}

/// The caller streams four RTP packets a millisecond, as fast as the loopback datapath carries them
/// without loss, across `switch` (a control step that moves the call between a relay or the engine's
/// pipeline and a bridge). Every packet the caller sent is warranted content the engine accepted, so
/// the Mediation Function must see each exactly once, with no gap at the switch and no duplicate
/// while two paths are briefly both tapped. Returns what was sent.
async fn stream_across<F: std::future::Future>(
    caller: &std::sync::Arc<Phone>,
    toward: SocketAddr,
    switch: F,
) -> Vec<Vec<u8>> {
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let streamer = {
        let (caller, running) = (caller.clone(), running.clone());
        tokio::spawn(async move {
            let mut sent = Vec::new();
            let mut sequence = 1u16;
            while running.load(std::sync::atomic::Ordering::Relaxed) {
                // A burst a tick, so the stream is dense enough to land in a window of tens of
                // microseconds.
                for _ in 0..4 {
                    let packet = rtp_from(CALLER_SSRC, sequence);
                    caller.send(&packet, toward).await;
                    sent.push(packet);
                    sequence += 1;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            sent
        })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = switch.await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    streamer.await.expect("the stream task")
}

async fn assert_no_gap(mdf: &mut Mdf, sent: &[Vec<u8>], what: &str) {
    // The engine's own egress (comfort noise, the bot) keeps the connection busy, so read for a fixed
    // grace after the last packet was sent rather than until idle: long enough for a duplicate to
    // show up.
    mdf.read_until(|read| count(read, from_target()) >= sent.len())
        .await;
    let until = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Some(pdu) = mdf.stream.next_within(Duration::from_millis(50)).await {
        mdf.check(&pdu);
        if tokio::time::Instant::now() > until {
            break;
        }
    }
    assert_all_delivered_once(sent, &payloads(mdf, from_target()), what);
}

async fn intercepted_relay(rig: &Rig, call: &str, caller: &Phone) -> (SocketAddr, Mdf) {
    let callee = Phone::new().await;
    let offer = rig
        .send(Command::Offer {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
            sdp: plain_sdp(caller.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "{offer:?}");
    let answer = rig
        .send(Command::Answer {
            call_id: call.into(),
            from_tag: FROM_TAG.into(),
            to_tag: "tag-b".into(),
            sdp: plain_sdp(callee.address, "sendrecv"),
            profile: ProfileFlags::default(),
        })
        .await;
    let toward = Rig::engine_address(&answer);
    assert!(matches!(
        rig.attach(call, X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    (toward, rig.accept().await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taking_an_intercepted_relay_over_misses_no_packet_of_a_continuous_stream() {
    let rig = Rig::new().await;
    let bot = bot(2).await;
    let caller = std::sync::Arc::new(Phone::new().await);
    let (toward, mut mdf) = intercepted_relay(&rig, "relay-over", &caller).await;
    let sent = stream_across(&caller, toward, rig.attach_bridge("relay-over", &bot)).await;
    assert_no_gap(&mut mdf, &sent, "across the takeover of the relay").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_a_bridge_back_to_an_intercepted_relay_misses_no_packet() {
    let rig = Rig::new().await;
    let bot = bot(2).await;
    let caller = std::sync::Arc::new(Phone::new().await);
    let (toward, mut mdf) = intercepted_relay(&rig, "relay-back", &caller).await;
    assert!(matches!(
        rig.attach_bridge("relay-back", &bot).await,
        CmdResult::Ok { .. }
    ));
    let sent = stream_across(&caller, toward, rig.detach_bridge("relay-back")).await;
    assert_no_gap(&mut mdf, &sent, "across the detach back to the relay").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handing_an_intercepted_anchor_to_a_bot_misses_no_packet_of_a_continuous_stream() {
    let rig = Rig::new().await;
    let bot = bot(2).await;
    let caller = std::sync::Arc::new(Phone::new().await);
    let toward = rig.answer_local("anchor-over", &caller, None).await;
    assert!(matches!(
        rig.attach("anchor-over", X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    let sent = stream_across(&caller, toward, rig.attach_bridge("anchor-over", &bot)).await;
    assert_no_gap(&mut mdf, &sent, "across the hand-over to the bot").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_a_bot_back_to_an_intercepted_anchor_misses_no_packet() {
    let rig = Rig::new().await;
    let bot = bot(2).await;
    let caller = std::sync::Arc::new(Phone::new().await);
    let toward = rig.answer_local("anchor-back", &caller, None).await;
    assert!(matches!(
        rig.attach("anchor-back", X3TargetLeg::Caller).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    assert!(matches!(
        rig.attach_bridge("anchor-back", &bot).await,
        CmdResult::Ok { .. }
    ));
    let sent = stream_across(&caller, toward, rig.detach_bridge("anchor-back")).await;
    assert_no_gap(&mut mdf, &sent, "across the hand-back to the engine").await;
}
