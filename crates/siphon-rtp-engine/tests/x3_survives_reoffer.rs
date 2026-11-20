//! A lawful interception belongs to the **call**, not to one negotiation of it (ETSI TS 103 221-2,
//! X3).
//!
//! A hold, a resume, a session refresh carrying SDP: each is a re-offer, and the answer to it
//! rebuilds the call's media path. The interception's taps, its delivery connection, its
//! Correlation ID and its PDU sequence counter must all come through that rebuild, so the Mediation
//! Function sees one unbroken stream. These tests drive the real engine over the UDP-loopback
//! datapath against a stub Mediation Function behind mutual TLS.
//!
//! The sequence numbers asserted below are the proof: they are per delivery connection, so one
//! counting straight on across a re-offer means the same connection carried it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::net::SocketAddr;

use common::x3_mdf::{acceptor, attribute, pki, read_pdus, rtp, Pki, CORRELATION_ID, SHORT};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_li::attributes::attribute_type;
use siphon_rtp_li::PayloadDirection;
use siphon_rtp_proto::{CmdResult, Command, Event, ProfileFlags, X3EndReason, X3TargetLeg, Xid};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";

/// One engine, one stub Mediation Function, two phones and the owner's event stream.
struct Rig {
    engine: Engine<Datapath>,
    pki: Pki,
    listener: TcpListener,
    events: flume::Receiver<Event>,
    phone_a: UdpSocket,
    phone_b: UdpSocket,
    call: &'static str,
}

impl Rig {
    async fn new(call: &'static str) -> Self {
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
            phone_a: UdpSocket::bind("127.0.0.2:0").await.expect("bind a"),
            phone_b: UdpSocket::bind("127.0.0.3:0").await.expect("bind b"),
            call,
        }
    }

    fn addr_a(&self) -> SocketAddr {
        self.phone_a.local_addr().expect("a addr")
    }

    fn addr_b(&self) -> SocketAddr {
        self.phone_b.local_addr().expect("b addr")
    }

    async fn send(&self, command: Command) -> CmdResult {
        self.engine.handle(CLIENT, command).await
    }

    /// The engine address a party sends to, read from the SDP the engine returned.
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

    async fn offer(&self, sdp: String, profile: ProfileFlags) -> SocketAddr {
        let result = self
            .send(Command::Offer {
                call_id: self.call.into(),
                from_tag: "tag-a".into(),
                sdp,
                profile,
            })
            .await;
        Self::engine_address(&result)
    }

    /// A re-offer from A (a hold, a resume, a session refresh): the same call, renegotiated.
    async fn reoffer(&self, sdp: String, profile: ProfileFlags) -> SocketAddr {
        let result = self
            .send(Command::Reoffer {
                call_id: self.call.into(),
                from_tag: "tag-a".into(),
                sdp,
                profile,
            })
            .await;
        Self::engine_address(&result)
    }

    async fn answer(&self, sdp: String) -> SocketAddr {
        let result = self
            .send(Command::Answer {
                call_id: self.call.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp,
                profile: ProfileFlags::default(),
            })
            .await;
        Self::engine_address(&result)
    }

    async fn attach(&self) -> CmdResult {
        self.attach_targeting(X3TargetLeg::Caller).await
    }

    async fn attach_targeting(&self, target_leg: X3TargetLeg) -> CmdResult {
        self.send(Command::AttachX3 {
            call_id: self.call.into(),
            from_tag: "tag-a".into(),
            delivery: self.listener.local_addr().expect("mdf addr").to_string(),
            xid: XID_TEXT.parse::<Xid>().expect("xid"),
            correlation_id: CORRELATION_ID,
            target_leg,
        })
        .await
    }

    /// Accept the delivery connection the engine opens and finish the mutual-TLS handshake.
    async fn accept(&self) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
        let acceptor = acceptor(&self.pki);
        let (stream, _) = timeout(SHORT, self.listener.accept())
            .await
            .expect("the engine connects to the mediation function")
            .expect("accept");
        timeout(SHORT, acceptor.accept(stream))
            .await
            .expect("no timeout")
            .expect("mutual TLS handshake")
    }

    /// Every event the owner has been sent so far.
    fn drained_events(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }

    async fn delete(&self) {
        let result = self
            .send(Command::Delete {
                call_id: self.call.into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(result, CmdResult::Ok { .. }), "delete: {result:?}");
    }
}

/// A plain `RTP/AVP` PCMU session description for one phone, with a direction attribute.
fn plain_sdp(address: SocketAddr, direction: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={direction}\r\n",
        ip = address.ip(),
        port = address.port(),
    )
}

/// An `RTP/SAVP` answer for one phone carrying `crypto`, in `payload_type`/`name`.
fn savp_sdp(address: SocketAddr, payload_type: u8, name: &str, crypto: &CryptoAttribute) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP {payload_type}\r\na=rtpmap:{payload_type} {name}/8000\r\n\
         a=rtcp-mux\r\na={crypto}\r\n",
        ip = address.ip(),
        port = address.port(),
        crypto = crypto.to_attribute_value(),
    )
}

fn sequence_of(pdu: &common::x3_mdf::DecodedPdu) -> u32 {
    let value = attribute(&pdu.attributes, attribute_type::SEQUENCE_NUMBER).expect("sequence");
    u32::from_be_bytes([value[0], value[1], value[2], value[3]])
}

fn rtp_sequence_of(pdu: &common::x3_mdf::DecodedPdu) -> u16 {
    u16::from_be_bytes([pdu.payload[2], pdu.payload[3]])
}

/// Send `sequences` from phone A toward the engine and read the PDUs they produce, asserting each
/// carries the interception's Correlation ID and that the connection's sequence counter continues
/// from `next_sequence`. Returns the counter's next value.
async fn expect_from_a<S>(
    rig: &Rig,
    tls: &mut S,
    toward: SocketAddr,
    sequences: &[u16],
    mut next_sequence: u32,
) -> u32
where
    S: tokio::io::AsyncRead + Unpin,
{
    for sequence in sequences {
        rig.phone_a
            .send_to(&rtp(*sequence), toward)
            .await
            .expect("a sends");
    }
    let pdus = read_pdus(tls, sequences.len()).await;
    for (pdu, sequence) in pdus.iter().zip(sequences) {
        assert_eq!(pdu.header.correlation_id, CORRELATION_ID, "same CID");
        assert_eq!(rtp_sequence_of(pdu), *sequence, "the packet that was sent");
        assert_eq!(
            pdu.header.payload_direction,
            PayloadDirection::FromTarget.to_u16()
        );
        assert_eq!(
            sequence_of(pdu),
            next_sequence,
            "the delivery connection's sequence counter continues across the re-offer"
        );
        next_sequence += 1;
    }
    next_sequence
}

fn assert_no_x3_end(events: &[Event], when: &str) {
    for event in events {
        assert!(
            !matches!(event, Event::X3Ended { .. }),
            "the interception ended {when} although the call goes on: {event:?}"
        );
    }
}

/// Re-offer from A (`direction` toward B) and the answer to it (`answer_direction`), keeping
/// everything else about the session.
async fn renegotiate(rig: &Rig, direction: &str, answer_direction: &str) {
    rig.reoffer(plain_sdp(rig.addr_a(), direction), ProfileFlags::default())
        .await;
    rig.answer(plain_sdp(rig.addr_b(), answer_direction)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x3_survives_a_hold_and_a_resume_on_a_plain_relay() {
    let rig = Rig::new("x3-hold-resume").await;
    let toward_b = rig
        .offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    let toward_a = rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;

    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut tls = rig.accept().await;

    let mut next = expect_from_a(&rig, &mut tls, toward_a, &[1, 2, 3], 0).await;

    // Hold: A re-offers sendonly, B answers recvonly.
    renegotiate(&rig, "sendonly", "recvonly").await;
    next = expect_from_a(&rig, &mut tls, toward_a, &[4, 5], next).await;
    assert_no_x3_end(&rig.drained_events(), "at the hold");

    // Resume: sendrecv both ways. Content flows in both directions again.
    renegotiate(&rig, "sendrecv", "sendrecv").await;
    next = expect_from_a(&rig, &mut tls, toward_a, &[6], next).await;
    rig.phone_b
        .send_to(&rtp(500), toward_b)
        .await
        .expect("b sends");
    let pdus = read_pdus(&mut tls, 1).await;
    assert_eq!(rtp_sequence_of(&pdus[0]), 500);
    assert_eq!(sequence_of(&pdus[0]), next);
    assert_eq!(pdus[0].header.correlation_id, CORRELATION_ID);
    assert_eq!(
        pdus[0].header.payload_direction,
        PayloadDirection::ToTarget.to_u16()
    );
    assert_no_x3_end(&rig.drained_events(), "at the resume");

    // A second hold/resume cycle: still the same connection, still counting.
    renegotiate(&rig, "sendonly", "recvonly").await;
    expect_from_a(&rig, &mut tls, toward_a, &[7], next + 1).await;
    assert_no_x3_end(&rig.drained_events(), "at the second hold");

    // The call really ending is what ends the interception.
    rig.delete().await;
    let ended: Vec<_> = rig
        .drained_events()
        .into_iter()
        .filter_map(|event| match event {
            Event::X3Ended {
                reason, delivered, ..
            } => Some((reason, delivered)),
            _ => None,
        })
        .collect();
    assert_eq!(
        ended,
        vec![(X3EndReason::CallEnded, 8)],
        "exactly one end event, naming the call, counting every PDU across the re-offers"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x3_survives_a_session_refresh_re_offer_with_unchanged_sdp() {
    // A carrier's session refresh restates the same session; it must not cost the interception.
    let rig = Rig::new("x3-refresh").await;
    rig.offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    let toward_a = rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;
    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut tls = rig.accept().await;

    let next = expect_from_a(&rig, &mut tls, toward_a, &[1], 0).await;
    renegotiate(&rig, "sendrecv", "sendrecv").await;
    expect_from_a(&rig, &mut tls, toward_a, &[2], next).await;
    assert_no_x3_end(&rig.drained_events(), "at the session refresh");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_attach_replaces_the_first_and_delivers_at_once() {
    // The re-attach a controller issues after it saw an interception end must not die on arrival:
    // replacing a live interception stops the old one first, then installs the new taps, never the
    // other way round (which removed the very taps it had just installed).
    let rig = Rig::new("x3-replace").await;
    rig.offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    let toward_a = rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;

    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut first = rig.accept().await;
    let next = expect_from_a(&rig, &mut first, toward_a, &[1], 0).await;
    assert_eq!(next, 1);

    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut second = rig.accept().await;
    expect_from_a(&rig, &mut second, toward_a, &[2, 3], 0).await;

    let reasons: Vec<_> = rig
        .drained_events()
        .into_iter()
        .filter_map(|event| match event {
            Event::X3Ended { reason, .. } => Some(reason),
            _ => None,
        })
        .collect();
    assert_eq!(
        reasons,
        vec![X3EndReason::Detached],
        "the replaced interception reports why it ended, and the new one has not ended"
    );
}

/// A call whose B leg is `RTP/SAVP`, so the engine terminates SRTP toward B.
async fn secure_call(call: &'static str, codec_b: (u8, &str)) -> (Rig, SocketAddr, SocketAddr) {
    let rig = Rig::new(call).await;
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    let toward_b = rig
        .offer(plain_sdp(rig.addr_a(), "sendrecv"), profile.clone())
        .await;
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let toward_a = rig
        .answer(savp_sdp(rig.addr_b(), codec_b.0, codec_b.1, &b_key))
        .await;
    (rig, toward_a, toward_b)
}

async fn secure_renegotiate(rig: &Rig, codec_b: (u8, &str), direction: &str) {
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    rig.reoffer(plain_sdp(rig.addr_a(), direction), profile)
        .await;
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let answer = savp_sdp(rig.addr_b(), codec_b.0, codec_b.1, &b_key);
    rig.answer(answer.replace("a=rtcp-mux", &format!("a=rtcp-mux\r\na={direction}")))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x3_survives_a_hold_and_a_resume_on_an_srtp_bridge() {
    // Same codec on both sides: an SDES bridge that relays without decoding, tapped on the bridge.
    let (rig, toward_a, _) = secure_call("x3-srtp-bridge", (0, "PCMU")).await;
    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut tls = rig.accept().await;

    let mut next = expect_from_a(&rig, &mut tls, toward_a, &[1, 2], 0).await;
    secure_renegotiate(&rig, (0, "PCMU"), "sendonly").await;
    next = expect_from_a(&rig, &mut tls, toward_a, &[3], next).await;
    secure_renegotiate(&rig, (0, "PCMU"), "sendrecv").await;
    expect_from_a(&rig, &mut tls, toward_a, &[4], next).await;
    assert_no_x3_end(&rig.drained_events(), "across the SRTP bridge re-offers");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x3_survives_a_hold_and_a_resume_on_a_secure_transcode() {
    // A different codec on the secure side makes this a transcoding pipeline with SRTP, so the
    // interception sits in the media actor the answer to each re-offer replaces.
    let (rig, toward_a, _) = secure_call("x3-srtp-media", (8, "PCMA")).await;
    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut tls = rig.accept().await;

    let mut next = expect_from_a(&rig, &mut tls, toward_a, &[1, 2], 0).await;
    secure_renegotiate(&rig, (8, "PCMA"), "sendonly").await;
    next = expect_from_a(&rig, &mut tls, toward_a, &[3], next).await;
    secure_renegotiate(&rig, (8, "PCMA"), "sendrecv").await;
    expect_from_a(&rig, &mut tls, toward_a, &[4], next).await;
    assert_no_x3_end(
        &rig.drained_events(),
        "across the secure transcode re-offers",
    );
}

fn timestamp_nanos(pdu: &common::x3_mdf::DecodedPdu) -> u64 {
    let value = attribute(&pdu.attributes, attribute_type::TIMESTAMP).expect("timestamp");
    let seconds = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    let nanoseconds = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
    u64::from(seconds) * 1_000_000_000 + u64::from(nanoseconds)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_x3_timestamp_is_interception_time_on_the_udp_datapath() {
    // TS 103 221-2 clause 5.3: the Timestamp is when the content was intercepted. The loopback
    // datapath's receive clock is a logical one that only ticks with the media-timeout sweep (one
    // tick per wall second, worth 20 ms), so deriving the stamp from it squeezed seconds of real
    // traffic into milliseconds. Packets sent 200 ms apart on the wall clock must be stamped about
    // 200 ms apart.
    let rig = Rig::new("x3-timestamp").await;
    rig.offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    let toward_a = rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;
    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut tls = rig.accept().await;

    for sequence in 1..=3u16 {
        rig.phone_a
            .send_to(&rtp(sequence), toward_a)
            .await
            .expect("a sends");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let pdus = read_pdus(&mut tls, 3).await;
    let spread = timestamp_nanos(&pdus[2]).saturating_sub(timestamp_nanos(&pdus[0]));
    assert!(
        (350_000_000..2_000_000_000).contains(&spread),
        "two packets 400 ms apart were stamped {} ms apart",
        spread / 1_000_000
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interception_attached_at_the_offer_delivers_from_the_first_answered_packet() {
    // A content warrant can match before the callee answers; the interception is taken at the
    // offer and its taps go onto the media path the first answer installs.
    let rig = Rig::new("x3-at-offer").await;
    rig.offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    let attached = rig.attach().await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach on an offered call: {attached:?}"
    );
    let mut tls = rig.accept().await;
    let toward_a = rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;
    expect_from_a(&rig, &mut tls, toward_a, &[1, 2], 0).await;
    assert_no_x3_end(&rig.drained_events(), "at the answer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_media_and_the_final_answer_share_one_delivery() {
    // A 183 with SDP is answered first, the 200 OK after it: one connection, one Correlation ID,
    // one unbroken sequence across both.
    let rig = Rig::new("x3-early-media").await;
    let toward_b = rig
        .offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let mut tls = rig.accept().await;
    rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;
    rig.phone_b
        .send_to(&rtp(700), toward_b)
        .await
        .expect("early media from b");
    let early = read_pdus(&mut tls, 1).await;
    assert_eq!(rtp_sequence_of(&early[0]), 700);
    assert_eq!(sequence_of(&early[0]), 0);
    assert_eq!(early[0].header.correlation_id, CORRELATION_ID);
    assert_eq!(
        early[0].header.payload_direction,
        PayloadDirection::ToTarget.to_u16()
    );
    let toward_a = rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;
    expect_from_a(&rig, &mut tls, toward_a, &[1, 2], 1).await;
    assert_no_x3_end(&rig.drained_events(), "at the final answer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callee_target_attached_before_the_callee_exists_is_tapped_as_the_target() {
    let rig = Rig::new("x3-callee-at-offer").await;
    let toward_b = rig
        .offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    assert!(matches!(
        rig.attach_targeting(X3TargetLeg::Callee).await,
        CmdResult::Ok { .. }
    ));
    let mut tls = rig.accept().await;
    rig.answer(plain_sdp(rig.addr_b(), "sendrecv")).await;
    rig.phone_b
        .send_to(&rtp(42), toward_b)
        .await
        .expect("b sends");
    let pdus = read_pdus(&mut tls, 1).await;
    assert_eq!(rtp_sequence_of(&pdus[0]), 42);
    assert_eq!(
        pdus[0].header.payload_direction,
        PayloadDirection::FromTarget.to_u16(),
        "the callee is the target, so its own packets are from the target"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interception_on_a_call_deleted_unanswered_ends_with_the_call() {
    let rig = Rig::new("x3-unanswered").await;
    rig.offer(plain_sdp(rig.addr_a(), "sendrecv"), ProfileFlags::default())
        .await;
    assert!(matches!(rig.attach().await, CmdResult::Ok { .. }));
    let _tls = rig.accept().await;
    rig.delete().await;
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(X3EndReason::CallEnded, 0)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_info_advertises_attach_at_offer_only_on_a_node_provisioned_for_x3() {
    let features = |result: CmdResult| match result {
        CmdResult::NodeInfo { node } => node.features,
        other => panic!("node_info answers a node: {other:?}"),
    };
    let rig = Rig::new("x3-feature").await;
    assert!(features(rig.send(Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_attach_at_offer"));
    let bare = Engine::new(Datapath::new());
    assert!(!features(bare.handle(CLIENT, Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_attach_at_offer"));
}
