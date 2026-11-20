//! Several lawful-interception deliveries on one call (ETSI TS 103 221-2, X3).
//!
//! A call can be intercepted under more than one warrant, or by one warrant to more than one
//! Mediation Function, or under one warrant twice when two calls covered by it are bridged onto one
//! engine call (each keeps its own LI session and Correlation ID). Each `attach_x3` with a new
//! (`xid`, `delivery`, `correlation_id`) triple adds a delivery with its own connection, PDU sequence
//! counter and target leg; the same triple replaces only itself. `detach_x3` takes an optional `xid`,
//! `delivery` and `correlation_id` and ends exactly what they name, each ending delivery reporting one
//! `x3_ended` that names it.
//!
//! These tests drive the real engine over the UDP-loopback datapath against stub Mediation
//! Functions behind mutual TLS (one listener per delivery address, one PKI).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::x3_mdf::{
    acceptor, from_target, pdu_sequence, pki, plain_sdp, rtp_from, rtp_sequence, to_target,
    DecodedPdu, PduStream, Phone, Pki, Tls, SHORT,
};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command, Event, ProfileFlags, X3EndReason, X3TargetLeg, Xid};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use tokio::net::TcpListener;
use tokio::time::timeout;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const CALL: &str = "multi";
const FROM_TAG: &str = "tag-a";
const A_SSRC: u32 = 0x0A0A_0A0A;
const B_SSRC: u32 = 0x0B0B_0B0B;

fn xid(text: &str) -> Xid {
    text.parse().expect("xid")
}

fn xid_one() -> Xid {
    xid("8c292fa1-5831-46ec-86be-bd85f2083299")
}

fn xid_two() -> Xid {
    xid("1f0e0d0c-0b0a-4908-8706-050403020100")
}

/// An `RTP/SAVP` PCMU session description for one phone carrying `crypto`.
fn savp_sdp(address: SocketAddr, crypto: &CryptoAttribute, direction: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         a={direction}\r\na={crypto}\r\n",
        ip = address.ip(),
        port = address.port(),
        crypto = crypto.to_attribute_value(),
    )
}

/// One stub Mediation Function: its listener and, once the engine has dialled, the connection.
struct Mdf {
    /// Shared by the sessions of one delivery address ([`Mdf::second_session`]).
    listener: Arc<TcpListener>,
    correlation_id: u64,
    stream: Option<PduStream<Tls>>,
    next_sequence: u32,
    /// Every PDU read: direction and RTP payload.
    seen: Vec<(u16, Vec<u8>)>,
}

impl Mdf {
    async fn new(correlation_id: u64) -> Self {
        Self {
            listener: Arc::new(TcpListener::bind("127.0.0.1:0").await.expect("bind mdf")),
            correlation_id,
            stream: None,
            next_sequence: 0,
            seen: Vec::new(),
        }
    }

    /// A second LI session at the same delivery address, under its own Correlation ID: the engine
    /// opens a connection of its own for it on the same listener.
    fn second_session(&self, correlation_id: u64) -> Self {
        Self {
            listener: Arc::clone(&self.listener),
            correlation_id,
            stream: None,
            next_sequence: 0,
            seen: Vec::new(),
        }
    }

    fn address(&self) -> String {
        self.listener.local_addr().expect("mdf addr").to_string()
    }

    async fn accept(&mut self, pki: &Pki) {
        let acceptor = acceptor(pki);
        let (stream, _) = timeout(SHORT, self.listener.accept())
            .await
            .expect("the engine connects to the mediation function")
            .expect("accept");
        let tls: Tls = timeout(SHORT, acceptor.accept(stream))
            .await
            .expect("no timeout")
            .expect("mutual TLS handshake");
        self.stream = Some(PduStream::new(tls));
    }

    /// Check one PDU against this delivery's invariants: its own Correlation ID, its warrant's XID
    /// and a sequence counter without a gap.
    fn check(&mut self, pdu: &DecodedPdu, expected_xid: Xid) {
        assert_eq!(pdu.header.correlation_id, self.correlation_id, "own CID");
        assert_eq!(&pdu.header.xid, expected_xid.as_bytes(), "own XID");
        assert_eq!(
            pdu_sequence(pdu),
            self.next_sequence,
            "this delivery's sequence counter continues without a gap"
        );
        self.next_sequence += 1;
        self.seen
            .push((pdu.header.payload_direction, pdu.payload.clone()));
    }

    /// Read until `done` is satisfied by what has been read since the call, checking every PDU.
    async fn read_until(&mut self, expected_xid: Xid, done: impl Fn(&[(u16, Vec<u8>)]) -> bool) {
        let start = self.seen.len();
        while !done(&self.seen[start..]) {
            let stream = self.stream.as_mut().expect("connected");
            let pdu = stream.next().await;
            self.check(&pdu, expected_xid);
        }
    }

    /// Whether any further PDU arrives within `wait`.
    async fn receives_more(&mut self, wait: Duration) -> bool {
        let stream = self.stream.as_mut().expect("connected");
        stream.next_within(wait).await.is_some()
    }

    fn count(&self, direction: u16, ssrc: u32) -> usize {
        self.seen
            .iter()
            .filter(|(read, payload)| {
                *read == direction && common::x3_mdf::ssrc_of(payload) == ssrc
            })
            .count()
    }

    /// The RTP sequence numbers delivered in `direction` for `ssrc`, in arrival order.
    fn rtp_sequences(&self, direction: u16, ssrc: u32) -> Vec<u16> {
        self.seen
            .iter()
            .filter(|(read, payload)| {
                *read == direction && common::x3_mdf::ssrc_of(payload) == ssrc
            })
            .map(|(_, payload)| rtp_sequence(payload))
            .collect()
    }
}

struct Rig {
    engine: Engine<Datapath>,
    pki: Pki,
    events: flume::Receiver<Event>,
    phone_a: Phone,
    phone_b: Phone,
    toward_b: SocketAddr,
    toward_a: SocketAddr,
}

impl Rig {
    /// A plain two-party relay call, answered.
    async fn new() -> Self {
        Self::with_transport(None).await
    }

    /// A call whose B leg is `RTP/SAVP`, so the engine terminates SRTP toward B on a bridge that
    /// relays without decoding (the same codec on both sides).
    async fn secure() -> Self {
        Self::with_transport(Some(
            CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key"),
        ))
        .await
    }

    async fn with_transport(secure_b: Option<CryptoAttribute>) -> Self {
        let pki = pki();
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
        let phone_a = Phone::new().await;
        let phone_b = Phone::new().await;
        let mut rig = Self {
            engine,
            pki,
            events,
            phone_a,
            phone_b,
            toward_b: "127.0.0.1:9".parse().expect("placeholder"),
            toward_a: "127.0.0.1:9".parse().expect("placeholder"),
        };
        let offered = rig
            .send(Command::Offer {
                call_id: CALL.into(),
                from_tag: FROM_TAG.into(),
                sdp: plain_sdp(rig.phone_a.address, "sendrecv"),
                profile: Self::profile(secure_b.is_some()),
            })
            .await;
        rig.toward_b = Self::engine_address(&offered);
        let answered = rig
            .send(Command::Answer {
                call_id: CALL.into(),
                from_tag: FROM_TAG.into(),
                to_tag: "tag-b".into(),
                sdp: match &secure_b {
                    Some(key) => savp_sdp(rig.phone_b.address, key, "sendrecv"),
                    None => plain_sdp(rig.phone_b.address, "sendrecv"),
                },
                profile: ProfileFlags::default(),
            })
            .await;
        rig.toward_a = Self::engine_address(&answered);
        rig
    }

    fn profile(secure: bool) -> ProfileFlags {
        ProfileFlags {
            transport_protocol: secure.then(|| "RTP/SAVP".to_string()),
            ..Default::default()
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

    async fn attach(
        &self,
        mdf: &Mdf,
        task: Xid,
        correlation_id: u64,
        target_leg: X3TargetLeg,
    ) -> CmdResult {
        self.send(Command::AttachX3 {
            call_id: CALL.into(),
            from_tag: FROM_TAG.into(),
            delivery: mdf.address(),
            xid: task,
            correlation_id,
            target_leg,
        })
        .await
    }

    async fn detach(
        &self,
        task: Option<Xid>,
        delivery: Option<String>,
        correlation_id: Option<u64>,
    ) -> CmdResult {
        self.send(Command::DetachX3 {
            call_id: CALL.into(),
            from_tag: FROM_TAG.into(),
            xid: task,
            delivery,
            correlation_id,
        })
        .await
    }

    /// A sends `sequences` toward the engine and B sends the same, 20 ms apart.
    async fn both_talk(&self, sequences: std::ops::Range<u16>) {
        for sequence in sequences {
            self.phone_a
                .send(&rtp_from(A_SSRC, sequence), self.toward_a)
                .await;
            self.phone_b
                .send(&rtp_from(B_SSRC, sequence), self.toward_b)
                .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn drained_events(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }

    /// Every `x3_ended`, as (xid, delivery, correlation id, reason).
    fn ends(&self) -> Vec<(Xid, String, u64, X3EndReason)> {
        self.drained_events()
            .into_iter()
            .filter_map(|event| match event {
                Event::X3Ended {
                    xid,
                    delivery,
                    correlation_id,
                    reason,
                    ..
                } => Some((
                    xid.expect("the engine always names the warrant"),
                    delivery.expect("the engine always names the delivery"),
                    correlation_id.expect("the engine always names the session"),
                    reason,
                )),
                _ => None,
            })
            .collect()
    }

    async fn delete(&self) {
        let result = self
            .send(Command::Delete {
                call_id: CALL.into(),
                from_tag: FROM_TAG.into(),
                to_tag: None,
            })
            .await;
        assert!(matches!(result, CmdResult::Ok { .. }), "delete: {result:?}");
    }
}

/// Attach `xid` with `correlation_id` toward a fresh stub MDF and accept the connection.
async fn attach_and_accept(
    rig: &Rig,
    task: Xid,
    correlation_id: u64,
    target_leg: X3TargetLeg,
) -> Mdf {
    let mut mdf = Mdf::new(correlation_id).await;
    let attached = rig.attach(&mdf, task, correlation_id, target_leg).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    mdf.accept(&rig.pki).await;
    mdf
}

const CID_ONE: u64 = 0x0102_0304_0506_0708;
const CID_TWO: u64 = 0x1112_1314_1516_1718;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_warrants_on_one_call_each_get_both_directions_with_their_own_cid_and_sequence() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Caller).await;

    rig.both_talk(1..6).await;

    for (mdf, task) in [(&mut first, xid_one()), (&mut second, xid_two())] {
        mdf.read_until(task, |read| read.len() >= 10).await;
        assert_eq!(mdf.count(from_target(), A_SSRC), 5, "what A sent");
        assert_eq!(mdf.count(to_target(), B_SSRC), 5, "what B sent");
        assert_eq!(
            mdf.rtp_sequences(from_target(), A_SSRC),
            vec![1, 2, 3, 4, 5]
        );
        assert!(
            !mdf.receives_more(Duration::from_millis(300)).await,
            "each packet is delivered once to each delivery"
        );
    }
    assert!(rig.ends().is_empty(), "both still attached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_warrant_can_deliver_to_two_mediation_functions() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_one(), CID_TWO, X3TargetLeg::Caller).await;

    rig.both_talk(1..4).await;
    first.read_until(xid_one(), |read| read.len() >= 6).await;
    second.read_until(xid_one(), |read| read.len() >= 6).await;
    assert_eq!(first.correlation_id, CID_ONE);
    assert_eq!(second.correlation_id, CID_TWO);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detaching_by_xid_ends_only_that_warrant_and_the_other_continues() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Caller).await;
    rig.both_talk(1..4).await;
    first.read_until(xid_one(), |read| read.len() >= 6).await;
    second.read_until(xid_two(), |read| read.len() >= 6).await;

    let detached = rig.detach(Some(xid_one()), None, None).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        rig.ends(),
        vec![(
            xid_one(),
            first.address(),
            first.correlation_id,
            X3EndReason::Detached
        )],
        "exactly one x3_ended, naming the warrant and its delivery"
    );

    // The other delivery carries on uninterrupted: same connection, sequence counting straight on.
    rig.both_talk(4..8).await;
    second.read_until(xid_two(), |read| read.len() >= 8).await;
    assert_eq!(
        second.rtp_sequences(from_target(), A_SSRC),
        vec![1, 2, 3, 4, 5, 6, 7],
        "the surviving delivery lost nothing"
    );
    assert!(rig.ends().is_empty(), "the other delivery has not ended");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detaching_by_xid_and_delivery_ends_exactly_one_of_two_deliveries_of_a_warrant() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_one(), CID_TWO, X3TargetLeg::Caller).await;
    rig.both_talk(1..3).await;
    first.read_until(xid_one(), |read| read.len() >= 4).await;
    second.read_until(xid_one(), |read| read.len() >= 4).await;

    let detached = rig
        .detach(Some(xid_one()), Some(second.address()), None)
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        rig.ends(),
        vec![(
            xid_one(),
            second.address(),
            second.correlation_id,
            X3EndReason::Detached
        )]
    );

    rig.both_talk(3..6).await;
    first.read_until(xid_one(), |read| read.len() >= 6).await;
    assert_eq!(
        first.rtp_sequences(from_target(), A_SSRC),
        vec![1, 2, 3, 4, 5]
    );
}

/// Two warrants can share one Mediation Function, so a delivery address alone does not say which
/// interception to end: it is refused and both keep delivering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detach_naming_only_a_delivery_is_refused_and_ends_nothing() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Caller).await;
    rig.both_talk(1..3).await;
    first.read_until(xid_one(), |read| read.len() >= 4).await;
    second.read_until(xid_two(), |read| read.len() >= 4).await;

    let refused = rig.detach(None, Some(second.address()), None).await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
    assert!(rig.ends().is_empty(), "nothing ended: {:?}", rig.ends());

    rig.both_talk(3..6).await;
    first.read_until(xid_one(), |read| read.len() >= 6).await;
    second.read_until(xid_two(), |read| read.len() >= 6).await;
    assert_eq!(
        first.rtp_sequences(from_target(), A_SSRC),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(
        second.rtp_sequences(from_target(), A_SSRC),
        vec![1, 2, 3, 4, 5]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detaching_with_no_xid_ends_every_delivery_with_one_end_event_each() {
    let rig = Rig::new().await;
    let first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let second = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Caller).await;

    let detached = rig.detach(None, None, None).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    let mut ends = rig.ends();
    ends.sort_by_key(|(task, _, _, _)| *task.as_bytes());
    let mut expected = vec![
        (
            xid_one(),
            first.address(),
            first.correlation_id,
            X3EndReason::Detached,
        ),
        (
            xid_two(),
            second.address(),
            second.correlation_id,
            X3EndReason::Detached,
        ),
    ];
    expected.sort_by_key(|(task, _, _, _)| *task.as_bytes());
    assert_eq!(ends, expected);

    // Idempotent: nothing left to end, no further events.
    assert!(matches!(
        rig.detach(None, None, None).await,
        CmdResult::Ok { .. }
    ));
    assert!(rig.ends().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_attach_of_the_same_xid_and_delivery_replaces_only_that_one() {
    let rig = Rig::new().await;
    let mut kept = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Caller).await;
    // The first warrant delivers to its own MDF; re-attaching the same pair replaces it.
    let mut replaced = Mdf::new(CID_ONE).await;
    assert!(matches!(
        rig.attach(&replaced, xid_one(), CID_ONE, X3TargetLeg::Caller)
            .await,
        CmdResult::Ok { .. }
    ));
    replaced.accept(&rig.pki).await;
    rig.both_talk(1..3).await;
    replaced.read_until(xid_one(), |read| read.len() >= 4).await;
    kept.read_until(xid_two(), |read| read.len() >= 4).await;
    assert!(rig.ends().is_empty());

    // Same pair again: only the first delivery is replaced, with a fresh connection and counter.
    assert!(matches!(
        rig.attach(&replaced, xid_one(), CID_ONE, X3TargetLeg::Caller)
            .await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        rig.ends(),
        vec![(
            xid_one(),
            replaced.address(),
            replaced.correlation_id,
            X3EndReason::Detached
        )],
        "only the replaced delivery reports an end"
    );
    replaced.next_sequence = 0;
    replaced.accept(&rig.pki).await;

    rig.both_talk(3..5).await;
    replaced.read_until(xid_one(), |read| read.len() >= 4).await;
    kept.read_until(xid_two(), |read| read.len() >= 4).await;
    assert_eq!(
        kept.rtp_sequences(from_target(), A_SSRC),
        vec![1, 2, 3, 4],
        "the other delivery never noticed"
    );
    assert!(rig.ends().is_empty());
}

/// Two calls covered by one warrant, bridged onto one engine call: each keeps its own LI session and
/// Correlation ID, so the same warrant and delivery address carry two sessions at once
/// (TS 103 221-2 clause 6: the CID ties X3 to the X2 records of its own session).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_warrant_and_delivery_carry_two_sessions_under_their_own_correlation_ids() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = first.second_session(CID_TWO);
    let attached = rig
        .attach(&second, xid_one(), CID_TWO, X3TargetLeg::Caller)
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    second.accept(&rig.pki).await;
    assert!(rig.ends().is_empty(), "the second session replaced nothing");

    rig.both_talk(1..5).await;
    for mdf in [&mut first, &mut second] {
        mdf.read_until(xid_one(), |read| read.len() >= 8).await;
        assert_eq!(mdf.rtp_sequences(from_target(), A_SSRC), vec![1, 2, 3, 4]);
        assert_eq!(mdf.rtp_sequences(to_target(), B_SSRC), vec![1, 2, 3, 4]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detaching_a_full_triple_ends_exactly_that_session_and_names_its_correlation_id() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = first.second_session(CID_TWO);
    assert!(matches!(
        rig.attach(&second, xid_one(), CID_TWO, X3TargetLeg::Caller)
            .await,
        CmdResult::Ok { .. }
    ));
    second.accept(&rig.pki).await;
    rig.both_talk(1..3).await;
    first.read_until(xid_one(), |read| read.len() >= 4).await;
    second.read_until(xid_one(), |read| read.len() >= 4).await;

    let detached = rig
        .detach(Some(xid_one()), Some(first.address()), Some(CID_TWO))
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        rig.ends(),
        vec![(xid_one(), second.address(), CID_TWO, X3EndReason::Detached)]
    );

    rig.both_talk(3..6).await;
    first.read_until(xid_one(), |read| read.len() >= 6).await;
    assert_eq!(
        first.rtp_sequences(from_target(), A_SSRC),
        vec![1, 2, 3, 4, 5],
        "the session under the other Correlation ID lost nothing"
    );
    assert!(rig.ends().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detaching_a_warrant_and_delivery_ends_every_session_at_that_address() {
    let rig = Rig::new().await;
    let first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = first.second_session(CID_TWO);
    assert!(matches!(
        rig.attach(&second, xid_one(), CID_TWO, X3TargetLeg::Caller)
            .await,
        CmdResult::Ok { .. }
    ));
    second.accept(&rig.pki).await;

    let detached = rig
        .detach(Some(xid_one()), Some(first.address()), None)
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    let mut ends = rig.ends();
    ends.sort_by_key(|(_, _, correlation_id, _)| *correlation_id);
    assert_eq!(
        ends,
        vec![
            (xid_one(), first.address(), CID_ONE, X3EndReason::Detached),
            (xid_one(), first.address(), CID_TWO, X3EndReason::Detached),
        ]
    );
}

/// A Correlation ID is provisioned per warrant over X1, so on its own it does not say which warrant's
/// session to end: refused, and both keep delivering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detach_naming_only_a_correlation_id_is_refused_and_ends_nothing() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Caller).await;

    let refused = rig.detach(None, None, Some(CID_TWO)).await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
    assert!(rig.ends().is_empty(), "nothing ended: {:?}", rig.ends());

    rig.both_talk(1..3).await;
    first.read_until(xid_one(), |read| read.len() >= 4).await;
    second.read_until(xid_two(), |read| read.len() >= 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_warrants_naming_different_legs_get_mirrored_directions() {
    let rig = Rig::new().await;
    let mut caller_target = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut callee_target = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Callee).await;

    rig.both_talk(1..4).await;
    caller_target
        .read_until(xid_one(), |read| read.len() >= 6)
        .await;
    callee_target
        .read_until(xid_two(), |read| read.len() >= 6)
        .await;

    // The same packets, seen from each warrant's target.
    assert_eq!(caller_target.count(from_target(), A_SSRC), 3);
    assert_eq!(caller_target.count(to_target(), B_SSRC), 3);
    assert_eq!(callee_target.count(to_target(), A_SSRC), 3);
    assert_eq!(callee_target.count(from_target(), B_SSRC), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_delivery_survives_a_re_offer_with_the_same_cids_and_unbroken_sequences() {
    let rig = Rig::new().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Callee).await;
    rig.both_talk(1..3).await;
    first.read_until(xid_one(), |read| read.len() >= 4).await;
    second.read_until(xid_two(), |read| read.len() >= 4).await;

    // A hold: A re-offers sendonly, B answers recvonly. The answer rebuilds the media path.
    rig.send(Command::Reoffer {
        call_id: CALL.into(),
        from_tag: FROM_TAG.into(),
        sdp: plain_sdp(rig.phone_a.address, "sendonly"),
        profile: ProfileFlags::default(),
    })
    .await;
    rig.send(Command::Answer {
        call_id: CALL.into(),
        from_tag: FROM_TAG.into(),
        to_tag: "tag-b".into(),
        sdp: plain_sdp(rig.phone_b.address, "recvonly"),
        profile: ProfileFlags::default(),
    })
    .await;

    for sequence in 10..13u16 {
        rig.phone_a
            .send(&rtp_from(A_SSRC, sequence), rig.toward_a)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    first.read_until(xid_one(), |read| read.len() >= 3).await;
    second.read_until(xid_two(), |read| read.len() >= 3).await;
    assert_eq!(
        first.rtp_sequences(from_target(), A_SSRC),
        vec![1, 2, 10, 11, 12],
        "the caller-target delivery carried through the re-offer"
    );
    assert_eq!(
        second.rtp_sequences(to_target(), A_SSRC),
        vec![1, 2, 10, 11, 12],
        "the callee-target delivery carried through the re-offer, still mirrored"
    );
    assert!(rig.ends().is_empty(), "a re-offer ends no delivery");

    // The call ending ends every delivery, once each.
    rig.delete().await;
    let ends = rig.ends();
    assert_eq!(ends.len(), 2);
    assert!(ends
        .iter()
        .all(|(_, _, _, reason)| *reason == X3EndReason::CallEnded));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_delivery_survives_a_re_offer_on_an_srtp_bridge() {
    // The taps sit on the crypto bridge's endpoints here, not in a media actor: the whole set has to
    // be carried onto the rebuilt bridge, not just one delivery.
    let rig = Rig::secure().await;
    let mut first = attach_and_accept(&rig, xid_one(), CID_ONE, X3TargetLeg::Caller).await;
    let mut second = attach_and_accept(&rig, xid_two(), CID_TWO, X3TargetLeg::Callee).await;
    rig.phone_a.send(&rtp_from(A_SSRC, 1), rig.toward_a).await;
    first.read_until(xid_one(), |read| !read.is_empty()).await;
    second.read_until(xid_two(), |read| !read.is_empty()).await;

    rig.send(Command::Reoffer {
        call_id: CALL.into(),
        from_tag: FROM_TAG.into(),
        sdp: plain_sdp(rig.phone_a.address, "sendonly"),
        profile: Rig::profile(true),
    })
    .await;
    let key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    rig.send(Command::Answer {
        call_id: CALL.into(),
        from_tag: FROM_TAG.into(),
        to_tag: "tag-b".into(),
        sdp: savp_sdp(rig.phone_b.address, &key, "recvonly"),
        profile: ProfileFlags::default(),
    })
    .await;

    for sequence in 2..5u16 {
        rig.phone_a
            .send(&rtp_from(A_SSRC, sequence), rig.toward_a)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    first.read_until(xid_one(), |read| read.len() >= 3).await;
    second.read_until(xid_two(), |read| read.len() >= 3).await;
    assert_eq!(first.rtp_sequences(from_target(), A_SSRC), vec![1, 2, 3, 4]);
    assert_eq!(second.rtp_sequences(to_target(), A_SSRC), vec![1, 2, 3, 4]);
    assert!(rig.ends().is_empty(), "a re-offer ends no delivery");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_info_advertises_multiple_deliveries_only_with_x3() {
    let features = |result: CmdResult| match result {
        CmdResult::NodeInfo { node } => node.features,
        other => panic!("node_info answers a node: {other:?}"),
    };
    let rig = Rig::new().await;
    assert!(features(rig.send(Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_multi_delivery"));
    let bare = Engine::new(Datapath::new());
    assert!(!features(bare.handle(CLIENT, Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_multi_delivery"));
}
