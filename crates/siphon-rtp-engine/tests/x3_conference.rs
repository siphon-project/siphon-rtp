//! Lawful interception (ETSI TS 103 221-2 X3) of a conference-room seat.
//!
//! A target merged into a room (`conference_seat`) must stay intercepted on the same delivery
//! connection, Correlation ID and PDU sequence, and must not be able to tell: the same merge works
//! with no warrant. In a room the target is the seated party, so what it said is `from_target` and
//! what the room sent it (its own mixed-minus-self stream, never another seat's raw stream) is
//! `to_target`. A seat that joined through `conference_join` has no call, so it is intercepted by
//! naming the room and the seat.
//!
//! These tests drive the real engine over the UDP-loopback datapath against a stub Mediation
//! Function behind mutual TLS.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use common::x3_mdf::{
    acceptor, from_target, pki, plain_sdp, rtp_from, rtp_sequence, ssrc_of, to_target, Mdf,
    PduStream, Phone, Pki, Tls, CORRELATION_ID, SHORT,
};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_li::PayloadDirection;
use siphon_rtp_proto::{
    CmdResult, Command, ConferenceDtmf, ConferenceRole, Event, ProfileFlags, X3EndReason,
    X3TargetLeg, Xid,
};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use siphon_rtp_srtp::SrtpContext;
use tokio::net::TcpListener;
use tokio::time::timeout;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const OTHER_CLIENT: ClientId = ClientId(2);
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";

const TARGET_SSRC: u32 = 0x0A0A_0A0A;
const CALLEE_SSRC: u32 = 0x0B0B_0B0B;
const THIRD_SSRC: u32 = 0x0C0C_0C0C;
const FOURTH_SSRC: u32 = 0x0D0D_0D0D;

struct Rig {
    engine: Engine<Datapath>,
    pki: Pki,
    listener: TcpListener,
    /// A second Mediation Function, for the tests with two deliveries on one call.
    second_listener: TcpListener,
    events: flume::Receiver<Event>,
}

/// A two-party call: `target` is the offerer, `callee` answered.
struct Call {
    id: &'static str,
    target: Phone,
    callee: Phone,
    /// The engine address the target sends to.
    toward_target: SocketAddr,
    /// The engine address the callee sends to.
    toward_callee: SocketAddr,
}

impl Call {
    fn target_tag(&self) -> String {
        format!("{}-target", self.id)
    }

    fn callee_tag(&self) -> String {
        format!("{}-callee", self.id)
    }
}

/// A seat that joined a room.
struct Joined {
    phone: Phone,
    /// The engine address the seat sends to.
    toward_engine: SocketAddr,
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
        let _other = engine.register_client_generation(OTHER_CLIENT);
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

    async fn two_party(&self, id: &'static str) -> Call {
        let target = Phone::new().await;
        let callee = Phone::new().await;
        let offer = self
            .send(Command::Offer {
                call_id: id.into(),
                from_tag: format!("{id}-target"),
                sdp: plain_sdp(target.address, "sendrecv"),
                profile: ProfileFlags::default(),
            })
            .await;
        let toward_callee = Self::engine_address(&offer);
        let answer = self
            .send(Command::Answer {
                call_id: id.into(),
                from_tag: format!("{id}-target"),
                to_tag: format!("{id}-callee"),
                sdp: plain_sdp(callee.address, "sendrecv"),
                profile: ProfileFlags::default(),
            })
            .await;
        let toward_target = Self::engine_address(&answer);
        Call {
            id,
            target,
            callee,
            toward_target,
            toward_callee,
        }
    }

    async fn join(&self, room: &str, tag: &'static str) -> Joined {
        let phone = Phone::new().await;
        let result = self
            .send(Command::ConferenceJoin {
                conference_id: room.into(),
                from_tag: tag.into(),
                sdp: plain_sdp(phone.address, "sendrecv"),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
                dtmf: ConferenceDtmf::Events,
            })
            .await;
        let toward_engine = Self::engine_address(&result);
        Joined {
            phone,
            toward_engine,
        }
    }

    async fn seat(&self, call: &str, tag: &str, room: &str) -> CmdResult {
        self.send(Command::ConferenceSeat {
            call_id: call.into(),
            from_tag: tag.into(),
            conference_id: room.into(),
            role: ConferenceRole::Talker,
            dtmf: ConferenceDtmf::Events,
        })
        .await
    }

    async fn leave(&self, room: &str, tag: &str) -> CmdResult {
        self.send(Command::ConferenceLeave {
            conference_id: room.into(),
            from_tag: tag.into(),
        })
        .await
    }

    fn attach_command(&self, call_id: &str, from_tag: &str, target_leg: X3TargetLeg) -> Command {
        Command::AttachX3 {
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            delivery: self.listener.local_addr().expect("mdf addr").to_string(),
            xid: XID_TEXT.parse::<Xid>().expect("xid"),
            correlation_id: CORRELATION_ID,
            target_leg,
        }
    }

    async fn attach(&self, call_id: &str, from_tag: &str) -> CmdResult {
        self.send(self.attach_command(call_id, from_tag, X3TargetLeg::Caller))
            .await
    }

    /// A second delivery of the same call: another warrant, to the second Mediation Function.
    async fn attach_second(&self, call_id: &str, from_tag: &str) -> CmdResult {
        self.send(Command::AttachX3 {
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            delivery: self
                .second_listener
                .local_addr()
                .expect("mdf addr")
                .to_string(),
            xid: "1f0e0d0c-0b0a-4908-8706-050403020100"
                .parse::<Xid>()
                .expect("xid"),
            correlation_id: CORRELATION_ID,
            target_leg: X3TargetLeg::Caller,
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

    /// Whether the engine opened a second delivery connection.
    async fn second_connection(&self) -> bool {
        timeout(Duration::from_millis(300), self.listener.accept())
            .await
            .is_ok()
    }

    fn drained_events(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }
}

fn x3_ends(events: Vec<Event>) -> Vec<(String, String, X3EndReason)> {
    events
        .into_iter()
        .filter_map(|event| match event {
            Event::X3Ended {
                call_id,
                from_tag,
                reason,
                ..
            } => Some((call_id, from_tag, reason)),
            _ => None,
        })
        .collect()
}

/// Everybody talks for `frames` 20 ms frames: the target, the third and the fourth party (and the
/// callee, toward its own engine port, when `callee_talks`). Returns what the target heard.
async fn everybody_talks(
    call: &Call,
    third: &Joined,
    fourth: &Joined,
    first_sequence: u16,
    frames: u16,
) -> Vec<Vec<u8>> {
    let mut heard = Vec::new();
    for sequence in first_sequence..first_sequence + frames {
        call.target
            .send(&rtp_from(TARGET_SSRC, sequence), call.toward_target)
            .await;
        third
            .phone
            .send(&rtp_from(THIRD_SSRC, sequence), third.toward_engine)
            .await;
        fourth
            .phone
            .send(&rtp_from(FOURTH_SSRC, sequence), fourth.toward_engine)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        heard.extend(call.target.drain_rtp().await);
    }
    heard
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_seated_in_a_room_keeps_one_delivery_in_both_directions() {
    let rig = Rig::new().await;
    let call = rig.two_party("merge").await;
    assert!(matches!(
        rig.attach(call.id, &call.target_tag()).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;

    // Before the merge: the two-party call's own ingress taps.
    for sequence in 1..=2 {
        call.target
            .send(&rtp_from(TARGET_SSRC, sequence), call.toward_target)
            .await;
    }
    let before = mdf.read(2).await;
    assert!(before
        .iter()
        .all(|(direction, _)| *direction == from_target()));
    // …and what the callee says is to the target.
    call.callee
        .send(&rtp_from(CALLEE_SSRC, 900), call.toward_callee)
        .await;
    let relayed = mdf.read(1).await;
    assert_eq!(relayed[0].0, to_target());
    assert_eq!(ssrc_of(&relayed[0].1), CALLEE_SSRC);

    // The merge: the target joins a room with two other parties. (What it heard of the callee
    // before the merge is not the room's stream.)
    call.target.drain_rtp().await;
    let third = rig.join("room-merge", "third").await;
    let fourth = rig.join("room-merge", "fourth").await;
    let seated = rig.seat(call.id, &call.target_tag(), "room-merge").await;
    assert!(
        matches!(seated, CmdResult::Ok { .. }),
        "the same merge works with a warrant attached: {seated:?}"
    );

    let mut heard = everybody_talks(&call, &third, &fourth, 3, 40).await;
    // Everything the target said reaches the agency, as from the target.
    mdf.read_until(|read| {
        read.iter()
            .filter(|(direction, payload)| {
                *direction == from_target() && ssrc_of(payload) == TARGET_SSRC
            })
            .count()
            >= 40
    })
    .await;
    heard.extend(call.target.drain_rtp().await);

    let said = mdf.delivered(3, PayloadDirection::FromTarget, TARGET_SSRC);
    let said_sequences: HashSet<u16> = said.iter().map(|packet| rtp_sequence(packet)).collect();
    assert!(
        (3..43).all(|sequence| said_sequences.contains(&sequence)),
        "every packet the target sent in the room is delivered"
    );

    // What the room sent the target is delivered as to the target, and it is the room's own stream
    // for that seat: one SSRC, the one the target hears, never another party's raw stream.
    let heard_ssrcs: HashSet<u32> = heard.iter().map(|packet| ssrc_of(packet)).collect();
    assert_eq!(
        heard_ssrcs.len(),
        1,
        "the target hears one stream: {heard_ssrcs:?}"
    );
    let room_ssrc = *heard_ssrcs.iter().next().expect("one ssrc");
    for foreign in [TARGET_SSRC, CALLEE_SSRC, THIRD_SSRC, FOURTH_SSRC] {
        assert_ne!(room_ssrc, foreign, "the room originates its own stream");
    }
    let sent_to_target = mdf.delivered(3, PayloadDirection::ToTarget, room_ssrc);
    assert!(
        sent_to_target.len() >= 20,
        "the room's stream toward the target is delivered ({} PDUs)",
        sent_to_target.len()
    );
    let heard_set: HashSet<&Vec<u8>> = heard.iter().collect();
    let last_heard = heard
        .iter()
        .map(|packet| rtp_sequence(packet))
        .max()
        .unwrap();
    for payload in &sent_to_target {
        if rtp_sequence(payload) <= last_heard {
            assert!(
                heard_set.contains(payload),
                "a delivered to_target packet is byte for byte what the target received"
            );
        }
    }
    for (direction, payload) in &mdf.seen[3..] {
        if *direction == to_target() {
            assert_eq!(
                ssrc_of(payload),
                room_ssrc,
                "to_target carries only the target's own stream, never a party's raw one"
            );
        } else {
            assert_eq!(*direction, from_target());
            assert_eq!(ssrc_of(payload), TARGET_SSRC);
        }
    }

    assert!(
        !rig.second_connection().await,
        "the merge must not open a second delivery connection"
    );
    let events = rig.drained_events();
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, Event::X3Ended { .. } | Event::X3Loss { .. })),
        "the interception goes on across the merge: {events:?}"
    );
}

/// The seated party and the room's two other parties talk for `frames` 20 ms frames. Returns what
/// the seated party heard (the room's stream for its seat).
async fn seated_party_talks(
    seated: &Phone,
    toward_engine: SocketAddr,
    seated_ssrc: u32,
    third: &Joined,
    fourth: &Joined,
    frames: u16,
) -> Vec<Vec<u8>> {
    let mut heard = Vec::new();
    for sequence in 1000..1000 + frames {
        seated
            .send(&rtp_from(seated_ssrc, sequence), toward_engine)
            .await;
        third
            .phone
            .send(&rtp_from(THIRD_SSRC, sequence), third.toward_engine)
            .await;
        fourth
            .phone
            .send(&rtp_from(FOURTH_SSRC, sequence), fourth.toward_engine)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        heard.extend(seated.drain_rtp().await);
    }
    heard
}

/// Read until the seat's own stream and the room's stream toward it are both delivered, then check
/// every PDU since `from` against the warrant's target: the seat's ingress is `from_target` only when
/// the seat is the target's leg, and the room's stream toward the seat is then `to_target`; when the
/// seat is the target's peer the two swap (ETSI TS 103 221-2 §5.2.6 is target-relative).
async fn assert_seat_directions(
    mdf: &mut Mdf,
    from: usize,
    seated_ssrc: u32,
    heard: &[Vec<u8>],
    seat_is_target: bool,
) {
    assert!(!heard.is_empty(), "the seated party hears the room");
    // Every room stream the party heard: after a move, the old room's last packets toward it are
    // still being delivered when the new room's begin.
    let room_ssrcs: HashSet<u32> = heard.iter().map(|packet| ssrc_of(packet)).collect();
    mdf.read_until(|read| {
        read.iter()
            .filter(|(_, payload)| ssrc_of(payload) == seated_ssrc)
            .count()
            >= 20
            && read
                .iter()
                .filter(|(_, payload)| room_ssrcs.contains(&ssrc_of(payload)))
                .count()
                >= 10
    })
    .await;
    let (seat_direction, room_direction) = if seat_is_target {
        (from_target(), to_target())
    } else {
        (to_target(), from_target())
    };
    for (direction, payload) in &mdf.seen[from..] {
        let ssrc = ssrc_of(payload);
        if ssrc == seated_ssrc {
            assert_eq!(
                *direction, seat_direction,
                "what the seated party sent, relative to the target"
            );
        } else {
            assert!(
                room_ssrcs.contains(&ssrc),
                "only the seat's own stream and the room's toward it are delivered"
            );
            assert_eq!(
                *direction, room_direction,
                "what the room sent the seated party, relative to the target"
            );
        }
    }
}

/// The target's peer is moved into a room (a REFER with Replaces adopting the far party): the call
/// stays intercepted, and its directions stay relative to the warrant's target. The callee's voice is
/// what the target is sent, so it is `to_target`; the room's mix toward the callee carries the
/// target's side, so it is `from_target`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seating_the_targets_peer_keeps_directions_relative_to_the_target() {
    let rig = Rig::new().await;
    let call = rig.two_party("peer").await;
    assert!(matches!(
        rig.attach(call.id, &call.target_tag()).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    call.callee
        .send(&rtp_from(CALLEE_SSRC, 1), call.toward_callee)
        .await;
    let before = mdf.read(1).await;
    assert_eq!(
        before[0].0,
        to_target(),
        "before the seat: the callee's voice"
    );

    let third = rig.join("room-peer", "third").await;
    let fourth = rig.join("room-peer", "fourth").await;
    let seated = rig.seat(call.id, &call.callee_tag(), "room-peer").await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");

    let from = mdf.seen.len();
    let mut heard = seated_party_talks(
        &call.callee,
        call.toward_callee,
        CALLEE_SSRC,
        &third,
        &fourth,
        30,
    )
    .await;
    assert_seat_directions(&mut mdf, from, CALLEE_SSRC, &heard, false).await;

    // The seat keeps its party across a leave and a seat in another room.
    assert!(matches!(
        rig.leave("room-peer", &call.callee_tag()).await,
        CmdResult::Ok { .. }
    ));
    let fifth = rig.join("room-peer-2", "fifth").await;
    let sixth = rig.join("room-peer-2", "sixth").await;
    assert!(matches!(
        rig.seat(call.id, &call.callee_tag(), "room-peer-2").await,
        CmdResult::Ok { .. }
    ));
    let from = mdf.seen.len();
    heard.extend(
        seated_party_talks(
            &call.callee,
            call.toward_callee,
            CALLEE_SSRC,
            &fifth,
            &sixth,
            30,
        )
        .await,
    );
    assert_seat_directions(&mut mdf, from, CALLEE_SSRC, &heard, false).await;
}

/// The mirror: the warrant names the callee and the caller is seated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seating_the_caller_of_a_callee_warrant_mirrors_the_directions() {
    let rig = Rig::new().await;
    let call = rig.two_party("mirror").await;
    assert!(matches!(
        rig.send(rig.attach_command(call.id, &call.target_tag(), X3TargetLeg::Callee))
            .await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    let third = rig.join("room-mirror", "third").await;
    let fourth = rig.join("room-mirror", "fourth").await;
    assert!(matches!(
        rig.seat(call.id, &call.target_tag(), "room-mirror").await,
        CmdResult::Ok { .. }
    ));

    let heard = seated_party_talks(
        &call.target,
        call.toward_target,
        TARGET_SSRC,
        &third,
        &fourth,
        30,
    )
    .await;
    assert_seat_directions(&mut mdf, 0, TARGET_SSRC, &heard, false).await;
}

/// An attach on a call whose callee is already seated, naming the caller: the room installs the
/// taps with the seat as the target's peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_on_a_call_whose_peer_is_seated_is_relative_to_the_target() {
    let rig = Rig::new().await;
    let call = rig.two_party("late").await;
    let third = rig.join("room-late", "third").await;
    let fourth = rig.join("room-late", "fourth").await;
    assert!(matches!(
        rig.seat(call.id, &call.callee_tag(), "room-late").await,
        CmdResult::Ok { .. }
    ));
    let attached = rig.attach(call.id, &call.callee_tag()).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

    let heard = seated_party_talks(
        &call.callee,
        call.toward_callee,
        CALLEE_SSRC,
        &third,
        &fourth,
        30,
    )
    .await;
    assert_seat_directions(&mut mdf, 0, CALLEE_SSRC, &heard, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interception_attached_on_a_seated_call_delivers_both_directions() {
    let rig = Rig::new().await;
    let call = rig.two_party("seated").await;
    let third = rig.join("room-seated", "third").await;
    let fourth = rig.join("room-seated", "fourth").await;
    assert!(matches!(
        rig.seat(call.id, &call.target_tag(), "room-seated").await,
        CmdResult::Ok { .. }
    ));

    let attached = rig.attach(call.id, &call.target_tag()).await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach_x3 on a seated call: {attached:?}"
    );
    let mut mdf = rig.accept().await;

    let heard = everybody_talks(&call, &third, &fourth, 1, 30).await;
    mdf.read_until(|read| {
        read.iter()
            .filter(|(direction, _)| *direction == from_target())
            .count()
            >= 30
            && read
                .iter()
                .filter(|(direction, _)| *direction == to_target())
                .count()
                >= 10
    })
    .await;
    assert!(!heard.is_empty(), "the target hears the room");
    let room_ssrc = ssrc_of(&heard[0]);
    assert_eq!(
        mdf.delivered(0, PayloadDirection::ToTarget, room_ssrc)
            .len(),
        mdf.seen
            .iter()
            .filter(|(direction, _)| *direction == to_target())
            .count(),
        "every to_target PDU is the room's stream for the target"
    );

    // Detaching on a seated call stops the delivery and says so.
    let detached = rig
        .send(Command::DetachX3 {
            call_id: call.id.into(),
            from_tag: call.target_tag(),
            xid: None,
            delivery: None,
            correlation_id: None,
        })
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(
            call.id.to_string(),
            call.target_tag(),
            X3EndReason::Detached
        )]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conference_join_seat_is_intercepted_by_naming_the_room_and_the_seat() {
    let rig = Rig::new().await;
    let target = rig.join("room-join", "target").await;
    let other = rig.join("room-join", "other").await;

    // Another controller does not own the seat; an unknown seat is not a seat.
    let foreign = rig
        .engine
        .handle(
            OTHER_CLIENT,
            rig.attach_command("room-join", "target", X3TargetLeg::Caller),
        )
        .await;
    assert!(
        matches!(foreign, CmdResult::Error { .. }),
        "a seat is invisible to a controller that did not seat it: {foreign:?}"
    );
    let unknown = rig.attach("room-join", "nobody").await;
    assert!(matches!(unknown, CmdResult::Error { .. }), "{unknown:?}");
    let no_room = rig.attach("room-none", "target").await;
    assert!(matches!(no_room, CmdResult::Error { .. }), "{no_room:?}");

    let attached = rig.attach("room-join", "target").await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach_x3 on a joined seat: {attached:?}"
    );
    let mut mdf = rig.accept().await;
    let started: Vec<_> = rig
        .drained_events()
        .into_iter()
        .filter_map(|event| match event {
            Event::X3Started {
                call_id, from_tag, ..
            } => Some((call_id, from_tag)),
            _ => None,
        })
        .collect();
    assert_eq!(
        started,
        vec![("room-join".to_string(), "target".to_string())],
        "the event names the room and the seat"
    );

    let mut heard = Vec::new();
    for sequence in 1..=30u16 {
        target
            .phone
            .send(&rtp_from(TARGET_SSRC, sequence), target.toward_engine)
            .await;
        other
            .phone
            .send(&rtp_from(THIRD_SSRC, sequence), other.toward_engine)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        heard.extend(target.phone.drain_rtp().await);
    }
    mdf.read_until(|read| {
        read.iter()
            .filter(|(direction, _)| *direction == from_target())
            .count()
            >= 30
            && read
                .iter()
                .filter(|(direction, _)| *direction == to_target())
                .count()
                >= 10
    })
    .await;
    heard.extend(target.phone.drain_rtp().await);
    let room_ssrc = ssrc_of(&heard[0]);
    for (direction, payload) in &mdf.seen {
        if *direction == to_target() {
            assert_eq!(ssrc_of(payload), room_ssrc);
        } else {
            assert_eq!(ssrc_of(payload), TARGET_SSRC);
        }
    }
    assert_ne!(room_ssrc, THIRD_SSRC);

    // Leaving the room ends the interception of the seat that left, naming the room and the seat.
    assert!(matches!(
        rig.leave("room-join", "target").await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(
            "room-join".to_string(),
            "target".to_string(),
            X3EndReason::CallEnded
        )]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detaching_a_joined_seat_ends_it_detached_and_the_room_stopping_ends_it_ended() {
    let rig = Rig::new().await;
    let seat = rig.join("room-detach", "only").await;
    assert!(matches!(
        rig.attach("room-detach", "only").await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;
    seat.phone
        .send(&rtp_from(TARGET_SSRC, 1), seat.toward_engine)
        .await;
    mdf.read(1).await;

    let detached = rig
        .send(Command::DetachX3 {
            call_id: "room-detach".into(),
            from_tag: "only".into(),
            xid: None,
            delivery: None,
            correlation_id: None,
        })
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(
            "room-detach".to_string(),
            "only".to_string(),
            X3EndReason::Detached
        )]
    );
    // Idempotent, like every detach.
    assert!(matches!(
        rig.send(Command::DetachX3 {
            call_id: "room-detach".into(),
            from_tag: "only".into(),
            xid: None,
            delivery: None,
            correlation_id: None,
        })
        .await,
        CmdResult::Ok { .. }
    ));

    // The last seat leaving stops the room, and the interception with it.
    assert!(matches!(
        rig.attach("room-detach", "only").await,
        CmdResult::Ok { .. }
    ));
    let _second = rig.accept().await;
    assert!(matches!(
        rig.leave("room-detach", "only").await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(
            "room-detach".to_string(),
            "only".to_string(),
            X3EndReason::CallEnded
        )]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_seated_call_that_leaves_and_is_seated_elsewhere_keeps_its_interception() {
    let rig = Rig::new().await;
    let call = rig.two_party("move").await;
    assert!(matches!(
        rig.attach(call.id, &call.target_tag()).await,
        CmdResult::Ok { .. }
    ));
    let mut mdf = rig.accept().await;

    let third = rig.join("room-one", "third").await;
    let fourth = rig.join("room-one", "fourth").await;
    assert!(matches!(
        rig.seat(call.id, &call.target_tag(), "room-one").await,
        CmdResult::Ok { .. }
    ));
    everybody_talks(&call, &third, &fourth, 1, 15).await;
    mdf.read_until(|read| {
        read.iter()
            .filter(|(direction, _)| *direction == from_target())
            .count()
            >= 15
    })
    .await;

    // Leaving the room is not the end of the call, so it is not the end of the interception: the
    // call can be seated in another room, and the warrant covers the call.
    assert!(matches!(
        rig.leave("room-one", &call.target_tag()).await,
        CmdResult::Ok { .. }
    ));
    assert!(
        x3_ends(rig.drained_events()).is_empty(),
        "a seat leaving its room does not end the interception of its call"
    );

    let fifth = rig.join("room-two", "fifth").await;
    let sixth = rig.join("room-two", "sixth").await;
    assert!(matches!(
        rig.seat(call.id, &call.target_tag(), "room-two").await,
        CmdResult::Ok { .. }
    ));
    let read_before = mdf.seen.len();
    everybody_talks(&call, &fifth, &sixth, 100, 15).await;
    mdf.read_until(|read| {
        read.iter()
            .filter(|(direction, payload)| {
                *direction == from_target() && rtp_sequence(payload) >= 100
            })
            .count()
            >= 15
    })
    .await;
    assert!(
        mdf.delivered(read_before, PayloadDirection::FromTarget, TARGET_SSRC)
            .len()
            >= 15,
        "the target is delivered in the second room"
    );
    assert!(!rig.second_connection().await, "one connection throughout");

    let deleted = rig
        .send(Command::Delete {
            call_id: call.id.into(),
            from_tag: call.target_tag(),
            to_tag: None,
        })
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(
            call.id.to_string(),
            call.target_tag(),
            X3EndReason::CallEnded
        )]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_on_a_call_that_left_its_room_is_still_refused() {
    // A left call relays nothing, so there is nothing to intercept until it is seated again.
    let rig = Rig::new().await;
    let call = rig.two_party("left").await;
    let _third = rig.join("room-left", "third").await;
    assert!(matches!(
        rig.seat(call.id, &call.target_tag(), "room-left").await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        rig.leave("room-left", &call.target_tag()).await,
        CmdResult::Ok { .. }
    ));
    let refused = rig.attach(call.id, &call.target_tag()).await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_the_room_cannot_take_is_refused_and_opens_no_delivery() {
    // Accepting an interception the room cannot tap reads as done and delivers nothing, so it is
    // refused: no session, no connection to the Mediation Function, no `x3_started`.
    let rig = Rig::new().await;
    let call = rig.two_party("gone").await;
    let _third = rig.join("room-gone", "third").await;
    assert!(matches!(
        rig.seat(call.id, &call.target_tag(), "room-gone").await,
        CmdResult::Ok { .. }
    ));
    rig.engine.conference().deregister("room-gone");

    let refused = rig.attach(call.id, &call.target_tag()).await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
    assert!(!rig.second_connection().await, "no delivery connection");
    assert!(rig
        .drained_events()
        .iter()
        .all(|event| !matches!(event, Event::X3Started { .. })));
}

/// An `RTP/SAVP` answer for one phone carrying `crypto`.
fn savp_sdp(address: SocketAddr, crypto: &CryptoAttribute) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={crypto}\r\n",
        ip = address.ip(),
        port = address.port(),
        crypto = crypto.to_attribute_value(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_seat_is_delivered_as_plaintext_never_ciphertext() {
    let rig = Rig::new().await;
    // The callee is the SDES leg: the engine terminates its SRTP.
    let target = Phone::new().await;
    let callee = Phone::new().await;
    let offer = rig
        .send(Command::Offer {
            call_id: "secure".into(),
            from_tag: "secure-target".into(),
            sdp: plain_sdp(target.address, "sendrecv"),
            profile: ProfileFlags {
                transport_protocol: Some("RTP/SAVP".into()),
                ..Default::default()
            },
        })
        .await;
    let engine_key = match &offer {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => *siphon_rtp_engine::sdp::parse(text)
            .expect("offer reply")
            .crypto
            .first()
            .expect("engine a=crypto"),
        other => panic!("offer: {other:?}"),
    };
    let toward_callee = Rig::engine_address(&offer);
    let callee_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let answer = rig
        .send(Command::Answer {
            call_id: "secure".into(),
            from_tag: "secure-target".into(),
            to_tag: "secure-callee".into(),
            sdp: savp_sdp(callee.address, &callee_key),
            profile: ProfileFlags::default(),
        })
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }), "{answer:?}");

    let attached = rig
        .send(rig.attach_command("secure", "secure-target", X3TargetLeg::Callee))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut mdf = rig.accept().await;

    let third = rig.join("room-secure", "third").await;
    let seated = rig.seat("secure", "secure-callee", "room-secure").await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");

    let mut callee_encrypt = SrtpContext::from_key_material(&callee_key.key);
    let mut callee_decrypt = SrtpContext::from_key_material(&engine_key.key);
    let mut sent_plaintext = Vec::new();
    let mut heard_plaintext = Vec::new();
    let mut buffer = [0u8; 2048];
    for sequence in 1..=25u16 {
        let plaintext = rtp_from(CALLEE_SSRC, sequence);
        let mut sealed = Vec::new();
        callee_encrypt
            .protect(&plaintext, &mut sealed)
            .expect("protect");
        assert_ne!(sealed, plaintext, "the callee really encrypts");
        callee.send(&sealed, toward_callee).await;
        sent_plaintext.push(plaintext);
        third
            .phone
            .send(&rtp_from(THIRD_SSRC, sequence), third.toward_engine)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Ok(Ok((length, _))) = timeout(
            Duration::from_millis(1),
            callee.socket.recv_from(&mut buffer),
        )
        .await
        {
            if (64..=95).contains(&(buffer[1] & 0x7f)) {
                continue;
            }
            let mut clear = Vec::new();
            if callee_decrypt
                .unprotect(&buffer[..length], &mut clear)
                .is_ok()
            {
                heard_plaintext.push(clear);
            }
        }
    }
    mdf.read_until(|read| {
        read.iter()
            .filter(|(direction, _)| *direction == from_target())
            .count()
            >= 25
            && read
                .iter()
                .filter(|(direction, _)| *direction == to_target())
                .count()
                >= 10
    })
    .await;
    let heard_set: HashSet<Vec<u8>> = heard_plaintext.iter().cloned().collect();
    let last_heard = heard_plaintext
        .iter()
        .map(|packet| rtp_sequence(packet))
        .max()
        .expect("the callee decrypted the room's stream");
    for (direction, payload) in &mdf.seen {
        if *direction == from_target() {
            assert!(
                sent_plaintext.contains(payload),
                "from_target is the callee's plaintext RTP, not the SRTP it sent"
            );
        } else {
            assert_eq!(*direction, to_target());
            if rtp_sequence(payload) <= last_heard {
                assert!(
                    heard_set.contains(payload),
                    "to_target is the plaintext the callee decrypted, not the SRTP the room sent"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_info_advertises_conference_seat_interception_only_with_x3() {
    let features = |result: CmdResult| match result {
        CmdResult::NodeInfo { node } => node.features,
        other => panic!("node_info answers a node: {other:?}"),
    };
    let rig = Rig::new().await;
    assert!(features(rig.send(Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_conference_seat"));
    let bare = Engine::new(Datapath::new());
    assert!(!features(bare.handle(CLIENT, Command::NodeInfo).await)
        .iter()
        .any(|name| name == "x3_conference_seat"));
}

/// Both deliveries of a call follow its leg into a room: the one install carries the whole set, so
/// neither is dropped by the merge, each keeps its connection and sequence counter, and a detach of
/// one warrant on the seated call leaves the other delivering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_deliveries_follow_a_call_into_a_room_and_detach_one_leaves_the_other() {
    let rig = Rig::new().await;
    let call = rig.two_party("merge-two").await;
    assert!(matches!(
        rig.attach(call.id, &call.target_tag()).await,
        CmdResult::Ok { .. }
    ));
    let mut first = rig.accept().await;
    assert!(matches!(
        rig.attach_second(call.id, &call.target_tag()).await,
        CmdResult::Ok { .. }
    ));
    let mut second = rig.accept_second().await;

    for sequence in 1..=2 {
        call.target
            .send(&rtp_from(TARGET_SSRC, sequence), call.toward_target)
            .await;
    }
    first.read(2).await;
    second.read(2).await;

    let third = rig.join("room-two-warrants", "third").await;
    let fourth = rig.join("room-two-warrants", "fourth").await;
    let seated = rig
        .seat(call.id, &call.target_tag(), "room-two-warrants")
        .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");

    everybody_talks(&call, &third, &fourth, 3, 20).await;
    for mdf in [&mut first, &mut second] {
        mdf.read_until(|read| {
            read.iter()
                .filter(|(direction, payload)| {
                    *direction == from_target() && ssrc_of(payload) == TARGET_SSRC
                })
                .count()
                >= 20
        })
        .await;
        assert!(
            mdf.seen
                .iter()
                .any(|(direction, _)| *direction == to_target()),
            "the room's stream toward the target reaches every delivery"
        );
    }
    assert!(
        x3_ends(rig.drained_events()).is_empty(),
        "the merge ended no delivery"
    );

    // Detach one warrant while the call is seated: its delivery ends, the other keeps going.
    let detached = rig
        .send(Command::DetachX3 {
            call_id: call.id.into(),
            from_tag: call.target_tag(),
            xid: Some(XID_TEXT.parse::<Xid>().expect("xid")),
            delivery: None,
            correlation_id: None,
        })
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    let ends = rig.drained_events();
    let ended: Vec<_> = ends
        .iter()
        .filter_map(|event| match event {
            Event::X3Ended { xid, reason, .. } => Some((*xid, *reason)),
            _ => None,
        })
        .collect();
    assert_eq!(
        ended,
        vec![(
            Some(XID_TEXT.parse::<Xid>().expect("xid")),
            X3EndReason::Detached
        )]
    );
    let before = second.seen.len();
    everybody_talks(&call, &third, &fourth, 100, 10).await;
    second
        .read_until(|read| {
            read.iter()
                .filter(|(direction, payload)| {
                    *direction == from_target() && rtp_sequence(payload) >= 100
                })
                .count()
                >= 10
        })
        .await;
    assert!(second.seen.len() > before);
}

/// A joined seat carries several deliveries too: each has its own connection, a detach of one warrant
/// ends that delivery alone (one `x3_ended` naming it) and the other goes on, and the seat leaving
/// ends what is left, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_joined_seat_carries_two_deliveries_and_detaching_one_leaves_the_other() {
    let rig = Rig::new().await;
    let target = rig.join("room-multi", "target").await;
    let other = rig.join("room-multi", "other").await;
    assert!(matches!(
        rig.attach("room-multi", "target").await,
        CmdResult::Ok { .. }
    ));
    let mut first = rig.accept().await;
    assert!(matches!(
        rig.attach_second("room-multi", "target").await,
        CmdResult::Ok { .. }
    ));
    let mut second = rig.accept_second().await;

    let talk = |first_sequence: u16, frames: u16| {
        let target = &target;
        let other = &other;
        async move {
            for sequence in first_sequence..first_sequence + frames {
                target
                    .phone
                    .send(&rtp_from(TARGET_SSRC, sequence), target.toward_engine)
                    .await;
                other
                    .phone
                    .send(&rtp_from(THIRD_SSRC, sequence), other.toward_engine)
                    .await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                target.phone.drain_rtp().await;
            }
        }
    };
    talk(1, 10).await;
    for mdf in [&mut first, &mut second] {
        mdf.read_until(|read| {
            read.iter()
                .filter(|(direction, _)| *direction == from_target())
                .count()
                >= 10
        })
        .await;
    }

    let detached = rig
        .send(Command::DetachX3 {
            call_id: "room-multi".into(),
            from_tag: "target".into(),
            xid: Some(XID_TEXT.parse::<Xid>().expect("xid")),
            delivery: None,
            correlation_id: None,
        })
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(
            "room-multi".to_string(),
            "target".to_string(),
            X3EndReason::Detached
        )],
        "one end event, for the delivery that was detached"
    );

    talk(100, 10).await;
    second
        .read_until(|read| {
            read.iter()
                .filter(|(direction, payload)| {
                    *direction == from_target() && rtp_sequence(payload) >= 100
                })
                .count()
                >= 10
        })
        .await;

    assert!(matches!(
        rig.leave("room-multi", "target").await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        x3_ends(rig.drained_events()),
        vec![(
            "room-multi".to_string(),
            "target".to_string(),
            X3EndReason::CallEnded
        )],
        "the seat leaving ends the remaining delivery, once"
    );
}
