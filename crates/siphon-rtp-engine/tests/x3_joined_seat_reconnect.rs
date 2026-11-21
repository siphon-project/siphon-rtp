//! A conference seat that joined its room (`conference_join`) is intercepted by the control client
//! that seated it (ETSI TS 103 221-2 X3). Its ownership is the client's identity, not the control
//! connection: a controller that holds nothing but joined seats and reconnects with the same
//! `controller_id` must still be able to `detach_x3` its seat, and `x3_loss` / `x3_ended` must reach
//! the new connection.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::time::Duration;

use common::x3_mdf::{
    acceptor, pki, plain_sdp, rtp_from, Mdf, PduStream, Phone, Pki, Tls, CORRELATION_ID, SHORT,
};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, ControllerAttachment, Engine};
use siphon_rtp_proto::{
    CmdResult, Command, ConferenceDtmf, ConferenceRole, Event, ProfileFlags, X3EndReason,
    X3TargetLeg, Xid,
};
use tokio::net::TcpListener;
use tokio::time::timeout;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CONTROLLER: &str = "sbc-1";
const ROOM: &str = "room";
const TAG: &str = "seat-a";
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
const SEAT_SSRC: u32 = 0x0A0A_0A0A;

struct Rig {
    engine: Engine<Datapath>,
    pki: Pki,
}

impl Rig {
    /// `buffer_packets` bounds each delivery's queue, so a small one makes loss easy to cause.
    async fn new(buffer_packets: usize) -> Self {
        let mut pki = pki();
        pki.config.buffer_packets = buffer_packets;
        let engine = Engine::new(Datapath::new()).with_x3(pki.config.clone());
        tokio::spawn(run_redirect_dispatcher(
            engine.datapath().rx(),
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        Self { engine, pki }
    }

    /// A control connection presenting `CONTROLLER`; `ordinal` is the connection's own id.
    fn connect(&self, ordinal: u64) -> ControllerAttachment {
        self.engine
            .attach_controller(CONTROLLER, ClientId(ordinal))
            .expect("the controller identity attaches")
    }

    /// What the control server does when a connection ends.
    fn disconnect(&self, attachment: &ControllerAttachment) {
        self.engine
            .deregister_client(attachment.client, attachment.generation);
        self.engine
            .detach_controller(CONTROLLER, attachment.generation);
    }

    async fn join(&self, client: ClientId) -> (Phone, std::net::SocketAddr) {
        let phone = Phone::new().await;
        let result = self
            .engine
            .handle(
                client,
                Command::ConferenceJoin {
                    conference_id: ROOM.into(),
                    from_tag: TAG.into(),
                    sdp: plain_sdp(phone.address, "sendrecv"),
                    role: ConferenceRole::Talker,
                    profile: ProfileFlags::default(),
                    dtmf: ConferenceDtmf::Events,
                },
            )
            .await;
        let CmdResult::Ok {
            sdp: Some(text), ..
        } = result
        else {
            panic!("the join is answered, got {result:?}");
        };
        let toward_engine = siphon_rtp_engine::sdp::parse(&text)
            .expect("parse the engine's sdp")
            .remote_rtp;
        (phone, toward_engine)
    }

    async fn attach(&self, client: ClientId, delivery: String) -> CmdResult {
        self.engine
            .handle(
                client,
                Command::AttachX3 {
                    call_id: ROOM.into(),
                    from_tag: TAG.into(),
                    delivery,
                    xid: XID_TEXT.parse::<Xid>().expect("xid"),
                    correlation_id: CORRELATION_ID,
                    target_leg: X3TargetLeg::Caller,
                },
            )
            .await
    }

    async fn accept(&self, listener: &TcpListener) -> Mdf {
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
}

/// The first event `events` yields that `pick` accepts, within `limit`.
async fn event_matching<T>(
    events: &flume::Receiver<Event>,
    limit: Duration,
    pick: impl Fn(Event) -> Option<T>,
) -> Option<T> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let event = timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            events.recv_async(),
        )
        .await
        .ok()?
        .ok()?;
        if let Some(found) = pick(event) {
            return Some(found);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_joined_seat_is_detached_and_ended_on_the_reconnected_controller() {
    let rig = Rig::new(256).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
    let first = rig.connect(1);
    let (_phone, _toward_engine) = rig.join(first.client).await;
    let attached = rig
        .attach(
            first.client,
            listener.local_addr().expect("addr").to_string(),
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let _mdf = rig.accept(&listener).await;

    // The control connection drops with only the joined seat up.
    rig.disconnect(&first);
    let second = rig.connect(2);
    assert_eq!(
        second.client, first.client,
        "the same controller identity resolves to the same client"
    );

    let detached = rig
        .engine
        .handle(
            second.client,
            Command::DetachX3 {
                call_id: ROOM.into(),
                from_tag: TAG.into(),
                xid: None,
                delivery: None,
                correlation_id: None,
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "the reconnected controller still owns its seat's interception: {detached:?}"
    );
    let reason = event_matching(&second.events, SHORT, |event| match event {
        Event::X3Ended { reason, .. } => Some(reason),
        _ => None,
    })
    .await;
    assert_eq!(
        reason,
        Some(X3EndReason::Detached),
        "x3_ended arrives on the new connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_x3_loss_on_a_joined_seat_after_a_reconnect_reaches_the_new_connection() {
    // The mediation function is not there: its address refuses connections, so the two-packet queue
    // overflows and what is dropped is loss the controller has to be told about.
    let rig = Rig::new(2).await;
    let dead = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let delivery = dead.local_addr().expect("addr").to_string();
    drop(dead);
    let first = rig.connect(1);
    let (phone, toward_engine) = rig.join(first.client).await;
    let attached = rig.attach(first.client, delivery).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");

    rig.disconnect(&first);
    let second = rig.connect(2);

    for sequence in 1..=40u16 {
        phone
            .send(&rtp_from(SEAT_SSRC, sequence), toward_engine)
            .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let loss = event_matching(
        &second.events,
        Duration::from_secs(20),
        |event| match event {
            Event::X3Loss { dropped, .. } => Some(dropped),
            _ => None,
        },
    )
    .await;
    assert!(
        loss.is_some_and(|dropped| dropped > 0),
        "x3_loss reaches the controller that reconnected: {loss:?}"
    );
}
