//! One engine, several anchors on one SIP Call-ID.
//!
//! Driven over the real JSON-over-TCP control connection with real RTP on loopback. Every call
//! here is named by the same `call_id` and `from_tag`, the way a chain of SIP proxies names it,
//! and is told apart only by the scope its controller puts on the frame.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher_with_text;
use siphon_rtp_engine::{sdp, server, Engine};
use siphon_rtp_proto::{
    frame, CmdResult, Command, ConferenceRole, Event, MediaTimeoutReason, PlayEndReason,
    PlayMediaSource, Request, Response, Scoped,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const CALL_ID: &str = "7f9a2b1c@192.0.2.20";
const FROM_TAG: &str = "a7c31f";
const TO_TAG: &str = "b19e02";

/// A scope-aware control client over one persistent TCP connection.
struct Control {
    stream: TcpStream,
    buffer: Vec<u8>,
    next_id: u64,
    events: VecDeque<Scoped<Event>>,
}

impl Control {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect control");
        Self {
            stream,
            buffer: Vec::new(),
            next_id: 1,
            events: VecDeque::new(),
        }
    }

    /// Connect and claim a stable controller identity, as a real controller process does.
    async fn connect_as(addr: SocketAddr, controller_id: &str) -> Self {
        let mut control = Self::connect(addr).await;
        let claimed = control
            .request(
                None,
                Command::Authenticate {
                    token: String::new(),
                    controller_id: Some(controller_id.to_string()),
                },
            )
            .await;
        assert!(matches!(claimed, CmdResult::Ok { .. }), "{claimed:?}");
        control
    }

    async fn read_frame(&mut self) -> serde_json::Value {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some((value, consumed)) =
                frame::decode::<serde_json::Value>(&self.buffer).expect("decode frame")
            {
                self.buffer.drain(..consumed);
                return value;
            }
            let read = timeout(Duration::from_secs(2), self.stream.read(&mut chunk))
                .await
                .expect("frame not timed out")
                .expect("read frame");
            assert_ne!(read, 0, "control connection closed unexpectedly");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Send `command` under `scope` and await its response, queueing events that arrive first.
    async fn request(&mut self, scope: Option<&str>, command: Command) -> CmdResult {
        let id = self.next_id;
        self.next_id += 1;
        let request = Scoped::new(scope.map(str::to_owned), Request { id, command });
        let bytes = frame::encode(&request).expect("encode request");
        self.stream.write_all(&bytes).await.expect("write request");
        loop {
            let value = self.read_frame().await;
            if value.get("event").is_some() {
                self.events
                    .push_back(serde_json::from_value(value).expect("event shape"));
                continue;
            }
            let response: Response = serde_json::from_value(value).expect("response shape");
            assert_eq!(response.id, id, "response correlates to request");
            return response.result;
        }
    }

    /// The next event with the scope it was emitted for.
    async fn next_event(&mut self) -> Scoped<Event> {
        if let Some(event) = self.events.pop_front() {
            return event;
        }
        let value = self.read_frame().await;
        assert!(value.get("event").is_some(), "expected an event: {value}");
        serde_json::from_value(value).expect("event shape")
    }

    async fn offer(&mut self, scope: Option<&str>, remote: SocketAddr) -> SocketAddr {
        let result = self
            .request(
                scope,
                Command::Offer {
                    call_id: CALL_ID.into(),
                    from_tag: FROM_TAG.into(),
                    sdp: sdp_for(remote),
                    profile: Default::default(),
                },
            )
            .await;
        engine_addr(&result)
    }

    async fn answer(&mut self, scope: Option<&str>, remote: SocketAddr) -> SocketAddr {
        let result = self
            .request(
                scope,
                Command::Answer {
                    call_id: CALL_ID.into(),
                    from_tag: FROM_TAG.into(),
                    to_tag: TO_TAG.into(),
                    sdp: sdp_for(remote),
                    profile: Default::default(),
                },
            )
            .await;
        engine_addr(&result)
    }

    async fn delete(&mut self, scope: Option<&str>) -> CmdResult {
        self.request(
            scope,
            Command::Delete {
                call_id: CALL_ID.into(),
                from_tag: FROM_TAG.into(),
                to_tag: None,
            },
        )
        .await
    }

    async fn query(&mut self, scope: Option<&str>) -> CmdResult {
        self.request(
            scope,
            Command::Query {
                call_id: CALL_ID.into(),
                from_tag: FROM_TAG.into(),
                to_tag: None,
            },
        )
        .await
    }

    async fn list(&mut self, scope: Option<&str>) -> Vec<String> {
        match self.request(scope, Command::List).await {
            CmdResult::List { call_ids } => call_ids,
            other => panic!("expected a list, got {other:?}"),
        }
    }
}

async fn serve() -> (Arc<Engine<UdpLoopbackDatapath>>, SocketAddr) {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    // The redirect dispatcher feeds every stream handled in userspace (a transcoding pipeline).
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
        engine.udptl(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    let serve_engine = engine.clone();
    tokio::spawn(async move {
        let _ = server::serve(serve_engine, listener).await;
    });
    (engine, control_addr)
}

async fn phone() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind phone");
    let addr = socket.local_addr().expect("phone addr");
    (socket, addr)
}

fn sdp_for(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

fn engine_addr(result: &CmdResult) -> SocketAddr {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => sdp::parse(text).expect("parse engine addr").remote_rtp,
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

fn error_reason(result: &CmdResult) -> &str {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected an error, got {other:?}"),
    }
}

/// An RTP packet (V=2, PT=0) whose payload names the direction it travels, so a relay that
/// crossed two streams would show.
fn rtp(ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (len, from) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("recv not timed out")
        .expect("recv");
    (buffer[..len].to_vec(), from)
}

async fn hears_nothing(socket: &UdpSocket) -> bool {
    let mut buffer = [0u8; 2048];
    timeout(Duration::from_millis(200), socket.recv_from(&mut buffer))
        .await
        .is_err()
}

/// The four engine addresses of two anchors chained on one call path.
struct Chain {
    /// Where the caller sends: the first anchor's caller-facing port.
    first_near: SocketAddr,
    /// The first anchor's port toward the second anchor.
    first_far: SocketAddr,
    /// The second anchor's port toward the first.
    second_near: SocketAddr,
    /// Where the callee sends: the second anchor's callee-facing port.
    second_far: SocketAddr,
}

/// Anchor one call twice, in signalling order: the offer passes the first anchor and then the
/// second, the answer comes back through the second and then the first. Each anchor is handed
/// the SDP the other one wrote, exactly as two proxies on one call path are.
async fn anchor_chain(
    first: (&mut Control, Option<&str>),
    second: (&mut Control, Option<&str>),
    caller: SocketAddr,
    callee: SocketAddr,
) -> Chain {
    let first_far = first.0.offer(first.1, caller).await;
    let second_far = second.0.offer(second.1, first_far).await;
    let second_near = second.0.answer(second.1, callee).await;
    let first_near = first.0.answer(first.1, second_near).await;
    Chain {
        first_near,
        first_far,
        second_near,
        second_far,
    }
}

/// Media crosses both anchors in each direction, payload intact.
async fn assert_chain_relays(chain: &Chain, caller: &UdpSocket, callee: &UdpSocket) {
    let forward = rtp(0x0A0A_0A0A, b"caller to callee");
    caller
        .send_to(&forward, chain.first_near)
        .await
        .expect("send caller");
    assert_eq!(recv(callee).await, (forward, chain.second_far));

    let backward = rtp(0x0B0B_0B0B, b"callee to caller");
    callee
        .send_to(&backward, chain.second_far)
        .await
        .expect("send callee");
    assert_eq!(recv(caller).await, (backward, chain.first_near));
}

/// UE to P-CSCF anchor to BGCF anchor to trunk: two controllers, one engine, one Call-ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_controllers_anchor_one_call_id_under_different_scopes() {
    let (engine, control_addr) = serve().await;
    let mut pcscf = Control::connect_as(control_addr, "pcscf-1").await;
    let mut bgcf = Control::connect_as(control_addr, "bgcf-1").await;
    let (ue, ue_addr) = phone().await;
    let (trunk, trunk_addr) = phone().await;

    let chain = anchor_chain(
        (&mut pcscf, Some("pcscf")),
        (&mut bgcf, Some("bgcf")),
        ue_addr,
        trunk_addr,
    )
    .await;
    let mut ports = vec![
        chain.first_near.port(),
        chain.first_far.port(),
        chain.second_near.port(),
        chain.second_far.port(),
    ];
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 4, "each anchor has its own pair of ports");

    assert_chain_relays(&chain, &ue, &trunk).await;

    // Each controller sees its own call, under its own scope, and nothing else.
    assert_eq!(pcscf.list(Some("pcscf")).await, vec![CALL_ID.to_string()]);
    assert_eq!(bgcf.list(Some("bgcf")).await, vec![CALL_ID.to_string()]);
    assert!(pcscf.list(Some("bgcf")).await.is_empty());
    assert!(pcscf.list(None).await.is_empty());
    assert_eq!(
        engine.metrics().scoped_offers_total(),
        2,
        "one scoped call anchored per function"
    );
}

/// Two instances of one function share a scope, so the pass one of them offered can be answered
/// and released by the other: an on-net call whose parties sit on two P-CSCF instances is **one**
/// call with two legs, as it is on a single instance. A BGCF on the same Call-ID has its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_instances_of_one_function_meet_in_one_call_of_their_scope() {
    let (_engine, control_addr) = serve().await;
    let mut originating = Control::connect_as(control_addr, "pcscf-1").await;
    let mut terminating = Control::connect_as(control_addr, "pcscf-2").await;
    let mut bgcf = Control::connect_as(control_addr, "bgcf-1").await;
    let (caller, caller_addr) = phone().await;
    let (callee, callee_addr) = phone().await;

    // The originating instance offers; the terminating instance answers the same call.
    let far = originating.offer(Some("pcscf"), caller_addr).await;
    let near = terminating.answer(Some("pcscf"), callee_addr).await;
    let forward = rtp(0x0A0A_0A0A, b"caller to callee");
    caller.send_to(&forward, near).await.expect("send caller");
    assert_eq!(recv(&callee).await, (forward, far));
    let backward = rtp(0x0B0B_0B0B, b"callee to caller");
    callee.send_to(&backward, far).await.expect("send callee");
    assert_eq!(recv(&caller).await, (backward, near));

    // A BGCF anchoring the same Call-ID gets a call of its own, on its own ports.
    let (breakout, breakout_addr) = phone().await;
    let (trunk, trunk_addr) = phone().await;
    let bgcf_far = bgcf.offer(Some("bgcf"), breakout_addr).await;
    let bgcf_near = bgcf.answer(Some("bgcf"), trunk_addr).await;
    assert!(![near, far].contains(&bgcf_far) && ![near, far].contains(&bgcf_near));
    let breakout_media = rtp(0x0C0C_0C0C, b"breakout to trunk");
    breakout
        .send_to(&breakout_media, bgcf_near)
        .await
        .expect("send breakout");
    assert_eq!(recv(&trunk).await, (breakout_media, bgcf_far));

    // Either instance may query the shared call, but a listing stays the creator's own: a
    // controller deletes what it lists and does not recognise.
    assert!(matches!(
        terminating.query(Some("pcscf")).await,
        CmdResult::Ok { stats: Some(_), .. }
    ));
    assert_eq!(
        originating.list(Some("pcscf")).await,
        vec![CALL_ID.to_string()]
    );
    assert!(terminating.list(Some("pcscf")).await.is_empty());

    // The BYE reaches the terminating instance first: it releases the call, and the originating
    // instance's own delete then finds it already gone.
    assert!(matches!(
        terminating.delete(Some("pcscf")).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        error_reason(&originating.delete(Some("pcscf")).await),
        format!("unknown call: {CALL_ID} (scope pcscf)")
    );
    // The BGCF's call never noticed.
    let still = rtp(0x0D0D_0D0D, b"still breaking out");
    breakout.send_to(&still, bgcf_near).await.expect("send");
    assert_eq!(recv(&trunk).await, (still, bgcf_far));
}

/// Without a scope nothing changed: a call is private to the controller that created it, and a
/// second controller naming the same Call-ID is told the call is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unscoped_call_stays_private_to_its_controller() {
    let (engine, control_addr) = serve().await;
    let mut first = Control::connect_as(control_addr, "pcscf-1").await;
    let mut second = Control::connect_as(control_addr, "bgcf-1").await;
    let (_caller, caller_addr) = phone().await;
    let (_callee, callee_addr) = phone().await;

    first.offer(None, caller_addr).await;
    assert_eq!(engine.metrics().scoped_offers_total(), 0);
    for refused in [
        second
            .request(
                None,
                Command::Offer {
                    call_id: CALL_ID.into(),
                    from_tag: FROM_TAG.into(),
                    sdp: sdp_for(callee_addr),
                    profile: Default::default(),
                },
            )
            .await,
        second
            .request(
                None,
                Command::Answer {
                    call_id: CALL_ID.into(),
                    from_tag: FROM_TAG.into(),
                    to_tag: TO_TAG.into(),
                    sdp: sdp_for(callee_addr),
                    profile: Default::default(),
                },
            )
            .await,
        second.query(None).await,
        second.delete(None).await,
    ] {
        assert_eq!(error_reason(&refused), format!("unknown call: {CALL_ID}"));
    }
    assert!(second.list(None).await.is_empty());
    assert_eq!(first.list(None).await, vec![CALL_ID.to_string()]);
}

/// An on-net call at one P-CSCF: the same controller anchors the originating and the terminating
/// side of one Call-ID, on one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_controller_anchors_one_call_id_twice_under_two_scopes() {
    let (_engine, control_addr) = serve().await;
    let mut control = Control::connect_as(control_addr, "pcscf-1").await;
    let (caller, caller_addr) = phone().await;
    let (callee, callee_addr) = phone().await;

    // One connection carries both passes, so the helper takes it twice in turn.
    let first_far = control.offer(Some("pcscf-orig"), caller_addr).await;
    let second_far = control.offer(Some("pcscf-term"), first_far).await;
    let second_near = control.answer(Some("pcscf-term"), callee_addr).await;
    let first_near = control.answer(Some("pcscf-orig"), second_near).await;
    let chain = Chain {
        first_near,
        first_far,
        second_near,
        second_far,
    };
    assert_chain_relays(&chain, &caller, &callee).await;

    assert_eq!(
        control.list(Some("pcscf-orig")).await,
        vec![CALL_ID.to_string()]
    );
    assert_eq!(
        control.list(Some("pcscf-term")).await,
        vec![CALL_ID.to_string()]
    );
    assert!(
        control.list(None).await.is_empty(),
        "neither pass is the unscoped call"
    );
}

/// Deleting one scope's call leaves the other scope's call, and the unscoped one, relaying.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_one_scope_leaves_the_others_relaying() {
    let (_engine, control_addr) = serve().await;
    let mut control = Control::connect(control_addr).await;

    let mut calls = Vec::new();
    for scope in [Some("bgcf"), Some("mrf"), None] {
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let far = control.offer(scope, addr_a).await;
        let near = control.answer(scope, addr_b).await;
        calls.push((scope, phone_a, phone_b, near, far));
    }

    assert!(matches!(
        control.delete(Some("bgcf")).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        error_reason(&control.query(Some("bgcf")).await),
        format!("unknown call: {CALL_ID} (scope bgcf)")
    );
    assert_eq!(
        error_reason(&control.delete(Some("bgcf")).await),
        format!("unknown call: {CALL_ID} (scope bgcf)"),
        "a second delete finds nothing, and does not fall through to another scope"
    );

    for (scope, phone_a, phone_b, near, far) in &calls {
        let packet = rtp(0x0C0C_0C0C, scope.unwrap_or("unscoped").as_bytes());
        phone_a.send_to(&packet, *near).await.expect("send a");
        if *scope == Some("bgcf") {
            assert!(hears_nothing(phone_b).await, "the deleted call is gone");
        } else {
            assert_eq!(
                recv(phone_b).await,
                (packet, *far),
                "{scope:?} still relays"
            );
            assert!(matches!(
                control.query(*scope).await,
                CmdResult::Ok { stats: Some(_), .. }
            ));
        }
    }
    assert_eq!(control.list(Some("mrf")).await, vec![CALL_ID.to_string()]);
    assert_eq!(control.list(None).await, vec![CALL_ID.to_string()]);
}

/// A media timeout in one scope is reported for that scope, and only that call ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_media_timeout_names_the_scope_it_happened_in() {
    let (engine, control_addr) = serve().await;
    let mut control = Control::connect(control_addr).await;

    // Three calls on one Call-ID. The `mrf` one keeps carrying media; the other two fall silent.
    let (_idle_scoped, idle_scoped_addr) = phone().await;
    control.offer(Some("bgcf"), idle_scoped_addr).await;
    let (_idle_plain, idle_plain_addr) = phone().await;
    control.offer(None, idle_plain_addr).await;
    let (live_a, live_a_addr) = phone().await;
    let (live_b, live_b_addr) = phone().await;
    let live_far = control.offer(Some("mrf"), live_a_addr).await;
    let live_near = control.answer(Some("mrf"), live_b_addr).await;

    engine.datapath().advance_clock(40);
    let packet = rtp(0x0D0D_0D0D, b"still talking");
    live_a.send_to(&packet, live_near).await.expect("send");
    assert_eq!(recv(&live_b).await, (packet, live_far));
    assert_eq!(engine.reap_idle(30, 0, 30).await.len(), 2);

    let mut timeouts = Vec::new();
    let mut summaries = Vec::new();
    for _ in 0..4 {
        let Scoped { scope, inner } = control.next_event().await;
        match inner {
            Event::MediaTimeout {
                call_id,
                from_tag,
                reason,
                ..
            } => {
                assert_eq!(call_id, CALL_ID, "the call id is the SIP one, not a key");
                assert_eq!(from_tag, FROM_TAG);
                assert_eq!(reason, MediaTimeoutReason::SetupTimeout);
                timeouts.push(scope);
            }
            Event::CallSummary { call_id, .. } => {
                assert_eq!(call_id, CALL_ID);
                summaries.push(scope);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
    timeouts.sort();
    summaries.sort();
    assert_eq!(timeouts, vec![None, Some("bgcf".to_string())]);
    assert_eq!(summaries, vec![None, Some("bgcf".to_string())]);

    assert_eq!(control.list(Some("mrf")).await, vec![CALL_ID.to_string()]);
    assert!(control.list(Some("bgcf")).await.is_empty());
    assert!(control.list(None).await.is_empty());
}

/// A playback started in one scope plays on that scope's call and reports its end there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_playback_event_names_the_scope_of_its_call() {
    let (_engine, control_addr) = serve().await;
    let mut control = Control::connect(control_addr).await;
    let (announced, announced_addr) = phone().await;
    let (bystander, bystander_addr) = phone().await;
    control.offer(Some("mrf"), announced_addr).await;
    control.offer(None, bystander_addr).await;

    let play = Command::PlayMedia {
        call_id: CALL_ID.into(),
        from_tag: FROM_TAG.into(),
        source: PlayMediaSource::Tone {
            tone: "425/60".to_string(),
        },
        repeat_times: None,
        start_pos_ms: None,
        duration_ms: None,
        overlay: false,
        gain_decibels: None,
        to_tag: None,
    };
    let accepted = control.request(Some("mrf"), play).await;
    let CmdResult::Ok {
        play_id: Some(play_id),
        ..
    } = accepted
    else {
        panic!("expected an accepted playback, got {accepted:?}");
    };
    let (packet, _) = recv(&announced).await;
    assert!(
        packet.len() > 12,
        "the tone reaches the scoped call's party"
    );

    let finished = loop {
        let event = control.next_event().await;
        if matches!(event.inner, Event::PlayFinished { .. }) {
            break event;
        }
    };
    assert_eq!(finished.scope.as_deref(), Some("mrf"));
    match finished.inner {
        Event::PlayFinished {
            call_id,
            play_id: finished_id,
            reason,
            ..
        } => {
            assert_eq!(call_id, CALL_ID);
            assert_eq!(finished_id, play_id);
            assert_eq!(reason, PlayEndReason::Completed);
        }
        other => panic!("unexpected event: {other:?}"),
    }
    assert!(
        hears_nothing(&bystander).await,
        "the unscoped call on the same Call-ID heard none of it"
    );
}

/// A call checkpointed in a scope is restored into that scope, beside its namesakes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_call_keeps_its_scope() {
    let (_primary_engine, primary_addr) = serve().await;
    let (_standby_engine, standby_addr) = serve().await;
    let mut primary = Control::connect(primary_addr).await;
    let mut standby = Control::connect(standby_addr).await;

    let mut calls = Vec::new();
    for scope in [Some("pcscf-orig"), Some("pcscf-term"), None] {
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let far = primary.offer(scope, addr_a).await;
        let near = primary.answer(scope, addr_b).await;
        let checkpoint = primary
            .request(
                scope,
                Command::Checkpoint {
                    call_id: CALL_ID.into(),
                    from_tag: FROM_TAG.into(),
                },
            )
            .await;
        let CmdResult::Checkpoint { snapshot } = checkpoint else {
            panic!("expected a checkpoint, got {checkpoint:?}");
        };
        let blob: serde_json::Value = serde_json::from_str(&snapshot).expect("snapshot is JSON");
        assert_eq!(
            blob["call_id"], CALL_ID,
            "the snapshot names the SIP call id"
        );
        match scope {
            Some(scope) => assert_eq!(blob["scope"], scope),
            None => {
                assert!(
                    blob.get("scope").is_none(),
                    "an unscoped snapshot has no scope key: {snapshot}"
                );
                assert_eq!(blob["version"], 2, "and keeps the version it always had");
            }
        }
        calls.push((scope, phone_a, phone_b, near, far, snapshot));
    }

    // The primary goes away: its ports are free for the standby to bind.
    for (scope, ..) in &calls {
        assert!(matches!(primary.delete(*scope).await, CmdResult::Ok { .. }));
    }
    // `restore` names no scope: the snapshot carries it.
    for (.., snapshot) in &calls {
        let restored = standby
            .request(
                None,
                Command::Restore {
                    snapshot: snapshot.clone(),
                },
            )
            .await;
        assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    }
    let again = standby
        .request(
            None,
            Command::Restore {
                snapshot: calls[0].5.clone(),
            },
        )
        .await;
    assert_eq!(
        error_reason(&again),
        format!("cannot restore: call {CALL_ID} (scope pcscf-orig) already exists")
    );

    for (scope, phone_a, phone_b, near, far, _) in &calls {
        assert_eq!(standby.list(*scope).await, vec![CALL_ID.to_string()]);
        let packet = rtp(0x0E0E_0E0E, scope.unwrap_or("unscoped").as_bytes());
        phone_a.send_to(&packet, *near).await.expect("send a");
        assert_eq!(
            recv(phone_b).await,
            (packet, *far),
            "{scope:?} resumes on its own ports"
        );
    }
    assert!(matches!(
        standby.delete(Some("pcscf-term")).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        standby.list(Some("pcscf-orig")).await,
        vec![CALL_ID.to_string()]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_scope_is_refused_before_any_work() {
    let (_engine, control_addr) = serve().await;
    let mut control = Control::connect(control_addr).await;
    let (_phone, addr) = phone().await;
    let offer = |call_id: &str| Command::Offer {
        call_id: call_id.into(),
        from_tag: FROM_TAG.into(),
        sdp: sdp_for(addr),
        profile: Default::default(),
    };

    let long = "a".repeat(65);
    assert_eq!(
        error_reason(&control.request(Some(&long), offer(CALL_ID)).await),
        "scope is 65 bytes; the maximum is 64"
    );
    for scope in ["pcscf orig", "pcscf/orig", "pcscf.orig", "pcscf\u{1f}"] {
        assert_eq!(
            error_reason(&control.request(Some(scope), offer(CALL_ID)).await),
            "scope may hold only ASCII letters, digits, '-' and '_'",
            "{scope:?}"
        );
    }
    // A scope is validated on every verb, including one that names no call.
    assert_eq!(
        error_reason(&control.request(Some("no good"), Command::Ping).await),
        "scope may hold only ASCII letters, digits, '-' and '_'"
    );
    assert_eq!(
        control.request(Some("bgcf"), Command::Ping).await,
        CmdResult::Pong
    );
    assert!(control.list(None).await.is_empty(), "nothing was anchored");

    // The byte that separates a call id from its scope inside the engine cannot be in a call id.
    assert_eq!(
        error_reason(&control.request(None, offer("abc\u{1f} scope=bgcf")).await),
        "call_id must not contain the control character U+001F"
    );

    // The empty scope is the unscoped call.
    control.offer(Some(""), addr).await;
    assert_eq!(control.list(None).await, vec![CALL_ID.to_string()]);
}

/// A room is named by an id its controller chose, not by a Call-ID, so there is nothing for a
/// scope to tell apart. Naming one is refused instead of being quietly dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scope_on_a_conference_verb_is_refused() {
    let (_engine, control_addr) = serve().await;
    let mut control = Control::connect(control_addr).await;
    let (_phone, addr) = phone().await;
    let join = Command::ConferenceJoin {
        conference_id: "room-1".into(),
        from_tag: FROM_TAG.into(),
        sdp: sdp_for(addr),
        role: ConferenceRole::Talker,
        profile: Default::default(),
    };
    assert_eq!(
        error_reason(&control.request(Some("mrf"), join.clone()).await),
        "scope does not apply to conference verbs; put the function in the conference_id"
    );
    assert!(matches!(
        control.request(None, join).await,
        CmdResult::Ok { .. }
    ));
}

/// A controller can tell, before it relies on scopes, whether this engine has them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_info_advertises_the_scope_feature() {
    let (_engine, control_addr) = serve().await;
    let mut control = Control::connect(control_addr).await;
    let CmdResult::NodeInfo { node } = control.request(None, Command::NodeInfo).await else {
        panic!("expected node_info");
    };
    assert!(node.features.iter().any(|feature| feature == "scope"));
}

/// Two scopes of one Call-ID record to two files: the scope is part of the name the engine
/// derives, and an unscoped call keeps the name it always had.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_of_a_scoped_call_has_its_own_file() {
    let (_engine, control_addr) = serve().await;
    let mut control = Control::connect(control_addr).await;
    let directory = std::env::temp_dir().join(format!("call-scope-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create recording dir");

    for scope in [Some("bgcf"), Some("mrf"), None] {
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        control.offer(scope, addr_a).await;
        control.answer(scope, addr_b).await;
        let started = control
            .request(
                scope,
                Command::StartRecording {
                    call_id: CALL_ID.into(),
                    from_tag: FROM_TAG.into(),
                    recording_dir: Some(directory.to_string_lossy().into_owned()),
                    format: None,
                    direction: None,
                    channels: None,
                    max_duration_ms: None,
                    silence_ms: None,
                    path: None,
                    bitrate_bps: None,
                },
            )
            .await;
        assert!(matches!(started, CmdResult::Ok { .. }), "{started:?}");
    }

    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .expect("read recording dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            format!("{CALL_ID}.bgcf.pcap"),
            format!("{CALL_ID}.mrf.pcap"),
            format!("{CALL_ID}.pcap"),
        ]
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// In a shared scope a call's events go to the instance that created it, including the events of
/// the media pipeline the other instance's `answer` built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shared_call_reports_to_the_instance_that_offered_it() {
    let (engine, control_addr) = serve().await;
    let mut originating = Control::connect_as(control_addr, "pcscf-1").await;
    let mut terminating = Control::connect_as(control_addr, "pcscf-2").await;
    let (caller, caller_addr) = phone().await;
    let (_callee, callee_addr) = phone().await;
    let audio = |addr: SocketAddr, payload_type: u8, codec: &str| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {payload_type} 101\r\na=rtpmap:{payload_type} {codec}/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\n",
            ip = addr.ip(),
            port = addr.port()
        )
    };

    // PCMU toward the caller, PCMA toward the callee: the answer builds a transcoding pipeline.
    let offered = originating
        .request(
            Some("pcscf"),
            Command::Offer {
                call_id: CALL_ID.into(),
                from_tag: FROM_TAG.into(),
                sdp: audio(caller_addr, 0, "PCMU"),
                profile: siphon_rtp_proto::ProfileFlags {
                    flags: vec!["codec-transcode-PCMA".into()],
                    ..Default::default()
                },
            },
        )
        .await;
    engine_addr(&offered);
    let answered = terminating
        .request(
            Some("pcscf"),
            Command::Answer {
                call_id: CALL_ID.into(),
                from_tag: FROM_TAG.into(),
                to_tag: TO_TAG.into(),
                sdp: audio(callee_addr, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let near = engine_addr(&answered);

    // The caller presses 5: an RFC 4733 event, its end sent three times (section 2.5.1.4).
    for sequence in 0..3u16 {
        let mut packet = vec![0x80, 101];
        packet.extend_from_slice(&(100 + sequence).to_be_bytes());
        packet.extend_from_slice(&8000u32.to_be_bytes());
        packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
        packet.extend_from_slice(&[5, 0x80 | 10, 0x03, 0xC0]);
        caller.send_to(&packet, near).await.expect("send dtmf");
    }
    let digit = loop {
        let event = originating.next_event().await;
        if matches!(event.inner, Event::Dtmf { .. }) {
            break event;
        }
    };
    assert_eq!(digit.scope.as_deref(), Some("pcscf"));
    match digit.inner {
        Event::Dtmf { call_id, digit, .. } => {
            assert_eq!(call_id, CALL_ID);
            assert_eq!(digit, "5");
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // The path dies: the timeout and the summary reach the offering instance too.
    engine.datapath().advance_clock(40);
    assert_eq!(engine.reap_idle(30, 0, 30).await.len(), 1);
    let mut seen = Vec::new();
    while seen.len() < 2 {
        let event = originating.next_event().await;
        assert_eq!(event.scope.as_deref(), Some("pcscf"));
        match event.inner {
            Event::MediaTimeout { .. } => seen.push("media_timeout"),
            Event::CallSummary { .. } => seen.push("call_summary"),
            _ => {}
        }
    }
    seen.sort_unstable();
    assert_eq!(seen, ["call_summary", "media_timeout"]);

    // Nothing was pushed to the instance that only answered.
    assert_eq!(
        terminating.request(Some("pcscf"), Command::Ping).await,
        CmdResult::Pong
    );
    assert!(terminating.events.is_empty(), "{:?}", terminating.events);
}
