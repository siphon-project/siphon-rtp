//! A WebSocket endpoint the engine is told to dial must not be able to take the control connection
//! down with it: not by accepting the TCP connection and never answering, not by answering slowly,
//! not by resetting, and not by stalling a TLS handshake.
//!
//! Driven over the real JSON-over-TCP control connection, with the endpoint a local TCP listener
//! that misbehaves in one way per test. NIC-free (UDP-loopback datapath, loopback sockets).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher_with_text;
use siphon_rtp_engine::{server, Engine};
use siphon_rtp_proto::{
    frame, CmdResult, Command, ProfileFlags, Request, Response, Scoped, WsTeeDirection,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// The dial bound these tests run the engine with: short, so a stalled endpoint is waited out
/// inside a test, and far above how long an unrelated command may take.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_200);
/// How long an unrelated command may take while a dial is in flight.
const PROMPT: Duration = Duration::from_millis(400);

/// A control client that can send a request without waiting for its response, so that a second
/// request can be put on the same connection while the first is still being served.
struct Control {
    stream: TcpStream,
    buffer: Vec<u8>,
    next_id: u64,
}

impl Control {
    async fn connect(addr: SocketAddr) -> Self {
        Self {
            stream: TcpStream::connect(addr).await.expect("connect control"),
            buffer: Vec::new(),
            next_id: 1,
        }
    }

    /// Put a request on the wire and return its id.
    async fn send(&mut self, command: Command) -> u64 {
        self.send_scoped(None, command).await
    }

    /// Put a request on the wire in a frame that names `scope`, and return its id. With no scope
    /// the frame is the plain request.
    async fn send_scoped(&mut self, scope: Option<&str>, command: Command) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let request = Scoped::new(scope.map(str::to_owned), Request { id, command });
        let bytes = frame::encode(&request).expect("encode request");
        self.stream.write_all(&bytes).await.expect("write request");
        id
    }

    /// The next response on the connection, events skipped, or `None` when none arrives in `wait`.
    async fn next_response(&mut self, wait: Duration) -> Option<Response> {
        let deadline = Instant::now() + wait;
        let mut chunk = [0u8; 4096];
        loop {
            while let Some((value, consumed)) =
                frame::decode::<serde_json::Value>(&self.buffer).expect("decode frame")
            {
                self.buffer.drain(..consumed);
                if value.get("event").is_none() {
                    return Some(serde_json::from_value(value).expect("response shape"));
                }
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let read = timeout(remaining, self.stream.read(&mut chunk))
                .await
                .ok()?
                .expect("read control");
            assert_ne!(read, 0, "control connection closed unexpectedly");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// The response to request `id`, which must be the next one to arrive, inside `wait`.
    async fn response_to(&mut self, id: u64, wait: Duration) -> CmdResult {
        let response = self
            .next_response(wait)
            .await
            .unwrap_or_else(|| panic!("no response to request {id} within {wait:?}"));
        assert_eq!(response.id, id, "the next response answers request {id}");
        response.result
    }

    async fn request(&mut self, command: Command) -> CmdResult {
        let id = self.send(command).await;
        self.response_to(id, Duration::from_secs(3)).await
    }
}

fn sdp_for(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

async fn phone() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind phone");
    socket.local_addr().expect("phone addr")
}

/// An engine behind a control listener, and a control connection to it.
async fn engine_and_control() -> (Arc<Engine<UdpLoopbackDatapath>>, Control) {
    let engine =
        Arc::new(Engine::new(UdpLoopbackDatapath::new()).with_ws_connect_timeout(CONNECT_TIMEOUT));
    // The redirect dispatcher, as the daemon runs it: a call that a tee holds in userspace has
    // its packets relayed by its media actor, which this feeds.
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
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let addr = listener.local_addr().expect("control addr");
    let serve_engine = engine.clone();
    tokio::spawn(async move {
        let _ = server::serve(serve_engine, listener).await;
    });
    (engine, Control::connect(addr).await)
}

/// Set a two-party relayed call up.
async fn two_party_call(control: &mut Control, call_id: &str) {
    let offer = control
        .request(Command::Offer {
            call_id: call_id.into(),
            from_tag: "tag-a".into(),
            sdp: sdp_for(phone().await),
            profile: ProfileFlags::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "{offer:?}");
    let answer = control
        .request(Command::Answer {
            call_id: call_id.into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: sdp_for(phone().await),
            profile: ProfileFlags::default(),
        })
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }), "{answer:?}");
}

fn attach_tee(call_id: &str, ws_uri: String) -> Command {
    Command::AttachWsTee {
        call_id: call_id.into(),
        from_tag: "tag-a".into(),
        ws_uri,
        direction: WsTeeDirection::Both,
        channels: None,
        sample_rate: None,
    }
}

fn delete(call_id: &str) -> Command {
    Command::Delete {
        call_id: call_id.into(),
        from_tag: "tag-a".into(),
        to_tag: None,
    }
}

/// How a misbehaving endpoint treats each connection it accepts.
#[derive(Clone, Copy)]
enum Endpoint {
    /// Accept, then never read or write: a hung process behind a live socket.
    NeverAnswers,
    /// Accept and close at once.
    Resets,
    /// Complete the WebSocket upgrade after this long.
    AnswersAfter(Duration),
    /// Complete the WebSocket upgrade, then hold the connection without ever reading from it.
    StopsReading,
}

/// A local endpoint that misbehaves as told. Returns its address, how many connections it has
/// accepted, and how many of those the engine has closed again.
async fn endpoint(behaviour: Endpoint) -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind endpoint");
    let addr = listener.local_addr().expect("endpoint addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (accepted_count, closed_count) = (accepted.clone(), closed.clone());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            accepted_count.fetch_add(1, Ordering::SeqCst);
            let closed_count = closed_count.clone();
            tokio::spawn(async move {
                match behaviour {
                    Endpoint::Resets => drop(stream),
                    Endpoint::NeverAnswers => {
                        // Hold the connection without ever reading: the peer's bytes stay in the
                        // socket buffer, exactly as with a process that is stuck. Noticing the
                        // close needs a read, so read only once the peer is done writing.
                        tokio::time::sleep(CONNECT_TIMEOUT + Duration::from_millis(300)).await;
                        let mut sink = [0u8; 4096];
                        while matches!(stream.read(&mut sink).await, Ok(read) if read > 0) {}
                        closed_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Endpoint::StopsReading => {
                        if let Ok(socket) = tokio_tungstenite::accept_async(stream).await {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            drop(socket);
                        }
                    }
                    Endpoint::AnswersAfter(delay) => {
                        tokio::time::sleep(delay).await;
                        if let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await {
                            use futures_util::StreamExt;
                            while let Some(Ok(_)) = socket.next().await {}
                        }
                        closed_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
        }
    });
    (addr, accepted, closed)
}

fn error_reason(result: &CmdResult) -> &str {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected an error, got {other:?}"),
    }
}

/// The defect: one endpoint that accepts and never answers, and from then on the control
/// connection serves nothing. The other commands must be answered while the dial is in flight, the
/// dial must give up at its bound, and only its own command fails.
#[tokio::test]
async fn an_endpoint_that_never_answers_stalls_neither_other_commands_nor_other_calls() {
    let (engine, mut control) = engine_and_control().await;
    two_party_call(&mut control, "tapped").await;
    let (hung, accepted, _closed) = endpoint(Endpoint::NeverAnswers).await;

    let started = Instant::now();
    let attach = control
        .send(attach_tee("tapped", format!("ws://{hung}/stream")))
        .await;
    // A health probe, and another call set up from scratch, on the same connection.
    let ping = control.send(Command::Ping).await;
    assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
    two_party_call(&mut control, "bystander").await;
    assert!(
        started.elapsed() < CONNECT_TIMEOUT,
        "the bystander call was set up while the dial was still in flight"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the endpoint was dialled"
    );

    // The dial gives up at its bound, and the error names what happened.
    let result = control
        .response_to(attach, CONNECT_TIMEOUT + Duration::from_secs(1))
        .await;
    let elapsed = started.elapsed();
    assert!(error_reason(&result).contains("timed out"), "{result:?}");
    assert!(
        elapsed >= CONNECT_TIMEOUT && elapsed < CONNECT_TIMEOUT + Duration::from_millis(700),
        "gave up after {elapsed:?}"
    );

    // The tapped call is untouched: still there, still deletable, at once.
    assert_eq!(engine.session_count(), 2);
    let removed = control.send(delete("tapped")).await;
    assert!(matches!(
        control.response_to(removed, PROMPT).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.session_count(), 1);
}

/// Commands for the call whose dial is in flight wait for it, in order, so that a controller's
/// own sequence on one call is never reordered; everything else overtakes.
#[tokio::test]
async fn commands_for_the_dialling_call_keep_their_order_and_others_overtake() {
    let (_engine, mut control) = engine_and_control().await;
    two_party_call(&mut control, "tapped").await;
    let (hung, _accepted, _closed) = endpoint(Endpoint::NeverAnswers).await;

    let attach = control
        .send(attach_tee("tapped", format!("ws://{hung}/stream")))
        .await;
    let removed = control.send(delete("tapped")).await;
    let ping = control.send(Command::Ping).await;
    // The ping overtakes both; the delete waits behind the attach it was sent after.
    assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
    let wait = CONNECT_TIMEOUT + Duration::from_secs(1);
    assert!(matches!(
        control.response_to(attach, wait).await,
        CmdResult::Error { .. }
    ));
    assert!(matches!(
        control.response_to(removed, PROMPT).await,
        CmdResult::Ok { .. }
    ));
}

/// An endpoint that answers the upgrade slowly, inside the bound: the attach succeeds, and
/// nothing waited for it.
#[tokio::test]
async fn a_slow_upgrade_inside_the_bound_succeeds_without_holding_anything_up() {
    let (_engine, mut control) = engine_and_control().await;
    two_party_call(&mut control, "tapped").await;
    let delay = CONNECT_TIMEOUT / 2;
    let (slow, _accepted, _closed) = endpoint(Endpoint::AnswersAfter(delay)).await;

    let started = Instant::now();
    let attach = control
        .send(attach_tee("tapped", format!("ws://{slow}/stream")))
        .await;
    let ping = control.send(Command::Ping).await;
    assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
    assert!(
        started.elapsed() < delay,
        "the ping did not wait for the upgrade"
    );
    let result = control.response_to(attach, CONNECT_TIMEOUT).await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    assert!(started.elapsed() >= delay);
}

/// An endpoint that accepts and resets: an error at once, for that command only.
#[tokio::test]
async fn an_endpoint_that_resets_fails_the_command_at_once() {
    let (engine, mut control) = engine_and_control().await;
    two_party_call(&mut control, "tapped").await;
    let (resetting, _accepted, _closed) = endpoint(Endpoint::Resets).await;

    let started = Instant::now();
    let result = control
        .request(attach_tee("tapped", format!("ws://{resetting}/stream")))
        .await;
    assert!(
        error_reason(&result).starts_with("attach_ws_tee: dial"),
        "{result:?}"
    );
    assert!(started.elapsed() < PROMPT, "after {:?}", started.elapsed());
    assert_eq!(engine.session_count(), 1, "the call is untouched");
}

/// `wss://` to an endpoint that accepts and never completes the TLS handshake: the same bound.
#[tokio::test]
async fn a_tls_handshake_that_stalls_is_bounded_like_the_rest_of_the_dial() {
    let (_engine, mut control) = engine_and_control().await;
    two_party_call(&mut control, "tapped").await;
    let (hung, _accepted, _closed) = endpoint(Endpoint::NeverAnswers).await;

    let started = Instant::now();
    let attach = control
        .send(attach_tee(
            "tapped",
            format!("wss://localhost:{}/stream", hung.port()),
        ))
        .await;
    let ping = control.send(Command::Ping).await;
    assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
    let result = control
        .response_to(attach, CONNECT_TIMEOUT + Duration::from_secs(1))
        .await;
    assert!(error_reason(&result).contains("timed out"), "{result:?}");
    assert!(started.elapsed() >= CONNECT_TIMEOUT);
}

/// The other verbs that dial: a runtime bridge attach, and a local answer whose profile names a
/// WebSocket server. A stalled endpoint fails each of them at the bound, with a health probe
/// answered meanwhile, and the local answer leaves no call behind.
#[tokio::test]
async fn a_bridge_attach_and_a_local_answer_are_bounded_too() {
    let (engine, mut control) = engine_and_control().await;
    two_party_call(&mut control, "bridged").await;
    let (hung, _accepted, _closed) = endpoint(Endpoint::NeverAnswers).await;
    let wait = CONNECT_TIMEOUT + Duration::from_secs(1);

    let attach = control
        .send(Command::AttachWsBridge {
            call_id: "bridged".into(),
            from_tag: "tag-a".into(),
            ws_uri: format!("ws://{hung}/agent"),
            profile: None,
        })
        .await;
    let ping = control.send(Command::Ping).await;
    assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
    let result = control.response_to(attach, wait).await;
    assert!(error_reason(&result).contains("timed out"), "{result:?}");

    let answer = control
        .send(Command::AnswerLocal {
            call_id: "agent-call".into(),
            from_tag: "tag-a".into(),
            sdp: sdp_for(phone().await),
            profile: ProfileFlags {
                ws_uri: Some(format!("ws://{hung}/agent")),
                ..ProfileFlags::default()
            },
        })
        .await;
    let ping = control.send(Command::Ping).await;
    assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
    let result = control.response_to(answer, wait).await;
    assert!(error_reason(&result).contains("timed out"), "{result:?}");
    assert_eq!(engine.session_count(), 1, "only the two-party call remains");
}

/// Twenty stalled dials at once: each fails on its own, every connection the engine opened is
/// closed again, no task outlives its dial, and each failure is counted by its class.
#[tokio::test]
async fn failed_dials_leave_no_socket_and_no_task_behind() {
    const CALLS: usize = 20;
    let (engine, mut control) = engine_and_control().await;
    for index in 0..CALLS {
        two_party_call(&mut control, &format!("call-{index}")).await;
    }
    let (hung, accepted, closed) = endpoint(Endpoint::NeverAnswers).await;
    let tasks_before = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();

    let mut pending = Vec::new();
    for index in 0..CALLS {
        let uri = format!("ws://{hung}/stream");
        pending.push(
            control
                .send(attach_tee(&format!("call-{index}"), uri))
                .await,
        );
    }
    let mut failed = 0;
    while failed < CALLS {
        let response = control
            .next_response(CONNECT_TIMEOUT + Duration::from_secs(2))
            .await
            .expect("every dial is answered");
        assert!(pending.contains(&response.id));
        assert!(error_reason(&response.result).contains("timed out"));
        failed += 1;
    }
    assert_eq!(accepted.load(Ordering::SeqCst), CALLS);

    // Every connection is closed from the engine's side, and the tasks are back to where they were
    // (plus the endpoint's own accept tasks, which end once they have seen the close).
    let deadline = Instant::now() + Duration::from_secs(3);
    while closed.load(Ordering::SeqCst) < CALLS && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(closed.load(Ordering::SeqCst), CALLS, "sockets closed");
    let tasks_after = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    assert!(
        tasks_after <= tasks_before,
        "{tasks_before} tasks before the dials, {tasks_after} after"
    );
    assert_eq!(engine.session_count(), CALLS, "every call is still up");

    let rendered = engine
        .metrics()
        .render(siphon_rtp_engine::metrics::LiveGauges::default(), 0);
    assert!(
        rendered.contains(&format!("siphon_rtp_ws_dial_timeouts_total {CALLS}\n")),
        "{rendered}"
    );
}

/// The port of the `m=audio` line of an SDP the engine returned.
fn audio_port(result: &CmdResult) -> u16 {
    let CmdResult::Ok { sdp: Some(sdp), .. } = result else {
        panic!("expected an SDP, got {result:?}");
    };
    sdp.lines()
        .find_map(|line| line.strip_prefix("m=audio "))
        .and_then(|rest| rest.split(' ').next())
        .and_then(|port| port.parse().ok())
        .expect("an audio port")
}

/// A minimal RTP packet (RFC 3550 §5.1): PCMA, 160 octets of payload.
fn rtp(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 8];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    packet.extend_from_slice(&[0xD5; 160]);
    packet
}

/// A server that completes the upgrade and then stops reading. The tee is attached, the call it
/// taps goes on relaying every packet, and detaching or deleting it does not wait for the server.
#[tokio::test]
async fn a_server_that_stops_reading_changes_nothing_for_the_call_it_taps() {
    let (engine, mut control) = engine_and_control().await;
    let caller = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let callee = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let offer = control
        .request(Command::Offer {
            call_id: "tapped".into(),
            from_tag: "tag-a".into(),
            sdp: sdp_for(caller.local_addr().expect("addr")),
            profile: ProfileFlags::default(),
        })
        .await;
    let answer = control
        .request(Command::Answer {
            call_id: "tapped".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: sdp_for(callee.local_addr().expect("addr")),
            profile: ProfileFlags::default(),
        })
        .await;
    // The caller sends to the port the answer gave it; the callee's packets arrive from the
    // engine's port on its side, which the offer's rewritten SDP named.
    let toward_engine = SocketAddr::from((Ipv4Addr::LOCALHOST, audio_port(&answer)));
    let _ = audio_port(&offer);

    let (stalled, _accepted, _closed) = endpoint(Endpoint::StopsReading).await;
    let attached = control
        .request(attach_tee("tapped", format!("ws://{stalled}/stream")))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");

    // Twenty seconds of audio, sent as fast as the relay takes it: far more than the tee's queue
    // and the server's socket buffer hold between them. Every packet still reaches the callee.
    let packets = 1_000u16;
    let mut received = 0u16;
    let mut buffer = [0u8; 1500];
    for sequence in 0..packets {
        caller
            .send_to(&rtp(sequence), toward_engine)
            .await
            .expect("send");
        let (length, _) = timeout(Duration::from_secs(1), callee.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("packet {sequence} was not relayed"))
            .expect("recv");
        assert_eq!(length, 172);
        received += 1;
    }
    assert_eq!(received, packets);

    // The control connection is as quick as ever, and so are detaching and deleting.
    let ping = control.send(Command::Ping).await;
    assert_eq!(control.response_to(ping, PROMPT).await, CmdResult::Pong);
    let detached = control
        .send(Command::DetachWsTee {
            call_id: "tapped".into(),
            from_tag: "tag-a".into(),
        })
        .await;
    assert!(matches!(
        control.response_to(detached, PROMPT).await,
        CmdResult::Ok { .. }
    ));
    let removed = control.send(delete("tapped")).await;
    assert!(matches!(
        control.response_to(removed, PROMPT).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.session_count(), 0);
}

/// A command served beside the loop still has its response written before the events it raised:
/// `ok` and then `ws_tee_started`, as when it was served in line.
#[tokio::test]
async fn a_dialling_commands_response_still_precedes_the_events_it_raised() {
    let (_engine, mut control) = engine_and_control().await;
    two_party_call(&mut control, "tapped").await;
    let (slow, _accepted, _closed) = endpoint(Endpoint::AnswersAfter(PROMPT)).await;
    let attach = control
        .send(attach_tee("tapped", format!("ws://{slow}/stream")))
        .await;

    let mut frames = Vec::new();
    let mut chunk = [0u8; 4096];
    while frames.len() < 2 {
        while let Some((value, consumed)) =
            frame::decode::<serde_json::Value>(&control.buffer).expect("decode frame")
        {
            control.buffer.drain(..consumed);
            frames.push(value);
        }
        if frames.len() < 2 {
            let read = timeout(CONNECT_TIMEOUT, control.stream.read(&mut chunk))
                .await
                .expect("a frame")
                .expect("read");
            control.buffer.extend_from_slice(&chunk[..read]);
        }
    }
    assert_eq!(frames[0]["id"], attach, "{frames:?}");
    assert_eq!(frames[0]["result"], "ok", "{frames:?}");
    assert_eq!(frames[1]["event"], "ws_tee_started", "{frames:?}");
}

/// A lane is one call, and a call is the one of its scope. A dial in flight on a scoped call
/// holds back what was sent for that scope of the `call_id` and nothing sent for another, and the
/// event the command raised still follows its response, named as the wire names a scoped call.
#[tokio::test]
async fn a_dial_on_a_scoped_call_holds_its_own_scope_only() {
    let (_engine, mut control) = engine_and_control().await;
    // One `call_id` anchored twice on this connection: unscoped, and under a scope.
    two_party_call(&mut control, "shared").await;
    let offer = Command::Offer {
        call_id: "shared".into(),
        from_tag: "tag-a".into(),
        sdp: sdp_for(phone().await),
        profile: ProfileFlags::default(),
    };
    let answer = Command::Answer {
        call_id: "shared".into(),
        from_tag: "tag-a".into(),
        to_tag: "tag-b".into(),
        sdp: sdp_for(phone().await),
        profile: ProfileFlags::default(),
    };
    for command in [offer, answer] {
        let id = control.send_scoped(Some("bgcf"), command).await;
        let result = control.response_to(id, Duration::from_secs(3)).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }

    let (slow, _accepted, _closed) = endpoint(Endpoint::AnswersAfter(PROMPT)).await;
    let attach = control
        .send_scoped(
            Some("bgcf"),
            attach_tee("shared", format!("ws://{slow}/stream")),
        )
        .await;
    let scoped_delete = control.send_scoped(Some("bgcf"), delete("shared")).await;
    let unscoped_delete = control.send(delete("shared")).await;

    // Every frame up to the response of the delete that waited.
    let mut frames: Vec<serde_json::Value> = Vec::new();
    let mut chunk = [0u8; 4096];
    while !frames.iter().any(|frame| frame["id"] == scoped_delete) {
        while let Some((value, consumed)) =
            frame::decode::<serde_json::Value>(&control.buffer).expect("decode frame")
        {
            control.buffer.drain(..consumed);
            frames.push(value);
        }
        if !frames.iter().any(|frame| frame["id"] == scoped_delete) {
            let read = timeout(CONNECT_TIMEOUT, control.stream.read(&mut chunk))
                .await
                .expect("a frame")
                .expect("read");
            control.buffer.extend_from_slice(&chunk[..read]);
        }
    }
    let position = |wanted: &dyn Fn(&serde_json::Value) -> bool| {
        frames
            .iter()
            .position(wanted)
            .unwrap_or_else(|| panic!("frame missing in {frames:?}"))
    };
    let unscoped_deleted = position(&|frame| frame["id"] == unscoped_delete);
    let attached = position(&|frame| frame["id"] == attach);
    let scoped_deleted = position(&|frame| frame["id"] == scoped_delete);
    let started = position(&|frame| frame["event"] == "ws_tee_started");
    // The unscoped call of the same `call_id` is another lane: its delete overtakes the dial.
    assert!(unscoped_deleted < attached, "{frames:?}");
    assert_eq!(frames[unscoped_deleted]["result"], "ok", "{frames:?}");
    // The delete of the dialling scope waited for the attach it was sent after.
    assert_eq!(frames[attached]["result"], "ok", "{frames:?}");
    assert!(attached < scoped_deleted, "{frames:?}");
    assert_eq!(frames[scoped_deleted]["result"], "ok", "{frames:?}");
    // `ok` and then `ws_tee_started`, which names the call by `call_id` with its scope beside it.
    assert!(attached < started, "{frames:?}");
    assert_eq!(frames[started]["call_id"], "shared", "{frames:?}");
    assert_eq!(frames[started]["scope"], "bgcf", "{frames:?}");
}
