//! The unscoped control wire, pinned as bytes.
//!
//! Every frame here is written out as JSON text, not built from the protocol types, so this file
//! says what a controller built against an earlier release puts on the wire and what it reads
//! back. It exercises nothing the call scope added: it passed, unchanged, on the release before
//! scopes existed, and it has to keep passing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{sdp, server, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// A control connection that speaks in JSON text and keeps each frame's exact body.
struct RawControl {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl RawControl {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect control");
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    async fn send(&mut self, body: &str) {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body.as_bytes());
        self.stream.write_all(&frame).await.expect("write frame");
    }

    /// The next frame's body, exactly as the engine wrote it.
    async fn next_frame(&mut self) -> String {
        let mut chunk = [0u8; 4096];
        loop {
            if self.buffer.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.buffer[0],
                    self.buffer[1],
                    self.buffer[2],
                    self.buffer[3],
                ]) as usize;
                if self.buffer.len() >= 4 + len {
                    let body = String::from_utf8(self.buffer[4..4 + len].to_vec())
                        .expect("frame body is UTF-8");
                    self.buffer.drain(..4 + len);
                    return body;
                }
            }
            let read = timeout(Duration::from_secs(2), self.stream.read(&mut chunk))
                .await
                .expect("frame not timed out")
                .expect("read frame");
            assert_ne!(read, 0, "control connection closed unexpectedly");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Send a request and return the response body, skipping events pushed in between.
    async fn request(&mut self, body: &str) -> String {
        self.send(body).await;
        loop {
            let frame = self.next_frame().await;
            if !frame.starts_with("{\"event\"") {
                return frame;
            }
        }
    }
}

async fn serve() -> (Arc<Engine<UdpLoopbackDatapath>>, SocketAddr) {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
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

/// An SDP body as it sits inside a JSON string (CRLF escaped).
fn sdp_json(addr: SocketAddr) -> String {
    format!(
        "v=0\\r\\no=- 1 1 IN IP4 {ip}\\r\\ns=-\\r\\nc=IN IP4 {ip}\\r\\nt=0 0\\r\\n\
         m=audio {port} RTP/AVP 0 8\\r\\na=rtpmap:0 PCMU/8000\\r\\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

/// The engine media address a response's SDP advertises.
fn engine_addr(response: &str) -> SocketAddr {
    let value: serde_json::Value = serde_json::from_str(response).expect("response is JSON");
    assert_eq!(value["result"], "ok", "expected ok, got {response}");
    let text = value["sdp"].as_str().expect("response carries sdp");
    sdp::parse(text).expect("parse engine sdp").remote_rtp
}

fn rtp(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(b"voice");
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

/// Whether anything reaches `socket` within a short window.
async fn hears_nothing(socket: &UdpSocket) -> bool {
    let mut buffer = [0u8; 2048];
    timeout(Duration::from_millis(200), socket.recv_from(&mut buffer))
        .await
        .is_err()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unscoped_frames_are_answered_byte_for_byte() {
    let (_engine, control_addr) = serve().await;
    let mut control = RawControl::connect(control_addr).await;

    assert_eq!(
        control.request(r#"{"id":1,"command":"ping"}"#).await,
        r#"{"id":1,"result":"pong"}"#
    );
    assert_eq!(
        control.request(r#"{"id":2,"command":"list"}"#).await,
        r#"{"id":2,"result":"list","call_ids":[]}"#
    );

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offer = control
        .request(&format!(
            r#"{{"id":3,"command":"offer","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","sdp":"{}","profile":{{}}}}"#,
            sdp_json(addr_a)
        ))
        .await;
    assert!(
        offer.starts_with(r#"{"id":3,"result":"ok","sdp":"v=0\r\n"#),
        "an offer is answered with the rewritten SDP and nothing before it: {offer}"
    );
    let far = engine_addr(&offer);
    let answer = control
        .request(&format!(
            r#"{{"id":4,"command":"answer","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","to_tag":"b19e02","sdp":"{}"}}"#,
            sdp_json(addr_b)
        ))
        .await;
    let near = engine_addr(&answer);

    phone_a
        .send_to(&rtp(0x0A0A_0A0A), near)
        .await
        .expect("send a");
    assert_eq!(recv(&phone_b).await, (rtp(0x0A0A_0A0A), far));
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far)
        .await
        .expect("send b");
    assert_eq!(recv(&phone_a).await, (rtp(0x0B0B_0B0B), near));

    assert_eq!(
        control.request(r#"{"id":5,"command":"list"}"#).await,
        r#"{"id":5,"result":"list","call_ids":["7f9a2b1c@192.0.2.20"]}"#
    );
    assert_eq!(
        control
            .request(r#"{"id":6,"command":"query","call_id":"nobody@192.0.2.20","from_tag":"x"}"#)
            .await,
        r#"{"id":6,"result":"error","reason":"unknown call: nobody@192.0.2.20"}"#
    );
    assert_eq!(
        control
            .request(
                r#"{"id":7,"command":"delete","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f"}"#
            )
            .await,
        r#"{"id":7,"result":"ok"}"#
    );
    assert_eq!(
        control
            .request(
                r#"{"id":8,"command":"delete","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f"}"#
            )
            .await,
        r#"{"id":8,"result":"error","reason":"unknown call: 7f9a2b1c@192.0.2.20"}"#
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unscoped_events_are_pushed_byte_for_byte() {
    let (engine, control_addr) = serve().await;
    let mut control = RawControl::connect(control_addr).await;
    let (_phone, addr) = phone().await;

    let offer = control
        .request(&format!(
            r#"{{"id":1,"command":"offer","call_id":"doomed@192.0.2.20","from_tag":"ft","sdp":"{}"}}"#,
            sdp_json(addr)
        ))
        .await;
    engine_addr(&offer);

    // Nothing ever arrives on the call, so the setup ceiling ends it.
    engine.datapath().advance_clock(40);
    assert_eq!(
        engine.reap_idle(30, 0, 30).await,
        vec!["doomed@192.0.2.20".to_string()]
    );

    let mut frames = [control.next_frame().await, control.next_frame().await];
    frames.sort();
    assert!(
        frames[0].starts_with(
            r#"{"event":"call_summary","call_id":"doomed@192.0.2.20","reason":"setup_timeout","#
        ),
        "the summary leads with the event tag and the call id: {}",
        frames[0]
    );
    assert_eq!(
        frames[1],
        r#"{"event":"media_timeout","call_id":"doomed@192.0.2.20","from_tag":"ft","reason":"setup_timeout"}"#
    );
}

/// A second anchoring pass of one controller on one Call-ID, with nothing to tell the two apart.
///
/// An IMS proxy that serves both parties of a call anchors it twice, originating side and
/// terminating side, under the same `call_id` and `from_tag`. The engine cannot tell that from a
/// controller repeating its offer, so the second offer **replaces** the first pass's call: the
/// first pass's ports are freed and stop relaying, a `call_summary` with reason `replaced` is
/// emitted for it, and the answers of both passes then land on the one call that is left. The
/// later answer wins the far leg, so the call ends up relaying to the wrong party. Nothing is
/// refused along the way, which is why a controller that anchors twice names a scope per pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_unscoped_pass_replaces_the_first() {
    let (_engine, control_addr) = serve().await;
    let mut control = RawControl::connect(control_addr).await;
    let (caller, caller_addr) = phone().await;
    let (core, core_addr) = phone().await;
    let (callee, callee_addr) = phone().await;

    // Pass 1 (originating side): the caller's offer.
    let first = control
        .request(&format!(
            r#"{{"id":1,"command":"offer","call_id":"onnet@192.0.2.20","from_tag":"a7c31f","sdp":"{}"}}"#,
            sdp_json(caller_addr)
        ))
        .await;
    let first_far = engine_addr(&first);

    // Pass 2 (terminating side): the same Call-ID and tag, the offer as it comes back from the core.
    control
        .send(&format!(
            r#"{{"id":2,"command":"offer","call_id":"onnet@192.0.2.20","from_tag":"a7c31f","sdp":"{}"}}"#,
            sdp_json(core_addr)
        ))
        .await;
    let mut frames = [control.next_frame().await, control.next_frame().await];
    frames.sort();
    let (summary, second) = (&frames[0], &frames[1]);
    assert!(
        summary.starts_with(
            r#"{"event":"call_summary","call_id":"onnet@192.0.2.20","reason":"replaced","#
        ),
        "the first pass's call is torn down as replaced: {summary}"
    );
    let second_far = engine_addr(second);
    assert_ne!(first_far, second_far, "the replacement binds fresh ports");

    // One call is left, not two.
    assert_eq!(
        control.request(r#"{"id":3,"command":"list"}"#).await,
        r#"{"id":3,"result":"list","call_ids":["onnet@192.0.2.20"]}"#
    );

    // The terminating side's answer completes the second pass's call.
    let answer = control
        .request(&format!(
            r#"{{"id":4,"command":"answer","call_id":"onnet@192.0.2.20","from_tag":"a7c31f","to_tag":"b19e02","sdp":"{}"}}"#,
            sdp_json(callee_addr)
        ))
        .await;
    let second_near = engine_addr(&answer);
    core.send_to(&rtp(0x0C0C_0C0C), second_near)
        .await
        .expect("send core");
    assert_eq!(recv(&callee).await, (rtp(0x0C0C_0C0C), second_far));

    // The originating side's answer arrives last. It names the same call, so it is taken as a
    // second answer on it rather than as the first pass's own.
    let late = control
        .request(&format!(
            r#"{{"id":5,"command":"answer","call_id":"onnet@192.0.2.20","from_tag":"a7c31f","to_tag":"b19e02","sdp":"{}"}}"#,
            sdp_json(core_addr)
        ))
        .await;
    assert!(
        late.starts_with(r#"{"id":5,"result":"ok","sdp":"#),
        "the late answer is accepted: {late}"
    );
    // And it re-points that call's far leg at its own SDP: the callee no longer hears the call.
    core.send_to(&rtp(0x0E0E_0E0E), second_near)
        .await
        .expect("send core");
    assert_eq!(recv(&core).await, (rtp(0x0E0E_0E0E), second_far));
    assert!(
        hears_nothing(&callee).await,
        "the callee lost the media the late answer redirected"
    );

    // The first pass's anchor is gone: what the callee side sends to its port reaches nobody.
    callee
        .send_to(&rtp(0x0D0D_0D0D), first_far)
        .await
        .expect("send to the freed port");
    assert!(
        hears_nothing(&caller).await,
        "the first pass no longer relays toward the caller"
    );
}
