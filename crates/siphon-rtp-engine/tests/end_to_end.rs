//! End-to-end proof of the runnable engine: drive offer/answer/relay/delete over the real
//! JSON-over-TCP control connection, then push RTP through the allocated ports and assert it is
//! relayed both ways. NIC-free (UDP-loopback datapath + loopback control socket).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{sdp, server, Engine};
use siphon_rtp_proto::{frame, CmdResult, Command, Event, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// A control client over one persistent TCP connection.
struct Control {
    stream: TcpStream,
    buffer: Vec<u8>,
    next_id: u64,
}

impl Control {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect control");
        Self {
            stream,
            buffer: Vec::new(),
            next_id: 1,
        }
    }

    /// Send a command and await its correlated response.
    async fn request(&mut self, command: Command) -> CmdResult {
        let id = self.next_id;
        self.next_id += 1;
        let bytes = frame::encode(&Request { id, command }).expect("encode request");
        self.stream.write_all(&bytes).await.expect("write request");

        let mut chunk = [0u8; 4096];
        loop {
            if let Some((response, consumed)) =
                frame::decode::<Response>(&self.buffer).expect("decode response")
            {
                self.buffer.drain(..consumed);
                assert_eq!(response.id, id, "response correlates to request");
                return response.result;
            }
            let read = timeout(Duration::from_secs(2), self.stream.read(&mut chunk))
                .await
                .expect("response not timed out")
                .expect("read response");
            assert_ne!(read, 0, "control connection closed unexpectedly");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Read the next frame as a server-initiated [`Event`] (no request correlation).
    async fn recv_event(&mut self) -> Event {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some((event, consumed)) =
                frame::decode::<Event>(&self.buffer).expect("decode event")
            {
                self.buffer.drain(..consumed);
                return event;
            }
            let read = timeout(Duration::from_secs(2), self.stream.read(&mut chunk))
                .await
                .expect("event not timed out")
                .expect("read event");
            assert_ne!(read, 0, "control connection closed before event");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
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

async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (len, from) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("recv not timed out")
        .expect("recv");
    (buffer[..len].to_vec(), from)
}

/// A minimal RTP packet (V=2, PT=0/PCMU) carrying `ssrc` — the relay's layer-1 demux only forwards
/// RTP/RTCP (RFC 7983), so media fixtures must be RTP-shaped.
fn rtp(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(b"voice");
    packet
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_relay_delete_over_tcp_control() {
    // Start the engine + control server on an ephemeral loopback port.
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    tokio::spawn(async move {
        let _ = server::serve(engine, listener).await;
    });

    let mut control = Control::connect(control_addr).await;

    // Liveness.
    assert_eq!(control.request(Command::Ping).await, CmdResult::Pong);

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    // Offer (A) → rewritten SDP advertises the engine far (B-facing) port.
    let offer = control
        .request(Command::Offer {
            call_id: "e2e-call".into(),
            from_tag: "tag-a".into(),
            sdp: sdp_for(addr_a),
            profile: Default::default(),
        })
        .await;
    let far_addr = engine_addr(&offer);

    // Answer (B) → rewritten SDP advertises the engine near (A-facing) port.
    let answer = control
        .request(Command::Answer {
            call_id: "e2e-call".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: sdp_for(addr_b),
            profile: Default::default(),
        })
        .await;
    let near_addr = engine_addr(&answer);

    // Relay A → B.
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), near_addr)
        .await
        .expect("send a");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A));
    assert_eq!(from, far_addr);

    // Relay B → A.
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far_addr)
        .await
        .expect("send b");
    let (data, from) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B));
    assert_eq!(from, near_addr);

    // Delete tears it down.
    let delete = control
        .request(Command::Delete {
            call_id: "e2e-call".into(),
            from_tag: "tag-a".into(),
            to_tag: None,
        })
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));

    // A subsequent query for the deleted call errors.
    let requery = control
        .request(Command::Query {
            call_id: "e2e-call".into(),
            from_tag: "tag-a".into(),
            to_tag: None,
        })
        .await;
    assert!(matches!(requery, CmdResult::Error { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_requires_authentication_when_a_secret_is_configured() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    tokio::spawn(async move {
        let _ = server::serve_with_auth(engine, listener, Some("s3cret".to_string())).await;
    });

    let mut control = Control::connect(control_addr).await;

    // A command before authenticating is rejected.
    assert!(
        matches!(
            control.request(Command::Ping).await,
            CmdResult::Error { .. }
        ),
        "commands are rejected before authentication"
    );
    // A wrong token is rejected.
    assert!(matches!(
        control
            .request(Command::Authenticate {
                token: "wrong".into()
            })
            .await,
        CmdResult::Error { .. }
    ));
    // The correct token authenticates the connection; commands then work.
    assert!(matches!(
        control
            .request(Command::Authenticate {
                token: "s3cret".into()
            })
            .await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(control.request(Command::Ping).await, CmdResult::Pong);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn media_timeout_event_is_pushed_over_the_control_connection() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    let serve_engine = engine.clone();
    tokio::spawn(async move {
        let _ = server::serve(serve_engine, listener).await;
    });

    let mut control = Control::connect(control_addr).await;
    let (_phone, addr) = phone().await;

    // Offer a call over this control connection (so it owns the call).
    let offer = control
        .request(Command::Offer {
            call_id: "doomed".into(),
            from_tag: "ft".into(),
            sdp: sdp_for(addr),
            profile: Default::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }));

    // Drive the media-timeout sweep on the shared engine handle: the call is silent, so it is reaped.
    engine.datapath().advance_clock(40);
    assert_eq!(engine.reap_idle(30).await, vec!["doomed".to_string()]);

    // The engine pushes a MediaTimeout event down the same control connection.
    let event = control.recv_event().await;
    assert_eq!(
        event,
        Event::MediaTimeout {
            call_id: "doomed".into(),
            from_tag: "ft".into()
        }
    );
}
