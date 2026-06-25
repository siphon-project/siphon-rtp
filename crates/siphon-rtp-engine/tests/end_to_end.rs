//! End-to-end proof of the runnable engine: drive offer/answer/relay/delete over the real
//! JSON-over-TCP control connection, then push RTP through the allocated ports and assert it is
//! relayed both ways. NIC-free (UDP-loopback datapath + loopback control socket).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_proto::{frame, CmdResult, Command, Request, Response};
use siphon_rtp_engine::{server, sdp, Engine};
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
}

async fn phone() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind phone");
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
        CmdResult::Ok { sdp: Some(text), .. } => {
            sdp::rewrite(text, "127.0.0.1:1".parse().unwrap())
                .expect("parse engine addr")
                .remote
        }
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
    phone_a.send_to(b"voice-a", near_addr).await.expect("send a");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, b"voice-a");
    assert_eq!(from, far_addr);

    // Relay B → A.
    phone_b.send_to(b"voice-b", far_addr).await.expect("send b");
    let (data, from) = recv(&phone_a).await;
    assert_eq!(data, b"voice-b");
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
