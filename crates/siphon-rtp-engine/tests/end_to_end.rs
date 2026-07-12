//! End-to-end proof of the runnable engine: drive offer/answer/relay/delete over the real
//! JSON-over-TCP control connection, then push RTP through the allocated ports and assert it is
//! relayed both ways. NIC-free (UDP-loopback datapath + loopback control socket).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{sdp, server, Engine};
use siphon_rtp_proto::{frame, CmdResult, Command, Event, ProfileFlags, Request, Response};
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

    /// Send a command without awaiting its response (for pipelining two requests to prove the
    /// control loop keeps serving while one is deferred). Returns the request id.
    async fn send(&mut self, command: Command) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let bytes = frame::encode(&Request { id, command }).expect("encode request");
        self.stream.write_all(&bytes).await.expect("write request");
        id
    }

    /// Read the next correlated [`Response`] off the wire (in arrival order, which may differ from
    /// send order when a response is deferred).
    async fn next_response(&mut self) -> Response {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some((response, consumed)) =
                frame::decode::<Response>(&self.buffer).expect("decode response")
            {
                self.buffer.drain(..consumed);
                return response;
            }
            let read = timeout(Duration::from_secs(3), self.stream.read(&mut chunk))
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

/// An offer advertising PCMU only (so a `codec-transcode-PCMA` flag genuinely *adds* PCMA).
fn pcmu_offer(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

/// A far-side answer selecting PCMA (PT 8) — the transcode target B picks.
fn pcma_answer(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 2 2 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

fn sdp_text(result: &CmdResult) -> String {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => text.clone(),
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
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

/// A minimal 8 kHz mono 16-bit PCM RIFF/WAVE with `sample_count` samples — a prompt blob for
/// `play_media`. `sample_count / 160` is the number of 20 ms playout frames (~duration).
fn wav_blob(sample_count: usize) -> Vec<u8> {
    let data_len = (sample_count * 2) as u32;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"RIFF");
    buffer.extend_from_slice(&(36 + data_len).to_le_bytes());
    buffer.extend_from_slice(b"WAVE");
    buffer.extend_from_slice(b"fmt ");
    buffer.extend_from_slice(&16u32.to_le_bytes());
    buffer.extend_from_slice(&1u16.to_le_bytes()); // PCM
    buffer.extend_from_slice(&1u16.to_le_bytes()); // mono
    buffer.extend_from_slice(&8000u32.to_le_bytes()); // sample rate
    buffer.extend_from_slice(&16000u32.to_le_bytes()); // byte rate
    buffer.extend_from_slice(&2u16.to_le_bytes()); // block align
    buffer.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    buffer.extend_from_slice(b"data");
    buffer.extend_from_slice(&data_len.to_le_bytes());
    for index in 0..sample_count {
        buffer.extend_from_slice(&((index as i16).wrapping_mul(7)).to_le_bytes());
    }
    buffer
}

/// Blocking `play_media` (`wait = true`) defers its response until the prompt drains, and the
/// control loop keeps serving other requests on the same connection meanwhile — the spec's
/// non-blocking invariant. A `Ping` sent right after a blocking play is answered *first*, while the
/// play's own response arrives later (once the prompt finishes).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_play_defers_its_response_and_does_not_stall_other_requests() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    tokio::spawn(async move {
        let _ = server::serve(engine, listener).await;
    });

    let mut control = Control::connect(control_addr).await;
    let (_phone_a, addr_a) = phone().await;

    // A UAS IVR: offer, never answer — an offer-only single-leg call `play_media` must promote.
    let offer = control
        .request(Command::Offer {
            call_id: "ivr".into(),
            from_tag: "tag-a".into(),
            sdp: sdp_for(addr_a),
            profile: Default::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }));

    // Pipeline: a blocking play (a ~100 ms prompt) immediately followed by a Ping — without awaiting
    // the play's response. If the control loop blocked on the play, the Ping would be answered only
    // after the prompt drained; instead the Pong must come back first.
    let play_id = control
        .send(Command::PlayMedia {
            call_id: "ivr".into(),
            from_tag: "tag-a".into(),
            source: siphon_rtp_proto::PlayMediaSource::Blob {
                data: wav_blob(800), // 5 frames ≈ 100 ms
            },
            repeat_times: None,
            start_pos_ms: None,
            duration_ms: None,
            to_tag: None,
            wait: true,
        })
        .await;
    let ping_id = control.send(Command::Ping).await;

    let first = control.next_response().await;
    assert_eq!(
        first.id, ping_id,
        "the Ping is answered while the blocking play is still pending (non-blocking invariant)"
    );
    assert_eq!(first.result, CmdResult::Pong);

    // The play's own response arrives later, once the prompt has drained, reporting the duration.
    let second = control.next_response().await;
    assert_eq!(
        second.id, play_id,
        "the deferred play response follows, by id"
    );
    assert!(
        matches!(
            second.result,
            CmdResult::Ok {
                duration_ms: Some(100),
                ..
            }
        ),
        "the blocking play resolves with the played duration, got {:?}",
        second.result
    );
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
async fn transcoded_answer_advertises_the_offerers_own_codec() {
    // A offers PCMU only; `codec-transcode-PCMA` adds PCMA to the offer to B; B answers PCMA. The
    // engine then transcodes PCMA↔PCMU, so the answer relayed to A must advertise PCMU — A's own
    // codec — and never leak B's PCMA (RFC 3264 §6). Regression guard for the answer-side codec bug.
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    tokio::spawn(async move {
        let _ = server::serve(engine, listener).await;
    });
    let mut control = Control::connect(control_addr).await;

    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    // Offer A (PCMU) with codec-transcode-PCMA → the rewritten offer to B carries PCMU + PCMA.
    let offer = control
        .request(Command::Offer {
            call_id: "xcode".into(),
            from_tag: "tag-a".into(),
            sdp: pcmu_offer(addr_a),
            profile: ProfileFlags {
                flags: vec!["codec-transcode-PCMA".into()],
                ..Default::default()
            },
        })
        .await;
    let offer_sdp = sdp_text(&offer);
    let offer_media = offer_sdp
        .lines()
        .find(|line| line.starts_with("m=audio"))
        .expect("offer m=audio");
    assert!(
        offer_media.split_whitespace().any(|field| field == "8"),
        "PCMA added to the offer to B: {offer_media}"
    );

    // Answer B (PCMA) → transcode pipeline (PCMU↔PCMA).
    let answer = control
        .request(Command::Answer {
            call_id: "xcode".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: pcma_answer(addr_b),
            profile: Default::default(),
        })
        .await;
    let answer_sdp = sdp_text(&answer);
    let answer_media = answer_sdp
        .lines()
        .find(|line| line.starts_with("m=audio"))
        .expect("answer m=audio");

    // A sees its own PCMU, never B's PCMA.
    assert!(
        answer_media.split_whitespace().any(|field| field == "0"),
        "PCMU presented to A: {answer_media}"
    );
    assert!(
        !answer_media.split_whitespace().any(|field| field == "8"),
        "B's PCMA not leaked to A: {answer_media}"
    );
    assert!(
        answer_sdp.contains("a=rtpmap:0 PCMU/8000"),
        "PCMU rtpmap advertised to A: {answer_sdp}"
    );
    assert!(
        !answer_sdp.contains("PCMA"),
        "no PCMA in A's answer: {answer_sdp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_relay_answer_keeps_the_negotiated_codec_untouched() {
    // Regression: a non-transcoded (same-codec) relay must NOT rewrite the answer's codec list —
    // force_answer_codec only fires on the transcode pipelines.
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    tokio::spawn(async move {
        let _ = server::serve(engine, listener).await;
    });
    let mut control = Control::connect(control_addr).await;

    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    control
        .request(Command::Offer {
            call_id: "relay".into(),
            from_tag: "tag-a".into(),
            sdp: pcmu_offer(addr_a),
            profile: Default::default(),
        })
        .await;
    let answer = control
        .request(Command::Answer {
            call_id: "relay".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: pcmu_offer(addr_b),
            profile: Default::default(),
        })
        .await;
    let answer_sdp = sdp_text(&answer);
    assert!(
        answer_sdp.contains("a=rtpmap:0 PCMU/8000"),
        "plain relay presents the shared PCMU: {answer_sdp}"
    );
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
