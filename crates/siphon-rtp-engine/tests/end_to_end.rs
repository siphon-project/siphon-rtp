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
            // The control connection interleaves async server events (e.g. the `Event::CallSummary`
            // pushed on teardown) with request responses, exactly as a real client sees. Decode each
            // frame generically and skip any event, returning only the correlated response.
            if let Some((value, consumed)) =
                frame::decode::<serde_json::Value>(&self.buffer).expect("decode frame")
            {
                self.buffer.drain(..consumed);
                if value.get("event").is_some() {
                    continue; // a server-initiated event, not our response
                }
                let response: Response = serde_json::from_value(value).expect("response shape");
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

/// Spawn an engine + control server on an ephemeral loopback port, returning its control address.
async fn spawn_control_server() -> SocketAddr {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    tokio::spawn(async move {
        let _ = server::serve(engine, listener).await;
    });
    control_addr
}

/// Offer an offer-only single-leg IVR call named `call_id` on `control` (a UAS that never answers) —
/// `play_media` promotes it into the userspace media pipeline. Returns the phone socket that hears
/// the prompt (kept alive by the caller).
async fn offer_ivr(control: &mut Control, call_id: &str) -> UdpSocket {
    let (phone_a, addr_a) = phone().await;
    let offer = control
        .request(Command::Offer {
            call_id: call_id.into(),
            from_tag: "tag-a".into(),
            sdp: sdp_for(addr_a),
            profile: Default::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "IVR offer accepted");
    phone_a
}

/// Await the next [`Event::PlayFinished`] on `control`, skipping any unrelated event. Returns
/// `(play_id, reason, played_ms)`.
async fn next_play_finished(
    control: &mut Control,
) -> (u64, siphon_rtp_proto::PlayEndReason, Option<u64>) {
    for _ in 0..20 {
        if let Event::PlayFinished {
            play_id,
            reason,
            played_ms,
            ..
        } = control.recv_event().await
        {
            return (play_id, reason, played_ms);
        }
    }
    panic!("no PlayFinished event arrived");
}

/// Send a `play_media` and assert it accepts immediately with a `play_id`, returning `(play_id,
/// duration_ms)`.
async fn play_blob(control: &mut Control, call_id: &str, samples: usize) -> (u64, Option<u64>) {
    let result = control
        .request(Command::PlayMedia {
            call_id: call_id.into(),
            from_tag: "tag-a".into(),
            source: siphon_rtp_proto::PlayMediaSource::Blob {
                data: wav_blob(samples),
            },
            repeat_times: None,
            start_pos_ms: None,
            duration_ms: None,
            to_tag: None,
        })
        .await;
    match result {
        CmdResult::Ok {
            play_id: Some(play_id),
            duration_ms,
            ..
        } => (play_id, duration_ms),
        other => panic!("play_media must accept with a play_id, got {other:?}"),
    }
}

/// `play_media` accepts immediately with a `play_id`, and a `PlayFinished{Completed}` carrying the
/// same `play_id` (and the played duration) arrives on the async event rail when the prompt drains —
/// the completion signal that replaced the deferred response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_media_emits_play_finished_completed_on_drain() {
    let control_addr = spawn_control_server().await;
    let mut control = Control::connect(control_addr).await;
    let _phone_a = offer_ivr(&mut control, "ivr").await;

    // A ~100 ms prompt (5 frames × 20 ms) accepts on start with its play_id and duration.
    let (play_id, duration_ms) = play_blob(&mut control, "ivr", 800).await;
    assert_eq!(
        duration_ms,
        Some(100),
        "the accept reports the prompt duration"
    );

    // The completion arrives asynchronously once the prompt drains.
    let (finished_id, reason, played_ms) = next_play_finished(&mut control).await;
    assert_eq!(
        finished_id, play_id,
        "PlayFinished carries the accept's play_id"
    );
    assert_eq!(reason, siphon_rtp_proto::PlayEndReason::Completed);
    assert_eq!(played_ms, Some(100), "the whole 100 ms prompt played");
}

/// `StopMedia` mid-play ends the prompt as `PlayFinished{Stopped}` (not `Completed`), so a controller
/// awaiting it resolves as not-completed rather than hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_media_emits_play_finished_stopped() {
    let control_addr = spawn_control_server().await;
    let mut control = Control::connect(control_addr).await;
    let _phone_a = offer_ivr(&mut control, "ivr").await;

    // A long prompt (~2 s) so the stop lands well before it would drain on its own.
    let (play_id, _) = play_blob(&mut control, "ivr", 160 * 100).await;
    let stopped = control
        .request(Command::StopMedia {
            call_id: "ivr".into(),
            from_tag: "tag-a".into(),
        })
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "stop accepted");

    let (finished_id, reason, _played_ms) = next_play_finished(&mut control).await;
    assert_eq!(finished_id, play_id, "the stopped prompt's play_id");
    assert_eq!(reason, siphon_rtp_proto::PlayEndReason::Stopped);
}

/// A second `play_media` on the same leg supersedes the first: the first play's id is reported as
/// `PlayFinished{Superseded}`, then the second drains to `PlayFinished{Completed}`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_play_supersedes_the_first_then_completes() {
    let control_addr = spawn_control_server().await;
    let mut control = Control::connect(control_addr).await;
    let _phone_a = offer_ivr(&mut control, "ivr").await;

    // A long first prompt, then a short second one that replaces it immediately.
    let (first_id, _) = play_blob(&mut control, "ivr", 160 * 100).await;
    let (second_id, _) = play_blob(&mut control, "ivr", 160 * 2).await;
    assert_ne!(first_id, second_id, "each play draws its own id");

    // The superseded first play is reported first (for its own id), then the second completes.
    let (superseded_id, superseded_reason, _) = next_play_finished(&mut control).await;
    assert_eq!(
        superseded_id, first_id,
        "the first play is the one superseded"
    );
    assert_eq!(
        superseded_reason,
        siphon_rtp_proto::PlayEndReason::Superseded
    );

    let (completed_id, completed_reason, _) = next_play_finished(&mut control).await;
    assert_eq!(completed_id, second_id, "the second play then completes");
    assert_eq!(completed_reason, siphon_rtp_proto::PlayEndReason::Completed);
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

    // Reaping pushes two events down the same control connection: the end-of-call `CallSummary` (CDR)
    // and the `MediaTimeout` dead-path signal SIPhon already relies on. Both arrive; confirm each.
    let mut got_summary = false;
    let mut got_timeout = false;
    for _ in 0..2 {
        match control.recv_event().await {
            Event::CallSummary {
                call_id, reason, ..
            } => {
                assert_eq!(call_id, "doomed");
                assert_eq!(reason, "media_timeout");
                got_summary = true;
            }
            Event::MediaTimeout { call_id, from_tag } => {
                assert_eq!(call_id, "doomed");
                assert_eq!(from_tag, "ft");
                got_timeout = true;
            }
            other => panic!("unexpected event pushed on reap: {other:?}"),
        }
    }
    assert!(got_summary, "the CallSummary CDR event was pushed");
    assert!(got_timeout, "the MediaTimeout event was pushed");
}
