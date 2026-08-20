//! End-to-end proof of the runnable engine: drive offer/answer/relay/delete over the real
//! JSON-over-TCP control connection, then push RTP through the allocated ports and assert it is
//! relayed both ways. NIC-free (UDP-loopback datapath + loopback control socket).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher_with_text;
use siphon_rtp_engine::{sdp, server, Engine};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_proto::{
    frame, CmdResult, Command, ConferenceRole, Event, ProfileFlags, Request, Response,
};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use siphon_rtp_srtp::SrtpContext;
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

/// Offer a single-leg local answer (`answer_local`) for `call_id` carrying PCMU + RFC 3389 comfort
/// noise (static PT 13) + telephone-event, and return the caller phone socket (kept alive by the
/// caller). The engine answers itself (UAS) and promotes the leg — its idle egress is comfort noise.
async fn answer_local_ivr(control: &mut Control, call_id: &str) -> UdpSocket {
    let (phone_a, addr_a) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 13 101\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n",
        ip = addr_a.ip(),
        port = addr_a.port()
    );
    let result = control
        .request(Command::AnswerLocal {
            call_id: call_id.into(),
            from_tag: "tag-a".into(),
            sdp: offer,
            profile: Default::default(),
        })
        .await;
    assert!(
        matches!(result, CmdResult::Ok { .. }),
        "answer_local accepted: {result:?}"
    );
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
            overlay: false,
            gain_decibels: None,
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
            play_id: None,
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

/// A local answer idles on comfort noise, not self-echo: with **no play and no echo**, the caller
/// receives a continuous RFC 3389 CN stream (the PT it negotiated), never its own audio looped back.
/// Drives the whole chain end to end — answer_local → CN negotiation → promote → with_comfort_idle →
/// the actor's playout tick → CN egress toward the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_idles_on_comfort_noise_not_self_echo() {
    let control_addr = spawn_control_server().await;
    let mut control = Control::connect(control_addr).await;
    let phone_a = answer_local_ivr(&mut control, "ivr-cn").await;

    // No play, no echo: the engine's playout tick already sends comfort noise toward the caller's
    // signalled address. Read two packets and prove they are a continuous CN stream (not looped audio).
    let (first, _) = recv(&phone_a).await;
    let (second, _) = recv(&phone_a).await;
    for packet in [&first, &second] {
        assert_eq!(
            packet[1] & 0x7f,
            13,
            "RFC 3389 comfort-noise payload type (PT 13): {packet:?}"
        );
        assert_eq!(
            packet.len(),
            13,
            "12-byte RTP header + a single -dBov level byte"
        );
    }
    let seq0 = u16::from_be_bytes([first[2], first[3]]);
    let seq1 = u16::from_be_bytes([second[2], second[3]]);
    assert_eq!(
        seq1,
        seq0.wrapping_add(1),
        "the comfort stream is continuous (sequence advances)"
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

/// An `m=audio` (PCMU) + RFC 4103 `m=text` (RED pt 98 wrapping T.140 pt 99) SDP, each on its own port
/// but sharing the loopback connection address.
fn audio_text_sdp(audio: SocketAddr, text: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {aport} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
         m=text {tport} RTP/AVP 98 99\r\na=rtpmap:98 red/1000\r\na=rtpmap:99 t140/1000\r\n",
        ip = audio.ip(),
        aport = audio.port(),
        tport = text.port(),
    )
}

/// The engine's advertised text-stream RTP address, parsed from a rewritten SDP's `m=text` section.
fn text_engine_addr(result: &CmdResult) -> SocketAddr {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => {
            sdp::parse(text)
                .expect("parse engine text addr")
                .text
                .expect("text stream anchored")
                .remote_rtp
        }
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

/// A minimal RTP packet on the RED payload type (98) carrying a T.140/RED-shaped payload — PR 1 relays
/// it verbatim (RED/T.140 is not parsed yet), so the exact block bytes are opaque here.
fn text_rtp(ssrc: u32) -> Vec<u8> {
    // V=2, PT=98 (RED), seq 1, ts 0.
    let mut packet = vec![0x80, 98, 0x00, 0x01, 0, 0, 0, 0];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    // RED redundant-block header + primary header + a couple of T.140 characters (RFC 2198 §4).
    packet.extend_from_slice(&[0xE3, 0x00, 0x00, 0x02, 0x63, b'h', b'i']);
    packet
}

/// A plaintext `m=audio` + RFC 4103 `m=text` call relays BOTH streams end-to-end over the UDP-loopback
/// datapath: a T.140/RED packet in one text port comes out the other, anchored to the engine's text
/// address, while the audio relay is unaffected. Proves the section-aware SDP anchor plus the per-stream
/// text relay + symmetric latch (PR 1). NIC-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_relays_audio_and_rfc4103_text_end_to_end() {
    let control_addr = spawn_control_server().await;
    let mut control = Control::connect(control_addr).await;

    let (phone_a_audio, addr_a_audio) = phone().await;
    let (phone_a_text, addr_a_text) = phone().await;
    let (phone_b_audio, addr_b_audio) = phone().await;
    let (phone_b_text, addr_b_text) = phone().await;

    // Offer (A) carries m=audio + m=text; the rewritten offer anchors both to the engine's far ports.
    let offer = control
        .request(Command::Offer {
            call_id: "rtt".into(),
            from_tag: "tag-a".into(),
            sdp: audio_text_sdp(addr_a_audio, addr_a_text),
            profile: Default::default(),
        })
        .await;
    let far_audio = engine_addr(&offer);
    let far_text = text_engine_addr(&offer);
    assert_ne!(
        far_audio.port(),
        far_text.port(),
        "audio + text anchored on distinct engine ports"
    );

    // Answer (B) → the engine's near audio + text ports advertised back to A.
    let answer = control
        .request(Command::Answer {
            call_id: "rtt".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: audio_text_sdp(addr_b_audio, addr_b_text),
            profile: Default::default(),
        })
        .await;
    let near_audio = engine_addr(&answer);
    let near_text = text_engine_addr(&answer);

    // Audio relay A → B is unaffected by the added text stream.
    phone_a_audio
        .send_to(&rtp(0x0A0A_0A0A), near_audio)
        .await
        .expect("send audio a");
    let (data, from) = recv(&phone_b_audio).await;
    assert_eq!(data, rtp(0x0A0A_0A0A), "audio relayed");
    assert_eq!(from, far_audio, "audio arrives from the engine far port");

    // Text relay A → B: a T.140/RED packet on the near text port emerges on B's text port, anchored to
    // the engine's far text address.
    phone_a_text
        .send_to(&text_rtp(0x0A0A_7E77), near_text)
        .await
        .expect("send text a");
    let (data, from) = recv(&phone_b_text).await;
    assert_eq!(data, text_rtp(0x0A0A_7E77), "text relayed verbatim");
    assert_eq!(from, far_text, "text arrives from the engine far text port");

    // Text relay B → A (reverse), exercising the text stream's own symmetric latch.
    phone_b_text
        .send_to(&text_rtp(0x0B0B_7E77), far_text)
        .await
        .expect("send text b");
    let (data, from) = recv(&phone_a_text).await;
    assert_eq!(data, text_rtp(0x0B0B_7E77), "reverse text relayed verbatim");
    assert_eq!(
        from, near_text,
        "reverse text arrives from the engine near text port"
    );

    // Teardown frees the text ports alongside the audio ports.
    let delete = control
        .request(Command::Delete {
            call_id: "rtt".into(),
            from_tag: "tag-a".into(),
            to_tag: None,
        })
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));
}

/// A minimal RTP packet on the RED payload type (98) carrying a **primary-only** RED body (RFC 2198
/// §3): the 1-byte primary header (`F=0 | PT=99` = 0x63) then the T.140 text bytes. The userspace text
/// processor reassembles this to `primary` — unlike PR 1's opaque `text_rtp`, this decodes cleanly.
fn red_text_rtp(sequence: u16, timestamp: u32, ssrc: u32, primary: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 98];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.push(0x63); // RED primary header: F=0, PT=99 (t140)
    packet.extend_from_slice(primary);
    packet
}

/// With `text_events` set, an audio+text call promotes ONLY the text stream to the userspace text
/// processor: RED/T.140 text is observed (`Event::Text` on the control connection) and relayed to the
/// far side, the end-of-call `CallSummary` carries per-leg RFC 4103 text counters, and — the load-bearing
/// invariant — the audio path stays the plain in-kernel relay (never promoted, still relaying). NIC-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_events_promotes_only_text_emits_events_and_carries_cdr_counters() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    // The redirect dispatcher must run so the promoted text stream's Redirect datagrams reach the actor.
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
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
    let mut control = Control::connect(control_addr).await;

    let (phone_a_audio, addr_a_audio) = phone().await;
    let (phone_a_text, addr_a_text) = phone().await;
    let (phone_b_audio, addr_b_audio) = phone().await;
    let (phone_b_text, addr_b_text) = phone().await;

    // Offer A carries m=audio + m=text, with text observability requested (`text_events`).
    let offer = control
        .request(Command::Offer {
            call_id: "rtt-obs".into(),
            from_tag: "tag-a".into(),
            sdp: audio_text_sdp(addr_a_audio, addr_a_text),
            profile: ProfileFlags {
                text_events: true,
                ..Default::default()
            },
        })
        .await;
    let far_audio = engine_addr(&offer);
    let far_text = text_engine_addr(&offer);

    let answer = control
        .request(Command::Answer {
            call_id: "rtt-obs".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: audio_text_sdp(addr_b_audio, addr_b_text),
            profile: Default::default(),
        })
        .await;
    let near_audio = engine_addr(&answer);
    let near_text = text_engine_addr(&answer);

    // The hard constraint: only text is promoted. Audio stays the plain in-kernel relay.
    assert!(
        !engine.media().is_media_call("rtt-obs"),
        "audio was NOT promoted to userspace for text observability"
    );
    assert!(
        engine.text().is_text_call("rtt-obs"),
        "the text stream was promoted to the userspace text processor"
    );

    // Audio relay A → B still works entirely in-kernel (byte-for-byte, no transcode).
    phone_a_audio
        .send_to(&rtp(0x0A0A_0A0A), near_audio)
        .await
        .expect("send audio a");
    let (data, from) = recv(&phone_b_audio).await;
    assert_eq!(data, rtp(0x0A0A_0A0A), "audio relayed in-kernel");
    assert_eq!(
        from, far_audio,
        "audio arrives from the engine far audio port"
    );

    // Text A → B: the RED/T.140 packet is relayed verbatim to B and observed as an Event::Text.
    let text_packet = red_text_rtp(1, 1000, 0x0A0A_7E77, b"hi");
    phone_a_text
        .send_to(&text_packet, near_text)
        .await
        .expect("send text a");
    let (data, from) = recv(&phone_b_text).await;
    assert_eq!(data, text_packet, "text relayed verbatim through userspace");
    assert_eq!(from, far_text, "text arrives from the engine far text port");

    // The observed increment reaches the control plane as Event::Text (sender = A, direction a_to_b).
    match control.recv_event().await {
        Event::Text {
            call_id,
            from_tag,
            text,
            direction,
            ..
        } => {
            assert_eq!(call_id, "rtt-obs");
            assert_eq!(from_tag, "tag-a");
            assert_eq!(text, "hi");
            assert_eq!(direction.as_deref(), Some("a_to_b"));
        }
        other => panic!("expected Event::Text, got {other:?}"),
    }

    // Reap the call (advance the clock past the timeout) → the CallSummary CDR is pushed with the
    // per-leg RFC 4103 text counters folded in.
    engine.datapath().advance_clock(40);
    assert_eq!(engine.reap_idle(30).await, vec!["rtt-obs".to_string()]);

    let mut summary_text_chars = None;
    for _ in 0..2 {
        match control.recv_event().await {
            Event::CallSummary { call_id, legs, .. } => {
                assert_eq!(call_id, "rtt-obs");
                let near = &legs[0];
                let text = near.text.expect("near leg carries RFC 4103 text QoS");
                assert_eq!(text.packets, 1, "one text packet accepted A->B");
                assert_eq!(text.characters, 2, "'hi' = 2 characters delivered");
                assert_eq!(text.missing_markers, 0);
                assert_eq!(text.recovered_from_redundancy, 0);
                summary_text_chars = Some(text.characters);
            }
            Event::MediaTimeout { .. } => {}
            other => panic!("unexpected event on reap: {other:?}"),
        }
    }
    assert_eq!(
        summary_text_chars,
        Some(2),
        "the CallSummary carried the RFC 4103 text counters"
    );
}

/// True when `haystack` contains the contiguous `needle` (a HEP payload substring match).
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// With HEP export enabled, tearing down an audio+text call whose text stream was promoted ships the
/// per-leg RFC 4103 Real-Time Text content QoS to the HEP collector as a type-35 report capture,
/// correlated by call-id — the wire complement to the `CallSummary`'s `text` field. Proves the
/// end-of-call `finish_call` → `export_text_qos` path emits the documented `"report":"rtt-text"` JSON.
/// NIC-free (UDP-loopback datapath, loopback HEP collector).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_call_exports_rfc4103_text_qos_to_the_hep_collector() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    // The redirect dispatcher must run so the promoted text stream's Redirect datagrams reach the actor.
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // Stand in for VoIPmonitor / Homer with a loopback UDP socket, and enable HEP export on the engine.
    let collector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind collector");
    let collector_addr = collector.local_addr().expect("collector addr");
    let exporter = HepExporter::connect(collector_addr).await.expect("connect");
    engine.set_hep_export(exporter, 7);

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    let serve_engine = engine.clone();
    tokio::spawn(async move {
        let _ = server::serve(serve_engine, listener).await;
    });
    let mut control = Control::connect(control_addr).await;

    let (_phone_a_audio, addr_a_audio) = phone().await;
    let (phone_a_text, addr_a_text) = phone().await;
    let (_phone_b_audio, addr_b_audio) = phone().await;
    let (_phone_b_text, addr_b_text) = phone().await;

    // Offer + answer an audio+text call with text observability, so the text stream is promoted and its
    // content counters are measured (an in-kernel-only text stream reports no content QoS).
    let offer = control
        .request(Command::Offer {
            call_id: "rtt-hep".into(),
            from_tag: "tag-a".into(),
            sdp: audio_text_sdp(addr_a_audio, addr_a_text),
            profile: ProfileFlags {
                text_events: true,
                ..Default::default()
            },
        })
        .await;
    let _far_text = text_engine_addr(&offer);
    let answer = control
        .request(Command::Answer {
            call_id: "rtt-hep".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: audio_text_sdp(addr_b_audio, addr_b_text),
            profile: Default::default(),
        })
        .await;
    let near_text = text_engine_addr(&answer);

    // A types "hi": one accepted text packet, two characters delivered A→B.
    let text_packet = red_text_rtp(1, 1000, 0x0A0A_7E77, b"hi");
    phone_a_text
        .send_to(&text_packet, near_text)
        .await
        .expect("send text a");
    // Drain the Event::Text so the counters are surely applied before teardown.
    match control.recv_event().await {
        Event::Text { text, .. } => assert_eq!(text, "hi"),
        other => panic!("expected Event::Text, got {other:?}"),
    }

    // Delete → finish_call → export_text_qos ships the HEP text QoS report.
    let delete = control
        .request(Command::Delete {
            call_id: "rtt-hep".into(),
            from_tag: "tag-a".into(),
            to_tag: None,
        })
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));

    // Both legs of a text call ship a report (the far B→A leg's counters are all zero — B typed
    // nothing — but it was still a text call). Collect the two per-leg datagrams as owned buffers.
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    for _ in 0..2 {
        let mut buffer = [0u8; 4096];
        let (len, _) = timeout(Duration::from_secs(2), collector.recv_from(&mut buffer))
            .await
            .expect("no timeout on the text QoS report")
            .expect("recv hep");
        datagrams.push(buffer[..len].to_vec());
    }

    for packet in &datagrams {
        assert_eq!(&packet[..4], b"HEP3", "a HEP3 packet reaches the collector");
        assert!(
            contains_bytes(packet, b"rtt-hep"),
            "correlation id = call-id, so the collector groups it with the call"
        );
        assert!(
            contains_bytes(packet, br#"{"report":"rtt-text","#),
            "the documented RFC 4103 text-QoS discriminator leads the payload"
        );
    }

    // The A→B report carries the measured counters (one packet, two characters).
    let saw_a_to_b = datagrams.iter().any(|packet| {
        contains_bytes(packet, br#""direction":"a_to_b""#)
            && contains_bytes(packet, br#""packets":1"#)
            && contains_bytes(packet, br#""characters":2"#)
    });
    assert!(
        saw_a_to_b,
        "the A→B text QoS report carried packets=1, characters=2"
    );
    // The B→A report is present too (B sent no text ⇒ zero counters).
    let saw_b_to_a = datagrams
        .iter()
        .any(|packet| contains_bytes(packet, br#""direction":"b_to_a""#));
    assert!(
        saw_b_to_a,
        "the far leg's B→A text QoS report is emitted too"
    );
}

/// An **audio-only** call ships NO RFC 4103 text-QoS HEP report on teardown — the text export is
/// gated on the call actually having carried a (promoted) text stream. With no `run_rtcp_export` task
/// and no RTCP sent, the collector sees nothing at all. NIC-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audio_only_call_exports_no_text_qos_hep_report() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let collector = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind collector");
    let collector_addr = collector.local_addr().expect("collector addr");
    let exporter = HepExporter::connect(collector_addr).await.expect("connect");
    engine.set_hep_export(exporter, 7);

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    let serve_engine = engine.clone();
    tokio::spawn(async move {
        let _ = server::serve(serve_engine, listener).await;
    });
    let mut control = Control::connect(control_addr).await;

    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    control
        .request(Command::Offer {
            call_id: "audio-only".into(),
            from_tag: "tag-a".into(),
            sdp: sdp_for(addr_a),
            profile: Default::default(),
        })
        .await;
    control
        .request(Command::Answer {
            call_id: "audio-only".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: sdp_for(addr_b),
            profile: Default::default(),
        })
        .await;

    // Delete → finish_call runs, but the audio-only call has no text stats, so no HEP report ships.
    let delete = control
        .request(Command::Delete {
            call_id: "audio-only".into(),
            from_tag: "tag-a".into(),
            to_tag: None,
        })
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));

    let mut buffer = [0u8; 4096];
    let got = timeout(Duration::from_millis(300), collector.recv_from(&mut buffer)).await;
    assert!(
        got.is_err(),
        "an audio-only call emits no RFC 4103 text-QoS HEP report"
    );
}

/// A secure (SDES-SRTP) `m=text` stream alongside a **plaintext** `m=audio` relay: audio is `RTP/AVP`,
/// text is `RTP/SAVP` carrying its own `a=crypto`. The engine terminates SRTP on the text leg (a per-leg
/// `SecureLeg`), so the phones do real SRTP on the text port and plain RTP on the audio port.
fn secure_text_sdp(audio: SocketAddr, text: SocketAddr, text_key: &CryptoAttribute) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {aport} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
         m=text {tport} RTP/SAVP 98 99\r\na=rtpmap:98 red/1000\r\na=rtpmap:99 t140/1000\r\na={crypto}\r\n",
        ip = audio.ip(),
        aport = audio.port(),
        tport = text.port(),
        crypto = text_key.to_attribute_value(),
    )
}

/// The engine's own SDES text `a=crypto` advertised in a rewritten SDP's `m=text` section.
fn text_engine_crypto(result: &CmdResult) -> CryptoAttribute {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => sdp::parse(text)
            .expect("parse engine text crypto")
            .text
            .expect("text stream anchored")
            .crypto
            .first()
            .copied()
            .expect("engine advertised a text a=crypto"),
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

/// A **secure** SDES-SRTP `m=text` stream is anchored + relayed end-to-end with per-leg keys: A and B
/// each key their own text leg, the engine decrypts each side's ingress and **re-encrypts** it with the
/// peer leg's own key (a secure↔secure re-key), the decrypted increment surfaces as `Event::Text`, and
/// the plaintext audio relay is unaffected. Proves the whole PR 2c wiring over the control connection.
/// Deterministic + NIC-free (UDP-loopback datapath + loopback control socket).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secure_sdes_text_bridge_rekeys_end_to_end_with_audio_unaffected() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    // The redirect dispatcher must run — a secure text stream runs on `Redirect` from the start.
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
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
    let mut control = Control::connect(control_addr).await;

    let (phone_a_audio, addr_a_audio) = phone().await;
    let (phone_a_text, addr_a_text) = phone().await;
    let (phone_b_audio, addr_b_audio) = phone().await;
    let (phone_b_text, addr_b_text) = phone().await;

    // A and B each mint their OWN text SDES key (their leg's inbound key).
    let a_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen a");
    let b_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen b");

    // Offer A: plaintext audio + secure text, with control-plane text events requested.
    let offer = control
        .request(Command::Offer {
            call_id: "sec-rtt".into(),
            from_tag: "tag-a".into(),
            sdp: secure_text_sdp(addr_a_audio, addr_a_text, &a_text_key),
            profile: ProfileFlags {
                text_events: true,
                ..Default::default()
            },
        })
        .await;
    let far_audio = engine_addr(&offer);
    let far_text = text_engine_addr(&offer);
    // The offer to B advertises `RTP/SAVP` text + the ENGINE's own far text key (not A's).
    assert!(
        sdp_text(&offer).contains(&format!("m=text {} RTP/SAVP", far_text.port())),
        "offer to B advertises secure text: {}",
        sdp_text(&offer)
    );
    let engine_far_text_key = text_engine_crypto(&offer);
    assert_ne!(
        engine_far_text_key.key, a_text_key.key,
        "the engine mints its own far text key, never forwarding A's"
    );

    // Answer B: secure text with B's own key.
    let answer = control
        .request(Command::Answer {
            call_id: "sec-rtt".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: secure_text_sdp(addr_b_audio, addr_b_text, &b_text_key),
            profile: Default::default(),
        })
        .await;
    let near_audio = engine_addr(&answer);
    let near_text = text_engine_addr(&answer);
    // The answer to A advertises `RTP/SAVP` text + the ENGINE's own near text key (not B's).
    assert!(
        sdp_text(&answer).contains(&format!("m=text {} RTP/SAVP", near_text.port())),
        "answer to A advertises secure text: {}",
        sdp_text(&answer)
    );
    let engine_near_text_key = text_engine_crypto(&answer);
    assert_ne!(
        engine_near_text_key.key, b_text_key.key,
        "the engine mints its own near text key, never forwarding B's"
    );

    // The secure text stream runs in the userspace text processor; audio stays a plain in-kernel relay.
    assert!(
        engine.text().is_text_call("sec-rtt"),
        "secure text is registered on the userspace text processor"
    );
    assert!(
        !engine.media().is_media_call("sec-rtt"),
        "audio was NOT promoted — the plaintext audio path is unaffected"
    );

    // Audio A → B (plaintext) relays untouched, unaffected by the secure text stream.
    phone_a_audio
        .send_to(&rtp(0x0A0A_0A0A), near_audio)
        .await
        .expect("send audio a");
    let (data, from) = recv(&phone_b_audio).await;
    assert_eq!(
        data,
        rtp(0x0A0A_0A0A),
        "audio relayed in the clear, unaffected"
    );
    assert_eq!(
        from, far_audio,
        "audio arrives from the engine far audio port"
    );

    // Text A → B: A encrypts a RED/T.140 "hi" with its own key; the engine decrypts on the near leg and
    // re-encrypts on the far leg — B decrypts it with the ENGINE's far key, recovering the exact bytes.
    let plaintext = red_text_rtp(1, 1000, 0x0A0A_7E77, b"hi");
    let mut a_encrypt = SrtpContext::from_key_material(&a_text_key.key);
    let mut a_srtp = Vec::new();
    a_encrypt
        .protect(&plaintext, &mut a_srtp)
        .expect("A encrypt");
    phone_a_text
        .send_to(&a_srtp, near_text)
        .await
        .expect("send secure text a");

    let (wire, from) = recv(&phone_b_text).await;
    assert_eq!(
        from, far_text,
        "secure text arrives from the engine far text port"
    );
    assert_ne!(
        wire, plaintext,
        "never forwarded in the clear to the secure peer"
    );
    assert_ne!(
        wire, a_srtp,
        "re-encrypted with the engine's far key, not relayed as A's ciphertext"
    );
    let mut b_decrypt = SrtpContext::from_key_material(&engine_far_text_key.key);
    let mut recovered = Vec::new();
    b_decrypt
        .unprotect(&wire, &mut recovered)
        .expect("B decrypts the re-keyed text with the engine's far key");
    assert_eq!(
        recovered, plaintext,
        "B recovers the exact T.140/RED bytes A sent"
    );

    // The DECRYPTED increment surfaces as Event::Text (sender = A, a_to_b) — observed after decrypt.
    match control.recv_event().await {
        Event::Text {
            call_id,
            from_tag,
            text,
            direction,
            ..
        } => {
            assert_eq!(call_id, "sec-rtt");
            assert_eq!(from_tag, "tag-a");
            assert_eq!(text, "hi");
            assert_eq!(direction.as_deref(), Some("a_to_b"));
        }
        other => panic!("expected Event::Text, got {other:?}"),
    }

    // Text B → A (reverse): B encrypts with its own key; A decrypts with the engine's near key.
    let plaintext_b = red_text_rtp(1, 2000, 0x0B0B_7E77, b"yo");
    let mut b_encrypt = SrtpContext::from_key_material(&b_text_key.key);
    let mut b_srtp = Vec::new();
    b_encrypt
        .protect(&plaintext_b, &mut b_srtp)
        .expect("B encrypt");
    phone_b_text
        .send_to(&b_srtp, far_text)
        .await
        .expect("send secure text b");
    let (wire_a, from_a) = recv(&phone_a_text).await;
    assert_eq!(
        from_a, near_text,
        "reverse secure text arrives from the engine near text port"
    );
    let mut a_decrypt = SrtpContext::from_key_material(&engine_near_text_key.key);
    let mut recovered_a = Vec::new();
    a_decrypt
        .unprotect(&wire_a, &mut recovered_a)
        .expect("A decrypts the reverse re-keyed text with the engine's near key");
    assert_eq!(
        recovered_a, plaintext_b,
        "A recovers B's exact T.140/RED bytes"
    );

    // Teardown frees the secure text ports (and their SecureLegs) alongside the audio ports.
    let delete = control
        .request(Command::Delete {
            call_id: "sec-rtt".into(),
            from_tag: "tag-a".into(),
            to_tag: None,
        })
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));
    assert!(
        !engine.text().is_text_call("sec-rtt"),
        "the secure text actor is deregistered on delete"
    );
}

/// Without any text-observability feature, an audio+text call leaves the text stream on the PR-1
/// in-kernel `Forward` relay (NOT promoted) — it still relays verbatim, and the audio relay is likewise
/// in-kernel. Proves text observation is never always-on. NIC-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_observability_text_stays_in_kernel_and_still_relays() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
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
    let mut control = Control::connect(control_addr).await;

    let (phone_a_audio, addr_a_audio) = phone().await;
    let (phone_a_text, addr_a_text) = phone().await;
    let (phone_b_audio, addr_b_audio) = phone().await;
    let (phone_b_text, addr_b_text) = phone().await;

    // Offer/answer with the default profile — no `text_events`, no recording.
    let offer = control
        .request(Command::Offer {
            call_id: "rtt-plain".into(),
            from_tag: "tag-a".into(),
            sdp: audio_text_sdp(addr_a_audio, addr_a_text),
            profile: Default::default(),
        })
        .await;
    let _far_audio = engine_addr(&offer);
    let far_text = text_engine_addr(&offer);
    let answer = control
        .request(Command::Answer {
            call_id: "rtt-plain".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: audio_text_sdp(addr_b_audio, addr_b_text),
            profile: Default::default(),
        })
        .await;
    let _near_audio = engine_addr(&answer);
    let near_text = text_engine_addr(&answer);

    // Neither stream is promoted — text stays on the in-kernel relay (PR-1 behaviour preserved).
    assert!(
        !engine.text().is_text_call("rtt-plain"),
        "text is NOT promoted without a text-observability feature"
    );
    assert!(
        !engine.media().is_media_call("rtt-plain"),
        "audio in-kernel"
    );

    // Text A → B still relays verbatim, in-kernel.
    let text_packet = red_text_rtp(1, 1000, 0x0A0A_7E77, b"hi");
    phone_a_text
        .send_to(&text_packet, near_text)
        .await
        .expect("send text a");
    let (data, from) = recv(&phone_b_text).await;
    assert_eq!(data, text_packet, "text relayed verbatim in-kernel");
    assert_eq!(from, far_text, "text arrives from the engine far text port");

    // Keep the audio phones alive for the duration.
    drop((phone_a_audio, phone_b_audio));
}

/// RFC 9071 multiparty real-time text in the conference: three participants join a room, each with an
/// `m=audio` + `m=text` leg. When one types, the room distributes its T.140 to **both** other
/// participants (mix-minus-self) on the text flush, each packet labelled with the typing source's
/// identity in the RTP CSRC list — so a receiver can present each source separately. Driven over the
/// real control connection + UDP-loopback datapath (NIC-free); the ~300 ms text flush is a live timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_distributes_multiparty_text_with_per_source_csrc() {
    use siphon_rtp_media::rtp::RtpPacket;
    use siphon_rtp_media::t140::RedPacket;

    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    // The redirect dispatcher routes each participant's text endpoint to the conference actor.
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
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
    let mut control = Control::connect(control_addr).await;

    // Three participants, each with an audio + a text phone.
    let (_a_audio, a_audio_addr) = phone().await;
    let (a_text, a_text_addr) = phone().await;
    let (_b_audio, b_audio_addr) = phone().await;
    let (b_text, _b_text_addr) = phone().await;
    let (_c_audio, c_audio_addr) = phone().await;
    let (c_text, _c_text_addr) = phone().await;

    // A joins first, so its answer's `m=text` is where A sends its own text.
    let a_join = control
        .request(Command::ConferenceJoin {
            conference_id: "room".into(),
            from_tag: "tag-a".into(),
            sdp: audio_text_sdp(a_audio_addr, a_text_addr),
            role: ConferenceRole::Talker,
            profile: Default::default(),
        })
        .await;
    let a_engine_text = text_engine_addr(&a_join);

    for (tag, audio, text) in [
        ("tag-b", b_audio_addr, _b_text_addr),
        ("tag-c", c_audio_addr, _c_text_addr),
    ] {
        let join = control
            .request(Command::ConferenceJoin {
                conference_id: "room".into(),
                from_tag: tag.into(),
                sdp: audio_text_sdp(audio, text),
                role: ConferenceRole::Talker,
                profile: Default::default(),
            })
            .await;
        // Every join anchors an `m=text` stream to the engine (RFC 9071 conference text).
        let _ = text_engine_addr(&join);
    }

    // A types "hi" (a primary-only RED/T.140 packet) toward the engine's text endpoint for A.
    a_text
        .send_to(&red_text_rtp(1, 1000, 0x0A0A_7E77, b"hi"), a_engine_text)
        .await
        .expect("send text a");

    // On the text flush, B and C each receive A's text — RED-framed, CSRC-labelled with A's source.
    let (b_data, _) = recv(&b_text).await;
    let (c_data, _) = recv(&c_text).await;

    let parse = |data: &[u8]| -> (u32, String) {
        let packet = RtpPacket::parse(data).expect("egress text RTP");
        assert_eq!(
            packet.csrc_count, 1,
            "RFC 9071 §4.2: one contributing source"
        );
        let csrc = packet.csrc(0).expect("CSRC 0 present");
        let red = RedPacket::parse(packet.payload).expect("RED payload");
        (
            csrc,
            String::from_utf8(red.primary().data.to_vec()).expect("utf8"),
        )
    };
    let (b_csrc, b_text_out) = parse(&b_data);
    let (c_csrc, c_text_out) = parse(&c_data);

    assert_eq!(b_text_out, "hi", "B receives A's text");
    assert_eq!(c_text_out, "hi", "C receives A's text");
    assert_eq!(
        b_csrc, c_csrc,
        "both receivers see the SAME source identity for A's text (RFC 9071 §4.2)"
    );

    // Leaving frees every participant (audio + text endpoints) and tears the room down.
    for tag in ["tag-a", "tag-b", "tag-c"] {
        let left = control
            .request(Command::ConferenceLeave {
                conference_id: "room".into(),
                from_tag: tag.into(),
            })
            .await;
        assert!(matches!(left, CmdResult::Ok { .. }));
    }
    assert!(
        !engine.conference().contains("room"),
        "empty room torn down"
    );
}

/// RFC 9071 **secure** (SDES-SRTP) multiparty real-time text: two participants join a room, each with
/// a plaintext `m=audio` and a **secure** (`RTP/SAVP` + `a=crypto`) `m=text` leg. The engine seats each
/// with a per-participant text `SecureLeg`, decrypts the typing participant's SRTP text into the room's
/// plaintext text mix, and re-encrypts the distributed increment with the RECEIVER's own key — so the
/// receiver decrypts it with the engine's offered key and never sees another leg's key. Each text leg
/// is secured independently, exactly like the conference audio in a mixed room. Driven over the real
/// control connection + UDP-loopback datapath; the ~300 ms text flush is a live timer. NIC-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_secures_multiparty_text_per_participant() {
    use siphon_rtp_media::rtp::RtpPacket;
    use siphon_rtp_media::t140::RedPacket;

    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    // A secure text stream runs on `Redirect` from the start, so the dispatcher must be running.
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
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
    let mut control = Control::connect(control_addr).await;

    let (_a_audio, a_audio_addr) = phone().await;
    let (a_text, a_text_addr) = phone().await;
    let (_b_audio, b_audio_addr) = phone().await;
    let (b_text, b_text_addr) = phone().await;

    // A and B each mint their OWN text SDES key (their leg's inbound key).
    let a_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen a");
    let b_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen b");

    // A joins with plaintext audio + secure text; its answer anchors `RTP/SAVP` text on a non-zero port.
    let a_join = control
        .request(Command::ConferenceJoin {
            conference_id: "room".into(),
            from_tag: "tag-a".into(),
            sdp: secure_text_sdp(a_audio_addr, a_text_addr, &a_text_key),
            role: ConferenceRole::Talker,
            profile: Default::default(),
        })
        .await;
    let a_engine_text = text_engine_addr(&a_join);
    let engine_a_text_key = text_engine_crypto(&a_join);
    assert!(
        sdp_text(&a_join).contains(&format!("m=text {} RTP/SAVP", a_engine_text.port())),
        "A's answer anchors secure text: {}",
        sdp_text(&a_join)
    );
    assert_ne!(
        engine_a_text_key.key, a_text_key.key,
        "the engine mints its own text key for A, never echoing A's"
    );

    // B joins with plaintext audio + secure text.
    let b_join = control
        .request(Command::ConferenceJoin {
            conference_id: "room".into(),
            from_tag: "tag-b".into(),
            sdp: secure_text_sdp(b_audio_addr, b_text_addr, &b_text_key),
            role: ConferenceRole::Talker,
            profile: Default::default(),
        })
        .await;
    let engine_b_text_key = text_engine_crypto(&b_join);
    assert_ne!(
        engine_b_text_key.key, engine_a_text_key.key,
        "each participant's text leg carries a distinct engine key"
    );

    // A types "hi": build a plaintext RED/T.140 packet and encrypt it with A's own text key (A→engine).
    let plaintext = red_text_rtp(1, 1000, 0x0A0A_7E77, b"hi");
    let mut a_encrypt = SrtpContext::from_key_material(&a_text_key.key);
    let mut srtp = Vec::new();
    a_encrypt.protect(&plaintext, &mut srtp).expect("A encrypt");
    a_text
        .send_to(&srtp, a_engine_text)
        .await
        .expect("send secure text a");

    // B receives A's text as SRTP under B's own leg key; B decrypts it with the engine's offered key.
    let (b_data, _) = recv(&b_text).await;
    let mut b_decrypt = SrtpContext::from_key_material(&engine_b_text_key.key);
    let mut clear = Vec::new();
    b_decrypt
        .unprotect(&b_data, &mut clear)
        .expect("B decrypts the conference text with the engine's offered key");
    assert_ne!(
        b_data, clear,
        "B's conference text egress is SRTP on the wire, not plaintext"
    );
    let packet = RtpPacket::parse(&clear).expect("egress text RTP");
    assert_eq!(
        packet.csrc_count, 1,
        "RFC 9071 §4.2: one contributing source, survives the re-encrypt"
    );
    let red = RedPacket::parse(packet.payload).expect("RED payload");
    assert_eq!(
        String::from_utf8(red.primary().data.to_vec()).expect("utf8"),
        "hi",
        "B recovers A's decrypted-then-re-encrypted text"
    );

    for tag in ["tag-a", "tag-b"] {
        let left = control
            .request(Command::ConferenceLeave {
                conference_id: "room".into(),
                from_tag: tag.into(),
            })
            .await;
        assert!(matches!(left, CmdResult::Ok { .. }));
    }
    assert!(
        !engine.conference().contains("room"),
        "empty room torn down"
    );
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

/// A minimal WebSocket tee consumer on an ephemeral loopback port: it accepts one connection and
/// republishes every frame it receives, so a test can read the `start` envelope and the audio frames.
async fn tee_consumer() -> (
    String,
    flume::Receiver<tokio_tungstenite::tungstenite::Message>,
) {
    use futures_util::StreamExt;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind tee ws");
    let addr = listener.local_addr().expect("tee ws addr");
    let (sender, receiver) = flume::unbounded();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept tee ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("tee ws handshake");
        let (_sink, mut source) = socket.split();
        while let Some(Ok(message)) = source.next().await {
            if sender.send(message).is_err() {
                break;
            }
        }
    });
    (format!("ws://{addr}/tee"), receiver)
}

/// A controller asking for a WebSocket tee at an explicit wire rate must be told, on the control
/// plane, the rate it actually got: `ws_tee_started.sample_rate` is the negotiated wire rate, not the
/// 8 kHz codec rate the G.711 legs run at. Driven over the real JSON-over-TCP connection so the whole
/// contract — profile flag in, async event out — is exercised end to end, and cross-checked against
/// the `start` envelope the WS consumer itself receives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_teed_call_reports_the_negotiated_wire_sample_rate_on_the_control_plane() {
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use tokio_tungstenite::tungstenite::Message;

    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    // The tee promotes the relay into the userspace pipeline, whose Redirect datagrams the dispatcher
    // routes to the media actor that feeds the tee's sink.
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
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
    let mut control = Control::connect(control_addr).await;

    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let (tee_uri, tee_frames) = tee_consumer().await;

    let offer = control
        .request(Command::Offer {
            call_id: "tee-rate".into(),
            from_tag: "tag-a".into(),
            sdp: pcmu_offer(addr_a),
            profile: Default::default(),
        })
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "{offer:?}");

    // `ws_tee` + `ws_tee_sample_rate` in one round-trip: the tee attaches at answer time at 16 kHz,
    // even though both legs are 8 kHz PCMU.
    let answer = control
        .request(Command::Answer {
            call_id: "tee-rate".into(),
            from_tag: "tag-a".into(),
            to_tag: "tag-b".into(),
            sdp: pcmu_answer(addr_b),
            profile: ProfileFlags {
                ws_tee: Some(tee_uri),
                ws_tee_direction: Some(siphon_rtp_proto::WsTeeDirection::Caller),
                ws_tee_sample_rate: Some(16_000),
                ..Default::default()
            },
        })
        .await;
    let near_addr = engine_addr(&answer);

    // The control plane reports the rate it negotiated.
    let mut reported = None;
    for _ in 0..8 {
        if let Event::WsTeeStarted {
            call_id,
            channels,
            sample_rate,
            ..
        } = control.recv_event().await
        {
            assert_eq!(call_id, "tee-rate");
            assert_eq!(channels, 1, "a caller-only tee is mono");
            reported = Some(sample_rate);
            break;
        }
    }
    assert_eq!(
        reported,
        Some(16_000),
        "ws_tee_started must carry the negotiated wire rate, not the 8 kHz codec rate"
    );

    // …and the consumer's own `start` envelope agrees, so the two can never drift.
    let first = timeout(Duration::from_secs(3), tee_frames.recv_async())
        .await
        .expect("no timeout")
        .expect("a frame");
    match first {
        Message::Text(text) => match ControlMessage::from_json(text.as_str()) {
            Ok(ControlMessage::Start(data)) => {
                assert_eq!(data.media.sample_rate, 16_000);
                assert_eq!(data.call_id, "tee-rate");
            }
            other => panic!("expected start, got {other:?}"),
        },
        other => panic!("expected a start text frame, got {other:?}"),
    }

    // And the audio really is framed at that rate: 16 kHz x 20 ms mono L16 = 640 bytes.
    for sequence in 0..8u16 {
        phone_a
            .send_to(&pcmu_rtp(sequence), near_addr)
            .await
            .expect("a send");
    }
    let mut audio_bytes = None;
    for _ in 0..40 {
        let message = timeout(Duration::from_secs(3), tee_frames.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        if let Message::Binary(bytes) = message {
            audio_bytes = Some(bytes.len());
            break;
        }
    }
    assert_eq!(
        audio_bytes,
        Some(640),
        "the teed frames must match the rate the start envelope announced"
    );
}

/// A far-side answer selecting PCMU (PT 0), so both legs run at the same 8 kHz codec.
fn pcmu_answer(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 2 2 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

/// A 20 ms PCMU RTP packet (silence, 0xFF decodes to 0) at `sequence`.
fn pcmu_rtp(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet.extend_from_slice(&[0xFFu8; 160]);
    packet
}
