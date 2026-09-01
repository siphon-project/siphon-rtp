//! The async WebSocket transport that drives a [`BridgeSession`].
//!
//! [`run_bridge`] owns one WebSocket connection and pumps it against the session: it sends `start`
//! first, then on every tick emits an uplink audio frame (binary) and renders one downlink frame
//! to RTP; inbound binary frames feed playout, inbound text frames are control. RTP flows in/out
//! over `flume` channels the engine wires to a datapath redirect flow. Generic over the socket IO
//! so it tests over an in-memory duplex with no NIC.

use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::interval;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::bridge::audio::MAX_FRAME_SAMPLES;
use crate::bridge::protocol::ControlMessage;
use crate::bridge::session::BridgeSession;
use crate::leg::MAX_RTP_PACKET;

/// Uplink scratch: the longest L16 frame [`BridgeSession::tick`] can emit. The core folds a
/// multi-channel decode to mono at the codec boundary, so this is mono — 48 kHz × the engine's ptime
/// ceiling × 2 B ([`MAX_FRAME_SAMPLES`]) = 11520 B. Derived, not chosen: a fixed 4096 here silently
/// truncated (and, with the staging slot, muted) every leg past 42 ms at 48 kHz.
const UPLINK_CAP: usize = MAX_FRAME_SAMPLES * 2;
/// Downlink scratch: one rendered RTP packet — header plus the largest payload the leg will emit,
/// which is an MTU bound rather than a ptime one (see [`MAX_RTP_PACKET`]).
const DOWNLINK_CAP: usize = MAX_RTP_PACKET;

/// Errors from the WebSocket bridge transport.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// A WebSocket protocol/transport error.
    #[error("websocket: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    /// Serializing an outbound control message failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Why a takeover bridge stopped, reported once when [`run_bridge`] returns.
///
/// The mirror of [`crate::bridge::TeeEndReason`], and for the same reason: a takeover bridge *is*
/// leg A's far side, so a bridge that ends without the controller asking is one-way audio on a live
/// call. The engine cannot report which end gave up unless the transport says so, and it can only
/// say so if this is a value rather than `()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeEndReason {
    /// The WS server closed the connection (RFC 6455 §5.5.1 close frame, or the stream just ended).
    ServerClosed,
    /// The WS server sent a `stop` control frame.
    ServerStopped,
    /// The call side went away — the RTP-in channel closed, or nothing is left to render RTP to.
    CallEnded,
}

/// Run the bridge until the peer closes, a `stop` is received, or the RTP source ends.
///
/// `rtp_in` carries packets from the call (redirected by the datapath); `rtp_out` carries packets
/// the bridge renders back toward the call. `ptime` is the audio frame interval (e.g. 20 ms).
///
/// The [`BridgeEndReason`] names which end ended it, so the engine can raise a `ws_bridge_ended`
/// that distinguishes "the controller detached it" from "the media server went away".
pub async fn run_bridge<S>(
    socket: WebSocketStream<S>,
    mut session: BridgeSession,
    rtp_in: flume::Receiver<Bytes>,
    rtp_out: flume::Sender<Bytes>,
    ptime: Duration,
) -> Result<BridgeEndReason, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = socket.split();

    // The first text frame announces the leg + audio format (mod_audio_fork handshake order).
    sink.send(Message::text(session.start_message().to_json()?))
        .await?;

    let mut ticker = interval(ptime);
    let mut uplink = vec![0u8; UPLINK_CAP];
    let mut downlink = vec![0u8; DOWNLINK_CAP];

    let reason = loop {
        if session.is_stopped() {
            // A `stop` control frame arrived on a previous iteration and the session latched it.
            break BridgeEndReason::ServerStopped;
        }
        tokio::select! {
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Binary(bytes))) => session.on_ws_binary(&bytes),
                Some(Ok(Message::Text(text))) => match ControlMessage::from_json(text.as_str()) {
                    Ok(control) => {
                        if let Some(reply) = session.on_control(control) {
                            sink.send(Message::text(reply.to_json()?)).await?;
                        }
                    }
                    Err(error) => tracing::debug!(%error, "bridge ignoring malformed control frame"),
                },
                Some(Ok(Message::Close(_))) | None => break BridgeEndReason::ServerClosed,
                Some(Ok(_)) => {} // ping/pong/raw frames: handled by tungstenite or ignored
                Some(Err(error)) => return Err(error.into()),
            },
            received = rtp_in.recv_async() => match received {
                Ok(packet) => session.on_rtp(&packet),
                Err(_) => break BridgeEndReason::CallEnded, // RTP source gone (call torn down)
            },
            _ = ticker.tick() => {
                let result = session.tick(&mut uplink, &mut downlink);
                // Turn signals (speech_started/stopped) go out first, so the server reacts to a
                // barge-in or turn endpoint without waiting behind this tick's audio frame.
                while let Some(control) = session.next_control() {
                    sink.send(Message::text(control.to_json()?)).await?;
                }
                if result.uplink_bytes > 0 {
                    sink.send(Message::binary(uplink[..result.uplink_bytes].to_vec())).await?;
                }
                if result.downlink_bytes > 0 && rtp_out.send(Bytes::copy_from_slice(&downlink[..result.downlink_bytes])).is_err() {
                    break BridgeEndReason::CallEnded; // call side gone
                }
            },
        }
    };

    let _ = sink.send(Message::Close(None)).await;
    Ok(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::protocol::{Direction, MediaFormat, StopData};
    use crate::bridge::{pcm_to_l16_le, BridgeSession};
    use crate::jitter::JitterBuffer;
    use crate::leg::MediaLeg;
    use crate::rtp::{write_packet, RtpHeader, RtpPacket};
    use siphon_rtp_codec::g711::G711;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::protocol::Role;

    fn session_fixture() -> BridgeSession {
        let leg = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x5555_6666,
            0,
        );
        BridgeSession::new(
            leg,
            MediaFormat::telephony_default(),
            "str_1",
            "call_1",
            Direction::Duplex,
            8,
        )
    }

    fn ulaw_packet(sequence: u16, byte: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 1,
        };
        let payload = [byte; 160];
        let mut buffer = vec![0u8; 172];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_pumps_audio_both_ways_over_websocket() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_ws = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let client_ws = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;

        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let (rtp_out_tx, rtp_out_rx) = flume::unbounded::<Bytes>();
        let bridge = tokio::spawn(run_bridge(
            server_ws,
            session_fixture(),
            rtp_in_rx,
            rtp_out_tx,
            Duration::from_millis(10),
        ));

        let (mut client_tx, mut client_rx) = client_ws.split();

        // 1. First frame is `start`.
        let first = timeout(Duration::from_secs(2), client_rx.next())
            .await
            .expect("no timeout")
            .expect("some")
            .expect("ok");
        match first {
            Message::Text(text) => assert!(matches!(
                ControlMessage::from_json(text.as_str()),
                Ok(ControlMessage::Start(_))
            )),
            other => panic!("expected start text frame, got {other:?}"),
        }

        // 2. Downlink: a binary L16 frame from the server is rendered to an RTP packet for the call.
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[1000i16; 160], &mut l16);
        client_tx
            .send(Message::binary(l16.to_vec()))
            .await
            .expect("send binary");
        let rtp = timeout(Duration::from_secs(2), rtp_out_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("rtp");
        let packet = RtpPacket::parse(&rtp).expect("parse rtp");
        assert_eq!(packet.payload.len(), 160);
        assert_eq!(packet.ssrc, 0x5555_6666);

        // 3. Uplink: an RTP packet from the call becomes a binary WS frame.
        rtp_in_tx
            .send(Bytes::from(ulaw_packet(7, 0xFF)))
            .expect("feed rtp");
        let mut got_uplink = false;
        for _ in 0..10 {
            let frame = timeout(Duration::from_secs(1), client_rx.next())
                .await
                .expect("no timeout")
                .expect("some")
                .expect("ok");
            if let Message::Binary(bytes) = frame {
                assert_eq!(bytes.len(), 320, "8k/20ms L16 uplink");
                got_uplink = true;
                break;
            }
        }
        assert!(got_uplink, "expected an uplink binary frame");

        // 4. `stop` ends the bridge.
        let stop = ControlMessage::Stop(StopData {
            stream_id: "str_1".into(),
            reason: "done".into(),
        });
        client_tx
            .send(Message::text(stop.to_json().expect("json")))
            .await
            .expect("send stop");
        let outcome = timeout(Duration::from_secs(2), bridge).await.expect("join");
        assert_eq!(
            outcome.expect("task").expect("clean exit"),
            BridgeEndReason::ServerStopped,
            "a `stop` frame is reported as the server stopping it, not as a generic clean exit"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_reports_the_server_closing_the_connection() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_ws = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let client_ws = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;

        let (_rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let (rtp_out_tx, _rtp_out_rx) = flume::unbounded::<Bytes>();
        let bridge = tokio::spawn(run_bridge(
            server_ws,
            session_fixture(),
            rtp_in_rx,
            rtp_out_tx,
            Duration::from_millis(10),
        ));

        let (mut client_tx, _client_rx) = client_ws.split();
        client_tx
            .send(Message::Close(None))
            .await
            .expect("send close");

        let outcome = timeout(Duration::from_secs(2), bridge).await.expect("join");
        assert_eq!(
            outcome.expect("task").expect("clean exit"),
            BridgeEndReason::ServerClosed,
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_reports_the_call_going_away() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_ws = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let _client_ws = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;

        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let (rtp_out_tx, _rtp_out_rx) = flume::unbounded::<Bytes>();
        let bridge = tokio::spawn(run_bridge(
            server_ws,
            session_fixture(),
            rtp_in_rx,
            rtp_out_tx,
            Duration::from_millis(10),
        ));

        drop(rtp_in_tx); // the call's redirect went away — teardown, not the server's doing
        let outcome = timeout(Duration::from_secs(2), bridge).await.expect("join");
        assert_eq!(
            outcome.expect("task").expect("clean exit"),
            BridgeEndReason::CallEnded,
        );
    }

    fn session_fixture_vad() -> BridgeSession {
        let leg = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x5555_6666,
            0,
        );
        BridgeSession::new(
            leg,
            MediaFormat::telephony_default(),
            "str_1",
            "call_1",
            Direction::Duplex,
            8,
        )
        .with_vad(1_000_000, 3, true)
    }

    fn ulaw_packet_pcm(sequence: u16, pcm: &[i16]) -> Vec<u8> {
        use siphon_rtp_codec::Encoder as _;
        let mut encoder = G711::ulaw();
        let mut payload = [0u8; 160];
        let len = encoder.encode(pcm, &mut payload).expect("encode");
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 1,
        };
        let mut buffer = vec![0u8; 12 + len];
        let written = write_packet(&header, &payload[..len], &mut buffer).expect("write");
        buffer.truncate(written);
        buffer
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_emits_speech_started_over_websocket_on_uplink_speech() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_ws = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let client_ws = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;

        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let (rtp_out_tx, _rtp_out_rx) = flume::unbounded::<Bytes>();
        let bridge = tokio::spawn(run_bridge(
            server_ws,
            session_fixture_vad(),
            rtp_in_rx,
            rtp_out_tx,
            Duration::from_millis(10),
        ));

        let (_client_tx, mut client_rx) = client_ws.split();

        // Drain the leading `start` text frame.
        let first = timeout(Duration::from_secs(2), client_rx.next())
            .await
            .expect("no timeout")
            .expect("some")
            .expect("ok");
        assert!(matches!(first, Message::Text(_)), "first frame is start");

        // The caller starts talking: several loud uplink frames.
        for sequence in 0..4 {
            rtp_in_tx
                .send(Bytes::from(ulaw_packet_pcm(sequence, &[4000i16; 160])))
                .expect("feed rtp");
        }

        // A `speech_started` text frame must surface among the WS frames the server receives.
        let mut got_speech_started = false;
        for _ in 0..30 {
            let frame = timeout(Duration::from_secs(1), client_rx.next())
                .await
                .expect("no timeout")
                .expect("some")
                .expect("ok");
            if let Message::Text(text) = frame {
                if matches!(
                    ControlMessage::from_json(text.as_str()),
                    Ok(ControlMessage::SpeechStarted(_))
                ) {
                    got_speech_started = true;
                    break;
                }
            }
        }
        assert!(got_speech_started, "expected a speech_started text frame");

        drop(rtp_in_tx); // ends the bridge (RTP source gone)
        let _ = timeout(Duration::from_secs(2), bridge).await;
    }
}
