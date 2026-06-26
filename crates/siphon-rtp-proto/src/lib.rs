//! siphon-rtp control protocol — the wire contract between SIPhon and `siphon-rtp-engine`.
//!
//! This crate is shared by both ends (SIPhon depends on it directly), so the types here
//! *are* the contract. The native transport is length-prefixed JSON over a persistent TCP
//! connection: each frame is a big-endian `u32` byte length followed by a JSON body.
//!
//! Request/response are correlated by [`Request::id`]; asynchronous [`Event`]s are
//! server-initiated and carry no id. The verb set and session keying
//! (`call_id` / `from_tag` / `to_tag`) mirror the rtpengine NG semantics SIPhon already
//! speaks — only the encoding (JSON, not bencode) differs.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped on any breaking change to the message schema.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard ceiling on a single control frame (1 MiB). Guards against a corrupt length prefix.
/// SDP and play-media blobs are the only large payloads and stay well under this.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// A control request from SIPhon to the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Correlation id, echoed back in the matching [`Response`].
    pub id: u64,
    #[serde(flatten)]
    pub command: Command,
}

/// The control verbs. Internally tagged on `"command"`; a near-mechanical translation of
/// the rtpengine NG verb set SIPhon emits today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// SDP offer (A→B). Allocates media ports, rewrites SDP, returns the rewritten SDP.
    Offer {
        call_id: String,
        from_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// SDP answer (B→A). Completes negotiation; returns the rewritten SDP.
    Answer {
        call_id: String,
        from_tag: String,
        to_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Tear down a session (or one leg when `to_tag` is given).
    Delete {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Retrieve session statistics.
    Query {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Liveness check — answered with [`CmdResult::Pong`].
    Ping,
    /// Inject an audio prompt into a leg.
    PlayMedia {
        call_id: String,
        from_tag: String,
        source: PlayMediaSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repeat_times: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        start_pos_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Stop prompt playback on a leg.
    StopMedia { call_id: String, from_tag: String },
    /// Inject DTMF (RFC 4733) toward a leg.
    PlayDtmf {
        call_id: String,
        from_tag: String,
        code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        volume_dbm0: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pause_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
    },
    /// Replace outgoing audio with comfort silence.
    SilenceMedia { call_id: String, from_tag: String },
    /// Resume forwarding original audio after [`Command::SilenceMedia`].
    UnsilenceMedia { call_id: String, from_tag: String },
    /// Drop outgoing packets entirely (no audio, not even silence).
    BlockMedia { call_id: String, from_tag: String },
    /// Resume forwarding after [`Command::BlockMedia`].
    UnblockMedia { call_id: String, from_tag: String },
    /// Create a media subscription (SIPREC / MPTY). `from_tags` may list multiple legs.
    SubscribeRequest {
        call_id: String,
        from_tags: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp: Option<String>,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Complete a subscription's SDP negotiation.
    SubscribeAnswer {
        call_id: String,
        from_tag: String,
        to_tag: String,
        sdp: String,
        #[serde(default)]
        profile: ProfileFlags,
    },
    /// Tear down a subscription.
    Unsubscribe {
        call_id: String,
        from_tag: String,
        to_tag: String,
    },
    /// Authenticate the control connection with the server's shared secret. Handled by the control
    /// server (not the session engine); required as the first command when a secret is configured.
    Authenticate { token: String },
}

/// Source for [`Command::PlayMedia`]. Tagged on `"source"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum PlayMediaSource {
    /// A path on the engine host.
    File { path: String },
    /// Raw audio bytes carried inline.
    Blob {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    /// A prompt id in the engine's media database.
    DbId { id: u64 },
}

/// Per-leg media-handling flags. JSON twin of SIPhon's `NgFlags` (rtpengine profile).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFlags {
    /// e.g. `RTP/AVP`, `RTP/SAVP`, `RTP/AVPF`, `RTP/SAVPF`, `UDP/TLS/RTP/SAVPF`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_protocol: Option<String>,
    /// `remove` | `force` | `force-relay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ice: Option<String>,
    /// `passive` | `active` | `off`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtls: Option<String>,
    /// SDP fields to rewrite (e.g. `["origin"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replace: Vec<String>,
    /// Behavioral flags (e.g. `trust-address`, `symmetric`, `port-latching`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// NAT leg designation pair (e.g. `["external", "internal"]`), reversed on answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direction: Vec<String>,
    /// Whether to record this call leg.
    #[serde(default, skip_serializing_if = "is_false")]
    pub record_call: bool,
    /// Recording output directory/path, when recording.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_path: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A response to a [`Request`], correlated by [`Response::id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(flatten)]
    pub result: CmdResult,
}

/// The result payload of a [`Response`]. Tagged on `"result"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CmdResult {
    /// Success. Fields are populated per the originating command.
    Ok {
        /// Rewritten SDP (offer / answer / subscribe).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp: Option<String>,
        /// Duration of injected media (play_media).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        /// UAS To-tag (subscribe_request / siprec).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        /// Session statistics (query).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stats: Option<SessionStats>,
    },
    /// Answer to [`Command::Ping`].
    Pong,
    /// Failure with a human-readable reason.
    Error { reason: String },
}

/// Session statistics returned by [`Command::Query`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Packets dropped (jitter overflow, late, malformed).
    pub packets_lost: u64,
}

/// An asynchronous event pushed from the engine to SIPhon (no request correlation).
/// `#[serde(other)]` keeps forward-compatibility: SIPhon tolerates new event kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A DTMF digit was detected on a leg. Deserializes 1:1 into SIPhon's `DtmfEvent`.
    Dtmf {
        call_id: String,
        from_tag: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_tag: Option<String>,
        digit: String,
        duration_ms: u32,
        volume: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    /// Unknown / future event kind (forward-compat).
    #[serde(other)]
    Unknown,
}

/// Errors from the framing helpers.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// JSON (de)serialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// A frame's declared length exceeds [`MAX_FRAME_LEN`].
    #[error("frame length {len} exceeds maximum {max}")]
    FrameTooLarge { len: usize, max: usize },
}

/// Frame helpers: big-endian `u32` length prefix + JSON body.
///
/// The async TCP server uses these to read/write frames off a stream; they are kept
/// transport-agnostic (operate on byte slices/vecs) so they are trivially unit-testable.
pub mod frame {
    use super::{ProtoError, MAX_FRAME_LEN};
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    /// Length-prefix header size in bytes.
    pub const HEADER_LEN: usize = 4;

    /// Serialize `value` to a complete length-prefixed JSON frame.
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
        let body = serde_json::to_vec(value)?;
        if body.len() > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge {
                len: body.len(),
                max: MAX_FRAME_LEN,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Try to decode one frame from the front of `buffer`.
    ///
    /// Returns `Ok(Some((value, consumed)))` when a whole frame is present (the caller should
    /// drop `consumed` bytes from the front), `Ok(None)` when more bytes are needed, or an
    /// error on an oversized or malformed frame.
    pub fn decode<T: DeserializeOwned>(buffer: &[u8]) -> Result<Option<(T, usize)>, ProtoError> {
        if buffer.len() < HEADER_LEN {
            return Ok(None);
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&buffer[..HEADER_LEN]);
        let len = u32::from_be_bytes(header) as usize;
        if len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge {
                len,
                max: MAX_FRAME_LEN,
            });
        }
        let total = HEADER_LEN + len;
        if buffer.len() < total {
            return Ok(None);
        }
        let value = serde_json::from_slice(&buffer[HEADER_LEN..total])?;
        Ok(Some((value, total)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, &back, "roundtrip mismatch via {json}");
    }

    #[test]
    fn offer_roundtrip_and_wire_shape() {
        let request = Request {
            id: 7,
            command: Command::Offer {
                call_id: "abc@host".to_string(),
                from_tag: "ft1".to_string(),
                sdp: "v=0\r\n".to_string(),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".to_string()),
                    ice: Some("remove".to_string()),
                    replace: vec!["origin".to_string()],
                    direction: vec!["external".to_string(), "internal".to_string()],
                    ..Default::default()
                },
            },
        };
        roundtrip(&request);

        // Lock the flattened, internally-tagged wire shape.
        let json = serde_json::to_value(&request).expect("to_value");
        assert_eq!(json["id"], 7);
        assert_eq!(json["command"], "offer");
        assert_eq!(json["call_id"], "abc@host");
        assert_eq!(json["profile"]["transport_protocol"], "RTP/SAVP");
    }

    #[test]
    fn all_commands_roundtrip() {
        let commands = vec![
            Command::Answer {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: "t".into(),
                sdp: "v=0".into(),
                profile: ProfileFlags::default(),
            },
            Command::Delete {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: Some("t".into()),
            },
            Command::Query {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: None,
            },
            Command::Ping,
            Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::File {
                    path: "/p.wav".into(),
                },
                repeat_times: Some(2),
                start_pos_ms: None,
                duration_ms: Some(5000),
                to_tag: None,
            },
            Command::PlayDtmf {
                call_id: "c".into(),
                from_tag: "f".into(),
                code: "123#".into(),
                duration_ms: Some(100),
                volume_dbm0: Some(-8),
                pause_ms: Some(60),
                to_tag: None,
            },
            Command::SilenceMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
            },
            Command::SubscribeRequest {
                call_id: "c".into(),
                from_tags: vec!["a".into(), "b".into()],
                sdp: Some("v=0".into()),
                profile: ProfileFlags::default(),
            },
            Command::Unsubscribe {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: "t".into(),
            },
            Command::Authenticate { token: "s3cret".into() },
        ];
        for command in &commands {
            roundtrip(&Request {
                id: 1,
                command: command.clone(),
            });
        }
    }

    #[test]
    fn play_media_blob_roundtrip() {
        let request = Request {
            id: 3,
            command: Command::PlayMedia {
                call_id: "c".into(),
                from_tag: "f".into(),
                source: PlayMediaSource::Blob {
                    data: vec![0u8, 1, 2, 255, 128],
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                to_tag: None,
            },
        };
        roundtrip(&request);
    }

    #[test]
    fn results_roundtrip() {
        roundtrip(&Response {
            id: 1,
            result: CmdResult::Ok {
                sdp: Some("v=0".into()),
                duration_ms: None,
                to_tag: None,
                stats: None,
            },
        });
        roundtrip(&Response {
            id: 2,
            result: CmdResult::Pong,
        });
        roundtrip(&Response {
            id: 3,
            result: CmdResult::Error {
                reason: "no such call".into(),
            },
        });
        roundtrip(&Response {
            id: 4,
            result: CmdResult::Ok {
                sdp: None,
                duration_ms: None,
                to_tag: None,
                stats: Some(SessionStats {
                    packets_in: 100,
                    packets_out: 99,
                    bytes_in: 16000,
                    bytes_out: 15840,
                    packets_lost: 1,
                }),
            },
        });
    }

    #[test]
    fn dtmf_event_roundtrip() {
        roundtrip(&Event::Dtmf {
            call_id: "c".into(),
            from_tag: "f".into(),
            to_tag: None,
            digit: "5".into(),
            duration_ms: 120,
            volume: -8,
            source: Some("rtp".into()),
        });
    }

    #[test]
    fn unknown_event_is_forward_compatible() {
        let json = r#"{"event":"media_timeout","call_id":"c"}"#;
        let event: Event = serde_json::from_str(json).expect("deserialize unknown");
        assert_eq!(event, Event::Unknown);
    }

    #[test]
    fn frame_roundtrip() {
        let request = Request {
            id: 42,
            command: Command::Ping,
        };
        let bytes = frame::encode(&request).expect("encode");
        let (decoded, consumed): (Request, usize) =
            frame::decode(&bytes).expect("decode").expect("complete");
        assert_eq!(decoded, request);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn frame_partial_returns_none() {
        let request = Request {
            id: 1,
            command: Command::Ping,
        };
        let bytes = frame::encode(&request).expect("encode");
        // Header present but body truncated.
        let decoded: Option<(Request, usize)> =
            frame::decode(&bytes[..bytes.len() - 1]).expect("decode");
        assert!(decoded.is_none());
        // Only part of the header.
        let decoded: Option<(Request, usize)> = frame::decode(&bytes[..2]).expect("decode");
        assert!(decoded.is_none());
    }

    #[test]
    fn frame_decodes_consecutive_frames() {
        let first = Request {
            id: 1,
            command: Command::Ping,
        };
        let second = Request {
            id: 2,
            command: Command::Delete {
                call_id: "c".into(),
                from_tag: "f".into(),
                to_tag: None,
            },
        };
        let mut buffer = frame::encode(&first).expect("encode");
        buffer.extend(frame::encode(&second).expect("encode"));

        let (decoded_first, consumed): (Request, usize) =
            frame::decode(&buffer).expect("decode").expect("complete");
        assert_eq!(decoded_first, first);

        let (decoded_second, _): (Request, usize) = frame::decode(&buffer[consumed..])
            .expect("decode")
            .expect("complete");
        assert_eq!(decoded_second, second);
    }

    #[test]
    fn frame_rejects_oversized_length() {
        let mut buffer = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes().to_vec();
        buffer.extend_from_slice(b"{}");
        let result: Result<Option<(Request, usize)>, _> = frame::decode(&buffer);
        assert!(matches!(result, Err(ProtoError::FrameTooLarge { .. })));
    }

    use proptest::prelude::*;

    proptest! {
        /// The control framing eats untrusted bytes — arbitrary input must decode-or-error, never
        /// panic (a corrupt length prefix or body is an `Err`, not a crash).
        #[test]
        fn frame_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let _ = frame::decode::<Request>(&bytes);
        }

        /// `decode(encode(request))` round-trips over arbitrary ids/tags.
        #[test]
        fn request_survives_frame_roundtrip(
            id in any::<u64>(),
            call_id in "[a-z0-9@._-]{0,40}",
            from_tag in "[a-z0-9]{0,20}",
        ) {
            let request = Request {
                id,
                command: Command::Delete { call_id, from_tag, to_tag: None },
            };
            let bytes = frame::encode(&request).expect("encode");
            let (decoded, consumed): (Request, usize) =
                frame::decode(&bytes).expect("decode").expect("complete");
            prop_assert_eq!(decoded, request);
            prop_assert_eq!(consumed, bytes.len());
        }
    }
}
