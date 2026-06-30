//! The raw-WS-PCM bridge control protocol (M1).
//!
//! Text WebSocket frames carry these `type`-tagged JSON messages; binary frames carry raw audio
//! (see [`super::pcm_to_l16_le`]). The schema follows the conventions distilled from
//! `mod_audio_stream`/`mod_audio_fork`, Twilio Media Streams, and the OpenAI Realtime API: a
//! `{ "type", "data", ... }` envelope, camelCase fields, binary audio off the JSON hot path.
//!
//! The OpenAI Realtime adapter (M2) maps these messages onto OpenAI's base64-in-JSON events; it
//! is a separate layer over the same [`super::pcm_to_l16_le`] audio core.

use serde::{Deserialize, Serialize};

/// Wire audio encoding for binary frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Encoding {
    /// 16-bit linear PCM.
    L16,
    /// G.711 µ-law.
    Pcmu,
    /// G.711 A-law.
    Pcma,
}

/// Byte order of L16 samples on the wire (the M1 default is little-endian; RTP L16 is big-endian
/// and byte-swapped at the RTP boundary — see the spec gotchas).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    /// Little-endian (M1 wire default / host order).
    Little,
    /// Big-endian.
    Big,
}

/// Stream direction relative to the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Engine → server only (uplink).
    Send,
    /// Server → engine only (downlink playout).
    Recv,
    /// Bidirectional.
    Duplex,
}

/// The negotiated binary audio format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaFormat {
    /// Sample encoding.
    pub encoding: Encoding,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Channel count (1 = mono/mixed, 2 = caller/callee).
    pub channels: u8,
    /// Bits per sample (16 for L16, 8 for G.711).
    pub bit_depth: u8,
    /// Wire byte order for L16.
    pub endianness: Endianness,
    /// Packetization time in milliseconds.
    pub ptime: u8,
}

impl MediaFormat {
    /// The M1 telephony default: L16, 8 kHz, mono, little-endian, 20 ms.
    #[must_use]
    pub fn telephony_default() -> Self {
        Self {
            encoding: Encoding::L16,
            sample_rate: 8000,
            channels: 1,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        }
    }

    /// Bytes in one binary audio frame at this format (L16).
    #[must_use]
    pub fn frame_bytes(&self) -> usize {
        let samples =
            (self.sample_rate as usize / 1000) * self.ptime as usize * self.channels as usize;
        samples * (self.bit_depth as usize / 8)
    }
}

/// `start` — engine → server, the first text frame, announcing the leg and audio format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartData {
    /// Bridge-assigned stream id, echoed on every later message.
    pub stream_id: String,
    /// SIP/leg correlation id.
    pub call_id: String,
    /// Stream direction.
    pub direction: Direction,
    /// Negotiated binary audio format.
    pub media: MediaFormat,
    /// Track labels (informational): `inbound` / `outbound`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracks: Vec<String>,
    /// Opaque application metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// `media_renegotiate` — mid-stream audio format change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenegotiateData {
    /// Stream id.
    pub stream_id: String,
    /// New format for subsequent binary frames.
    pub media: MediaFormat,
}

/// `play_start` — server → engine, request playback into the call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayStartData {
    /// Stream id.
    pub stream_id: String,
    /// Playback segment id (correlates `play_stop` / `mark`).
    pub play_id: String,
    /// `inline` (decode `audio_data`) or `binary` (audio follows as binary frames).
    pub source: PlaySource,
    /// Inline audio container (`raw` required; others optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_data_type: Option<String>,
    /// Inline audio encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Encoding>,
    /// Inline audio sample rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<u32>,
    /// Base64 inline audio (for `source = inline`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_data: Option<String>,
    /// Whether barge-in may clear this segment.
    #[serde(default = "default_true")]
    pub interruptible: bool,
    /// Mark name emitted when this segment finishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark_name: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Where `play_start` audio comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlaySource {
    /// Decode the inline `audio_data` (base64).
    Inline,
    /// Audio arrives as subsequent binary frames until `play_stop`.
    Binary,
}

/// `play_stop` — end of a `source: binary` playback segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayStopData {
    /// Stream id.
    pub stream_id: String,
    /// Segment id.
    pub play_id: String,
}

/// `clear` — barge-in / flush of buffered playout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearData {
    /// Stream id.
    pub stream_id: String,
    /// Segment to flush, or `None` to flush everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub play_id: Option<String>,
    /// Reason (e.g. `barge_in`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `mark` — engine → server, a playout boundary was rendered (or skipped on clear).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkData {
    /// Stream id.
    pub stream_id: String,
    /// Segment id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub play_id: Option<String>,
    /// The mark name reached.
    pub name: String,
}

/// `dtmf` — engine → server, a detected telephone-event digit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DtmfData {
    /// Stream id.
    pub stream_id: String,
    /// The digit (`0`-`9`, `*`, `#`, `A`-`D`).
    pub digit: String,
    /// Which track the digit was on.
    pub track: String,
    /// Event duration in milliseconds.
    pub duration_ms: u32,
}

/// `stop` — graceful close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopData {
    /// Stream id.
    pub stream_id: String,
    /// Reason (e.g. `call_ended`).
    pub reason: String,
}

/// `error` — failure report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorData {
    /// Stream id.
    pub stream_id: String,
    /// Machine-readable code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Whether the socket closes after this.
    pub fatal: bool,
}

/// `event` — opaque application event passthrough.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventData {
    /// Stream id.
    pub stream_id: String,
    /// Event name (e.g. `transcription`).
    pub name: String,
    /// Opaque payload.
    pub payload: serde_json::Value,
}

/// A bridge control message — the `type`-tagged envelope carried in text WS frames.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ControlMessage {
    /// Announce the leg + audio format (first text frame).
    Start(StartData),
    /// Change audio format mid-stream.
    MediaRenegotiate(RenegotiateData),
    /// Request playback into the call.
    PlayStart(PlayStartData),
    /// End a binary playback segment.
    PlayStop(PlayStopData),
    /// Flush playout (barge-in).
    Clear(ClearData),
    /// Playout boundary reached.
    Mark(MarkData),
    /// Detected DTMF digit.
    Dtmf(DtmfData),
    /// Graceful close.
    Stop(StopData),
    /// Failure report.
    Error(ErrorData),
    /// Opaque application event.
    Event(EventData),
}

impl ControlMessage {
    /// Serialize to a JSON text-frame body.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a JSON text-frame body.
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(message: &ControlMessage) {
        let json = message.to_json().expect("serialize");
        let back = ControlMessage::from_json(&json).expect("deserialize");
        assert_eq!(message, &back, "roundtrip via {json}");
    }

    #[test]
    fn start_wire_shape() {
        let message = ControlMessage::Start(StartData {
            stream_id: "str_a1b2c3".into(),
            call_id: "leg-1".into(),
            direction: Direction::Duplex,
            media: MediaFormat::telephony_default(),
            tracks: vec!["inbound".into(), "outbound".into()],
            metadata: None,
        });
        roundtrip(&message);

        let value: serde_json::Value = serde_json::to_value(&message).expect("value");
        assert_eq!(value["type"], "start");
        assert_eq!(value["data"]["streamId"], "str_a1b2c3");
        assert_eq!(value["data"]["media"]["encoding"], "L16");
        assert_eq!(value["data"]["media"]["sampleRate"], 8000);
        assert_eq!(value["data"]["media"]["endianness"], "little");
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(&ControlMessage::MediaRenegotiate(RenegotiateData {
            stream_id: "s".into(),
            media: MediaFormat {
                sample_rate: 16000,
                ..MediaFormat::telephony_default()
            },
        }));
        roundtrip(&ControlMessage::PlayStart(PlayStartData {
            stream_id: "s".into(),
            play_id: "p1".into(),
            source: PlaySource::Inline,
            audio_data_type: Some("raw".into()),
            encoding: Some(Encoding::L16),
            sample_rate: Some(8000),
            audio_data: Some("AAAA".into()),
            interruptible: true,
            mark_name: Some("p1_end".into()),
        }));
        roundtrip(&ControlMessage::PlayStop(PlayStopData {
            stream_id: "s".into(),
            play_id: "p1".into(),
        }));
        roundtrip(&ControlMessage::Clear(ClearData {
            stream_id: "s".into(),
            play_id: None,
            reason: Some("barge_in".into()),
        }));
        roundtrip(&ControlMessage::Mark(MarkData {
            stream_id: "s".into(),
            play_id: Some("p1".into()),
            name: "p1_end".into(),
        }));
        roundtrip(&ControlMessage::Dtmf(DtmfData {
            stream_id: "s".into(),
            digit: "5".into(),
            track: "inbound".into(),
            duration_ms: 160,
        }));
        roundtrip(&ControlMessage::Stop(StopData {
            stream_id: "s".into(),
            reason: "call_ended".into(),
        }));
        roundtrip(&ControlMessage::Error(ErrorData {
            stream_id: "s".into(),
            code: "unsupported_encoding".into(),
            message: "nope".into(),
            fatal: true,
        }));
        roundtrip(&ControlMessage::Event(EventData {
            stream_id: "s".into(),
            name: "transcription".into(),
            payload: serde_json::json!({ "text": "hi", "final": true }),
        }));
    }

    #[test]
    fn play_start_defaults_interruptible_true() {
        let json =
            r#"{"type":"play_start","data":{"streamId":"s","playId":"p","source":"binary"}}"#;
        let message = ControlMessage::from_json(json).expect("parse");
        match message {
            ControlMessage::PlayStart(data) => {
                assert!(data.interruptible, "interruptible defaults to true");
                assert_eq!(data.source, PlaySource::Binary);
            }
            other => panic!("expected play_start, got {other:?}"),
        }
    }

    #[test]
    fn frame_bytes_matches_format() {
        assert_eq!(MediaFormat::telephony_default().frame_bytes(), 320); // 8k mono 20ms L16
        let wideband = MediaFormat {
            sample_rate: 16000,
            ..MediaFormat::telephony_default()
        };
        assert_eq!(wideband.frame_bytes(), 640);
    }
}
