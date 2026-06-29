//! SDP payload-type → codec construction.
//!
//! Maps a negotiated SDP codec (encoding name + clock rate, from `a=rtpmap` or the RFC 3551 static
//! payload-type table) onto a concrete [`Decoder`]/[`Encoder`] pair. The media slow path resolves a
//! leg's codec here once, at call setup, then runs the returned trait objects per frame.

use crate::amr::AmrWb;
use crate::g711::{Variant, G711};
use crate::l16::L16;
use crate::{CodecError, Decoder, Encoder};

/// A negotiated codec for one RTP stream: the wire payload type plus the encoding parameters needed
/// to build the codec. `encoding_name` is the `a=rtpmap` token (e.g. `"PCMU"`, `"L16"`, `"AMR-WB"`),
/// matched case-insensitively (SDP encoding names are case-insensitive — RFC 4566 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecSpec {
    /// RTP payload type (the number on the `m=` line).
    pub payload_type: u8,
    /// The `a=rtpmap` encoding name, uppercased on construction.
    pub encoding_name: String,
    /// RTP clock / native sample rate in Hz.
    pub clock_rate_hz: u32,
    /// Channel count (1 for telephony codecs).
    pub channels: u8,
    /// Packetization time in milliseconds.
    pub ptime_ms: u8,
}

impl CodecSpec {
    /// Build a spec, normalising the encoding name to uppercase for case-insensitive matching.
    #[must_use]
    pub fn new(
        payload_type: u8,
        encoding_name: &str,
        clock_rate_hz: u32,
        channels: u8,
        ptime_ms: u8,
    ) -> Self {
        Self {
            payload_type,
            encoding_name: encoding_name.to_ascii_uppercase(),
            clock_rate_hz,
            channels: channels.max(1),
            ptime_ms: ptime_ms.max(1),
        }
    }

    /// Resolve a static (RFC 3551) payload type to a spec when no `a=rtpmap` is present.
    ///
    /// Covers the static audio types the engine can build a codec for; returns `None` for a dynamic
    /// type (96–127) with no rtpmap, or a static type outside this set.
    #[must_use]
    pub fn from_static_payload_type(payload_type: u8, ptime_ms: u8) -> Option<Self> {
        // RFC 3551 §6 audio payload types (clock rate, channels).
        let (name, clock, channels) = match payload_type {
            0 => ("PCMU", 8000, 1),
            8 => ("PCMA", 8000, 1),
            9 => ("G722", 8000, 1), // RTP clock is 8000 even though G.722 samples at 16 kHz.
            _ => return None,
        };
        Some(Self::new(payload_type, name, clock, channels, ptime_ms))
    }

    /// Whether this spec names the RFC 4733 telephone-event "codec" (DTMF), which the media path
    /// handles out of band rather than as an audio codec.
    #[must_use]
    pub fn is_telephone_event(&self) -> bool {
        self.encoding_name == "TELEPHONE-EVENT"
    }
}

/// Build a decoder for `spec`, or [`CodecError::Unsupported`] when the codec is not implemented.
pub fn decoder_for(spec: &CodecSpec) -> Result<Box<dyn Decoder>, CodecError> {
    match spec.encoding_name.as_str() {
        "PCMU" => Ok(Box::new(G711::new(Variant::Ulaw, spec.ptime_ms))),
        "PCMA" => Ok(Box::new(G711::new(Variant::Alaw, spec.ptime_ms))),
        "L16" => Ok(Box::new(L16::new(spec.clock_rate_hz, spec.ptime_ms))),
        // AMR-WB decode is bit-exact for all 9 modes (the RTP path un-sorts the RFC 4867 payload);
        // the encoder is not yet implemented, so encoding AMR-WB still returns Unsupported below.
        "AMR-WB" => Ok(Box::new(AmrWb::new())),
        _ => Err(CodecError::Unsupported(unsupported_name(&spec.encoding_name))),
    }
}

/// Build an encoder for `spec`, or [`CodecError::Unsupported`] when the codec is not implemented.
pub fn encoder_for(spec: &CodecSpec) -> Result<Box<dyn Encoder>, CodecError> {
    match spec.encoding_name.as_str() {
        "PCMU" => Ok(Box::new(G711::new(Variant::Ulaw, spec.ptime_ms))),
        "PCMA" => Ok(Box::new(G711::new(Variant::Alaw, spec.ptime_ms))),
        "L16" => Ok(Box::new(L16::new(spec.clock_rate_hz, spec.ptime_ms))),
        _ => Err(CodecError::Unsupported(unsupported_name(&spec.encoding_name))),
    }
}

/// Map an encoding name to a stable `&'static str` for the `Unsupported` error (the error type holds
/// `&'static str`, so we can only name codecs we know about).
fn unsupported_name(encoding_name: &str) -> &'static str {
    match encoding_name {
        "G722" => "G.722 codec not yet implemented",
        "AMR-WB" => "AMR-WB encoder not yet implemented (decode is supported)",
        "AMR" => "AMR-NB codec not yet implemented",
        "OPUS" => "Opus codec not yet implemented",
        "TELEPHONE-EVENT" => "telephone-event is not an audio codec",
        _ => "unknown or unsupported codec",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_g711_ulaw_from_static_payload_type() {
        let spec = CodecSpec::from_static_payload_type(0, 20).expect("PCMU is static PT 0");
        assert_eq!(spec.encoding_name, "PCMU");
        assert_eq!(spec.clock_rate_hz, 8000);
        let decoder = decoder_for(&spec).expect("ulaw decoder");
        assert_eq!(decoder.params().sample_rate_hz, 8000);
        assert!(encoder_for(&spec).is_ok());
    }

    #[test]
    fn builds_g711_alaw_from_static_payload_type() {
        let spec = CodecSpec::from_static_payload_type(8, 20).expect("PCMA is static PT 8");
        assert_eq!(spec.encoding_name, "PCMA");
        assert!(decoder_for(&spec).is_ok());
        assert!(encoder_for(&spec).is_ok());
    }

    #[test]
    fn builds_l16_from_rtpmap_spec() {
        let spec = CodecSpec::new(96, "l16", 16000, 1, 20);
        assert_eq!(spec.encoding_name, "L16", "name is uppercased");
        let decoder = decoder_for(&spec).expect("l16 decoder");
        assert_eq!(decoder.params().sample_rate_hz, 16000);
        assert_eq!(decoder.frame_samples(), 320);
    }

    #[test]
    fn encoding_name_match_is_case_insensitive() {
        let spec = CodecSpec::new(0, "PcMu", 8000, 1, 20);
        assert!(decoder_for(&spec).is_ok());
    }

    #[test]
    fn dynamic_payload_type_without_rtpmap_is_none() {
        assert!(CodecSpec::from_static_payload_type(96, 20).is_none());
        assert!(CodecSpec::from_static_payload_type(101, 20).is_none());
    }

    #[test]
    fn unimplemented_codec_is_unsupported_not_panic() {
        let spec = CodecSpec::new(96, "opus", 48000, 2, 20);
        assert!(matches!(decoder_for(&spec), Err(CodecError::Unsupported(_))));
        assert!(matches!(encoder_for(&spec), Err(CodecError::Unsupported(_))));
    }

    #[test]
    fn amr_wb_decoder_is_wired_encoder_is_unsupported() {
        let spec = CodecSpec::new(96, "AMR-WB", 16000, 1, 20);
        let decoder = decoder_for(&spec).expect("AMR-WB decode is wired");
        assert_eq!(decoder.params().sample_rate_hz, 16000);
        assert_eq!(decoder.frame_samples(), 320, "16 kHz / 20 ms");
        // No AMR-WB encoder yet — encoding must fail cleanly, not panic.
        assert!(matches!(encoder_for(&spec), Err(CodecError::Unsupported(_))));
    }

    #[test]
    fn telephone_event_is_recognised_and_unsupported_as_audio() {
        let spec = CodecSpec::new(101, "telephone-event", 8000, 1, 20);
        assert!(spec.is_telephone_event());
        assert!(matches!(decoder_for(&spec), Err(CodecError::Unsupported(_))));
    }

    #[test]
    fn zero_channels_and_ptime_are_clamped() {
        let spec = CodecSpec::new(0, "PCMU", 8000, 0, 0);
        assert_eq!(spec.channels, 1);
        assert_eq!(spec.ptime_ms, 1);
    }
}
