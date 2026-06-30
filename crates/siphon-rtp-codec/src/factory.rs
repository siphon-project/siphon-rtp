//! SDP payload-type → codec construction.
//!
//! Maps a negotiated SDP codec (encoding name + clock rate, from `a=rtpmap` or the RFC 3551 static
//! payload-type table) onto a concrete [`Decoder`]/[`Encoder`] pair. The media slow path resolves a
//! leg's codec here once, at call setup, then runs the returned trait objects per frame.

#[cfg(feature = "amr")]
use crate::amr::{AmrNb, AmrWb};
use crate::cn::Cn;
use crate::g711::{Variant, G711};
use crate::g722::G722;
use crate::g726::{Rate, G726};
use crate::gsm_fr::GsmFr;
use crate::l16::L16;
use crate::{CodecError, Decoder, Encoder};

/// Map an SDP encoding name to a G.726 bit rate (RFC 3551 §4.5.4 names `G726-16/24/32/40`; `G721`
/// is the deprecated alias for `G726-32`). Returns `None` for any non-G.726 name.
fn g726_rate(encoding_name: &str) -> Option<Rate> {
    match encoding_name {
        "G726-16" => Some(Rate::R16),
        "G726-24" => Some(Rate::R24),
        "G726-32" | "G721" => Some(Rate::R32),
        "G726-40" => Some(Rate::R40),
        _ => None,
    }
}

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
    /// Egress encode mode for a variable-rate codec (AMR-WB speech mode 0..=8), when the peer's SDP
    /// `a=fmtp` `mode-set` constrains it. `None` ⇒ the codec's own default (AMR-WB mode 2 / 12.65
    /// kbit/s). Honoured by [`encoder_for`]; ignored by decoders (the wire frame carries its own mode).
    pub encode_mode: Option<u8>,
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
            encode_mode: None,
        }
    }

    /// Set the egress encode mode (e.g. resolved from an SDP `mode-set`). Chainable on [`new`].
    #[must_use]
    pub fn with_encode_mode(mut self, mode: Option<u8>) -> Self {
        self.encode_mode = mode;
        self
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
            3 => ("GSM", 8000, 1), // GSM 06.10 Full-Rate.
            8 => ("PCMA", 8000, 1),
            9 => ("G722", 8000, 1), // RTP clock is 8000 even though G.722 samples at 16 kHz.
            13 => ("CN", 8000, 1),  // RFC 3389 comfort noise.
            _ => return None,
        };
        Some(Self::new(payload_type, name, clock, channels, ptime_ms))
    }

    /// Whether this spec names RFC 3389 comfort noise (PT 13 / `CN`). Like telephone-event, CN is a
    /// secondary payload type the media path recognizes mid-stream and decodes through a generator,
    /// rather than the leg's primary audio codec.
    #[must_use]
    pub fn is_comfort_noise(&self) -> bool {
        self.encoding_name == "CN"
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
    if let Some(rate) = g726_rate(&spec.encoding_name) {
        return Ok(Box::new(G726::new(rate, spec.ptime_ms)));
    }
    match spec.encoding_name.as_str() {
        "PCMU" => Ok(Box::new(G711::new(Variant::Ulaw, spec.ptime_ms))),
        "PCMA" => Ok(Box::new(G711::new(Variant::Alaw, spec.ptime_ms))),
        "G722" => Ok(Box::new(G722::new(spec.ptime_ms))),
        "GSM" => Ok(Box::new(GsmFr::new())),
        "L16" => Ok(Box::new(L16::new(spec.clock_rate_hz, spec.ptime_ms))),
        // RFC 3389 comfort noise: a decode-side generator. There is no audio "encoder" — CN packets
        // are emitted by a VAD/DTX media-path policy, not by a per-frame encoder (see `encoder_for`).
        "CN" => Ok(Box::new(Cn::new(spec.clock_rate_hz, spec.ptime_ms))),
        // AMR-WB decode + encode are bit-exact for all 9 modes (the RTP path un-/re-sorts the RFC 4867
        // payload), validated against the 3GPP TS 26.174 vectors. Gated behind the `amr` feature
        // (patent-encumbered transcoding — see docs/codec-licensing.md); AMR passthrough/relay does not
        // reach here and is always available.
        #[cfg(feature = "amr")]
        "AMR-WB" => Ok(Box::new(AmrWb::new())),
        // AMR-NB decode is bit-exact for all 8 speech modes (0..=7) against 3GPP TS 26.074, with the
        // RFC 4867 RTP payload un-sorted to encoder order in `AmrNb::decode`. Encode is still WIP
        // (see `encoder_for`), so AMR-NB is reachable as a decode-side codec — transcode *out* to
        // another codec, conference ingress, recording, and voice-AI WS legs — but not yet as an
        // egress encoder. Same `amr`-feature gate (patent-licensed — docs/codec-licensing.md).
        #[cfg(feature = "amr")]
        "AMR" => Ok(Box::new(AmrNb::new())),
        _ => Err(CodecError::Unsupported(unsupported_name(
            &spec.encoding_name,
        ))),
    }
}

/// Build an encoder for `spec`, or [`CodecError::Unsupported`] when the codec is not implemented.
pub fn encoder_for(spec: &CodecSpec) -> Result<Box<dyn Encoder>, CodecError> {
    if let Some(rate) = g726_rate(&spec.encoding_name) {
        return Ok(Box::new(G726::new(rate, spec.ptime_ms)));
    }
    match spec.encoding_name.as_str() {
        "PCMU" => Ok(Box::new(G711::new(Variant::Ulaw, spec.ptime_ms))),
        "PCMA" => Ok(Box::new(G711::new(Variant::Alaw, spec.ptime_ms))),
        "G722" => Ok(Box::new(G722::new(spec.ptime_ms))),
        "GSM" => Ok(Box::new(GsmFr::new())),
        "L16" => Ok(Box::new(L16::new(spec.clock_rate_hz, spec.ptime_ms))),
        // AMR-WB encode is bit-exact (modes 0–7) against 3GPP TS 26.174 — same `amr`-feature gate as
        // decode (docs/codec-licensing.md). The egress mode is the SDP `mode-set`-resolved
        // `spec.encode_mode` when present, else the codec default (mode 2 / 12.65 kbit/s).
        #[cfg(feature = "amr")]
        "AMR-WB" => Ok(Box::new(match spec.encode_mode {
            Some(mode) => AmrWb::new().with_encode_mode(mode),
            None => AmrWb::new(),
        })),
        _ => Err(CodecError::Unsupported(unsupported_name(
            &spec.encoding_name,
        ))),
    }
}

/// Map an encoding name to a stable `&'static str` for the `Unsupported` error (the error type holds
/// `&'static str`, so we can only name codecs we know about).
fn unsupported_name(encoding_name: &str) -> &'static str {
    match encoding_name {
        "CN" => "comfort-noise generation (DTX) is a media-path policy, not an audio encoder",
        // With `amr` on, AMR-WB (decode + encode) and AMR-NB decode are wired, so they never reach
        // here. AMR-NB *encode* is still WIP — `encoder_for("AMR")` falls through to this message.
        #[cfg(feature = "amr")]
        "AMR" => "AMR-NB encode DSP not yet implemented (AMR-NB decode is supported)",
        #[cfg(not(feature = "amr"))]
        "AMR" | "AMR-WB" => {
            "AMR transcoding requires the `amr` build feature (patent-licensed — see \
             docs/codec-licensing.md); AMR passthrough/relay is always available"
        }
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
    fn builds_g722_from_static_payload_type() {
        let spec = CodecSpec::from_static_payload_type(9, 20).expect("G722 is static PT 9");
        assert_eq!(spec.encoding_name, "G722");
        // RFC 3551 §4.5.2: the RTP clock is 8 kHz even though G.722 carries 16 kHz audio.
        assert_eq!(spec.clock_rate_hz, 8000);
        let decoder = decoder_for(&spec).expect("g722 decoder");
        assert_eq!(
            decoder.params().sample_rate_hz,
            16000,
            "native PCM rate is 16 kHz"
        );
        let encoder = encoder_for(&spec).expect("g722 encoder");
        assert_eq!(
            encoder.rtp_clock_rate_hz(),
            8000,
            "RTP timestamp clock stays 8 kHz"
        );
    }

    #[test]
    fn builds_gsm_fr_from_static_payload_type() {
        let spec = CodecSpec::from_static_payload_type(3, 20).expect("GSM is static PT 3");
        assert_eq!(spec.encoding_name, "GSM");
        assert_eq!(spec.clock_rate_hz, 8000);
        let decoder = decoder_for(&spec).expect("gsm decoder");
        assert_eq!(decoder.frame_samples(), 160);
        assert!(encoder_for(&spec).is_ok(), "gsm encoder");
    }

    #[test]
    fn builds_g726_all_rates_and_g721_alias() {
        // RFC 3551 §4.5.4 names + the deprecated G721 alias for G726-32; all 8 kHz, encode + decode.
        for name in ["G726-16", "G726-24", "G726-32", "G726-40", "G721"] {
            let spec = CodecSpec::new(96, name, 8000, 1, 20);
            let decoder = decoder_for(&spec).unwrap_or_else(|_| panic!("{name} decoder"));
            assert_eq!(decoder.params().sample_rate_hz, 8000, "{name}");
            assert!(encoder_for(&spec).is_ok(), "{name} encoder");
        }
    }

    #[test]
    fn comfort_noise_decodes_but_has_no_encoder() {
        // RFC 3389 CN (static PT 13): a decode-side generator only — the encode side is a DTX policy.
        let spec = CodecSpec::from_static_payload_type(13, 20).expect("CN is static PT 13");
        assert_eq!(spec.encoding_name, "CN");
        assert!(spec.is_comfort_noise());
        assert!(
            decoder_for(&spec).is_ok(),
            "CN generator builds as a decoder"
        );
        assert!(
            matches!(encoder_for(&spec), Err(CodecError::Unsupported(_))),
            "CN has no per-frame audio encoder"
        );
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
        assert!(matches!(
            decoder_for(&spec),
            Err(CodecError::Unsupported(_))
        ));
        assert!(matches!(
            encoder_for(&spec),
            Err(CodecError::Unsupported(_))
        ));
    }

    #[cfg(not(feature = "amr"))]
    #[test]
    fn amr_transcoding_is_unsupported_without_the_amr_feature() {
        // Default build: AMR transcoding is gated off (patent-encumbered). Both directions must
        // return Unsupported — never panic. (Passthrough/relay never reaches the factory.)
        for name in ["AMR", "AMR-WB"] {
            let spec = CodecSpec::new(96, name, 16000, 1, 20);
            assert!(
                matches!(decoder_for(&spec), Err(CodecError::Unsupported(_))),
                "{name}"
            );
            assert!(
                matches!(encoder_for(&spec), Err(CodecError::Unsupported(_))),
                "{name}"
            );
        }
    }

    #[cfg(feature = "amr")]
    #[test]
    fn amr_wb_decodes_and_encodes_with_the_amr_feature() {
        // With the `amr` feature, AMR-WB builds in both directions (bit-exact, 3GPP TS 26.174) — so
        // it can be a conference egress codec.
        let wb = CodecSpec::new(96, "AMR-WB", 16000, 1, 20);
        assert!(decoder_for(&wb).is_ok(), "AMR-WB decoder");
        assert!(encoder_for(&wb).is_ok(), "AMR-WB encoder");
    }

    #[cfg(feature = "amr")]
    #[test]
    fn amr_wb_encoder_honours_the_spec_encode_mode() {
        // The SDP-`mode-set`-resolved `encode_mode` selects the egress AMR-WB speech mode; the RFC
        // 4867 octet-aligned ToC byte (byte 1) carries the frame type FT in bits 6..3.
        let pcm: Vec<i16> = (0..320)
            .map(|i| ((i as f32 * 0.2).sin() * 6000.0) as i16)
            .collect();
        let mut payload = vec![0u8; 64];

        let mut mode0 = encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20).with_encode_mode(Some(0)))
            .expect("amr-wb encoder");
        assert!(mode0.encode(&pcm, &mut payload).expect("encode") > 0);
        assert_eq!((payload[1] >> 3) & 0x0F, 0, "egress frame is mode 0 (ToC FT=0)");

        let mut default = encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("encoder");
        assert!(default.encode(&pcm, &mut payload).expect("encode") > 0);
        assert_eq!((payload[1] >> 3) & 0x0F, 2, "default egress frame is mode 2 (ToC FT=2)");
    }

    #[cfg(feature = "amr")]
    #[test]
    fn amr_nb_decodes_but_encode_is_still_wip() {
        // AMR-NB decode is bit-exact (3GPP TS 26.074) and now reachable from the factory, so AMR-NB
        // is usable as a decode-side codec (transcode egress, conference ingress, recording, voice-AI
        // WS). Encode DSP is still WIP, so `encoder_for` reports `Unsupported` rather than mis-encode.
        let nb = CodecSpec::new(97, "AMR", 8000, 1, 20);
        let mut decoder = decoder_for(&nb).expect("AMR-NB decoder builds");
        // A minimal RFC 4867 octet-aligned mode-0 (MR475) frame: CMR=0xF, then ToC (F=0, FT=0, Q=1),
        // then 12 speech bytes — decodes to one 160-sample 8 kHz frame.
        let payload = {
            let mut bytes = vec![0xF0u8, 0x04];
            bytes.extend(std::iter::repeat_n(0u8, 12));
            bytes
        };
        let mut pcm = [0i16; 160];
        assert_eq!(
            decoder.decode(&payload, &mut pcm).expect("AMR-NB decodes"),
            160,
            "one 20 ms / 160-sample frame"
        );
        assert!(
            matches!(encoder_for(&nb), Err(CodecError::Unsupported(_))),
            "AMR-NB encode is still WIP"
        );
    }

    #[test]
    fn telephone_event_is_recognised_and_unsupported_as_audio() {
        let spec = CodecSpec::new(101, "telephone-event", 8000, 1, 20);
        assert!(spec.is_telephone_event());
        assert!(matches!(
            decoder_for(&spec),
            Err(CodecError::Unsupported(_))
        ));
    }

    #[test]
    fn zero_channels_and_ptime_are_clamped() {
        let spec = CodecSpec::new(0, "PCMU", 8000, 0, 0);
        assert_eq!(spec.channels, 1);
        assert_eq!(spec.ptime_ms, 1);
    }
}
