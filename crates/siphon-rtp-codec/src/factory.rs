//! SDP payload-type → codec construction.
//!
//! Maps a negotiated SDP codec (encoding name + clock rate, from `a=rtpmap` or the RFC 3551 static
//! payload-type table) onto a concrete [`Decoder`]/[`Encoder`] pair. The media slow path resolves a
//! leg's codec here once, at call setup, then runs the returned trait objects per frame.

#[cfg(feature = "amr")]
use crate::amr::{AmrNb, AmrNbMode, AmrWb};
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

/// The SDP encoding name of Opus (RFC 7587 §6.1 registers the media subtype `opus`), uppercased to
/// match [`CodecSpec::encoding_name`]'s normalisation.
pub const OPUS_ENCODING_NAME: &str = "OPUS";

/// The one RTP clock rate Opus signals, in Hz. RFC 7587 §4.1: "the RTP timestamp is incremented with
/// a 48000 Hz clock rate for all modes of Opus and all sampling rates", and §7.1 repeats it for SDP —
/// "Opus supports several clock rates. For signaling purposes, only the highest, i.e., 48000, is
/// used." A peer that signals anything else is signalling a rate Opus does not clock at.
pub const OPUS_CLOCK_RATE_HZ: u32 = 48_000;

/// The RTP channel count Opus signals in `a=rtpmap`. RFC 7587 §7: the number of channels "MUST be 2"
/// — always, including for a mono stream, because it names the RTP channel count, not the audio
/// channel count. Mono/stereo is signalled by the `stereo` / `sprop-stereo` fmtp parameters instead
/// ([`OpusParams`]), which is why [`CodecSpec::decode_channels`] / [`CodecSpec::encode_channels`]
/// exist and `channels` alone must never be read as "this stream is stereo".
pub const OPUS_RTPMAP_CHANNELS: u8 = 2;

/// The RFC 7587 §6.1 Opus `a=fmtp` parameters negotiated with one peer.
///
/// Every field is **unidirectional and declarative** (RFC 7587 §7.1) — there is no negotiation, each
/// side simply states its own posture — so the direction each one applies in is fixed by the spec and
/// noted per field. As received from a peer's SDP:
///
/// - the *receive-only* parameters (`maxaveragebitrate`, `maxplaybackrate`, `stereo`, `cbr`,
///   `useinbandfec`, `usedtx`, `maxptime`) are that peer's limits on what the engine may **send** it;
/// - the *sender-only* parameters (`sprop-stereo`) describe what the peer will **send** the engine.
///
/// [`Default`] is the RFC 7587 §6.1 default for every parameter, so `OpusParams::default()` is
/// exactly "the peer sent no `a=fmtp`" and a consumer never has to know the defaults itself.
///
/// `sprop-maxcapturerate` is deliberately absent: nothing in the engine consumes it, and a parameter
/// that is parsed but never read is indistinguishable from one that is honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpusParams {
    /// `maxaveragebitrate` (RFC 7587 §6.1): the peer's maximum average **receive** bitrate in bit/s,
    /// valid 6000..=510000. `None` when unstated — the RFC default is mode-dependent, not a number.
    /// Bounds the Opus encoder's rate control; **no consumer in the engine until the Opus encoder
    /// lands** (it is carried through SDP and the HA snapshot so nothing is lost meanwhile).
    pub max_average_bitrate: Option<u32>,
    /// `maxplaybackrate` (RFC 7587 §6.1): the maximum output sampling rate the peer can render, in
    /// Hz, valid 8000..=48000, RFC default 48000. Caps the audio bandwidth the engine encodes toward
    /// it; **no consumer in the engine until the Opus encoder lands.**
    pub max_playback_rate_hz: u32,
    /// `maxptime` (RFC 7587 §6.1, carried in SDP as `a=maxptime` per §7): the longest packetization
    /// the peer accepts, in ms, RFC default 120. Consumed today — it clamps the leg's egress
    /// `ptime_ms`, so the engine never sends a packet longer than the peer will take.
    pub max_ptime_ms: u8,
    /// `stereo` (RFC 7587 §6.1, receive-only): whether the peer can **render** stereo, default 0.
    /// A ceiling, never an obligation — §7.1 only forbids sending stereo when it is 0. The engine's
    /// media path is mono, so it never sends stereo regardless; see [`CodecSpec::encode_channels`].
    pub stereo: bool,
    /// `sprop-stereo` (RFC 7587 §6.1, sender-only): whether the peer will **send** stereo, default 0.
    /// Consumed today — it is the ingress channel count ([`CodecSpec::decode_channels`]), so the
    /// decoder is built for the right layout and the media path folds it to mono.
    pub sprop_stereo: bool,
    /// `cbr` (RFC 7587 §6.1, receive-only): the peer asks for constant bitrate, default 0 (VBR).
    /// Selects the Opus encoder's rate-control mode; **no consumer until the Opus encoder lands.**
    pub cbr: bool,
    /// `useinbandfec` (RFC 7587 §6.1, receive-only): the peer's decoder will use in-band FEC (LBRR),
    /// default 0. Enables FEC generation in the Opus encoder; **no consumer until it lands.**
    pub use_inband_fec: bool,
    /// `usedtx` (RFC 7587 §6.1, receive-only): the peer accepts discontinuous transmission, default
    /// 0. Enables DTX in the Opus encoder; **no consumer until it lands.**
    pub use_dtx: bool,
}

/// RFC 7587 §6.1 defaults: `maxplaybackrate` 48000 Hz, `maxptime` 120 ms, and 0 (off/mono) for every
/// flag. `maxaveragebitrate` has no fixed default (it is mode-dependent), hence `None`.
impl Default for OpusParams {
    fn default() -> Self {
        Self {
            max_average_bitrate: None,
            max_playback_rate_hz: OPUS_CLOCK_RATE_HZ,
            max_ptime_ms: OPUS_MAX_PTIME_MS,
            stereo: false,
            sprop_stereo: false,
            cbr: false,
            use_inband_fec: false,
            use_dtx: false,
        }
    }
}

/// Longest packetization Opus signals, in milliseconds — the RFC 7587 §6.1 `maxptime` default and its
/// hard ceiling ("a maximum value of 120"). Also the longest audio one RFC 6716 §3.2 packet can carry
/// (a code-3 packet of 48 × 2.5 ms frames), which a decoder must accept whatever ptime was negotiated.
pub const OPUS_MAX_PTIME_MS: u8 = 120;

/// Lowest `maxplaybackrate` / `sprop-maxcapturerate` RFC 7587 §6.1 permits, in Hz.
const OPUS_MIN_PLAYBACK_RATE_HZ: u32 = 8_000;
/// Lowest `maxaveragebitrate` RFC 7587 §6.1 permits, in bit/s.
const OPUS_MIN_AVERAGE_BITRATE: u32 = 6_000;
/// Highest `maxaveragebitrate` RFC 7587 §6.1 permits, in bit/s.
const OPUS_MAX_AVERAGE_BITRATE: u32 = 510_000;

impl OpusParams {
    /// Clamp a `maxplaybackrate` into the RFC 7587 §6.1 range (8000..=48000 Hz). A value outside it
    /// is out of spec; clamping keeps the nearest legal meaning rather than discarding the peer's
    /// intent (an under-range value still says "I am narrowband").
    #[must_use]
    pub fn clamp_playback_rate_hz(rate_hz: u32) -> u32 {
        rate_hz.clamp(OPUS_MIN_PLAYBACK_RATE_HZ, OPUS_CLOCK_RATE_HZ)
    }

    /// Clamp a `maxaveragebitrate` into the RFC 7587 §6.1 range (6000..=510000 bit/s).
    #[must_use]
    pub fn clamp_average_bitrate(bitrate: u32) -> u32 {
        bitrate.clamp(OPUS_MIN_AVERAGE_BITRATE, OPUS_MAX_AVERAGE_BITRATE)
    }

    /// Clamp a `ptime`/`maxptime` into the RFC 7587 §6.1 ceiling of 120 ms (0 is meaningless, so it
    /// floors at 1 — the same clamp [`CodecSpec::new`] applies to `ptime_ms`).
    #[must_use]
    pub fn clamp_ptime_ms(ptime_ms: u8) -> u8 {
        ptime_ms.clamp(1, OPUS_MAX_PTIME_MS)
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
    /// The full set of AMR speech modes the peer's SDP `mode-set` permits (RFC 4867 §8.1), empty when
    /// unconstrained. Passed to the AMR-WB encoder so a per-frame RFC 4867 CMR is clamped into it and
    /// the engine never encodes a disallowed mode. Distinct from `encode_mode` (the *default* mode).
    pub allowed_modes: Vec<u8>,
    /// The peer's RFC 7587 §6.1 Opus `a=fmtp` parameters, when this spec names Opus and the peer sent
    /// an `a=fmtp` (or an `a=maxptime`). `None` for every other codec, and for an Opus leg that
    /// declared nothing — a consumer reads [`OpusParams::default`] then, which *is* the RFC default
    /// set. Ignored by every non-Opus codec.
    pub opus: Option<OpusParams>,
}

impl CodecSpec {
    /// Build a spec, normalising the encoding name to uppercase for case-insensitive matching.
    ///
    /// Opus is normalised to the two values RFC 7587 fixes for it, whatever the peer signalled: the
    /// clock rate to 48000 (§4.1 / §7.1 — Opus clocks RTP at 48 kHz in every mode, so believing a
    /// peer's `opus/16000` would mis-scale every timestamp and the RFC 3550 §6.4.1 jitter estimate)
    /// and the rtpmap channel count to 2 (§7 — "MUST be 2", even for mono). The *audio* channel count
    /// is a separate question answered by [`Self::decode_channels`] / [`Self::encode_channels`].
    #[must_use]
    pub fn new(
        payload_type: u8,
        encoding_name: &str,
        clock_rate_hz: u32,
        channels: u8,
        ptime_ms: u8,
    ) -> Self {
        let encoding_name = encoding_name.to_ascii_uppercase();
        let is_opus = encoding_name == OPUS_ENCODING_NAME;
        Self {
            payload_type,
            clock_rate_hz: if is_opus {
                OPUS_CLOCK_RATE_HZ
            } else {
                clock_rate_hz
            },
            channels: if is_opus {
                OPUS_RTPMAP_CHANNELS
            } else {
                channels.max(1)
            },
            encoding_name,
            ptime_ms: ptime_ms.max(1),
            encode_mode: None,
            allowed_modes: Vec::new(),
            opus: None,
        }
    }

    /// Whether this spec names Opus (RFC 7587).
    #[must_use]
    pub fn is_opus(&self) -> bool {
        self.encoding_name == OPUS_ENCODING_NAME
    }

    /// The peer's Opus parameters, or the RFC 7587 §6.1 default set when it declared none. Returns
    /// the defaults for a non-Opus spec too, so a caller that has already established the codec never
    /// has to unwrap an `Option`.
    #[must_use]
    pub fn opus_params(&self) -> OpusParams {
        self.opus.unwrap_or_default()
    }

    /// Audio channels in the PCM the engine **decodes** from this peer — the length unit
    /// [`Decoder::frame_samples`] is counted in, interleaved (see the crate-level channel contract).
    ///
    /// For Opus this is the peer's `sprop-stereo` (RFC 7587 §6.1, sender-only: what the peer will
    /// send), **not** the rtpmap channel count, which §7 pins at 2 for every Opus stream. For every
    /// other codec it is the rtpmap channel count.
    #[must_use]
    pub fn decode_channels(&self) -> u8 {
        if self.is_opus() {
            if self.opus_params().sprop_stereo {
                2
            } else {
                1
            }
        } else {
            self.channels.max(1)
        }
    }

    /// Audio channels in the PCM the engine **encodes** toward this peer.
    ///
    /// Always 1 for Opus today: the engine's media path is mono end to end (mixer, resampler, jitter,
    /// AEC/NS), so a stereo ingress is folded to mono at the trait boundary and there is no stereo
    /// PCM to encode. That is spec-clean — RFC 7587 §7.1 makes `stereo` a ceiling ("MUST NOT be sent
    /// stereo" when 0), never an obligation to use it — and the engine states it back as
    /// `sprop-stereo=0` so the peer's decoder knows exactly what it will receive. When the media path
    /// gains a multi-channel mode, this becomes the peer's `stereo` capability.
    #[must_use]
    pub fn encode_channels(&self) -> u8 {
        if self.is_opus() {
            1
        } else {
            self.channels.max(1)
        }
    }

    /// Set the egress encode mode (e.g. resolved from an SDP `mode-set`). Chainable on [`CodecSpec::new`].
    #[must_use]
    pub fn with_encode_mode(mut self, mode: Option<u8>) -> Self {
        self.encode_mode = mode;
        self
    }

    /// Set the AMR `mode-set`-permitted speech modes for per-frame CMR clamping. Chainable on
    /// [`CodecSpec::new`].
    #[must_use]
    pub fn with_allowed_modes(mut self, modes: Vec<u8>) -> Self {
        self.allowed_modes = modes;
        self
    }

    /// Attach the peer's RFC 7587 Opus `a=fmtp` parameters (the Opus counterpart of
    /// [`Self::with_allowed_modes`]). Chainable on [`CodecSpec::new`].
    ///
    /// Also applies the one parameter that constrains framing rather than the codec: `maxptime` caps
    /// this leg's egress `ptime_ms` (RFC 7587 §6.1 / §7 — the peer states the longest packet it will
    /// accept), so the encoder built from this spec never produces one the peer would drop. A
    /// non-Opus spec is left untouched.
    #[must_use]
    pub fn with_opus_params(mut self, params: Option<OpusParams>) -> Self {
        if !self.is_opus() {
            return self;
        }
        if let Some(params) = params {
            self.ptime_ms = self
                .ptime_ms
                .min(OpusParams::clamp_ptime_ms(params.max_ptime_ms.max(1)));
        }
        self.opus = params;
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

/// Every codec in this factory but Opus is mono by definition, so a spec asking one of them for more
/// than one channel cannot be honoured. Reject it rather than silently building a mono codec: a
/// stereo `L16/44100/2` stream decoded as mono would read interleaved pairs as consecutive samples
/// and play back at double speed with the channels smeared together — audible garbage, no error.
fn reject_multi_channel(channels: u8) -> Result<(), CodecError> {
    if channels > 1 {
        return Err(CodecError::Unsupported(
            "codec is mono-only; a multi-channel stream was negotiated for it",
        ));
    }
    Ok(())
}

/// Build a decoder for `spec`, or [`CodecError::Unsupported`] when the codec is not implemented.
pub fn decoder_for(spec: &CodecSpec) -> Result<Box<dyn Decoder>, CodecError> {
    // The ingress channel count is `decode_channels`, not the rtpmap `channels` — they differ for
    // Opus, whose rtpmap is always `/2` (RFC 7587 §7) while the stream may well be mono.
    if !spec.is_opus() {
        reject_multi_channel(spec.decode_channels())?;
    }
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
        // RFC 4867 RTP payload un-sorted to encoder order in `AmrNb::decode`. Encode is bit-exact for
        // all 8 speech modes as well (see `encoder_for`), so AMR-NB works as both a decode-side codec
        // and an egress encoder (enabling AMR-NB↔G.711 transcode). Same `amr`-feature gate
        // (patent-licensed — docs/codec-licensing.md).
        #[cfg(feature = "amr")]
        "AMR" => Ok(Box::new(AmrNb::new())),
        _ => Err(CodecError::Unsupported(unsupported_name(
            &spec.encoding_name,
        ))),
    }
}

/// Build an encoder for `spec`, or [`CodecError::Unsupported`] when the codec is not implemented.
pub fn encoder_for(spec: &CodecSpec) -> Result<Box<dyn Encoder>, CodecError> {
    // Same guard as `decoder_for`, on the egress channel count (1 for Opus — see
    // [`CodecSpec::encode_channels`] — so the Opus arm is never rejected on channels).
    reject_multi_channel(spec.encode_channels())?;
    if let Some(rate) = g726_rate(&spec.encoding_name) {
        return Ok(Box::new(G726::new(rate, spec.ptime_ms)));
    }
    match spec.encoding_name.as_str() {
        "PCMU" => Ok(Box::new(G711::new(Variant::Ulaw, spec.ptime_ms))),
        "PCMA" => Ok(Box::new(G711::new(Variant::Alaw, spec.ptime_ms))),
        "G722" => Ok(Box::new(G722::new(spec.ptime_ms))),
        "GSM" => Ok(Box::new(GsmFr::new())),
        "L16" => Ok(Box::new(L16::new(spec.clock_rate_hz, spec.ptime_ms))),
        // AMR-WB encode is bit-exact (all 9 modes, 0..=8) against 3GPP TS 26.174 — same `amr`-feature gate as
        // decode (docs/codec-licensing.md). The egress mode is the SDP `mode-set`-resolved
        // `spec.encode_mode` when present, else the codec default (mode 2 / 12.65 kbit/s). The full
        // `mode-set` (`spec.allowed_modes`) bounds per-frame RFC 4867 CMR adaptation (`request_mode`).
        #[cfg(feature = "amr")]
        "AMR-WB" => {
            let mut encoder = AmrWb::new().with_allowed_modes(&spec.allowed_modes);
            if let Some(mode) = spec.encode_mode {
                encoder = encoder.with_encode_mode(mode);
            }
            Ok(Box::new(encoder))
        }
        // AMR-NB encode is bit-exact (3GPP TS 26.074) for all 8 speech modes: MR475 (4.75k), MR515
        // (5.15k), MR59 (5.90k), MR67 (6.70k), MR74 (7.40k), MR795 (7.95k), MR102 (10.2k) and MR122
        // (12.2k, GSM-EFR). No `mode-set` ⇒ the codec default (MR122). Same `amr`-feature gate.
        #[cfg(feature = "amr")]
        "AMR" => match spec.encode_mode {
            None => Ok(Box::new(AmrNb::new())),
            Some(m) => match AmrNbMode::from_frame_type(m) {
                Some(
                    mode @ (AmrNbMode::Mr475
                    | AmrNbMode::Mr515
                    | AmrNbMode::Mr590
                    | AmrNbMode::Mr670
                    | AmrNbMode::Mr740
                    | AmrNbMode::Mr795
                    | AmrNbMode::Mr1020
                    | AmrNbMode::Mr1220),
                ) => Ok(Box::new(AmrNb::new().with_encode_mode(mode))),
                // Only non-speech frame types (SID/DTX/NO_DATA) remain unsupported for encode.
                _ => Err(CodecError::Unsupported(
                    "AMR-NB encode is wired for all 8 speech modes; SID/DTX frame types are not encodable",
                )),
            },
        },
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
        // With `amr` on, AMR-WB (decode + encode) and AMR-NB decode + all 8 speech-mode encoders are
        // wired, so supported specs never reach here. `encoder_for("AMR")` handles a SID/DTX-mode
        // request with its own message; this fallback is only hit for a decode-side "AMR" spec that
        // has no encoder.
        #[cfg(feature = "amr")]
        "AMR" => {
            "AMR-NB encode is wired for all 8 speech modes; SID/DTX frame types are not encodable"
        }
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

    #[test]
    fn opus_spec_is_normalised_to_the_rfc_7587_clock_and_rtpmap_channels() {
        // RFC 7587 §4.1/§7.1: Opus always clocks RTP at 48 kHz. §7: the rtpmap channel count MUST be
        // 2. A peer signalling `opus/16000/1` is out of spec — the spec wins, so both are corrected.
        let spec = CodecSpec::new(111, "opus", 16_000, 1, 20);
        assert!(spec.is_opus());
        assert_eq!(spec.clock_rate_hz, 48_000);
        assert_eq!(spec.channels, 2);
        // The correction is Opus-only — every other codec keeps exactly what was signalled.
        let l16 = CodecSpec::new(96, "L16", 44_100, 2, 20);
        assert_eq!((l16.clock_rate_hz, l16.channels), (44_100, 2));
    }

    #[test]
    fn opus_params_default_to_the_rfc_7587_values() {
        // RFC 7587 §6.1 defaults: maxplaybackrate 48000, maxptime 120, every flag 0/mono, and no
        // fixed maxaveragebitrate (it is mode-dependent).
        let params = OpusParams::default();
        assert_eq!(params.max_playback_rate_hz, 48_000);
        assert_eq!(params.max_ptime_ms, 120);
        assert_eq!(params.max_average_bitrate, None);
        assert!(!params.stereo);
        assert!(!params.sprop_stereo);
        assert!(!params.cbr);
        assert!(!params.use_inband_fec);
        assert!(!params.use_dtx);
        // An Opus spec with no fmtp reads the same defaults through `opus_params()`.
        assert_eq!(
            CodecSpec::new(111, "opus", 48_000, 2, 20).opus_params(),
            params
        );
    }

    #[test]
    fn opus_channel_counts_come_from_fmtp_not_from_the_rtpmap() {
        // `channels` is pinned at 2 for every Opus stream (RFC 7587 §7), so reading it as the audio
        // channel count would make every mono Opus leg "stereo". The fmtp answers instead.
        let mono = CodecSpec::new(111, "opus", 48_000, 2, 20);
        assert_eq!(mono.decode_channels(), 1, "sprop-stereo defaults to 0");
        assert_eq!(mono.encode_channels(), 1);

        let stereo_in =
            CodecSpec::new(111, "opus", 48_000, 2, 20).with_opus_params(Some(OpusParams {
                sprop_stereo: true,
                ..OpusParams::default()
            }));
        assert_eq!(stereo_in.decode_channels(), 2, "the peer sends stereo");
        assert_eq!(
            stereo_in.encode_channels(),
            1,
            "the engine's media path is mono, so it never encodes stereo"
        );

        // `stereo=1` is a receive ceiling (RFC 7587 §7.1), not an obligation — egress stays mono.
        let stereo_out =
            CodecSpec::new(111, "opus", 48_000, 2, 20).with_opus_params(Some(OpusParams {
                stereo: true,
                ..OpusParams::default()
            }));
        assert_eq!(stereo_out.decode_channels(), 1);
        assert_eq!(stereo_out.encode_channels(), 1);
    }

    #[test]
    fn opus_maxptime_clamps_the_leg_ptime() {
        // RFC 7587 §6.1/§7: `maxptime` is the longest packet the peer will accept, so a negotiated
        // 60 ms ptime against `maxptime=40` must send 40 ms — the parameter is honoured, not stored.
        let clamped =
            CodecSpec::new(111, "opus", 48_000, 2, 60).with_opus_params(Some(OpusParams {
                max_ptime_ms: 40,
                ..OpusParams::default()
            }));
        assert_eq!(clamped.ptime_ms, 40);
        // A maxptime above the negotiated ptime does not raise it (it is a ceiling, not a target).
        let unclamped = CodecSpec::new(111, "opus", 48_000, 2, 20)
            .with_opus_params(Some(OpusParams::default()));
        assert_eq!(unclamped.ptime_ms, 20);
        // A degenerate `maxptime=0` cannot floor the ptime to zero (that would be a zero-length frame).
        let degenerate =
            CodecSpec::new(111, "opus", 48_000, 2, 20).with_opus_params(Some(OpusParams {
                max_ptime_ms: 0,
                ..OpusParams::default()
            }));
        assert_eq!(degenerate.ptime_ms, 1);
    }

    #[test]
    fn opus_params_are_ignored_on_a_non_opus_spec() {
        // The carrier is Opus-specific; attaching it to G.711 must not touch the spec (in particular
        // it must not clamp its ptime through an Opus `maxptime`).
        let spec = CodecSpec::new(0, "PCMU", 8000, 1, 60).with_opus_params(Some(OpusParams {
            max_ptime_ms: 20,
            ..OpusParams::default()
        }));
        assert_eq!(spec.ptime_ms, 60);
        assert!(spec.opus.is_none());
    }

    #[test]
    fn opus_fmtp_range_clamps_follow_rfc_7587() {
        // §6.1 ranges: maxplaybackrate 8000..=48000, maxaveragebitrate 6000..=510000, ptime ..=120.
        assert_eq!(OpusParams::clamp_playback_rate_hz(4000), 8000);
        assert_eq!(OpusParams::clamp_playback_rate_hz(96_000), 48_000);
        assert_eq!(OpusParams::clamp_playback_rate_hz(16_000), 16_000);
        assert_eq!(OpusParams::clamp_average_bitrate(1), 6000);
        assert_eq!(OpusParams::clamp_average_bitrate(1_000_000), 510_000);
        assert_eq!(OpusParams::clamp_average_bitrate(20_000), 20_000);
        assert_eq!(OpusParams::clamp_ptime_ms(0), 1);
        assert_eq!(OpusParams::clamp_ptime_ms(255), 120);
        assert_eq!(OpusParams::clamp_ptime_ms(60), 60);
    }

    #[test]
    fn mono_only_codecs_reject_a_multi_channel_spec() {
        // A stereo `L16/44100/2` decoded by the mono L16 codec would read interleaved pairs as
        // consecutive samples — double-speed, channels smeared. Reject instead of mis-decoding.
        for name in ["PCMU", "PCMA", "G722", "GSM", "L16", "G726-32"] {
            let spec = CodecSpec::new(96, name, 8000, 2, 20);
            assert!(
                matches!(decoder_for(&spec), Err(CodecError::Unsupported(_))),
                "{name} decoder must decline a stereo spec"
            );
            assert!(
                matches!(encoder_for(&spec), Err(CodecError::Unsupported(_))),
                "{name} encoder must decline a stereo spec"
            );
        }
        // Mono specs for the same codecs still build.
        for name in ["PCMU", "PCMA", "G722", "GSM", "L16", "G726-32"] {
            let spec = CodecSpec::new(96, name, 8000, 1, 20);
            assert!(decoder_for(&spec).is_ok(), "{name} mono decoder");
            assert!(encoder_for(&spec).is_ok(), "{name} mono encoder");
        }
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

        let mut mode0 =
            encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20).with_encode_mode(Some(0)))
                .expect("amr-wb encoder");
        assert!(mode0.encode(&pcm, &mut payload).expect("encode") > 0);
        assert_eq!(
            (payload[1] >> 3) & 0x0F,
            0,
            "egress frame is mode 0 (ToC FT=0)"
        );

        let mut default =
            encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("encoder");
        assert!(default.encode(&pcm, &mut payload).expect("encode") > 0);
        assert_eq!(
            (payload[1] >> 3) & 0x0F,
            2,
            "default egress frame is mode 2 (ToC FT=2)"
        );
    }

    #[cfg(feature = "amr")]
    #[test]
    fn amr_nb_decodes_and_encodes_the_wired_modes() {
        // AMR-NB decode is bit-exact for all 8 modes (3GPP TS 26.074). Encode is now bit-exact for
        // every speech mode too, enabling AMR-NB↔G.711 transcode at any negotiated rate.
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
        // No mode-set ⇒ default MR122 encoder; every speech frame type builds: MR475 (FT=0),
        // MR515 (FT=1), MR59 (FT=2), MR67 (FT=3), MR74 (FT=4), MR795 (FT=5), MR102 (FT=6),
        // MR122 (FT=7).
        assert!(encoder_for(&nb).is_ok(), "default AMR-NB encoder (MR122)");
        for (frame_type, name) in [
            (0u8, "MR475"),
            (1, "MR515"),
            (2, "MR59"),
            (3, "MR67"),
            (4, "MR74"),
            (5, "MR795"),
            (6, "MR102"),
            (7, "MR122"),
        ] {
            assert!(
                encoder_for(
                    &CodecSpec::new(97, "AMR", 8000, 1, 20).with_encode_mode(Some(frame_type))
                )
                .is_ok(),
                "{name} encoder builds"
            );
        }
        // A non-speech frame type (e.g. FT=8 / SID) is declined.
        assert!(
            matches!(
                encoder_for(&CodecSpec::new(97, "AMR", 8000, 1, 20).with_encode_mode(Some(8))),
                Err(CodecError::Unsupported(_))
            ),
            "SID/DTX frame type is declined"
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
