//! Pure-Rust audio codecs for siphon-rtp — zero C dependencies.
//!
//! IMS/VoLTE first: **G.711** (PSTN interconnect) and **AMR-NB/AMR-WB** (VoLTE), pure-Rust and
//! bit-exact against the 3GPP reference, with a strong focus on per-frame performance.
//! G.722, Opus, and EVS follow on the same [`Decoder`]/[`Encoder`] trait.
//!
//! ## Hot-path contract
//! Codecs operate one frame at a time into **caller-owned output buffers** — there is no
//! per-frame heap allocation. Decoders carry adaptive state (`&mut self`) and expose
//! packet-loss concealment ([`Decoder::conceal`]) as a first-class operation.

// AMR-NB/AMR-WB transcoding is patent-encumbered (3GPP pool) — gated behind the off-by-default
// `amr` feature. Passthrough/relay of AMR is unaffected (it never builds a codec). See
// `docs/codec-licensing.md` and the `[features]` section of Cargo.toml.
#[cfg(feature = "amr")]
pub mod amr;
pub mod cn;
pub mod factory;
pub mod g711;
pub mod g722;
pub mod g726;
pub mod gsm_fr;
pub mod l16;
pub mod opus;

/// Codec configuration: native sample rate, channel count, and packetization time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecParams {
    /// Native sample rate in Hz (e.g. 8000 for G.711, 16000 for AMR-WB).
    pub sample_rate_hz: u32,
    /// Channel count (mono = 1 for all telephony codecs).
    pub channels: u8,
    /// Packetization time in milliseconds (e.g. 20).
    pub ptime_ms: u8,
}

impl CodecParams {
    /// Number of PCM samples in one packetization interval at the native rate (mono).
    #[must_use]
    pub const fn frame_samples(&self) -> usize {
        (self.sample_rate_hz as usize / 1000) * self.ptime_ms as usize
    }
}

/// Decodes codec payloads into linear 16-bit PCM.
pub trait Decoder: Send {
    /// The codec's native parameters.
    fn params(&self) -> CodecParams;

    /// Samples produced by one nominal frame at the native rate.
    fn frame_samples(&self) -> usize;

    /// Decode one payload into `out`, returning the number of samples written.
    ///
    /// `out` must be at least [`Decoder::frame_samples`] long (codec-dependent; G.711 needs
    /// `payload.len()`). Errors instead of panicking on a too-small buffer or bad payload.
    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError>;

    /// Synthesize one concealment frame for a lost packet, returning samples written.
    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError>;

    /// The RTP timestamp clock for this codec's **inbound** stream, in Hz (RFC 3551 §4.5) — the rate
    /// inbound RTP timestamps advance, which the RTCP interarrival-jitter estimate is measured in
    /// (RFC 3550 §6.4.1). Defaults to the native sample rate; G.722 overrides it to 8 kHz (it clocks
    /// RTP at 8 kHz while sampling 16 kHz, RFC 3551 §4.5.2), mirroring [`Encoder::rtp_clock_rate_hz`].
    fn rtp_clock_rate_hz(&self) -> u32 {
        self.params().sample_rate_hz
    }

    /// The Codec Mode Request (CMR) carried by the most recently decoded payload, for a variable-rate
    /// codec that signals one (RFC 4867 §4.3.1 AMR / AMR-WB): `Some(mode)` when the peer requested a
    /// specific speech mode, `None` for "no request" (CMR = 15) or a codec with no CMR. Per RFC 4867
    /// the request applies to the media sent back *towards* this decoder's peer, so the media path
    /// feeds it to the **opposite** direction's [`Encoder::request_mode`]. Default `None` (fixed-rate
    /// codecs carry no CMR).
    fn last_mode_request(&self) -> Option<u8> {
        None
    }
}

/// Encodes linear 16-bit PCM into codec payloads.
pub trait Encoder: Send {
    /// The codec's native parameters.
    fn params(&self) -> CodecParams;

    /// Samples consumed by one nominal frame at the native rate.
    fn frame_samples(&self) -> usize;

    /// Encode one PCM frame into `out`, returning the number of bytes written.
    ///
    /// Errors instead of panicking on a too-small output buffer or wrong input length.
    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError>;

    /// The RTP timestamp clock for this codec, in Hz (RFC 3551 §4.5). Defaults to the native sample
    /// rate, which is correct for every telephony codec **except G.722**: it samples 16 kHz audio
    /// but, for historical reasons, clocks its RTP timestamps at 8 kHz (RFC 3551 §4.5.2), so the
    /// G.722 codec overrides this. The synthesized-egress timestamp step is derived from this rate,
    /// not from the (possibly different) native sample rate.
    fn rtp_clock_rate_hz(&self) -> u32 {
        self.params().sample_rate_hz
    }

    /// Whether this encoder is **stateless** — each frame encodes independently of prior frames, so
    /// encoding identical PCM always yields identical bytes (G.711, L16). The conference mixer's
    /// shared-encode path relies on this: it encodes the common listener mix **once** and fans the
    /// payload out to every listener on that codec. Stateful codecs (ADPCM, ACELP) must override to
    /// keep `false` — sharing their output across legs with divergent histories would corrupt it.
    fn is_stateless(&self) -> bool {
        false
    }

    /// Request the egress speech mode for subsequent frames (RFC 4867 §4.3.1 Codec Mode Request).
    /// A variable-rate codec (AMR / AMR-WB) switches to `mode`, clamped into the modes its SDP
    /// `mode-set` permits so it never emits a disallowed mode; the request is sticky until the next
    /// one. Default no-op — a fixed-rate codec has a single mode and ignores it.
    fn request_mode(&mut self, _mode: u8) {}
}

/// Errors produced by codecs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Input frame had an unexpected sample count.
    #[error("bad frame size: expected {expected} samples, got {got}")]
    BadFrameSize { expected: usize, got: usize },

    /// The caller-provided output buffer is too small.
    #[error("output buffer too small: need {needed}, have {have}")]
    OutputTooSmall { needed: usize, have: usize },

    /// The payload was malformed or truncated.
    #[error("malformed payload: {0}")]
    Malformed(&'static str),

    /// The requested codec/mode is not yet implemented.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}
