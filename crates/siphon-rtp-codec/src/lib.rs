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

pub mod amr;
pub mod g711;
pub mod l16;

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
