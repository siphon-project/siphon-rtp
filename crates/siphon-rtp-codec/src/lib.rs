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
//!
//! ## Channel contract (multi-channel PCM)
//!
//! Every telephony codec here is mono, but Opus is not (RFC 7587 §6.1 signals mono or stereo through
//! the `stereo` / `sprop-stereo` fmtp parameters), so the trait boundary fixes the layout **once**:
//!
//! - **PCM is interleaved.** A multi-channel frame is `L, R, L, R, …` — channel-major within a
//!   sample instant, never planar. This is the layout `opus_decode` produces and the layout
//!   RIFF/WAVE stores, so no repacking happens at either edge.
//! - [`CodecParams::frame_samples`] is the frame length in **samples per channel** (i.e. in time);
//!   [`CodecParams::frame_values`] is the **`i16` count of one interleaved frame**
//!   (`frame_samples × channels`). A decode output buffer is sized by `frame_values`, a duration or
//!   RTP-timestamp step by `frame_samples`. Mixing the two up is the whole reason both exist.
//! - [`Decoder::frame_samples`] / [`Encoder::frame_samples`] are the buffer contract, so they are
//!   **interleaved `i16` counts** (they equal `params().frame_values()`, and for every mono codec
//!   that is the same number as the per-channel count).
//! - The engine's media path is mono end to end (mixer, resampler, jitter, AEC/NS, RTP timestamp
//!   arithmetic). It therefore folds a multi-channel decoded frame down at the trait boundary with
//!   [`downmix_to_mono`] and stays mono downstream — driven by `params().channels`, never by a
//!   per-codec special case — and declares `stereo=0` / `sprop-stereo=0` on its own SDP so a peer
//!   never sends or expects stereo (RFC 7587 §7.1: both are unidirectional and declarative).

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
    /// Channel count: 1 for every telephony codec; 2 for a stereo Opus stream (RFC 7587 §6.1). PCM
    /// carrying more than one channel is **interleaved** — see the crate-level channel contract.
    pub channels: u8,
    /// Packetization time in milliseconds (e.g. 20).
    pub ptime_ms: u8,
}

impl CodecParams {
    /// PCM samples **per channel** in one packetization interval at the native rate — the frame
    /// length in time. Multiply by [`Self::channels`] ([`Self::frame_values`]) for the buffer size.
    #[must_use]
    pub const fn frame_samples(&self) -> usize {
        (self.sample_rate_hz as usize / 1000) * self.ptime_ms as usize
    }

    /// `i16` count of one **interleaved** frame — `frame_samples × channels`, the size a decode
    /// output buffer (or an encode input buffer) must have. Identical to [`Self::frame_samples`] for
    /// every mono codec; the two diverge only for a stereo Opus stream. A `channels` of 0 is read as
    /// mono (the same clamp [`crate::factory::CodecSpec::new`] applies).
    #[must_use]
    pub const fn frame_values(&self) -> usize {
        let channels = if self.channels == 0 {
            1
        } else {
            self.channels as usize
        };
        self.frame_samples() * channels
    }
}

/// Fold an **interleaved** multi-channel PCM frame down to mono, in place, returning the mono sample
/// count (`frame.len() / channels`). The mono sample is the arithmetic mean of the channels at that
/// instant, which cannot overflow `i16` (a mean of `i16`s is an `i16`), so no saturation is needed.
///
/// This is the engine's boundary between a multi-channel codec and its mono media path (mixer,
/// resampler, jitter buffer, AEC/NS, RTP timestamp arithmetic): a decoded frame is folded here, right
/// after [`Decoder::decode`], and everything downstream stays mono. It is driven by
/// [`CodecParams::channels`] rather than by the codec's identity, so it applies to any future
/// multi-channel codec without a special case.
///
/// `channels <= 1` is a no-op returning `frame.len()`. A trailing partial group (a truncated frame)
/// is dropped rather than folded against zeroes, so the returned count only covers whole instants.
#[must_use]
pub fn downmix_to_mono(frame: &mut [i16], channels: u8) -> usize {
    if channels <= 1 {
        return frame.len();
    }
    let channels = channels as usize;
    let samples = frame.len() / channels;
    for sample in 0..samples {
        let base = sample * channels;
        let mut sum = 0i32;
        for offset in 0..channels {
            sum += i32::from(frame[base + offset]);
        }
        frame[sample] = (sum / channels as i32) as i16;
    }
    samples
}

/// Decodes codec payloads into linear 16-bit PCM.
pub trait Decoder: Send {
    /// The codec's native parameters.
    fn params(&self) -> CodecParams;

    /// `i16` values one nominal frame produces at the native rate — the **interleaved** count
    /// (`params().frame_values()`), so it is directly a buffer size. Equal to the per-channel sample
    /// count for every mono codec; see the crate-level channel contract.
    fn frame_samples(&self) -> usize;

    /// Decode one payload into `out`, returning the number of `i16` values written (interleaved
    /// across channels — the crate-level channel contract).
    ///
    /// `out` must be at least [`Decoder::frame_samples`] long (codec-dependent; G.711 needs
    /// `payload.len()`). Errors instead of panicking on a too-small buffer or bad payload.
    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError>;

    /// Synthesize one concealment frame for a lost packet, returning `i16` values written (same
    /// interleaved layout and count as [`Decoder::decode`]).
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

    /// `i16` values one nominal frame consumes at the native rate — the **interleaved** count
    /// (`params().frame_values()`), so it is directly the length of the `pcm` slice
    /// [`Encoder::encode`] expects. Equal to the per-channel sample count for every mono codec.
    fn frame_samples(&self) -> usize;

    /// Encode one PCM frame into `out`, returning the number of bytes written. `pcm` is
    /// **interleaved** across channels (the crate-level channel contract).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn params(sample_rate_hz: u32, channels: u8, ptime_ms: u8) -> CodecParams {
        CodecParams {
            sample_rate_hz,
            channels,
            ptime_ms,
        }
    }

    #[test]
    fn frame_samples_is_per_channel_and_frame_values_is_interleaved() {
        // Mono telephony: the two are the same number (8 kHz × 20 ms = 160).
        let mono = params(8000, 1, 20);
        assert_eq!(mono.frame_samples(), 160);
        assert_eq!(mono.frame_values(), 160);
        // Stereo 48 kHz Opus, 20 ms: 960 samples per channel, 1920 interleaved i16 values.
        let stereo = params(48_000, 2, 20);
        assert_eq!(stereo.frame_samples(), 960);
        assert_eq!(stereo.frame_values(), 1920);
    }

    #[test]
    fn frame_values_reads_zero_channels_as_mono() {
        // A malformed `channels` must not collapse the buffer size to 0 (that would size a decode
        // buffer at zero and fail every frame); it is read as mono, like `CodecSpec::new`'s clamp.
        assert_eq!(params(16_000, 0, 20).frame_values(), 320);
    }

    #[test]
    fn frame_values_covers_the_opus_maximum_frame() {
        // RFC 7587 §6.1 caps ptime/maxptime at 120 ms; RFC 6716 §3.2 code-3 packets carry up to
        // 120 ms of audio regardless. Full-band stereo: 48 kHz × 120 ms × 2 = 11520 i16 values.
        assert_eq!(params(48_000, 2, 120).frame_samples(), 5760);
        assert_eq!(params(48_000, 2, 120).frame_values(), 11_520);
    }

    #[test]
    fn downmix_folds_interleaved_stereo_to_the_channel_mean() {
        // L, R pairs → the arithmetic mean of each instant, written back over the frame head.
        let mut frame = [100i16, 200, -300, -100, 32_767, 32_767, -32_768, -32_768];
        assert_eq!(downmix_to_mono(&mut frame, 2), 4);
        assert_eq!(&frame[..4], &[150i16, -200, 32_767, -32_768]);
    }

    #[test]
    fn downmix_is_a_no_op_for_mono_and_degenerate_channel_counts() {
        let mut frame = [1i16, 2, 3];
        assert_eq!(downmix_to_mono(&mut frame, 1), 3);
        assert_eq!(frame, [1, 2, 3], "mono frame is untouched");
        assert_eq!(downmix_to_mono(&mut frame, 0), 3);
        assert_eq!(frame, [1, 2, 3], "a 0 channel count is read as mono");
    }

    #[test]
    fn downmix_drops_a_trailing_partial_instant_and_handles_an_empty_frame() {
        // A truncated frame (5 values, 2 channels) folds 2 whole instants; the orphan value is not
        // folded against an imaginary zero (which would emit a half-amplitude click).
        let mut frame = [10i16, 20, 30, 40, 50];
        assert_eq!(downmix_to_mono(&mut frame, 2), 2);
        assert_eq!(&frame[..2], &[15i16, 35]);
        let mut empty: [i16; 0] = [];
        assert_eq!(downmix_to_mono(&mut empty, 2), 0);
    }

    #[test]
    fn downmix_folds_three_channels() {
        // The fold is channel-count generic, not a stereo special case.
        let mut frame = [3i16, 6, 9, -3, -6, -9];
        assert_eq!(downmix_to_mono(&mut frame, 3), 2);
        assert_eq!(&frame[..2], &[6i16, -6]);
    }
}
