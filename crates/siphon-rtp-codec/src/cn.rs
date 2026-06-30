//! Comfort Noise (RFC 3389), RTP payload type 13 (RFC 3551 §4.5.4).
//!
//! Comfort noise is not a waveform codec — it is a **generator**. A CN payload carries a single
//! noise-level byte (the noise level in `-dBov`, RFC 3389 §3.1) optionally followed by spectral
//! information (reflection coefficients). The decoder synthesizes a frame of low-level noise at that
//! level so the listener hears a natural background hiss during a talker's silence (DTX), instead of
//! dead air. The *generation* of CN packets (the encode/DTX side) is a VAD-driven media-path policy,
//! not a per-frame audio encoder, so this type implements [`Decoder`] only.
//!
//! In a transcoding relay, CN arrives as a secondary payload type mid-stream (like RFC 4733
//! telephone-events), so the media path recognizes PT 13 and decodes it through this generator into
//! PCM, which is then re-encoded toward the far leg. That media-path recognition is wired separately.
//!
//! **v1 scope:** the noise level is honoured; the optional spectral (reflection-coefficient) shaping
//! of RFC 3389 §3.2 is parsed-but-not-applied — the generated noise is spectrally flat at the
//! signalled level. Endpoints commonly send level-only CN, and flat noise at the correct level is
//! recognizable comfort noise; LPC shaping is a later refinement.
//!
//! The PRNG is a deterministic xorshift seeded at construction, so the generated noise is
//! reproducible — required for deterministic DSP tests (never an `Instant`-derived seed).

use crate::{CodecError, CodecParams, Decoder};

/// Fixed xorshift seed — comfort noise need not be cryptographically random, only plausible and
/// (for tests) reproducible.
const PRNG_SEED: u32 = 0x2545_F491;

/// √3, the peak/RMS ratio of uniform white noise (used to hit a target RMS from a uniform source).
const SQRT_3: f64 = 1.732_050_807_568_877_2;

/// RFC 3389 comfort-noise generator (decode side).
#[derive(Debug, Clone)]
pub struct Cn {
    params: CodecParams,
    /// xorshift32 state.
    rng: u32,
    /// Last noise level seen (`-dBov`), reused when concealing a lost CN frame.
    last_level: u8,
}

impl Cn {
    /// Create a comfort-noise generator at the given RTP clock / sample rate (8000 for PT 13).
    #[must_use]
    pub fn new(clock_rate_hz: u32, ptime_ms: u8) -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz: clock_rate_hz.max(8000),
                channels: 1,
                ptime_ms: ptime_ms.max(1),
            },
            rng: PRNG_SEED,
            last_level: 70, // a quiet default until the first packet sets the real level
        }
    }

    /// The codec's parameters.
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// Samples generated per frame.
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    /// Next xorshift32 value.
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }

    /// Convert a CN level byte (`-dBov`, RFC 3389 §3.1) to a peak amplitude for uniform white noise.
    fn peak_amplitude(level: u8) -> f64 {
        // RMS relative to full scale: 10^(-level/20) × 32768. Peak of uniform noise = RMS × √3.
        let rms = 32_768.0 * 10f64.powf(-f64::from(level) / 20.0);
        rms * SQRT_3
    }

    /// Fill `out[..count]` with flat white noise at `level` (`-dBov`).
    fn generate(&mut self, level: u8, out: &mut [i16], count: usize) {
        let peak = Self::peak_amplitude(level);
        for sample in out.iter_mut().take(count) {
            // Map the xorshift word to [-1, 1), then scale to the target peak and clamp.
            let normalized = (self.next_u32() as i32 as f64) / (i32::MAX as f64);
            *sample = (normalized * peak).clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16;
        }
    }
}

impl Decoder for Cn {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        let count = self.frame_samples();
        if out.len() < count {
            return Err(CodecError::OutputTooSmall {
                needed: count,
                have: out.len(),
            });
        }
        // RFC 3389 §3.1: the first payload byte is the noise level in -dBov. An empty payload
        // carries no level update (e.g. a keep-alive) — emit a frame of silence rather than guess.
        match payload.first() {
            Some(&level) => {
                self.last_level = level;
                self.generate(level, out, count);
            }
            None => out[..count].fill(0),
        }
        Ok(count)
    }

    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        // A lost CN frame: keep the comfort noise going at the last known level rather than dropping
        // to silence (which would be an audible "hole" in the background hiss).
        let count = self.frame_samples().min(out.len());
        let level = self.last_level;
        self.generate(level, out, count);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: usize = 160; // 20 ms at 8 kHz (PT 13)

    fn rms(samples: &[i16]) -> f64 {
        let sum: f64 = samples.iter().map(|&s| f64::from(s).powi(2)).sum();
        (sum / samples.len() as f64).sqrt()
    }

    /// Decode `frames` CN frames at a fixed level and return the concatenated PCM.
    fn decode_level(level: u8, frames: usize) -> Vec<i16> {
        let mut codec = Cn::new(8000, 20);
        let mut out = Vec::with_capacity(frames * FRAME);
        let mut frame = [0i16; FRAME];
        for _ in 0..frames {
            codec.decode(&[level], &mut frame).expect("decode");
            out.extend_from_slice(&frame);
        }
        out
    }

    #[test]
    fn reports_8k_params() {
        let codec = Cn::new(8000, 20);
        assert_eq!(codec.params().sample_rate_hz, 8000);
        assert_eq!(codec.frame_samples(), FRAME);
    }

    #[test]
    fn generated_rms_tracks_the_signalled_level() {
        // -40 dBov → RMS ≈ 32768 × 10^-2 ≈ 328. Measure over many frames for a stable estimate.
        let pcm = decode_level(40, 50);
        let measured = rms(&pcm);
        let expected = 32_768.0 * 10f64.powf(-40.0 / 20.0);
        assert!(
            (measured / expected) > 0.7 && (measured / expected) < 1.3,
            "RMS {measured:.0} not within 30% of expected {expected:.0}"
        );
    }

    #[test]
    fn louder_level_byte_yields_more_energy() {
        // A smaller -dBov value is a louder noise floor (−30 dBov ≫ −60 dBov).
        let loud = rms(&decode_level(30, 30));
        let quiet = rms(&decode_level(60, 30));
        assert!(
            loud > quiet * 4.0,
            "louder CN level must yield clearly more energy"
        );
    }

    #[test]
    fn empty_payload_is_silence() {
        let mut codec = Cn::new(8000, 20);
        let mut out = [123i16; FRAME];
        assert_eq!(codec.decode(&[], &mut out).expect("decode"), FRAME);
        assert!(out.iter().all(|&s| s == 0));
    }

    #[test]
    fn decode_is_deterministic_for_same_seed_and_level() {
        let a = decode_level(45, 5);
        let b = decode_level(45, 5);
        assert_eq!(a, b, "fixed-seed PRNG ⇒ reproducible comfort noise");
    }

    #[test]
    fn decode_rejects_small_output() {
        let mut codec = Cn::new(8000, 20);
        let mut out = [0i16; 10];
        assert_eq!(
            codec.decode(&[40], &mut out),
            Err(CodecError::OutputTooSmall {
                needed: FRAME,
                have: 10
            })
        );
    }

    #[test]
    fn conceal_continues_noise_at_last_level() {
        let mut codec = Cn::new(8000, 20);
        let mut frame = [0i16; FRAME];
        codec
            .decode(&[35], &mut frame)
            .expect("decode sets last level");
        let mut concealed = [0i16; FRAME];
        assert_eq!(codec.conceal(&mut concealed).expect("conceal"), FRAME);
        // Concealment keeps the hiss going (not silence) at roughly the established level.
        let level_35 = 32_768.0 * 10f64.powf(-35.0 / 20.0);
        let measured = rms(&concealed);
        assert!(
            measured > level_35 * 0.4,
            "conceal should keep comfort noise audible"
        );
    }
}
