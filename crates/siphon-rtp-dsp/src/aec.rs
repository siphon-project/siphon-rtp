//! Acoustic echo cancellation — a fixed-delay, time-domain **NLMS** adaptive filter (the first,
//! correctness-anchored slice of the AEC; the frequency-domain partitioned filter, GCC-PHAT delay
//! estimation, and the residual-echo suppressor build on this).
//!
//! The canceller models the echo path from the far-end **reference** (what we played toward the
//! near party) to the **near-end** microphone signal (near speech + echo), and subtracts its
//! estimate so the residual carries only the near speech. Adaptation is the normalized
//! least-mean-squares update (Haykin, *Adaptive Filter Theory*): scale-invariant, stable for a step
//! size in `(0, 2)`. A **Geigel** double-talk detector freezes adaptation while the near talker is
//! active, so the filter never diverges by trying to model the near speech (Duttweiler 1978).
//!
//! Pure, safe Rust (`#![forbid(unsafe_code)]` at the crate root; the SIMD dot lives in
//! `siphon-rtp-simd`), **deterministic** (no clock, no randomness — it golden-tests against a
//! synthetic room impulse response by ERLE), and **zero per-frame heap**: every buffer is sized once
//! in [`EchoCanceller::new`] and [`cancel`](EchoCanceller::cancel) mutates in place. i16 in, i16 out,
//! caller-owned 20 ms frames, exactly like the codec boundary.

use siphon_rtp_simd::fir_dot_f32;

/// i16 full-scale — samples are processed internally in `[-1, 1)` so the NLMS numerics (and the
/// regularization floor) are independent of the codec's integer scale.
const SAMPLE_SCALE: f32 = 32768.0;

/// Errors constructing an [`EchoCanceller`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AecError {
    /// The sample rate was zero.
    #[error("sample rate must be non-zero")]
    ZeroRate,
    /// The adaptive-filter tail length was zero (it must span at least one tap).
    #[error("adaptive-filter tail length must be non-zero")]
    ZeroTail,
}

/// A time-domain NLMS echo canceller with a Geigel double-talk freeze.
#[derive(Debug, Clone)]
pub struct EchoCanceller {
    sample_rate_hz: u32,
    /// Number of adaptive-filter taps (the modelled echo tail, in samples).
    tail: usize,
    /// The adaptive filter, aligned oldest-first with [`reference_line`](Self::reference_line): tap
    /// `j` multiplies `reference_line[j]`. Converges to (a time-reversed image of) the echo path.
    weights: Vec<f32>,
    /// The last `tail` **reference** samples, oldest-first, normalized to `[-1, 1)` — the filter's
    /// delay line. Preallocated; slid by one each sample (a bounded `copy_within`, no allocation).
    reference_line: Vec<f32>,
    /// NLMS step size `mu` (0 < mu < 2). Larger converges faster but with more misadjustment.
    step_size: f32,
    /// NLMS regularization `delta` — the denominator floor that keeps the update finite when the
    /// reference is (near-)silent.
    regularization: f32,
    /// Geigel double-talk threshold: adaptation freezes for a sample whose near-end magnitude reaches
    /// `threshold * max|reference|` over the current block (Duttweiler 1978, classic value 0.5 for a
    /// ~6 dB echo-return loss). Below it, only echo is assumed present, so the filter adapts.
    geigel_threshold: f32,
}

impl EchoCanceller {
    /// A canceller for `sample_rate_hz` audio with a `tail_samples`-tap adaptive filter (the modelled
    /// echo length — e.g. 128 taps = 16 ms at 8 kHz). Weights start at zero; the filter adapts from
    /// the first frame.
    pub fn new(sample_rate_hz: u32, tail_samples: usize) -> Result<Self, AecError> {
        if sample_rate_hz == 0 {
            return Err(AecError::ZeroRate);
        }
        if tail_samples == 0 {
            return Err(AecError::ZeroTail);
        }
        Ok(Self {
            sample_rate_hz,
            tail: tail_samples,
            weights: vec![0.0; tail_samples],
            reference_line: vec![0.0; tail_samples],
            step_size: 0.5,
            regularization: 1.0e-6,
            geigel_threshold: 0.5,
        })
    }

    /// Override the NLMS step size `mu` (default 0.5). Clamped to `(0, 2)` for stability.
    #[must_use]
    pub fn with_step_size(mut self, step_size: f32) -> Self {
        self.step_size = step_size.clamp(f32::MIN_POSITIVE, 2.0);
        self
    }

    /// Override the Geigel double-talk threshold (default 0.5). A larger value freezes less often
    /// (assumes more echo-return loss); `0` disables the freeze.
    #[must_use]
    pub fn with_geigel_threshold(mut self, threshold: f32) -> Self {
        self.geigel_threshold = threshold.max(0.0);
        self
    }

    /// The configured sample rate (Hz).
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// The adaptive-filter tail length (taps).
    #[must_use]
    pub fn tail(&self) -> usize {
        self.tail
    }

    /// The current adaptive-filter coefficients (oldest-first). Exposed for diagnostics and tests
    /// (e.g. asserting the filter did not drift through a double-talk burst).
    #[must_use]
    pub fn coefficients(&self) -> &[f32] {
        &self.weights
    }

    /// Cancel the echo of `reference` out of `near_end`, **in place**. `near_end` and `reference` are
    /// time-aligned equal-length blocks (one 20 ms frame); if their lengths differ, the overlap is
    /// processed and the rest of `near_end` is left untouched (never panics). Each output sample is
    /// the residual `d − ŷ` (near speech with the echo removed).
    pub fn cancel(&mut self, near_end: &mut [i16], reference: &[i16]) {
        let len = near_end.len().min(reference.len());
        // Geigel far-end level: the loudest reference magnitude in this block (normalized). O(N) once
        // per block, so the per-sample double-talk test is O(1).
        let far_level = reference[..len]
            .iter()
            .map(|&sample| (f32::from(sample) / SAMPLE_SCALE).abs())
            .fold(0.0f32, f32::max);
        let double_talk_floor = self.geigel_threshold * far_level;

        for index in 0..len {
            let reference_sample = f32::from(reference[index]) / SAMPLE_SCALE;
            let near_sample = f32::from(near_end[index]) / SAMPLE_SCALE;

            // Slide the new reference sample into the oldest-first delay line (newest at the end).
            self.reference_line.copy_within(1.., 0);
            self.reference_line[self.tail - 1] = reference_sample;

            // Estimate the echo and form the residual.
            let echo_estimate = fir_dot_f32(&self.reference_line, &self.weights);
            let residual = near_sample - echo_estimate;

            // NLMS weight update, frozen while the near talker dominates (Geigel double-talk).
            if near_sample.abs() < double_talk_floor || self.geigel_threshold == 0.0 {
                let energy = fir_dot_f32(&self.reference_line, &self.reference_line);
                let step = self.step_size * residual / (energy + self.regularization);
                for (weight, &sample) in self.weights.iter_mut().zip(self.reference_line.iter()) {
                    *weight += step * sample;
                }
            }

            near_end[index] = to_i16(residual * SAMPLE_SCALE);
        }
    }

    /// Reset the filter to its initial state (zero weights, empty delay line) — e.g. on a codec/route
    /// change where the echo path is no longer the one the filter learned.
    pub fn reset(&mut self) {
        self.weights.iter_mut().for_each(|weight| *weight = 0.0);
        self.reference_line
            .iter_mut()
            .for_each(|sample| *sample = 0.0);
    }
}

/// Round a processed `f32` sample back to i16, saturating at full scale (RFC-agnostic clamp).
fn to_i16(value: f32) -> i16 {
    value
        .round()
        .clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic white noise in `[-1, 1)` via xorshift64 (fixed seed — no `rand`, no clock).
    fn white_noise(len: usize, seed: u64) -> Vec<f32> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                // Top 24 bits → [0, 2) → [-1, 1).
                (state >> 40) as f32 / (1u32 << 23) as f32 - 1.0
            })
            .collect()
    }

    /// A synthetic room impulse response: `delay` leading zeros (bulk delay), then a pseudo-random
    /// sign sequence with exponential decay, L2-normalized to a modest echo-path gain. Deterministic.
    fn synthetic_rir(len: usize, delay: usize) -> Vec<f32> {
        let mut rir = vec![0.0f32; len];
        let mut state = 0xBEEFu64 | 1;
        for (tap, coefficient) in rir.iter_mut().enumerate().skip(delay) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let sign = if state & 1 == 0 { 1.0 } else { -1.0 };
            let decay = (-((tap - delay) as f32) / 12.0).exp();
            *coefficient = sign * decay;
        }
        let norm: f32 = rir
            .iter()
            .map(|coefficient| coefficient * coefficient)
            .sum::<f32>()
            .sqrt();
        if norm > 0.0 {
            // Echo-path gain 0.5 → with a -12 dBov reference the echo lands ~-18 dBov, well above the
            // i16 quantization floor so the ERLE headroom is the filter's, not the codec's.
            for coefficient in rir.iter_mut() {
                *coefficient *= 0.5 / norm;
            }
        }
        rir
    }

    /// `echo[n] = Σ_k rir[k]·reference[n−k]` — the synthetic microphone echo.
    fn convolve(reference: &[f32], rir: &[f32]) -> Vec<f32> {
        let mut echo = vec![0.0f32; reference.len()];
        for sample_index in 0..reference.len() {
            let mut accumulator = 0.0f32;
            for (tap_index, &coefficient) in rir.iter().enumerate() {
                if sample_index >= tap_index {
                    accumulator += coefficient * reference[sample_index - tap_index];
                }
            }
            echo[sample_index] = accumulator;
        }
        echo
    }

    fn to_pcm(signal: &[f32], gain: f32) -> Vec<i16> {
        signal
            .iter()
            .map(|&sample| to_i16(sample * gain * SAMPLE_SCALE))
            .collect()
    }

    /// Echo-return loss enhancement over two aligned signals: `10·log10(E[echo²]/E[residual²])`.
    fn erle_db(echo: &[i16], residual: &[i16]) -> f32 {
        let echo_energy: f64 = echo.iter().map(|&sample| f64::from(sample).powi(2)).sum();
        let residual_energy: f64 = residual
            .iter()
            .map(|&sample| f64::from(sample).powi(2))
            .sum::<f64>()
            .max(1.0);
        (10.0 * (echo_energy / residual_energy).log10()) as f32
    }

    const FRAME: usize = 160; // 20 ms @ 8 kHz

    #[test]
    fn rejects_zero_rate_and_zero_tail() {
        assert_eq!(EchoCanceller::new(0, 128).err(), Some(AecError::ZeroRate));
        assert_eq!(EchoCanceller::new(8000, 0).err(), Some(AecError::ZeroTail));
        assert!(EchoCanceller::new(8000, 128).is_ok());
    }

    #[test]
    fn converges_and_cancels_synthetic_echo() {
        let reference = white_noise(8000, 0x1234_5678);
        let echo = convolve(&reference, &synthetic_rir(64, 0));
        let reference_pcm = to_pcm(&reference, 0.25); // -12 dBov reference
        let echo_pcm = to_pcm(&echo, 0.25);

        let mut canceller = EchoCanceller::new(8000, 128).expect("build");
        let mut residual_tail = Vec::new();
        let mut echo_tail = Vec::new();
        let warmup_frames = 25; // ~4000 samples for a 128-tap filter to converge
        for (frame_index, (near_frame, reference_frame)) in echo_pcm
            .chunks(FRAME)
            .zip(reference_pcm.chunks(FRAME))
            .enumerate()
        {
            let mut near = near_frame.to_vec();
            canceller.cancel(&mut near, reference_frame);
            if frame_index >= warmup_frames {
                residual_tail.extend_from_slice(&near);
                echo_tail.extend_from_slice(near_frame);
            }
        }
        let erle = erle_db(&echo_tail, &residual_tail);
        assert!(
            erle >= 25.0,
            "converged ERLE was {erle:.1} dB (expected ≥ 25)"
        );
    }

    #[test]
    fn covers_a_bulk_delay_within_the_tail() {
        // The echo path is delayed by 32 samples; a 128-tap fixed-delay filter still spans it.
        let reference = white_noise(8000, 0x0f0f_0f0f);
        let echo = convolve(&reference, &synthetic_rir(96, 32));
        let reference_pcm = to_pcm(&reference, 0.25);
        let echo_pcm = to_pcm(&echo, 0.25);

        let mut canceller = EchoCanceller::new(8000, 128).expect("build");
        let mut residual_tail = Vec::new();
        let mut echo_tail = Vec::new();
        for (frame_index, (near_frame, reference_frame)) in echo_pcm
            .chunks(FRAME)
            .zip(reference_pcm.chunks(FRAME))
            .enumerate()
        {
            let mut near = near_frame.to_vec();
            canceller.cancel(&mut near, reference_frame);
            if frame_index >= 30 {
                residual_tail.extend_from_slice(&near);
                echo_tail.extend_from_slice(near_frame);
            }
        }
        let erle = erle_db(&echo_tail, &residual_tail);
        assert!(
            erle >= 20.0,
            "delayed-path ERLE was {erle:.1} dB (expected ≥ 20)"
        );
    }

    #[test]
    fn double_talk_does_not_diverge_the_filter() {
        // Converge on echo-only, then drive a loud near-end burst (double-talk). The Geigel freeze
        // must keep the filter from adapting toward the near speech, so ERLE survives afterwards.
        let reference = white_noise(12_000, 0xabcd_ef01);
        let rir = synthetic_rir(64, 0);
        let echo = convolve(&reference, &rir);
        let reference_pcm = to_pcm(&reference, 0.25);
        let echo_pcm = to_pcm(&echo, 0.25);
        // Near-end speech present only in the middle third (frames 25..50), louder than the echo.
        let near_speech = white_noise(12_000, 0x5555_aaaa);

        let mut canceller = EchoCanceller::new(8000, 128).expect("build");
        let mut coefficients_before_double_talk = Vec::new();
        let mut post_residual = Vec::new();
        let mut post_echo = Vec::new();
        for (frame_index, (echo_frame, reference_frame)) in echo_pcm
            .chunks(FRAME)
            .zip(reference_pcm.chunks(FRAME))
            .enumerate()
        {
            // Build the microphone frame: echo always, plus near speech during the double-talk window.
            let mut near: Vec<i16> = echo_frame.to_vec();
            let double_talk = (25..50).contains(&frame_index);
            if double_talk {
                let base = frame_index * FRAME;
                for (offset, sample) in near.iter_mut().enumerate() {
                    let speech = to_i16(near_speech[base + offset] * 0.5 * SAMPLE_SCALE);
                    *sample = sample.saturating_add(speech);
                }
            }
            if frame_index == 25 {
                coefficients_before_double_talk = canceller.coefficients().to_vec();
            }
            canceller.cancel(&mut near, reference_frame);
            // Measure ERLE on the echo-only tail *after* the double-talk window.
            if frame_index >= 55 {
                post_residual.extend_from_slice(&near);
                post_echo.extend_from_slice(echo_frame);
            }
        }

        // The filter barely moved through the double-talk burst (DTD froze adaptation).
        let coefficients_after = canceller.coefficients();
        let drift: f32 = coefficients_before_double_talk
            .iter()
            .zip(coefficients_after)
            .map(|(before, after)| (before - after).powi(2))
            .sum();
        let magnitude: f32 = coefficients_before_double_talk.iter().map(|c| c * c).sum();
        assert!(
            drift <= 0.05 * magnitude,
            "filter drifted through double-talk (drift {drift:.4} vs magnitude {magnitude:.4})"
        );
        // And echo cancellation still holds afterwards.
        let erle = erle_db(&post_echo, &post_residual);
        assert!(
            erle >= 20.0,
            "post-double-talk ERLE was {erle:.1} dB (expected ≥ 20)"
        );
    }

    #[test]
    fn reset_restores_the_initial_state() {
        let reference = white_noise(2000, 7);
        let echo = convolve(&reference, &synthetic_rir(64, 0));
        let reference_pcm = to_pcm(&reference, 0.25);
        let echo_pcm = to_pcm(&echo, 0.25);
        let mut canceller = EchoCanceller::new(8000, 128).expect("build");
        for (near_frame, reference_frame) in echo_pcm.chunks(FRAME).zip(reference_pcm.chunks(FRAME))
        {
            let mut near = near_frame.to_vec();
            canceller.cancel(&mut near, reference_frame);
        }
        assert!(
            canceller.coefficients().iter().any(|&c| c != 0.0),
            "filter adapted"
        );
        canceller.reset();
        assert!(
            canceller.coefficients().iter().all(|&c| c == 0.0),
            "reset zeroed the filter"
        );
    }

    #[test]
    fn mismatched_block_lengths_never_panic() {
        let mut canceller = EchoCanceller::new(8000, 64).expect("build");
        let mut near = vec![100i16; 100];
        canceller.cancel(&mut near, &[10i16; 40]); // shorter reference
        canceller.cancel(&mut near, &[10i16; 200]); // longer reference
    }
}
