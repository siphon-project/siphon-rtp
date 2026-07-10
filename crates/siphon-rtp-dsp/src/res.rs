//! Residual-echo suppressor (RES): a spectral post-filter that runs **after** the linear echo
//! canceller on its residual, knocking down the nonlinear / under-modelled echo the adaptive filter
//! cannot remove.
//!
//! ## Why a post-filter at all
//!
//! A linear adaptive filter (NLMS or MDF, [`crate::aec`]) can only cancel the part of the echo that
//! is a *linear* function of the far-end reference within its tail. Loudspeaker/amplifier
//! nonlinearity, and any echo-path energy beyond the modelled tail, survive as a **residual echo** in
//! `e = near − echo_estimate`. The RES attenuates that residual with a per-bin spectral gain — the
//! same decision-directed Wiener machinery the noise suppressor uses, but with the interference PSD
//! set to an estimate of the residual-echo power instead of the noise PSD (hence the shared
//! `DecisionDirectedWiener` per-bin gain and the shared √Hann WOLA framing, reused from [`crate::ns`]).
//!
//! ## Residual-echo PSD estimate (adaptive per-bin leakage)
//!
//! The residual-echo power in each bin is modelled as an adaptively-tracked fraction of the linear
//! **echo estimate** `y_echo = near − e` (the part the linear filter *did* remove):
//!
//! ```text
//!   S̄_e[b] = λ·S̄_e[b] + (1−λ)·|E[b]|²                (smoothed residual power)
//!   S̄_y[b] = λ·S̄_y[b] + (1−λ)·|Y_echo[b]|²           (smoothed echo-estimate power)
//!   η[b]  ← (1−ρ)·η[b] + ρ·min(S̄_e[b]/S̄_y[b], η_max)  (per-bin leakage, frozen in double-talk)
//!   S_echo[b] = β · η[b] · |Y_echo[b]|²                (residual-echo PSD this hop)
//! ```
//!
//! Using the echo *estimate* as the predictor (rather than the raw far-end reference) is what makes
//! the RES backend- and delay-agnostic: `Y_echo` and `E` are both taken at the near-end time index
//! (the canceller hands the RES a frame-synchronous pair), so no reference alignment is needed and
//! `η[b]` is a clean per-bin *residual-to-cancelled* ratio. In echo-only single-talk the smoothed
//! ratio converges to the true leakage; a near-end talker would inflate `|E|²` and corrupt it, so the
//! leakage update is **frozen** while the canceller's double-talk detector flags near-end presence
//! (`|Y_echo|²` below a floor — no echo — also freezes it). `β ≥ 1` is an over-subtraction knob.
//!
//! ## Suppression gain and near-end protection
//!
//! The interference PSD `S_echo` drives the shared decision-directed Wiener gain
//! `G[b] = ξ/(1+ξ)` with a spectral floor, so during echo-only the gain collapses toward the floor
//! (residual echo attenuated) while during near-end/double-talk `|E|²` dominates `S_echo` and the
//! gain returns to ≈ 1 (near-end preserved). As a belt-and-braces guard the gain is additionally
//! floored **up** to a high value while double-talk is flagged, so the RES can never chew the
//! near-end talker.
//!
//! ## Determinism, latency & allocation
//!
//! No wall clock, no randomness — identical inputs give identical output, so it golden-tests without
//! audio hardware on a logical sample-clock. Every buffer (both WOLA rings, the FFT scratch, the
//! per-bin leakage / smoothing / gain state, and the per-hop echo-power queue) is preallocated in
//! [`ResidualEchoSuppressor::new`]; [`ResidualEchoSuppressor::process`] does **zero per-frame heap
//! allocation**. The √Hann WOLA adds a constant `N`-sample algorithmic delay
//! ([`ResidualEchoSuppressor::latency_samples`]) on top of the linear canceller's own latency.

use crate::fft::Complex;
use crate::spectral::DecisionDirectedWiener;
use crate::window::{WolaAnalyzer, WolaProcessor};
use crate::DspError;

/// i16 full-scale: the residual is processed in normalized `f32` in `[-1, 1)`, matching the echo
/// canceller's [`crate::aec`] scale so the echo-estimate frame the canceller hands over needs no
/// rescaling.
const SAMPLE_SCALE: f32 = 32_768.0;

/// 8 kHz narrowband: 20 ms frame / FFT size / hop (matches [`crate::ns`]).
const NB_FRAME: usize = 160;
const NB_FFT: usize = 256;
/// 16 kHz wideband: 20 ms frame / FFT size / hop.
const WB_FRAME: usize = 320;
const WB_FFT: usize = 512;

/// A single-channel residual-echo suppressor over the √Hann WOLA STFT.
#[derive(Clone, Debug)]
pub struct ResidualEchoSuppressor {
    sample_rate_hz: u32,
    frame_len: usize,
    hop: usize,
    bins: usize,
    /// The residual WOLA framing (analysis → gain → synthesis; produces the emitted output).
    residual_wola: WolaProcessor,
    /// The echo-estimate analysis framing (analysis only; hop-locked to `residual_wola`).
    echo_analyzer: WolaAnalyzer,
    /// Per-bin leakage + decision-directed Wiener gain state.
    state: ResidualEchoState,
    /// Preallocated `i16 → f32` residual input scratch (length `frame_len`).
    residual_in: Vec<f32>,
    /// Preallocated `f32 → i16` residual output scratch (length `frame_len`).
    residual_out: Vec<f32>,
    /// Per-hop echo-power queue: `|Y_echo[b]|²` for each hop of the current frame, hop-major
    /// (`[hop · bins + b]`). Filled by the echo analysis pass, drained by the residual gain pass.
    echo_power: Vec<f32>,
    /// Valid entries currently staged in [`Self::echo_power`] (a multiple of `bins`).
    echo_power_len: usize,
}

impl ResidualEchoSuppressor {
    /// Build a residual-echo suppressor for the given native sample rate (8000 or 16000 Hz — the
    /// narrowband/wideband media-plane rates, matching the noise suppressor's WOLA sizes).
    ///
    /// # Errors
    /// [`DspError::InvalidSampleRate`] for any rate other than 8000 or 16000 Hz.
    pub fn new(sample_rate_hz: u32) -> Result<Self, DspError> {
        let (frame_len, fft_size) = match sample_rate_hz {
            8_000 => (NB_FRAME, NB_FFT),
            16_000 => (WB_FRAME, WB_FFT),
            rate => return Err(DspError::InvalidSampleRate { rate }),
        };
        let residual_wola = WolaProcessor::new(fft_size, frame_len)?;
        let echo_analyzer = WolaAnalyzer::new(fft_size, frame_len)?;
        let hop = fft_size / 2;
        let bins = fft_size / 2 + 1;
        // Worst-case hops per call: the input ring can carry up to `hop − 1` leftover samples, plus a
        // full frame, so `⌊(hop − 1 + frame_len)/hop⌋ ≤ frame_len/hop + 1` hops drain. `+2` is slack.
        let max_hops = frame_len / hop + 2;
        Ok(Self {
            sample_rate_hz,
            frame_len,
            hop,
            bins,
            residual_wola,
            echo_analyzer,
            state: ResidualEchoState::new(bins),
            residual_in: vec![0.0; frame_len],
            residual_out: vec![0.0; frame_len],
            echo_power: vec![0.0; max_hops * bins],
            echo_power_len: 0,
        })
    }

    /// The native sample rate this suppressor was built for (Hz).
    #[inline]
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Expected pipeline frame length in samples (160 @ 8 kHz, 320 @ 16 kHz).
    #[inline]
    #[must_use]
    pub fn frame_len(&self) -> usize {
        self.frame_len
    }

    /// Constant algorithmic delay in samples (one FFT window `N`; see [`WolaProcessor`]). This adds to
    /// the linear canceller's own latency (0 for the time-domain backends, one block for the MDF).
    #[inline]
    #[must_use]
    pub fn latency_samples(&self) -> usize {
        self.residual_wola.latency_samples()
    }

    /// Suppress the residual echo in one frame **in place**.
    ///
    /// `residual` is the linear canceller's echo-subtracted output (i16, native rate); `echo_estimate`
    /// is the frame-synchronous linear echo estimate `y_echo = near − residual`, in the same
    /// normalized `f32` `[-1, 1)` scale, aligned sample-for-sample with `residual`. `double_talk` is
    /// the canceller's per-frame double-talk decision — while it is set the leakage estimate is frozen
    /// and the gain is floored up so the near-end talker is not attenuated.
    ///
    /// The two inputs must be the same length (the caller passes matching frames); the output is the
    /// suppressed residual delayed by [`Self::latency_samples`].
    pub fn process(&mut self, residual: &mut [i16], echo_estimate: &[f32], double_talk: bool) {
        let length = residual.len().min(echo_estimate.len());
        if length == 0 {
            return;
        }
        // Grow scratch only if a caller passes an unusually long frame (never on the steady path).
        if self.residual_in.len() < length {
            self.residual_in.resize(length, 0.0);
            self.residual_out.resize(length, 0.0);
            let needed = (length / self.hop + 2) * self.bins;
            if self.echo_power.len() < needed {
                self.echo_power.resize(needed, 0.0);
            }
        }

        for (slot, &sample) in self.residual_in[..length].iter_mut().zip(residual.iter()) {
            *slot = f32::from(sample) / SAMPLE_SCALE;
        }

        // Split the borrows so the two WOLA passes and the shared state can be driven from closures.
        let Self {
            residual_wola,
            echo_analyzer,
            state,
            residual_in,
            residual_out,
            echo_power,
            echo_power_len,
            bins,
            ..
        } = self;
        let bins = *bins;

        // Pass 1 — echo-estimate analysis: stage `|Y_echo[b]|²` for every hop of this frame.
        *echo_power_len = 0;
        echo_analyzer.analyze_frame(&echo_estimate[..length], |spectrum| {
            let base = *echo_power_len;
            for (slot, bin) in echo_power[base..base + bins]
                .iter_mut()
                .zip(spectrum.iter())
            {
                *slot = bin.norm_squared();
            }
            *echo_power_len += bins;
        });

        // Pass 2 — residual analysis → per-bin suppression gain → synthesis. Drains the same number of
        // hops in the same order as pass 1 (both fed the same-length frame), so `read` walks the queue
        // hop-for-hop.
        let mut read = 0usize;
        residual_wola.process_frame(
            &residual_in[..length],
            &mut residual_out[..length],
            |spectrum| {
                let echo = &echo_power[read..read + bins];
                state.apply(spectrum, echo, double_talk);
                read += bins;
            },
        );

        for (sample, &value) in residual.iter_mut().zip(self.residual_out[..length].iter()) {
            *sample = clamp_to_i16(value * SAMPLE_SCALE);
        }
    }

    /// Reset the framing and leakage tracking (e.g. on a stream discontinuity).
    pub fn reset(&mut self) {
        self.residual_wola.reset();
        self.echo_analyzer.reset();
        self.state.reset();
        self.echo_power_len = 0;
    }
}

/// Round-and-clamp a denormalized `f32` sample to `i16` (saturating).
#[inline]
fn clamp_to_i16(value: f32) -> i16 {
    let rounded = value.round();
    if rounded >= f32::from(i16::MAX) {
        i16::MAX
    } else if rounded <= f32::from(i16::MIN) {
        i16::MIN
    } else {
        rounded as i16
    }
}

/// Per-bin residual-echo leakage tracking + decision-directed Wiener gain state.
#[derive(Clone, Debug)]
struct ResidualEchoState {
    bins: usize,
    /// Smoothed residual power `S̄_e[b]`.
    smoothed_residual: Vec<f32>,
    /// Smoothed echo-estimate power `S̄_y[b]`.
    smoothed_echo: Vec<f32>,
    /// Adaptive per-bin leakage `η[b]` (residual-to-cancelled ratio), frozen during double-talk.
    leakage: Vec<f32>,
    /// Previous frame's clean-amplitude estimate squared `Â_prev²` (the decision-directed term).
    previous_clean_power: Vec<f32>,
    /// The shared decision-directed Wiener gain (interference = the residual-echo PSD).
    gain: DecisionDirectedWiener,
    /// Whether the first hop has seeded the estimates.
    initialized: bool,
    // --- fixed coefficients (documented at construction) ---
    power_smoothing: f32,
    leakage_smoothing: f32,
    over_subtraction: f32,
    echo_floor: f32,
    leakage_max: f32,
    initial_leakage: f32,
    double_talk_gain_floor: f32,
}

impl ResidualEchoState {
    fn new(bins: usize) -> Self {
        Self {
            bins,
            smoothed_residual: vec![0.0; bins],
            smoothed_echo: vec![0.0; bins],
            leakage: vec![0.0; bins],
            previous_clean_power: vec![0.0; bins],
            gain: DecisionDirectedWiener {
                // Match the noise suppressor's canonical decision-directed constants: heavy temporal
                // smoothing (musical-noise defence) with a −16 dB spectral floor so a comfort residual
                // survives and the output never fully gates.
                decision_directed: 0.99,
                a_priori_floor: 0.003,
                gain_floor: 0.158_489_32,
            },
            initialized: false,
            // Residual/echo power smoothing (~100 ms at the 62.5 Hz hop rate): fast enough to track the
            // echo envelope, slow enough for a stable leakage ratio.
            power_smoothing: 0.9,
            // Leakage smoothing (~200 ms): η is a slowly-varying path property, so smooth it hard.
            leakage_smoothing: 0.9,
            // Over-subtraction β: 1.0 = the estimated residual-echo power verbatim (no aggression).
            over_subtraction: 1.0,
            // Below this smoothed echo-estimate power there is effectively no echo, so the leakage
            // update is frozen (a silent far-end must not drive η toward the near-end/noise ratio).
            echo_floor: 1.0e-8,
            // Clamp the tracked leakage: a residual a few times the estimate is plausible under strong
            // nonlinearity, but an unbounded ratio (e.g. a transient 0/0) must not blow up the PSD.
            leakage_max: 4.0,
            // Seed leakage assuming the residual initially equals the estimate (unconverged filter):
            // conservative — the RES suppresses from the first frames and relaxes as η is learned down.
            initial_leakage: 1.0,
            // During flagged double-talk the gain is floored up to this (≈ −6 dB) so the near-end
            // talker passes essentially untouched even in the pathological near≈residual-echo case.
            double_talk_gain_floor: 0.5,
        }
    }

    /// Apply the per-bin residual-echo suppression gain to one hop's `N/2 + 1` complex bins in place,
    /// given that hop's echo-estimate power `|Y_echo[b]|²` and the frame's double-talk decision.
    fn apply(&mut self, spectrum: &mut [Complex], echo_power: &[f32], double_talk: bool) {
        const EPSILON: f32 = 1e-12;
        let count = spectrum.len().min(self.bins).min(echo_power.len());

        if !self.initialized {
            self.seed(spectrum, echo_power, count);
        }

        for (index, bin) in spectrum.iter_mut().enumerate().take(count) {
            let residual_power = bin.norm_squared();
            let echo_estimate_power = echo_power[index];

            self.smoothed_residual[index] = self.power_smoothing * self.smoothed_residual[index]
                + (1.0 - self.power_smoothing) * residual_power;
            self.smoothed_echo[index] = self.power_smoothing * self.smoothed_echo[index]
                + (1.0 - self.power_smoothing) * echo_estimate_power;

            // Freeze the leakage estimate during double-talk (near-end would corrupt the ratio) and
            // when the far-end carries no echo (nothing to measure the leakage against).
            if !double_talk && self.smoothed_echo[index] > self.echo_floor {
                let instantaneous = (self.smoothed_residual[index] / self.smoothed_echo[index])
                    .min(self.leakage_max);
                self.leakage[index] = self.leakage_smoothing * self.leakage[index]
                    + (1.0 - self.leakage_smoothing) * instantaneous;
            }

            // Residual-echo PSD this hop, from the instantaneous echo estimate scaled by the stable
            // per-bin leakage (a small floor keeps the SNR ratios finite when there is no echo).
            let interference =
                (self.over_subtraction * self.leakage[index] * echo_estimate_power).max(EPSILON);

            let mut gain = self.gain.gain(
                residual_power,
                interference,
                self.previous_clean_power[index],
            );
            if double_talk && gain < self.double_talk_gain_floor {
                gain = self.double_talk_gain_floor;
            }

            bin.re *= gain;
            bin.im *= gain;
            // Â² for the next hop's decision-directed term: (G·|E|)² = G²·|E|².
            self.previous_clean_power[index] = gain * gain * residual_power;
        }

        self.initialized = true;
    }

    /// Seed the smoothing and leakage state from the first hop.
    fn seed(&mut self, spectrum: &[Complex], echo_power: &[f32], count: usize) {
        for index in 0..count {
            let residual_power = spectrum[index].norm_squared();
            let echo_estimate_power = echo_power[index];
            self.smoothed_residual[index] = residual_power;
            self.smoothed_echo[index] = echo_estimate_power;
            self.leakage[index] = if echo_estimate_power > self.echo_floor {
                (residual_power / echo_estimate_power).min(self.leakage_max)
            } else {
                self.initial_leakage
            };
        }
    }

    fn reset(&mut self) {
        self.smoothed_residual.iter_mut().for_each(|v| *v = 0.0);
        self.smoothed_echo.iter_mut().for_each(|v| *v = 0.0);
        self.leakage.iter_mut().for_each(|v| *v = 0.0);
        self.previous_clean_power.iter_mut().for_each(|v| *v = 0.0);
        self.initialized = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic fixed-seed PRNG (splitmix64 → white f32); never `rand`, never the wall clock.
    struct SplitMix64 {
        state: u64,
    }
    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }
        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        /// Uniform white noise in `[-amplitude, amplitude)`.
        fn next_noise(&mut self, amplitude: f32) -> f32 {
            let unit = (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32; // [0, 1)
            (unit * 2.0 - 1.0) * amplitude
        }
    }

    fn power_i16(samples: &[i16]) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let sum: f64 = samples.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
        sum / samples.len() as f64
    }

    #[test]
    fn rejects_unsupported_sample_rate() {
        assert_eq!(
            ResidualEchoSuppressor::new(44_100).unwrap_err(),
            DspError::InvalidSampleRate { rate: 44_100 }
        );
        assert!(ResidualEchoSuppressor::new(8_000).is_ok());
        assert!(ResidualEchoSuppressor::new(16_000).is_ok());
    }

    #[test]
    fn frame_geometry_matches_rate() {
        let nb = ResidualEchoSuppressor::new(8_000).expect("build");
        assert_eq!(nb.frame_len(), 160);
        assert_eq!(nb.latency_samples(), 256);
        let wb = ResidualEchoSuppressor::new(16_000).expect("build");
        assert_eq!(wb.frame_len(), 320);
        assert_eq!(wb.latency_samples(), 512);
    }

    /// Standalone RES: on an echo-only residual whose power tracks the echo estimate (the residual is
    /// a leakage-scaled copy of the estimate — exactly the model), the suppressor drives the residual
    /// power well down. Measured as a steady-state power ratio (latency-invariant).
    #[test]
    fn suppresses_echo_only_residual() {
        let frame = 160usize;
        let frames = 200;
        let mut prng = SplitMix64::new(0x9E5_1D0A1);
        let mut res = ResidualEchoSuppressor::new(8_000).expect("build");

        // Echo estimate: a moderate broadband "removed echo". Residual: a −12 dB leakage copy (so its
        // power is ~1/16 of the estimate) — the linear filter left this behind.
        let leak = 0.25f32; // amplitude leak → −12 dB power
        let mut input_power = 0.0f64;
        let mut output_power = 0.0f64;
        let tail_frames = 60;
        for index in 0..frames {
            let echo: Vec<f32> = (0..frame).map(|_| prng.next_noise(0.1)).collect();
            let residual_f: Vec<f32> = echo.iter().map(|&y| leak * y).collect();
            let mut residual: Vec<i16> = residual_f
                .iter()
                .map(|&r| clamp_to_i16(r * SAMPLE_SCALE))
                .collect();
            let reference = residual.clone();
            res.process(&mut residual, &echo, false);
            if index >= frames - tail_frames {
                input_power += power_i16(&reference);
                output_power += power_i16(&residual);
            }
        }
        let suppression_db = 10.0 * (input_power / output_power.max(1.0)).log10();
        assert!(
            suppression_db >= 6.0,
            "RES only suppressed the echo-only residual by {suppression_db:.1} dB (want ≥ 6 dB)"
        );
    }

    /// Standalone RES: near-end-only (the echo estimate is silent → no echo) must pass through with
    /// negligible attenuation — the RES must not treat the near-end talker as residual echo.
    #[test]
    fn preserves_near_end_when_no_echo() {
        let frame = 160usize;
        let frames = 120;
        let mut prng = SplitMix64::new(0x0EA5_1DE0);
        let mut res = ResidualEchoSuppressor::new(8_000).expect("build");

        let silent_echo = vec![0.0f32; frame];
        let mut near_power = 0.0f64;
        let mut output_power = 0.0f64;
        let tail_frames = 40;
        for index in 0..frames {
            let near: Vec<i16> = (0..frame)
                .map(|_| clamp_to_i16(prng.next_noise(0.3) * SAMPLE_SCALE))
                .collect();
            let mut residual = near.clone();
            res.process(&mut residual, &silent_echo, false);
            if index >= frames - tail_frames {
                near_power += power_i16(&near);
                output_power += power_i16(&residual);
            }
        }
        // The reconstructed near-end power is within ~1 dB of the input (only WOLA edge effects).
        let attenuation_db = 10.0 * (output_power / near_power.max(1.0)).log10();
        assert!(
            attenuation_db.abs() <= 1.0,
            "near-end (no echo) attenuated by {attenuation_db:.2} dB (want |·| ≤ 1 dB)"
        );
    }

    /// Standalone RES: during flagged double-talk (near-end present on top of an echo estimate) the
    /// leakage estimate is frozen and the gain floored up, so the near-end talker passes with bounded
    /// attenuation rather than being chewed as echo.
    #[test]
    fn preserves_near_end_during_double_talk() {
        let frame = 160usize;
        let frames = 160;
        let mut prng = SplitMix64::new(0xD0B1_E7A1);
        let mut res = ResidualEchoSuppressor::new(8_000).expect("build");

        // First converge the leakage on echo-only, then inject near-end with the double-talk flag set.
        let mut near_power = 0.0f64;
        let mut output_power = 0.0f64;
        let double_talk_start = 100;
        for index in 0..frames {
            let echo: Vec<f32> = (0..frame).map(|_| prng.next_noise(0.1)).collect();
            let double_talk = index >= double_talk_start;
            let near: Vec<f32> = if double_talk {
                (0..frame).map(|_| prng.next_noise(0.3)).collect()
            } else {
                vec![0.0f32; frame]
            };
            // Residual = a −12 dB echo leak plus the near-end talker.
            let mut residual: Vec<i16> = (0..frame)
                .map(|i| clamp_to_i16((0.25 * echo[i] + near[i]) * SAMPLE_SCALE))
                .collect();
            res.process(&mut residual, &echo, double_talk);
            if index >= double_talk_start + 10 {
                let near_i16: Vec<i16> = near
                    .iter()
                    .map(|&n| clamp_to_i16(n * SAMPLE_SCALE))
                    .collect();
                near_power += power_i16(&near_i16);
                output_power += power_i16(&residual);
            }
        }
        // The output tracks the near-end talker power to within ~3 dB (neither cancelled nor amplified).
        let ratio_db = 10.0 * (output_power / near_power.max(1.0)).log10();
        assert!(
            ratio_db.abs() <= 3.0,
            "double-talk near-end not preserved: output/near power {ratio_db:.1} dB (want |·| ≤ 3 dB)"
        );
    }

    /// No musical noise: on an echo-only residual tail, the suppressed output's per-frame energy has a
    /// bounded coefficient of variation (musical noise would show up as flickering isolated tones →
    /// high frame-to-frame variance).
    #[test]
    fn echo_only_tail_has_no_musical_noise() {
        let frame = 160usize;
        let frames = 200;
        let mut prng = SplitMix64::new(0xBADF_00D5);
        let mut res = ResidualEchoSuppressor::new(8_000).expect("build");

        let mut energies = Vec::new();
        for index in 0..frames {
            let echo: Vec<f32> = (0..frame).map(|_| prng.next_noise(0.1)).collect();
            let mut residual: Vec<i16> = echo
                .iter()
                .map(|&y| clamp_to_i16(0.25 * y * SAMPLE_SCALE))
                .collect();
            res.process(&mut residual, &echo, false);
            if index >= frames / 2 {
                energies.push(power_i16(&residual) as f32);
            }
        }
        let mean = energies.iter().sum::<f32>() / energies.len() as f32;
        let variance = energies
            .iter()
            .map(|&e| (e - mean) * (e - mean))
            .sum::<f32>()
            / energies.len() as f32;
        let coefficient_of_variation = variance.sqrt() / mean.max(1e-6);
        assert!(
            coefficient_of_variation < 0.6,
            "suppressed-residual energy CoV {coefficient_of_variation:.3} too high (musical noise)"
        );
    }

    #[test]
    fn silence_stays_silent() {
        let mut res = ResidualEchoSuppressor::new(8_000).expect("build");
        let echo = [0.0f32; 160];
        let mut frame = [0i16; 160];
        for _ in 0..20 {
            res.process(&mut frame, &echo, false);
            assert!(frame.iter().all(|&s| s == 0), "silence must stay silent");
        }
    }

    #[test]
    fn empty_frame_is_a_noop() {
        let mut res = ResidualEchoSuppressor::new(8_000).expect("build");
        res.process(&mut [], &[], false);
    }

    #[test]
    fn reset_clears_state() {
        let frame = 160usize;
        let mut prng = SplitMix64::new(0x5E7_0001);
        let mut res = ResidualEchoSuppressor::new(8_000).expect("build");
        for _ in 0..20 {
            let echo: Vec<f32> = (0..frame).map(|_| prng.next_noise(0.1)).collect();
            let mut residual: Vec<i16> = echo
                .iter()
                .map(|&y| clamp_to_i16(0.25 * y * SAMPLE_SCALE))
                .collect();
            res.process(&mut residual, &echo, false);
        }
        assert!(res.state.initialized);
        res.reset();
        assert!(!res.state.initialized, "reset clears seeding");
        assert!(res.state.leakage.iter().all(|&v| v == 0.0));
    }

    /// Determinism: the RES is a pure function of its inputs (logical clock, fixed-seed PRNG), so two
    /// identical runs produce identical output.
    #[test]
    fn is_deterministic() {
        let run = || {
            let frame = 160usize;
            let mut prng = SplitMix64::new(0xD37E_9001);
            let mut res = ResidualEchoSuppressor::new(8_000).expect("build");
            let mut out = Vec::new();
            for _ in 0..60 {
                let echo: Vec<f32> = (0..frame).map(|_| prng.next_noise(0.1)).collect();
                let mut residual: Vec<i16> = echo
                    .iter()
                    .map(|&y| clamp_to_i16(0.25 * y * SAMPLE_SCALE))
                    .collect();
                res.process(&mut residual, &echo, false);
                out.extend_from_slice(&residual);
            }
            out
        };
        assert_eq!(run(), run());
    }
}
