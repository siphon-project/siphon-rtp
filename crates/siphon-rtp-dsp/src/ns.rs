//! Single-channel noise suppression: decision-directed Wiener filtering in the √Hann WOLA STFT.
//!
//! [`NoiseSuppressor`] cleans one 20 ms frame of narrowband (8 kHz) or wideband (16 kHz) `i16` PCM
//! in place. It is deterministic (no clock, no randomness) and does **zero per-frame heap
//! allocation** — all state is preallocated in [`NoiseSuppressor::new`].
//!
//! ## Algorithm (this slice)
//!
//! Per STFT hop, for each of the `N/2 + 1` bins:
//! 1. **Posterior SNR** `γ = |Y|² / N̂`, from the bin power and the noise-PSD estimate `N̂`.
//! 2. **A priori SNR** by the decision-directed recursion (Ephraim & Malah 1984,
//!    *Speech enhancement using a minimum mean-square error short-time spectral amplitude
//!    estimator*, IEEE TASSP 32(6)): `ξ = α·Â_prev²/N̂ + (1-α)·max(γ-1, 0)`, where `Â_prev` is the
//!    previous frame's clean-amplitude estimate. The decision-directed `ξ` is the standard defence
//!    against musical noise.
//! 3. **Wiener gain** `G = ξ / (1 + ξ)`.
//! 4. **Spectral floor** `G = max(G, G_floor)` (≈ −16 dB) so the output never fully gates and the
//!    residual stays natural.
//!
//! The noise PSD `N̂` is tracked by **minimum statistics** (Martin, *Noise power spectral density
//! estimation based on optimal smoothing and minimum statistics*, IEEE TSAP 9(5) 2001): the
//! per-bin minimum of the smoothed power spectrum over a ~1.5 s sliding window (implemented with
//! Martin's sub-window scheme for O(1) updates) times a fixed bias correction. The window minimum is
//! held by the pauses between words, so — unlike an instantaneous minimum tracker — it does **not**
//! follow a decaying word ending down and suppress it.
//!
//! follow-up: this slice ships the DD-Wiener gain with a fixed-bias windowed minimum-statistics
//! tracker. The MMSE-LSA gain (Ephraim & Malah 1985), Martin's optimal *adaptive* bias/smoothing, and
//! a full IMCRA / MCRA soft-decision noise estimator are deferred to a later PR. The suppressor is
//! wired into the engine media pipeline: the `noise_suppression` profile flag gates it per leg on the
//! transcode path and the WS voice-AI bridge (rate-gated to 8/16 kHz at build time).

use crate::fft::Complex;
use crate::spectral::DecisionDirectedWiener;
use crate::window::WolaProcessor;
use crate::DspError;

/// 8 kHz narrowband: 20 ms frame / FFT size / hop.
const NB_FRAME: usize = 160;
const NB_FFT: usize = 256;
/// 16 kHz wideband: 20 ms frame / FFT size / hop.
const WB_FRAME: usize = 320;
const WB_FFT: usize = 512;

/// A single-channel decision-directed Wiener noise suppressor.
#[derive(Clone, Debug)]
pub struct NoiseSuppressor {
    sample_rate_hz: u32,
    frame_len: usize,
    wola: WolaProcessor,
    state: SpectralState,
    /// Preallocated `i16 → f32` input scratch (length `frame_len`).
    frame_in: Vec<f32>,
    /// Preallocated `f32 → i16` output scratch (length `frame_len`).
    frame_out: Vec<f32>,
}

impl NoiseSuppressor {
    /// Build a suppressor for the given native sample rate.
    ///
    /// # Errors
    /// [`DspError::InvalidSampleRate`] for any rate other than 8000 or 16000 Hz.
    pub fn new(sample_rate_hz: u32) -> Result<Self, DspError> {
        let (frame_len, fft_size) = match sample_rate_hz {
            8_000 => (NB_FRAME, NB_FFT),
            16_000 => (WB_FRAME, WB_FFT),
            rate => return Err(DspError::InvalidSampleRate { rate }),
        };
        let wola = WolaProcessor::new(fft_size, frame_len)?;
        let bins = fft_size / 2 + 1;
        Ok(Self {
            sample_rate_hz,
            frame_len,
            wola,
            state: SpectralState::new(bins),
            frame_in: vec![0.0; frame_len],
            frame_out: vec![0.0; frame_len],
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

    /// Constant algorithmic delay in samples (one FFT window `N`; see [`WolaProcessor`]).
    #[inline]
    #[must_use]
    pub fn latency_samples(&self) -> usize {
        self.wola.latency_samples()
    }

    /// Suppress noise in one 20 ms frame in place.
    ///
    /// `frame` is expected to hold [`Self::frame_len`] samples at the native rate; any length is
    /// handled safely (the WOLA is sample-driven), returning the reconstructed stream delayed by
    /// [`Self::latency_samples`].
    pub fn process(&mut self, frame: &mut [i16]) {
        let length = frame.len();
        // Grow scratch only if a caller passes an unusually long frame (never on the steady path);
        // the steady-state 20 ms frame reuses the preallocated buffers with no allocation.
        if self.frame_in.len() < length {
            self.frame_in.resize(length, 0.0);
            self.frame_out.resize(length, 0.0);
        }
        let frame_in = &mut self.frame_in[..length];
        let frame_out = &mut self.frame_out[..length];

        for (slot, &sample) in frame_in.iter_mut().zip(frame.iter()) {
            *slot = f32::from(sample);
        }

        let state = &mut self.state;
        self.wola
            .process_frame(frame_in, frame_out, |spectrum| state.apply(spectrum));

        for (sample, &value) in frame.iter_mut().zip(frame_out.iter()) {
            *sample = clamp_to_i16(value);
        }
    }

    /// Reset the framing and spectral tracking (e.g. on a stream discontinuity).
    pub fn reset(&mut self) {
        self.wola.reset();
        self.state.reset();
    }
}

/// Round-and-clamp an `f32` sample to `i16` (saturating), matching the resampler's output rule.
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

/// Number of Martin sub-windows spanning the minimum-search window.
const SUBWINDOW_COUNT: usize = 8;
/// Hops per sub-window. `SUBWINDOW_COUNT · SUBWINDOW_LENGTH` ≈ 96 hops ≈ 1.5 s at both rates
/// (the hop rate is 62.5 Hz for both 8 kHz/128 and 16 kHz/256).
const SUBWINDOW_LENGTH: usize = 12;

/// Per-bin spectral tracking + gain state for the decision-directed Wiener filter.
#[derive(Clone, Debug)]
struct SpectralState {
    bins: usize,
    /// Noise power spectral density estimate `N̂` (= `noise_bias` · windowed minimum).
    noise_psd: Vec<f32>,
    /// Recursively smoothed observed power spectrum.
    smoothed_power: Vec<f32>,
    /// Running minimum of `smoothed_power` within the current sub-window (per bin).
    current_subwindow_min: Vec<f32>,
    /// Ring of the last [`SUBWINDOW_COUNT`] completed sub-window minima, bin-major
    /// (`[bin · SUBWINDOW_COUNT + u]`); the noise floor is the minimum across the ring plus the
    /// in-progress sub-window.
    subwindow_mins: Vec<f32>,
    /// Previous frame's clean-amplitude estimate squared `Â_prev²` (drives the decision-directed ξ).
    previous_clean_power: Vec<f32>,
    /// Hops elapsed within the current sub-window.
    subwindow_hop: usize,
    /// Ring write position (`0..SUBWINDOW_COUNT`).
    subwindow_index: usize,
    /// Whether the first frame has seeded the estimates.
    initialized: bool,
    // --- fixed coefficients (documented at construction) ---
    power_smoothing: f32,
    noise_bias: f32,
    /// The shared decision-directed Wiener gain (interference = the tracked noise PSD).
    gain: DecisionDirectedWiener,
}

impl SpectralState {
    fn new(bins: usize) -> Self {
        Self {
            bins,
            noise_psd: vec![0.0; bins],
            smoothed_power: vec![0.0; bins],
            current_subwindow_min: vec![0.0; bins],
            subwindow_mins: vec![0.0; bins * SUBWINDOW_COUNT],
            previous_clean_power: vec![0.0; bins],
            subwindow_hop: 0,
            subwindow_index: 0,
            initialized: false,
            // Power spectrum smoothing (higher = smoother noise estimate).
            power_smoothing: 0.88,
            // The windowed minimum sits well below the mean noise power (Martin's Q_eq bias); a
            // fixed 3.0 brings the estimate up to the mean, which both suppresses residual noise
            // fully and stops isolated bins flickering through (musical noise).
            noise_bias: 3.0,
            gain: DecisionDirectedWiener {
                // Decision-directed a priori SNR smoothing (Ephraim–Malah). The canonical 0.98..0.99
                // range; 0.99 maximises the temporal smoothing that suppresses musical noise.
                decision_directed: 0.99,
                // Small a priori SNR floor so ξ stays positive before the gain floor applies.
                a_priori_floor: 0.003,
                // Spectral floor ≈ −16 dB amplitude (10^(-16/20)); output never fully gates, and the
                // constant floor bed masks any residual isolated survivors (musical noise).
                gain_floor: 0.158_489_32,
            },
        }
    }

    /// Apply the decision-directed Wiener gain to one frame's `N/2 + 1` complex bins in place.
    fn apply(&mut self, spectrum: &mut [Complex]) {
        const EPSILON: f32 = 1e-12;
        let count = spectrum.len().min(self.bins);

        if !self.initialized {
            self.seed(spectrum, count);
        }

        for (index, bin) in spectrum.iter_mut().enumerate().take(count) {
            let power = bin.norm_squared();

            self.smoothed_power[index] = self.power_smoothing * self.smoothed_power[index]
                + (1.0 - self.power_smoothing) * power;
            self.current_subwindow_min[index] =
                self.current_subwindow_min[index].min(self.smoothed_power[index]);

            // Windowed minimum: smallest of the in-progress sub-window and the completed ring.
            let ring = &self.subwindow_mins[index * SUBWINDOW_COUNT..(index + 1) * SUBWINDOW_COUNT];
            let mut windowed_min = self.current_subwindow_min[index];
            for &value in ring {
                windowed_min = windowed_min.min(value);
            }
            self.noise_psd[index] = (self.noise_bias * windowed_min).max(EPSILON);

            let noise = self.noise_psd[index];
            let gain = self
                .gain
                .gain(power, noise, self.previous_clean_power[index]);

            bin.re *= gain;
            bin.im *= gain;
            // Â² for the next frame's decision-directed term: (G·|Y|)² = G²·|Y|².
            self.previous_clean_power[index] = gain * gain * power;
        }

        self.advance_subwindow_clock(count);
        self.initialized = true;
    }

    /// Seed the smoothing and minimum ring from the first frame (assumed to lead in with noise).
    fn seed(&mut self, spectrum: &[Complex], count: usize) {
        for (index, bin) in spectrum.iter().enumerate().take(count) {
            let power = bin.norm_squared();
            self.smoothed_power[index] = power;
            self.current_subwindow_min[index] = power;
            for slot in
                &mut self.subwindow_mins[index * SUBWINDOW_COUNT..(index + 1) * SUBWINDOW_COUNT]
            {
                *slot = power;
            }
        }
    }

    /// Advance Martin's sub-window clock: on sub-window boundaries, store the completed minimum into
    /// the ring and restart the in-progress minimum.
    fn advance_subwindow_clock(&mut self, count: usize) {
        self.subwindow_hop += 1;
        if self.subwindow_hop < SUBWINDOW_LENGTH {
            return;
        }
        self.subwindow_hop = 0;
        for index in 0..count {
            self.subwindow_mins[index * SUBWINDOW_COUNT + self.subwindow_index] =
                self.current_subwindow_min[index];
            self.current_subwindow_min[index] = f32::INFINITY;
        }
        self.subwindow_index = (self.subwindow_index + 1) % SUBWINDOW_COUNT;
    }

    fn reset(&mut self) {
        self.noise_psd.iter_mut().for_each(|value| *value = 0.0);
        self.smoothed_power
            .iter_mut()
            .for_each(|value| *value = 0.0);
        self.current_subwindow_min
            .iter_mut()
            .for_each(|value| *value = 0.0);
        self.subwindow_mins
            .iter_mut()
            .for_each(|value| *value = 0.0);
        self.previous_clean_power
            .iter_mut()
            .for_each(|value| *value = 0.0);
        self.subwindow_hop = 0;
        self.subwindow_index = 0;
        self.initialized = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG (fixed seed) for reproducible noise — never `rand`, never the wall clock.
    struct Lcg(u32);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            self.0
        }
        /// Uniform white noise in `[-1, 1)`.
        fn next_bipolar(&mut self) -> f32 {
            (self.next() >> 8) as f32 / (1u32 << 23) as f32 - 1.0
        }
    }

    /// A synthetic voiced signal: a low-vowel harmonic complex (fundamental + a steeply rolled-off
    /// harmonic), a spectrally sparse stand-in for a voiced speech segment.
    fn voiced_sample(fundamental_hz: f32, rate: f32, sample_index: usize) -> f32 {
        let t = sample_index as f32 / rate;
        let harmonics = [1.0f32, 2.0];
        let weights = [1.0f32, 0.5];
        let mut value = 0.0;
        for (harmonic, weight) in harmonics.iter().zip(weights.iter()) {
            value += weight * (2.0 * std::f32::consts::PI * fundamental_hz * harmonic * t).sin();
        }
        value
    }

    /// A syllabic envelope: a trapezoidal burst (raised-cosine attack/release, flat sustain) with
    /// silent gaps. Real speech is **non-stationary**; the gaps let a minimum-statistics tracker see
    /// the noise floor, while the flat sustain (not a long decay) keeps the tracker from following
    /// the speech level down. A stationary tone would (correctly) be tracked as noise and suppressed.
    fn syllabic_envelope(rate: f32, sample_index: usize, syllable_hz: f32) -> f32 {
        let t = sample_index as f32 / rate;
        let phase = (t * syllable_hz).fract();
        let active = 0.6f32;
        let edge = 0.08f32;
        if phase >= active {
            0.0
        } else if phase < edge {
            0.5 - 0.5 * (std::f32::consts::PI * phase / edge).cos()
        } else if phase > active - edge {
            0.5 - 0.5 * (std::f32::consts::PI * (active - phase) / edge).cos()
        } else {
            1.0
        }
    }

    /// Segmental SNR (dB) of `estimate` against `reference`, averaged over **active** 20 ms segments.
    ///
    /// Active frames are those whose reference energy exceeds a fraction of the peak segment energy —
    /// the conventional way to compute segmental SNR, excluding silence and near-silent burst edges
    /// (where relative error is meaningless). Both input and output are scored on the same set.
    fn segmental_snr(reference: &[f32], estimate: &[f32], frame_len: usize) -> f32 {
        let end = reference.len().min(estimate.len());
        let segment_energy = |start: usize| -> f32 {
            reference[start..start + frame_len]
                .iter()
                .map(|&value| value * value)
                .sum::<f32>()
        };

        let mut peak = 0.0f32;
        let mut start = 0;
        while start + frame_len <= end {
            peak = peak.max(segment_energy(start));
            start += frame_len;
        }
        let activity_threshold = 0.1 * peak;

        let mut total = 0.0f32;
        let mut segments = 0u32;
        start = 0;
        while start + frame_len <= end {
            let signal = segment_energy(start);
            if signal >= activity_threshold && signal > 1.0 {
                let error: f32 = (0..frame_len)
                    .map(|offset| {
                        let difference = estimate[start + offset] - reference[start + offset];
                        difference * difference
                    })
                    .sum();
                total += 10.0 * (signal / error.max(1e-9)).log10();
                segments += 1;
            }
            start += frame_len;
        }
        if segments == 0 {
            0.0
        } else {
            total / segments as f32
        }
    }

    #[test]
    fn rejects_unsupported_sample_rate() {
        assert_eq!(
            NoiseSuppressor::new(44_100).unwrap_err(),
            DspError::InvalidSampleRate { rate: 44_100 }
        );
        assert_eq!(
            NoiseSuppressor::new(0).unwrap_err(),
            DspError::InvalidSampleRate { rate: 0 }
        );
        assert!(NoiseSuppressor::new(8_000).is_ok());
        assert!(NoiseSuppressor::new(16_000).is_ok());
    }

    #[test]
    fn frame_geometry_matches_rate() {
        let nb = NoiseSuppressor::new(8_000).expect("build");
        assert_eq!(nb.frame_len(), 160);
        assert_eq!(nb.latency_samples(), 256);
        let wb = NoiseSuppressor::new(16_000).expect("build");
        assert_eq!(wb.frame_len(), 320);
        assert_eq!(wb.latency_samples(), 512);
    }

    /// Build clean speech + a noise lead-in, run the suppressor, and report input/output seg-SNR.
    fn run_snr_scenario(rate: u32) -> (f32, f32) {
        let rate_f = rate as f32;
        let frame_len = if rate == 8_000 { 160 } else { 320 };
        let fundamental = 160.0f32;

        // ~500 ms noise-only lead-in lets the minimum-statistics tracker converge, then ~1.2 s of
        // speech+noise. Amplitudes chosen for ~5 dB input SNR over the speech region.
        let lead_in_frames = 25;
        let speech_frames = 60;
        let total = (lead_in_frames + speech_frames) * frame_len;

        let speech_amplitude = 3200.0f32;
        let noise_amplitude = 2400.0f32;

        let mut rng = Lcg(0x51A9_2E17 ^ rate);
        let mut clean = vec![0.0f32; total];
        let mut noisy = vec![0.0f32; total];
        for index in 0..total {
            let frame_number = index / frame_len;
            let speech = if frame_number >= lead_in_frames {
                let envelope = syllabic_envelope(rate_f, index, 3.0);
                speech_amplitude * envelope * voiced_sample(fundamental, rate_f, index)
            } else {
                0.0
            };
            let noise = noise_amplitude * rng.next_bipolar();
            clean[index] = speech;
            noisy[index] = speech + noise;
        }

        // Run the suppressor on the noisy signal.
        let mut suppressor = NoiseSuppressor::new(rate).expect("build");
        let latency = suppressor.latency_samples();
        let mut enhanced = vec![0.0f32; total];
        let mut frame = vec![0i16; frame_len];
        for (frame_number, chunk) in noisy.chunks(frame_len).enumerate() {
            for (slot, &value) in frame.iter_mut().zip(chunk.iter()) {
                *slot = clamp_to_i16(value);
            }
            suppressor.process(&mut frame);
            let base = frame_number * frame_len;
            for (offset, &sample) in frame.iter().enumerate() {
                enhanced[base + offset] = f32::from(sample);
            }
        }

        // Delay-align: enhanced[n] corresponds to clean[n - latency]. Compare over the speech region.
        let speech_start = lead_in_frames * frame_len + latency;
        let speech_end = total - frame_len;
        let clean_region = &clean[speech_start - latency..speech_end - latency];
        let noisy_region = &noisy[speech_start - latency..speech_end - latency];
        let enhanced_region = &enhanced[speech_start..speech_end];

        let input_snr = segmental_snr(clean_region, noisy_region, frame_len);
        let output_snr = segmental_snr(clean_region, enhanced_region, frame_len);
        (input_snr, output_snr)
    }

    #[test]
    fn improves_segmental_snr_narrowband() {
        let (input_snr, output_snr) = run_snr_scenario(8_000);
        assert!(
            output_snr - input_snr >= 8.0,
            "8 kHz: seg-SNR improvement {:.2} dB (in {:.2}, out {:.2}) below 8 dB target",
            output_snr - input_snr,
            input_snr,
            output_snr
        );
    }

    #[test]
    fn improves_segmental_snr_wideband() {
        let (input_snr, output_snr) = run_snr_scenario(16_000);
        assert!(
            output_snr - input_snr >= 8.0,
            "16 kHz: seg-SNR improvement {:.2} dB (in {:.2}, out {:.2}) below 8 dB target",
            output_snr - input_snr,
            input_snr,
            output_snr
        );
    }

    #[test]
    fn does_not_materially_distort_clean_speech() {
        // On clean-only input the suppressor must leave speech nearly untouched: the output tracks
        // the (delayed) input at high segmental SNR — a bounded speech-distortion guarantee.
        let rate = 16_000u32;
        let frame_len = 320usize;
        let rate_f = rate as f32;
        let frames = 80;
        let total = frames * frame_len;

        let mut clean = vec![0.0f32; total];
        for (index, slot) in clean.iter_mut().enumerate() {
            let envelope = syllabic_envelope(rate_f, index, 3.0);
            *slot = 4000.0 * envelope * voiced_sample(150.0, rate_f, index);
        }

        let mut suppressor = NoiseSuppressor::new(rate).expect("build");
        let latency = suppressor.latency_samples();
        let mut enhanced = vec![0.0f32; total];
        let mut frame = vec![0i16; frame_len];
        for (frame_number, chunk) in clean.chunks(frame_len).enumerate() {
            for (slot, &value) in frame.iter_mut().zip(chunk.iter()) {
                *slot = clamp_to_i16(value);
            }
            suppressor.process(&mut frame);
            let base = frame_number * frame_len;
            for (offset, &sample) in frame.iter().enumerate() {
                enhanced[base + offset] = f32::from(sample);
            }
        }

        // Skip the startup transient (a few frames past the latency) before scoring.
        let start = latency + 4 * frame_len;
        let distortion_snr = segmental_snr(
            &clean[start - latency..total - latency - frame_len],
            &enhanced[start..total - frame_len],
            frame_len,
        );
        assert!(
            distortion_snr >= 12.0,
            "clean-speech distortion seg-SNR {distortion_snr:.2} dB too low (speech over-processed)"
        );
    }

    #[test]
    fn residual_noise_floor_is_stable_no_musical_noise() {
        // Musical noise shows up as flickering isolated spectral tones → high frame-to-frame variance
        // of the residual energy. On a noise-only tail, bound the residual energy's coefficient of
        // variation as a no-musical-noise proxy.
        let rate = 8_000u32;
        let frame_len = 160usize;
        let frames = 120;
        let total = frames * frame_len;

        let mut rng = Lcg(0x0BADF00D);
        let mut noisy = vec![0.0f32; total];
        for slot in noisy.iter_mut() {
            *slot = 2000.0 * rng.next_bipolar();
        }

        let mut suppressor = NoiseSuppressor::new(rate).expect("build");
        let mut enhanced = vec![0.0f32; total];
        let mut frame = vec![0i16; frame_len];
        for (frame_number, chunk) in noisy.chunks(frame_len).enumerate() {
            for (slot, &value) in frame.iter_mut().zip(chunk.iter()) {
                *slot = clamp_to_i16(value);
            }
            suppressor.process(&mut frame);
            let base = frame_number * frame_len;
            for (offset, &sample) in frame.iter().enumerate() {
                enhanced[base + offset] = f32::from(sample);
            }
        }

        // Per-frame residual energy over the converged tail (skip the first half).
        let mut energies = Vec::new();
        let mut start = (frames / 2) * frame_len;
        while start + frame_len <= total {
            let energy: f32 = enhanced[start..start + frame_len]
                .iter()
                .map(|&s| s * s)
                .sum::<f32>()
                / frame_len as f32;
            energies.push(energy);
            start += frame_len;
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
            "residual energy CoV {coefficient_of_variation:.3} too high (musical noise)"
        );
    }

    #[test]
    fn silence_stays_silent() {
        let mut suppressor = NoiseSuppressor::new(8_000).expect("build");
        let mut frame = [0i16; 160];
        for _ in 0..20 {
            suppressor.process(&mut frame);
            assert!(frame.iter().all(|&s| s == 0), "silence must stay silent");
        }
    }

    #[test]
    fn reset_clears_state() {
        let mut suppressor = NoiseSuppressor::new(8_000).expect("build");
        let mut rng = Lcg(7);
        let mut frame = [0i16; 160];
        for _ in 0..10 {
            for slot in frame.iter_mut() {
                *slot = clamp_to_i16(3000.0 * rng.next_bipolar());
            }
            suppressor.process(&mut frame);
        }
        suppressor.reset();
        assert!(!suppressor.state.initialized, "reset clears seeding");
        let silent = [0i16; 160];
        let mut check = silent;
        suppressor.process(&mut check);
        assert_eq!(check, silent, "post-reset silence stays silent");
    }

    // ---- committed golden output vector: pins the deterministic path -----------------------------
    //
    // A fixed deterministic input → the exact suppressed output this implementation produces. The
    // FFT/WOLA/DD-Wiener chain is deterministic (twiddles narrowed from f64, no FMA contraction, no
    // clock), so this vector is stable; a ±2 tolerance absorbs last-ULP libm differences across
    // platforms. The SNR / PR / FFT tests are the real acceptance criteria; this pins determinism.

    fn golden_input() -> [i16; 160] {
        let mut rng = Lcg(0xC0DE_1234);
        let mut frame = [0i16; 160];
        for (index, slot) in frame.iter_mut().enumerate() {
            let voiced = 3000.0 * voiced_sample(180.0, 8000.0, index);
            let noise = 1500.0 * rng.next_bipolar();
            *slot = clamp_to_i16(voiced + noise);
        }
        frame
    }

    #[test]
    fn golden_output_vector_is_stable() {
        let mut suppressor = NoiseSuppressor::new(8_000).expect("build");
        // Warm the tracker with a few identical noisy frames so the golden frame is a steady-state
        // output, then capture the fourth frame's output.
        let input = golden_input();
        let mut frame = input;
        suppressor.process(&mut frame); // frame 1 (warm-up)
        for _ in 0..3 {
            frame = input;
            suppressor.process(&mut frame); // frames 2, 3, then the captured frame 4
        }

        // Captured from this verified implementation (see GOLDEN below). Regenerate intentionally
        // only when the algorithm changes; a silent drift is a regression.
        let golden: [i16; 160] = GOLDEN_NB_FRAME4;
        let mut max_difference = 0i32;
        for (index, (&produced, &expected)) in frame.iter().zip(golden.iter()).enumerate() {
            let difference = (i32::from(produced) - i32::from(expected)).abs();
            max_difference = max_difference.max(difference);
            assert!(
                difference <= 2,
                "golden mismatch at {index}: produced {produced}, expected {expected}"
            );
        }
    }

    // Captured from the verified implementation; see `golden_output_vector_is_stable`.
    #[rustfmt::skip]
    const GOLDEN_NB_FRAME4: [i16; 160] = [
        -187, 42, 71, 135, 185, 253, -129, -34,
        168, -84, -413, -563, -540, -328, -435, -743,
        -422, -400, -876, -815, -269, -329, -418, -373,
        113, -158, 119, 355, 517, 359, 325, 589,
        496, 371, 249, 459, 694, 305, 445, 475,
        22, 316, 76, 225, -55, -159, -215, 165,
        -119, -178, -6, -28, -392, -315, 120, -190,
        -495, -177, -244, -650, -388, -794, -687, -576,
        -847, -747, -185, -436, -221, 172, 271, 294,
        501, 282, 748, 610, 858, 790, 636, 633,
        291, 269, 181, 288, 453, 388, -91, 76,
        -18, -151, 67, 77, 170, 283, -84, 8,
        -76, -60, 201, 465, 269, 359, 329, 744,
        515, 709, 664, 493, 600, 172, 407, 383,
        178, -95, 213, 5, 146, -87, 12, 160,
        -74, 109, -150, -69, -154, -34, -65, -108,
        -160, -280, -574, -348, -775, -738, -517, -641,
        -612, -394, -122, -152, 52, -115, 23, 338,
        370, 648, 779, 830, 467, 436, 682, 735,
        478, 216, 503, 246, -32, 87, -24, -164,
    ];
}
