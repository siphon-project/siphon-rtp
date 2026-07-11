//! A fixed-delay time-domain **NLMS** acoustic echo canceller (AEC).
//!
//! The near-end microphone signal `d[n]` carries the near-end talker `s[n]` plus an echo of the
//! far-end (loudspeaker) reference `x[n]` shaped by the room impulse response `h`:
//!
//! ```text
//!   d[n] = s[n] + Σ_k h[k]·x[n − τ − k] + noise[n]
//! ```
//!
//! An adaptive FIR filter `w` of length `tail_samples` (the *tail*) estimates the echo from the
//! aligned reference and the residual is what we forward:
//!
//! ```text
//!   echo_hat[n] = Σ_k w[k]·x_aligned[n − k]        (one contiguous `fir_dot_f32`)
//!   residual[n] = d[n] − echo_hat[n]               (the echo-subtracted near-end we emit)
//! ```
//!
//! The filter adapts by the **normalized LMS** (NLMS) rule — RFC-free classical adaptive filtering
//! (Haykin, *Adaptive Filter Theory*, §6; Duttweiler, *Proportionate NLMS*, 2000):
//!
//! ```text
//!   w[k] += μ · residual[n] · x_aligned[n − k] / (‖x_aligned‖² + δ)
//! ```
//!
//! Adaptation is **frozen** whenever a [`Geigel`](https://ieeexplore.ieee.org/document/1163130)
//! double-talk detector (cheap `max|far|` vs `|near|`) sees near-end speech, so the filter never
//! learns the near-end talker (which would make it cancel *him*, not the echo).
//!
//! ## Determinism & allocation
//! No wall clock, no randomness: identical input frames yield identical output, so it golden-tests
//! without audio hardware on a purely logical sample-clock. Every buffer (the filter weights and the
//! far-end delay ring) is preallocated in [`EchoCanceller::new`]; the near-end is filtered in place,
//! so [`EchoCanceller::cancel`] does **zero per-frame heap allocation**.
//!
//! ## Fixed bulk delay (this slice) vs. delay estimation (later)
//! The loudspeaker→microphone acoustic + buffering delay `τ` is a **configuration parameter** here
//! ([`EchoCanceller::with_bulk_delay`]); the adaptive filter only has to cover the impulse-response
//! *spread*, not the bulk transport delay, which keeps the tail short. Automatic delay estimation
//! (GCC-PHAT) is a later PR — see the crate roadmap.

use siphon_rtp_simd::fir_dot_f32;

/// i16 full-scale. Samples are processed in normalized `f32` in `[-1, 1)` so the NLMS step size,
/// regularization, and Geigel threshold are all scale-independent pure ratios.
const SAMPLE_SCALE: f32 = 32_768.0;

/// Longest adaptive tail we preallocate for (256 taps @ 8 kHz is the default target; this bounds a
/// pathological request to ~0.5 s @ 8 kHz).
const MAX_TAIL_SAMPLES: usize = 4_096;
/// Longest bulk delay we preallocate the far-end ring for (1 s @ 16 kHz).
const MAX_BULK_DELAY_SAMPLES: usize = 16_000;

/// Default NLMS step size `μ` (0 < μ < 2 for stability; 0.5 trades convergence speed for a low
/// steady-state misadjustment).
const DEFAULT_STEP_SIZE: f32 = 0.5;
/// Default NLMS regularization `δ` (normalized energy units). Prevents division blow-up when the
/// far-end is near silent — at which point the regressor is ~0 and the step vanishes anyway.
const DEFAULT_REGULARIZATION: f32 = 1.0e-3;
/// Default Geigel factor: declare double-talk when `max|near| ≥ threshold·max|far|` over the frame.
/// 0.5 assumes an echo return loss of at least ~6 dB (echo ≤ ½·far), the hands-free norm.
const DEFAULT_GEIGEL_THRESHOLD: f32 = 0.5;
/// Below this normalized far-end peak there is effectively no far-end (hence no echo), so the Geigel
/// detector stays disarmed regardless of the near-end level (~−60 dBFS).
const DEFAULT_FAR_PEAK_FLOOR: f32 = 1.0e-3;
/// Frames adaptation stays frozen after the last double-talk trigger (~60 ms at a 20 ms frame), so a
/// brief near-end gap mid-word doesn't let the filter resume learning the near-end talker.
const DEFAULT_DOUBLETALK_HANGOVER_FRAMES: usize = 3;

/// Errors constructing an [`EchoCanceller`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AecError {
    /// The sample rate is below 8 kHz or not a multiple of 50 Hz (so a 20 ms frame is a whole
    /// number of samples).
    #[error(
        "sample rate must be >= 8000 Hz and a multiple of 50 for a whole 20 ms frame (got {0} Hz)"
    )]
    InvalidSampleRate(u32),
    /// The adaptive tail length is zero or exceeds the preallocation cap.
    #[error("adaptive filter tail must be in 1..={max} samples (got {got})")]
    InvalidTail {
        /// The requested tail length.
        got: usize,
        /// The maximum supported tail length.
        max: usize,
    },
    /// The configured bulk delay exceeds the preallocation cap.
    #[error("bulk delay must be <= {max} samples (got {got})")]
    InvalidBulkDelay {
        /// The requested bulk delay in samples.
        got: usize,
        /// The maximum supported bulk delay.
        max: usize,
    },
}

/// A preallocated far-end delay line — the fixed-bulk-delay FIFO feeding the adaptive filter.
///
/// One contiguous `line` of `carry + frame_capacity` normalized samples. The first
/// `carry = bulk_delay + tail − 1` slots hold the delay-line history carried over from the previous
/// frame; the frame region `[carry, carry + n)` receives the current frame's far-end samples. The
/// bulk delay is baked into `carry`, so the length-`tail` regressor the filter convolves for
/// near-end sample `i` is exactly the contiguous slice `line[i .. i + tail]` — a single
/// `fir_dot_f32`, no gather. After a frame, [`FarEndReference::compact`] slides the trailing `carry`
/// samples to the front for the next call. Fully preallocated: no per-frame heap.
#[derive(Debug, Clone)]
struct FarEndReference {
    tail: usize,
    bulk_delay: usize,
    /// `bulk_delay + tail − 1` — the history that must precede the frame region.
    carry: usize,
    /// Largest frame this ring can absorb without reallocating (the 20 ms frame for the rate).
    frame_capacity: usize,
    /// `carry + frame_capacity` normalized samples, oldest-first.
    line: Vec<f32>,
}

impl FarEndReference {
    fn new(tail: usize, bulk_delay: usize, frame_capacity: usize) -> Self {
        let carry = bulk_delay + tail - 1;
        Self {
            tail,
            bulk_delay,
            carry,
            frame_capacity,
            line: vec![0.0; carry + frame_capacity],
        }
    }

    /// Write up to `frame_capacity` normalized far-end samples into the frame region, returning the
    /// count written (`min(reference.len(), frame_capacity)`).
    fn write_frame(&mut self, reference: &[i16]) -> usize {
        let count = reference.len().min(self.frame_capacity);
        let base = self.carry;
        for (slot, &sample) in self.line[base..base + count].iter_mut().zip(reference) {
            *slot = f32::from(sample) / SAMPLE_SCALE;
        }
        count
    }

    /// The length-`tail` regressor window for near-end sample `i` (`0 ≤ i < n`).
    #[inline]
    fn window(&self, i: usize) -> &[f32] {
        &self.line[i..i + self.tail]
    }

    /// The single normalized sample at absolute `line` index `index` (for the sliding-energy update:
    /// `line[i]` leaves and `line[i + tail]` enters the window when advancing from `i` to `i + 1`).
    #[inline]
    fn at(&self, index: usize) -> f32 {
        self.line[index]
    }

    /// Carry the trailing `carry` samples of the just-processed `n`-sample frame to the front so the
    /// next frame's windows see continuous history.
    fn compact(&mut self, frame_len: usize) {
        self.line.copy_within(frame_len..frame_len + self.carry, 0);
    }

    fn reset(&mut self) {
        self.line.iter_mut().for_each(|sample| *sample = 0.0);
    }
}

/// A fixed-delay time-domain NLMS acoustic echo canceller with a Geigel double-talk detector.
#[derive(Debug, Clone)]
pub struct EchoCanceller {
    sample_rate_hz: u32,
    /// Samples in one 20 ms frame (`sample_rate_hz / 50`).
    frame_samples: usize,
    /// Adaptive filter length `L` (the *tail*).
    tail_samples: usize,
    /// Adaptive FIR weights, length `tail_samples`, aligned to the ascending regressor window (so
    /// `residual = near − fir_dot_f32(weights, window)`).
    weights: Vec<f32>,
    reference: FarEndReference,
    // --- adaptation (all wired; no dead knobs) ---
    step_size: f32,
    regularization: f32,
    // --- Geigel double-talk detector (per-frame block decision) ---
    geigel_threshold: f32,
    far_peak_floor: f32,
    /// Remaining frames for which adaptation stays frozen after the last double-talk trigger.
    doubletalk_hold_frames: usize,
    /// Freeze duration re-armed on every trigger (~60 ms), so a brief near-end gap mid-word doesn't
    /// let the filter resume adapting on the near-end talker.
    doubletalk_hangover_frames: usize,
    /// Whether the most recent [`EchoCanceller::cancel`] frame had adaptation frozen for double-talk
    /// (a status surface the engine can meter/log).
    doubletalk_active: bool,
}

impl EchoCanceller {
    /// A canceller for `sample_rate_hz` with a `tail_samples`-tap adaptive filter and **no** bulk
    /// delay (the echo is assumed to start within the tail). Default target: `tail_samples = 256`
    /// at 8 kHz. Preallocates all state.
    ///
    /// # Errors
    /// [`AecError::InvalidSampleRate`] if the rate is below 8 kHz or not a multiple of 50 Hz;
    /// [`AecError::InvalidTail`] if `tail_samples` is 0 or exceeds the preallocation cap.
    pub fn new(sample_rate_hz: u32, tail_samples: usize) -> Result<Self, AecError> {
        Self::with_bulk_delay(sample_rate_hz, tail_samples, 0)
    }

    /// A canceller with an explicit fixed **bulk delay** `bulk_delay_samples` — the known
    /// loudspeaker→microphone transport delay the reference ring pre-aligns, so the adaptive tail
    /// only has to span the impulse-response spread. Preallocates all state.
    ///
    /// # Errors
    /// As [`EchoCanceller::new`], plus [`AecError::InvalidBulkDelay`] if the delay exceeds the cap.
    pub fn with_bulk_delay(
        sample_rate_hz: u32,
        tail_samples: usize,
        bulk_delay_samples: usize,
    ) -> Result<Self, AecError> {
        if sample_rate_hz < 8_000 || !sample_rate_hz.is_multiple_of(50) {
            return Err(AecError::InvalidSampleRate(sample_rate_hz));
        }
        if tail_samples == 0 || tail_samples > MAX_TAIL_SAMPLES {
            return Err(AecError::InvalidTail {
                got: tail_samples,
                max: MAX_TAIL_SAMPLES,
            });
        }
        if bulk_delay_samples > MAX_BULK_DELAY_SAMPLES {
            return Err(AecError::InvalidBulkDelay {
                got: bulk_delay_samples,
                max: MAX_BULK_DELAY_SAMPLES,
            });
        }
        let frame_samples = (sample_rate_hz / 50) as usize;
        Ok(Self {
            sample_rate_hz,
            frame_samples,
            tail_samples,
            weights: vec![0.0; tail_samples],
            reference: FarEndReference::new(tail_samples, bulk_delay_samples, frame_samples),
            step_size: DEFAULT_STEP_SIZE,
            regularization: DEFAULT_REGULARIZATION,
            geigel_threshold: DEFAULT_GEIGEL_THRESHOLD,
            far_peak_floor: DEFAULT_FAR_PEAK_FLOOR,
            doubletalk_hold_frames: 0,
            doubletalk_hangover_frames: DEFAULT_DOUBLETALK_HANGOVER_FRAMES,
            doubletalk_active: false,
        })
    }

    /// The sample rate this canceller was built for.
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Samples in the 20 ms frame this canceller expects (`sample_rate_hz / 50`).
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    /// The adaptive filter tail length in samples.
    #[must_use]
    pub fn tail_samples(&self) -> usize {
        self.tail_samples
    }

    /// The configured fixed bulk delay in samples.
    #[must_use]
    pub fn bulk_delay_samples(&self) -> usize {
        self.reference.bulk_delay
    }

    /// Whether the most recently cancelled frame contained double-talk (near-end speech that froze
    /// adaptation).
    #[must_use]
    pub fn double_talk_active(&self) -> bool {
        self.doubletalk_active
    }

    /// Cancel the echo in one frame **in place**: subtract the estimated echo (the adaptive filter
    /// applied to the aligned far-end `reference`) from `near_end`, then adapt the filter by NLMS on
    /// the residual — frozen for any sample the Geigel detector flags as double-talk.
    ///
    /// `near_end` and `reference` are a frame-synchronous pair (same time interval). This processes
    /// `min(near_end.len(), reference.len(), frame_samples())` samples — for a correct 20 ms caller
    /// that is the whole frame; a short pair is processed partially and a longer one is truncated to
    /// the preallocated frame (never reallocating, never panicking).
    pub fn cancel(&mut self, near_end: &mut [i16], reference: &[i16]) {
        let n = near_end.len().min(reference.len()).min(self.frame_samples);
        if n == 0 {
            self.doubletalk_active = false;
            return;
        }

        // --- Geigel double-talk decision for the whole frame (cheap block max|far| vs max|near|) ---
        // A block (per-frame) decision is stable and O(n): the far-end level is slowly varying, so
        // one comparison per 20 ms frame gates adaptation without the intra-frame jitter a per-sample
        // leaky peak-hold suffers. `max|near|` uses the *raw* microphone (echo + any near-end talker):
        // during single-talk it is the attenuated echo (below the threshold); a near-end talker lifts
        // it above `threshold·max|far|` and freezes the update so the filter never learns the talker.
        let far_peak = normalized_peak(&reference[..n]);
        let near_peak = normalized_peak(&near_end[..n]);
        if far_peak > self.far_peak_floor && near_peak >= self.geigel_threshold * far_peak {
            self.doubletalk_hold_frames = self.doubletalk_hangover_frames;
        }
        let adapt = self.doubletalk_hold_frames == 0;
        self.doubletalk_active = !adapt;
        if self.doubletalk_hold_frames > 0 {
            self.doubletalk_hold_frames -= 1;
        }

        // Load the far-end frame into the delay ring (normalized f32).
        let written = self.reference.write_frame(&reference[..n]);
        debug_assert_eq!(written, n, "far-end ring must absorb the whole frame");

        // Running energy of the length-`tail` regressor window, seeded for window(0) and slid one
        // sample at a time (SIMD dot for the seed; O(1) add/sub thereafter).
        let mut energy = {
            let window = self.reference.window(0);
            fir_dot_f32(window, window)
        };

        for (i, near_sample) in near_end.iter_mut().enumerate().take(n) {
            // --- echo estimate + residual (the output) ---
            let estimate = fir_dot_f32(&self.weights, self.reference.window(i));
            let near = f32::from(*near_sample) / SAMPLE_SCALE;
            let residual = near - estimate;

            // --- NLMS update on the residual (scalar loop; frozen for the whole double-talk frame) ---
            if adapt {
                let normalized_step = self.step_size * residual / (energy + self.regularization);
                for (weight, &sample) in self.weights.iter_mut().zip(self.reference.window(i)) {
                    *weight += normalized_step * sample;
                }
            }

            // Emit the echo-subtracted near-end.
            *near_sample = denormalize(residual);

            // Slide the window energy to i+1 (line[i] leaves, line[i+tail] enters); skip after the
            // last sample. Reseeded every frame above, so f32 drift can't accumulate across frames.
            if i + 1 < n {
                let leaving = self.reference.at(i);
                let entering = self.reference.at(i + self.tail_samples);
                energy += entering * entering - leaving * leaving;
                if energy < 0.0 {
                    energy = 0.0; // guard f32 round-off below zero
                }
            }
        }

        self.reference.compact(n);
    }

    /// Reset the adaptive filter, far-end ring, and detector state (e.g. on a stream discontinuity).
    pub fn reset(&mut self) {
        self.weights.iter_mut().for_each(|weight| *weight = 0.0);
        self.reference.reset();
        self.doubletalk_hold_frames = 0;
        self.doubletalk_active = false;
    }

    /// The adaptive filter weights (tests assert convergence/freezing on these).
    #[cfg(test)]
    fn weights(&self) -> &[f32] {
        &self.weights
    }
}

/// Peak magnitude of a frame in normalized `[0, 1]` scale (`max|sample| / SAMPLE_SCALE`), for the
/// block Geigel comparison. Uses `unsigned_abs` so `i16::MIN` is handled without overflow.
#[inline]
fn normalized_peak(frame: &[i16]) -> f32 {
    let peak = frame.iter().map(|&sample| sample.unsigned_abs()).max();
    f32::from(peak.unwrap_or(0)) / SAMPLE_SCALE
}

/// Denormalize a `[-1, 1)`-scale residual back to a saturated `i16`.
#[inline]
fn denormalize(value: f32) -> i16 {
    let scaled = (value * SAMPLE_SCALE).round();
    if scaled >= f32::from(i16::MAX) {
        i16::MAX
    } else if scaled <= f32::from(i16::MIN) {
        i16::MIN
    } else {
        scaled as i16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- deterministic fixed-seed PRNG (splitmix64 → white f32 in [-1, 1)); no external rand ----
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

    /// A committed sparse, decaying room impulse response (128 taps @ 8 kHz): a direct-path spike
    /// plus a handful of decaying reflections. The loudspeaker→microphone coupling is attenuated
    /// (peak 0.12 → echo return loss ≈ 18 dB, a typical hands-free path), so the single-talk echo
    /// sits comfortably below the Geigel threshold and never trips a false double-talk.
    const ROOM_IMPULSE_RESPONSE: &[(usize, f32)] = &[
        (0, 0.120),
        (7, -0.070),
        (16, 0.050),
        (31, -0.035),
        (52, 0.022),
        (79, -0.014),
        (110, 0.007),
    ];

    /// Committed golden residual (first frame of the `golden_residual_matches_committed_vector`
    /// scenario), generated from the verified implementation. Regenerate with `DUMP_GOLDEN=1`.
    #[rustfmt::skip]
    const GOLDEN_RESIDUAL: [i16; 160] = [
        2049, 207, -550, -18, -275, -579, 587, -1217, -622, -70, -759, 151, 728, -1050, -911, 147,
        1133, 370, -693, -192, 506, 46, 1394, 708, 29, -1138, -945, -671, -214, -1891, -502, -1179,
        602, -379, 1735, 635, 1111, 712, 489, -664, -30, -916, -440, -1351, 310, 1328, -674, 778,
        513, -518, -130, 1651, 374, 608, -704, 248, 247, -1075, -79, 647, -927, 1593, -837, 531,
        813, -1142, -553, -1033, -668, 196, -110, 1468, -238, -112, -525, -9, -679, -398, -182,
        -124, 437, -367, -298, -770, -89, 733, -100, 824, 431, 960, 328, 56, -306, 217, 1, 672,
        206, -76, -22, 481, -1042, 156, -672, 268, -205, 349, 185, 130, -591, -325, 703, -475,
        -275, -108, 99, -83, -1089, 915, -229, 305, 24, 1022, -705, 437, -53, 59, -189, -216, 562,
        -7, 105, 167, -303, 552, 69, -904, -330, 523, 482, -589, -85, -201, 151, -124, -135, 89,
        60, 626, -1121, -234, -305, -192, -469, 373, 318, -166, -135, 167, 403, -560,
    ];

    fn build_rir(len: usize) -> Vec<f32> {
        let mut rir = vec![0.0f32; len];
        for &(tap, amplitude) in ROOM_IMPULSE_RESPONSE {
            if tap < len {
                rir[tap] = amplitude;
            }
        }
        rir
    }

    /// Convolve a **continuous** normalized far-end stream through `rir` with a `bulk_delay` sample
    /// shift, producing the echo at the microphone (normalized), then scale to i16. The convolution
    /// spans the whole stream (only genuine pre-stream indices are zero), so chunking it into frames
    /// keeps the exact cross-frame history the canceller's delay ring carries — the two must agree
    /// frame-to-frame or the ERLE is capped by a boundary artifact, not the filter.
    fn synthesize_echo(far: &[f32], rir: &[f32], bulk_delay: usize) -> Vec<i16> {
        let mut echo = vec![0i16; far.len()];
        for (n, out) in echo.iter_mut().enumerate() {
            let mut accumulator = 0.0f32;
            for (k, &coefficient) in rir.iter().enumerate() {
                let source = n as isize - bulk_delay as isize - k as isize;
                if source >= 0 {
                    accumulator += coefficient * far[source as usize];
                }
            }
            *out = super::denormalize(accumulator);
        }
        echo
    }

    /// A continuous far-end (loudspeaker) stream of white noise in `[-amplitude, amplitude)`.
    fn far_stream(prng: &mut SplitMix64, amplitude: f32, len: usize) -> Vec<i16> {
        (0..len)
            .map(|_| super::denormalize(prng.next_noise(amplitude)))
            .collect()
    }

    fn normalize(stream: &[i16]) -> Vec<f32> {
        stream
            .iter()
            .map(|&s| f32::from(s) / SAMPLE_SCALE)
            .collect()
    }

    fn power_i16(samples: &[i16]) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }
        let sum: f64 = samples.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
        sum / samples.len() as f64
    }

    /// ERLE (dB) = 10·log10(E[echo²] / E[residual²]).
    fn erle_db(echo: &[i16], residual: &[i16]) -> f64 {
        let echo_power = power_i16(echo);
        let residual_power = power_i16(residual).max(1.0e-9);
        10.0 * (echo_power / residual_power).log10()
    }

    #[test]
    fn rejects_invalid_sample_rate() {
        assert!(matches!(
            EchoCanceller::new(7_000, 256),
            Err(AecError::InvalidSampleRate(7_000))
        ));
        assert!(matches!(
            EchoCanceller::new(8_010, 256), // not a multiple of 50
            Err(AecError::InvalidSampleRate(8_010))
        ));
    }

    #[test]
    fn rejects_invalid_tail() {
        assert!(matches!(
            EchoCanceller::new(8_000, 0),
            Err(AecError::InvalidTail { got: 0, .. })
        ));
        assert!(matches!(
            EchoCanceller::new(8_000, MAX_TAIL_SAMPLES + 1),
            Err(AecError::InvalidTail { .. })
        ));
    }

    #[test]
    fn rejects_invalid_bulk_delay() {
        assert!(matches!(
            EchoCanceller::with_bulk_delay(8_000, 256, MAX_BULK_DELAY_SAMPLES + 1),
            Err(AecError::InvalidBulkDelay { .. })
        ));
    }

    #[test]
    fn accessors_report_configuration() {
        let canceller = EchoCanceller::with_bulk_delay(16_000, 512, 80).expect("build");
        assert_eq!(canceller.sample_rate_hz(), 16_000);
        assert_eq!(canceller.frame_samples(), 320);
        assert_eq!(canceller.tail_samples(), 512);
        assert_eq!(canceller.bulk_delay_samples(), 80);
        assert!(!canceller.double_talk_active());
    }

    #[test]
    fn empty_frame_is_a_noop() {
        let mut canceller = EchoCanceller::new(8_000, 256).expect("build");
        canceller.cancel(&mut [], &[]);
        assert!(!canceller.double_talk_active());
    }

    /// Golden ERLE: a converged filter cancels a committed synthetic echo by ≥ 20 dB, and reaches
    /// 20 dB inside a bounded frame count.
    #[test]
    fn converges_to_high_erle_on_synthetic_echo() {
        let tail = 256;
        let frame = 160;
        let frames = 200;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0xA1CE_2026);
        let mut canceller = EchoCanceller::new(8_000, tail).expect("build");

        // One continuous far-end stream and its echo, chunked into frames.
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);

        let mut converged_frame: Option<usize> = None;
        let mut steady_erle = f64::NAN;
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            let erle = erle_db(&echo[range], &mic);
            if converged_frame.is_none() && erle >= 20.0 {
                converged_frame = Some(index);
            }
            steady_erle = erle;
        }

        // White-noise excitation with a matched-length filter converges fast; frame 5 on this box.
        let converged = converged_frame.expect("filter must reach 20 dB ERLE");
        assert!(
            converged <= 20,
            "converged only after {converged} frames (>20)"
        );
        assert!(
            steady_erle >= 20.0,
            "steady-state ERLE {steady_erle:.1} dB < 20 dB"
        );
    }

    /// Double-talk: a well-converged filter must (a) freeze on scripted near-end so it does not
    /// diverge, (b) pass the near-end through with bounded echo leakage, and (c) recover ERLE once
    /// the near-end stops.
    #[test]
    fn double_talk_freezes_filter_and_recovers() {
        let tail = 256;
        let frame = 160;
        let converge_frames = 120;
        let double_talk_frames = 30;
        let recover_frames = 40;
        let total = converge_frames + double_talk_frames + recover_frames;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x00DD_BA11);
        let mut canceller = EchoCanceller::new(8_000, tail).expect("build");

        // Continuous far-end + echo for the whole scenario.
        let far = far_stream(&mut prng, 0.6, total * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        // A continuous near-end talker tone (~0.6 full-scale) present only during the middle phase.
        let near_talk: Vec<i16> = (0..total * frame)
            .map(|t| {
                super::denormalize(
                    0.6 * (2.0 * std::f32::consts::PI * 400.0 * t as f32 / 8_000.0).sin(),
                )
            })
            .collect();

        let frame_range = |index: usize| index * frame..(index + 1) * frame;

        // 1) Converge on pure echo.
        for index in 0..converge_frames {
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }
        let converged_weight_energy: f32 = canceller.weights().iter().map(|w| w * w).sum();

        // 2) Inject the near-end talker on top of the echo → double-talk.
        let mut near_leakage = 0.0f64;
        let mut near_power = 0.0f64;
        let mut double_talk_seen = false;
        for index in converge_frames..converge_frames + double_talk_frames {
            let range = frame_range(index);
            let talk = &near_talk[range.clone()];
            let mut mic: Vec<i16> = echo[range.clone()]
                .iter()
                .zip(talk)
                .map(|(&e, &s)| e.saturating_add(s))
                .collect();
            canceller.cancel(&mut mic, &far[range]);
            double_talk_seen |= canceller.double_talk_active();
            // Residual should track the near-end talker: bound the leakage energy.
            for (&residual, &s) in mic.iter().zip(talk) {
                let difference = f64::from(residual) - f64::from(s);
                near_leakage += difference * difference;
                near_power += f64::from(s) * f64::from(s);
            }
        }
        assert!(double_talk_seen, "Geigel detector must fire on double-talk");
        // The filter must not have run off learning the near-end talker.
        let after_weight_energy: f32 = canceller.weights().iter().map(|w| w * w).sum();
        assert!(
            after_weight_energy <= converged_weight_energy * 4.0,
            "filter diverged during double-talk: {converged_weight_energy} -> {after_weight_energy}"
        );
        // Near-end passes through: leakage ≥ ~12 dB below the near-end talker.
        let leakage_db = 10.0 * (near_leakage / near_power.max(1.0)).log10();
        assert!(
            leakage_db <= -12.0,
            "near-end leakage {leakage_db:.1} dB (want ≤ -12 dB)"
        );

        // 3) Near-end stops: ERLE recovers (weights survived the double-talk).
        let mut recovered = f64::NAN;
        for index in converge_frames + double_talk_frames..total {
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            recovered = erle_db(&echo[range], &mic);
        }
        assert!(
            recovered >= 20.0,
            "ERLE recovered to only {recovered:.1} dB after double-talk"
        );
    }

    /// Direct proof the Geigel detector *gates* the NLMS update: once the filter has learned some
    /// non-zero weights, a loud-near-end frame freezes them bit-for-bit; a single-talk frame changes
    /// them.
    #[test]
    fn geigel_gates_the_update() {
        let tail = 64;
        let frame = 160;
        let total = 80;
        let rir = build_rir(64);
        let mut prng = SplitMix64::new(0xBEEF_F00D);
        let mut canceller = EchoCanceller::new(8_000, tail).expect("build");

        let far = far_stream(&mut prng, 0.6, total * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        let frame_range = |index: usize| index * frame..(index + 1) * frame;

        // Converge on single-talk so the weights are non-zero (a meaningful freeze target).
        let mut next = 0;
        for index in 0..60 {
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
            next = index + 1;
        }
        let before: Vec<f32> = canceller.weights().to_vec();
        assert!(
            before.iter().any(|&w| w != 0.0),
            "filter should have adapted"
        );

        // Frame with a loud near-end tone (+ far-end reference) → double-talk → weights frozen.
        let range = frame_range(next);
        let mut near_loud: Vec<i16> = (0..frame)
            .map(|i| super::denormalize(0.9 * (i as f32 * 0.7).sin()))
            .collect();
        canceller.cancel(&mut near_loud, &far[range]);
        next += 1;
        assert!(canceller.double_talk_active(), "loud near-end must be DT");
        assert_eq!(
            before,
            canceller.weights(),
            "weights must be frozen during double-talk"
        );

        // Let the hangover expire, then a single-talk frame → adaptation runs → weights change.
        for _ in 0..DEFAULT_DOUBLETALK_HANGOVER_FRAMES {
            let range = frame_range(next);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
            next += 1;
        }
        let hangover_expired: Vec<f32> = canceller.weights().to_vec();
        let range = frame_range(next);
        let mut echo_only = echo[range.clone()].to_vec();
        canceller.cancel(&mut echo_only, &far[range]);
        assert!(!canceller.double_talk_active(), "single-talk is not DT");
        assert_ne!(
            hangover_expired,
            canceller.weights(),
            "weights must adapt during single-talk"
        );
    }

    /// Delay robustness: a bulk delay that pushes the echo entirely outside a short tail is
    /// uncancellable at zero delay, but the fixed-delay ring recovers ERLE when configured.
    #[test]
    fn fixed_bulk_delay_recovers_erle() {
        let tail = 64; // short tail: cannot by itself span a large transport delay
        let frame = 160;
        let bulk_delay = 128; // echo starts well past the tail
        let rir = build_rir(64);

        let frames = 200;
        let run = |canceller: &mut EchoCanceller, seed: u64| -> f64 {
            let mut prng = SplitMix64::new(seed);
            let far = far_stream(&mut prng, 0.6, frames * frame);
            let echo = synthesize_echo(&normalize(&far), &rir, bulk_delay);
            let mut erle = f64::NAN;
            for index in 0..frames {
                let range = index * frame..(index + 1) * frame;
                let mut mic = echo[range.clone()].to_vec();
                canceller.cancel(&mut mic, &far[range.clone()]);
                erle = erle_db(&echo[range], &mic);
            }
            erle
        };

        // Mis-configured (no bulk delay): the echo is out of the tail window → little cancellation.
        let mut naive = EchoCanceller::new(8_000, tail).expect("build");
        let naive_erle = run(&mut naive, 0x5EED_0001);
        assert!(
            naive_erle < 6.0,
            "zero-delay canceller unexpectedly cancelled a delayed echo ({naive_erle:.1} dB)"
        );

        // Correctly configured bulk delay: the ring pre-aligns the echo into the tail → recovers.
        let mut aligned = EchoCanceller::with_bulk_delay(8_000, tail, bulk_delay).expect("build");
        let aligned_erle = run(&mut aligned, 0x5EED_0001);
        assert!(
            aligned_erle >= 20.0,
            "bulk-delay canceller only reached {aligned_erle:.1} dB (want ≥ 20 dB)"
        );
    }

    /// Regression guard: the echo-subtracted residual of the first frame of a fixed single-talk
    /// scenario matches a committed golden vector within a small f32 tolerance. The weights start
    /// identical (zero), so the only cross-machine variance is the SIMD-vs-scalar `fir_dot_f32`
    /// rounding — bounded to a couple of LSBs. The ERLE/DTD tests above are the real acceptance
    /// criteria; this pins the exact numeric path against silent drift.
    #[test]
    fn golden_residual_matches_committed_vector() {
        let frame = 160;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x6010_0000);
        let mut canceller = EchoCanceller::new(8_000, 256).expect("build");
        let far = far_stream(&mut prng, 0.6, frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        let mut residual = echo;
        canceller.cancel(&mut residual, &far);

        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!("GOLDEN {residual:?}");
        }
        let max_abs = residual
            .iter()
            .zip(GOLDEN_RESIDUAL)
            .map(|(&r, g)| (i32::from(r) - i32::from(g)).abs())
            .max()
            .unwrap_or(i32::MAX);
        assert!(
            max_abs <= 4,
            "golden residual drift: max |Δ| = {max_abs} LSB (tolerance 4)"
        );
    }

    #[test]
    fn reset_restores_initial_state() {
        let frame = 160;
        let mut prng = SplitMix64::new(0x1234_5678);
        let mut canceller = EchoCanceller::new(8_000, 128).expect("build");
        let rir = build_rir(64);
        let far = far_stream(&mut prng, 0.6, 30 * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        for index in 0..30 {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }
        assert!(canceller.weights().iter().any(|&w| w != 0.0));
        canceller.reset();
        assert!(
            canceller.weights().iter().all(|&w| w == 0.0),
            "reset must zero the filter"
        );
        assert!(!canceller.double_talk_active());
    }

    /// A short frame (fewer samples than one 20 ms frame) is processed partially without panicking.
    #[test]
    fn short_frame_is_processed_partially() {
        let mut canceller = EchoCanceller::new(8_000, 64).expect("build");
        let mut near = vec![1000i16; 40];
        let reference = vec![2000i16; 40];
        canceller.cancel(&mut near, &reference);
        // No panic, no allocation blow-up; output is well-formed i16 (nothing to assert beyond that).
    }
}
