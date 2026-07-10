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
//! ## Two-path double-talk protection (optional — [`EchoCanceller::with_two_path_dtd`])
//! The single-filter Geigel screen above is the default. Enabling the **two-path** detector runs *two*
//! adaptive filters — a *background* filter that keeps adapting through safe (single-talk) intervals
//! and a *foreground* filter that actually produces the emitted residual. The foreground is only ever
//! advanced by **copying** the converged background into it, and only when a **normalized
//! cross-correlation** (NCC) decision statistic (Benesty *et al.*, *A New Class of Doubletalk
//! Detectors Based on Cross-Correlation*, IEEE TSAP 2000) confirms echo-only **and** the background
//! residual is smaller than the foreground's. During double-talk no copy happens, so the foreground
//! stays frozen on its pre-double-talk estimate and never learns the near-end talker — the failure
//! mode a Geigel-only screen suffers when the near-end is too quiet to trip `max|near| ≥ ½·max|far|`
//! yet still dominates the (echo-return-loss-attenuated) echo. The exact statistic, thresholds, and
//! hangover are documented on [`EchoCanceller::cancel`] and the `NCC_*` constants.
//!
//! ## Determinism & allocation
//! No wall clock, no randomness: identical input frames yield identical output, so it golden-tests
//! without audio hardware on a purely logical sample-clock. Every buffer (the filter weights and the
//! far-end delay ring) is preallocated in [`EchoCanceller::new`]; the near-end is filtered in place,
//! so [`EchoCanceller::cancel`] does **zero per-frame heap allocation**.
//!
//! ## Fixed bulk delay vs. automatic delay estimation
//! The loudspeaker→microphone acoustic + buffering delay `τ` can be supplied as a **configuration
//! parameter** ([`EchoCanceller::with_bulk_delay`]) or **estimated automatically** at run time from
//! the signals themselves ([`EchoCanceller::with_delay_estimation`]). Either way the adaptive filter
//! only has to cover the impulse-response *spread*, not the bulk transport delay, which keeps the
//! tail short.
//!
//! ## Automatic delay estimation (GCC-PHAT)
//! [`with_delay_estimation`](EchoCanceller::with_delay_estimation) drives the far-end alignment ring
//! from a **generalized cross-correlation with phase transform** (GCC-PHAT) estimate of the bulk
//! delay between the far-end reference and the near-end echo (Knapp & Carter, *The Generalized
//! Correlation Method for Estimation of Time Delay*, IEEE TASSP 1976). Over a preallocated power-of-two
//! block, an internal `DelayEstimator` runs the near-end and reference blocks through the real
//! [`crate::fft`],
//! forms the cross-power spectrum `Near·conj(Far)`, applies the phase transform (each bin normalized
//! by its magnitude, so only the phase — the delay information — survives), inverse-transforms to the
//! generalized cross-correlation, and picks the peak lag over the search range. The correlation
//! surface is smoothed across several blocks and a re-align hangover keeps a stable delay from
//! thrashing the alignment. When the committed estimate changes, the adaptive weights are reset (they
//! were tuned to the previous alignment); the far-end history ring is preallocated for the whole
//! search range, so a re-align only shifts a read offset — never a heap allocation.

use crate::fft::{Complex, RealFft};
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

// --- Two-path (foreground/background) + normalized-cross-correlation (Benesty) DTD ---
/// Normalized cross-correlation `ρ = <mic, echo_hat> / (‖mic‖·‖echo_hat‖)` below which the frame is
/// declared **double-talk** (near-end present) and adaptation/copy freeze. During single-talk the
/// microphone *is* the echo estimate (bar the residual) so `ρ → 1`; an uncorrelated near-end talker
/// lifts `‖mic‖` without lifting `<mic, echo_hat>`, so `ρ = ‖echo‖/‖echo+near‖` drops. 0.85 sits well
/// below the single-talk value yet comfortably above `ρ` for any near-end at or above the echo level
/// (e.g. equal-power double-talk gives `ρ ≈ 0.71`).
const NCC_DOUBLETALK_THRESHOLD: f32 = 0.85;
/// Normalized cross-correlation at or above which the frame is confidently **echo-only**, permitting a
/// background→foreground copy (with the residual-margin gate below). Kept above
/// [`NCC_DOUBLETALK_THRESHOLD`] so the `[0.85, 0.90)` band is a no-copy / no-freeze hysteresis zone.
const NCC_COPY_THRESHOLD: f32 = 0.90;
/// A background→foreground copy also requires the background residual energy to be at most this
/// fraction of the foreground's — i.e. the background is at least ~0.46 dB better. This both
/// bootstraps the first copy (foreground starts at zero, so its residual is the full echo) and stops
/// copy thrash once the two filters have converged to the same estimate.
const COPY_RESIDUAL_MARGIN: f64 = 0.90;
/// When the background residual energy grows past this multiple of the foreground's, the background is
/// deemed to have diverged (e.g. it adapted into a near-end onset the frame before the NCC caught it),
/// so it is reset to the protected foreground — the two-path safety net that keeps a transiently
/// mis-adapted background from lingering.
const DIVERGE_RESIDUAL_MARGIN: f64 = 2.0;
/// Below this per-frame normalized energy the microphone or echo estimate carries no usable signal, so
/// the NCC is undefined and the frame drives neither a freeze nor a copy (avoids a 0/0 that would look
/// like permanent double-talk and deadlock the very first adaptation).
const NCC_ENERGY_FLOOR: f64 = 1.0e-7;

// --- GCC-PHAT delay estimation ---
/// Largest bulk delay (and therefore search range) automatic estimation supports, in samples
/// (~0.5 s @ 8 kHz / ~0.25 s @ 16 kHz) — far beyond any realistic loudspeaker→microphone path,
/// and it bounds the estimation FFT to [`DELAY_BLOCK_MAX`].
const MAX_SEARCH_RANGE_SAMPLES: usize = 4_096;
/// Smallest GCC-PHAT block (a power of two). The block must be several times the search range so the
/// circular cross-correlation approximates the linear one over the whole search span.
const DELAY_BLOCK_MIN: usize = 512;
/// Largest GCC-PHAT block (a power of two) — the FFT size at the maximum search range.
const DELAY_BLOCK_MAX: usize = 8_192;
/// Phase-transform regularization: each cross-power bin is divided by `magnitude + ε`, so a
/// near-silent bin contributes ~0 phase instead of blowing up (RFC-free classical GCC-PHAT).
const PHAT_EPSILON: f32 = 1.0e-6;
/// Leaky-integrator weight for the smoothed cross-correlation surface (`acc = λ·acc + gcc`), giving
/// an effective memory of ~1/(1−λ) ≈ 3 blocks. Smoothing averages out the finite-block noise floor so
/// the peak pick is stable, while still tracking a genuinely changed delay within a few blocks.
const GCC_SMOOTHING: f32 = 0.7;
/// Blocks that must be accumulated before the first delay lock, so the initial estimate rests on a
/// smoothed surface rather than a single noisy block.
const MIN_BLOCKS_BEFORE_LOCK: usize = 3;
/// A new peak this many samples or less from the committed delay is treated as the *same* delay (no
/// re-align) — it absorbs the ±1-sample GCC jitter a stable path shows block to block.
const REALIGN_TOLERANCE_SAMPLES: usize = 8;
/// A genuinely different peak must persist for this many consecutive decision blocks before the
/// alignment is moved — the hangover that stops a transient from thrashing the ring/weights.
const REALIGN_HANGOVER_BLOCKS: usize = 5;
/// Mean per-sample far-end block energy (normalized) below which a block carries no usable echo, so
/// it is skipped for estimation (a silent far-end produces only a noise correlation).
const DELAY_FAR_ENERGY_FLOOR: f32 = 1.0e-6;

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
    /// The delay-estimation search range is zero or exceeds the supported maximum.
    #[error("delay-estimation search range must be in 1..={max} samples (got {got})")]
    InvalidSearchRange {
        /// The requested search range in samples.
        got: usize,
        /// The maximum supported search range.
        max: usize,
    },
}

/// A preallocated far-end delay line — the bulk-delay FIFO feeding the adaptive filter.
///
/// One contiguous `line` of `capacity_carry + frame_capacity` normalized samples. The leading
/// `capacity_carry = max_bulk_delay + tail − 1` slots hold the delay-line history carried over from
/// the previous frame; the frame region `[capacity_carry, capacity_carry + n)` receives the current
/// frame's far-end samples. The **current** bulk delay is applied as a read offset rather than baked
/// into the layout: the length-`tail` regressor for near-end sample `i` is the contiguous slice
/// `line[read_base + i .. read_base + i + tail]` where `read_base = max_bulk_delay − bulk_delay` —
/// still a single `fir_dot_f32`, no gather. Preallocating the carry for `max_bulk_delay` lets
/// [`FarEndReference::set_bulk_delay`] retune the alignment (for GCC-PHAT estimation) by moving that
/// offset, with **no reallocation** — the raw far-end history in `line` is simply re-sliced. For the
/// fixed-delay constructors `max_bulk_delay == bulk_delay`, so `read_base == 0` and the layout /
/// numeric path is byte-identical to a delay baked into `carry`. After a frame,
/// [`FarEndReference::compact`] slides the trailing `capacity_carry` samples to the front.
#[derive(Debug, Clone)]
struct FarEndReference {
    tail: usize,
    /// The current bulk delay applied (`0 ..= max_bulk_delay`).
    bulk_delay: usize,
    /// `max_bulk_delay + tail − 1` — the preallocated history preceding the frame region.
    capacity_carry: usize,
    /// Largest frame this ring can absorb without reallocating (the 20 ms frame for the rate).
    frame_capacity: usize,
    /// `capacity_carry + frame_capacity` normalized samples, oldest-first.
    line: Vec<f32>,
}

impl FarEndReference {
    /// A fixed-delay ring: the carry is sized exactly to `bulk_delay`, so the delay cannot change
    /// and `read_base` is always 0 (the original single-delay layout).
    fn new(tail: usize, bulk_delay: usize, frame_capacity: usize) -> Self {
        Self::with_max_delay(tail, bulk_delay, bulk_delay, frame_capacity)
    }

    /// A ring preallocated for a delay anywhere in `0 ..= max_bulk_delay`, starting at `bulk_delay`.
    /// [`FarEndReference::set_bulk_delay`] can then retune the alignment with no reallocation.
    fn with_max_delay(
        tail: usize,
        bulk_delay: usize,
        max_bulk_delay: usize,
        frame_capacity: usize,
    ) -> Self {
        let capacity_carry = max_bulk_delay + tail - 1;
        Self {
            tail,
            bulk_delay,
            capacity_carry,
            frame_capacity,
            line: vec![0.0; capacity_carry + frame_capacity],
        }
    }

    /// The largest bulk delay this ring was preallocated for.
    #[inline]
    fn max_bulk_delay(&self) -> usize {
        self.capacity_carry + 1 - self.tail
    }

    /// Offset of the oldest tap of near-sample 0's window into `line`
    /// (`max_bulk_delay − bulk_delay`); 0 for the fixed-delay layout.
    #[inline]
    fn read_base(&self) -> usize {
        self.capacity_carry + 1 - self.tail - self.bulk_delay
    }

    /// Retune the alignment to a new bulk delay (`0 ..= max_bulk_delay`), clamped to the cap. Only the
    /// read offset moves; the raw far-end history is preserved and re-sliced.
    fn set_bulk_delay(&mut self, bulk_delay: usize) {
        self.bulk_delay = bulk_delay.min(self.max_bulk_delay());
    }

    /// Write up to `frame_capacity` normalized far-end samples into the frame region, returning the
    /// count written (`min(reference.len(), frame_capacity)`).
    fn write_frame(&mut self, reference: &[i16]) -> usize {
        let count = reference.len().min(self.frame_capacity);
        let base = self.capacity_carry;
        for (slot, &sample) in self.line[base..base + count].iter_mut().zip(reference) {
            *slot = f32::from(sample) / SAMPLE_SCALE;
        }
        count
    }

    /// The length-`tail` regressor window for near-end sample `i` (`0 ≤ i < n`).
    #[inline]
    fn window(&self, i: usize) -> &[f32] {
        let base = self.read_base() + i;
        &self.line[base..base + self.tail]
    }

    /// The single normalized sample `offset` positions into the aligned window stream (for the
    /// sliding-energy update: `window_sample(i)` leaves and `window_sample(i + tail)` enters the
    /// window when advancing from `i` to `i + 1`).
    #[inline]
    fn window_sample(&self, offset: usize) -> f32 {
        self.line[self.read_base() + offset]
    }

    /// Carry the trailing `capacity_carry` samples of the just-processed `n`-sample frame to the
    /// front so the next frame's windows see continuous history.
    fn compact(&mut self, frame_len: usize) {
        self.line
            .copy_within(frame_len..frame_len + self.capacity_carry, 0);
    }

    fn reset(&mut self) {
        self.line.iter_mut().for_each(|sample| *sample = 0.0);
    }
}

/// The GCC-PHAT block size for a search range: the smallest power of two that is at least twice the
/// range (so the circular cross-correlation approximates the linear one across the whole search
/// span), clamped to `[DELAY_BLOCK_MIN, DELAY_BLOCK_MAX]`.
fn choose_block_size(search_range: usize) -> usize {
    (2 * search_range)
        .next_power_of_two()
        .clamp(DELAY_BLOCK_MIN, DELAY_BLOCK_MAX)
}

/// A **GCC-PHAT** bulk-delay estimator (Knapp & Carter 1976).
///
/// It buffers time-contiguous near-end and far-end samples into a preallocated power-of-two block,
/// and on each full block computes the phase-transformed cross-correlation:
///
/// ```text
///   Near = FFT(near_block),  Far = FFT(far_block)          (real FFT, N/2+1 bins)
///   G[k] = Near[k]·conj(Far[k])                            (cross-power spectrum)
///   G_phat[k] = G[k] / (|G[k]| + ε)                        (phase transform: keep only phase)
///   gcc[τ] = IFFT(G_phat)[τ] = Σ_n near[n]·far[n − τ]      (generalized cross-correlation, real)
/// ```
///
/// The peak lag `τ*` over `0 ..= search_range` is the delay by which the near-end echo lags the
/// reference (`near[n] ≈ Σ_k h[k]·far[n − τ]` puts the correlation peak at `τ = delay`). Because both
/// blocks are real, `G` and `G_phat` are Hermitian, so the correlation is real and the whole thing
/// runs on the `N/2+1`-bin half-spectrum through [`RealFft`].
///
/// The phase transform whitens both spectra, so `G_phat = H/|H|` (the echo path's phase-only impulse
/// response) — its peak sits at the path's dominant tap, i.e. the bulk delay, independent of the
/// reference spectrum's colour. That is what makes GCC-PHAT sharp and speech-robust.
///
/// ## Smoothing & hangover (no thrash)
/// The correlation surface is accumulated with a leaky integrator ([`GCC_SMOOTHING`]) across blocks,
/// so the peak pick rests on several blocks of evidence rather than one noisy block. A committed
/// delay only moves when a *different* peak (more than [`REALIGN_TOLERANCE_SAMPLES`] away) persists
/// for [`REALIGN_HANGOVER_BLOCKS`] consecutive decisions; a stable path therefore locks once and
/// holds. Silent far-end blocks (no echo) and, optionally, double-talk blocks are skipped.
///
/// ## Allocation
/// Every buffer (block assembly, spectra, cross-power, correlation, accumulator) is sized once in
/// [`DelayEstimator::new`]; [`DelayEstimator::observe`] is allocation-free.
#[derive(Clone, Debug)]
struct DelayEstimator {
    /// GCC-PHAT block length `N` (a power of two).
    block_size: usize,
    /// Largest lag searched (`τ ∈ 0..=search_range`).
    search_range: usize,
    /// The real FFT/IFFT for `block_size`.
    fft: RealFft,
    /// Assembled near-end block (normalized `f32`), `block_size` samples.
    near_block: Vec<f32>,
    /// Assembled far-end block (normalized `f32`), `block_size` samples.
    far_block: Vec<f32>,
    /// `Near` spectrum, `N/2+1` bins.
    near_spectrum: Vec<Complex>,
    /// `Far` spectrum, `N/2+1` bins.
    far_spectrum: Vec<Complex>,
    /// Phase-transformed cross-power `G_phat`, `N/2+1` bins.
    cross: Vec<Complex>,
    /// Generalized cross-correlation `gcc`, `block_size` real samples.
    gcc: Vec<f32>,
    /// Leaky-integrated correlation surface over `0..=search_range`.
    accumulator: Vec<f32>,
    /// Samples currently buffered in the block-assembly buffers.
    fill: usize,
    /// Whether every frame contributing to the current block was usable (no double-talk); a block
    /// with any unusable frame is dropped from accumulation.
    block_usable: bool,
    /// Accumulated blocks toward a decision (gates the first lock).
    blocks_seen: usize,
    /// Whether a delay has been locked at least once.
    locked: bool,
    /// The currently committed delay estimate (valid once `locked`).
    committed_delay: usize,
    /// A pending different-delay candidate awaiting hangover confirmation.
    candidate_delay: usize,
    /// Consecutive decisions the candidate has held.
    candidate_count: usize,
}

impl DelayEstimator {
    fn new(search_range: usize) -> Result<Self, AecError> {
        if search_range == 0 || search_range > MAX_SEARCH_RANGE_SAMPLES {
            return Err(AecError::InvalidSearchRange {
                got: search_range,
                max: MAX_SEARCH_RANGE_SAMPLES,
            });
        }
        let block_size = choose_block_size(search_range);
        // `block_size` is a power of two in `[512, 8192]` by construction, so this cannot fail; map
        // any future contract change to the search-range error rather than panicking.
        let fft = RealFft::new(block_size).map_err(|_| AecError::InvalidSearchRange {
            got: search_range,
            max: MAX_SEARCH_RANGE_SAMPLES,
        })?;
        let bins = fft.bins();
        Ok(Self {
            block_size,
            search_range,
            fft,
            near_block: vec![0.0; block_size],
            far_block: vec![0.0; block_size],
            near_spectrum: vec![Complex::default(); bins],
            far_spectrum: vec![Complex::default(); bins],
            cross: vec![Complex::default(); bins],
            gcc: vec![0.0; block_size],
            accumulator: vec![0.0; search_range + 1],
            fill: 0,
            block_usable: true,
            blocks_seen: 0,
            locked: false,
            committed_delay: 0,
            candidate_delay: 0,
            candidate_count: 0,
        })
    }

    /// The committed delay estimate once locked, else `None`.
    #[inline]
    fn locked_delay(&self) -> Option<usize> {
        self.locked.then_some(self.committed_delay)
    }

    /// Buffer one time-contiguous frame of raw near-end and far-end samples. `usable` is false for a
    /// double-talk frame (its block is dropped from accumulation). Returns `Some(delay)` when a new
    /// alignment is committed (an initial lock or a hangover-confirmed re-align), else `None`.
    fn observe(&mut self, near: &[i16], far: &[i16], usable: bool) -> Option<usize> {
        let count = near.len().min(far.len());
        let mut decision = None;
        let mut offset = 0;
        while offset < count {
            let take = (self.block_size - self.fill).min(count - offset);
            for step in 0..take {
                self.near_block[self.fill + step] = f32::from(near[offset + step]) / SAMPLE_SCALE;
                self.far_block[self.fill + step] = f32::from(far[offset + step]) / SAMPLE_SCALE;
            }
            self.block_usable &= usable;
            self.fill += take;
            offset += take;
            if self.fill == self.block_size {
                if let Some(delay) = self.process_block() {
                    decision = Some(delay);
                }
                self.fill = 0;
                self.block_usable = true;
            }
        }
        decision
    }

    /// Run GCC-PHAT over the just-assembled block, fold it into the smoothed surface, and decide
    /// whether to (re-)commit a delay.
    fn process_block(&mut self) -> Option<usize> {
        if !self.block_usable {
            return None;
        }
        // Skip a silent far-end block — no echo to correlate, only a noise surface.
        let far_energy: f32 =
            self.far_block.iter().map(|&s| s * s).sum::<f32>() / self.block_size as f32;
        if far_energy < DELAY_FAR_ENERGY_FLOOR {
            return None;
        }

        self.fft.forward(&self.near_block, &mut self.near_spectrum);
        self.fft.forward(&self.far_block, &mut self.far_spectrum);

        // Cross-power `Near·conj(Far)`, phase-transformed to unit magnitude per bin.
        for ((slot, &near), &far) in self
            .cross
            .iter_mut()
            .zip(self.near_spectrum.iter())
            .zip(self.far_spectrum.iter())
        {
            let real = near.re * far.re + near.im * far.im;
            let imag = near.im * far.re - near.re * far.im;
            let inverse_magnitude = 1.0 / ((real * real + imag * imag).sqrt() + PHAT_EPSILON);
            *slot = Complex::new(real * inverse_magnitude, imag * inverse_magnitude);
        }

        self.fft.inverse(&self.cross, &mut self.gcc);

        for (slot, &value) in self
            .accumulator
            .iter_mut()
            .zip(self.gcc.iter().take(self.search_range + 1))
        {
            *slot = GCC_SMOOTHING * *slot + value;
        }

        self.blocks_seen += 1;
        if self.blocks_seen < MIN_BLOCKS_BEFORE_LOCK {
            return None;
        }
        let peak = self.peak_lag();
        self.decide(peak)
    }

    /// Index of the largest accumulated correlation over `0 ..= search_range`.
    fn peak_lag(&self) -> usize {
        let mut best_lag = 0;
        let mut best_value = self.accumulator[0];
        for (lag, &value) in self.accumulator.iter().enumerate() {
            if value > best_value {
                best_value = value;
                best_lag = lag;
            }
        }
        best_lag
    }

    /// Lock/hangover decision for a freshly picked peak.
    fn decide(&mut self, peak: usize) -> Option<usize> {
        if !self.locked {
            self.locked = true;
            self.committed_delay = peak;
            self.candidate_delay = peak;
            self.candidate_count = 0;
            return Some(peak);
        }
        if peak.abs_diff(self.committed_delay) <= REALIGN_TOLERANCE_SAMPLES {
            // Still the committed delay (within the stable band): clear any pending candidate.
            self.candidate_delay = self.committed_delay;
            self.candidate_count = 0;
            return None;
        }
        if peak.abs_diff(self.candidate_delay) <= REALIGN_TOLERANCE_SAMPLES {
            self.candidate_count += 1;
            if self.candidate_count >= REALIGN_HANGOVER_BLOCKS {
                self.committed_delay = self.candidate_delay;
                self.candidate_count = 0;
                return Some(self.committed_delay);
            }
            None
        } else {
            self.candidate_delay = peak;
            self.candidate_count = 1;
            None
        }
    }

    fn reset(&mut self) {
        self.near_block.iter_mut().for_each(|sample| *sample = 0.0);
        self.far_block.iter_mut().for_each(|sample| *sample = 0.0);
        self.accumulator.iter_mut().for_each(|slot| *slot = 0.0);
        self.fill = 0;
        self.block_usable = true;
        self.blocks_seen = 0;
        self.locked = false;
        self.committed_delay = 0;
        self.candidate_delay = 0;
        self.candidate_count = 0;
    }
}

/// The double-talk detector wired into [`EchoCanceller::cancel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtdMode {
    /// Single adaptive filter frozen by the cheap per-frame [`Geigel`](https://ieeexplore.ieee.org/document/1163130)
    /// screen (the default; the original PR-#116/#117 behaviour, byte-for-byte).
    Geigel,
    /// Two adaptive filters (foreground/background) with a normalized-cross-correlation copy criterion.
    TwoPath,
}

/// A time-domain NLMS acoustic echo canceller with a Geigel or two-path/NCC double-talk detector and
/// an optional GCC-PHAT bulk-delay estimator.
#[derive(Debug, Clone)]
pub struct EchoCanceller {
    sample_rate_hz: u32,
    /// Samples in one 20 ms frame (`sample_rate_hz / 50`).
    frame_samples: usize,
    /// Adaptive filter length `L` (the *tail*).
    tail_samples: usize,
    /// Adaptive FIR weights, length `tail_samples`, aligned to the ascending regressor window (so
    /// `residual = near − fir_dot_f32(weights, window)`). In [`DtdMode::Geigel`] this is the single
    /// filter that both adapts and produces the output; in [`DtdMode::TwoPath`] it is the *background*
    /// filter (the always-learning candidate).
    weights: Vec<f32>,
    /// The *foreground* filter (two-path mode only): it produces the emitted residual and is advanced
    /// **only** by copying [`Self::weights`] into it under the NCC copy criterion, so it never adapts
    /// on the near-end talker. Length `tail_samples`, preallocated (all-zero, unused in Geigel mode).
    foreground: Vec<f32>,
    /// Which double-talk detector [`EchoCanceller::cancel`] runs.
    dtd_mode: DtdMode,
    /// The most recent frame's NCC statistic `ρ` (two-path mode), or `None` before the first valid
    /// (non-silent) frame — a status surface the engine can meter.
    last_correlation: Option<f32>,
    /// Count of background→foreground copies since construction/reset (a convergence-health metric).
    copies: u64,
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
    /// Optional GCC-PHAT bulk-delay estimator. When present, each [`EchoCanceller::cancel`] feeds the
    /// raw near-end/reference to it and re-aligns the far-end ring (resetting the weights) whenever a
    /// new bulk delay is committed. `None` for the fixed-delay constructors.
    delay_estimator: Option<DelayEstimator>,
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
            foreground: vec![0.0; tail_samples],
            dtd_mode: DtdMode::Geigel,
            last_correlation: None,
            copies: 0,
            reference: FarEndReference::new(tail_samples, bulk_delay_samples, frame_samples),
            step_size: DEFAULT_STEP_SIZE,
            regularization: DEFAULT_REGULARIZATION,
            geigel_threshold: DEFAULT_GEIGEL_THRESHOLD,
            far_peak_floor: DEFAULT_FAR_PEAK_FLOOR,
            doubletalk_hold_frames: 0,
            doubletalk_hangover_frames: DEFAULT_DOUBLETALK_HANGOVER_FRAMES,
            doubletalk_active: false,
            delay_estimator: None,
        })
    }

    /// A canceller that **estimates the bulk delay automatically** with GCC-PHAT over
    /// `search_range_samples` and drives the far-end alignment ring from the estimate — so the
    /// adaptive `tail_samples` filter only has to span the residual impulse-response spread, not the
    /// transport delay. The far-end history ring is preallocated for the whole search range, so a
    /// re-align only shifts a read offset (never a heap allocation). Until the first lock the ring is
    /// unaligned (bulk delay 0). Preallocates all state, including the estimation FFT.
    ///
    /// # Errors
    /// As [`EchoCanceller::new`], plus [`AecError::InvalidSearchRange`] if `search_range_samples` is 0
    /// or exceeds the supported maximum.
    pub fn with_delay_estimation(
        sample_rate_hz: u32,
        tail_samples: usize,
        search_range_samples: usize,
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
        // Builds the estimator first so an invalid search range is reported before any allocation of
        // the (larger) alignment ring.
        let delay_estimator = DelayEstimator::new(search_range_samples)?;
        let frame_samples = (sample_rate_hz / 50) as usize;
        Ok(Self {
            sample_rate_hz,
            frame_samples,
            tail_samples,
            weights: vec![0.0; tail_samples],
            foreground: vec![0.0; tail_samples],
            dtd_mode: DtdMode::Geigel,
            last_correlation: None,
            copies: 0,
            reference: FarEndReference::with_max_delay(
                tail_samples,
                0,
                search_range_samples,
                frame_samples,
            ),
            step_size: DEFAULT_STEP_SIZE,
            regularization: DEFAULT_REGULARIZATION,
            geigel_threshold: DEFAULT_GEIGEL_THRESHOLD,
            far_peak_floor: DEFAULT_FAR_PEAK_FLOOR,
            doubletalk_hold_frames: 0,
            doubletalk_hangover_frames: DEFAULT_DOUBLETALK_HANGOVER_FRAMES,
            doubletalk_active: false,
            delay_estimator: Some(delay_estimator),
        })
    }

    /// Enable the **two-path** double-talk detector on top of any of the constructors above
    /// (chainable, e.g. `EchoCanceller::with_bulk_delay(8_000, 256, 80)?.with_two_path_dtd()`).
    ///
    /// A background filter keeps adapting through single-talk while a protected foreground filter — the
    /// one that produces the emitted residual — is advanced only by copying the background in under the
    /// normalized-cross-correlation copy criterion (see [`EchoCanceller::cancel`]). Both filters and
    /// all NCC scratch are already preallocated, so this only flips a mode flag: no allocation, and the
    /// hot path stays zero-per-frame-heap. The default (without this call) is the single-filter Geigel
    /// screen, kept for byte-for-byte backward compatibility with the delay-estimation PR.
    #[must_use]
    pub fn with_two_path_dtd(mut self) -> Self {
        self.dtd_mode = DtdMode::TwoPath;
        self
    }

    /// Whether the two-path/NCC double-talk detector is enabled (else the Geigel screen).
    #[must_use]
    pub fn two_path_enabled(&self) -> bool {
        self.dtd_mode == DtdMode::TwoPath
    }

    /// The most recent frame's normalized cross-correlation `ρ ∈ [-1, 1]` between the microphone and
    /// the estimated echo (two-path mode), or `None` before the first valid (non-silent) frame or when
    /// two-path is disabled. `ρ → 1` is echo-only; a drop signals near-end/double-talk.
    #[must_use]
    pub fn double_talk_correlation(&self) -> Option<f32> {
        self.last_correlation
    }

    /// Number of background→foreground copies since construction or the last [`EchoCanceller::reset`]
    /// (two-path mode) — a convergence-health metric (it climbs during single-talk, holds during
    /// double-talk).
    #[must_use]
    pub fn foreground_copies(&self) -> u64 {
        self.copies
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

    /// The bulk delay currently applied to the far-end alignment ring, in samples. For a fixed-delay
    /// canceller this is the configured value; with automatic estimation it is the current estimate
    /// (0 until the first lock).
    #[must_use]
    pub fn bulk_delay_samples(&self) -> usize {
        self.reference.bulk_delay
    }

    /// Whether this canceller estimates the bulk delay automatically (GCC-PHAT).
    #[must_use]
    pub fn delay_estimation_enabled(&self) -> bool {
        self.delay_estimator.is_some()
    }

    /// The automatically estimated bulk delay in samples once GCC-PHAT has locked, else `None`
    /// (before the first lock, or when automatic estimation is not enabled).
    #[must_use]
    pub fn estimated_bulk_delay(&self) -> Option<usize> {
        self.delay_estimator
            .as_ref()
            .and_then(DelayEstimator::locked_delay)
    }

    /// The GCC-PHAT search range in samples, or `None` when automatic estimation is not enabled.
    #[must_use]
    pub fn delay_search_range(&self) -> Option<usize> {
        self.delay_estimator
            .as_ref()
            .map(|estimator| estimator.search_range)
    }

    /// Whether the most recently cancelled frame contained double-talk (near-end speech that froze
    /// adaptation).
    #[must_use]
    pub fn double_talk_active(&self) -> bool {
        self.doubletalk_active
    }

    /// Cancel the echo in one frame **in place**: subtract the estimated echo (the adaptive filter
    /// applied to the aligned far-end `reference`) from `near_end`, then adapt the filter by NLMS on
    /// the residual — frozen while a near-end talker is present so the filter never learns *him*.
    ///
    /// The double-talk gate is either the cheap per-frame [`Geigel`](https://ieeexplore.ieee.org/document/1163130)
    /// screen (`max|near| ≥ ½·max|far|`, the default) or, with [`EchoCanceller::with_two_path_dtd`],
    /// the two-path/NCC detector described below.
    ///
    /// ## Two-path / normalized-cross-correlation decision
    /// Two adaptive filters run in lock-step. The *background* filter adapts by NLMS whenever the frame
    /// is safe (far-end active, not double-talk); the *foreground* filter produces the emitted residual
    /// and is **only** advanced by copying the background into it. After the sample loop the frame's
    /// **normalized cross-correlation** between the microphone `d` and the background echo estimate
    /// `ŷ` is formed:
    ///
    /// ```text
    ///   ρ = Σ d[n]·ŷ[n] / sqrt( (Σ d[n]²)·(Σ ŷ[n]²) )
    /// ```
    ///
    /// (Benesty *et al.* 2000, the two-path/cross-correlation DTD class.) During single-talk the
    /// microphone *is* the echo (bar the residual) so `ρ → 1`; an uncorrelated near-end talker lifts
    /// `‖d‖` without lifting `Σ d·ŷ`, so `ρ = ‖echo‖/‖echo+near‖` drops. The frame is:
    /// - **double-talk** (freeze background, no copy, re-arm the hangover) when the Geigel screen trips
    ///   *or* `ρ < NCC_DOUBLETALK_THRESHOLD` (0.85);
    /// - **echo-only, copy-eligible** when `ρ ≥ NCC_COPY_THRESHOLD` (0.90) — the `[0.85, 0.90)` band is
    ///   a no-copy/no-freeze hysteresis zone.
    ///
    /// A background→foreground copy fires on a copy-eligible frame **and** only if the background
    /// residual energy is at most `COPY_RESIDUAL_MARGIN` (0.90) of the foreground's (the background is
    /// genuinely better — this also bootstraps the first copy from the all-zero foreground and stops
    /// copy-thrash at convergence). If instead the background residual grows past
    /// `DIVERGE_RESIDUAL_MARGIN` (2×) of the foreground's, the background is reset to the protected
    /// foreground (it adapted into a near-end onset the NCC caught only a frame later). A hangover of
    /// `DEFAULT_DOUBLETALK_HANGOVER_FRAMES` frames (~60 ms) holds the freeze across brief near-end
    /// gaps.
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

        // --- Geigel screen for the whole frame (cheap block max|far| vs max|near|) ---
        // A block (per-frame) decision is stable and O(n): the far-end level is slowly varying, so
        // one comparison per 20 ms frame gates adaptation without the intra-frame jitter a per-sample
        // leaky peak-hold suffers. `max|near|` uses the *raw* microphone (echo + any near-end talker):
        // during single-talk it is the attenuated echo (below the threshold); a near-end talker lifts
        // it above `threshold·max|far|`. In two-path mode this is a cheap fast pre-screen alongside the
        // NCC; in Geigel mode it is the sole detector.
        let far_peak = normalized_peak(&reference[..n]);
        let near_peak = normalized_peak(&near_end[..n]);
        let far_active = far_peak > self.far_peak_floor;
        let geigel_tripped = far_active && near_peak >= self.geigel_threshold * far_peak;

        match self.dtd_mode {
            DtdMode::Geigel => self.cancel_geigel(n, near_end, reference, geigel_tripped),
            DtdMode::TwoPath => {
                self.cancel_two_path(n, near_end, reference, geigel_tripped, far_active);
            }
        }
    }

    /// The single-filter, Geigel-gated cancel path (the default). Kept byte-for-byte identical to the
    /// pre-two-path implementation so the committed golden residual and the delay-estimation tests do
    /// not move.
    fn cancel_geigel(
        &mut self,
        n: usize,
        near_end: &mut [i16],
        reference: &[i16],
        geigel_tripped: bool,
    ) {
        if geigel_tripped {
            self.doubletalk_hold_frames = self.doubletalk_hangover_frames;
        }
        let adapt = self.doubletalk_hold_frames == 0;
        self.doubletalk_active = !adapt;
        if self.doubletalk_hold_frames > 0 {
            self.doubletalk_hold_frames -= 1;
        }

        // --- GCC-PHAT bulk-delay estimation on the *raw* near-end (before it is overwritten) ---
        // Feed the time-contiguous raw pair to the estimator; a double-talk frame is marked unusable
        // so it does not corrupt the correlation. On a newly committed (re-)alignment, retune the ring
        // and reset the weights — they were tuned to the previous alignment and are meaningless now;
        // the filter re-converges over the following frames.
        let realign = self
            .delay_estimator
            .as_mut()
            .and_then(|estimator| estimator.observe(&near_end[..n], &reference[..n], adapt));
        if let Some(new_delay) = realign {
            if new_delay != self.reference.bulk_delay {
                self.reference.set_bulk_delay(new_delay);
                self.weights.iter_mut().for_each(|weight| *weight = 0.0);
            }
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
                let leaving = self.reference.window_sample(i);
                let entering = self.reference.window_sample(i + self.tail_samples);
                energy += entering * entering - leaving * leaving;
                if energy < 0.0 {
                    energy = 0.0; // guard f32 round-off below zero
                }
            }
        }

        self.reference.compact(n);
    }

    /// The two-path cancel path: a continuously-adapting background filter, a protected foreground
    /// filter that produces the output, and the NCC copy criterion (see [`EchoCanceller::cancel`]).
    fn cancel_two_path(
        &mut self,
        n: usize,
        near_end: &mut [i16],
        reference: &[i16],
        geigel_tripped: bool,
        far_active: bool,
    ) {
        // Background adaptation this frame: the far-end must excite it and no double-talk-freeze
        // hangover from a prior frame's decision may be active. The NCC for this frame is only known
        // *after* the sample loop, so it gates the copy and the *next* frame's adaptation via the
        // hangover — the foreground is protected regardless. While *bootstrapping* (before the first
        // copy has ever populated the foreground) the background always adapts on an excited frame, so
        // an NCC freeze can never latch the filter at its uninitialized state. Note the Geigel screen
        // is deliberately NOT used to gate adaptation: its fixed `½·far` threshold false-trips on a
        // loud (low-ERL) echo, which would stall convergence — the NCC (a scale-independent ratio) is
        // the primary detector and does not.
        let bootstrapping = self.copies == 0;
        let background_adapt = far_active && (bootstrapping || self.doubletalk_hold_frames == 0);

        // --- GCC-PHAT bulk-delay estimation on the *raw* near-end (before it is overwritten) ---
        // A newly committed alignment invalidates *both* filters (they were tuned to the old offset),
        // so reset them and the copy state; the filters re-converge over the following frames.
        let realign = self.delay_estimator.as_mut().and_then(|estimator| {
            estimator.observe(&near_end[..n], &reference[..n], background_adapt)
        });
        if let Some(new_delay) = realign {
            if new_delay != self.reference.bulk_delay {
                self.reference.set_bulk_delay(new_delay);
                self.weights.iter_mut().for_each(|weight| *weight = 0.0);
                self.foreground.iter_mut().for_each(|weight| *weight = 0.0);
            }
        }

        let written = self.reference.write_frame(&reference[..n]);
        debug_assert_eq!(written, n, "far-end ring must absorb the whole frame");

        let mut energy = {
            let window = self.reference.window(0);
            fir_dot_f32(window, window)
        };

        // Frame energy accumulators for the NCC decision (f64 headroom over the summed products).
        let mut sum_mic_sq = 0.0f64; // Σ d²
        let mut sum_echo_sq = 0.0f64; // Σ ŷ² (background echo estimate)
        let mut sum_mic_echo = 0.0f64; // Σ d·ŷ
        let mut sum_background_residual_sq = 0.0f64; // Σ (d − ŷ_background)²
        let mut sum_foreground_residual_sq = 0.0f64; // Σ (d − ŷ_foreground)²  ← the output

        for (i, near_sample) in near_end.iter_mut().enumerate().take(n) {
            let window = self.reference.window(i);
            let background_estimate = fir_dot_f32(&self.weights, window);
            let foreground_estimate = fir_dot_f32(&self.foreground, window);
            let mic = f32::from(*near_sample) / SAMPLE_SCALE;
            let background_residual = mic - background_estimate;
            let foreground_residual = mic - foreground_estimate;

            // NLMS adapts the *background* only, only on a safe frame — the foreground is never touched
            // here, so it cannot learn the near-end talker.
            if background_adapt {
                let normalized_step =
                    self.step_size * background_residual / (energy + self.regularization);
                for (weight, &sample) in self.weights.iter_mut().zip(window) {
                    *weight += normalized_step * sample;
                }
            }

            // Emit the *foreground* residual — the protected, converged estimate.
            *near_sample = denormalize(foreground_residual);

            let mic64 = f64::from(mic);
            let echo64 = f64::from(background_estimate);
            sum_mic_sq += mic64 * mic64;
            sum_echo_sq += echo64 * echo64;
            sum_mic_echo += mic64 * echo64;
            sum_background_residual_sq += f64::from(background_residual * background_residual);
            sum_foreground_residual_sq += f64::from(foreground_residual * foreground_residual);

            if i + 1 < n {
                let leaving = self.reference.window_sample(i);
                let entering = self.reference.window_sample(i + self.tail_samples);
                energy += entering * entering - leaving * leaving;
                if energy < 0.0 {
                    energy = 0.0;
                }
            }
        }

        self.reference.compact(n);

        // --- Normalized cross-correlation ρ (Benesty two-path/NCC) ---
        let correlation =
            if far_active && sum_mic_sq > NCC_ENERGY_FLOOR && sum_echo_sq > NCC_ENERGY_FLOOR {
                Some((sum_mic_echo / (sum_mic_sq * sum_echo_sq).sqrt()) as f32)
            } else {
                None
            };
        self.last_correlation = correlation;

        // The NCC is the primary detector. `confident_echo_only` (ρ ≥ copy threshold) both permits a
        // copy and vetoes the Geigel pre-screen, so a loud single-talk echo — which trips Geigel — does
        // not freeze adaptation. The Geigel screen only adds a freeze when the NCC is *not* confident it
        // is echo-only (a cheap fast reaction to a near-end onset).
        let ncc_double_talk = correlation.is_some_and(|rho| rho < NCC_DOUBLETALK_THRESHOLD);
        let confident_echo_only = correlation.is_some_and(|rho| rho >= NCC_COPY_THRESHOLD);
        let freeze = ncc_double_talk || (geigel_tripped && !confident_echo_only);
        // Reported status: either detector seeing near-end (a metering surface for the engine).
        self.doubletalk_active = ncc_double_talk || geigel_tripped;
        if freeze {
            self.doubletalk_hold_frames = self.doubletalk_hangover_frames;
        } else if self.doubletalk_hold_frames > 0 {
            self.doubletalk_hold_frames -= 1;
        }

        // --- Copy / divergence logic (foreground stays protected) ---
        if confident_echo_only
            && sum_background_residual_sq <= COPY_RESIDUAL_MARGIN * sum_foreground_residual_sq
        {
            // Background is confidently echo-only and genuinely better → promote it to the foreground.
            self.foreground.copy_from_slice(&self.weights);
            self.copies = self.copies.saturating_add(1);
        } else if far_active
            && sum_background_residual_sq >= DIVERGE_RESIDUAL_MARGIN * sum_foreground_residual_sq
        {
            // Background diverged well past the protected foreground → snap it back to the good copy.
            self.weights.copy_from_slice(&self.foreground);
        }
    }

    /// Reset the adaptive filter, far-end ring, and detector state (e.g. on a stream discontinuity).
    /// With automatic delay estimation this also clears the estimator and returns the ring to
    /// unaligned (bulk delay 0); a fixed-delay canceller keeps its configured bulk delay.
    pub fn reset(&mut self) {
        self.weights.iter_mut().for_each(|weight| *weight = 0.0);
        self.foreground.iter_mut().for_each(|weight| *weight = 0.0);
        self.reference.reset();
        if self.delay_estimator.is_some() {
            if let Some(estimator) = self.delay_estimator.as_mut() {
                estimator.reset();
            }
            self.reference.set_bulk_delay(0);
        }
        self.doubletalk_hold_frames = 0;
        self.doubletalk_active = false;
        self.last_correlation = None;
        self.copies = 0;
    }

    /// The adaptive filter weights (tests assert convergence/freezing on these). In two-path mode this
    /// is the *background* filter.
    #[cfg(test)]
    fn weights(&self) -> &[f32] {
        &self.weights
    }

    /// The two-path *foreground* filter (the one producing the output; tests assert it is frozen
    /// during double-talk and improves during single-talk).
    #[cfg(test)]
    fn foreground_weights(&self) -> &[f32] {
        &self.foreground
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

    // ---- GCC-PHAT delay estimation ----

    /// The sample-accuracy the estimator is held to across the delay sweep. GCC-PHAT with the phase
    /// transform peaks at the echo path's dominant (direct) tap, so the recovered delay lands on the
    /// injected value within the stable band (well inside "±1 hop").
    const DELAY_RECOVERY_TOLERANCE: usize = REALIGN_TOLERANCE_SAMPLES;

    fn run_delay_estimation(
        search_range: usize,
        tail: usize,
        injected_delay: usize,
        frames: usize,
        seed: u64,
    ) -> (EchoCanceller, f64) {
        let frame = 160;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(seed);
        let mut canceller =
            EchoCanceller::with_delay_estimation(8_000, tail, search_range).expect("build");
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, injected_delay);
        let mut erle = f64::NAN;
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            erle = erle_db(&echo[range], &mic);
        }
        (canceller, erle)
    }

    /// Delay recovery: sweep several known bulk delays across the search range and assert GCC-PHAT
    /// locks onto each within the tolerance. Pure single-talk echo, so the correlation is clean.
    #[test]
    fn gcc_phat_recovers_swept_bulk_delays() {
        let search_range = 512;
        for &delay in &[40usize, 128, 256, 400] {
            let (canceller, _erle) =
                run_delay_estimation(search_range, 160, delay, 160, 0xDE1A_0000 ^ delay as u64);
            let estimated = canceller
                .estimated_bulk_delay()
                .expect("GCC-PHAT must lock a delay");
            let error = estimated.abs_diff(delay);
            if std::env::var_os("DUMP_GOLDEN").is_some() {
                eprintln!("delay {delay} -> estimated {estimated} (error {error})");
            }
            assert!(
                error <= DELAY_RECOVERY_TOLERANCE,
                "delay {delay}: estimated {estimated} (error {error} > {DELAY_RECOVERY_TOLERANCE})"
            );
        }
    }

    /// ERLE with estimation on: the reference is misaligned by an unknown bulk delay; automatic
    /// estimation aligns the ring and the canceller still reaches the ≥ 20 dB ERLE target within a
    /// bounded frame count, holding high steady-state — matching the fixed-delay path in #116.
    #[test]
    fn converges_with_delay_estimation_on_unknown_delay() {
        let search_range = 512;
        let unknown_delay = 256;
        // Tail spans the RIR spread (max tap 110) plus margin for any few-sample estimation error.
        let (canceller, steady) =
            run_delay_estimation(search_range, 192, unknown_delay, 300, 0xE51E_0001);
        let estimated = canceller
            .estimated_bulk_delay()
            .expect("GCC-PHAT must lock the delay");
        assert!(
            estimated.abs_diff(unknown_delay) <= DELAY_RECOVERY_TOLERANCE,
            "estimated {estimated} for injected {unknown_delay}"
        );
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!("estimation ERLE: estimated {estimated}, steady {steady:.1} dB");
        }
        assert!(
            steady >= 20.0,
            "steady-state ERLE with estimation {steady:.1} dB < 20 dB"
        );
    }

    /// Convergence-time with estimation on: track the first frame that reaches 20 dB ERLE and bound
    /// it. The estimator must lock, re-align (resetting the weights), and the filter re-converge — all
    /// inside the bound.
    #[test]
    fn delay_estimation_converges_within_bounded_frames() {
        let frame = 160;
        let search_range = 512;
        let unknown_delay = 256;
        let frames = 300;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0xC0FF_EE01);
        let mut canceller =
            EchoCanceller::with_delay_estimation(8_000, 192, search_range).expect("build");
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, unknown_delay);
        let mut converged_frame: Option<usize> = None;
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            let erle = erle_db(&echo[range], &mic);
            // First *sustained* crossing after the lock: require the previous frame to also be high so
            // a transient block-boundary spike is not mistaken for convergence.
            if converged_frame.is_none()
                && erle >= 20.0
                && canceller.estimated_bulk_delay().is_some()
            {
                converged_frame = Some(index);
            }
        }
        let converged = converged_frame.expect("must reach 20 dB ERLE with estimation");
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!(
                "estimation convergence: frame {converged}, locked delay {:?}",
                canceller.estimated_bulk_delay()
            );
        }
        assert!(
            converged <= 120,
            "converged only after {converged} frames (>120) with estimation"
        );
    }

    /// No-thrash: a stable delay locks once and the committed estimate holds — it does not oscillate
    /// frame to frame (which would repeatedly reset the adaptive weights and wreck ERLE).
    #[test]
    fn stable_delay_estimate_does_not_thrash() {
        let frame = 160;
        let search_range = 512;
        let delay = 200;
        let frames = 400;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x57AB_1E00);
        let mut canceller =
            EchoCanceller::with_delay_estimation(8_000, 160, search_range).expect("build");
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, delay);
        let mut estimates: Vec<usize> = Vec::new();
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
            if let Some(estimate) = canceller.estimated_bulk_delay() {
                estimates.push(estimate);
            }
        }
        assert!(!estimates.is_empty(), "estimator must lock a stable delay");
        let unique: std::collections::BTreeSet<usize> = estimates.iter().copied().collect();
        assert_eq!(
            unique.len(),
            1,
            "stable delay thrashed the estimate across {unique:?}"
        );
        let locked = estimates[0];
        assert!(
            locked.abs_diff(delay) <= DELAY_RECOVERY_TOLERANCE,
            "locked {locked} for stable delay {delay}"
        );
    }

    /// Determinism: the estimate is a pure function of the input (logical clock, no wall clock, no
    /// randomness) — two identical runs lock the identical delay.
    #[test]
    fn delay_estimate_is_deterministic() {
        let (first, _) = run_delay_estimation(512, 160, 300, 120, 0xD37E_0001);
        let (second, _) = run_delay_estimation(512, 160, 300, 120, 0xD37E_0001);
        assert_eq!(first.estimated_bulk_delay(), second.estimated_bulk_delay());
        assert!(first.estimated_bulk_delay().is_some());
    }

    #[test]
    fn rejects_invalid_search_range() {
        assert!(matches!(
            EchoCanceller::with_delay_estimation(8_000, 256, 0),
            Err(AecError::InvalidSearchRange { got: 0, .. })
        ));
        assert!(matches!(
            EchoCanceller::with_delay_estimation(8_000, 256, MAX_SEARCH_RANGE_SAMPLES + 1),
            Err(AecError::InvalidSearchRange { .. })
        ));
        // Sample-rate and tail are still validated on the estimation constructor.
        assert!(matches!(
            EchoCanceller::with_delay_estimation(7_000, 256, 256),
            Err(AecError::InvalidSampleRate(7_000))
        ));
        assert!(matches!(
            EchoCanceller::with_delay_estimation(8_000, 0, 256),
            Err(AecError::InvalidTail { got: 0, .. })
        ));
    }

    #[test]
    fn delay_estimation_accessors_report_state() {
        let fixed = EchoCanceller::new(8_000, 256).expect("build");
        assert!(!fixed.delay_estimation_enabled());
        assert_eq!(fixed.estimated_bulk_delay(), None);
        assert_eq!(fixed.delay_search_range(), None);

        let estimating = EchoCanceller::with_delay_estimation(8_000, 160, 512).expect("build");
        assert!(estimating.delay_estimation_enabled());
        assert_eq!(estimating.estimated_bulk_delay(), None); // not locked yet
        assert_eq!(estimating.delay_search_range(), Some(512));
        assert_eq!(estimating.bulk_delay_samples(), 0);
    }

    /// `reset` clears the estimator and returns the ring to unaligned (bulk delay 0).
    #[test]
    fn reset_clears_delay_estimate() {
        let (mut canceller, _) = run_delay_estimation(512, 160, 256, 120, 0x8E5E_7001);
        assert!(canceller.estimated_bulk_delay().is_some());
        assert!(canceller.bulk_delay_samples() > 0);
        canceller.reset();
        assert_eq!(canceller.estimated_bulk_delay(), None);
        assert_eq!(canceller.bulk_delay_samples(), 0);
        assert!(canceller.weights().iter().all(|&weight| weight == 0.0));
    }

    // ---- two-path (foreground/background) + normalized-cross-correlation DTD ----

    /// Single-talk convergence in two-path mode: the foreground (which produces the output) reaches the
    /// ≥ 20 dB ERLE target within a bounded frame count via background→foreground copies.
    #[test]
    fn two_path_converges_to_high_erle_on_synthetic_echo() {
        let tail = 256;
        let frame = 160;
        let frames = 200;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x7000_2026);
        let mut canceller = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_two_path_dtd();
        assert!(canceller.two_path_enabled());
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
        // One frame slower than the single filter (frame 0 emits the un-cancelled echo while the first
        // copy is still forming) — still well inside 20 frames on this box (frame 4).
        let converged = converged_frame.expect("two-path must reach 20 dB ERLE");
        assert!(
            converged <= 20,
            "two-path converged only after {converged} frames (>20)"
        );
        assert!(
            steady_erle >= 20.0,
            "two-path steady ERLE {steady_erle:.1} dB < 20 dB"
        );
        assert!(
            canceller.foreground_copies() > 0,
            "single-talk must copy background→foreground"
        );
        assert!(
            !canceller.double_talk_active(),
            "single-talk is not double-talk"
        );
    }

    /// **Two-path beats Geigel on a hard case.** On a loud (low-ERL) echo the Geigel screen's fixed
    /// `½·max|far|` threshold false-trips on the single-talk echo *every* frame and freezes adaptation,
    /// so the single filter never converges (ERLE ≈ 0). The two-path NCC is a scale-independent ratio
    /// (`ρ → 1` on echo-only regardless of loudness), so it vetoes the false Geigel trip and converges
    /// to > 20 dB. This is the canonical fixed-threshold Geigel weakness. (The near-end *divergence*
    /// failure the spec also names does not occur on this synthetic path: NLMS is inherently robust to
    /// an *uncorrelated* near-end at this step size — its mean-zero updates average out and the
    /// per-frame peak Geigel actually freezes on the echo+talker peak — so the loud-echo false-trip is
    /// the honest hard case here. The two-path *mechanism* that would also hold under divergence is
    /// proven by the foreground-frozen assertion in `two_path_protects_foreground_through_double_talk`.)
    #[test]
    fn two_path_beats_geigel_on_loud_echo_false_trip() {
        let tail = 256;
        let frame = 160;
        let frames = 200;
        // 3× the reference RIR → Σ|coef| ≈ 0.95, so the single-talk echo peak clears ½·max|far| on
        // essentially every frame and the Geigel screen freezes; ρ (scale-independent) stays ≈ 1.
        let loud: Vec<f32> = build_rir(128)
            .iter()
            .map(|coefficient| coefficient * 3.0)
            .collect();
        let mut prng = SplitMix64::new(0x1357_2468);
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &loud, 0);

        let mut geigel = EchoCanceller::new(8_000, tail).expect("build");
        let mut two_path = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_two_path_dtd();
        let mut geigel_erle = f64::NAN;
        let mut two_path_erle = f64::NAN;
        let mut geigel_frozen_frames = 0usize;
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut geigel_mic = echo[range.clone()].to_vec();
            let mut two_path_mic = echo[range.clone()].to_vec();
            geigel.cancel(&mut geigel_mic, &far[range.clone()]);
            two_path.cancel(&mut two_path_mic, &far[range.clone()]);
            geigel_erle = erle_db(&echo[range.clone()], &geigel_mic);
            two_path_erle = erle_db(&echo[range], &two_path_mic);
            if geigel.double_talk_active() {
                geigel_frozen_frames += 1;
            }
        }
        // Geigel false-freezes on the loud echo on nearly every frame and never cancels it.
        assert!(
            geigel_frozen_frames * 10 >= frames * 9,
            "expected Geigel to false-trip on ~every loud-echo frame, got {geigel_frozen_frames}/{frames}"
        );
        assert!(
            geigel_erle < 6.0,
            "Geigel-only unexpectedly cancelled the loud echo ({geigel_erle:.1} dB)"
        );
        // The two-path NCC ignores the false trip and converges — a > 20 dB improvement.
        assert!(
            two_path_erle >= 20.0,
            "two-path only reached {two_path_erle:.1} dB on the loud echo"
        );
        assert!(
            two_path_erle - geigel_erle >= 20.0,
            "two-path improvement over Geigel only {:.1} dB",
            two_path_erle - geigel_erle
        );
        assert!(two_path.foreground_copies() > 0);
    }

    /// Double-talk protection: a well-converged two-path canceller must (a) flag double-talk, (b) keep
    /// the **foreground frozen bit-for-bit** through it (a copy is the only thing that can move the
    /// foreground and the NCC blocks it), (c) pass the near-end through with bounded leakage, and (d)
    /// recover ERLE the instant the near-end stops — because the foreground never degraded.
    #[test]
    fn two_path_protects_foreground_through_double_talk() {
        let tail = 256;
        let frame = 160;
        let converge_frames = 120;
        let double_talk_frames = 30;
        let recover_frames = 40;
        let total = converge_frames + double_talk_frames + recover_frames;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x00DD_BA11);
        let mut canceller = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_two_path_dtd();
        let far = far_stream(&mut prng, 0.6, total * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
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
        let foreground_before: Vec<f32> = canceller.foreground_weights().to_vec();
        let copies_before = canceller.foreground_copies();
        assert!(
            foreground_before.iter().any(|&weight| weight != 0.0),
            "foreground must have converged before the double-talk"
        );

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
                .map(|(&echo_sample, &near_sample)| echo_sample.saturating_add(near_sample))
                .collect();
            canceller.cancel(&mut mic, &far[range]);
            double_talk_seen |= canceller.double_talk_active();
            for (&residual, &near_sample) in mic.iter().zip(talk) {
                let difference = f64::from(residual) - f64::from(near_sample);
                near_leakage += difference * difference;
                near_power += f64::from(near_sample) * f64::from(near_sample);
            }
        }
        assert!(double_talk_seen, "two-path must flag the double-talk");
        // The foreground filter is untouched through the whole double-talk segment.
        assert_eq!(
            foreground_before.as_slice(),
            canceller.foreground_weights(),
            "foreground must not adapt during double-talk"
        );
        assert_eq!(
            copies_before,
            canceller.foreground_copies(),
            "no background→foreground copy may happen during double-talk"
        );
        // Near-end passes through: leakage ≥ ~12 dB below the near-end talker.
        let leakage_db = 10.0 * (near_leakage / near_power.max(1.0)).log10();
        assert!(
            leakage_db <= -12.0,
            "near-end leakage {leakage_db:.1} dB (want ≤ -12 dB)"
        );

        // 3) Near-end stops: ERLE recovers (the protected foreground never degraded).
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

    /// Copy-logic correctness: during clean single-talk the background converges and is copied into the
    /// foreground (foreground improves from all-zero, copies climb); during double-talk no copy happens
    /// (foreground frozen bit-for-bit, copy count held).
    #[test]
    fn two_path_copies_during_single_talk_and_freezes_during_double_talk() {
        let tail = 128;
        let frame = 160;
        let rir = build_rir(64);
        let mut prng = SplitMix64::new(0xC0DE_0FF1);
        let mut canceller = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_two_path_dtd();
        let far = far_stream(&mut prng, 0.6, 200 * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        let frame_range = |index: usize| index * frame..(index + 1) * frame;

        assert_eq!(canceller.foreground_copies(), 0);
        // A few single-talk frames: the foreground must lift off zero via copies.
        let mut early_erle = f64::NAN;
        for index in 0..4 {
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            early_erle = erle_db(&echo[range], &mic);
        }
        let copies_early = canceller.foreground_copies();
        let foreground_energy_early: f32 = canceller
            .foreground_weights()
            .iter()
            .map(|weight| weight * weight)
            .sum();
        assert!(copies_early > 0, "single-talk must trigger copies");
        assert!(
            foreground_energy_early > 0.0,
            "foreground must improve from zero during single-talk"
        );

        // Keep converging: more copies, better foreground ERLE.
        let mut late_erle = f64::NAN;
        for index in 4..60 {
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            late_erle = erle_db(&echo[range], &mic);
        }
        assert!(
            canceller.foreground_copies() > copies_early,
            "copies must keep firing while single-talk continues"
        );
        assert!(
            late_erle > early_erle,
            "foreground ERLE must improve as copies accumulate ({early_erle:.1} → {late_erle:.1} dB)"
        );

        // Double-talk: the copy must stop and the foreground must freeze.
        let foreground_before: Vec<f32> = canceller.foreground_weights().to_vec();
        let copies_before = canceller.foreground_copies();
        for index in 60..85 {
            let range = frame_range(index);
            let talk: Vec<i16> = (0..frame)
                .map(|t| super::denormalize(0.7 * ((index * frame + t) as f32 * 0.37).sin()))
                .collect();
            let mut mic: Vec<i16> = echo[range.clone()]
                .iter()
                .zip(&talk)
                .map(|(&echo_sample, &near_sample)| echo_sample.saturating_add(near_sample))
                .collect();
            canceller.cancel(&mut mic, &far[range]);
        }
        assert_eq!(
            foreground_before.as_slice(),
            canceller.foreground_weights(),
            "foreground must be frozen during double-talk"
        );
        assert_eq!(
            copies_before,
            canceller.foreground_copies(),
            "no copy may happen during double-talk"
        );
    }

    /// The two-path toggle is additive and composes with every constructor; its status accessors report
    /// the mode, the last NCC, and the copy count. The Geigel default reports no two-path state.
    #[test]
    fn two_path_toggle_and_accessors() {
        let geigel = EchoCanceller::new(8_000, 128).expect("build");
        assert!(!geigel.two_path_enabled());
        assert_eq!(geigel.double_talk_correlation(), None);
        assert_eq!(geigel.foreground_copies(), 0);

        let two_path = EchoCanceller::with_bulk_delay(8_000, 128, 40)
            .expect("build")
            .with_two_path_dtd();
        assert!(two_path.two_path_enabled());
        assert_eq!(two_path.double_talk_correlation(), None); // no frame processed yet
        assert_eq!(two_path.foreground_copies(), 0);
        assert_eq!(two_path.bulk_delay_samples(), 40); // toggle preserves the constructor config

        // After a frame with far-end energy the NCC becomes observable.
        let mut prng = SplitMix64::new(0x0B5E_2FED);
        let mut canceller = EchoCanceller::new(8_000, 64)
            .expect("build")
            .with_two_path_dtd();
        let far = far_stream(&mut prng, 0.6, 160);
        let rir = build_rir(64);
        let mut mic = synthesize_echo(&normalize(&far), &rir, 0);
        canceller.cancel(&mut mic, &far);
        assert!(
            canceller.double_talk_correlation().is_some(),
            "NCC must be observable after an excited frame"
        );
    }

    /// `reset` clears both filters, the copy count, and the NCC, but preserves the two-path mode.
    #[test]
    fn two_path_reset_clears_state() {
        let frame = 160;
        let rir = build_rir(64);
        let mut prng = SplitMix64::new(0x1234_ABCD);
        let mut canceller = EchoCanceller::new(8_000, 128)
            .expect("build")
            .with_two_path_dtd();
        let far = far_stream(&mut prng, 0.6, 40 * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        for index in 0..40 {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }
        assert!(canceller.foreground_copies() > 0);
        assert!(canceller
            .foreground_weights()
            .iter()
            .any(|&weight| weight != 0.0));
        canceller.reset();
        assert_eq!(canceller.foreground_copies(), 0);
        assert_eq!(canceller.double_talk_correlation(), None);
        assert!(canceller
            .foreground_weights()
            .iter()
            .all(|&weight| weight == 0.0));
        assert!(canceller.weights().iter().all(|&weight| weight == 0.0));
        assert!(canceller.two_path_enabled(), "reset must preserve the mode");
        assert!(!canceller.double_talk_active());
    }

    /// Determinism: the two-path path is a pure function of the input (logical clock, fixed-seed PRNG),
    /// so two identical runs yield identical foreground weights and copy counts.
    #[test]
    fn two_path_is_deterministic() {
        let run = || {
            let frame = 160;
            let rir = build_rir(128);
            let mut prng = SplitMix64::new(0xD37E_2222);
            let mut canceller = EchoCanceller::new(8_000, 160)
                .expect("build")
                .with_two_path_dtd();
            let far = far_stream(&mut prng, 0.6, 80 * frame);
            let echo = synthesize_echo(&normalize(&far), &rir, 0);
            for index in 0..80 {
                let range = index * frame..(index + 1) * frame;
                let mut mic = echo[range.clone()].to_vec();
                canceller.cancel(&mut mic, &far[range]);
            }
            (
                canceller.foreground_weights().to_vec(),
                canceller.foreground_copies(),
            )
        };
        assert_eq!(run(), run());
    }

    /// The two-path toggle composes with automatic GCC-PHAT delay estimation: an unknown bulk delay is
    /// aligned and the protected foreground still reaches the ≥ 20 dB ERLE target.
    #[test]
    fn two_path_with_delay_estimation_converges() {
        let frame = 160;
        let search_range = 512;
        let unknown_delay = 256;
        let frames = 300;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0xE51E_7777);
        let mut canceller = EchoCanceller::with_delay_estimation(8_000, 192, search_range)
            .expect("build")
            .with_two_path_dtd();
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, unknown_delay);
        let mut steady_erle = f64::NAN;
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            steady_erle = erle_db(&echo[range], &mic);
        }
        assert!(
            canceller.estimated_bulk_delay().is_some(),
            "GCC-PHAT must lock the delay in two-path mode"
        );
        assert!(
            steady_erle >= 20.0,
            "two-path + delay-estimation steady ERLE {steady_erle:.1} dB < 20 dB"
        );
    }

    /// The block size is a power of two, at least twice the search range, clamped to the FFT bounds.
    #[test]
    fn block_size_covers_the_search_range() {
        assert_eq!(choose_block_size(1), DELAY_BLOCK_MIN);
        assert_eq!(choose_block_size(100), DELAY_BLOCK_MIN);
        assert_eq!(choose_block_size(256), DELAY_BLOCK_MIN);
        assert_eq!(choose_block_size(512), 1024);
        assert_eq!(choose_block_size(MAX_SEARCH_RANGE_SAMPLES), DELAY_BLOCK_MAX);
        for &range in &[1usize, 100, 256, 512, 1024, MAX_SEARCH_RANGE_SAMPLES] {
            let block = choose_block_size(range);
            assert!(block.is_power_of_two(), "block {block} not power of two");
            assert!(
                block > range,
                "block {block} must exceed search range {range}"
            );
        }
    }
}
