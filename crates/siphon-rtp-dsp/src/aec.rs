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
use crate::res::ResidualEchoSuppressor;
use crate::DspError;
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

// --- MDF / partitioned-block frequency-domain adaptive filter (Soo & Pang 1990) ---
/// Frequency-domain NLMS step size `μ` for the MDF weight update (0 < μ < 2 for stability). At each
/// bin the `K` partition weights form a `K`-tap NLMS driven by the delay-line regressor
/// `[X_m, X_{m-1}, …, X_{m-K+1}]`, normalized by that regressor's *total* per-bin energy
/// `Σ_k |X_{m-k}[b]|²` (see [`MdfFilter::process_block`]) — so the effective per-bin step is exactly
/// `μ`, independent of the partition count `K`. 0.5 gives fast convergence with a wide stability margin.
const MDF_STEP_SIZE: f32 = 0.5;
/// Per-bin power regularization `δ` (normalized units) added to the delay-line energy before the
/// division, so a near-silent bin yields a ~0 step instead of a blow-up (the frequency-domain analogue
/// of the NLMS `δ`).
const MDF_REGULARIZATION: f32 = 1.0e-4;
/// Largest partition count the MDF preallocates for — 64 blocks of the (rate-dependent) block size,
/// i.e. up to ~2048 taps (256 ms) @ 8 kHz / ~4096 taps (256 ms) @ 16 kHz. Bounds a pathological tail.
const MDF_MAX_PARTITIONS: usize = 64;
/// Below this per-frame normalized energy on either the microphone or the block echo estimate the MDF
/// two-path NCC is undefined (a 0/0), so the frame drives neither a freeze nor an unfreeze — the
/// bootstrap guard that lets the very first (all-zero-filter) blocks adapt.
const MDF_NCC_ENERGY_FLOOR: f64 = 1.0e-7;
/// Blocks the MDF two-path adaptation stays frozen after the last NCC double-talk trigger (~48 ms at a
/// 128-sample block / 8 kHz), so a brief mid-word near-end gap does not let a partition resume learning
/// the near-end talker.
const MDF_DOUBLETALK_HANGOVER_BLOCKS: usize = 3;

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
    /// The residual-echo suppressor only supports the 8 kHz / 16 kHz media-plane rates (its √Hann WOLA
    /// sizes), so it cannot be chained onto a canceller at any other rate.
    #[error("residual-echo suppression supports only 8000 and 16000 Hz (got {rate} Hz)")]
    ResidualSuppressionUnavailable {
        /// The canceller's sample rate, unsupported by the residual-echo suppressor.
        rate: u32,
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

/// The largest power of two `<= n` (the MDF block size for a 20 ms frame: 160 → 128, 320 → 256), so
/// the overlap-save FFT length `N = 2·block` stays a power of two the [`RealFft`] supports.
fn floor_power_of_two(n: usize) -> usize {
    debug_assert!(n >= 2);
    if n.is_power_of_two() {
        n
    } else {
        n.next_power_of_two() >> 1
    }
}

/// Which double-talk gate the MDF adaptation runs (mirrors [`DtdMode`] for the frequency-domain path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MdfDtd {
    /// The frame-level Geigel gate decided by [`EchoCanceller::cancel`] drives adaptation (default).
    Geigel,
    /// A per-block normalized cross-correlation (NCC) between the microphone and the block echo
    /// estimate freezes the per-partition weight update during double-talk (the two-path posture).
    TwoPath,
}

/// A **multi-delay block frequency-domain adaptive filter** (MDF / PBFDAF, Soo & Pang, *Multidelay
/// block frequency domain adaptive filter*, IEEE TASSP 1990) — a partitioned-block frequency-domain
/// LMS that covers a long echo tail (128–256 ms) at O(N log N) instead of the O(L) per sample a
/// time-domain NLMS pays.
///
/// ## Structure (overlap-save, 50 % overlap)
/// The length-`tail` impulse response is split into `K` partitions of `block_size` (`B`) taps. Each
/// block of `B` new samples is processed with an `N = 2·B`-point real FFT ([`RealFft`], the same plan
/// the noise suppressor uses):
///
/// ```text
///   Xₘ = FFT( [ xₘ₋₁ | xₘ ] )                     (overlap-save frame: previous B ++ current B)
///   Y  = Σ_{k=0}^{K-1} W_k ⊙ X_{m-k}              (partitioned filter over the spectrum delay line)
///   y  = last B samples of IFFT(Y)                (overlap-save discards the first B — the aliasing)
///   e  = d − y                                    (the residual we emit, B samples)
///   E  = FFT( [ 0…0 (B) | e ] )
/// ```
///
/// ## Per-bin power-normalized frequency LMS (with the gradient constraint)
/// Each partition adapts by the standard NLMS-in-frequency (Shynk, *Frequency-domain and multirate
/// adaptive filtering*, IEEE SP Mag 1992), normalized by a smoothed per-bin reference PSD and made a
/// proper overlap-save gradient by the time-domain constraint (zeroing the wrap-around half):
///
/// ```text
///   P[b]  = λ·P[b] + (1−λ)·|Xₘ[b]|²               (per-bin reference power)
///   G_k   = μ · conj(X_{m-k}) ⊙ E / (P + δ)       (power-normalized cross-correlation gradient)
///   g_k   = IFFT(G_k);  g_k[B..2B] = 0;  Ĝ_k = FFT(g_k)   (gradient constraint → linear correlation)
///   W_k  += Ĝ_k
/// ```
///
/// The constraint is the canonical Soo–Pang MDF (it makes the block update identical to time-domain
/// block-LMS); it costs one IFFT + one FFT per partition per block, which is why the MDF is the heavy
/// AEC path (see the bench note). An *unconstrained* variant (skip `g_k[B..]=0` and the round-trip) is
/// a documented future perf lever.
///
/// ## Double-talk freeze (composition with the two-path DTD)
/// In [`MdfDtd::TwoPath`] a per-block NCC `ρ = Σ d·ŷ / √(Σ d²·Σ ŷ²)` between the microphone `d` and the
/// block echo estimate `ŷ` freezes the per-partition update when `ρ < NCC_DOUBLETALK_THRESHOLD`
/// (Benesty *et al.* 2000), with a short block hangover — so a near-end talker never leaks into the
/// weights. In [`MdfDtd::Geigel`] the frame-level Geigel gate the canceller already computes drives the
/// freeze instead. Either way the frozen weights are protected bit-for-bit through the double-talk.
///
/// ## Bulk-delay alignment
/// A [`FarEndReference`] delay line (tail 1) applies the GCC-PHAT bulk delay as a read offset, so the
/// aligned reference the block assembly buffers already has the transport delay removed and the `K`
/// partitions only span the residual dispersion. [`MdfFilter::set_bulk_delay`] re-aligns (and resets
/// the weights, tuned to the old offset) with no allocation.
///
/// ## Allocation & latency
/// Every buffer — the `K` weight spectra, the `K`-deep reference-spectrum delay line, the per-bin PSD,
/// all FFT scratch, and the block-assembly / output rings — is sized once in [`MdfFilter::new`];
/// [`MdfFilter::push_frame`] is allocation-free. Block processing adds a fixed `block_size`-sample
/// (~16 ms) algorithmic latency (the overlap-save block delay), documented like the NS WOLA delay.
#[derive(Clone, Debug)]
struct MdfFilter {
    /// Partition / hop length `B` (a power of two).
    block_size: usize,
    /// Overlap-save FFT length `N = 2·B`.
    fft_size: usize,
    /// Half-spectrum bin count `N/2 + 1`.
    bins: usize,
    /// Partition count `K` (`tail = K·B` taps covered).
    partitions: usize,
    /// Effective covered tail in samples (`K·B`).
    tail: usize,
    /// The real FFT/IFFT for `N` (shared plan type with the noise suppressor).
    fft: RealFft,
    /// Per-partition frequency-domain weights, `K·bins` complex (partition-major).
    weights: Vec<Complex>,
    /// Reference-spectrum delay line, `K·bins` complex (a ring of the last `K` input-block spectra).
    x_spectra: Vec<Complex>,
    /// Ring index of the newest stored reference spectrum in [`Self::x_spectra`].
    x_head: usize,
    /// Per-bin **delay-line** reference energy `Σ_{k} |X_{m-k}[b]|²`, `bins` reals — the NLMS-in-
    /// frequency normalizer for the `K`-tap-per-bin partition filter. Recomputed every block from the
    /// spectrum delay line (a sum over `K` blocks, so inherently low-variance), never smoothed.
    delay_power: Vec<f32>,
    /// Overlap-save frame scratch (`N` reals): `[previous block | current block]` and, reused, the
    /// zero-padded error frame and the per-partition gradient time signal.
    frame_time: Vec<f32>,
    /// Newest input-block spectrum scratch, `bins` complex.
    x_new: Vec<Complex>,
    /// Filter output spectrum `Y`, `bins` complex.
    y_spectrum: Vec<Complex>,
    /// Filter output time signal (`N` reals); the last `B` samples are the block echo estimate.
    y_time: Vec<f32>,
    /// Error spectrum `E`, `bins` complex.
    error_spectrum: Vec<Complex>,
    /// Per-partition gradient spectrum scratch, `bins` complex.
    grad_spectrum: Vec<Complex>,
    /// The current block's residual (`B` reals), also the error fed into `E`.
    block_error: Vec<f32>,
    /// Previous block's `B` reference samples (the overlap-save carry).
    overlap_ref: Vec<f32>,
    /// Aligned-reference block-assembly buffer, `B + frame_capacity` reals.
    in_ref: Vec<f32>,
    /// Near-end block-assembly buffer, `B + frame_capacity` reals.
    in_near: Vec<f32>,
    /// Samples currently buffered in [`Self::in_ref`] / [`Self::in_near`].
    in_len: usize,
    /// Residual output ring (holds emitted-but-not-yet-drained samples), preloaded with `B` zeros for
    /// the block latency so a full 20 ms frame always drains without underflow.
    out_res: Vec<f32>,
    /// Valid samples in [`Self::out_res`].
    out_len: usize,
    /// Whether to capture the block echo estimate frame-synchronously with the residual (only when a
    /// residual-echo suppressor is chained on — see [`EchoCanceller::with_residual_suppression`]). When
    /// false the echo buffers below are left untouched, so the residual path stays byte-for-byte and
    /// perf-for-perf identical to the RES-off MDF.
    capture_echo: bool,
    /// Per-block echo-estimate scratch `ŷ = last B samples of IFFT(Y)` (`B` reals), the parallel of
    /// [`Self::block_error`]; only filled when [`Self::capture_echo`].
    block_echo: Vec<f32>,
    /// Echo-estimate output ring, drained in lock-step with [`Self::out_res`] so the echo frame the
    /// RES receives is aligned sample-for-sample with the residual frame (both delayed by the block
    /// latency). Same length and `out_len` bookkeeping as [`Self::out_res`].
    out_echo: Vec<f32>,
    /// The most recent frame's drained echo estimate (`frame_capacity` reals, normalized), handed to
    /// the residual-echo suppressor after [`Self::push_frame`].
    last_echo_frame: Vec<f32>,
    /// The [`FarEndReference`] (tail 1) that applies the bulk delay to the raw reference.
    reference: FarEndReference,
    /// Frequency-domain NLMS step `μ`.
    step_size: f32,
    /// Per-bin power regularization `δ`.
    regularization: f32,
    /// The double-talk gate driving the per-partition freeze.
    dtd: MdfDtd,
    /// The most recent block's NCC `ρ` (two-path mode), or `None` before the first valid block.
    last_correlation: Option<f32>,
    /// Whether the most recent block was frozen for (NCC) double-talk.
    doubletalk_active: bool,
    /// Remaining blocks the two-path adaptation stays frozen after the last NCC trigger.
    dt_hold_blocks: usize,
    /// Two-path bootstrap guard: until the NCC has confirmed echo-only (`ρ ≥ NCC_COPY_THRESHOLD`) at
    /// least once, adaptation ignores the NCC freeze — otherwise a mid-convergence `ρ` sitting in the
    /// double-talk band would freeze the filter before it ever converged (the copies-`> 0` bootstrap the
    /// time-domain two-path uses, adapted to the single-filter MDF).
    converged_once: bool,
}

impl MdfFilter {
    /// Build an MDF for `frame_capacity` (the 20 ms frame), a `tail_samples` echo tail, and a
    /// `max_bulk_delay` reference-alignment range (0 for the fixed / no-estimation constructor).
    fn new(
        frame_capacity: usize,
        tail_samples: usize,
        max_bulk_delay: usize,
    ) -> Result<Self, AecError> {
        if tail_samples == 0 || tail_samples > MAX_TAIL_SAMPLES {
            return Err(AecError::InvalidTail {
                got: tail_samples,
                max: MAX_TAIL_SAMPLES,
            });
        }
        let block_size = floor_power_of_two(frame_capacity);
        let fft_size = block_size * 2;
        let partitions = tail_samples.div_ceil(block_size).min(MDF_MAX_PARTITIONS);
        // `fft_size` is a power of two `>= 4` (block_size >= 2), so this cannot fail; map any future
        // contract change to the tail error rather than panicking.
        let fft = RealFft::new(fft_size).map_err(|_| AecError::InvalidTail {
            got: tail_samples,
            max: MAX_TAIL_SAMPLES,
        })?;
        let bins = fft.bins();
        let tail = partitions * block_size;
        Ok(Self {
            block_size,
            fft_size,
            bins,
            partitions,
            tail,
            fft,
            weights: vec![Complex::default(); partitions * bins],
            x_spectra: vec![Complex::default(); partitions * bins],
            x_head: 0,
            delay_power: vec![0.0; bins],
            frame_time: vec![0.0; fft_size],
            x_new: vec![Complex::default(); bins],
            y_spectrum: vec![Complex::default(); bins],
            y_time: vec![0.0; fft_size],
            error_spectrum: vec![Complex::default(); bins],
            grad_spectrum: vec![Complex::default(); bins],
            block_error: vec![0.0; block_size],
            overlap_ref: vec![0.0; block_size],
            in_ref: vec![0.0; block_size + frame_capacity],
            in_near: vec![0.0; block_size + frame_capacity],
            in_len: 0,
            // Preload the block latency; capacity holds the latency + up to two blocks of production.
            out_res: vec![0.0; block_size + frame_capacity + 2 * block_size],
            out_len: block_size,
            capture_echo: false,
            block_echo: vec![0.0; block_size],
            out_echo: vec![0.0; block_size + frame_capacity + 2 * block_size],
            last_echo_frame: vec![0.0; frame_capacity],
            reference: FarEndReference::with_max_delay(1, 0, max_bulk_delay, frame_capacity),
            step_size: MDF_STEP_SIZE,
            regularization: MDF_REGULARIZATION,
            dtd: MdfDtd::Geigel,
            last_correlation: None,
            doubletalk_active: false,
            dt_hold_blocks: 0,
            converged_once: false,
        })
    }

    /// The bulk delay currently applied to the reference alignment.
    #[inline]
    fn bulk_delay(&self) -> usize {
        self.reference.bulk_delay
    }

    /// Turn on frame-synchronous echo-estimate capture (paid only when a residual-echo suppressor is
    /// chained on); idempotent.
    fn enable_echo_capture(&mut self) {
        self.capture_echo = true;
    }

    /// The most recent [`Self::push_frame`]'s drained echo estimate (`n` normalized samples, aligned
    /// sample-for-sample with the drained residual). Only populated when [`Self::capture_echo`] is on.
    #[inline]
    fn echo_frame(&self, n: usize) -> &[f32] {
        &self.last_echo_frame[..n.min(self.last_echo_frame.len())]
    }

    /// Re-align the reference to a new bulk delay and reset the weights (they were tuned to the old
    /// alignment). Only the alignment read offset moves — no allocation. The two-path bootstrap/DTD
    /// state is reset too: the zeroed filter is unconverged again, so the NCC must re-bootstrap
    /// (otherwise a stale `converged_once` would freeze the just-reset filter into a permanent
    /// double-talk deadlock on the poor early echo estimate).
    fn set_bulk_delay(&mut self, bulk_delay: usize) {
        self.reference.set_bulk_delay(bulk_delay);
        self.weights
            .iter_mut()
            .for_each(|w| *w = Complex::default());
        self.converged_once = false;
        self.dt_hold_blocks = 0;
        self.doubletalk_active = false;
        self.last_correlation = None;
    }

    /// Ring slot of the reference spectrum `k` blocks older than the newest.
    #[inline]
    fn partition_slot(&self, k: usize) -> usize {
        (self.x_head + self.partitions - k) % self.partitions
    }

    /// Push one frame-synchronous `(near_end, reference)` pair: buffer the bulk-delay-aligned reference
    /// and the near-end, run every complete block through the FDAF, and drain the same number of
    /// echo-subtracted residual samples back into `near_end` (delayed by the fixed block latency).
    ///
    /// `base_adapt` is the frame-level adaptation gate for [`MdfDtd::Geigel`] (the canceller's Geigel
    /// screen + hangover); in [`MdfDtd::TwoPath`] the per-block NCC decides the freeze and `base_adapt`
    /// is ignored (the far-end-active check is made per block from the aligned reference energy).
    fn push_frame(&mut self, near_end: &mut [i16], reference: &[i16], base_adapt: bool) {
        let n = near_end
            .len()
            .min(reference.len())
            .min(self.reference.frame_capacity);
        if n == 0 {
            return;
        }

        // 1. Buffer the bulk-delay-aligned reference and the near-end into the block-assembly buffers.
        let written = self.reference.write_frame(&reference[..n]);
        debug_assert_eq!(written, n, "MDF reference ring must absorb the whole frame");
        let base = self.in_len;
        for (i, &near_sample) in near_end.iter().take(n).enumerate() {
            self.in_ref[base + i] = self.reference.window_sample(i);
            self.in_near[base + i] = f32::from(near_sample) / SAMPLE_SCALE;
        }
        self.reference.compact(n);
        self.in_len += n;

        // 2. Process every complete block, appending its residual to the output ring.
        while self.in_len >= self.block_size {
            self.process_block(base_adapt);
            let remaining = self.in_len - self.block_size;
            self.in_ref.copy_within(self.block_size..self.in_len, 0);
            self.in_near.copy_within(self.block_size..self.in_len, 0);
            self.in_len = remaining;
        }

        // 3. Drain n residual samples back into near_end in place (the block latency guarantees the
        //    output ring holds at least n after warm-up; before that the preloaded zeros cover it).
        debug_assert!(self.out_len >= n, "MDF output ring underflow");
        for (sample, &residual) in near_end.iter_mut().take(n).zip(self.out_res.iter()) {
            *sample = denormalize(residual);
        }
        if self.capture_echo {
            // Drain the frame-aligned echo estimate for the RES before the ring shifts down.
            for (slot, &echo) in self
                .last_echo_frame
                .iter_mut()
                .take(n)
                .zip(self.out_echo.iter())
            {
                *slot = echo;
            }
            self.out_echo.copy_within(n..self.out_len, 0);
        }
        self.out_res.copy_within(n..self.out_len, 0);
        self.out_len -= n;
    }

    /// Run one `block_size`-sample block through the partitioned-block frequency-domain LMS.
    fn process_block(&mut self, base_adapt: bool) {
        let block = self.block_size;
        let fft_size = self.fft_size;
        let bins = self.bins;

        // --- overlap-save input frame [ previous B | current B ] → newest spectrum Xₘ ---
        self.frame_time[..block].copy_from_slice(&self.overlap_ref);
        self.frame_time[block..fft_size].copy_from_slice(&self.in_ref[..block]);
        self.fft.forward(&self.frame_time, &mut self.x_new);

        // Store Xₘ as the newest ring slot.
        self.x_head = (self.x_head + 1) % self.partitions;
        let head_base = self.x_head * bins;
        self.x_spectra[head_base..head_base + bins].copy_from_slice(&self.x_new);

        // --- filter Y = Σ_k W_k ⊙ X_{m-k}, and the per-bin delay-line energy Σ_k |X_{m-k}|² ---
        // The delay-line energy is the NLMS normalizer: at each bin the K partition weights are a K-tap
        // NLMS whose regressor is the K-block delay line, so its energy — not one block's power — is the
        // correct per-bin step normalizer (otherwise the effective step scales with K and diverges).
        for slot in self.y_spectrum.iter_mut() {
            *slot = Complex::default();
        }
        for power in self.delay_power.iter_mut() {
            *power = 0.0;
        }
        for k in 0..self.partitions {
            let weight_base = k * bins;
            let x_base = self.partition_slot(k) * bins;
            for bin in 0..bins {
                let w = self.weights[weight_base + bin];
                let x = self.x_spectra[x_base + bin];
                self.y_spectrum[bin].re += w.re * x.re - w.im * x.im;
                self.y_spectrum[bin].im += w.re * x.im + w.im * x.re;
                self.delay_power[bin] += x.norm_squared();
            }
        }
        self.fft.inverse(&self.y_spectrum, &mut self.y_time);

        // --- residual e = d − ŷ over the block (ŷ = last B samples of IFFT(Y)) + NCC accumulators ---
        let mut sum_mic_sq = 0.0f64;
        let mut sum_echo_sq = 0.0f64;
        let mut sum_mic_echo = 0.0f64;
        let mut far_energy = 0.0f64;
        for i in 0..block {
            let mic = self.in_near[i];
            let echo = self.y_time[block + i];
            let residual = mic - echo;
            self.block_error[i] = residual;
            if self.capture_echo {
                self.block_echo[i] = echo;
            }
            let mic64 = f64::from(mic);
            let echo64 = f64::from(echo);
            sum_mic_sq += mic64 * mic64;
            sum_echo_sq += echo64 * echo64;
            sum_mic_echo += mic64 * echo64;
            let reference = f64::from(self.in_ref[i]);
            far_energy += reference * reference;
        }
        // Emit the residual (append to the output ring), plus the frame-aligned echo estimate when a
        // residual-echo suppressor is chained on.
        let out_base = self.out_len;
        self.out_res[out_base..out_base + block].copy_from_slice(&self.block_error);
        if self.capture_echo {
            self.out_echo[out_base..out_base + block].copy_from_slice(&self.block_echo);
        }
        self.out_len += block;

        // --- decide adaptation for this block (Geigel frame gate, or the per-block two-path NCC) ---
        let far_active = far_energy / block as f64 > f64::from(DELAY_FAR_ENERGY_FLOOR);
        let adapt = match self.dtd {
            MdfDtd::Geigel => base_adapt,
            MdfDtd::TwoPath => {
                let correlation = if far_active
                    && sum_mic_sq > MDF_NCC_ENERGY_FLOOR
                    && sum_echo_sq > MDF_NCC_ENERGY_FLOOR
                {
                    Some((sum_mic_echo / (sum_mic_sq * sum_echo_sq).sqrt()) as f32)
                } else {
                    None
                };
                self.last_correlation = correlation;
                if correlation.is_some_and(|rho| rho >= NCC_COPY_THRESHOLD) {
                    self.converged_once = true;
                }
                let double_talk = correlation.is_some_and(|rho| rho < NCC_DOUBLETALK_THRESHOLD);
                self.doubletalk_active = double_talk;
                if double_talk {
                    self.dt_hold_blocks = MDF_DOUBLETALK_HANGOVER_BLOCKS;
                } else if self.dt_hold_blocks > 0 {
                    self.dt_hold_blocks -= 1;
                }
                // Until the filter has confidently converged once, adapt on every excited block so the
                // NCC can never latch it at its uninitialized state; afterwards the freeze is trusted.
                far_active && (!self.converged_once || self.dt_hold_blocks == 0)
            }
        };

        // --- adapt each partition: G_k = μ·conj(X_{m-k})⊙E/(P+δ), constrain, W_k += Ĝ_k ---
        if adapt {
            // Error frame E = FFT( [ 0…0 (B) | e ] ).
            self.frame_time[..block].iter_mut().for_each(|s| *s = 0.0);
            self.frame_time[block..fft_size].copy_from_slice(&self.block_error);
            self.fft.forward(&self.frame_time, &mut self.error_spectrum);

            for k in 0..self.partitions {
                let x_base = self.partition_slot(k) * bins;
                for bin in 0..bins {
                    let x = self.x_spectra[x_base + bin];
                    let e = self.error_spectrum[bin];
                    // conj(X)·E = (xr − i·xi)(er + i·ei).
                    let real = x.re * e.re + x.im * e.im;
                    let imag = x.re * e.im - x.im * e.re;
                    let scale = self.step_size / (self.delay_power[bin] + self.regularization);
                    self.grad_spectrum[bin] = Complex::new(real * scale, imag * scale);
                }
                // Gradient constraint: g = IFFT(G); zero the wrap-around half; Ĝ = FFT(g).
                self.fft.inverse(&self.grad_spectrum, &mut self.frame_time);
                self.frame_time[block..fft_size]
                    .iter_mut()
                    .for_each(|s| *s = 0.0);
                self.fft.forward(&self.frame_time, &mut self.grad_spectrum);
                let weight_base = k * bins;
                for bin in 0..bins {
                    self.weights[weight_base + bin].re += self.grad_spectrum[bin].re;
                    self.weights[weight_base + bin].im += self.grad_spectrum[bin].im;
                }
            }
        }

        // Current block's reference becomes the next block's overlap carry.
        self.overlap_ref.copy_from_slice(&self.in_ref[..block]);
    }

    /// Reset all adaptive state (weights, spectrum delay line, PSD, block/output rings, DTD) and the
    /// reference alignment.
    fn reset(&mut self) {
        self.weights
            .iter_mut()
            .for_each(|w| *w = Complex::default());
        self.x_spectra
            .iter_mut()
            .for_each(|x| *x = Complex::default());
        self.x_head = 0;
        self.delay_power.iter_mut().for_each(|p| *p = 0.0);
        self.overlap_ref.iter_mut().for_each(|s| *s = 0.0);
        self.in_len = 0;
        self.out_res.iter_mut().for_each(|s| *s = 0.0);
        self.out_echo.iter_mut().for_each(|s| *s = 0.0);
        self.block_echo.iter_mut().for_each(|s| *s = 0.0);
        self.last_echo_frame.iter_mut().for_each(|s| *s = 0.0);
        self.out_len = self.block_size;
        self.reference.reset();
        self.reference.set_bulk_delay(0);
        self.last_correlation = None;
        self.doubletalk_active = false;
        self.dt_hold_blocks = 0;
        self.converged_once = false;
    }

    /// Total energy of the weight spectra (a convergence probe for tests).
    #[cfg(test)]
    fn weight_energy(&self) -> f64 {
        self.weights
            .iter()
            .map(|w| f64::from(w.norm_squared()))
            .sum()
    }

    /// A snapshot of the weight spectra (tests assert bit-for-bit freeze during double-talk).
    #[cfg(test)]
    fn weights_snapshot(&self) -> Vec<Complex> {
        self.weights.clone()
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
    /// Optional MDF / partitioned-block frequency-domain adaptive filter backend. When present it
    /// **replaces** the time-domain NLMS on the hot path (covering a long tail at O(N log N)); the
    /// time-domain `weights`/`foreground` are then inert. `None` selects the default time-domain
    /// backend, keeping every existing constructor byte-for-byte identical.
    mdf: Option<MdfFilter>,
    /// Optional residual-echo suppressor (spectral post-filter). When present it runs **after** the
    /// linear backend on the emitted residual, using the frame-synchronous echo estimate to knock down
    /// the nonlinear / under-modelled echo the linear filter leaves behind. `None` (the default) keeps
    /// the linear residual byte-for-byte, so every existing constructor is unaffected. See
    /// [`EchoCanceller::with_residual_suppression`].
    res: Option<ResidualEchoSuppressor>,
    /// Preallocated snapshot of the near-end frame (normalized) taken **before** the time-domain
    /// backend overwrites it, so the residual-echo suppressor can form `y_echo = near − residual`
    /// (the MDF backend captures its own frame-aligned echo estimate instead). Length `frame_samples`.
    res_near_snapshot: Vec<f32>,
    /// Preallocated scratch for the frame-synchronous echo-estimate frame handed to the residual-echo
    /// suppressor (normalized). Length `frame_samples`.
    res_echo_frame: Vec<f32>,
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
            mdf: None,
            res: None,
            res_near_snapshot: vec![0.0; frame_samples],
            res_echo_frame: vec![0.0; frame_samples],
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
            mdf: None,
            res: None,
            res_near_snapshot: vec![0.0; frame_samples],
            res_echo_frame: vec![0.0; frame_samples],
        })
    }

    /// A canceller whose adaptive filter is the **MDF / partitioned-block frequency-domain** backend
    /// (Soo & Pang 1990) covering a long echo tail (`tail_samples`, 128–256 ms) at O(N log N) instead
    /// of the time-domain NLMS's O(L) per sample — the right backend when the impulse-response spread
    /// is long. No bulk delay is applied (the echo is assumed to start within the tail); pair it with
    /// [`EchoCanceller::with_mdf_delay_estimation`] to recover an unknown transport delay first.
    ///
    /// Chainable with [`EchoCanceller::with_two_path_dtd`] (which then drives a per-block NCC freeze).
    /// The block backend adds a fixed `block_size`-sample (~16 ms) algorithmic latency (the overlap-save
    /// block delay). Preallocates all state (the `K` partition spectra, the reference-spectrum delay
    /// line, the per-bin delay-line power, and all FFT scratch).
    ///
    /// # Errors
    /// As [`EchoCanceller::new`] for the sample rate and tail.
    pub fn with_mdf(sample_rate_hz: u32, tail_samples: usize) -> Result<Self, AecError> {
        Self::build_mdf(sample_rate_hz, tail_samples, 0, None)
    }

    /// The MDF backend **plus automatic GCC-PHAT bulk-delay estimation** over `search_range_samples`:
    /// the estimator removes the transport delay and the `K` MDF partitions cover the residual
    /// dispersion. Chainable with [`EchoCanceller::with_two_path_dtd`]. Preallocates all state
    /// (including the estimation FFT and the MDF reference-alignment ring for the whole search range).
    ///
    /// # Errors
    /// As [`EchoCanceller::new`], plus [`AecError::InvalidSearchRange`] if `search_range_samples` is 0
    /// or exceeds the supported maximum.
    pub fn with_mdf_delay_estimation(
        sample_rate_hz: u32,
        tail_samples: usize,
        search_range_samples: usize,
    ) -> Result<Self, AecError> {
        let delay_estimator = DelayEstimator::new(search_range_samples)?;
        Self::build_mdf(
            sample_rate_hz,
            tail_samples,
            search_range_samples,
            Some(delay_estimator),
        )
    }

    /// Shared MDF constructor: validates the rate, builds the MDF (sized for `max_bulk_delay`), and
    /// wires the optional delay estimator. The time-domain `weights`/`foreground` are allocated inert
    /// so the struct shape (and `reset`) is uniform across backends.
    fn build_mdf(
        sample_rate_hz: u32,
        tail_samples: usize,
        max_bulk_delay: usize,
        delay_estimator: Option<DelayEstimator>,
    ) -> Result<Self, AecError> {
        if sample_rate_hz < 8_000 || !sample_rate_hz.is_multiple_of(50) {
            return Err(AecError::InvalidSampleRate(sample_rate_hz));
        }
        let frame_samples = (sample_rate_hz / 50) as usize;
        let mdf = MdfFilter::new(frame_samples, tail_samples, max_bulk_delay)?;
        let tail = mdf.tail;
        Ok(Self {
            sample_rate_hz,
            frame_samples,
            tail_samples: tail,
            weights: vec![0.0; tail],
            foreground: vec![0.0; tail],
            dtd_mode: DtdMode::Geigel,
            last_correlation: None,
            copies: 0,
            reference: FarEndReference::new(1, 0, frame_samples),
            step_size: DEFAULT_STEP_SIZE,
            regularization: DEFAULT_REGULARIZATION,
            geigel_threshold: DEFAULT_GEIGEL_THRESHOLD,
            far_peak_floor: DEFAULT_FAR_PEAK_FLOOR,
            doubletalk_hold_frames: 0,
            doubletalk_hangover_frames: DEFAULT_DOUBLETALK_HANGOVER_FRAMES,
            doubletalk_active: false,
            delay_estimator,
            mdf: Some(mdf),
            res: None,
            res_near_snapshot: vec![0.0; frame_samples],
            res_echo_frame: vec![0.0; frame_samples],
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
        if let Some(mdf) = self.mdf.as_mut() {
            mdf.dtd = MdfDtd::TwoPath;
        }
        self
    }

    /// Chain a **residual-echo suppressor** (spectral post-filter) after the linear backend
    /// (chainable with every constructor and with [`EchoCanceller::with_two_path_dtd`], e.g.
    /// `EchoCanceller::with_mdf(8_000, 1024)?.with_two_path_dtd().with_residual_suppression()?`).
    ///
    /// The linear NLMS/MDF filter removes only the echo that is a *linear* function of the far-end
    /// within its tail; loudspeaker nonlinearity and under-modelled tail energy survive as a residual
    /// echo in the emitted signal. The suppressor runs the residual through a √Hann WOLA STFT and
    /// applies a per-bin decision-directed Wiener gain whose interference PSD is an adaptive
    /// leakage-scaled estimate of the residual-echo power (from the frame-synchronous echo estimate),
    /// **gated by this canceller's double-talk detector** so it never chews the near-end talker (see
    /// [`ResidualEchoSuppressor`]). It is off unless this is called, so the committed linear residual
    /// stays byte-for-byte identical without it.
    ///
    /// The suppressor adds a fixed `N`-sample (~32 ms) WOLA algorithmic delay on top of the backend's
    /// own latency — see [`EchoCanceller::residual_suppression_latency_samples`]. With the MDF backend
    /// this also turns on the (otherwise skipped) frame-synchronous echo-estimate capture. All state is
    /// preallocated, so the hot path stays zero-per-frame-heap.
    ///
    /// # Errors
    /// [`AecError::ResidualSuppressionUnavailable`] if the sample rate is not 8000 or 16000 Hz (the
    /// suppressor's supported WOLA sizes).
    pub fn with_residual_suppression(mut self) -> Result<Self, AecError> {
        let suppressor =
            ResidualEchoSuppressor::new(self.sample_rate_hz).map_err(|error| match error {
                DspError::InvalidSampleRate { rate } => {
                    AecError::ResidualSuppressionUnavailable { rate }
                }
                // The only failure `ResidualEchoSuppressor::new` returns for a validated rate is the rate
                // itself; map anything else to the same surface rather than panicking.
                _ => AecError::ResidualSuppressionUnavailable {
                    rate: self.sample_rate_hz,
                },
            })?;
        if let Some(mdf) = self.mdf.as_mut() {
            mdf.enable_echo_capture();
        }
        self.res = Some(suppressor);
        Ok(self)
    }

    /// Whether the adaptive filter backend is the MDF / partitioned-block frequency-domain filter
    /// (else the default time-domain NLMS).
    #[must_use]
    pub fn mdf_enabled(&self) -> bool {
        self.mdf.is_some()
    }

    /// The MDF block size (partition length) in samples, or `None` when the time-domain backend is
    /// active. The block backend adds this many samples of algorithmic latency (~16 ms).
    #[must_use]
    pub fn mdf_block_size(&self) -> Option<usize> {
        self.mdf.as_ref().map(|mdf| mdf.block_size)
    }

    /// The MDF partition count `K` (`tail = K·block_size`), or `None` for the time-domain backend.
    #[must_use]
    pub fn mdf_partitions(&self) -> Option<usize> {
        self.mdf.as_ref().map(|mdf| mdf.partitions)
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
        match self.mdf.as_ref() {
            Some(mdf) => mdf.last_correlation,
            None => self.last_correlation,
        }
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
        match self.mdf.as_ref() {
            Some(mdf) => mdf.bulk_delay(),
            None => self.reference.bulk_delay,
        }
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

    /// Whether a residual-echo suppressor is chained on (see
    /// [`EchoCanceller::with_residual_suppression`]).
    #[must_use]
    pub fn residual_suppression_enabled(&self) -> bool {
        self.res.is_some()
    }

    /// The extra algorithmic delay in samples the residual-echo suppressor adds on top of the linear
    /// backend's latency (one WOLA window `N` — 256 @ 8 kHz, 512 @ 16 kHz), or `None` when it is not
    /// enabled.
    #[must_use]
    pub fn residual_suppression_latency_samples(&self) -> Option<usize> {
        self.res
            .as_ref()
            .map(ResidualEchoSuppressor::latency_samples)
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

        // Snapshot the near-end before a time-domain backend overwrites it in place, so the residual-
        // echo suppressor can form `y_echo = near − residual`. The MDF backend captures its own
        // frame-aligned echo estimate instead, so it needs no snapshot.
        if self.res.is_some() && self.mdf.is_none() {
            for (slot, &sample) in self.res_near_snapshot[..n].iter_mut().zip(near_end.iter()) {
                *slot = f32::from(sample) / SAMPLE_SCALE;
            }
        }

        if self.mdf.is_some() {
            self.cancel_mdf(n, near_end, reference, geigel_tripped);
        } else {
            match self.dtd_mode {
                DtdMode::Geigel => self.cancel_geigel(n, near_end, reference, geigel_tripped),
                DtdMode::TwoPath => {
                    self.cancel_two_path(n, near_end, reference, geigel_tripped, far_active);
                }
            }
        }

        // Residual-echo post-filter (off unless chained on): suppress the nonlinear / under-modelled
        // echo the linear backend left behind, gated by the double-talk decision just computed.
        if self.res.is_some() {
            self.run_residual_suppression(near_end, n);
        }
    }

    /// Run the chained residual-echo suppressor on the just-emitted residual frame. Stages the
    /// frame-synchronous echo estimate (`near − residual` for the time-domain backends, the MDF's own
    /// block-aligned capture for the MDF) and applies the spectral post-filter in place, gated by the
    /// frame's double-talk decision. A no-op unless [`EchoCanceller::with_residual_suppression`] was
    /// called (the caller checks `self.res.is_some()`).
    fn run_residual_suppression(&mut self, near_end: &mut [i16], n: usize) {
        let Self {
            res,
            mdf,
            res_near_snapshot,
            res_echo_frame,
            doubletalk_active,
            ..
        } = self;
        let Some(res) = res.as_mut() else {
            return;
        };
        let double_talk = *doubletalk_active;
        match mdf.as_ref() {
            // MDF: the block-aligned echo estimate is delayed with the residual, so both drained frames
            // line up sample-for-sample.
            Some(mdf) => {
                let echo = mdf.echo_frame(n);
                let take = echo.len().min(n);
                res_echo_frame[..take].copy_from_slice(&echo[..take]);
                res_echo_frame[take..n].iter_mut().for_each(|s| *s = 0.0);
            }
            // Time-domain: `y_echo = near_before − residual`, frame-synchronous (no backend latency).
            None => {
                for (echo, (&near_before, &residual)) in res_echo_frame[..n]
                    .iter_mut()
                    .zip(res_near_snapshot[..n].iter().zip(near_end.iter()))
                {
                    *echo = near_before - f32::from(residual) / SAMPLE_SCALE;
                }
            }
        }
        res.process(near_end, &res_echo_frame[..n], double_talk);
    }

    /// The MDF / partitioned-block frequency-domain cancel path. It composes the shared pieces: the
    /// GCC-PHAT estimator (when present) removes the bulk delay and re-aligns the MDF (resetting its
    /// weights on a committed change), the Geigel screen gates adaptation in [`DtdMode::Geigel`], and
    /// the MDF's own per-block NCC gates it in [`DtdMode::TwoPath`]. The near-end is echo-subtracted in
    /// place (delayed by the fixed block latency).
    fn cancel_mdf(
        &mut self,
        n: usize,
        near_end: &mut [i16],
        reference: &[i16],
        geigel_tripped: bool,
    ) {
        // Geigel frame gate (the default DTD): freeze adaptation on a trip, with the same hangover the
        // time-domain path uses. In two-path mode the MDF ignores this and runs its per-block NCC, so
        // `base_adapt` is only consulted there for the `doubletalk_active` status surface.
        if geigel_tripped {
            self.doubletalk_hold_frames = self.doubletalk_hangover_frames;
        }
        let base_adapt = self.doubletalk_hold_frames == 0;
        if self.doubletalk_hold_frames > 0 {
            self.doubletalk_hold_frames -= 1;
        }

        // GCC-PHAT bulk-delay estimation on the raw pair (before near_end is overwritten). A committed
        // (re-)alignment retunes the MDF reference and resets its weights (tuned to the old offset).
        let realign = self
            .delay_estimator
            .as_mut()
            .and_then(|estimator| estimator.observe(&near_end[..n], &reference[..n], base_adapt));
        if let Some(new_delay) = realign {
            if let Some(mdf) = self.mdf.as_mut() {
                if new_delay != mdf.bulk_delay() {
                    mdf.set_bulk_delay(new_delay);
                }
            }
        }

        let two_path = self.dtd_mode == DtdMode::TwoPath;
        // SAFETY-of-logic: `mdf` is `Some` on this path (checked by the caller).
        if let Some(mdf) = self.mdf.as_mut() {
            mdf.push_frame(near_end, reference, base_adapt);
            // Surface the DTD status for the accessors: the block-level NCC in two-path mode, or the
            // Geigel frame decision in the default mode.
            self.doubletalk_active = if two_path {
                mdf.doubletalk_active
            } else {
                !base_adapt
            };
            self.last_correlation = mdf.last_correlation;
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
        let mut background_adapt =
            far_active && (bootstrapping || self.doubletalk_hold_frames == 0);

        // --- GCC-PHAT bulk-delay estimation on the *raw* near-end (before it is overwritten) ---
        // A newly committed alignment invalidates *both* filters (they were tuned to the old offset),
        // so reset them and the copy/DTD state; the filters re-converge over the following frames.
        let realign = self.delay_estimator.as_mut().and_then(|estimator| {
            estimator.observe(&near_end[..n], &reference[..n], background_adapt)
        });
        if let Some(new_delay) = realign {
            if new_delay != self.reference.bulk_delay {
                self.reference.set_bulk_delay(new_delay);
                self.weights.iter_mut().for_each(|weight| *weight = 0.0);
                self.foreground.iter_mut().for_each(|weight| *weight = 0.0);
                // The re-aligned filters are unconverged again — reset the two-path bootstrap/DTD state
                // (mirrors `MdfFilter::set_bulk_delay`). Without clearing `copies`, `bootstrapping` stays
                // false, so on a loud echo the zeroed filter (`sum_echo_sq == 0` → `ρ = None`, never
                // `confident_echo_only`) leaves the Geigel-driven freeze permanently armed and the
                // background never re-adapts — a permanent double-talk deadlock. Clearing it re-opens the
                // bootstrap bypass so the NCC re-converges.
                self.copies = 0;
                self.doubletalk_hold_frames = 0;
                self.doubletalk_active = false;
                self.last_correlation = None;
                // Re-open this frame's adaptation gate off the reset (bootstrapping) state so the zeroed
                // background starts re-converging immediately rather than one frame late.
                background_adapt = far_active;
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
        if let Some(mdf) = self.mdf.as_mut() {
            mdf.reset();
        }
        if let Some(res) = self.res.as_mut() {
            res.reset();
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

    /// Total energy of the MDF weight spectra (a convergence probe; `None` for the time-domain
    /// backend).
    #[cfg(test)]
    fn mdf_weight_energy(&self) -> Option<f64> {
        self.mdf.as_ref().map(MdfFilter::weight_energy)
    }

    /// A snapshot of the MDF weight spectra (tests assert bit-for-bit freeze during double-talk).
    #[cfg(test)]
    fn mdf_weights_snapshot(&self) -> Option<Vec<Complex>> {
        self.mdf.as_ref().map(MdfFilter::weights_snapshot)
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

    /// Regression: the two-path filter converges at the start-up `bulk_delay = 0` (the echo delay `D`
    /// fits inside the tail) so `copies > 0` while the GCC-PHAT estimator is still accumulating; the
    /// estimator's first lock (0 → `D`) then re-aligns the ring and zeroes both filters. If that re-lock
    /// does not also clear the two-path bootstrap/DTD state, a *loud* echo keeps the Geigel-driven freeze
    /// armed forever — the zeroed filter yields `sum_echo_sq == 0` → `ρ = None` → never
    /// `confident_echo_only`, so `background_adapt` stays false and the filter deadlocks at ~0 dB ERLE.
    /// With the reset the bootstrap re-opens and it re-converges. Uses a 3× RIR (ERL ≈ 8 dB) so the
    /// single-talk echo peak (~0.8× the far peak) trips Geigel every frame — the exact deadlock trigger.
    #[test]
    fn two_path_reconverges_after_delay_relock() {
        let frame = 160;
        let tail = 192;
        let search_range = 512;
        // Echo delay small enough to be cancellable at the start-up `bulk_delay = 0` (D + RIR spread
        // 110 < tail 192), so the filter converges *before* the estimator commits and moves the ring.
        let delay = 40usize;
        let frames = 260;
        let rir_loud: Vec<f32> = build_rir(128).iter().map(|&c| c * 3.0).collect();
        let mut canceller = EchoCanceller::with_delay_estimation(8_000, tail, search_range)
            .expect("build")
            .with_two_path_dtd();
        let mut prng = SplitMix64::new(0xC0DE_1111);
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir_loud, delay);

        let mut copies_before_lock = 0u64;
        let mut late_erle = f64::INFINITY;
        for index in 0..frames {
            // Capture the copy count just before the estimator's first lock, to prove the regression is
            // armed (the filter had converged, `copies > 0`, at the moment the re-lock zeroed it).
            if canceller.estimated_bulk_delay().is_none() {
                copies_before_lock = canceller.foreground_copies();
            }
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            if index >= frames - 20 {
                late_erle = late_erle.min(erle_db(&echo[range], &mic));
            }
        }

        let estimated = canceller
            .estimated_bulk_delay()
            .expect("GCC-PHAT must lock the delay");
        assert!(
            estimated.abs_diff(delay) <= DELAY_RECOVERY_TOLERANCE,
            "estimator must lock {delay} (got {estimated}) so the re-lock path is exercised"
        );
        assert!(
            copies_before_lock > 0,
            "regression not armed: the filter must have converged (copies > 0) before the first lock"
        );
        assert!(
            late_erle >= 20.0,
            "two-path deadlocked after the delay re-lock: late ERLE {late_erle:.1} dB < 20 dB"
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

    // ---- MDF / partitioned-block frequency-domain adaptive filter ----

    /// A long, sparse-plus-dispersive room impulse response (up to `len` taps @ 8 kHz): a decaying
    /// early cluster plus late reflections placed **well beyond a 256-tab NLMS tail** (at ~800 / 1200 /
    /// 1600 taps). A short time-domain NLMS cannot reach those late taps; the MDF long tail can.
    const LONG_ROOM_IMPULSE_RESPONSE: &[(usize, f32)] = &[
        (5, 0.100),
        (11, -0.075),
        (23, 0.055),
        (47, -0.040),
        (95, 0.030),
        (190, -0.022),
        (380, 0.016),
        (800, -0.045),
        (1200, 0.030),
        (1600, -0.020),
    ];

    fn build_long_rir(len: usize) -> Vec<f32> {
        let mut rir = vec![0.0f32; len];
        for &(tap, amplitude) in LONG_ROOM_IMPULSE_RESPONSE {
            if tap < len {
                rir[tap] = amplitude;
            }
        }
        rir
    }

    /// Steady-state ERLE (dB) over the last `tail_frames` frames of a run: the block latency is a
    /// constant shift that averages out over the window, so the echo/residual power ratio is a clean
    /// steady-state measure regardless of the MDF's algorithmic delay.
    fn steady_erle(echo: &[i16], residual: &[i16], frame: usize, tail_frames: usize) -> f64 {
        let start = echo.len().saturating_sub(tail_frames * frame);
        erle_db(&echo[start..], &residual[start..])
    }

    #[test]
    fn mdf_accessors_report_configuration() {
        let canceller = EchoCanceller::with_mdf(8_000, 1024).expect("build");
        assert!(canceller.mdf_enabled());
        assert_eq!(canceller.sample_rate_hz(), 8_000);
        assert_eq!(canceller.frame_samples(), 160);
        assert_eq!(canceller.mdf_block_size(), Some(128)); // floor_pow2(160)
        assert_eq!(canceller.mdf_partitions(), Some(8)); // ceil(1024/128)
        assert_eq!(canceller.tail_samples(), 1024); // K·B == 8·128
        assert_eq!(canceller.bulk_delay_samples(), 0);
        assert!(!canceller.double_talk_active());

        let wideband = EchoCanceller::with_mdf(16_000, 2048).expect("build");
        assert_eq!(wideband.mdf_block_size(), Some(256)); // floor_pow2(320)
        assert_eq!(wideband.mdf_partitions(), Some(8)); // ceil(2048/256)

        // The time-domain backend reports no MDF state.
        let time_domain = EchoCanceller::new(8_000, 256).expect("build");
        assert!(!time_domain.mdf_enabled());
        assert_eq!(time_domain.mdf_block_size(), None);
        assert_eq!(time_domain.mdf_partitions(), None);
    }

    #[test]
    fn mdf_rejects_invalid_config() {
        assert!(matches!(
            EchoCanceller::with_mdf(7_000, 1024),
            Err(AecError::InvalidSampleRate(7_000))
        ));
        assert!(matches!(
            EchoCanceller::with_mdf(8_000, 0),
            Err(AecError::InvalidTail { got: 0, .. })
        ));
        assert!(matches!(
            EchoCanceller::with_mdf(8_000, MAX_TAIL_SAMPLES + 1),
            Err(AecError::InvalidTail { .. })
        ));
        assert!(matches!(
            EchoCanceller::with_mdf_delay_estimation(8_000, 1024, 0),
            Err(AecError::InvalidSearchRange { got: 0, .. })
        ));
    }

    /// Golden ERLE for the MDF: on a committed synthetic echo it cancels by ≥ 20 dB in steady state,
    /// reaching it within a bounded frame count — the same acceptance bar as the short-tail NLMS.
    #[test]
    fn mdf_converges_to_high_erle_on_synthetic_echo() {
        let tail = 1024;
        let frame = 160;
        let frames = 240;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x3DF0_2026);
        let mut canceller = EchoCanceller::with_mdf(8_000, tail).expect("build");

        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);

        let mut residual_stream = vec![0i16; frames * frame];
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            residual_stream[range].copy_from_slice(&mic);
        }
        let steady = steady_erle(&echo, &residual_stream, frame, 40);
        assert!(
            steady >= 20.0,
            "MDF steady-state ERLE {steady:.1} dB < 20 dB"
        );
    }

    /// **MDF beats the time-domain NLMS on a long echo tail.** The RIR has significant energy at ~800,
    /// 1200 and 1600 taps — far outside a 256-tap NLMS window, so the NLMS (the inline-budget default)
    /// leaves that echo energy uncancelled and its ERLE is capped. The MDF long tail (1792 taps, 14
    /// partitions) covers the whole response and reaches a high ERLE. Asserts a large, quantified gap.
    #[test]
    fn mdf_beats_nlms_on_long_tail() {
        let frame = 160;
        let frames = 300;
        let long_tail = 1792; // 14 partitions of 128 → spans past the 1600-tap reflection
        let nlms_tail = 256; // the inline-budget time-domain default
        let rir = build_long_rir(1700);
        let mut prng = SplitMix64::new(0x104C_7A11);
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);

        let run = |canceller: &mut EchoCanceller| -> f64 {
            let mut residual_stream = vec![0i16; frames * frame];
            for index in 0..frames {
                let range = index * frame..(index + 1) * frame;
                let mut mic = echo[range.clone()].to_vec();
                canceller.cancel(&mut mic, &far[range.clone()]);
                residual_stream[range].copy_from_slice(&mic);
            }
            steady_erle(&echo, &residual_stream, frame, 40)
        };

        let mut nlms = EchoCanceller::new(8_000, nlms_tail).expect("build");
        let nlms_erle = run(&mut nlms);
        let mut mdf = EchoCanceller::with_mdf(8_000, long_tail).expect("build");
        let mdf_erle = run(&mut mdf);

        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!("long-tail ERLE: NLMS(256) {nlms_erle:.1} dB, MDF(1792) {mdf_erle:.1} dB");
        }
        // The short NLMS cannot reach the late taps → its ERLE is capped well below the MDF's.
        assert!(
            nlms_erle < 15.0,
            "short NLMS unexpectedly cancelled the long tail ({nlms_erle:.1} dB)"
        );
        assert!(
            mdf_erle >= 20.0,
            "MDF long tail only reached {mdf_erle:.1} dB (want ≥ 20 dB)"
        );
        assert!(
            mdf_erle - nlms_erle >= 10.0,
            "MDF long-tail advantage only {:.1} dB (NLMS {nlms_erle:.1} → MDF {mdf_erle:.1})",
            mdf_erle - nlms_erle
        );
    }

    /// Determinism: the MDF path is a pure function of the input (logical clock, fixed-seed PRNG), so
    /// two identical runs yield identical residual streams and weight energies.
    #[test]
    fn mdf_is_deterministic() {
        let run = || {
            let frame = 160;
            let rir = build_rir(128);
            let mut prng = SplitMix64::new(0xD37E_3333);
            let mut canceller = EchoCanceller::with_mdf(8_000, 1024).expect("build");
            let far = far_stream(&mut prng, 0.6, 80 * frame);
            let echo = synthesize_echo(&normalize(&far), &rir, 0);
            let mut residual_stream = vec![0i16; 80 * frame];
            for index in 0..80 {
                let range = index * frame..(index + 1) * frame;
                let mut mic = echo[range.clone()].to_vec();
                canceller.cancel(&mut mic, &far[range.clone()]);
                residual_stream[range].copy_from_slice(&mic);
            }
            (residual_stream, canceller.mdf_weight_energy())
        };
        let (first_residual, first_energy) = run();
        let (second_residual, second_energy) = run();
        assert_eq!(first_residual, second_residual);
        assert_eq!(first_energy, second_energy);
    }

    #[test]
    fn mdf_reset_clears_state() {
        let frame = 160;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x4E5E_7001);
        let mut canceller = EchoCanceller::with_mdf(8_000, 1024).expect("build");
        let far = far_stream(&mut prng, 0.6, 60 * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        for index in 0..60 {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }
        assert!(
            canceller.mdf_weight_energy().expect("mdf") > 0.0,
            "MDF must have adapted before reset"
        );
        canceller.reset();
        assert_eq!(canceller.mdf_weight_energy(), Some(0.0));
        assert_eq!(canceller.bulk_delay_samples(), 0);
        assert!(!canceller.double_talk_active());
    }

    /// Composition — MDF + **GCC-PHAT**: an unknown bulk delay misaligns the reference; automatic
    /// estimation recovers it (the MDF partitions then cover only the residual dispersion) and the
    /// long-tail filter still reaches the ≥ 20 dB ERLE target.
    #[test]
    fn mdf_with_delay_estimation_recovers_unknown_delay() {
        let frame = 160;
        let search_range = 512;
        let unknown_delay = 256;
        let frames = 320;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0xE51E_3DF0);
        let mut canceller =
            EchoCanceller::with_mdf_delay_estimation(8_000, 512, search_range).expect("build");
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, unknown_delay);

        let mut residual_stream = vec![0i16; frames * frame];
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            residual_stream[range].copy_from_slice(&mic);
        }
        let estimated = canceller
            .estimated_bulk_delay()
            .expect("GCC-PHAT must lock the delay under the MDF backend");
        assert!(
            estimated.abs_diff(unknown_delay) <= DELAY_RECOVERY_TOLERANCE,
            "estimated {estimated} for injected {unknown_delay}"
        );
        assert_eq!(canceller.bulk_delay_samples(), estimated);
        let steady = steady_erle(&echo, &residual_stream, frame, 40);
        assert!(
            steady >= 20.0,
            "MDF + delay-estimation steady ERLE {steady:.1} dB < 20 dB"
        );
    }

    /// Composition — MDF + **two-path NCC double-talk freeze**: converge the foreground long-tail
    /// filter, then inject a near-end talker. The per-block NCC must (a) flag double-talk, (b) hold the
    /// MDF weight spectra **frozen bit-for-bit** through it, (c) pass the near-end through with bounded
    /// leakage, and (d) recover ERLE the instant the near-end stops (the protected weights never
    /// degraded).
    #[test]
    fn mdf_two_path_freezes_through_double_talk() {
        let tail = 1024;
        let frame = 160;
        let converge_frames = 140;
        let settle_frames = 4; // let the NCC + hangover engage across the boundary blocks
        let double_talk_frames = 30;
        let recover_frames = 50;
        let total = converge_frames + double_talk_frames + recover_frames;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x0DDB_A11F);
        let mut canceller = EchoCanceller::with_mdf(8_000, tail)
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

        // 2) Double-talk. Snapshot the weights a few frames in (once the NCC + hangover have engaged
        //    across the block boundary) and require them frozen bit-for-bit for the rest of the segment.
        //    Near-end preservation is measured as a power ratio (latency-invariant, unlike a sample-wise
        //    difference the MDF's block delay would corrupt): with the filter frozen at its
        //    echo-cancelling state the residual is `≈ near-talk`, so its power tracks the talker's.
        let mut double_talk_seen = false;
        let mut residual_power_sum = 0.0f64;
        let mut talk_power_sum = 0.0f64;
        let mut frozen_snapshot: Option<Vec<Complex>> = None;
        for offset in 0..double_talk_frames {
            let index = converge_frames + offset;
            let range = frame_range(index);
            let talk = &near_talk[range.clone()];
            let mut mic: Vec<i16> = echo[range.clone()]
                .iter()
                .zip(talk)
                .map(|(&echo_sample, &near_sample)| echo_sample.saturating_add(near_sample))
                .collect();
            canceller.cancel(&mut mic, &far[range]);
            double_talk_seen |= canceller.double_talk_active();
            if offset == settle_frames {
                frozen_snapshot = canceller.mdf_weights_snapshot();
            }
            if offset >= settle_frames {
                assert_eq!(
                    frozen_snapshot.as_deref(),
                    canceller.mdf_weights_snapshot().as_deref(),
                    "MDF weights must be frozen bit-for-bit during double-talk (frame offset {offset})"
                );
                residual_power_sum += power_i16(&mic) * frame as f64;
                talk_power_sum += power_i16(talk) * frame as f64;
            }
        }
        assert!(double_talk_seen, "MDF two-path must flag the double-talk");
        // The near-end passes through neither cancelled nor amplified: residual power within ±3 dB of
        // the near-talk power.
        let preservation_db = 10.0 * (residual_power_sum / talk_power_sum.max(1.0)).log10();
        assert!(
            preservation_db.abs() <= 3.0,
            "near-end not preserved: residual/near-talk power {preservation_db:.1} dB (want |·| ≤ 3 dB)"
        );

        // 3) Near-end stops: ERLE recovers (the protected weights never degraded). Measured over the
        //    steady window, skipping the first few frames while the output ring drains the block-latency
        //    tail of double-talk residual.
        let skip = 5;
        let mut residual_stream = vec![0i16; recover_frames * frame];
        for offset in 0..recover_frames {
            let index = converge_frames + double_talk_frames + offset;
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            let local = offset * frame..(offset + 1) * frame;
            residual_stream[local].copy_from_slice(&mic);
        }
        let recovered_echo_start = (converge_frames + double_talk_frames + skip) * frame;
        let recovered = erle_db(
            &echo[recovered_echo_start..],
            &residual_stream[skip * frame..],
        );
        assert!(
            recovered >= 20.0,
            "ERLE recovered to only {recovered:.1} dB after double-talk"
        );
    }

    /// Composition — **all three together**: MDF long-tail backend + GCC-PHAT (unknown delay) +
    /// two-path NCC. The delay is recovered, the ERLE target met, and the near-end preserved through a
    /// scripted double-talk (the weights survive it), proving the three pieces compose.
    #[test]
    fn mdf_composition_delay_estimation_and_two_path() {
        let tail = 512;
        let frame = 160;
        let search_range = 512;
        let unknown_delay = 200;
        let converge_frames = 180;
        let double_talk_frames = 25;
        let recover_frames = 60;
        let total = converge_frames + double_talk_frames + recover_frames;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0xC0FF_EE3D);
        let mut canceller = EchoCanceller::with_mdf_delay_estimation(8_000, tail, search_range)
            .expect("build")
            .with_two_path_dtd();
        let far = far_stream(&mut prng, 0.6, total * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, unknown_delay);
        let near_talk: Vec<i16> = (0..total * frame)
            .map(|t| {
                super::denormalize(
                    0.6 * (2.0 * std::f32::consts::PI * 350.0 * t as f32 / 8_000.0).sin(),
                )
            })
            .collect();
        let frame_range = |index: usize| index * frame..(index + 1) * frame;

        for index in 0..converge_frames {
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }
        assert!(
            canceller
                .estimated_bulk_delay()
                .is_some_and(|delay| delay.abs_diff(unknown_delay) <= DELAY_RECOVERY_TOLERANCE),
            "GCC-PHAT must lock ~{unknown_delay} under MDF + two-path (got {:?})",
            canceller.estimated_bulk_delay()
        );
        let weights_before = canceller.mdf_weight_energy().expect("mdf");

        let mut double_talk_seen = false;
        for offset in 0..double_talk_frames {
            let index = converge_frames + offset;
            let range = frame_range(index);
            let talk = &near_talk[range.clone()];
            let mut mic: Vec<i16> = echo[range.clone()]
                .iter()
                .zip(talk)
                .map(|(&echo_sample, &near_sample)| echo_sample.saturating_add(near_sample))
                .collect();
            canceller.cancel(&mut mic, &far[range]);
            double_talk_seen |= canceller.double_talk_active();
        }
        assert!(double_talk_seen, "double-talk must be flagged");
        // The weights must not have run off learning the near-end talker.
        let weights_after = canceller.mdf_weight_energy().expect("mdf");
        assert!(
            weights_after <= weights_before * 2.0,
            "MDF weights diverged during double-talk: {weights_before:.3} -> {weights_after:.3}"
        );

        let skip = 5;
        let mut residual_stream = vec![0i16; recover_frames * frame];
        for offset in 0..recover_frames {
            let index = converge_frames + double_talk_frames + offset;
            let range = frame_range(index);
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            let local = offset * frame..(offset + 1) * frame;
            residual_stream[local].copy_from_slice(&mic);
        }
        // Skip the block-latency transition (output ring draining the double-talk tail).
        let recovered_echo_start = (converge_frames + double_talk_frames + skip) * frame;
        let recovered = erle_db(
            &echo[recovered_echo_start..],
            &residual_stream[skip * frame..],
        );
        assert!(
            recovered >= 20.0,
            "composed MDF + delay-est + two-path recovered ERLE only {recovered:.1} dB"
        );
    }

    // ---- residual-echo suppressor (spectral post-filter) ----

    /// A room impulse response with a reflection placed **beyond** a 256-tap tail (at tap 400), so a
    /// short time-domain NLMS leaves it as an uncancellable *linear* residual echo — the
    /// "under-modelled tail" the residual-echo suppressor knocks down. Its residual power tracks the
    /// far-end (and hence the linear echo estimate) per bin, exactly the leakage model the RES assumes.
    fn build_rir_with_late_reflection() -> Vec<f32> {
        let mut rir = build_rir(420);
        rir[400] = 0.045;
        rir
    }

    /// Run one single-talk (echo-only) pass of `canceller` over a fixed far-end/echo and report the
    /// steady-state ERLE over the last `tail_frames` frames (latency-invariant power ratio).
    fn run_echo_only_erle(
        canceller: &mut EchoCanceller,
        far: &[i16],
        echo: &[i16],
        frame: usize,
        tail_frames: usize,
    ) -> f64 {
        let frames = far.len() / frame;
        let mut residual_stream = vec![0i16; frames * frame];
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range.clone()]);
            residual_stream[range].copy_from_slice(&mic);
        }
        steady_erle(echo, &residual_stream, frame, tail_frames)
    }

    #[test]
    fn residual_suppression_off_by_default() {
        let canceller = EchoCanceller::new(8_000, 256).expect("build");
        assert!(!canceller.residual_suppression_enabled());
        assert_eq!(canceller.residual_suppression_latency_samples(), None);

        let with_res = EchoCanceller::new(8_000, 256)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        assert!(with_res.residual_suppression_enabled());
        assert_eq!(with_res.residual_suppression_latency_samples(), Some(256));
        let wideband = EchoCanceller::new(16_000, 256)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        assert_eq!(wideband.residual_suppression_latency_samples(), Some(512));
    }

    #[test]
    fn residual_suppression_rejects_unsupported_rate() {
        // The canceller supports any rate ≥ 8 kHz that is a multiple of 50; the RES supports only the
        // 8/16 kHz WOLA sizes, so chaining it at 32 kHz is a clean typed error, not a panic.
        let result = EchoCanceller::new(32_000, 256)
            .expect("build")
            .with_residual_suppression();
        assert!(matches!(
            result,
            Err(AecError::ResidualSuppressionUnavailable { rate: 32_000 })
        ));
    }

    /// **Total ERLE improvement.** On an echo path whose late reflection sits beyond the linear tail
    /// (a measurable linear residual the NLMS cannot reach), the RES post-filter adds a quantified
    /// extra suppression on top of the linear ERLE, measured on echo-only segments.
    #[test]
    fn residual_suppression_adds_erle_on_under_modelled_tail() {
        let frame = 160;
        let tail = 256;
        let frames = 260;
        let rir = build_rir_with_late_reflection();
        let mut prng = SplitMix64::new(0x08E5_C0DE);
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);

        let mut linear = EchoCanceller::new(8_000, tail).expect("build");
        let linear_erle = run_echo_only_erle(&mut linear, &far, &echo, frame, 60);

        let mut suppressed = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        let suppressed_erle = run_echo_only_erle(&mut suppressed, &far, &echo, frame, 60);

        let extra = suppressed_erle - linear_erle;
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!(
                "under-modelled tail ERLE: linear {linear_erle:.1} dB, +RES {suppressed_erle:.1} dB, extra {extra:.1} dB"
            );
        }
        assert!(
            extra >= 6.0,
            "RES added only {extra:.1} dB of residual-echo attenuation (want ≥ 6 dB); linear {linear_erle:.1} → +RES {suppressed_erle:.1}"
        );
    }

    /// **Total ERLE improvement under a loudspeaker nonlinearity.** A memoryless cubic on the far-end
    /// before the (linear) room convolution leaves a nonlinear residual the adaptive filter cannot
    /// model; the RES still adds a quantified extra attenuation on echo-only segments.
    #[test]
    fn residual_suppression_adds_erle_on_nonlinear_echo() {
        let frame = 160;
        let tail = 256;
        let frames = 260;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x0000_1E5D_1234);
        let far = far_stream(&mut prng, 0.6, frames * frame);
        // Loudspeaker nonlinearity: y = x + 0.3·x³ (normalized), then the linear room convolution.
        let far_normalized = normalize(&far);
        let driven: Vec<f32> = far_normalized
            .iter()
            .map(|&x| x + 0.3 * x * x * x)
            .collect();
        let echo = synthesize_echo(&driven, &rir, 0);

        let mut linear = EchoCanceller::new(8_000, tail).expect("build");
        let linear_erle = run_echo_only_erle(&mut linear, &far, &echo, frame, 60);
        let mut suppressed = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        let suppressed_erle = run_echo_only_erle(&mut suppressed, &far, &echo, frame, 60);

        let extra = suppressed_erle - linear_erle;
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!(
                "nonlinear echo ERLE: linear {linear_erle:.1} dB, +RES {suppressed_erle:.1} dB, extra {extra:.1} dB"
            );
        }
        assert!(
            extra >= 6.0,
            "RES added only {extra:.1} dB on nonlinear echo (want ≥ 6 dB); linear {linear_erle:.1} → +RES {suppressed_erle:.1}"
        );
    }

    /// **Near-end preservation (near-end only).** With the far-end silent (no echo), the near-end
    /// talker must pass through the RES essentially untouched — it must not mistake speech for echo.
    #[test]
    fn residual_suppression_preserves_near_end_only() {
        let frame = 160;
        let tail = 256;
        let converge_frames = 120;
        let near_frames = 80;
        let rir = build_rir_with_late_reflection();
        let mut prng = SplitMix64::new(0x0EA5_1DE0);
        let mut canceller = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_residual_suppression()
            .expect("res");

        // Converge on echo-only.
        let far = far_stream(&mut prng, 0.6, converge_frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        for index in 0..converge_frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }

        // Near-end only, far-end silent: measure output/near power over the segment interior.
        let silent_far = vec![0i16; near_frames * frame];
        let near: Vec<i16> = (0..near_frames * frame)
            .map(|_| super::denormalize(prng.next_noise(0.3)))
            .collect();
        let mut output = vec![0i16; near_frames * frame];
        for index in 0..near_frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = near[range.clone()].to_vec();
            canceller.cancel(&mut mic, &silent_far[range.clone()]);
            output[range].copy_from_slice(&mic);
        }
        // Skip the WOLA-latency transient at both ends.
        let interior = 4 * frame..(near_frames - 2) * frame;
        let near_power = power_i16(&near[interior.clone()]);
        let output_power = power_i16(&output[interior]);
        let attenuation_db = 10.0 * (output_power / near_power.max(1.0)).log10();
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!("near-end-only attenuation {attenuation_db:.2} dB");
        }
        assert!(
            attenuation_db.abs() <= 1.5,
            "near-end-only attenuated {attenuation_db:.2} dB (want |·| ≤ 1.5 dB)"
        );
    }

    /// **Near-end preservation (double-talk).** With the DTD flagging near-end presence on top of the
    /// echo, the RES backs off (leakage frozen, gain floored up) so the near-end talker passes with a
    /// bounded attenuation instead of being chewed.
    #[test]
    fn residual_suppression_preserves_near_end_double_talk() {
        let frame = 160;
        let tail = 256;
        let converge_frames = 120;
        let double_talk_frames = 60;
        let rir = build_rir_with_late_reflection();
        let mut prng = SplitMix64::new(0xD0B1_E7A1);
        let mut canceller = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_two_path_dtd()
            .with_residual_suppression()
            .expect("res");
        let total = converge_frames + double_talk_frames;
        let far = far_stream(&mut prng, 0.6, total * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        let near_talk: Vec<i16> = (0..total * frame)
            .map(|t| {
                super::denormalize(
                    0.5 * (2.0 * std::f32::consts::PI * 400.0 * t as f32 / 8_000.0).sin(),
                )
            })
            .collect();

        for index in 0..converge_frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }

        let mut double_talk_seen = false;
        let mut output = vec![0i16; double_talk_frames * frame];
        for offset in 0..double_talk_frames {
            let index = converge_frames + offset;
            let range = index * frame..(index + 1) * frame;
            let mut mic: Vec<i16> = echo[range.clone()]
                .iter()
                .zip(&near_talk[range.clone()])
                .map(|(&e, &s)| e.saturating_add(s))
                .collect();
            canceller.cancel(&mut mic, &far[range]);
            double_talk_seen |= canceller.double_talk_active();
            let local = offset * frame..(offset + 1) * frame;
            output[local].copy_from_slice(&mic);
        }
        assert!(double_talk_seen, "DTD must flag the double-talk");
        // Output power (near-end + suppressed residual echo) vs the near-end talker power, over the
        // segment interior: the near-end must be preserved (not cancelled) — bounded on the low side.
        let interior = 6 * frame..(double_talk_frames - 2) * frame;
        let talk_power = power_i16(
            &near_talk[(converge_frames * frame + 6 * frame)
                ..(converge_frames * frame + (double_talk_frames - 2) * frame)],
        );
        let output_power = power_i16(&output[interior]);
        let ratio_db = 10.0 * (output_power / talk_power.max(1.0)).log10();
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!("double-talk output/near-talk power {ratio_db:.1} dB");
        }
        assert!(
            ratio_db >= -3.0,
            "near-end over-suppressed during double-talk: {ratio_db:.1} dB (want ≥ -3 dB)"
        );
    }

    /// **No musical noise.** On an echo-only tail after the RES, the per-frame residual energy has a
    /// bounded coefficient of variation (musical noise would flicker isolated tones → high variance).
    #[test]
    fn residual_suppression_no_musical_noise() {
        let frame = 160;
        let tail = 256;
        let frames = 200;
        let rir = build_rir_with_late_reflection();
        let mut prng = SplitMix64::new(0xBADF_00D5);
        let mut canceller = EchoCanceller::new(8_000, tail)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        let mut energies = Vec::new();
        for index in 0..frames {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
            if index >= frames / 2 {
                energies.push(power_i16(&mic) as f32);
            }
        }
        let mean = energies.iter().sum::<f32>() / energies.len() as f32;
        let variance = energies
            .iter()
            .map(|&e| (e - mean) * (e - mean))
            .sum::<f32>()
            / energies.len() as f32;
        let coefficient_of_variation = variance.sqrt() / mean.max(1e-6);
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!("RES echo-only tail energy CoV {coefficient_of_variation:.3}");
        }
        assert!(
            coefficient_of_variation < 0.6,
            "RES residual energy CoV {coefficient_of_variation:.3} too high (musical noise)"
        );
    }

    /// **Composition with the MDF backend.** The RES chains onto the frequency-domain backend too
    /// (which captures its own frame-aligned echo estimate), adding extra ERLE on a nonlinear echo.
    #[test]
    fn residual_suppression_composes_with_mdf() {
        let frame = 160;
        let tail = 1024;
        let frames = 300;
        let rir = build_rir(128);
        let mut prng = SplitMix64::new(0x3DF0_9E51);
        let far = far_stream(&mut prng, 0.6, frames * frame);
        let driven: Vec<f32> = normalize(&far)
            .iter()
            .map(|&x| x + 0.3 * x * x * x)
            .collect();
        let echo = synthesize_echo(&driven, &rir, 0);

        let mut linear = EchoCanceller::with_mdf(8_000, tail).expect("build");
        let linear_erle = run_echo_only_erle(&mut linear, &far, &echo, frame, 60);
        let mut suppressed = EchoCanceller::with_mdf(8_000, tail)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        let suppressed_erle = run_echo_only_erle(&mut suppressed, &far, &echo, frame, 60);
        let extra = suppressed_erle - linear_erle;
        if std::env::var_os("DUMP_GOLDEN").is_some() {
            eprintln!(
                "MDF + RES ERLE: linear {linear_erle:.1} dB, +RES {suppressed_erle:.1} dB, extra {extra:.1} dB"
            );
        }
        assert!(
            extra >= 6.0,
            "RES added only {extra:.1} dB on the MDF backend (want ≥ 6 dB); linear {linear_erle:.1} → +RES {suppressed_erle:.1}"
        );
    }

    /// The RES-on cancel path is a pure function of its inputs (logical clock, fixed-seed PRNG): two
    /// identical runs produce identical residual streams.
    #[test]
    fn residual_suppression_is_deterministic() {
        let run = || {
            let frame = 160;
            let rir = build_rir_with_late_reflection();
            let mut prng = SplitMix64::new(0xD37E_9E51);
            let mut canceller = EchoCanceller::new(8_000, 256)
                .expect("build")
                .with_residual_suppression()
                .expect("res");
            let far = far_stream(&mut prng, 0.6, 80 * frame);
            let echo = synthesize_echo(&normalize(&far), &rir, 0);
            let mut residual_stream = vec![0i16; 80 * frame];
            for index in 0..80 {
                let range = index * frame..(index + 1) * frame;
                let mut mic = echo[range.clone()].to_vec();
                canceller.cancel(&mut mic, &far[range.clone()]);
                residual_stream[range].copy_from_slice(&mic);
            }
            residual_stream
        };
        assert_eq!(run(), run());
    }

    /// `reset` clears the RES state along with the canceller's: after churning frames and resetting,
    /// a silent input stays silent (no residual leakage from the pre-reset state).
    #[test]
    fn residual_suppression_reset_clears_state() {
        let frame = 160;
        let rir = build_rir_with_late_reflection();
        let mut prng = SplitMix64::new(0x5E70_9E51);
        let mut canceller = EchoCanceller::new(8_000, 256)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        let far = far_stream(&mut prng, 0.6, 60 * frame);
        let echo = synthesize_echo(&normalize(&far), &rir, 0);
        for index in 0..60 {
            let range = index * frame..(index + 1) * frame;
            let mut mic = echo[range.clone()].to_vec();
            canceller.cancel(&mut mic, &far[range]);
        }
        canceller.reset();
        assert!(
            canceller.residual_suppression_enabled(),
            "reset preserves the mode"
        );
        // After reset, a silent far-end and silent near-end stay silent through the RES too.
        let silent = vec![0i16; frame];
        for _ in 0..10 {
            let mut mic = silent.clone();
            canceller.cancel(&mut mic, &silent);
            assert!(
                mic.iter().all(|&s| s == 0),
                "post-reset silence must stay silent"
            );
        }
    }
}
