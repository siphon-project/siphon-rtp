//! √Hann analysis/synthesis windows and a streaming WOLA (weighted overlap-add) framing.
//!
//! Noise suppression runs an STFT: each internal frame is √Hann-windowed, transformed, gained, and
//! inverse-transformed, then overlap-added back into a continuous stream. This module owns the
//! framing that bridges the media pipeline's 20 ms frames (160 samples @ 8 kHz, 320 @ 16 kHz) to the
//! internal FFT hop, and guarantees **perfect reconstruction** under a unit-gain spectral operation.
//!
//! ## √Hann perfect reconstruction (50 % overlap)
//!
//! With the periodic Hann `hann[i] = 0.5 - 0.5·cos(2π·i/N)` and hop `H = N/2`, the two overlapping
//! windows satisfy `hann[i] + hann[i+H] = 1` exactly (the `+π` phase shift cancels the cosine). Using
//! the same √Hann for analysis **and** synthesis, `w_a[i]·w_s[i] = hann[i]`, so summing the two
//! overlapping analysis·synthesis products is exactly 1 — a constant-overlap-add (COLA) window pair.
//! Hence, for a unit-gain spectral op, the WOLA reproduces its input (see [`WolaProcessor`] tests).
//!
//! ## Sizes and algorithmic delay
//!
//! | rate     | frame (20 ms) | `N_fft` | hop `H = N/2` |
//! |----------|---------------|---------|---------------|
//! | 8 kHz    | 160           | 256     | 128           |
//! | 16 kHz   | 320           | 512     | 256           |
//!
//! The end-to-end algorithmic delay is **`N` samples** ([`WolaProcessor::latency_samples`]): the
//! 50 %-overlap reconstruction contributes `N/2` (≈ 16 ms at both rates — the figure usually quoted
//! for a √Hann WOLA), and because the 20 ms pipeline frame (160/320) is **not** a whole number of
//! hops (128/256), the block re-framing adds the other `N/2` (≈ 16 ms) of buffering. So the constant
//! path delay is ≈ 32 ms (256 samples @ 8 kHz, 512 @ 16 kHz), of which ≈ 16 ms is the WOLA overlap.

use crate::fft::{Complex, RealFft};
use crate::DspError;

/// Build the √Hann window of length `n`: `sqrt(0.5 - 0.5·cos(2π·i/n))`.
///
/// Used for both analysis and synthesis; the pair is COLA at 50 % overlap (see the module docs).
fn sqrt_hann(n: usize) -> Vec<f32> {
    (0..n)
        .map(|i| {
            let hann = 0.5 - 0.5 * (2.0 * std::f32::consts::PI * i as f32 / n as f32).cos();
            hann.max(0.0).sqrt()
        })
        .collect()
}

/// A fixed-capacity FIFO ring of `f32` samples with no reallocation after construction.
///
/// Both the input-pending and output-ready queues use this so the WOLA hot path never allocates.
#[derive(Clone, Debug)]
struct SampleRing {
    buffer: Vec<f32>,
    head: usize,
    length: usize,
}

impl SampleRing {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: vec![0.0; capacity.max(1)],
            head: 0,
            length: 0,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.length
    }

    /// Push one sample. Silently drops on overflow, which cannot happen because the capacity is
    /// sized to the proven worst-case occupancy in [`WolaProcessor::new`]; a `debug_assert` catches
    /// any sizing regression in tests.
    #[inline]
    fn push_back(&mut self, value: f32) {
        debug_assert!(self.length < self.buffer.len(), "SampleRing overflow");
        if self.length < self.buffer.len() {
            let index = (self.head + self.length) % self.buffer.len();
            self.buffer[index] = value;
            self.length += 1;
        }
    }

    #[inline]
    fn pop_front(&mut self) -> Option<f32> {
        if self.length == 0 {
            return None;
        }
        let value = self.buffer[self.head];
        self.head = (self.head + 1) % self.buffer.len();
        self.length -= 1;
        Some(value)
    }

    fn clear(&mut self) {
        self.head = 0;
        self.length = 0;
    }
}

/// Streaming √Hann WOLA framing over an internal real FFT.
///
/// Feed pipeline frames of any length via [`WolaProcessor::process_frame`]; each call returns the
/// same number of samples it was given, delayed by [`WolaProcessor::latency_samples`]. The spectral
/// operation closure sees each frame's `N/2 + 1` complex bins and may modify them in place (noise
/// suppression multiplies each by a Wiener gain); a no-op closure yields perfect reconstruction.
#[derive(Clone, Debug)]
pub struct WolaProcessor {
    n: usize,
    hop: usize,
    analysis_window: Vec<f32>,
    synthesis_window: Vec<f32>,
    /// Sliding analysis window: the most recent `N` input samples (oldest first).
    frame: Vec<f32>,
    /// Overlap-add accumulator for reconstructed output (length `N`).
    overlap: Vec<f32>,
    /// Scratch for the windowed time frame / IFFT output (length `N`).
    scratch: Vec<f32>,
    /// Scratch spectrum (length `N/2 + 1`).
    spectrum: Vec<Complex>,
    fft: RealFft,
    input_pending: SampleRing,
    output_ready: SampleRing,
}

impl WolaProcessor {
    /// Build a WOLA framing with FFT size `n_fft` and pipeline frame length `frame_len`.
    ///
    /// # Errors
    /// - [`DspError::InvalidFrameLength`] if `frame_len` is 0.
    /// - [`DspError::InvalidFftSize`] if `n_fft` is not a power of two `>= 4` (from [`RealFft::new`]).
    pub fn new(n_fft: usize, frame_len: usize) -> Result<Self, DspError> {
        if frame_len == 0 {
            return Err(DspError::InvalidFrameLength { length: frame_len });
        }
        let fft = RealFft::new(n_fft)?;
        let n = n_fft;
        let hop = n / 2;

        // Worst-case occupancy bounds (see the module docs): input-pending stays below hop+frame_len;
        // output-ready holds the `hop` prefill plus at most a couple of hops of within-call transient
        // before `frame_len` are drained. Size generously so the rings never reallocate.
        let mut output_ready = SampleRing::with_capacity(4 * n + frame_len);
        // Prefill `hop` zeros so the very first frame can emit `frame_len` samples without underflow
        // (the 20 ms frame is not a whole number of hops); this prefill is the block-framing delay.
        for _ in 0..hop {
            output_ready.push_back(0.0);
        }

        Ok(Self {
            n,
            hop,
            analysis_window: sqrt_hann(n),
            synthesis_window: sqrt_hann(n),
            frame: vec![0.0; n],
            overlap: vec![0.0; n],
            scratch: vec![0.0; n],
            spectrum: vec![Complex::default(); n / 2 + 1],
            fft,
            input_pending: SampleRing::with_capacity(2 * n + frame_len),
            output_ready,
        })
    }

    /// FFT size `N`.
    #[inline]
    #[must_use]
    pub fn fft_size(&self) -> usize {
        self.n
    }

    /// Hop size `H = N/2`.
    #[inline]
    #[must_use]
    pub fn hop(&self) -> usize {
        self.hop
    }

    /// Constant input→output algorithmic delay in samples (`N`): `N/2` WOLA overlap + `N/2` framing.
    #[inline]
    #[must_use]
    pub fn latency_samples(&self) -> usize {
        self.n
    }

    /// The √Hann analysis window (also the synthesis window).
    #[must_use]
    pub fn window(&self) -> &[f32] {
        &self.analysis_window
    }

    /// Process one pipeline frame in the float domain.
    ///
    /// `input` and `output` must be the same length (any length; the STFT is sample-driven). The
    /// output is the reconstructed stream delayed by [`Self::latency_samples`]. `spectrum_op` is
    /// invoked once per internal STFT hop with the `N/2 + 1` complex bins to modify in place.
    pub fn process_frame<F>(&mut self, input: &[f32], output: &mut [f32], mut spectrum_op: F)
    where
        F: FnMut(&mut [Complex]),
    {
        for &sample in input {
            self.input_pending.push_back(sample);
        }

        while self.input_pending.len() >= self.hop {
            self.step(&mut spectrum_op);
        }

        for slot in output.iter_mut() {
            // Never underflows in practice (the `hop` prefill covers the framing remainder); the
            // 0.0 fallback keeps the hot path panic-free without an unwrap.
            *slot = self.output_ready.pop_front().unwrap_or(0.0);
        }
    }

    /// Run one STFT hop: slide in `hop` new samples, analysis-window, FFT, apply `spectrum_op`,
    /// IFFT, synthesis-window, overlap-add, and emit the finalized `hop` samples.
    fn step<F>(&mut self, spectrum_op: &mut F)
    where
        F: FnMut(&mut [Complex]),
    {
        // Slide the analysis frame left by one hop (N - hop == hop) and append the new hop.
        self.frame.copy_within(self.hop.., 0);
        for slot in self.frame[self.hop..].iter_mut() {
            match self.input_pending.pop_front() {
                Some(sample) => *slot = sample,
                None => break, // unreachable: guarded by len() >= hop
            }
        }

        // Analysis window.
        for ((windowed, &sample), &weight) in self
            .scratch
            .iter_mut()
            .zip(self.frame.iter())
            .zip(self.analysis_window.iter())
        {
            *windowed = sample * weight;
        }

        self.fft.forward(&self.scratch, &mut self.spectrum);
        spectrum_op(&mut self.spectrum);
        self.fft.inverse(&self.spectrum, &mut self.scratch);

        // Synthesis window + overlap-add.
        for ((accumulator, &sample), &weight) in self
            .overlap
            .iter_mut()
            .zip(self.scratch.iter())
            .zip(self.synthesis_window.iter())
        {
            *accumulator += sample * weight;
        }

        // Emit the finalized (oldest) hop, then shift the accumulator down and zero the exposed tail.
        for &finalized in &self.overlap[..self.hop] {
            self.output_ready.push_back(finalized);
        }
        self.overlap.copy_within(self.hop.., 0);
        for slot in self.overlap[self.hop..].iter_mut() {
            *slot = 0.0;
        }
    }

    /// Reset all framing state (e.g. on a stream discontinuity). Re-prefills the output delay line.
    pub fn reset(&mut self) {
        self.frame.iter_mut().for_each(|s| *s = 0.0);
        self.overlap.iter_mut().for_each(|s| *s = 0.0);
        self.scratch.iter_mut().for_each(|s| *s = 0.0);
        self.input_pending.clear();
        self.output_ready.clear();
        for _ in 0..self.hop {
            self.output_ready.push_back(0.0);
        }
    }
}

/// Streaming √Hann **analysis-only** framing over the same real FFT and hop clock as
/// [`WolaProcessor`], with no synthesis / overlap-add.
///
/// The AEC residual-echo suppressor ([`crate::res`]) needs the far-end **echo-estimate** spectrum
/// frame-synchronous with the residual it reconstructs: for every internal STFT hop the residual
/// [`WolaProcessor`] takes, it needs the echo estimate's spectrum for that same hop. Running the echo
/// estimate through this analyzer — same `N`, same hop, fed the same-length frames — keeps the two in
/// exact lock-step (both drain `⌊pending / hop⌋` hops per call from an identically-filled input ring),
/// so the k-th [`WolaAnalyzer`] spectrum covers the identical sample interval as the k-th
/// [`WolaProcessor`] analysis window. It skips the IFFT / synthesis-window / overlap-add the
/// residual path pays, so the echo side costs one forward FFT per hop and nothing else.
#[derive(Clone, Debug)]
pub struct WolaAnalyzer {
    n: usize,
    hop: usize,
    analysis_window: Vec<f32>,
    /// Sliding analysis window: the most recent `N` input samples (oldest first).
    frame: Vec<f32>,
    /// Scratch for the windowed time frame (length `N`).
    scratch: Vec<f32>,
    /// Scratch spectrum (length `N/2 + 1`).
    spectrum: Vec<Complex>,
    fft: RealFft,
    input_pending: SampleRing,
}

impl WolaAnalyzer {
    /// Build an analysis framing with FFT size `n_fft` and pipeline frame length `frame_len`. The
    /// `√Hann` analysis window and hop match [`WolaProcessor::new`] exactly.
    ///
    /// # Errors
    /// - [`DspError::InvalidFrameLength`] if `frame_len` is 0.
    /// - [`DspError::InvalidFftSize`] if `n_fft` is not a power of two `>= 4`.
    pub fn new(n_fft: usize, frame_len: usize) -> Result<Self, DspError> {
        if frame_len == 0 {
            return Err(DspError::InvalidFrameLength { length: frame_len });
        }
        let fft = RealFft::new(n_fft)?;
        let n = n_fft;
        let hop = n / 2;
        Ok(Self {
            n,
            hop,
            analysis_window: sqrt_hann(n),
            frame: vec![0.0; n],
            scratch: vec![0.0; n],
            spectrum: vec![Complex::default(); n / 2 + 1],
            fft,
            input_pending: SampleRing::with_capacity(2 * n + frame_len),
        })
    }

    /// FFT size `N`.
    #[inline]
    #[must_use]
    pub fn fft_size(&self) -> usize {
        self.n
    }

    /// Hop size `H = N/2`.
    #[inline]
    #[must_use]
    pub fn hop(&self) -> usize {
        self.hop
    }

    /// Feed one pipeline frame (float domain) and invoke `spectrum_op` once per internal STFT hop with
    /// that hop's `N/2 + 1` complex analysis bins (read-only). Produces no output stream.
    pub fn analyze_frame<F>(&mut self, input: &[f32], mut spectrum_op: F)
    where
        F: FnMut(&[Complex]),
    {
        for &sample in input {
            self.input_pending.push_back(sample);
        }
        while self.input_pending.len() >= self.hop {
            // Slide the analysis frame left by one hop (N - hop == hop) and append the new hop —
            // byte-for-byte the same frame management as `WolaProcessor::step`.
            self.frame.copy_within(self.hop.., 0);
            for slot in self.frame[self.hop..].iter_mut() {
                match self.input_pending.pop_front() {
                    Some(sample) => *slot = sample,
                    None => break, // unreachable: guarded by len() >= hop
                }
            }
            for ((windowed, &sample), &weight) in self
                .scratch
                .iter_mut()
                .zip(self.frame.iter())
                .zip(self.analysis_window.iter())
            {
                *windowed = sample * weight;
            }
            self.fft.forward(&self.scratch, &mut self.spectrum);
            spectrum_op(&self.spectrum);
        }
    }

    /// Reset the framing state (e.g. on a stream discontinuity).
    pub fn reset(&mut self) {
        self.frame.iter_mut().for_each(|s| *s = 0.0);
        self.scratch.iter_mut().for_each(|s| *s = 0.0);
        self.input_pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u32);
    impl Lcg {
        fn next_unit(&mut self) -> f32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (self.0 >> 8) as f32 / (1u32 << 24) as f32 - 0.5
        }
    }

    #[test]
    fn rejects_zero_frame_length() {
        assert_eq!(
            WolaProcessor::new(256, 0).unwrap_err(),
            DspError::InvalidFrameLength { length: 0 }
        );
    }

    #[test]
    fn rejects_bad_fft_size() {
        assert_eq!(
            WolaProcessor::new(100, 160).unwrap_err(),
            DspError::InvalidFftSize { size: 100 }
        );
    }

    #[test]
    fn sqrt_hann_squares_to_periodic_hann() {
        let n = 256;
        let window = sqrt_hann(n);
        for (i, &weight) in window.iter().enumerate() {
            let hann = 0.5 - 0.5 * (2.0 * std::f32::consts::PI * i as f32 / n as f32).cos();
            assert!(
                (weight * weight - hann).abs() < 1e-5,
                "i={i}: w² {} != hann {hann}",
                weight * weight
            );
        }
    }

    #[test]
    fn window_pair_is_cola_at_fifty_percent_overlap() {
        // The core perfect-reconstruction condition: for each position i in a hop, the analysis·
        // synthesis products of the two overlapping frames sum to exactly 1.
        for &n in &[256usize, 512] {
            let hop = n / 2;
            let window = sqrt_hann(n);
            for i in 0..hop {
                let sum = window[i] * window[i] + window[i + hop] * window[i + hop];
                assert!((sum - 1.0).abs() < 1e-5, "n={n} i={i}: COLA sum {sum} != 1");
            }
        }
    }

    #[test]
    fn identity_op_perfectly_reconstructs_delayed_input() {
        // Unit-gain WOLA must reproduce the input, delayed by `latency_samples`, within tight f32
        // tolerance — this proves the framing + FFT + overlap-add is perfect-reconstruction.
        for &(rate_n, frame_len) in &[(256usize, 160usize), (512, 320)] {
            let mut wola = WolaProcessor::new(rate_n, frame_len).expect("build");
            let latency = wola.latency_samples();

            let mut rng = Lcg(0xABCD ^ rate_n as u32);
            let total_frames = 40;
            let signal: Vec<f32> = (0..total_frames * frame_len)
                .map(|_| rng.next_unit() * 1000.0)
                .collect();

            let mut output = Vec::with_capacity(signal.len());
            let mut scratch = vec![0.0f32; frame_len];
            for chunk in signal.chunks(frame_len) {
                wola.process_frame(chunk, &mut scratch, |_| {});
                output.extend_from_slice(&scratch);
            }

            // Compare steady-state region (skip the leading `latency` and a tail margin).
            let mut max_error = 0.0f32;
            for index in latency..(signal.len() - frame_len) {
                let error = (output[index] - signal[index - latency]).abs();
                max_error = max_error.max(error);
            }
            assert!(
                max_error < 0.5,
                "n={rate_n}: WOLA PR max error {max_error} (signal amp ~1000) exceeds tolerance"
            );
        }
    }

    #[test]
    fn same_length_out_per_call() {
        let mut wola = WolaProcessor::new(256, 160).expect("build");
        let input = vec![100.0f32; 160];
        let mut output = vec![0.0f32; 160];
        for _ in 0..10 {
            wola.process_frame(&input, &mut output, |_| {});
            assert_eq!(output.len(), 160);
        }
    }

    #[test]
    fn reset_restores_initial_delay_line() {
        let mut wola = WolaProcessor::new(256, 160).expect("build");
        let input = vec![500.0f32; 160];
        let mut output = vec![0.0f32; 160];
        for _ in 0..5 {
            wola.process_frame(&input, &mut output, |_| {});
        }
        wola.reset();
        // After reset the first emitted frame is the prefill zeros again.
        wola.process_frame(&input, &mut output, |_| {});
        assert!(
            output.iter().take(128).all(|&s| s == 0.0),
            "post-reset prefill should be zeros"
        );
    }

    #[test]
    fn analyzer_hops_are_bit_identical_to_the_processor() {
        // The residual-echo suppressor relies on the analysis-only `WolaAnalyzer` producing exactly
        // the same per-hop spectra, in the same order, as the full `WolaProcessor` — that lock-step is
        // what makes the echo-estimate spectrum frame-synchronous with the residual. Feed both the
        // same variable-length frames and require every hop's spectrum bit-for-bit identical.
        for &(n, frame_len) in &[(256usize, 160usize), (512, 320)] {
            let mut processor = WolaProcessor::new(n, frame_len).expect("build");
            let mut analyzer = WolaAnalyzer::new(n, frame_len).expect("build");
            let mut rng = Lcg(0x0C0F_FEE0 ^ n as u32);

            let mut processor_hops: Vec<Vec<Complex>> = Vec::new();
            let mut analyzer_hops: Vec<Vec<Complex>> = Vec::new();
            let mut output = vec![0.0f32; frame_len];
            for _ in 0..30 {
                let frame: Vec<f32> = (0..frame_len).map(|_| rng.next_unit() * 1000.0).collect();
                processor.process_frame(&frame, &mut output, |spectrum| {
                    processor_hops.push(spectrum.to_vec());
                });
                analyzer.analyze_frame(&frame, |spectrum| {
                    analyzer_hops.push(spectrum.to_vec());
                });
            }

            assert_eq!(
                processor_hops.len(),
                analyzer_hops.len(),
                "n={n}: hop counts differ ({} vs {})",
                processor_hops.len(),
                analyzer_hops.len()
            );
            assert!(!processor_hops.is_empty(), "n={n}: no hops produced");
            for (hop, (a, b)) in processor_hops.iter().zip(analyzer_hops.iter()).enumerate() {
                assert_eq!(a, b, "n={n} hop={hop}: analyzer spectrum diverged");
            }
        }
    }
}
