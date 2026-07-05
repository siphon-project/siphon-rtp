//! A streaming rational resampler (polyphase FIR) for the telephony ↔ voice-AI rate boundary.
//!
//! Converts between 8 / 16 / 24 / 48 kHz by an exact rational ratio `L/M` (`L = out/gcd`,
//! `M = in/gcd`): a windowed-sinc prototype low-pass, decomposed into `L` polyphase branches, runs
//! per output sample using `i = ⌊nM/L⌋` and phase `nM mod L`. It carries filter history across
//! calls, so feeding 20 ms frames produces a continuous stream. Deterministic (no clock, no
//! randomness): the same input always yields the same output, so it golden-tests cleanly.

use siphon_rtp_simd::fir_dot_f32;
use std::f32::consts::PI;

/// Errors constructing a resampler.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResampleError {
    /// A sample rate was zero.
    #[error("sample rate must be non-zero")]
    ZeroRate,
}

/// A streaming polyphase rational resampler.
#[derive(Debug, Clone)]
pub struct Resampler {
    input_rate: u32,
    output_rate: u32,
    /// Upsample factor `L` and downsample factor `M` (the reduced ratio out/in).
    upsample: u64,
    downsample: u64,
    taps_per_phase: usize,
    /// Polyphase branches, row-major `[phase][tap]`, `upsample` rows of `taps_per_phase`, with each
    /// row **tap-reversed** so a filtered output is one contiguous dot of the oldest-first `history`
    /// against `branches_rev[phase][taps - 1 - base ..]` (see [`Resampler::filter`]).
    branches_rev: Vec<f32>,
    /// The most recent `taps_per_phase` input samples (oldest first); the filter delay line.
    history: Vec<f32>,
    /// Absolute count of input samples consumed so far.
    inputs_seen: u64,
    /// Index of the next output sample to emit.
    output_index: u64,
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a.max(1)
}

fn sinc(x: f32) -> f32 {
    if x.abs() < 1.0e-7 {
        1.0
    } else {
        let pix = PI * x;
        pix.sin() / pix
    }
}

impl Resampler {
    /// A resampler from `input_rate` to `output_rate` with a default 32-tap-per-phase filter.
    pub fn new(input_rate: u32, output_rate: u32) -> Result<Self, ResampleError> {
        Self::with_taps(input_rate, output_rate, 32)
    }

    /// A resampler with an explicit polyphase tap count (quality/cost knob).
    pub fn with_taps(
        input_rate: u32,
        output_rate: u32,
        taps_per_phase: usize,
    ) -> Result<Self, ResampleError> {
        if input_rate == 0 || output_rate == 0 {
            return Err(ResampleError::ZeroRate);
        }
        let divisor = gcd(u64::from(input_rate), u64::from(output_rate));
        let upsample = u64::from(output_rate) / divisor;
        let downsample = u64::from(input_rate) / divisor;
        let taps_per_phase = taps_per_phase.max(2);

        let length = taps_per_phase * upsample as usize;
        // Prototype low-pass at the upsampled rate: cutoff = 1 / (2·max(L,M)) of that Nyquist,
        // DC-gain L so each polyphase branch passes a constant at unity.
        let cutoff = 0.5 / upsample.max(downsample) as f32;
        let center = (length - 1) as f32 / 2.0;
        let mut prototype = vec![0.0f32; length];
        for (index, tap) in prototype.iter_mut().enumerate() {
            let position = index as f32 - center;
            let window = 0.5 - 0.5 * (2.0 * PI * index as f32 / (length - 1) as f32).cos(); // Hann
            *tap = upsample as f32 * 2.0 * cutoff * sinc(2.0 * cutoff * position) * window;
        }

        // Polyphase decomposition: branch p gets prototype[p], prototype[p+L], …, then each row is
        // tap-reversed so [`filter`] can dot the oldest-first history against a contiguous tail.
        let mut branches_rev = vec![0.0f32; length];
        for phase in 0..upsample as usize {
            for tap in 0..taps_per_phase {
                let source = phase + tap * upsample as usize;
                let coefficient = if source < length {
                    prototype[source]
                } else {
                    0.0
                };
                branches_rev[phase * taps_per_phase + (taps_per_phase - 1 - tap)] = coefficient;
            }
        }

        Ok(Self {
            input_rate,
            output_rate,
            upsample,
            downsample,
            taps_per_phase,
            branches_rev,
            history: Vec::with_capacity(taps_per_phase),
            inputs_seen: 0,
            output_index: 0,
        })
    }

    /// Input sample rate (Hz).
    #[must_use]
    pub fn input_rate(&self) -> u32 {
        self.input_rate
    }

    /// Output sample rate (Hz).
    #[must_use]
    pub fn output_rate(&self) -> u32 {
        self.output_rate
    }

    /// Whether input and output rates are equal (the resampler is a pass-through).
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.upsample == self.downsample
    }

    /// Resample `input`, appending the produced samples to `output`.
    pub fn process(&mut self, input: &[i16], output: &mut Vec<i16>) {
        for &sample in input {
            self.push(f32::from(sample));
            let newest = self.inputs_seen - 1;
            // Emit every output whose source input index has now arrived.
            loop {
                let position = self.output_index * self.downsample;
                let source_index = position / self.upsample;
                if source_index > newest {
                    break;
                }
                let phase = (position % self.upsample) as usize;
                output.push(self.filter(phase, source_index));
                self.output_index += 1;
            }
        }
    }

    /// Reset the filter history and counters (e.g. on a stream discontinuity).
    pub fn reset(&mut self) {
        self.history.clear();
        self.inputs_seen = 0;
        self.output_index = 0;
    }

    fn push(&mut self, sample: f32) {
        if self.history.len() == self.taps_per_phase {
            self.history.remove(0);
        }
        self.history.push(sample);
        self.inputs_seen += 1;
    }

    /// Convolve branch `phase` against the history ending at absolute input `source_index`.
    ///
    /// The original per-tap form `Σ branch[tap]·history[base − tap]` (with `base = source_index −
    /// history_start`, valid taps `0..=base`) is exactly `Σ_p history[p]·branch[base − p]`, i.e. one
    /// contiguous dot of `history[..=base]` against the reversed branch tail
    /// `branches_rev[phase][taps − 1 − base ..]` — vectorized via `fir_dot_f32`.
    fn filter(&self, phase: usize, source_index: u64) -> i16 {
        let history_start = self.inputs_seen - self.history.len() as u64;
        if source_index < history_start {
            return 0; // every tap is a pre-stream zero
        }
        let base = (source_index - history_start) as usize; // ≤ history.len() − 1
        let taps = self.taps_per_phase;
        let coefficients = &self.branches_rev[phase * taps + (taps - 1 - base)..(phase + 1) * taps];
        let acc = fir_dot_f32(&self.history[..=base], coefficients);
        let rounded = acc.round();
        if rounded >= f32::from(i16::MAX) {
            i16::MAX
        } else if rounded <= f32::from(i16::MIN) {
            i16::MIN
        } else {
            rounded as i16
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduces_ratio_via_gcd() {
        let resampler = Resampler::new(16000, 24000).expect("build");
        // 16000:24000 → 2:3.
        assert_eq!(resampler.downsample, 2);
        assert_eq!(resampler.upsample, 3);
    }

    #[test]
    fn identity_rate_passes_through() {
        let mut resampler = Resampler::new(8000, 8000).expect("build");
        assert!(resampler.is_identity());
        let input: Vec<i16> = (0..160).map(|index| (index * 50) as i16).collect();
        let mut output = Vec::new();
        resampler.process(&input, &mut output);
        assert_eq!(output.len(), input.len());
    }

    #[test]
    fn upsampling_doubles_sample_count() {
        let mut resampler = Resampler::new(8000, 16000).expect("build");
        let input = vec![0i16; 160]; // 20 ms at 8 kHz
        let mut output = Vec::new();
        resampler.process(&input, &mut output);
        // 2× output, within a few samples of filter latency.
        assert!((315..=325).contains(&output.len()), "got {}", output.len());
    }

    #[test]
    fn downsampling_halves_sample_count() {
        let mut resampler = Resampler::new(16000, 8000).expect("build");
        let input = vec![0i16; 320];
        let mut output = Vec::new();
        resampler.process(&input, &mut output);
        assert!((155..=165).contains(&output.len()), "got {}", output.len());
    }

    #[test]
    fn constant_signal_is_preserved() {
        let mut resampler = Resampler::new(8000, 24000).expect("build");
        let input = vec![1000i16; 400];
        let mut output = Vec::new();
        resampler.process(&input, &mut output);
        // After the filter fills, the constant passes through near unity gain.
        let steady = &output[output.len() / 2..];
        let average: f32 = steady.iter().map(|&s| f32::from(s)).sum::<f32>() / steady.len() as f32;
        assert!(
            (average - 1000.0).abs() < 20.0,
            "steady-state average {average}"
        );
    }

    #[test]
    fn streaming_matches_single_block() {
        // Feeding in two halves must equal feeding the whole at once (history continuity).
        let signal: Vec<i16> = (0..200)
            .map(|index| ((index as f32 * 0.2).sin() * 8000.0) as i16)
            .collect();

        let mut whole = Resampler::new(8000, 16000).expect("build");
        let mut whole_out = Vec::new();
        whole.process(&signal, &mut whole_out);

        let mut split = Resampler::new(8000, 16000).expect("build");
        let mut split_out = Vec::new();
        split.process(&signal[..100], &mut split_out);
        split.process(&signal[100..], &mut split_out);

        assert_eq!(whole_out, split_out, "streaming must be split-invariant");
    }

    #[test]
    fn preserves_a_low_frequency_sine_amplitude() {
        // A 300 Hz tone at 8 kHz, upsampled to 16 kHz, keeps its amplitude (well below cutoff).
        let amplitude = 10000.0f32;
        let input: Vec<i16> = (0..800)
            .map(|n| (amplitude * (2.0 * PI * 300.0 * n as f32 / 8000.0).sin()) as i16)
            .collect();
        let mut resampler = Resampler::new(8000, 16000).expect("build");
        let mut output = Vec::new();
        resampler.process(&input, &mut output);
        let peak = output[output.len() / 2..]
            .iter()
            .map(|&s| s.unsigned_abs())
            .max()
            .unwrap_or(0);
        assert!(
            (peak as f32) > amplitude * 0.85,
            "peak {peak} should be near {amplitude}"
        );
    }

    #[test]
    fn rejects_zero_rate() {
        assert!(matches!(
            Resampler::new(0, 8000),
            Err(ResampleError::ZeroRate)
        ));
        assert!(matches!(
            Resampler::new(8000, 0),
            Err(ResampleError::ZeroRate)
        ));
    }
}

// Property tests: the resampler fed an arbitrary logical sample-clock schedule (arbitrary rate pairs,
// arbitrary chunk boundaries, full-range i16 input) must never panic and must produce a *bounded*
// number of output samples. Deterministic by construction: the resampler has no wall clock, its whole
// state is the input schedule (CLAUDE.md forbids Instant::now() in DSP tests).
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Telephony/wideband rates the engine actually resamples between.
    fn rate() -> impl Strategy<Value = u32> {
        prop::sample::select(vec![8_000u32, 16_000, 32_000, 48_000])
    }

    // A single `process` emits, per input sample, every output whose source index has arrived, so the
    // running count is at most ceil(inputs * out/in) plus a small filter transient. This constant slack
    // covers the first-phase rounding on every rate pair below.
    const SLACK: u64 = 64;

    fn output_upper_bound(input_len: usize, in_rate: u32, out_rate: u32) -> u64 {
        (input_len as u64 * out_rate as u64).div_ceil(in_rate as u64) + SLACK
    }

    proptest! {
        #[test]
        fn process_output_is_bounded_and_never_panics(
            in_rate in rate(),
            out_rate in rate(),
            samples in prop::collection::vec(any::<i16>(), 0..4000),
        ) {
            let mut resampler = Resampler::new(in_rate, out_rate).expect("non-zero rates");
            let mut output = Vec::new();
            resampler.process(&samples, &mut output);
            prop_assert!(
                output.len() as u64 <= output_upper_bound(samples.len(), in_rate, out_rate),
                "produced {} outputs for {} inputs at {}->{}",
                output.len(), samples.len(), in_rate, out_rate,
            );
        }

        #[test]
        fn streaming_arbitrary_chunk_schedule_stays_bounded(
            in_rate in rate(),
            out_rate in rate(),
            chunks in prop::collection::vec(prop::collection::vec(any::<i16>(), 0..400), 0..24),
        ) {
            // Feeding the same samples split at arbitrary boundaries must not blow the total output
            // count past the single-block bound (the filter carries history across chunks).
            let mut resampler = Resampler::new(in_rate, out_rate).expect("non-zero rates");
            let mut total_in = 0usize;
            let mut total_out = 0usize;
            let mut output = Vec::new();
            for chunk in &chunks {
                output.clear();
                resampler.process(chunk, &mut output);
                total_in += chunk.len();
                total_out += output.len();
            }
            prop_assert!(
                total_out as u64 <= output_upper_bound(total_in, in_rate, out_rate),
                "streamed {} outputs for {} inputs at {}->{}",
                total_out, total_in, in_rate, out_rate,
            );
        }
    }
}
