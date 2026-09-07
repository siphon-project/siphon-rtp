//! Output post-processing (ITU-T G.729 Release 3 `post_pro.c`): a 100 Hz high-pass filter and a
//! doubling of the level, applied to the postfiltered speech on its way out.
//!
//! The encoder halves its input before analysing it, so the decoder has to put that factor back;
//! doing it here, after the filter, is what keeps the filter's own arithmetic away from the top of
//! the range. The filter state is carried in double precision because a second-order recursion at
//! 8 kHz with a 100 Hz corner has poles close enough to the unit circle that 16-bit state would
//! drift audibly.

use super::tables::{A100, B100};
use crate::itu::basic_ops::{l_add, l_mac, l_shl, round_word};
use crate::itu::oper_32b::{l_extract, mpy_32_16};

/// The post-processor's filter state.
#[derive(Debug, Clone, Default)]
pub struct PostProcessor {
    /// Previous two outputs, high and low halves of a double-precision value.
    output_history: [(i16, i16); 2],
    /// Previous two inputs.
    input_history: [i16; 2],
}

impl PostProcessor {
    /// A processor with cleared state (`Init_Post_Process`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter and scale one block of samples in place.
    pub fn process(&mut self, signal: &mut [i16]) {
        for sample in signal.iter_mut() {
            let x2 = self.input_history[1];
            let x1 = self.input_history[0];
            let x0 = *sample;

            let (y1_hi, y1_lo) = self.output_history[0];
            let (y2_hi, y2_lo) = self.output_history[1];

            let mut accumulator = mpy_32_16(y1_hi, y1_lo, A100[1]);
            accumulator = l_add(accumulator, mpy_32_16(y2_hi, y2_lo, A100[2]));
            accumulator = l_mac(accumulator, x0, B100[0]);
            accumulator = l_mac(accumulator, x1, B100[1]);
            accumulator = l_mac(accumulator, x2, B100[2]);
            accumulator = l_shl(accumulator, 2); // Q29 to Q31

            // The level doubling, saturating rather than wrapping: a sample already at full scale
            // stays at full scale instead of flipping sign.
            *sample = round_word(l_shl(accumulator, 1));

            self.output_history[1] = self.output_history[0];
            self.output_history[0] = l_extract(accumulator);
            self.input_history[1] = self.input_history[0];
            self.input_history[0] = x0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_in_gives_silence_out() {
        let mut processor = PostProcessor::new();
        let mut signal = [0_i16; 80];
        processor.process(&mut signal);
        assert!(signal.iter().all(|&s| s == 0));
    }

    #[test]
    fn a_constant_offset_is_removed() {
        // A DC offset is exactly what a 100 Hz high-pass is for: an electrical bias on the far end
        // would otherwise ride through the whole call and eat headroom.
        let mut processor = PostProcessor::new();
        let mut signal = [4000_i16; 800];
        processor.process(&mut signal);
        let tail_energy: i64 = signal[700..]
            .iter()
            .map(|&s| i64::from(s) * i64::from(s))
            .sum();
        assert!(
            tail_energy < 800 * 100 * 100,
            "the offset should be gone by the tail, energy was {tail_energy}"
        );
    }

    #[test]
    fn a_mid_band_tone_passes_and_is_roughly_doubled() {
        // 1 kHz is far above the corner, so it survives; the deliberate factor of two on the way
        // out is the encoder's input halving being undone.
        let mut processor = PostProcessor::new();
        let mut signal: Vec<i16> = (0..800)
            .map(|i| ((f64::from(i) * 2.0 * std::f64::consts::PI / 8.0).sin() * 4000.0) as i16)
            .collect();
        let input_peak = signal
            .iter()
            .map(|&s| i32::from(s).abs())
            .max()
            .unwrap_or(0);
        processor.process(&mut signal);
        let output_peak = signal[400..]
            .iter()
            .map(|&s| i32::from(s).abs())
            .max()
            .unwrap_or(0);
        let ratio = f64::from(output_peak) / f64::from(input_peak);
        assert!(
            (1.6..2.4).contains(&ratio),
            "1 kHz tone gain was {ratio}, expected about 2"
        );
    }

    #[test]
    fn a_full_scale_input_saturates_rather_than_wrapping() {
        // The doubling is the one place the output can exceed the range. Wrapping here would put a
        // full-amplitude sign flip into the audio, which is far worse than clipping.
        let mut processor = PostProcessor::new();
        let mut signal = [i16::MAX; 200];
        processor.process(&mut signal);
        // Whatever the filter does with a step, no sample may have wrapped to a large negative.
        assert!(
            signal.iter().all(|&s| s > -20_000),
            "a positive full-scale input must not produce a large negative sample"
        );
    }

    #[test]
    fn state_carries_across_calls() {
        // The media path hands this 80 samples at a time, so a processor that reset per call would
        // put a discontinuity at every frame boundary.
        let tone: Vec<i16> = (0..160)
            .map(|i| ((f64::from(i) * 0.7).sin() * 8000.0) as i16)
            .collect();

        let mut whole = tone.clone();
        PostProcessor::new().process(&mut whole);

        let mut split = tone.clone();
        let mut processor = PostProcessor::new();
        let (first, second) = split.split_at_mut(80);
        processor.process(first);
        processor.process(second);

        assert_eq!(whole, split, "block boundaries must not disturb the filter");
    }
}
