//! The comfort-noise excitation both directions generate — ITU-T G.729 Annex B §4.4, reference
//! `calcexc.c`.
//!
//! A frame that is not transmitted still has to produce sound, and silence is the wrong sound: a
//! call that goes completely quiet between words reads as a dropped line, which is why every DTX
//! scheme sends a level and synthesises noise at it rather than muting. The descriptor says how
//! loud; this decides what.
//!
//! The shape is deliberately the codec's own: a random pitch lag and gain, four random algebraic
//! pulses, and a Gaussian component, run through the same adaptive and fixed codebook structure a
//! speech frame uses. Noise made any other way would not sit in the synthesis filter the same, and
//! the switch between speech and comfort noise would be audible as a change of texture rather than
//! a change of level.
//!
//! The fixed-codebook gain is not random: it is solved for, so that the total excitation has
//! exactly the energy the descriptor asked for. That is the quadratic in the middle of this module.

use super::bitstream::{FRAME_SAMPLES, SUBFRAME_SAMPLES};
use super::dspfunc::inv_sqrt;
use super::excitation::{adaptive_codebook, PitchLag};
use super::weighting::Taming;
use crate::itu::basic_ops::{
    abs_s, add, extract_h, extract_l, l_add, l_deposit_l, l_mac, l_mult, l_shr, l_sub, mult_r,
    negate, norm_l, norm_s, shl, shr, shr_r, sub,
};
use crate::itu::oper_32b::{l_extract, mpy_32_16};

/// `sqrt(40)·alpha/2 − 1` in Q15, with alpha = 0.5 (`FRAC1`).
const GAUSSIAN_SCALE: i16 = 19_043;
/// `1 − alpha²` in Q15 (`K0`).
const ONE_MINUS_ALPHA_SQUARED: i16 = 24_576;
/// Largest fixed-codebook gain the solve may return (`G_MAX`).
const MAX_CODE_GAIN: i16 = 5000;
/// The seed both directions start from and the encoder returns to on every speech frame
/// (`INIT_SEED`), which is what keeps them generating the same noise.
pub const INITIAL_SEED: i16 = 11_111;

/// The reference's linear congruential generator (`Random`), shared by concealment and comfort
/// noise.
///
/// Both ends run it over the same seed, so the "random" excitation is identical at each — that is
/// the whole point: the decoder is not receiving noise, it is being told how to make the same noise.
#[derive(Debug, Clone, Copy)]
pub struct Random {
    seed: i16,
}

impl Random {
    /// A generator at the given seed.
    #[must_use]
    pub fn new(seed: i16) -> Self {
        Self { seed }
    }

    /// Reset to a known seed.
    pub fn reseed(&mut self, seed: i16) {
        self.seed = seed;
    }

    /// The next value: `seed = seed · 31821 + 13849`, in the reference's fixed-point form.
    ///
    /// Deliberately not an [`Iterator`]: it is an infinite deterministic sequence both ends step in
    /// lockstep, and the iterator adaptors would invite exactly the buffering and short-circuiting
    /// that breaks that.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> i16 {
        self.seed = extract_l(l_add(l_shr(l_mult(self.seed, 31_821), 1), 13_849));
        self.seed
    }

    /// Twelve uniform draws summed and scaled: a normal deviate at about 512 times unit variance
    /// (`Gauss`). Twelve is the reference's choice, and it is what makes the sum's variance one.
    fn gaussian(&mut self) -> i16 {
        let mut accumulator = 0_i32;
        for _ in 0..12 {
            accumulator = l_add(accumulator, l_deposit_l(self.next()));
        }
        extract_l(l_shr(accumulator, 7))
    }
}

/// Fill one frame of excitation with comfort noise at `gain` (`Calc_exc_rand`).
///
/// `excitation[origin..origin + FRAME_SAMPLES]` is the frame being produced and everything before it
/// is history the random adaptive contribution reads back into. `taming` is the encoder's
/// accumulated-error guard, which must see these frames too — it is tracking how far the decoder's
/// excitation history could have drifted from the encoder's, and a comfort-noise frame is part of
/// that history.
pub fn generate(
    gain: i16,
    excitation: &mut [i16],
    origin: usize,
    random: &mut Random,
    taming: Option<&mut Taming>,
) {
    let mut taming = taming;
    if gain == 0 {
        excitation[origin..origin + FRAME_SAMPLES].fill(0);
        if let Some(taming) = taming.as_deref_mut() {
            for _ in 0..FRAME_SAMPLES / SUBFRAME_SAMPLES {
                taming.update(0, SUBFRAME_SAMPLES as i16 + 1);
            }
        }
        return;
    }

    for subframe in 0..FRAME_SAMPLES / SUBFRAME_SAMPLES {
        let start = origin + subframe * SUBFRAME_SAMPLES;

        // Every codebook parameter a speech frame would transmit, drawn instead.
        let mut word = random.next();
        let mut fraction = sub(word & 0x0003, 1);
        if sub(fraction, 2) == 0 {
            fraction = 0;
        }
        word = shr(word, 2);
        let lag = add(word & 0x003F, 40);
        word = shr(word, 6);
        let mut positions = [0_usize; 4];
        let mut signs = [0_i16; 4];
        let track = word & 0x0007;
        positions[0] = add(shl(track, 2), track) as usize;
        word = shr(word, 3);
        signs[0] = word & 0x0001;
        word = shr(word, 1);
        let track = word & 0x0007;
        positions[1] = add(add(shl(track, 2), track), 1) as usize;
        word = shr(word, 3);
        signs[1] = word & 0x0001;

        let mut word = random.next();
        let track = word & 0x0007;
        positions[2] = add(add(shl(track, 2), track), 2) as usize;
        word = shr(word, 3);
        signs[2] = word & 0x0001;
        word = shr(word, 1);
        let track = word & 0x000F;
        let within = add(track & 1, 3);
        let group = shr(track, 1) & 0x0007;
        positions[3] = add(within, add(shl(group, 2), group)) as usize;
        word = shr(word, 4);
        signs[3] = word & 0x0001;

        // Under a half in Q14, so the random periodic part can never run away.
        let pitch_gain = random.next() & 0x1FFF;
        let pitch_gain_q15 = shl(pitch_gain, 1);

        // The Gaussian part, normalised to the requested gain.
        let mut gaussian = [0_i16; SUBFRAME_SAMPLES];
        let mut energy = 0_i32;
        for sample in gaussian.iter_mut() {
            let value = random.gaussian();
            energy = l_mac(energy, value, value);
            *sample = value;
        }
        let inverse = inv_sqrt(l_shr(energy, 1));
        let (high, low) = l_extract(inverse);
        let scaled_gain = add(gain, mult_r(gain, GAUSSIAN_SCALE));
        let product = mpy_32_16(high, low, scaled_gain);
        let normalisation = norm_l(product);
        let factor = extract_h(crate::itu::basic_ops::l_shl(product, normalisation));
        let shift = sub(normalisation, 14);
        for sample in gaussian.iter_mut() {
            *sample = shr_r(mult_r(*sample, factor), shift);
        }

        // The random periodic part, read out of the excitation history exactly as a coded frame's
        // adaptive codebook would be.
        adaptive_codebook(
            excitation,
            start,
            PitchLag {
                integer: lag,
                fraction,
            },
            SUBFRAME_SAMPLES,
        );

        let mut largest = 0_i16;
        for index in 0..SUBFRAME_SAMPLES {
            let combined = add(
                mult_r(excitation[start + index], pitch_gain_q15),
                gaussian[index],
            );
            excitation[start + index] = combined;
            let magnitude = abs_s(combined);
            if sub(magnitude, largest) > 0 {
                largest = magnitude;
            }
        }

        // Headroom for the energy sum below.
        let mut scaling = if largest == 0 {
            0
        } else {
            let candidate = sub(3, norm_s(largest));
            if candidate <= 0 {
                0
            } else {
                candidate
            }
        };
        let mut scaled = [0_i16; SUBFRAME_SAMPLES];
        for (slot, index) in (start..start + SUBFRAME_SAMPLES).enumerate() {
            scaled[slot] = shr(excitation[index], scaling);
        }

        // Solve 4x² + 2bx + c = 0 for the pulse amplitude that makes the subframe's total energy
        // equal to what the descriptor asked for: `c` is how far the noise already built is from
        // that target, and `b` is how much the pulses correlate with it.
        let mut total = 0_i32;
        for &sample in scaled.iter() {
            total = l_mac(total, sample, sample);
        }
        let mut correlation = 0_i16;
        for (&position, &sign) in positions.iter().zip(signs.iter()) {
            correlation = if sign == 0 {
                sub(correlation, scaled[position])
            } else {
                add(correlation, scaled[position])
            };
        }

        let target = l_shr(l_mult(gain, SUBFRAME_SAMPLES as i16), 6);
        let target = l_mult(gain, extract_l(target));
        let mut discriminant = l_shr(target, add(1, shl(scaling, 1)));
        discriminant = l_sub(discriminant, total);
        correlation = shr(correlation, 1);
        discriminant = l_mac(discriminant, correlation, correlation);
        scaling = add(scaling, 1);

        let mut pitch_gain_used = pitch_gain;
        if discriminant < 0 {
            // No amplitude can reach the target with the periodic part in the way: drop it and
            // solve again against the Gaussian alone, which always has a solution.
            excitation[start..start + SUBFRAME_SAMPLES].copy_from_slice(&gaussian);
            let magnitude = abs_s(gaussian[positions[0]])
                | abs_s(gaussian[positions[1]])
                | abs_s(gaussian[positions[2]])
                | abs_s(gaussian[positions[3]]);
            scaling = if magnitude & 0x4000 == 0 { 1 } else { 2 };
            correlation = 0;
            for (&position, &sign) in positions.iter().zip(signs.iter()) {
                let value = shr(gaussian[position], scaling);
                correlation = if sign == 0 {
                    sub(correlation, value)
                } else {
                    add(correlation, value)
                };
            }
            let (high, low) = l_extract(target);
            let mut scaled_target = mpy_32_16(high, low, ONE_MINUS_ALPHA_SQUARED);
            scaled_target = l_shr(scaled_target, sub(shl(scaling, 1), 1));
            discriminant = l_mac(scaled_target, correlation, correlation);
            pitch_gain_used = 0;
        }

        let root = square_root(discriminant);
        let first = sub(root, correlation);
        let second = negate(add(correlation, root));
        let chosen = if sub(abs_s(second), abs_s(first)) < 0 {
            second
        } else {
            first
        };
        let mut amplitude = shr_r(chosen, sub(2, scaling));
        amplitude = amplitude.clamp(-MAX_CODE_GAIN, MAX_CODE_GAIN);

        for (&position, &sign) in positions.iter().zip(signs.iter()) {
            let index = start + position;
            excitation[index] = if sign != 0 {
                add(excitation[index], amplitude)
            } else {
                sub(excitation[index], amplitude)
            };
        }

        if let Some(taming) = taming.as_deref_mut() {
            taming.update(pitch_gain_used, lag);
        }
    }
}

/// `sqrt(value / 2)` by binary search over the bits of the answer (`Sqrt`).
///
/// Fourteen iterations, one per bit, each testing whether setting the next bit overshoots. It is
/// the reference's own routine rather than [`inv_sqrt`], because this needs the root itself and at
/// a different scale.
fn square_root(value: i32) -> i16 {
    let mut result = 0_i16;
    let mut bit = 0x4000_i16;
    for _ in 0..14 {
        let candidate = add(result, bit);
        if l_sub(value, l_mult(candidate, candidate)) >= 0 {
            result = add(result, bit);
        }
        bit = shr(bit, 1);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The excitation buffer the generator writes into: history, then the frame.
    const ORIGIN: usize = 154;

    fn buffer() -> Vec<i16> {
        vec![0_i16; ORIGIN + FRAME_SAMPLES]
    }

    fn energy(frame: &[i16]) -> i64 {
        frame.iter().map(|&s| i64::from(s) * i64::from(s)).sum()
    }

    #[test]
    fn a_zero_gain_frame_is_silent() {
        // The descriptor can ask for nothing, and then nothing is what the frame must be — not the
        // noise floor of the generator.
        let mut excitation = buffer();
        let mut random = Random::new(INITIAL_SEED);
        generate(0, &mut excitation, ORIGIN, &mut random, None);
        assert!(excitation[ORIGIN..].iter().all(|&s| s == 0));
    }

    #[test]
    fn the_frame_gets_louder_as_the_descriptor_asks_for_more() {
        // The gain is the one thing the descriptor controls, and the fixed-codebook amplitude is
        // solved for so the frame lands on it. Monotonic, or the level the encoder measured would
        // not be the level the decoder plays.
        let mut previous = 0_i64;
        for gain in [8_i16, 64, 505, 4009, 15_962] {
            let mut excitation = buffer();
            let mut random = Random::new(INITIAL_SEED);
            generate(gain, &mut excitation, ORIGIN, &mut random, None);
            let measured = energy(&excitation[ORIGIN..]);
            assert!(
                measured > previous,
                "gain {gain}: energy {measured} did not exceed {previous}"
            );
            previous = measured;
        }
    }

    #[test]
    fn both_ends_generate_the_same_noise_from_the_same_seed() {
        // The decoder is not receiving noise, it is being told how to make the same noise. If the
        // two generators ever diverged, the encoder's local synthesis — and so every frame it codes
        // after the silence — would be predicting from a history the decoder does not have.
        let mut first = buffer();
        let mut second = buffer();
        let mut one = Random::new(INITIAL_SEED);
        let mut two = Random::new(INITIAL_SEED);
        generate(505, &mut first, ORIGIN, &mut one, None);
        generate(505, &mut second, ORIGIN, &mut two, None);
        assert_eq!(first, second);
    }

    #[test]
    fn successive_frames_differ() {
        // The generator advances with the frame, so a long silence is noise rather than a 10 ms
        // loop — which would be plainly audible as a buzz at 100 Hz.
        let mut excitation = buffer();
        let mut random = Random::new(INITIAL_SEED);
        generate(505, &mut excitation, ORIGIN, &mut random, None);
        let first: Vec<i16> = excitation[ORIGIN..].to_vec();
        excitation.copy_within(FRAME_SAMPLES.., 0);
        generate(505, &mut excitation, ORIGIN, &mut random, None);
        assert_ne!(first, excitation[ORIGIN..].to_vec());
    }

    #[test]
    fn the_square_root_agrees_with_the_real_one() {
        // `sqrt(value / 2)` by bit search: it is the reference's own routine and everything the
        // fixed-codebook amplitude is solved from goes through it.
        for value in [0_i32, 1, 100, 5000, 1 << 20, 1 << 28, i32::MAX] {
            let got = i64::from(square_root(value));
            let want = ((f64::from(value) / 2.0).sqrt()) as i64;
            assert!((got - want).abs() <= 1, "sqrt({value}/2): {got} vs {want}");
        }
    }
}
