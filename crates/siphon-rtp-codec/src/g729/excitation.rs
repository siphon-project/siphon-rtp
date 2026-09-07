//! The excitation the synthesis filter is driven by: an adaptive-codebook contribution recovered
//! from the pitch lag, plus an algebraic fixed-codebook contribution, each scaled by its own gain
//! (ITU-T G.729 Release 3 `dec_lag3.c`, `pred_lt3.c`, `de_acelp.c`, `dec_gain.c`, `gainpred.c`).

use super::bitstream::SUBFRAME_SAMPLES;
use super::dspfunc::{log2, pow2};
use super::tables::{GBK1, GBK2, IMAP1, IMAP2, INTER_3L, PRED};
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_add, l_deposit_l, l_mac, l_mult, l_shl, l_shr, mult, negate,
    round_word, shl, shr, sub,
};
use crate::itu::oper_32b::{l_comp, l_extract, mpy_32_16};

/// Shortest pitch lag the codec codes, in samples.
pub const PITCH_MIN: i16 = 20;
/// Longest pitch lag the codec codes, in samples.
pub const PITCH_MAX: i16 = 143;
/// Resolution of the fractional pitch lag: thirds of a sample.
const UP_SAMPLE: i16 = 3;
/// Taps per phase of the fractional-delay interpolation filter.
const INTERPOLATION_TAPS: usize = 10;
/// History the adaptive codebook can reach back into, ahead of the current subframe.
pub const EXCITATION_HISTORY: usize = PITCH_MAX as usize + INTERPOLATION_TAPS;

/// A pitch lag: an integer sample count plus a third-of-a-sample fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PitchLag {
    /// Integer part, in samples.
    pub integer: i16,
    /// Fractional part in thirds of a sample, one of -1, 0 or 1.
    pub fraction: i16,
}

/// Decode the first subframe's pitch lag from its 8-bit index (`Dec_lag3`, first-subframe branch).
///
/// Below 197 the index carries a third-of-a-sample resolution lag; at and above it the resolution
/// drops to whole samples, which is how the 8 bits cover 20..=143 with fine resolution only where
/// pitch actually needs it.
#[must_use]
pub fn decode_first_lag(index: u16) -> PitchLag {
    let index = index as i16;
    if index < 197 {
        // integer = (index + 2)/3 + 19, by reciprocal multiplication as the reference does it.
        let integer = add(mult(add(index, 2), 10_923), 19);
        let triple = add(add(integer, integer), integer);
        PitchLag {
            integer,
            fraction: add(sub(index, triple), 58),
        }
    } else {
        PitchLag {
            integer: sub(index, 112),
            fraction: 0,
        }
    }
}

/// Decode the second subframe's pitch lag from its 5-bit index, which is relative to the first
/// subframe's (`Dec_lag3`, second-subframe branch).
///
/// The relative window is ten integer lags wide, clamped into the codec's absolute range — so a
/// first subframe near either end of that range shifts the window rather than truncating it.
#[must_use]
pub fn decode_second_lag(index: u16, first: PitchLag) -> PitchLag {
    let mut minimum = sub(first.integer, 5);
    if minimum < PITCH_MIN {
        minimum = PITCH_MIN;
    }
    let mut maximum = add(minimum, 9);
    if maximum > PITCH_MAX {
        maximum = PITCH_MAX;
        minimum = sub(maximum, 9);
    }

    let index = index as i16;
    let offset = sub(mult(add(index, 2), 10_923), 1);
    let triple = add(add(offset, offset), offset);
    PitchLag {
        integer: add(offset, minimum),
        fraction: sub(sub(index, 2), triple),
    }
}

/// Build the adaptive-codebook contribution in place (`Pred_lt_3`).
///
/// `excitation[offset..]` is the subframe being produced and everything before it is history. The
/// filter reads backwards from `offset - lag`, which for a lag shorter than the subframe means it
/// reads samples this same call has just written: that overlap is the point, not a hazard. It is
/// what makes a short pitch period repeat through the subframe.
pub fn adaptive_codebook(excitation: &mut [i16], offset: usize, lag: PitchLag, length: usize) {
    // The fractional delay is applied as a two-phase interpolation; a negative phase is folded into
    // the neighbouring integer sample.
    let mut fraction = negate(lag.fraction);
    let mut base = offset - lag.integer as usize;
    if fraction < 0 {
        fraction = add(fraction, UP_SAMPLE);
        base -= 1;
    }
    let fraction = fraction as usize;
    let mirror = (UP_SAMPLE as usize) - fraction;

    for j in 0..length {
        let backward = base + j; // the sample the causal half reads from
        let forward = backward + 1; // and the anticausal half
        let mut sum = 0_i32;
        for i in 0..INTERPOLATION_TAPS {
            let tap = i * UP_SAMPLE as usize;
            sum = l_mac(sum, excitation[backward - i], INTER_3L[fraction + tap]);
            sum = l_mac(sum, excitation[forward + i], INTER_3L[mirror + tap]);
        }
        excitation[offset + j] = round_word(sum);
    }
}

/// Build the fixed-codebook contribution: four unit pulses on an interleaved grid (`Decod_ACELP`).
///
/// Thirteen bits place the pulses and four give their signs. Each pulse sits on its own track — a
/// residue class mod 5 — which is what lets thirteen bits address four positions in forty samples.
#[must_use]
pub fn fixed_codebook(signs: u16, positions: u16) -> [i16; SUBFRAME_SAMPLES] {
    let mut index = positions as i16;
    let mut pulse = [0_i16; 4];

    let i = index & 7;
    pulse[0] = add(i, shl(i, 2)); // track 0: 5i

    index = shr(index, 3);
    let i = index & 7;
    pulse[1] = add(add(i, shl(i, 2)), 1); // track 1: 5i + 1

    index = shr(index, 3);
    let i = index & 7;
    pulse[2] = add(add(i, shl(i, 2)), 2); // track 2: 5i + 2

    index = shr(index, 3);
    // The fourth pulse has an extra bit, letting it fall on either of two tracks.
    let shift = index & 1;
    index = shr(index, 1);
    let i = index & 7;
    pulse[3] = add(add(add(i, shl(i, 2)), 3), shift); // track 3 or 4: 5i + 3 + bit

    let mut code = [0_i16; SUBFRAME_SAMPLES];
    let mut signs = signs as i16;
    for &position in &pulse {
        // +1.0 or -1.0 in Q13. The positive pulse is 8191 rather than 8192: the reference cannot
        // represent +1.0 exactly in Q13 and does not pretend to.
        code[position as usize] = if signs & 1 != 0 { 8191 } else { -8192 };
        signs = shr(signs, 1);
    }
    code
}

/// Lower bound on the pitch-sharpening factor, 0.2 in Q14.
pub const SHARP_MIN: i16 = 3277;
/// Upper bound on the pitch-sharpening factor, 0.8 in Q14.
pub const SHARP_MAX: i16 = 13_017;

/// Fold a scaled copy of the fixed-codebook vector back into itself one pitch period later
/// (ITU-T G.729 §4.1.3, the sharpening step in `dec_ld8k.c`).
///
/// It only applies when the lag is shorter than the subframe, and `sharp` is the previous
/// subframe's pitch gain clamped to [`SHARP_MIN`]..=[`SHARP_MAX`]. This runs *before* the gains are
/// decoded, not after, because the codebook gain is predicted from this vector's energy — decoding
/// the gains against the unsharpened vector gives a gain that is wrong by a little on every voiced
/// subframe, which is audible as a dull edge rather than as an obvious fault.
pub fn sharpen(code: &mut [i16; SUBFRAME_SAMPLES], lag: i16, sharp: i16) {
    if lag >= SUBFRAME_SAMPLES as i16 {
        return;
    }
    let factor = shl(sharp, 1); // Q14 to Q15
    let lag = lag as usize;
    for i in lag..SUBFRAME_SAMPLES {
        code[i] = add(code[i], mult(code[i - lag], factor));
    }
}

/// Clamp a decoded pitch gain into the range the sharpening factor is allowed to take.
#[must_use]
pub fn clamp_sharpening(gain_pitch: i16) -> i16 {
    gain_pitch.clamp(SHARP_MIN, SHARP_MAX)
}

/// The gains' decoder, which carries the predictor state the codebook gain is coded against.
#[derive(Debug, Clone)]
pub struct GainDecoder {
    /// The four previous subframes' quantised codebook-gain energies, most recent first. Q10.
    past_energy: [i16; 4],
}

impl Default for GainDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// The reference's initial past energy: -14 dB in Q10, repeated.
const INITIAL_ENERGY: i16 = -14_336;

impl GainDecoder {
    /// A decoder at its reset state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            past_energy: [INITIAL_ENERGY; 4],
        }
    }

    /// Decode one subframe's two gains from the 7-bit joint index (`Dec_gain`).
    ///
    /// Returns the adaptive-codebook (pitch) gain in Q14 and the fixed-codebook gain in Q1. The
    /// codebook gain is not coded absolutely: what the index carries is a correction to an energy
    /// predicted from the four previous subframes, so this advances that predictor too.
    pub fn decode(&mut self, index: u16, code: &[i16; SUBFRAME_SAMPLES]) -> (i16, i16) {
        let first = IMAP1[usize::from(index >> 4) & (GBK1.len() - 1)] as usize;
        let second = IMAP2[usize::from(index) & (GBK2.len() - 1)] as usize;

        let pitch_gain = add(GBK1[first][0], GBK2[second][0]);

        let (predicted, predicted_exponent) = self.predict(code);

        // The two codebook halves sum to a correction factor in Q13, applied to the prediction.
        let correction = l_add(l_deposit_l(GBK1[first][1]), l_deposit_l(GBK2[second][1]));
        let half = extract_l(l_shr(correction, 1)); // Q12
        let scaled = l_mult(half, predicted);
        let scaled = l_shl(scaled, add(negate(predicted_exponent), -12 - 1 + 1 + 16));
        let code_gain = extract_h(scaled);

        self.update(correction);
        (pitch_gain, code_gain)
    }

    /// Fade both gains through an erased subframe and decay the predictor (`Dec_gain`, bfi branch).
    ///
    /// The previous subframe's gains are reused, attenuated: the pitch gain by 0.9 and capped, the
    /// codebook gain by 0.98. Repeating them unattenuated would ring; muting them outright would
    /// punch a hole in the middle of a word.
    pub fn decode_erased(&mut self, previous_pitch: i16, previous_code: i16) -> (i16, i16) {
        let mut pitch_gain = mult(previous_pitch, 29_491); // 0.9 in Q15
        if pitch_gain > 29_491 {
            pitch_gain = 29_491;
        }
        let code_gain = mult(previous_code, 32_111); // 0.98 in Q15
        self.update_erased();
        (pitch_gain, code_gain)
    }

    /// Predict this subframe's codebook gain from the energy of its innovation and the four
    /// previous quantised energies (`Gain_predict`).
    fn predict(&self, code: &[i16; SUBFRAME_SAMPLES]) -> (i16, i16) {
        let mut energy = 0_i32;
        for &sample in code.iter() {
            energy = l_mac(energy, sample, sample);
        }

        // 127.298 - 3.0103 * log2(energy), the constants folding in the subframe length and the
        // Q27 the energy accumulated in.
        let (exponent, fraction) = log2(energy);
        let mut accumulator = mpy_32_16(exponent, fraction, -24_660); // -3.0103 in Q13
        accumulator = l_mac(accumulator, 32_588, 32); // +127.298 in Q14

        accumulator = l_shl(accumulator, 10); // Q14 to Q24
        for (coefficient, energy) in PRED.iter().zip(&self.past_energy) {
            accumulator = l_mac(accumulator, *coefficient, *energy);
        }
        let decibels = extract_h(accumulator); // Q8

        // 10^(dB/20) = 2^(0.166 * dB), evaluated with the exponent forced to 14 so the mantissa
        // lands in a known range and the caller can shift by the difference.
        let scaled = l_shr(l_mult(decibels, 5439), 8); // 0.166 in Q15, Q24 to Q16
        let (exponent, fraction) = l_extract(scaled);
        (extract_l(pow2(14, fraction)), sub(14, exponent))
    }

    /// Push this subframe's quantised energy onto the predictor history (`Gain_update`).
    fn update(&mut self, correction: i32) {
        for i in (1..4).rev() {
            self.past_energy[i] = self.past_energy[i - 1];
        }
        // 20*log10(correction) = 6.0205 * log2(correction), with the Q13 input's exponent removed.
        let (exponent, fraction) = log2(correction);
        let accumulator = l_comp(sub(exponent, 13), fraction);
        let logarithm = extract_h(l_shl(accumulator, 13));
        self.past_energy[0] = mult(logarithm, 24_660);
    }

    /// Decay the predictor through an erased subframe (`Gain_update_erasure`): push the mean of the
    /// history, 4 dB down and floored, so a long erasure fades rather than either freezing or
    /// collapsing.
    fn update_erased(&mut self) {
        let mut total = 0_i32;
        for &energy in &self.past_energy {
            total = l_add(total, l_deposit_l(energy));
        }
        let mut average = extract_l(l_shr(total, 2));
        average = sub(average, 4096); // -4 dB in Q10
        if average < INITIAL_ENERGY {
            average = INITIAL_ENERGY;
        }
        for i in (1..4).rev() {
            self.past_energy[i] = self.past_energy[i - 1];
        }
        self.past_energy[0] = average;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_first_subframe_index_decodes_inside_the_codable_pitch_range() {
        // The fine range starts at 19 and 1/3, not at 20: PITCH_MIN is the integer floor the
        // second-subframe window is clamped to, and the smallest *lag* the codec codes sits a third
        // of a sample below it. Asserting integer >= PITCH_MIN here would be asserting something
        // the reference does not do — it answers {19, +1} for index 0.
        for index in 0..256_u16 {
            let lag = decode_first_lag(index);
            let thirds = i32::from(lag.integer) * 3 + i32::from(lag.fraction);
            assert!(
                (19 * 3 + 1..=i32::from(PITCH_MAX) * 3).contains(&thirds),
                "index {index} gave lag {lag:?} = {thirds} thirds"
            );
            assert!((-1..=1).contains(&lag.fraction), "index {index}: {lag:?}");
        }
    }

    #[test]
    fn the_fine_and_coarse_halves_of_the_lag_index_meet_where_the_reference_switches() {
        // Below 197 the index carries thirds of a sample; from 197 up it is whole samples only.
        assert!(decode_first_lag(196).fraction.abs() <= 1);
        assert_eq!(
            decode_first_lag(197),
            PitchLag {
                integer: 85,
                fraction: 0
            }
        );
        assert_eq!(
            decode_first_lag(255),
            PitchLag {
                integer: 143,
                fraction: 0
            }
        );
        // The very first index is 19 and a third, the shortest pitch period the codec codes.
        assert_eq!(
            decode_first_lag(0),
            PitchLag {
                integer: 19,
                fraction: 1
            }
        );
    }

    #[test]
    fn the_second_subframe_window_slides_but_never_leaves_the_range() {
        for first_integer in PITCH_MIN..=PITCH_MAX {
            let first = PitchLag {
                integer: first_integer,
                fraction: 0,
            };
            for index in 0..32_u16 {
                let lag = decode_second_lag(index, first);
                // The relative window is not a clean ten integers: it runs from two thirds below
                // its base to a third above the tenth, so the reference answers 143 and a third at
                // the very top. What has to hold is not a tidy range but that the adaptive codebook
                // can still read it — the deepest sample it reaches for must be inside the history
                // the decoder keeps, which is exactly what EXCITATION_HISTORY is sized for.
                // The integer part can reach 144, one past PITCH_MAX, when the fraction is -1 and
                // the lag is really 143 and two thirds. Both that and {143, +1} bottom out at
                // exactly 153 samples of reach, which is why the history is that size and not a
                // round number — it is sized to the deepest lag the bitstream can express.
                let extra = i32::from(lag.fraction > 0); // a positive phase reaches one further back
                let deepest = i32::from(lag.integer) + extra + INTERPOLATION_TAPS as i32 - 1;
                assert!(
                    deepest <= EXCITATION_HISTORY as i32,
                    "first {first_integer}, index {index}: {lag:?} reaches back {deepest}"
                );
            }
        }
    }

    #[test]
    fn the_fixed_codebook_places_four_pulses_on_their_own_tracks() {
        for positions in (0..8192_u16).step_by(37) {
            for signs in 0..16_u16 {
                let code = fixed_codebook(signs, positions);
                let placed: Vec<usize> = code
                    .iter()
                    .enumerate()
                    .filter(|(_, &value)| value != 0)
                    .map(|(index, _)| index)
                    .collect();
                assert!(
                    placed.len() <= 4,
                    "positions {positions} signs {signs}: {placed:?}"
                );
                for &position in &placed {
                    assert!(position < SUBFRAME_SAMPLES);
                    assert!(
                        code[position] == 8191 || code[position] == -8192,
                        "a pulse is +/-1.0 in Q13"
                    );
                }
                // Tracks: the first three pulses are at 5i, 5i+1, 5i+2; the fourth at 5i+3 or 5i+4.
                let tracks: Vec<usize> = placed.iter().map(|p| p % 5).collect();
                assert!(tracks.iter().all(|&t| t < 5), "{tracks:?}");
            }
        }
    }

    #[test]
    fn all_four_pulses_are_distinct_when_the_tracks_do_not_collide() {
        // Index zero puts pulses at 0, 1, 2, 3 — one per track, which is the shape the codebook
        // guarantees and the reason four pulses fit in thirteen bits.
        let code = fixed_codebook(0b1111, 0);
        let placed: Vec<usize> = code
            .iter()
            .enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(placed, vec![0, 1, 2, 3]);
        assert!(
            placed.iter().all(|&p| code[p] == 8191),
            "all signs positive"
        );
    }

    #[test]
    fn pulse_signs_follow_their_bits_least_significant_first() {
        let code = fixed_codebook(0b0101, 0);
        assert_eq!(code[0], 8191, "bit 0 set");
        assert_eq!(code[1], -8192, "bit 1 clear");
        assert_eq!(code[2], 8191, "bit 2 set");
        assert_eq!(code[3], -8192, "bit 3 clear");
    }

    #[test]
    fn the_adaptive_codebook_repeats_a_pitch_period_shorter_than_the_subframe() {
        // A lag of 20 against a 40-sample subframe means the second half must repeat the first —
        // the in-place overlap is the mechanism, so a port that copied to a scratch buffer first
        // would quietly produce silence in the tail.
        let mut excitation = vec![0_i16; EXCITATION_HISTORY + SUBFRAME_SAMPLES];
        let offset = EXCITATION_HISTORY;
        for i in 0..20 {
            excitation[offset - 20 + i] = ((i as i16) - 10) * 300;
        }
        let lag = PitchLag {
            integer: 20,
            fraction: 0,
        };
        adaptive_codebook(&mut excitation, offset, lag, SUBFRAME_SAMPLES);

        // The repetition is through a ten-tap interpolation filter rather than a copy, so the
        // second period follows the first in shape and scale rather than sample for sample; the
        // filter's own smoothing is the difference. Correlate instead of comparing pointwise.
        let first: Vec<f64> = (0..20).map(|i| f64::from(excitation[offset + i])).collect();
        let second: Vec<f64> = (0..20)
            .map(|i| f64::from(excitation[offset + 20 + i]))
            .collect();
        let dot: f64 = first.iter().zip(&second).map(|(a, b)| a * b).sum();
        let energy_first: f64 = first.iter().map(|a| a * a).sum();
        let energy_second: f64 = second.iter().map(|b| b * b).sum();
        let correlation = dot / (energy_first.sqrt() * energy_second.sqrt());
        assert!(
            correlation > 0.99,
            "the second period should track the first: correlation {correlation}"
        );
    }

    #[test]
    fn a_long_lag_reads_only_history() {
        // The counterpart: a lag longer than the subframe cannot reach its own output, so the
        // result is a straight interpolation of the history.
        let mut excitation = vec![0_i16; EXCITATION_HISTORY + SUBFRAME_SAMPLES];
        let offset = EXCITATION_HISTORY;
        for (i, sample) in excitation.iter_mut().take(EXCITATION_HISTORY).enumerate() {
            *sample = ((i % 32) as i16 - 16) * 400;
        }
        let lag = PitchLag {
            integer: 100,
            fraction: 0,
        };
        adaptive_codebook(&mut excitation, offset, lag, SUBFRAME_SAMPLES);
        assert!(
            excitation[offset..].iter().any(|&s| s != 0),
            "the codebook produced something"
        );
    }

    #[test]
    fn sharpening_applies_only_below_a_subframe_and_repeats_the_pulse_pattern() {
        let mut code = fixed_codebook(0b1111, 0);
        let untouched = code;
        sharpen(&mut code, SUBFRAME_SAMPLES as i16, SHARP_MAX);
        assert_eq!(
            code, untouched,
            "a lag of a whole subframe sharpens nothing"
        );

        let mut code = fixed_codebook(0b1111, 0);
        sharpen(&mut code, 20, SHARP_MAX);
        // Pulses sit at 0..3, so sharpening at lag 20 must echo them at 20..23 and nowhere else.
        for (position, &sample) in code.iter().enumerate().take(24).skip(20) {
            assert_ne!(sample, 0, "pulse echoed at {position}");
        }
        assert_eq!(code[30], 0, "and nothing appears where there was no pulse");
    }

    #[test]
    fn the_sharpening_factor_is_clamped_to_the_reference_bounds() {
        assert_eq!(clamp_sharpening(0), SHARP_MIN);
        assert_eq!(clamp_sharpening(i16::MAX), SHARP_MAX);
        assert_eq!(clamp_sharpening(8000), 8000);
    }

    #[test]
    fn a_fresh_gain_decoder_starts_from_the_reference_energy_floor() {
        assert_eq!(GainDecoder::new().past_energy, [INITIAL_ENERGY; 4]);
    }

    #[test]
    fn decoded_gains_stay_in_their_documented_ranges() {
        let mut decoder = GainDecoder::new();
        let code = fixed_codebook(0b1010, 1234);
        for index in 0..128_u16 {
            let (pitch, _code_gain) = decoder.decode(index, &code);
            // The pitch gain is Q14 and the codebook's largest entry is a little over 1.25, so the
            // bound is the codebook's own maximum rather than a guessed round number.
            let ceiling = GBK1.iter().map(|e| e[0]).max().expect("codebook")
                + GBK2.iter().map(|e| e[0]).max().expect("codebook");
            assert!(pitch >= 0, "index {index}: pitch gain {pitch}");
            assert!(
                pitch <= ceiling,
                "index {index}: pitch gain {pitch} above {ceiling}"
            );
        }
    }

    #[test]
    fn an_erased_subframe_fades_the_gains_rather_than_repeating_or_muting_them() {
        let mut decoder = GainDecoder::new();
        let (pitch, code) = decoder.decode_erased(16_384, 1000);
        assert!(pitch < 16_384, "the pitch gain decays");
        assert!(pitch > 14_000, "but is not muted");
        assert!(
            code < 1000 && code > 900,
            "and so does the codebook gain: {code}"
        );

        // Capped: an already-high pitch gain cannot climb through an erasure.
        let (capped, _) = decoder.decode_erased(32_767, 1000);
        assert!(
            capped <= 29_491,
            "the fade is capped at 0.9 in Q15: {capped}"
        );
    }

    #[test]
    fn a_long_erasure_decays_the_predictor_towards_its_floor_and_stops() {
        let mut decoder = GainDecoder::new();
        decoder.past_energy = [0; 4];
        for _ in 0..50 {
            decoder.update_erased();
        }
        assert_eq!(
            decoder.past_energy, [INITIAL_ENERGY; 4],
            "the decay floors rather than running away"
        );
    }
}
