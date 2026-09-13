//! The encoder's gain quantiser — ITU-T G.729 §3.9, reference `qua_gain.c`.
//!
//! Both gains for a subframe are sent in seven bits, jointly: three select a vector from an
//! eight-entry first stage, four a vector from a sixteen-entry second, and the two are added. The
//! pair being quantised together is the point — the pitch and codebook contributions trade off
//! against each other, and quantising them apart would let two individually-close choices combine
//! into a worse reconstruction than a pair that is individually worse.
//!
//! What the codebook holds for the fixed-codebook gain is a *correction factor*, not the gain: the
//! gain itself is predicted from the energy of the innovation and the four previous subframes'
//! quantised energies, and only the ratio between prediction and reality is transmitted. See
//! [`GainPredictor`](super::excitation::GainPredictor), which both directions run.
//!
//! Scoring all 128 pairs per subframe was more than the reference was willing to spend, so a
//! pre-selection solves the unconstrained minimum in closed form and scores only 4 × 8 pairs around
//! it.

use super::bitstream::SUBFRAME_SAMPLES;
use super::excitation::GainPredictor;
use super::tables::{COEF, GBK1, GBK2, INV_COEF, L_COEF, MAP1, MAP2, THR1, THR2};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr,
    l_sub, mult, negate, norm_l, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::{l_extract, mpy_32_16};

/// First-stage vectors scored around the pre-selected one (`NCAN1`).
const CANDIDATES1: usize = 4;
/// Second-stage vectors scored around the pre-selected one (`NCAN2`).
const CANDIDATES2: usize = 8;
/// Largest pitch gain the taming procedure admits, 0.94 in Q9 (`GPCLIP2`).
const TAMED_BEST_GAIN: i16 = 481;
/// Largest pitch gain a tamed subframe may quantise to, just under 1.0 in Q14 (`GP0999`).
const TAMED_QUANTISED_GAIN: i16 = 16_383;

/// One subframe's quantised gains and the index that carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantisedGains {
    /// The 7-bit joint index, as transmitted.
    pub index: u16,
    /// Adaptive-codebook (pitch) gain, Q14.
    pub pitch: i16,
    /// Fixed-codebook gain, Q1.
    pub code: i16,
}

/// Assemble the five mantissa/exponent pairs the quantiser minimises over (`Corr_xy2`, plus the
/// restatement of the pitch search's own two terms that precedes it in `Coder_ld8k`).
///
/// The distortion for a candidate gain pair `(gp, gc)` is
/// `gp²·c0 + gp·c1 + gc²·c2 + gc·c3 + gp·gc·c4`, so `c0 = <y1,y1>`, `c1 = −2<xn,y1>`,
/// `c2 = <y2,y2>`, `c3 = −2<xn,y2>` and `c4 = 2<y1,y2>`. The first two have already been computed
/// by the pitch gain, which needed them; the other three are computed here.
///
/// Each is returned as a normalised mantissa with its own exponent, because the five span far more
/// dynamic range than a common scale would hold — `<y2,y2>` is an energy of a Q12 vector and
/// `<xn,y1>` a cross-correlation of two Q0 ones.
#[must_use]
pub fn distortion_terms(
    pitch_terms: &[i16; 4],
    target: &[i16; SUBFRAME_SAMPLES],
    adaptive: &[i16; SUBFRAME_SAMPLES],
    filtered_code: &[i16; SUBFRAME_SAMPLES],
) -> ([i16; 5], [i16; 5]) {
    let mut correlations = [0_i16; 5];
    let mut exponents = [0_i16; 5];

    correlations[0] = pitch_terms[0];
    exponents[0] = negate(pitch_terms[1]);
    correlations[1] = negate(pitch_terms[2]);
    exponents[1] = negate(add(pitch_terms[3], 1));

    // Q12 down to Q9: three bits of headroom, so that the energy below cannot overflow whatever the
    // codeword's gain turned out to be.
    let mut scaled = [0_i16; SUBFRAME_SAMPLES];
    for (out, &sample) in scaled.iter_mut().zip(filtered_code.iter()) {
        *out = shr(sample, 3);
    }

    // Each product starts at one rather than zero, so an all-zero subframe still normalises.
    let mut energy = 1_i32;
    for &sample in scaled.iter() {
        energy = l_mac(energy, sample, sample);
    }
    let shift = norm_l(energy);
    correlations[2] = round_word(l_shl(energy, shift));
    exponents[2] = add(shift, 19 - 16);

    let mut cross = 1_i32;
    for (&t, &c) in target.iter().zip(scaled.iter()) {
        cross = l_mac(cross, t, c);
    }
    let shift = norm_l(cross);
    correlations[3] = negate(round_word(l_shl(cross, shift)));
    exponents[3] = sub(add(shift, 10 - 16), 1);

    let mut cross = 1_i32;
    for (&a, &c) in adaptive.iter().zip(scaled.iter()) {
        cross = l_mac(cross, a, c);
    }
    let shift = norm_l(cross);
    correlations[4] = round_word(l_shl(cross, shift));
    exponents[4] = sub(add(shift, 10 - 16), 1);

    (correlations, exponents)
}

/// The gain quantiser, holding the encoder's copy of the predictor state.
#[derive(Debug, Clone, Default)]
pub struct GainQuantiser {
    predictor: GainPredictor,
}

impl GainQuantiser {
    /// A quantiser in its reset state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            predictor: GainPredictor::new(),
        }
    }

    /// Quantise one subframe's gain pair (`Qua_gain`).
    ///
    /// `correlations` and `exponents` are the five mantissa/exponent pairs describing the quadratic
    /// the gains minimise: `<y1,y1>`, `−2<xn,y1>`, `<y2,y2>`, `−2<xn,y2>` and `2<y1,y2>`. `tamed`
    /// is the taming procedure's verdict for this subframe, which caps the pitch gain both in the
    /// closed-form solution and in what the search is allowed to pick.
    pub fn quantise(
        &mut self,
        code: &[i16; SUBFRAME_SAMPLES],
        correlations: &[i16; 5],
        exponents: &[i16; 5],
        tamed: bool,
    ) -> QuantisedGains {
        let (predicted, predicted_exponent) = self.predictor.predict(code);
        let best = unconstrained_gains(correlations, exponents, tamed);

        // The prediction, restated in Q4, which is the scale the pre-selection thresholds are in.
        let predicted_q4 = if sub(predicted_exponent, 4) >= 0 {
            shr(predicted, sub(predicted_exponent, 4))
        } else {
            extract_h(l_shl(
                l_deposit_l(predicted),
                sub(4 + 16, predicted_exponent),
            ))
        };
        let (first_candidate, second_candidate) = preselect(&best, predicted_q4);

        // Align the five terms to one exponent so the distortion is a single accumulation. Each
        // term's exponent is its correlation's plus the Q format the gain product it multiplies
        // lands in, which depends on the prediction's exponent.
        let term_exponents = [
            add(exponents[0], 13),
            add(exponents[1], 14),
            add(exponents[2], sub(shl(predicted_exponent, 1), 21)),
            add(exponents[3], sub(predicted_exponent, 3)),
            add(exponents[4], sub(predicted_exponent, 4)),
        ];
        let smallest = *term_exponents.iter().min().unwrap_or(&0);
        let mut aligned = [(0_i16, 0_i16); 5];
        for (slot, (&correlation, &exponent)) in
            correlations.iter().zip(term_exponents.iter()).enumerate()
        {
            let shifted = l_shr(l_deposit_h(correlation), sub(exponent, smallest));
            aligned[slot] = l_extract(shifted);
        }

        let mut best_distortion = i32::MAX;
        let mut first_index = first_candidate;
        let mut second_index = second_candidate;
        for i in 0..CANDIDATES1 {
            for j in 0..CANDIDATES2 {
                let first = first_candidate + i;
                let second = second_candidate + j;
                let pitch = add(GBK1[first][0], GBK2[second][0]); // Q14
                if tamed && pitch >= TAMED_QUANTISED_GAIN {
                    continue;
                }

                let correction = l_add(l_deposit_l(GBK1[first][1]), l_deposit_l(GBK2[second][1])); // Q13
                let half = extract_l(l_shr(correction, 1)); // Q12
                let gain = mult(predicted, half);

                // Accumulated strictly left to right: `l_add` saturates, so the association is
                // observable and has to be the reference's.
                let mut distortion = mpy_32_16(aligned[0].0, aligned[0].1, mult(pitch, pitch));
                distortion = l_add(distortion, mpy_32_16(aligned[1].0, aligned[1].1, pitch));
                distortion = l_add(
                    distortion,
                    mpy_32_16(aligned[2].0, aligned[2].1, mult(gain, gain)),
                );
                distortion = l_add(distortion, mpy_32_16(aligned[3].0, aligned[3].1, gain));
                distortion = l_add(
                    distortion,
                    mpy_32_16(aligned[4].0, aligned[4].1, mult(gain, pitch)),
                );

                if l_sub(distortion, best_distortion) < 0 {
                    best_distortion = distortion;
                    first_index = first;
                    second_index = second;
                }
            }
        }

        let pitch = add(GBK1[first_index][0], GBK2[second_index][0]);
        let correction = l_add(
            l_deposit_l(GBK1[first_index][1]),
            l_deposit_l(GBK2[second_index][1]),
        );
        let half = extract_l(l_shr(correction, 1)); // Q12
        let scaled = l_shl(
            l_mult(half, predicted),
            add(negate(predicted_exponent), -12 - 1 + 1 + 16),
        );
        let code_gain = extract_h(scaled);

        self.predictor.update(correction);

        // The transmitted index is the two stage indices permuted: the mapping spreads neighbouring
        // gain pairs across the codeword so a single bit error moves the gain less far.
        let index = MAP1[first_index] * GBK2.len() as i16 + MAP2[second_index];
        QuantisedGains {
            index: index as u16,
            pitch,
            code: code_gain,
        }
    }
}

/// Solve the quadratic for the gain pair that minimises the distortion, ignoring the codebook.
///
/// Returns `[pitch in Q9, code in Q2]`. The search only ever visits vectors near this point, so it
/// is what makes 32 candidates enough; being unquantised, it is also where the taming cap has to be
/// applied first, or the pre-selection would start from a gain the search is forbidden to choose.
fn unconstrained_gains(correlations: &[i16; 5], exponents: &[i16; 5], tamed: bool) -> [i16; 2] {
    // denominator = 4·c0·c2 − c4², negated and inverted.
    let (determinant, determinant_exponent) = difference(
        l_mult(correlations[0], correlations[2]),
        add(add(exponents[0], exponents[2]), 1 - 2),
        l_mult(correlations[4], correlations[4]),
        add(add(exponents[4], exponents[4]), 1),
        false,
    );
    let shift = norm_l(determinant);
    let denominator = extract_h(l_shl(determinant, shift));
    let denominator_exponent = sub(add(determinant_exponent, shift), 16);
    let inverse = negate(div_s(16_384, denominator));
    let inverse_exponent = sub(14 + 15, denominator_exponent);

    // pitch = (2·c2·c1 − c3·c4) / denominator, in Q9.
    let (numerator, numerator_exponent) = difference(
        l_mult(correlations[2], correlations[1]),
        add(exponents[2], exponents[1]),
        l_mult(correlations[3], correlations[4]),
        add(add(exponents[3], exponents[4]), 1),
        true,
    );
    let shift = norm_l(numerator);
    let scaled = extract_h(l_shl(numerator, shift));
    let scaled_exponent = sub(add(numerator_exponent, shift), 16);
    let shift = sub(add(scaled_exponent, inverse_exponent), 9 + 16 - 1);
    let mut pitch = extract_h(l_shr(l_mult(scaled, inverse), shift));

    if tamed && sub(pitch, TAMED_BEST_GAIN) > 0 {
        pitch = TAMED_BEST_GAIN;
    }

    // code = (2·c0·c3 − c1·c4) / denominator, in Q2.
    let (numerator, numerator_exponent) = difference(
        l_mult(correlations[0], correlations[3]),
        add(exponents[0], exponents[3]),
        l_mult(correlations[1], correlations[4]),
        add(add(exponents[1], exponents[4]), 1),
        true,
    );
    let shift = norm_l(numerator);
    let scaled = extract_h(l_shl(numerator, shift));
    let scaled_exponent = sub(add(numerator_exponent, shift), 16);
    let shift = sub(add(scaled_exponent, inverse_exponent), 2 + 16 - 1);
    let code = extract_h(l_shr(l_mult(scaled, inverse), shift));

    [pitch, code]
}

/// Subtract two mantissa/exponent values, bringing the larger exponent down to the smaller.
///
/// `halve` gives both sides one extra bit of headroom first, which the two numerators need and the
/// determinant does not.
fn difference(
    left: i32,
    left_exponent: i16,
    right: i32,
    right_exponent: i16,
    halve: bool,
) -> (i32, i16) {
    let extra = i16::from(halve);
    if sub(left_exponent, right_exponent) > 0 {
        (
            l_sub(
                l_shr(left, add(sub(left_exponent, right_exponent), extra)),
                l_shr(right, extra),
            ),
            sub(right_exponent, extra),
        )
    } else {
        (
            l_sub(
                l_shr(left, extra),
                l_shr(right, add(sub(right_exponent, left_exponent), extra)),
            ),
            sub(left_exponent, extra),
        )
    }
}

/// Pick the first vector of each stage's candidate window (`Gbk_presel`).
///
/// The unconstrained solution is mapped through the codebook's own geometry into two scalars, each
/// compared against a ladder of thresholds; the number of thresholds it clears is the index the
/// window starts at.
fn preselect(best: &[i16; 2], predicted: i16) -> (usize, usize) {
    // x = (best_code − (coef[0][0]·best_pitch + coef[1][1])·predicted) · inv_coef
    let product = l_mult(COEF[0][0], best[0]); // Q20
    let mut accumulator = l_add(product, l_shr(L_COEF[1][1], 15));
    let high = extract_h(accumulator); // Q4
    let predicted_term = l_mult(high, predicted); // Q9
    accumulator = l_sub(l_shl(l_deposit_l(best[1]), 7), predicted_term);
    let high = extract_h(l_shl(accumulator, 2));
    let x = l_mult(high, INV_COEF); // Q15

    // y = (coef[1][0]·(best_pitch·coef[0][0] − coef[0][1])·predicted − coef[0][0]·best_code)·inv_coef
    accumulator = l_sub(product, l_shr(L_COEF[0][1], 10)); // Q20
    let high = mult(extract_h(accumulator), predicted); // Q-7
    let term = l_mult(high, COEF[1][0]); // Q10
    accumulator = l_sub(term, l_shr(l_mult(COEF[0][0], best[1]), 3));
    let high = extract_h(l_shl(accumulator, 2));
    let y = l_mult(high, INV_COEF); // Q16

    let y_shift = (14 + 4 + 1) - 16;
    let x_shift = (15 + 4 + 1) - 15;

    // A negative prediction reverses the comparison, because the thresholds are scaled by it. The
    // two directions are not mirror images: a difference of exactly zero ends the walk either way,
    // so each side gets its own strict test rather than the negation of the other's.
    let advance = |difference: i32| {
        if predicted > 0 {
            difference > 0
        } else {
            difference < 0
        }
    };

    let mut first = 0;
    while first < THR1.len() {
        if !advance(l_sub(y, l_shr(l_mult(THR1[first], predicted), y_shift))) {
            break;
        }
        first += 1;
    }
    let mut second = 0;
    while second < THR2.len() {
        if !advance(l_sub(x, l_shr(l_mult(THR2[second], predicted), x_shift))) {
            break;
        }
        second += 1;
    }
    (first, second)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g729::excitation::GainDecoder;
    use crate::g729::pitch::pitch_gain;

    /// A plausible subframe: a target, the adaptive contribution filtered, a four-pulse codeword and
    /// that codeword filtered. Scaled by `loudness` so a sweep can reach both ends of the codebook.
    struct Subframe {
        pitch_terms: [i16; 4],
        target: [i16; SUBFRAME_SAMPLES],
        adaptive: [i16; SUBFRAME_SAMPLES],
        filtered: [i16; SUBFRAME_SAMPLES],
        code: [i16; SUBFRAME_SAMPLES],
    }

    fn subframe(loudness: f32) -> Subframe {
        let target: [i16; SUBFRAME_SAMPLES] =
            std::array::from_fn(|i| ((i as f32 * 0.33).sin() * 4000.0 * loudness) as i16);
        let adaptive: [i16; SUBFRAME_SAMPLES] =
            std::array::from_fn(|i| ((i as f32 * 0.33).sin() * 3200.0) as i16);
        let (_, pitch_terms) = pitch_gain(&target, &adaptive);

        let mut code = [0_i16; SUBFRAME_SAMPLES];
        for (pulse, &position) in [0_usize, 11, 22, 33].iter().enumerate() {
            code[position] = if pulse % 2 == 0 { 8191 } else { -8192 };
        }
        let filtered: [i16; SUBFRAME_SAMPLES] =
            std::array::from_fn(|i| ((i as f32 * 0.9).cos() * 2400.0) as i16);

        Subframe {
            pitch_terms,
            target,
            adaptive,
            filtered,
            code,
        }
    }

    #[test]
    fn the_transmitted_index_decodes_back_to_the_gains_the_encoder_kept() {
        // The contract across the two halves. Both sides start their predictor at the same floor
        // and see the same codeword, so a disagreement here is an encoder modelling a decoder
        // nobody has — and since the gain is a correction to a predicted energy, that disagreement
        // compounds across subframes rather than staying local.
        let mut quantiser = GainQuantiser::new();
        let mut decoder = GainDecoder::new();

        for step in 0..20 {
            let loudness = 0.2 + step as f32 * 0.15;
            let s = subframe(loudness);
            let (correlations, exponents) =
                distortion_terms(&s.pitch_terms, &s.target, &s.adaptive, &s.filtered);
            let quantised = quantiser.quantise(&s.code, &correlations, &exponents, false);
            let (pitch, gain) = decoder.decode(quantised.index, &s.code);
            assert_eq!(
                (quantised.pitch, quantised.code),
                (pitch, gain),
                "step {step}, index {}",
                quantised.index
            );
        }
    }

    #[test]
    fn the_index_fits_the_seven_bits_the_bitstream_allots_it() {
        let mut quantiser = GainQuantiser::new();
        for step in 0..20 {
            let s = subframe(0.2 + step as f32 * 0.15);
            let (correlations, exponents) =
                distortion_terms(&s.pitch_terms, &s.target, &s.adaptive, &s.filtered);
            let quantised = quantiser.quantise(&s.code, &correlations, &exponents, false);
            assert!(quantised.index < 128, "index {}", quantised.index);
        }
    }

    #[test]
    fn taming_holds_the_pitch_gain_below_unity() {
        // The taming procedure exists because a pitch gain at or above one turns the adaptive
        // codebook into an oscillator: any error in the excitation history is amplified every
        // period rather than decaying, and on an erased frame the decoder's history differs from
        // the encoder's by construction. The sweep is checked to actually reach the cap, so the
        // test cannot pass by never exercising it.
        let mut untamed_reached_the_cap = false;
        for step in 0..20 {
            let loudness = 0.2 + step as f32 * 0.15;
            let subframe = subframe(loudness);
            let (correlations, exponents) = distortion_terms(
                &subframe.pitch_terms,
                &subframe.target,
                &subframe.adaptive,
                &subframe.filtered,
            );

            let mut free = GainQuantiser::new();
            if free
                .quantise(&subframe.code, &correlations, &exponents, false)
                .pitch
                >= TAMED_QUANTISED_GAIN
            {
                untamed_reached_the_cap = true;
            }

            let mut tamed = GainQuantiser::new();
            let quantised = tamed.quantise(&subframe.code, &correlations, &exponents, true);
            assert!(
                quantised.pitch < TAMED_QUANTISED_GAIN,
                "step {step}: tamed pitch gain {}",
                quantised.pitch
            );
        }
        assert!(
            untamed_reached_the_cap,
            "the sweep never reached a gain the cap would bind on"
        );
    }

    #[test]
    fn the_predictor_advances_with_every_quantised_subframe() {
        // The codebook gain is a correction to a predicted energy, so the same inputs twice running
        // must not give the same answer: if they did, the predictor would not be advancing and the
        // decoder's would drift away from it.
        let s = subframe(1.0);
        let (correlations, exponents) =
            distortion_terms(&s.pitch_terms, &s.target, &s.adaptive, &s.filtered);

        let mut quantiser = GainQuantiser::new();
        let first = quantiser.quantise(&s.code, &correlations, &exponents, false);
        let second = quantiser.quantise(&s.code, &correlations, &exponents, false);
        assert_ne!(
            (first.index, first.code),
            (second.index, second.code),
            "the prediction did not move"
        );
    }

    #[test]
    fn a_silent_subframe_quantises_to_a_transmittable_index() {
        let mut quantiser = GainQuantiser::new();
        let (correlations, exponents) = distortion_terms(
            &[0; 4],
            &[0; SUBFRAME_SAMPLES],
            &[0; SUBFRAME_SAMPLES],
            &[0; SUBFRAME_SAMPLES],
        );
        let quantised =
            quantiser.quantise(&[0; SUBFRAME_SAMPLES], &correlations, &exponents, false);
        assert!(quantised.index < 128);
    }

    #[test]
    fn the_distortion_terms_carry_the_signs_the_quadratic_expects() {
        // Two of the five are negated cross-correlations. Getting a sign wrong here would make the
        // quantiser minimise the wrong quadratic and still return a plausible-looking gain pair.
        let s = subframe(1.0);
        let (correlations, _) =
            distortion_terms(&s.pitch_terms, &s.target, &s.adaptive, &s.filtered);
        assert!(correlations[0] >= 0, "<y1,y1> is an energy");
        assert!(correlations[2] >= 0, "<y2,y2> is an energy");

        let cross: i64 = s
            .target
            .iter()
            .zip(s.filtered.iter())
            .map(|(&t, &f)| i64::from(t) * i64::from(f))
            .sum();
        assert_eq!(
            correlations[3] <= 0,
            cross >= 0,
            "-2<xn,y2> opposes the correlation it is built from"
        );
    }
}
