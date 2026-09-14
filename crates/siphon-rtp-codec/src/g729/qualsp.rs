//! The encoder's LSP quantiser (ITU-T G.729 Release 3 `qua_lsp.c`): choosing the two indices the
//! frame transmits, and the MA predictor set they are coded against.
//!
//! The search is over a residual, not the line frequencies themselves: the predictor's contribution
//! is removed first, the two-stage codebook is searched against what is left, and the whole thing is
//! done twice — once per MA coefficient set — with the set that fits better winning the one bit that
//! selects it. That is why the encoder carries its own [`Predictor`] instance driven exactly as the
//! decoder's is; the reference keeps two file-scope copies of the same state for the same reason.
//!
//! The distortion is weighted, and the weights come from how close each line frequency sits to its
//! neighbours: a pair that is nearly coincident describes a sharp formant, where an error is
//! audible, so it is weighted up.

use super::lspdec::{lsf_to_lsp, Predictor, ORDER};
use super::tables::{LSPCB1, LSPCB2, SLOPE_ACOS, TABLE2};
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_mac, l_mult, l_shl, l_shr, mult, norm_s, shl, sub,
};

/// Split point of the two-stage codebook.
const SPLIT: usize = 5;
/// MA coefficient sets the encoder chooses between.
const MODES: usize = 2;
/// Minimum spacing enforced between adjacent frequencies, first pass. Q13.
const GAP1: i16 = 10;
/// Minimum spacing enforced in the second pass. Q13.
const GAP2: i16 = 5;
/// `pi * 0.04` in Q13, the low edge the weighting measures against.
const PI_LOW: i16 = 1029;
/// `pi * 0.92` in Q13, the high edge.
const PI_HIGH: i16 = 23_677;
/// 10.0 in Q11, the weighting's slope for a close pair.
const WEIGHT_SLOPE: i16 = 10 * (1 << 11);
/// 1.2 in Q14, the extra emphasis the middle of the band gets.
const WEIGHT_MID: i16 = 19_661;

/// The encoder's LSP quantiser state.
#[derive(Debug, Clone, Default)]
pub struct LspQuantiser {
    predictor: Predictor,
}

impl LspQuantiser {
    /// A quantiser at its reset state (`Lsp_encw_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            predictor: Predictor::new(),
        }
    }

    /// Quantise one frame's line spectral pairs.
    ///
    /// Returns the two transmitted parameters — the 8-bit MA-set-and-first-stage index and the
    /// 10-bit pair of second-stage indices — together with the quantised LSPs the encoder must then
    /// use itself, so that its local synthesis tracks what the decoder will actually reconstruct.
    pub fn quantise(&mut self, lsp: &[i16; ORDER]) -> (u16, u16, [i16; ORDER]) {
        let lsf = lsp_to_lsf(lsp);
        let weights = weights(&lsf);

        let mut candidate = [0_usize; MODES];
        let mut lower_index = [0_usize; MODES];
        let mut upper_index = [0_usize; MODES];
        let mut distortion = [0_i32; MODES];

        for mode in 0..MODES {
            // Search against the prediction residual, not the frequencies themselves.
            let residual = self.predictor.extract_residual(&lsf, mode);

            let first = pre_select(&residual);
            candidate[mode] = first;

            let lower = select_half(&residual, &LSPCB1[first], &weights, 0..SPLIT);
            lower_index[mode] = lower;

            let mut buffer = [0_i16; ORDER];
            for j in 0..SPLIT {
                buffer[j] = add(LSPCB1[first][j], LSPCB2[lower][j]);
            }
            expand(&mut buffer, GAP1, 1..SPLIT);

            let upper = select_half(&residual, &LSPCB1[first], &weights, SPLIT..ORDER);
            upper_index[mode] = upper;
            for j in SPLIT..ORDER {
                buffer[j] = add(LSPCB1[first][j], LSPCB2[upper][j]);
            }
            expand(&mut buffer, GAP1, SPLIT..ORDER);
            expand(&mut buffer, GAP2, 1..ORDER);

            distortion[mode] = total_distortion(&weights, &buffer, &residual, mode);
        }

        // The better-fitting predictor set wins the mode bit.
        let mode = usize::from(distortion[1] < distortion[0]);

        let first = candidate[mode];
        let lower = lower_index[mode];
        let upper = upper_index[mode];

        // Reconstruct exactly what the decoder will, and advance the predictor with it.
        let mut residual = [0_i16; ORDER];
        for j in 0..SPLIT {
            residual[j] = add(LSPCB1[first][j], LSPCB2[lower][j]);
        }
        for j in SPLIT..ORDER {
            residual[j] = add(LSPCB1[first][j], LSPCB2[upper][j]);
        }
        expand(&mut residual, GAP1, 1..ORDER);
        expand(&mut residual, GAP2, 1..ORDER);
        let mut quantised = self.predictor.compose(&residual, mode);
        self.predictor.push(&residual);
        super::lspdec::stabilise_public(&mut quantised);

        let stage1 = ((mode as u16) << 7) | first as u16;
        let stage2 = ((lower as u16) << 5) | upper as u16;
        (stage1, stage2, lsf_to_lsp(&quantised))
    }
}

/// Convert line spectral pairs (Q15) back to frequencies (Q13) — `Lsp_lsf2`, the inverse of the
/// decoder's conversion, by searching the same cosine table backwards.
#[must_use]
pub fn lsp_to_lsf(lsp: &[i16; ORDER]) -> [i16; ORDER] {
    let mut lsf = [0_i16; ORDER];
    let mut point = TABLE2.len() - 1;
    for i in (0..ORDER).rev() {
        while sub(TABLE2[point], lsp[i]) < 0 {
            point -= 1;
            if point == 0 {
                break;
            }
        }
        let offset = sub(lsp[i], TABLE2[point]);
        let interpolated = l_mult(SLOPE_ACOS[point], offset);
        let frequency = add(shl(point as i16, 9), extract_l(l_shr(interpolated, 12)));
        lsf[i] = mult(frequency, 25_736); // 2*pi in Q12
    }
    lsf
}

/// Weighting coefficients for the distortion measure (`Get_wegt`).
///
/// Each frequency's weight rises as its neighbours close in, because a narrow pair is a sharp
/// formant and an error there is heard. The middle of the band gets a further 1.2x, which is where
/// the ear is most sensitive.
fn weights(lsf: &[i16; ORDER]) -> [i16; ORDER] {
    let mut spacing = [0_i16; ORDER];
    spacing[0] = sub(lsf[1], add(PI_LOW, 8192));
    for i in 1..ORDER - 1 {
        spacing[i] = sub(sub(lsf[i + 1], lsf[i - 1]), 8192);
    }
    spacing[ORDER - 1] = sub(sub(PI_HIGH, 8192), lsf[ORDER - 2]);

    let mut weight = [0_i16; ORDER];
    for (index, &gap) in spacing.iter().enumerate() {
        weight[index] = if gap > 0 {
            2048 // 1.0 in Q11
        } else {
            let squared = extract_h(l_shl(l_mult(gap, gap), 2));
            let scaled = extract_h(l_shl(l_mult(squared, WEIGHT_SLOPE), 2));
            add(scaled, 2048)
        };
    }
    weight[4] = extract_h(l_shl(l_mult(weight[4], WEIGHT_MID), 1));
    weight[5] = extract_h(l_shl(l_mult(weight[5], WEIGHT_MID), 1));

    // Normalise so the largest weight uses the full range, keeping the distortion sums comparable.
    let largest = weight.iter().copied().max().unwrap_or(0);
    let shift = norm_s(largest);
    for value in &mut weight {
        *value = shl(*value, shift);
    }
    weight
}

/// Nearest first-stage codebook entry by unweighted squared distance (`Lsp_pre_select`).
fn pre_select(residual: &[i16; ORDER]) -> usize {
    let mut best = 0_usize;
    let mut smallest = i32::MAX;
    for (index, entry) in LSPCB1.iter().enumerate() {
        let mut distance = 0_i32;
        for j in 0..ORDER {
            let difference = sub(residual[j], entry[j]);
            distance = l_mac(distance, difference, difference);
        }
        if distance < smallest {
            smallest = distance;
            best = index;
        }
    }
    best
}

/// Best second-stage entry for one half of the vector, by weighted squared distance
/// (`Lsp_select_1` / `Lsp_select_2`, which differ only in the range they cover).
fn select_half(
    residual: &[i16; ORDER],
    first_stage: &[i16; ORDER],
    weights: &[i16; ORDER],
    range: std::ops::Range<usize>,
) -> usize {
    let mut target = [0_i16; ORDER];
    for j in range.clone() {
        target[j] = sub(residual[j], first_stage[j]);
    }

    let mut best = 0_usize;
    let mut smallest = i32::MAX;
    for (index, entry) in LSPCB2.iter().enumerate() {
        let mut distance = 0_i32;
        for j in range.clone() {
            let difference = sub(target[j], entry[j]);
            let weighted = mult(weights[j], difference);
            distance = l_mac(distance, weighted, difference);
        }
        if distance < smallest {
            smallest = distance;
            best = index;
        }
    }
    best
}

/// Weighted distortion of a candidate against the target, in the composed domain
/// (`Lsp_get_tdist`).
fn total_distortion(
    weights: &[i16; ORDER],
    candidate: &[i16; ORDER],
    target: &[i16; ORDER],
    mode: usize,
) -> i32 {
    let mut total = 0_i32;
    for j in 0..ORDER {
        let difference = mult(sub(candidate[j], target[j]), super::tables::FG_SUM[mode][j]);
        let weighted = extract_h(l_shl(l_mult(weights[j], difference), 4));
        total = l_mac(total, weighted, difference);
    }
    total
}

/// Force a minimum spacing across part of the vector (`Lsp_expand_1` / `_2` / `_1_2`, which are the
/// same routine over different ranges).
fn expand(buffer: &mut [i16; ORDER], gap: i16, range: std::ops::Range<usize>) {
    for j in range {
        let difference = sub(buffer[j - 1], buffer[j]);
        let correction = crate::itu::basic_ops::shr(add(difference, gap), 1);
        if correction > 0 {
            buffer[j - 1] = sub(buffer[j - 1], correction);
            buffer[j] = add(buffer[j], correction);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LSP: [i16; ORDER] = [
        30_864, 27_346, 22_887, 16_217, 2516, -5842, -13_459, -20_234, -25_756, -29_622,
    ];

    #[test]
    fn line_pairs_and_frequencies_round_trip() {
        // `lsp_to_lsf` here and `lsf_to_lsp` in the decoder are inverses through the same table, so
        // a scaling error in either shows up immediately.
        let lsf = lsp_to_lsf(&LSP);
        assert!(
            lsf.windows(2).all(|w| w[0] < w[1]),
            "frequencies rise: {lsf:?}"
        );
        let back = lsf_to_lsp(&lsf);
        for (index, (&got, &want)) in back.iter().zip(LSP.iter()).enumerate() {
            assert!(
                (i32::from(got) - i32::from(want)).abs() < 200,
                "pair {index}: {got} vs {want}"
            );
        }
    }

    #[test]
    fn close_line_frequencies_are_weighted_above_widely_spaced_ones() {
        // The whole point of the weighting: a narrow pair is a sharp formant, where quantisation
        // error is audible, so it must not be traded away against a wide one.
        let spread: [i16; ORDER] = [
            2000, 4600, 7200, 9800, 12_400, 15_000, 17_600, 20_200, 22_800, 25_400,
        ];
        let mut narrow = spread;
        narrow[6] = narrow[5] + 100; // pull one pair together
        narrow[7] = narrow[6] + 100;

        let spread_weights = weights(&spread);
        let narrow_weights = weights(&narrow);
        assert!(
            narrow_weights[6] >= spread_weights[6],
            "the crowded frequency should not be weighted lower"
        );
    }

    #[test]
    fn quantising_returns_indices_that_fit_their_transmitted_widths() {
        let mut quantiser = LspQuantiser::new();
        let (stage1, stage2, _) = quantiser.quantise(&LSP);
        assert!(stage1 < 256, "the first parameter is 8 bits: {stage1}");
        assert!(stage2 < 1024, "the second is 10 bits: {stage2}");
    }

    #[test]
    fn the_quantised_pairs_stay_ordered_and_close_to_the_input() {
        // The quantiser must hand the encoder something the decoder can build a stable filter from,
        // and it must resemble what went in or the codec is not coding anything.
        let mut quantiser = LspQuantiser::new();
        for _ in 0..8 {
            let (_, _, quantised) = quantiser.quantise(&LSP);
            assert!(
                quantised.windows(2).all(|w| w[0] > w[1]),
                "ordered: {quantised:?}"
            );
            let error: i32 = quantised
                .iter()
                .zip(LSP.iter())
                .map(|(&a, &b)| (i32::from(a) - i32::from(b)).abs())
                .sum();
            assert!(error < 40_000, "quantised too far from the input: {error}");
        }
    }

    #[test]
    fn the_encoder_and_decoder_agree_on_what_was_transmitted() {
        // The contract between the two halves: whatever the quantiser says it sent, feeding those
        // same indices to the decoder's quantiser must reproduce the pairs the encoder kept for its
        // own local synthesis. A drift here is an encoder that models a decoder nobody has.
        use crate::g729::lspdec::LspDecoder;
        let mut quantiser = LspQuantiser::new();
        let mut decoder = LspDecoder::new();
        for step in 0..12 {
            let mut moving = LSP;
            for (index, value) in moving.iter_mut().enumerate() {
                *value = value.saturating_sub(step * (index as i16 + 1) * 20);
            }
            let (stage1, stage2, encoder_side) = quantiser.quantise(&moving);
            let decoder_side = decoder.decode(stage1, stage2, false);
            assert_eq!(
                encoder_side, decoder_side,
                "step {step}: the two sides disagree on the reconstruction"
            );
        }
    }
}
