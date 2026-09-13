//! The silence descriptor's spectrum: nine bits for what a speech frame spends eighteen on —
//! ITU-T G.729 Annex B §4.2, reference `qsidlsf.c` and the decode half of `dec_sid.c`.
//!
//! One bit chooses between two moving-average predictors, five address a subset of the speech
//! quantiser's first-stage codebook and four a subset of its second. Reusing the speech codebooks
//! rather than carrying a second pair is the whole trick: the subsets
//! ([`SID_LSF_STAGE1`], [`SID_LSF_STAGE2`]) are chosen to span the space the entries cover, and
//! what the descriptor loses is resolution, not reach.
//!
//! The two halves share one predictor memory with the speech quantiser — a descriptor sent in the
//! middle of a call predicts from the frames before it, speech or not — which is why both of these
//! take the [`Predictor`] rather than owning one.

use super::lspdec::{lsf_to_lsp, stabilise_public, Predictor};
use super::qualsp::{expand, lsp_to_lsf, weights};
use super::tables::{
    LSPCB1, LSPCB2, NOISE_FG, NOISE_FG_SUM, NOISE_FG_SUM_INV, SID_LSF_STAGE1, SID_LSF_STAGE2,
    SID_MODE_WEIGHT,
};
use crate::itu::basic_ops::{add, extract_h, l_mac, l_mult, mult, sub};

/// Line-spectral-frequency order.
const ORDER: usize = 10;
/// Predictor sets the one transmitted bit chooses between.
const MODES: usize = 2;
/// Survivors carried from the first stage into the second.
const SURVIVORS: usize = 4;
/// Smallest and largest line frequency, and the minimum spacing enforced before quantisation. Q13.
const LOW_LIMIT: i16 = 40;
const HIGH_LIMIT: i16 = 25_681;
const MINIMUM_GAP: i16 = 321;

/// The three indices a silence descriptor carries for its spectrum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpectrumIndices {
    /// Which predictor set, one bit.
    pub mode: u16,
    /// First-stage codebook entry, five bits.
    pub stage1: u16,
    /// Second-stage codebook entry, four bits.
    pub stage2: u16,
}

/// Quantise one frame's line spectral pairs for a silence descriptor (`lsfq_noise`).
///
/// Returns the indices to transmit and the pairs the decoder will rebuild from them, which the
/// encoder must then use for its own synthesis.
pub fn quantise(predictor: &mut Predictor, lsp: &[i16; ORDER]) -> (SpectrumIndices, [i16; ORDER]) {
    let mut lsf = lsp_to_lsf(lsp);

    // Space the frequencies to roughly 100 Hz before quantising. A descriptor is coarse enough that
    // two frequencies landing on top of each other would give a filter that rings on noise.
    if lsf[0] < LOW_LIMIT {
        lsf[0] = LOW_LIMIT;
    }
    for i in 0..ORDER - 1 {
        if sub(lsf[i + 1], lsf[i]) < 2 * MINIMUM_GAP {
            lsf[i + 1] = add(lsf[i], 2 * MINIMUM_GAP);
        }
    }
    if lsf[ORDER - 1] > HIGH_LIMIT {
        lsf[ORDER - 1] = HIGH_LIMIT;
    }
    if lsf[ORDER - 1] < lsf[ORDER - 2] {
        lsf[ORDER - 2] = sub(lsf[ORDER - 1], MINIMUM_GAP);
    }

    let weight = weights(&lsf);

    // One prediction residual per predictor set; the search below picks between them.
    let mut residuals = [[0_i16; ORDER]; MODES];
    for (mode, residual) in residuals.iter_mut().enumerate() {
        *residual = predictor.extract_residual_with(&lsf, &NOISE_FG[mode], &NOISE_FG_SUM_INV[mode]);
    }

    let (mut quantised_residual, indices) = search(&residuals, &weight);

    // The same 0.0012 minimum spacing the decoder applies, so both sides hold the same vector.
    expand(&mut quantised_residual, 10, 1..ORDER);

    let mode = indices.mode as usize;
    let mut lsf = predictor.compose_with(&quantised_residual, &NOISE_FG[mode], &NOISE_FG_SUM[mode]);
    predictor.push(&quantised_residual);
    stabilise_public(&mut lsf);
    (indices, lsf_to_lsp(&lsf))
}

/// Rebuild the pairs a silence descriptor's indices describe (`sid_lsfq_decode`).
pub fn dequantise(predictor: &mut Predictor, indices: SpectrumIndices) -> [i16; ORDER] {
    let mut residual = codeword(indices.stage1 as usize, indices.stage2 as usize);

    // The decoder spells the minimum-spacing step out in 32-bit arithmetic rather than calling the
    // shared routine; the difference is only whether the intermediate can saturate, and this is the
    // form the vectors were generated from.
    for j in 1..ORDER {
        let mut accumulator = l_mult(residual[j - 1], 16_384);
        accumulator = l_mac(accumulator, residual[j], -16_384);
        accumulator = l_mac(accumulator, 10, 16_384);
        let correction = extract_h(accumulator);
        if correction > 0 {
            residual[j - 1] = sub(residual[j - 1], correction);
            residual[j] = add(residual[j], correction);
        }
    }

    let mode = indices.mode as usize;
    let mut lsf = predictor.compose_with(&residual, &NOISE_FG[mode], &NOISE_FG_SUM[mode]);
    predictor.push(&residual);
    stabilise_public(&mut lsf);
    lsf_to_lsp(&lsf)
}

/// The two-stage codeword a pair of indices addresses: the first-stage entry with the second-stage
/// correction added, each half of the vector taking its own second-stage row.
fn codeword(stage1: usize, stage2: usize) -> [i16; ORDER] {
    let mut vector = LSPCB1[SID_LSF_STAGE1[stage1] as usize];
    for i in 0..ORDER / 2 {
        vector[i] = add(vector[i], LSPCB2[SID_LSF_STAGE2[0][stage2] as usize][i]);
    }
    for i in ORDER / 2..ORDER {
        vector[i] = add(vector[i], LSPCB2[SID_LSF_STAGE2[1][stage2] as usize][i]);
    }
    vector
}

/// The two-stage search (`Qnt_e`), over both predictor sets at once.
///
/// The first stage keeps four survivors across both sets rather than the best one from each, so the
/// choice of predictor is not made before the codebook has had its say — a set that fits the first
/// stage slightly worse can still win once the second stage is added.
fn search(
    residuals: &[[i16; ORDER]; MODES],
    weight: &[i16; ORDER],
) -> ([i16; ORDER], SpectrumIndices) {
    let (first_stage, first_errors, first_sets) = search_stage1(residuals);
    let (second_indices, second_sets) = search_stage2(&first_errors, weight, &first_sets);

    let stage2 = second_indices;
    let survivor = second_sets;
    let stage1 = first_stage[survivor];
    let mode = first_sets[survivor];

    (
        codeword(stage1, stage2),
        SpectrumIndices {
            mode: mode as u16,
            stage1: stage1 as u16,
            stage2: stage2 as u16,
        },
    )
}

/// First stage (`New_ML_search_1`): the four closest entries over both predictor sets, unweighted,
/// each set's distortion scaled by how much of the spectrum that set leaves for the codebook.
fn search_stage1(
    residuals: &[[i16; ORDER]; MODES],
) -> (
    [usize; SURVIVORS],
    [[i16; ORDER]; SURVIVORS],
    [usize; SURVIVORS],
) {
    let mut distortion = [[0_i16; 32]; MODES];
    for ((set, residual), row) in residuals.iter().enumerate().zip(distortion.iter_mut()) {
        for (entry, slot) in row.iter_mut().enumerate() {
            let candidate = &LSPCB1[SID_LSF_STAGE1[entry] as usize];
            let mut accumulator = 0_i32;
            for (&value, &reference) in residual.iter().zip(candidate.iter()) {
                let difference = sub(value, reference);
                accumulator = l_mac(accumulator, difference, difference);
            }
            *slot = mult(extract_h(accumulator), SID_MODE_WEIGHT[set]);
        }
    }

    let mut sets = [0_usize; SURVIVORS];
    let mut chosen = [0_usize; SURVIVORS];
    let mut errors = [[0_i16; ORDER]; SURVIVORS];
    for survivor in 0..SURVIVORS {
        let mut best = i16::MAX;
        let (mut best_set, mut best_entry) = (0_usize, 0_usize);
        for (set, row) in distortion.iter().enumerate() {
            for (entry, &value) in row.iter().enumerate() {
                if sub(value, best) < 0 {
                    best = value;
                    best_set = set;
                    best_entry = entry;
                }
            }
        }
        // Take it out of the running so the next pass finds the next best.
        distortion[best_set][best_entry] = i16::MAX;

        let candidate = &LSPCB1[SID_LSF_STAGE1[best_entry] as usize];
        for (slot, (&value, &reference)) in errors[survivor]
            .iter_mut()
            .zip(residuals[best_set].iter().zip(candidate.iter()))
        {
            *slot = sub(value, reference);
        }
        sets[survivor] = best_set;
        chosen[survivor] = best_entry;
    }
    (chosen, errors, sets)
}

/// Second stage (`New_ML_search_2`): the entry that minimises the weighted error, over the four
/// survivors.
///
/// The weighting here folds in the predictor set's own sum as well as the perceptual weight, which
/// is what makes the two sets' distortions comparable — the residual each set leaves is on a
/// different scale, and comparing them raw would always pick the same set.
fn search_stage2(
    errors: &[[i16; ORDER]; SURVIVORS],
    weight: &[i16; ORDER],
    sets: &[usize; SURVIVORS],
) -> (usize, usize) {
    let entries = SID_LSF_STAGE2[0].len();
    let mut best = i16::MAX;
    let (mut best_survivor, mut best_entry) = (0_usize, 0_usize);

    for (survivor, error) in errors.iter().enumerate() {
        let sum = &NOISE_FG_SUM[sets[survivor]];
        for entry in 0..entries {
            let mut accumulator = 0_i32;
            // Each half of the vector takes its own second-stage row.
            for (half, rows) in SID_LSF_STAGE2.iter().enumerate() {
                let row = rows[entry] as usize;
                let range = if half == 0 {
                    0..ORDER / 2
                } else {
                    ORDER / 2..ORDER
                };
                for index in range {
                    let scale = extract_h(crate::itu::basic_ops::l_shl(
                        l_mult(sum[index], sum[index]),
                        2,
                    ));
                    let scaled = mult(scale, weight[index]);
                    let difference = sub(error[index], LSPCB2[row][index]);
                    let product =
                        extract_h(crate::itu::basic_ops::l_shl(l_mult(scaled, difference), 3));
                    accumulator = l_mac(accumulator, product, difference);
                }
            }
            let total = extract_h(accumulator);
            if sub(total, best) < 0 {
                best = total;
                best_survivor = survivor;
                best_entry = entry;
            }
        }
    }
    (best_entry, best_survivor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plausible background spectrum: ordered line spectral pairs spanning the band.
    const LSP: [i16; ORDER] = [
        30_864, 27_346, 22_887, 16_217, 2516, -5842, -13_459, -20_234, -25_756, -29_622,
    ];

    #[test]
    fn the_indices_fit_the_nine_bits_the_descriptor_allots_them() {
        let mut predictor = Predictor::new();
        let (indices, _) = quantise(&mut predictor, &LSP);
        assert!(indices.mode < 2, "one bit");
        assert!(indices.stage1 < 32, "five bits");
        assert!(indices.stage2 < 16, "four bits");
    }

    #[test]
    fn what_the_encoder_keeps_is_what_the_decoder_rebuilds() {
        // Both sides run the same predictor over the same history, so the encoder's own copy of the
        // background must be the one the decoder reconstructs — and the predictor is a moving
        // average, so a disagreement here does not stay local, it compounds over the silence.
        let mut encoder_predictor = Predictor::new();
        let mut decoder_predictor = Predictor::new();
        for step in 0..8 {
            // Drift the spectrum a little each descriptor, as a real background does.
            let lsp: [i16; ORDER] =
                std::array::from_fn(|i| LSP[i].saturating_sub((step * 40 * (i as i16 + 1)) / 4));
            let (indices, kept) = quantise(&mut encoder_predictor, &lsp);
            let rebuilt = dequantise(&mut decoder_predictor, indices);
            assert_eq!(kept, rebuilt, "step {step}");
        }
    }

    #[test]
    fn the_quantised_pairs_stay_ordered() {
        // The pairs become a synthesis filter both ends run. Out of order they are not a stable
        // filter at all, which on comfort noise means a howl rather than a hiss.
        let mut predictor = Predictor::new();
        for step in 0..8 {
            let lsp: [i16; ORDER] =
                std::array::from_fn(|i| LSP[i].saturating_sub(step * 300 * (i as i16 % 3)));
            let (_, kept) = quantise(&mut predictor, &lsp);
            assert!(
                kept.windows(2).all(|pair| pair[0] > pair[1]),
                "step {step}: {kept:?}"
            );
        }
    }

    #[test]
    fn a_degenerate_spectrum_is_spaced_rather_than_rejected() {
        // Every line frequency identical is not a spectrum, but it is something a silent leg can
        // produce. The spacing step has to pull them apart rather than hand the filter a repeated
        // root.
        let mut predictor = Predictor::new();
        let (_, kept) = quantise(&mut predictor, &[0_i16; ORDER]);
        assert!(kept.windows(2).all(|pair| pair[0] > pair[1]), "{kept:?}");
    }
}
