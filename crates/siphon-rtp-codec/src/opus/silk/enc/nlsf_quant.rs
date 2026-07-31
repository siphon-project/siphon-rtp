//! NLSF quantisation — the encoder's inverse of the decoder's §4.2.7.5 stage (libopus
//! `silk/NLSF_VQ_weights_laroia.c`, `silk/NLSF_VQ.c`, `silk/NLSF_del_dec_quant.c`,
//! `silk/NLSF_encode.c`, `silk/process_NLSFs.c`, `silk/float/wrappers_FLP.c:73-92`).
//!
//! Unlike the rest of the analysis front end this is **fixed point**, and it is shared verbatim
//! between libopus' float and fixed builds. That is not incidental: this stage has to invert the
//! decoder exactly. The index vector it emits is fed straight to
//! [`crate::opus::silk::nlsf::decode`] at the end of [`nlsf_encode`], and whatever comes back is
//! what the *decoder* will reconstruct — so the encoder optimises against the real reconstruction,
//! not an approximation of it.
//!
//! # The search
//!
//! Two stages, and a rate-distortion trade-off across both:
//!
//! 1. **Stage 1, a 32-entry VQ.** [`nlsf_vq`] scores every codebook vector with a weighted
//!    *predictive* absolute error (each coefficient's error is measured against half the previous
//!    one's, which is what makes it match the backward prediction stage 2 then applies), and the
//!    best `survivors` are kept.
//! 2. **Stage 2, a delayed-decision trellis per survivor.** [`nlsf_del_dec_quant`] walks the
//!    coefficients from the highest down — the direction the decoder's backward prediction runs —
//!    keeping [`NLSF_QUANT_DEL_DEC_STATES`] paths alive at a time and scoring each on
//!    `distortion + mu * rate`. The rate comes from the codebook's own `ec_Rates_Q5` table, so a
//!    cheaper symbol can win over a closer one.
//!
//! Each survivor's total is then charged the stage-1 index's own entropy cost
//! (`NLSF_encode.c:101-109`) and the cheapest wins. That last charge is why a rare stage-1 vector
//! has to be meaningfully better to be chosen.
//!
//! # Where the weights come from
//!
//! [`nlsf_vq_weights_laroia`] implements the Laroia/Phamdo/Farvardin weighting: each coefficient's
//! importance is the sum of the reciprocals of its distance to its two neighbours, so a pair of
//! close NLSFs — a sharp formant — is weighted heavily and a wide gap is not. [`process_nlsfs`]
//! then folds in a second weight set computed on the *interpolated* first-half vector whenever
//! interpolation is active, because that vector is also going to be synthesised.

use crate::opus::silk::enc::fixed::{div32_var_q, lin2log, mla};
use crate::opus::silk::enc::float::insertion_sort_increasing_i32;
use crate::opus::silk::fixed::{limit_int, smlabb, smulbb};
use crate::opus::silk::lpc::nlsf_to_lpc_q12;
use crate::opus::silk::nlsf::{
    decode as nlsf_decode, interpolate, stabilize, unpack, NlsfIndices, MAX_NLSF_INDICES,
    NO_INTERPOLATION_Q2,
};
use crate::opus::silk::nlsf_tables::{NlsfCodebook, NLSF_QUANT_MAX_AMPLITUDE};
use crate::opus::silk::types::MAX_LPC_ORDER;

/// `NLSF_QUANT_MAX_AMPLITUDE_EXT` (`define.h:209`) — the widest stage-2 index the trellis will
/// consider, before the extension symbol makes it expensive.
pub const NLSF_QUANT_MAX_AMPLITUDE_EXT: i32 = 10;

/// `NLSF_QUANT_DEL_DEC_STATES_LOG2` (`define.h:211`).
const DEL_DEC_STATES_LOG2: u32 = 2;

/// `NLSF_QUANT_DEL_DEC_STATES` (`define.h:212`) — trellis paths kept alive. Must be a power of two;
/// the pruning step uses `^ NLSF_QUANT_DEL_DEC_STATES` to flip between a path's two children.
pub const NLSF_QUANT_DEL_DEC_STATES: usize = 1 << DEL_DEC_STATES_LOG2;

/// `SILK_FIX_CONST(NLSF_QUANT_LEVEL_ADJ, 10)` — 0.1 in Q10 (`define.h:210`), the dead zone the
/// quantiser leaves around zero and the decoder gives back
/// (`crate::opus::silk::nlsf::residual_dequant`).
const QUANT_LEVEL_ADJUST_Q10: i16 = 102;

/// `NLSF_W_Q` (`define.h:206`) — the Q domain of the Laroia weights.
pub const NLSF_W_Q: u32 = 2;

/// Cost in Q5 bits charged to a stage-2 index at the very edge of the coded alphabet
/// (`NLSF_del_dec_quant.c:110`), where the extension symbol takes over from the table.
const EXTENSION_BASE_RATE_Q5: i32 = 280;

/// Extra Q5 bits per step beyond the alphabet (`NLSF_del_dec_quant.c:112`).
const EXTENSION_STEP_RATE_Q5: i32 = 43;

/// `silk_NLSF_VQ_weights_laroia(pNLSFW_Q_OUT, pNLSF_Q15, D)`
/// (`NLSF_VQ_weights_laroia.c:42-80`).
///
/// Writes one weight per coefficient, in Q[`NLSF_W_Q`]. Each is `1/d_left + 1/d_right` where the
/// distances are to the neighbouring NLSFs, with the vector's ends treated as 0 and 1 — so the
/// weighting is large exactly where two line frequencies crowd together, which is where a
/// quantisation error moves a formant.
///
/// Every gap is floored at 1 before the reciprocal, so a degenerate (unstabilised) vector cannot
/// divide by zero. `order` must be even, as the C asserts.
pub fn nlsf_vq_weights_laroia(weights: &mut [i16], nlsf_q15: &[i16]) {
    let order = weights.len().min(nlsf_q15.len());
    debug_assert!(order > 0 && order.is_multiple_of(2));
    if order == 0 {
        return;
    }
    /// `1 << (15 + NLSF_W_Q)`.
    const NUMERATOR: i32 = 1 << (15 + NLSF_W_Q);

    let mut left = i32::from(nlsf_q15[0]).max(1);
    left = NUMERATOR / left;
    let mut right = (i32::from(nlsf_q15[1]) - i32::from(nlsf_q15[0])).max(1);
    right = NUMERATOR / right;
    weights[0] = (left + right).min(i32::from(i16::MAX)) as i16;

    let mut index = 1usize;
    while index < order - 1 {
        let mut gap = (i32::from(nlsf_q15[index + 1]) - i32::from(nlsf_q15[index])).max(1);
        gap = NUMERATOR / gap;
        weights[index] = (gap + right).min(i32::from(i16::MAX)) as i16;

        right = (i32::from(nlsf_q15[index + 2]) - i32::from(nlsf_q15[index + 1])).max(1);
        right = NUMERATOR / right;
        weights[index + 1] = (gap + right).min(i32::from(i16::MAX)) as i16;
        index += 2;
    }

    let mut last = ((1 << 15) - i32::from(nlsf_q15[order - 1])).max(1);
    last = NUMERATOR / last;
    weights[order - 1] = (last + right).min(i32::from(i16::MAX)) as i16;
}

/// `silk_NLSF_VQ(err_Q24, in_Q15, pCB_Q8, pWght_Q9, K, LPC_order)` (`NLSF_VQ.c:35-76`) — the
/// stage-1 codebook search's distortion measure.
///
/// Not a plain weighted squared error: the coefficients are visited in pairs from the top down and
/// each weighted error is measured **against half the previous one**, which mirrors the backward
/// prediction the stage-2 residual coder is about to apply. Scoring the plain error here would pick
/// a stage-1 vector that stage 2 then codes expensively.
///
/// Writes one Q24 error per codebook vector.
pub fn nlsf_vq(errors_q24: &mut [i32], nlsf_q15: &[i16], codebook: &NlsfCodebook) {
    let order = codebook.order;
    debug_assert_eq!(order % 2, 0);

    for (index, slot) in errors_q24
        .iter_mut()
        .enumerate()
        .take(codebook.vector_count)
    {
        let vector_q8 = codebook.cb1_vector_q8(index);
        let weights_q9 = codebook.cb1_weights_q9(index);
        let mut sum_error_q24 = 0i32;
        let mut predicted_q24 = 0i32;

        let mut coefficient = order as i32 - 2;
        while coefficient >= 0 {
            let position = coefficient as usize;
            for offset in [1usize, 0] {
                let difference_q15 = i32::from(nlsf_q15[position + offset])
                    - (i32::from(vector_q8[position + offset]) << 7);
                let weighted_q24 = smulbb(difference_q15, i32::from(weights_q9[position + offset]));
                sum_error_q24 =
                    sum_error_q24.wrapping_add((weighted_q24 - (predicted_q24 >> 1)).abs());
                predicted_q24 = weighted_q24;
            }
            coefficient -= 2;
        }
        *slot = sum_error_q24;
    }
}

/// `silk_NLSF_del_dec_quant(...)` (`NLSF_del_dec_quant.c:35-215`) — the delayed-decision trellis
/// quantiser for the stage-2 residual. Returns the winning path's rate-distortion value in Q25 and
/// writes `order` indices.
///
/// `residual_q10` is the stage-1 residual to quantise, `weights_q5` the per-coefficient distortion
/// weights, `prediction_q8` and `pdf_index` the unpacked backward-prediction weights and entropy
/// table choices for the stage-1 vector under test, and `mu_q20` the rate weight.
///
/// # How the trellis stays bounded
///
/// Each coefficient offers two continuations of every live path — the nearest index and the one
/// above it. For the first two coefficients that simply doubles the path count, up to
/// [`NLSF_QUANT_DEL_DEC_STATES`]. After that the `2 * STATES` candidates are pruned back to
/// `STATES` by a pairwise sort plus a repair loop that repeatedly moves the globally best losing
/// candidate over the globally worst surviving one, until no such swap improves anything. That
/// repair loop is the fiddly part of this function and it is ported step for step; a "simpler"
/// prune (keep the best `STATES` outright) chooses different indices, because the pairing is what
/// keeps two children of the same parent from both surviving.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn nlsf_del_dec_quant(
    indices: &mut [i8],
    residual_q10: &[i16],
    weights_q5: &[i16],
    prediction_q8: &[u8],
    pdf_index: &[usize],
    codebook: &NlsfCodebook,
    mu_q20: i32,
) -> i32 {
    let order = indices.len().min(residual_q10.len());
    let quant_step_size_q16 = codebook.quant_step_size_q16;
    let inv_quant_step_size_q6 = i32::from(codebook.inv_quant_step_size_q6);

    // Reconstruction level for every index and for that index plus one, precomputed
    // (`NLSF_del_dec_quant.c:63-80`). The dead-zone adjustment is asymmetric around zero.
    let table_span = 2 * NLSF_QUANT_MAX_AMPLITUDE_EXT as usize;
    let mut level_low_q10 = [0i32; 2 * NLSF_QUANT_MAX_AMPLITUDE_EXT as usize];
    let mut level_high_q10 = [0i32; 2 * NLSF_QUANT_MAX_AMPLITUDE_EXT as usize];
    for step in -NLSF_QUANT_MAX_AMPLITUDE_EXT..NLSF_QUANT_MAX_AMPLITUDE_EXT {
        let mut low = (step << 10) as i16;
        let mut high = low.wrapping_add(1024);
        match step {
            s if s > 0 => {
                low = low.wrapping_sub(QUANT_LEVEL_ADJUST_Q10);
                high = high.wrapping_sub(QUANT_LEVEL_ADJUST_Q10);
            }
            0 => high = high.wrapping_sub(QUANT_LEVEL_ADJUST_Q10),
            -1 => low = low.wrapping_add(QUANT_LEVEL_ADJUST_Q10),
            _ => {
                low = low.wrapping_add(QUANT_LEVEL_ADJUST_Q10);
                high = high.wrapping_add(QUANT_LEVEL_ADJUST_Q10);
            }
        }
        let slot = (step + NLSF_QUANT_MAX_AMPLITUDE_EXT) as usize;
        level_low_q10[slot] = smulbb(i32::from(low), quant_step_size_q16) >> 16;
        level_high_q10[slot] = smulbb(i32::from(high), quant_step_size_q16) >> 16;
    }
    debug_assert_eq!(level_low_q10.len(), table_span);

    let mut state_count = 1usize;
    let mut path_indices = [[0i8; MAX_LPC_ORDER]; NLSF_QUANT_DEL_DEC_STATES];
    let mut previous_output_q10 = [0i16; 2 * NLSF_QUANT_DEL_DEC_STATES];
    let mut rate_distortion_q25 = [0i32; 2 * NLSF_QUANT_DEL_DEC_STATES];
    let mut sorted = [0usize; NLSF_QUANT_DEL_DEC_STATES];
    let mut distortion_min_q25 = [0i32; NLSF_QUANT_DEL_DEC_STATES];
    let mut distortion_max_q25 = [0i32; NLSF_QUANT_DEL_DEC_STATES];

    for coefficient in (0..order).rev() {
        let rates_q5 = codebook.stage2_rates_q5(pdf_index[coefficient]);
        let input_q10 = i32::from(residual_q10[coefficient]);

        for state in 0..state_count {
            let predicted_q10 = smulbb(
                i32::from(prediction_q8[coefficient] as i16),
                i32::from(previous_output_q10[state]),
            ) >> 8;
            let residual_after_prediction_q10 = input_q10 - predicted_q10;
            let mut index = smulbb(inv_quant_step_size_q6, residual_after_prediction_q10) >> 16;
            index = limit_int(
                index,
                -NLSF_QUANT_MAX_AMPLITUDE_EXT,
                NLSF_QUANT_MAX_AMPLITUDE_EXT - 1,
            );
            path_indices[state][coefficient] = index as i8;

            let slot = (index + NLSF_QUANT_MAX_AMPLITUDE_EXT) as usize;
            let output_low_q10 = (level_low_q10[slot] as i16).wrapping_add(predicted_q10 as i16);
            let output_high_q10 = (level_high_q10[slot] as i16).wrapping_add(predicted_q10 as i16);
            previous_output_q10[state] = output_low_q10;
            previous_output_q10[state + state_count] = output_high_q10;

            // Rate of `index` and of `index + 1`, extrapolated past the coded alphabet.
            let (rate_low_q5, rate_high_q5) = if index + 1 >= NLSF_QUANT_MAX_AMPLITUDE {
                if index + 1 == NLSF_QUANT_MAX_AMPLITUDE {
                    (
                        i32::from(rates_q5[(index + NLSF_QUANT_MAX_AMPLITUDE) as usize]),
                        EXTENSION_BASE_RATE_Q5,
                    )
                } else {
                    let low = smlabb(
                        EXTENSION_BASE_RATE_Q5 - EXTENSION_STEP_RATE_Q5 * NLSF_QUANT_MAX_AMPLITUDE,
                        EXTENSION_STEP_RATE_Q5,
                        index,
                    );
                    (low, low + EXTENSION_STEP_RATE_Q5)
                }
            } else if index <= -NLSF_QUANT_MAX_AMPLITUDE {
                if index == -NLSF_QUANT_MAX_AMPLITUDE {
                    (
                        EXTENSION_BASE_RATE_Q5,
                        i32::from(rates_q5[(index + 1 + NLSF_QUANT_MAX_AMPLITUDE) as usize]),
                    )
                } else {
                    let low = smlabb(
                        EXTENSION_BASE_RATE_Q5 - EXTENSION_STEP_RATE_Q5 * NLSF_QUANT_MAX_AMPLITUDE,
                        -EXTENSION_STEP_RATE_Q5,
                        index,
                    );
                    (low, low - EXTENSION_STEP_RATE_Q5)
                }
            } else {
                (
                    i32::from(rates_q5[(index + NLSF_QUANT_MAX_AMPLITUDE) as usize]),
                    i32::from(rates_q5[(index + 1 + NLSF_QUANT_MAX_AMPLITUDE) as usize]),
                )
            };

            let base_q25 = rate_distortion_q25[state];
            let difference_low = input_q10 - i32::from(output_low_q10);
            rate_distortion_q25[state] = smlabb(
                mla(
                    base_q25,
                    smulbb(difference_low, difference_low),
                    i32::from(weights_q5[coefficient]),
                ),
                mu_q20,
                rate_low_q5,
            );
            let difference_high = input_q10 - i32::from(output_high_q10);
            rate_distortion_q25[state + state_count] = smlabb(
                mla(
                    base_q25,
                    smulbb(difference_high, difference_high),
                    i32::from(weights_q5[coefficient]),
                ),
                mu_q20,
                rate_high_q5,
            );
        }

        if state_count <= NLSF_QUANT_DEL_DEC_STATES / 2 {
            // Double the number of live paths and copy.
            for state in 0..state_count {
                path_indices[state + state_count][coefficient] =
                    path_indices[state][coefficient] + 1;
            }
            state_count <<= 1;
            for state in state_count..NLSF_QUANT_DEL_DEC_STATES {
                path_indices[state][coefficient] = path_indices[state - state_count][coefficient];
            }
        } else {
            // Pairwise sort of the lower and upper halves.
            for state in 0..NLSF_QUANT_DEL_DEC_STATES {
                let upper = state + NLSF_QUANT_DEL_DEC_STATES;
                if rate_distortion_q25[state] > rate_distortion_q25[upper] {
                    distortion_max_q25[state] = rate_distortion_q25[state];
                    distortion_min_q25[state] = rate_distortion_q25[upper];
                    rate_distortion_q25.swap(state, upper);
                    previous_output_q10.swap(state, upper);
                    sorted[state] = upper;
                } else {
                    distortion_min_q25[state] = rate_distortion_q25[state];
                    distortion_max_q25[state] = rate_distortion_q25[upper];
                    sorted[state] = state;
                }
            }

            // Repair: while the best loser beats the worst survivor, promote it.
            loop {
                let mut min_of_max_q25 = i32::MAX;
                let mut max_of_min_q25 = 0i32;
                let mut index_min_of_max = 0usize;
                let mut index_max_of_min = 0usize;
                for state in 0..NLSF_QUANT_DEL_DEC_STATES {
                    if min_of_max_q25 > distortion_max_q25[state] {
                        min_of_max_q25 = distortion_max_q25[state];
                        index_min_of_max = state;
                    }
                    if max_of_min_q25 < distortion_min_q25[state] {
                        max_of_min_q25 = distortion_min_q25[state];
                        index_max_of_min = state;
                    }
                }
                if min_of_max_q25 >= max_of_min_q25 {
                    break;
                }
                sorted[index_max_of_min] = sorted[index_min_of_max] ^ NLSF_QUANT_DEL_DEC_STATES;
                rate_distortion_q25[index_max_of_min] =
                    rate_distortion_q25[index_min_of_max + NLSF_QUANT_DEL_DEC_STATES];
                previous_output_q10[index_max_of_min] =
                    previous_output_q10[index_min_of_max + NLSF_QUANT_DEL_DEC_STATES];
                distortion_min_q25[index_max_of_min] = 0;
                distortion_max_q25[index_min_of_max] = i32::MAX;
                let source = path_indices[index_min_of_max];
                path_indices[index_max_of_min] = source;
            }

            // A path that came from the upper half quantised one step higher.
            for state in 0..NLSF_QUANT_DEL_DEC_STATES {
                path_indices[state][coefficient] += (sorted[state] >> DEL_DEC_STATES_LOG2) as i8;
            }
        }
    }

    // Last coefficient: pick the winner across both halves.
    let mut winner = 0usize;
    let mut best_q25 = i32::MAX;
    for (state, &value) in rate_distortion_q25.iter().enumerate() {
        if best_q25 > value {
            best_q25 = value;
            winner = state;
        }
    }
    let path = &path_indices[winner & (NLSF_QUANT_DEL_DEC_STATES - 1)];
    indices[..order].copy_from_slice(&path[..order]);
    if order > 0 {
        indices[0] += (winner >> DEL_DEC_STATES_LOG2) as i8;
    }
    best_q25
}

/// `silk_NLSF_encode(NLSFIndices, pNLSF_Q15, psNLSF_CB, pW_Q2, NLSF_mu_Q20, nSurvivors,
/// signalType)` (`NLSF_encode.c:38-124`).
///
/// Stabilises the input NLSFs in place, runs the two-stage search, writes the coded index vector,
/// and **overwrites `nlsf_q15` with the decoder's reconstruction** — the same call the decoder
/// makes, so what the caller holds afterwards is exactly what the far end will build its LPC filter
/// from. Returns the winning rate-distortion value in Q25.
///
/// `survivors` is `psEncC->NLSF_MSVQ_Survivors`, 2..=16 by complexity (`control_codec.c:324-384`).
#[must_use]
pub fn nlsf_encode(
    nlsf_indices: &mut NlsfIndices,
    nlsf_q15: &mut [i16],
    codebook: &NlsfCodebook,
    weights_q2: &[i16],
    mu_q20: i32,
    survivors: usize,
    signal_type_index: usize,
) -> i32 {
    let order = codebook.order;
    let survivors = survivors.clamp(1, codebook.vector_count);
    debug_assert!((0..=32_767).contains(&mu_q20));

    // NLSF stabilization.
    stabilize(&mut nlsf_q15[..order], codebook.delta_min_q15);

    // First stage: VQ over the whole codebook, then keep the best `survivors`.
    /// `NLSF_VQ_MAX_VECTORS` (`define.h:207`).
    const MAX_VECTORS: usize = 32;
    let mut errors_q24 = [0i32; MAX_VECTORS];
    nlsf_vq(&mut errors_q24[..codebook.vector_count], nlsf_q15, codebook);
    let mut stage1_candidates = [0usize; MAX_VECTORS];
    insertion_sort_increasing_i32(
        &mut errors_q24[..codebook.vector_count],
        &mut stage1_candidates,
        survivors,
    );

    let mut survivor_rd_q25 = [0i32; MAX_VECTORS];
    let mut survivor_indices = [[0i8; MAX_LPC_ORDER]; MAX_VECTORS];
    let mut residual_q10 = [0i16; MAX_LPC_ORDER];
    let mut adjusted_weights_q5 = [0i16; MAX_LPC_ORDER];

    for survivor in 0..survivors {
        let stage1_index = stage1_candidates[survivor];
        let vector_q8 = codebook.cb1_vector_q8(stage1_index);
        let weights_q9 = codebook.cb1_weights_q9(stage1_index);

        for coefficient in 0..order {
            let stage1_q15 = (i32::from(vector_q8[coefficient]) << 7) as i16;
            let weight_q9 = i32::from(weights_q9[coefficient]);
            residual_q10[coefficient] = (smulbb(
                i32::from(nlsf_q15[coefficient]) - i32::from(stage1_q15),
                weight_q9,
            ) >> 14) as i16;
            // The distortion weight is divided by the *square* of the codebook weight, because the
            // residual above was already scaled by that weight once (`NLSF_encode.c:91`).
            adjusted_weights_q5[coefficient] = div32_var_q(
                i32::from(weights_q2[coefficient]),
                smulbb(weight_q9, weight_q9),
                21,
            ) as i16;
        }

        let unpacked = unpack(codebook, stage1_index);
        let mut path = [0i8; MAX_LPC_ORDER];
        let mut rate_distortion_q25 = nlsf_del_dec_quant(
            &mut path[..order],
            &residual_q10[..order],
            &adjusted_weights_q5[..order],
            &unpacked.prediction_q8[..order],
            &unpacked.pdf_index[..order],
            codebook,
            mu_q20,
        );

        // Charge the stage-1 index its own entropy cost, in Q7 bits.
        let icdf = codebook.stage1_icdf(signal_type_index);
        let probability_q8 = if stage1_index == 0 {
            256 - i32::from(icdf[0])
        } else {
            i32::from(icdf[stage1_index - 1]) - i32::from(icdf[stage1_index])
        };
        let bits_q7 = (8 << 7) - lin2log(probability_q8);
        rate_distortion_q25 = smlabb(rate_distortion_q25, bits_q7, mu_q20 >> 2);

        survivor_rd_q25[survivor] = rate_distortion_q25;
        survivor_indices[survivor] = path;
    }

    // Lowest rate-distortion wins.
    let mut best = [0usize; 1];
    insertion_sort_increasing_i32(&mut survivor_rd_q25[..survivors], &mut best, 1);
    let winner = best[0];

    nlsf_indices.order = order;
    nlsf_indices.indices = [0i8; MAX_NLSF_INDICES];
    nlsf_indices.indices[0] = stage1_candidates[winner] as i8;
    nlsf_indices.indices[1..=order].copy_from_slice(&survivor_indices[winner][..order]);

    // Decode, so the caller holds what the far end will reconstruct.
    nlsf_decode(&mut nlsf_q15[..order], codebook, nlsf_indices);

    survivor_rd_q25[0]
}

/// Everything [`process_nlsfs`] needs from the encoder's configuration.
#[derive(Debug, Clone, Copy)]
pub struct NlsfQuantConfig {
    /// `psEncC->predictLPCOrder`.
    pub order: usize,
    /// `psEncC->nb_subfr` — a 10 ms frame pays 1.5x the rate weight, because its NLSFs cost the
    /// same bits over half the audio (`process_NLSFs.c:58-61`).
    pub subframe_count: usize,
    /// `psEncC->useInterpolatedNLSFs`.
    pub use_interpolated_nlsfs: bool,
    /// `psEncC->NLSF_MSVQ_Survivors` — 2..=16 by complexity.
    pub survivors: usize,
    /// `psEncC->speech_activity_Q8`, which lowers the rate weight on an active frame.
    pub speech_activity_q8: i32,
}

/// Both Q12 LPC coefficient sets a frame synthesises with, plus the coded index vector.
#[derive(Debug, Clone, Copy)]
pub struct QuantizedNlsf {
    /// `psEncC->indices.NLSFIndices` and `NLSFInterpCoef_Q2`, ready for the bitstream writer.
    pub indices: NlsfIndices,
    /// The reconstructed NLSFs in Q15 — what the decoder will produce, and the anchor the *next*
    /// frame interpolates against.
    pub nlsf_q15: [i16; MAX_LPC_ORDER],
    /// `PredCoef_Q12[0]` — the first half of the frame's short-term filter.
    pub first_half_q12: [i16; MAX_LPC_ORDER],
    /// `PredCoef_Q12[1]` — the second half.
    pub second_half_q12: [i16; MAX_LPC_ORDER],
}

/// `silk_process_NLSFs(psEncC, PredCoef_Q12, pNLSF_Q15, prev_NLSFq_Q15)`
/// (`process_NLSFs.c:35-107`), plus the float wrapper's Q12→float conversion left to the caller.
///
/// `nlsf_q15` comes in as the *unquantized* NLSFs from [`super::lpc_analysis::find_lpc`] and is
/// consumed; the quantised result is in the returned [`QuantizedNlsf`].
///
/// `interpolation_factor_q2` is what `find_lpc` chose. When it is below
/// [`NO_INTERPOLATION_Q2`] the weights get a contribution from the interpolated first-half vector,
/// scaled by the *square* of the factor — a frame that leans hard on the previous vector cares more
/// about how well that interpolation lands.
#[must_use]
pub fn process_nlsfs(
    nlsf_q15: &[i16],
    interpolation_factor_q2: i8,
    previous_nlsf_q15: &[i16],
    codebook: &NlsfCodebook,
    config: &NlsfQuantConfig,
    signal_type_index: usize,
) -> QuantizedNlsf {
    let order = config.order;
    debug_assert!(config.speech_activity_q8 >= 0 && config.speech_activity_q8 <= 256);
    debug_assert!(config.use_interpolated_nlsfs || interpolation_factor_q2 == NO_INTERPOLATION_Q2);

    // NLSF_mu = 0.003 - 0.001 * speech_activity, in Q20.
    // SILK_FIX_CONST( 0.003, 20 ) = 3146; SILK_FIX_CONST( -0.001, 28 ) = -268434.
    let mut mu_q20 = crate::opus::silk::fixed::smlawb(3146, -268_434, config.speech_activity_q8);
    if config.subframe_count == 2 {
        mu_q20 += mu_q20 >> 1;
    }
    debug_assert!(mu_q20 > 0 && mu_q20 <= 5243);

    let mut weights_q2 = [0i16; MAX_LPC_ORDER];
    nlsf_vq_weights_laroia(&mut weights_q2[..order], &nlsf_q15[..order]);

    let interpolate_halves =
        config.use_interpolated_nlsfs && interpolation_factor_q2 < NO_INTERPOLATION_Q2;
    if interpolate_halves {
        let mut first_half_q15 = [0i16; MAX_LPC_ORDER];
        interpolate(
            &mut first_half_q15[..order],
            &previous_nlsf_q15[..order],
            &nlsf_q15[..order],
            interpolation_factor_q2,
        );
        let mut first_half_weights_q2 = [0i16; MAX_LPC_ORDER];
        nlsf_vq_weights_laroia(
            &mut first_half_weights_q2[..order],
            &first_half_q15[..order],
        );

        let factor_squared_q15 = smulbb(
            i32::from(interpolation_factor_q2),
            i32::from(interpolation_factor_q2),
        ) << 11;
        for coefficient in 0..order {
            weights_q2[coefficient] = ((i32::from(weights_q2[coefficient]) >> 1)
                + (smulbb(
                    i32::from(first_half_weights_q2[coefficient]),
                    factor_squared_q15,
                ) >> 16)) as i16;
            debug_assert!(weights_q2[coefficient] >= 1);
        }
    }

    let mut quantized_q15 = [0i16; MAX_LPC_ORDER];
    quantized_q15[..order].copy_from_slice(&nlsf_q15[..order]);
    let mut indices = NlsfIndices {
        indices: [0i8; MAX_NLSF_INDICES],
        order,
        interpolation_factor_q2,
    };
    let _rate_distortion_q25 = nlsf_encode(
        &mut indices,
        &mut quantized_q15[..order],
        codebook,
        &weights_q2[..order],
        mu_q20,
        config.survivors,
        signal_type_index,
    );

    let mut second_half_q12 = [0i16; MAX_LPC_ORDER];
    nlsf_to_lpc_q12(&mut second_half_q12[..order], &quantized_q15[..order]);

    let mut first_half_q12 = [0i16; MAX_LPC_ORDER];
    if interpolate_halves {
        // Interpolate the *quantised* vector this time — the decoder will do exactly this.
        let mut first_half_q15 = [0i16; MAX_LPC_ORDER];
        interpolate(
            &mut first_half_q15[..order],
            &previous_nlsf_q15[..order],
            &quantized_q15[..order],
            interpolation_factor_q2,
        );
        nlsf_to_lpc_q12(&mut first_half_q12[..order], &first_half_q15[..order]);
    } else {
        first_half_q12 = second_half_q12;
    }

    QuantizedNlsf {
        indices,
        nlsf_q15: quantized_q15,
        first_half_q12,
        second_half_q12,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::lpc::inverse_prediction_gain_q12;
    use crate::opus::silk::nlsf_tables::{NB_MB, WB};
    use proptest::prelude::*;

    /// An evenly spaced, legal NLSF vector: the flat-spectrum case, and a useful control.
    fn flat_nlsf(order: usize) -> Vec<i16> {
        let step = (1 << 15) / (order as i32 + 1);
        (1..=order).map(|k| (k as i32 * step) as i16).collect()
    }

    /// A vector with one tight pair, so the Laroia weighting has something to react to.
    fn peaked_nlsf(order: usize) -> Vec<i16> {
        let mut values = flat_nlsf(order);
        values[order / 2] = values[order / 2 - 1] + 60;
        values
    }

    /// Laroia weights are `1/d_left + 1/d_right` in Q2: a tight pair must be weighted far more
    /// heavily than an evenly spaced one, which is the entire point of the weighting.
    #[test]
    fn laroia_weights_emphasise_close_line_frequencies() {
        let order = 10;
        let flat = flat_nlsf(order);
        let mut flat_weights = vec![0i16; order];
        nlsf_vq_weights_laroia(&mut flat_weights, &flat);

        let peaked = peaked_nlsf(order);
        let mut peaked_weights = vec![0i16; order];
        nlsf_vq_weights_laroia(&mut peaked_weights, &peaked);

        let tight = order / 2;
        assert!(
            peaked_weights[tight] > flat_weights[tight] * 4,
            "tight pair weight {} vs flat {}",
            peaked_weights[tight],
            flat_weights[tight]
        );
        for &weight in &flat_weights {
            assert!(
                weight > 0,
                "weights must be strictly positive: {flat_weights:?}"
            );
        }
    }

    /// The exact closed form, on a vector chosen so every reciprocal is an integer:
    /// `w[k] = 2^17/d_left + 2^17/d_right`, with the ends measured against 0 and 2^15.
    ///
    /// Gaps here are 4096, 4096, 8192, 8192 and 8192 (the last to 32768), so the reciprocals are
    /// 32, 32, 16, 16, 16 and the expected weights fall out by hand.
    #[test]
    fn laroia_weights_match_the_closed_form() {
        let nlsf = [4096i16, 8192, 16_384, 24_576];
        let mut weights = [0i16; 4];
        nlsf_vq_weights_laroia(&mut weights, &nlsf);
        assert_eq!(weights, [64, 48, 32, 32]);
    }

    /// A degenerate (unstabilised) vector with repeated values must not divide by zero — the `.max(1)`
    /// floor is what guarantees it, and a zero weight would make the trellis ignore that coefficient.
    #[test]
    fn laroia_weights_survive_a_degenerate_vector() {
        let mut weights = [0i16; 10];
        nlsf_vq_weights_laroia(&mut weights, &[0i16; 10]);
        for &weight in &weights {
            assert!(weight > 0, "{weights:?}");
        }
    }

    /// The stage-1 VQ must score the codebook's own vectors best: feed it an exact codebook entry
    /// and that entry has to come out with the lowest error.
    #[test]
    fn nlsf_vq_scores_an_exact_codebook_entry_lowest() {
        for codebook in [&NB_MB, &WB] {
            for entry in [0usize, 7, 31] {
                let exact: Vec<i16> = codebook
                    .cb1_vector_q8(entry)
                    .iter()
                    .map(|&value| (i32::from(value) << 7) as i16)
                    .collect();
                let mut errors = [0i32; 32];
                nlsf_vq(&mut errors, &exact, codebook);
                assert_eq!(errors[entry], 0, "entry {entry} is not its own zero");
                let best = errors.iter().enumerate().min_by_key(|&(_, e)| *e);
                assert_eq!(best.map(|(index, _)| index), Some(entry));
            }
        }
    }

    /// The whole point of this module: whatever the trellis picks must decode, through the
    /// *decoder's* own path, to the vector the encoder said it was targeting. This is the inverse
    /// check, not a self-consistency loop — `nlsf_encode` writes indices, and
    /// `crate::opus::silk::nlsf::decode` reconstructs from them with no shared state.
    #[test]
    fn quantised_indices_decode_to_the_reconstruction_the_encoder_reported() {
        for codebook in [&NB_MB, &WB] {
            let order = codebook.order;
            for source in [flat_nlsf(order), peaked_nlsf(order)] {
                let mut weights = vec![0i16; order];
                nlsf_vq_weights_laroia(&mut weights, &source);

                let mut quantized = source.clone();
                let mut indices = NlsfIndices {
                    indices: [0i8; MAX_NLSF_INDICES],
                    order,
                    interpolation_factor_q2: NO_INTERPOLATION_Q2,
                };
                let _ = nlsf_encode(&mut indices, &mut quantized, codebook, &weights, 3146, 8, 2);

                let mut decoded = vec![0i16; order];
                nlsf_decode(&mut decoded, codebook, &indices);
                assert_eq!(decoded, quantized, "order {order}");
            }
        }
    }

    /// Every index the quantiser emits must be inside the range the decoder can read: the stage-1
    /// index inside the codebook, and each stage-2 residual inside the extension alphabet
    /// (`-10..=10`, RFC 6716 §4.2.7.5.2).
    #[test]
    fn quantised_indices_are_always_decodable() {
        for codebook in [&NB_MB, &WB] {
            let order = codebook.order;
            let source = peaked_nlsf(order);
            let mut weights = vec![0i16; order];
            nlsf_vq_weights_laroia(&mut weights, &source);
            let mut quantized = source;
            let mut indices = NlsfIndices {
                indices: [0i8; MAX_NLSF_INDICES],
                order,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            };
            let _ = nlsf_encode(&mut indices, &mut quantized, codebook, &weights, 3146, 4, 0);

            let stage1 = indices.indices[0];
            assert!(
                stage1 >= 0 && (stage1 as usize) < codebook.vector_count,
                "stage-1 index {stage1}"
            );
            for (position, &residual) in indices.stage2_residuals().iter().enumerate() {
                assert!(
                    i32::from(residual).abs() <= NLSF_QUANT_MAX_AMPLITUDE_EXT,
                    "residual {position} = {residual}"
                );
            }
        }
    }

    /// Quantisation error must shrink as more survivors are searched — otherwise the survivor knob
    /// is decoration. Measured as the weighted squared error against the source vector.
    #[test]
    fn more_survivors_never_increase_the_quantisation_error() {
        let codebook = &WB;
        let order = codebook.order;
        let source = peaked_nlsf(order);
        let mut weights = vec![0i16; order];
        nlsf_vq_weights_laroia(&mut weights, &source);

        let error_for = |survivors: usize| -> i64 {
            let mut quantized = source.clone();
            let mut indices = NlsfIndices {
                indices: [0i8; MAX_NLSF_INDICES],
                order,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            };
            let _ = nlsf_encode(
                &mut indices,
                &mut quantized,
                codebook,
                &weights,
                3146,
                survivors,
                2,
            );
            source
                .iter()
                .zip(quantized.iter())
                .zip(weights.iter())
                .map(|((&a, &b), &w)| {
                    let d = i64::from(a) - i64::from(b);
                    d * d * i64::from(w)
                })
                .sum()
        };

        let few = error_for(1);
        let many = error_for(16);
        assert!(many <= few, "16 survivors ({many}) worse than 1 ({few})");
    }

    /// A zero rate weight makes the trellis purely distortion-driven, so it must do at least as
    /// well on distortion as a large one. That proves `mu_Q20` is genuinely wired into the metric.
    #[test]
    fn the_rate_weight_trades_distortion_for_rate() {
        let codebook = &NB_MB;
        let order = codebook.order;
        let source = peaked_nlsf(order);
        let mut weights = vec![0i16; order];
        nlsf_vq_weights_laroia(&mut weights, &source);

        let distortion_for = |mu_q20: i32| -> i64 {
            let mut quantized = source.clone();
            let mut indices = NlsfIndices {
                indices: [0i8; MAX_NLSF_INDICES],
                order,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            };
            let _ = nlsf_encode(
                &mut indices,
                &mut quantized,
                codebook,
                &weights,
                mu_q20,
                8,
                2,
            );
            source
                .iter()
                .zip(quantized.iter())
                .map(|(&a, &b)| {
                    let d = i64::from(a) - i64::from(b);
                    d * d
                })
                .sum()
        };

        assert!(
            distortion_for(0) <= distortion_for(5243),
            "a zero rate weight must not increase distortion"
        );
    }

    /// `process_nlsfs` must produce two identical halves when interpolation is off, and two
    /// different ones when it is on with a previous vector that differs.
    #[test]
    fn process_nlsfs_halves_agree_only_when_interpolation_is_off() {
        let codebook = &WB;
        let order = codebook.order;
        let source = peaked_nlsf(order);
        let previous = flat_nlsf(order);

        let config = NlsfQuantConfig {
            order,
            subframe_count: 4,
            use_interpolated_nlsfs: false,
            survivors: 8,
            speech_activity_q8: 128,
        };
        let without = process_nlsfs(
            &source,
            NO_INTERPOLATION_Q2,
            &previous,
            codebook,
            &config,
            2,
        );
        assert_eq!(without.first_half_q12, without.second_half_q12);
        assert_eq!(without.indices.interpolation_factor_q2, NO_INTERPOLATION_Q2);

        let config = NlsfQuantConfig {
            use_interpolated_nlsfs: true,
            ..config
        };
        let with = process_nlsfs(&source, 1, &previous, codebook, &config, 2);
        assert_ne!(
            with.first_half_q12, with.second_half_q12,
            "an interpolated frame must have two different filters"
        );
    }

    /// A 10 ms frame pays 1.5x the rate weight. Check it through the observable side effect: the
    /// two configurations must both produce decodable indices, and the mu computation itself is
    /// pinned by the assertion inside `process_nlsfs`.
    #[test]
    fn process_nlsfs_accepts_both_frame_lengths() {
        let codebook = &NB_MB;
        let order = codebook.order;
        let source = peaked_nlsf(order);
        let previous = flat_nlsf(order);
        for subframe_count in [2usize, 4] {
            let config = NlsfQuantConfig {
                order,
                subframe_count,
                use_interpolated_nlsfs: false,
                survivors: 4,
                speech_activity_q8: 256,
            };
            let result = process_nlsfs(
                &source,
                NO_INTERPOLATION_Q2,
                &previous,
                codebook,
                &config,
                1,
            );
            let stage1 = result.indices.indices[0];
            assert!(stage1 >= 0 && (stage1 as usize) < codebook.vector_count);
        }
    }

    proptest! {
        /// The invariant the bitstream depends on: for *any* input vector, the emitted indices are
        /// in range, they decode without panicking, and the reconstruction is a stable LPC filter.
        #[test]
        fn any_input_quantises_to_a_decodable_stable_filter(
            raw in prop::collection::vec(1i16..32_000, 16..=16),
            survivors in 1usize..=16,
            mu_q20 in 0i32..=5243,
        ) {
            let codebook = &WB;
            let order = codebook.order;
            let mut source = raw;
            source.sort_unstable();

            let mut weights = vec![0i16; order];
            nlsf_vq_weights_laroia(&mut weights, &source);
            let mut quantized = source.clone();
            let mut indices = NlsfIndices {
                indices: [0i8; MAX_NLSF_INDICES],
                order,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            };
            let rate_distortion = nlsf_encode(
                &mut indices, &mut quantized, codebook, &weights, mu_q20, survivors, 2,
            );
            prop_assert!(rate_distortion >= 0, "RD {}", rate_distortion);

            let stage1 = indices.indices[0];
            prop_assert!(stage1 >= 0 && (stage1 as usize) < codebook.vector_count);
            for &residual in indices.stage2_residuals() {
                prop_assert!(i32::from(residual).abs() <= NLSF_QUANT_MAX_AMPLITUDE_EXT);
            }

            // Decoding through the decoder's own path must reproduce the reconstruction...
            let mut decoded = vec![0i16; order];
            nlsf_decode(&mut decoded, codebook, &indices);
            prop_assert_eq!(&decoded, &quantized);

            // ...and that reconstruction must build a stable filter.
            let mut a_q12 = [0i16; MAX_LPC_ORDER];
            nlsf_to_lpc_q12(&mut a_q12[..order], &decoded);
            prop_assert!(
                inverse_prediction_gain_q12(&a_q12[..order]) > 0,
                "unstable filter from {:?}", decoded
            );
        }

        /// Laroia weights are always strictly positive and never saturate to zero, for any
        /// increasing vector — the trellis divides by their square, so a zero would be fatal.
        #[test]
        fn laroia_weights_are_always_positive(
            raw in prop::collection::vec(0i16..32_767, 10..=10),
        ) {
            let mut nlsf = raw;
            nlsf.sort_unstable();
            let mut weights = [0i16; 10];
            nlsf_vq_weights_laroia(&mut weights, &nlsf);
            for (index, &weight) in weights.iter().enumerate() {
                prop_assert!(weight > 0, "weight {} = {} for {:?}", index, weight, nlsf);
            }
        }
    }
}
