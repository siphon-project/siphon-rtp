//! Short-term (LPC) analysis: Burg's method, LPC↔NLSF conversion, and the NLSF interpolation
//! search (libopus `silk/float/burg_modified_FLP.c`, `silk/A2NLSF.c`,
//! `silk/float/wrappers_FLP.c:37-69`, `silk/float/find_LPC_FLP.c`).
//!
//! This is the stage that decides *what spectral envelope the frame has*. It runs on the
//! gain-normalised, LTP-filtered residual that [`super::pred_coefs`] prepares, and hands the
//! resulting normalized line spectral frequencies to [`super::nlsf_quant`].
//!
//! Three pieces, in the order `silk_find_LPC_FLP` uses them:
//!
//! 1. [`burg_modified`] — a **modified** Burg recursion (forward *and* backward prediction error,
//!    summed over the frame's subframes) with a hard ceiling on the prediction gain. The ceiling is
//!    not cosmetic: an LPC filter whose synthesis gain runs away turns a single lost packet into
//!    seconds of ringing at the decoder, so the recursion clamps the reflection coefficient the
//!    moment the gain would be exceeded and zeroes everything after it.
//! 2. [`a2nlsf`] — the LPC→NLSF root finder, in **fixed point**, shared verbatim with the decoder's
//!    inverse [`nlsf_to_lpc_q12`]. Both sides use the same piecewise-linear cosine table, which is
//!    what makes them accurate inverses of each other even though neither is an accurate NLSF
//!    computation in the textbook sense (the C says exactly this at `A2NLSF.c:28-33`).
//! 3. [`find_lpc`] — one Burg pass over the whole frame, then, when interpolation is enabled, a
//!    second pass over the last 10 ms and a search over the four interpolation weights for the one
//!    with the lowest residual energy.

use crate::opus::silk::enc::float::{energy, lpc_analysis_filter};
use crate::opus::silk::lpc::{bwexpander_32, nlsf_to_lpc_q12};
use crate::opus::silk::nlsf::{interpolate, NO_INTERPOLATION_Q2};
use crate::opus::silk::nlsf_tables::{LSF_COS_TAB_Q12, LSF_COS_TAB_SIZE};
use crate::opus::silk::types::{MAX_FRAME_LENGTH, MAX_LPC_ORDER, MAX_NB_SUBFR};

use super::float::float2int;

/// `FIND_LPC_COND_FAC` (`tuning_parameters.h:54`) — the diagonal loading Burg adds to the zero-lag
/// autocorrelation. Without it a periodic, nearly-singular frame produces a filter with an enormous
/// prediction gain and a numerically meaningless residual.
const FIND_LPC_COND_FAC: f64 = 1e-5f32 as f64;

/// `BIN_DIV_STEPS_A2NLSF_FIX` (`A2NLSF.c:42`) — bisection steps per root before the linear
/// interpolation refinement. The C's comment bounds it: "must be no higher than
/// `16 - log2(LSF_COS_TAB_SZ_FIX)`".
const BIN_DIV_STEPS: u32 = 3;

/// `MAX_ITERATIONS_A2NLSF_FIX` (`A2NLSF.c:43`) — bandwidth expansions before giving up on finding
/// all the roots and falling back to a flat spectrum.
const MAX_A2NLSF_ITERATIONS: usize = 16;

/// Longest input `silk_find_LPC_FLP` filters: `MAX_FRAME_LENGTH + MAX_NB_SUBFR * MAX_LPC_ORDER`
/// (`find_LPC_FLP.c:52`), i.e. the frame plus each subframe's `order` preceding samples.
pub const MAX_LPC_INPUT_LENGTH: usize = MAX_FRAME_LENGTH + MAX_NB_SUBFR * MAX_LPC_ORDER;

/// `silk_burg_modified_FLP(A, x, minInvGain, subfr_length, nb_subfr, D, arch)`
/// (`burg_modified_FLP.c:39-187`) — the modified covariance / Burg AR estimator.
///
/// Returns the residual energy and writes `order` prediction coefficients into `coefficients`.
/// `input` holds `subframe_count` stacked blocks of `subframe_length` samples each, where every
/// block already includes its `order` preceding samples (the caller stacks them that way so one
/// call covers the whole frame while each subframe keeps its own history).
///
/// `min_inv_gain` is the reciprocal of the largest synthesis gain the filter may have. When the
/// recursion would cross it, the reflection coefficient is replaced by the value that lands
/// *exactly* on the limit — keeping its sign — and every later coefficient is zeroed
/// (`burg_modified_FLP.c:123-151`). Because the loop then exits early, the returned energy is the
/// approximation `C0 * invGain` rather than the exact `CAf[0]` form; both branches are ported.
///
/// The accumulators are `double` throughout, as in the C: the correlation updates subtract
/// same-magnitude terms and an `f32` accumulator loses the difference entirely.
#[must_use]
pub fn burg_modified(
    coefficients: &mut [f32],
    input: &[f32],
    min_inv_gain: f32,
    subframe_length: usize,
    subframe_count: usize,
) -> f32 {
    let order = coefficients.len();
    debug_assert!(order <= MAX_LPC_ORDER);
    debug_assert!(subframe_count * subframe_length <= input.len());
    if order == 0 || subframe_length <= order || subframe_count == 0 {
        return 0.0;
    }

    let mut c_first_row = [0.0f64; MAX_LPC_ORDER];
    let mut c_last_row = [0.0f64; MAX_LPC_ORDER];
    let mut correlation_forward = [0.0f64; MAX_LPC_ORDER + 1];
    let mut correlation_backward = [0.0f64; MAX_LPC_ORDER + 1];
    let mut prediction = [0.0f64; MAX_LPC_ORDER];

    // Autocorrelations, added over subframes.
    let mut c0 = energy(&input[..subframe_count * subframe_length]);
    for subframe in 0..subframe_count {
        let block = &input[subframe * subframe_length..][..subframe_length];
        for lag in 1..=order {
            c_first_row[lag - 1] += super::float::inner_product(block, &block[lag..]);
        }
    }
    c_last_row[..order].copy_from_slice(&c_first_row[..order]);

    correlation_forward[0] = c0 + FIND_LPC_COND_FAC * c0 + f64::from(1e-9f32);
    correlation_backward[0] = correlation_forward[0];
    let mut inverse_gain = 1.0f64;
    let mut reached_max_gain = false;
    let min_inv_gain = f64::from(min_inv_gain);

    let mut stage = 0usize;
    while stage < order {
        for subframe in 0..subframe_count {
            let block = &input[subframe * subframe_length..][..subframe_length];
            let mut tmp1 = f64::from(block[stage]);
            let mut tmp2 = f64::from(block[subframe_length - stage - 1]);
            for k in 0..stage {
                // These two products are `float` in the C (`burg_modified_FLP.c:83-84` has no
                // `(double)` cast, unlike `silk_energy_FLP`), so only the accumulator is double.
                c_first_row[k] -= f64::from(block[stage] * block[stage - k - 1]);
                c_last_row[k] -= f64::from(
                    block[subframe_length - stage - 1] * block[subframe_length - stage + k],
                );
                let coefficient = prediction[k];
                tmp1 += f64::from(block[stage - k - 1]) * coefficient;
                tmp2 += f64::from(block[subframe_length - stage + k]) * coefficient;
            }
            for k in 0..=stage {
                correlation_forward[k] -= tmp1 * f64::from(block[stage - k]);
                correlation_backward[k] -= tmp2 * f64::from(block[subframe_length - stage + k - 1]);
            }
        }

        let mut tmp1 = c_first_row[stage];
        let mut tmp2 = c_last_row[stage];
        for k in 0..stage {
            let coefficient = prediction[k];
            tmp1 += c_last_row[stage - k - 1] * coefficient;
            tmp2 += c_first_row[stage - k - 1] * coefficient;
        }
        correlation_forward[stage + 1] = tmp1;
        correlation_backward[stage + 1] = tmp2;

        // Numerator and denominator of the next reflection (parcor) coefficient.
        let mut numerator = correlation_backward[stage + 1];
        let mut energy_backward = correlation_backward[0];
        let mut energy_forward = correlation_forward[0];
        for k in 0..stage {
            let coefficient = prediction[k];
            numerator += correlation_backward[stage - k] * coefficient;
            energy_backward += correlation_backward[k + 1] * coefficient;
            energy_forward += correlation_forward[k + 1] * coefficient;
        }

        let mut reflection = -2.0 * numerator / (energy_forward + energy_backward);

        // Update the inverse prediction gain, clamping to the ceiling if this step would cross it.
        let candidate_gain = inverse_gain * (1.0 - reflection * reflection);
        if candidate_gain <= min_inv_gain {
            reflection = (1.0 - min_inv_gain / inverse_gain).sqrt();
            if numerator > 0.0 {
                // Keep the sign the unclamped coefficient had.
                reflection = -reflection;
            }
            inverse_gain = min_inv_gain;
            reached_max_gain = true;
        } else {
            inverse_gain = candidate_gain;
        }

        // Levinson step-up of the AR coefficients.
        for k in 0..((stage + 1) >> 1) {
            let low = prediction[k];
            let high = prediction[stage - k - 1];
            prediction[k] = low + reflection * high;
            prediction[stage - k - 1] = high + reflection * low;
        }
        prediction[stage] = reflection;

        if reached_max_gain {
            for slot in prediction.iter_mut().take(order).skip(stage + 1) {
                *slot = 0.0;
            }
            break;
        }

        // Update C * Af and C * Ab. The C writes the mirrored index as `n - k + 1`, which reaches 0
        // at `k == n + 1` only because it is signed arithmetic; grouped as `(stage + 1) - k` it is
        // the same value without an unsigned underflow on the way.
        //
        // Not an iterator: each step reads `correlation_backward` forwards and writes it backwards
        // in the same expression, so the two arrays are walked in opposite directions at once.
        #[allow(clippy::needless_range_loop)]
        for k in 0..=(stage + 1) {
            let mirrored = stage + 1 - k;
            let forward = correlation_forward[k];
            correlation_forward[k] += reflection * correlation_backward[mirrored];
            correlation_backward[mirrored] += reflection * forward;
        }
        stage += 1;
    }

    let residual_energy = if reached_max_gain {
        for (slot, &value) in coefficients.iter_mut().zip(prediction.iter()) {
            *slot = -value as f32;
        }
        // Subtract the energy of the preceding samples from C0, then approximate.
        for subframe in 0..subframe_count {
            c0 -= energy(&input[subframe * subframe_length..][..order]);
        }
        c0 * inverse_gain
    } else {
        let mut accumulator = correlation_forward[0];
        let mut coefficient_energy = 1.0f64;
        for k in 0..order {
            let value = prediction[k];
            accumulator += correlation_forward[k + 1] * value;
            coefficient_energy += value * value;
            coefficients[k] = -value as f32;
        }
        accumulator - FIND_LPC_COND_FAC * c0 * coefficient_energy
    };

    residual_energy as f32
}

/// `silk_A2NLSF_trans_poly(p, dd)` (`A2NLSF.c:47-60`) — rewrite a polynomial from the `cos(n*f)`
/// basis into the `cos(f)^n` basis, in place.
fn trans_poly(polynomial: &mut [i32], half_order: usize) {
    for k in 2..=half_order {
        let mut n = half_order;
        while n > k {
            polynomial[n - 2] -= polynomial[n];
            n -= 1;
        }
        polynomial[k - 2] -= polynomial[k] << 1;
    }
}

/// `silk_A2NLSF_eval_poly(p, x, dd)` (`A2NLSF.c:63-93`) — Horner evaluation of a Q16 polynomial at
/// a Q12 point, returning Q16.
fn eval_poly(polynomial: &[i32], x_q12: i32, half_order: usize) -> i32 {
    let x_q16 = x_q12 << 4;
    let mut y32 = polynomial[half_order];
    for n in (0..half_order).rev() {
        y32 = super::fixed::smlaww(polynomial[n], y32, x_q16);
    }
    y32
}

/// `silk_A2NLSF_init(a_Q16, P, Q, dd)` (`A2NLSF.c:95-123`) — split the whitening filter into its
/// symmetric (`P`) and antisymmetric (`Q`) halves, divide out the two known roots at `z = ±1`, and
/// move both into the `cos(f)^n` basis.
fn a2nlsf_init(a_q16: &[i32], symmetric: &mut [i32], antisymmetric: &mut [i32], half_order: usize) {
    symmetric[half_order] = 1 << 16;
    antisymmetric[half_order] = 1 << 16;
    for k in 0..half_order {
        symmetric[k] = -a_q16[half_order - k - 1] - a_q16[half_order + k];
        antisymmetric[k] = -a_q16[half_order - k - 1] + a_q16[half_order + k];
    }
    // z = 1 is always a root of Q and z = -1 always a root of P, for an even order.
    for k in (1..=half_order).rev() {
        symmetric[k - 1] -= symmetric[k];
        antisymmetric[k - 1] += antisymmetric[k];
    }
    trans_poly(symmetric, half_order);
    trans_poly(antisymmetric, half_order);
}

/// `silk_A2NLSF(NLSF, a_Q16, d)` (`A2NLSF.c:127-267`) — normalized line spectral frequencies from a
/// monic whitening filter, by locating the interleaved roots of the symmetric and antisymmetric
/// polynomials on the unit circle.
///
/// `a_q16` is **modified in place**: when a root is missed, the filter is progressively
/// bandwidth-expanded and the search restarts, and the caller sees the expanded filter. `order` must
/// be even. The output is `order` values in Q15, strictly increasing.
///
/// The two exit paths are the C's: all roots found, or `MAX_A2NLSF_ITERATIONS` expansions
/// exhausted, in which case the NLSFs are set to a flat (white) spectrum rather than left
/// undefined. Nothing here can loop forever — each failed pass increments the expansion counter.
pub fn a2nlsf(nlsf_q15: &mut [i16], a_q16: &mut [i32], order: usize) {
    debug_assert_eq!(order % 2, 0, "silk enc: A2NLSF order must be even");
    debug_assert!(order <= MAX_LPC_ORDER && nlsf_q15.len() >= order);
    let half_order = order >> 1;

    let mut symmetric = [0i32; MAX_LPC_ORDER / 2 + 1];
    let mut antisymmetric = [0i32; MAX_LPC_ORDER / 2 + 1];
    a2nlsf_init(a_q16, &mut symmetric, &mut antisymmetric, half_order);

    // `false` selects the symmetric polynomial, `true` the antisymmetric one; the roots alternate.
    let mut on_antisymmetric = false;
    let mut x_low = i32::from(LSF_COS_TAB_Q12[0]);
    let mut y_low = eval_poly(&symmetric, x_low, half_order);

    let mut root_index = if y_low < 0 {
        // The first root sits below the table's first point: pin it at zero and move on.
        nlsf_q15[0] = 0;
        on_antisymmetric = true;
        y_low = eval_poly(&antisymmetric, x_low, half_order);
        1usize
    } else {
        0usize
    };

    let mut table_index = 1usize;
    let mut expansions = 0usize;
    let mut threshold = 0i32;

    loop {
        let polynomial: &[i32] = if on_antisymmetric {
            &antisymmetric
        } else {
            &symmetric
        };
        let mut x_high = i32::from(LSF_COS_TAB_Q12[table_index]);
        let mut y_high = eval_poly(polynomial, x_high, half_order);

        let crossed = (y_low <= 0 && y_high >= threshold) || (y_low >= 0 && y_high <= -threshold);
        if crossed {
            // A root exactly on the interval's right edge belongs to the *next* interval.
            threshold = i32::from(y_high == 0);

            // Bisection.
            let mut fraction = -256i32;
            for step in 0..BIN_DIV_STEPS {
                let x_mid = crate::opus::silk::fixed::rshift_round(x_low + x_high, 1);
                let y_mid = eval_poly(polynomial, x_mid, half_order);
                if (y_low <= 0 && y_mid >= 0) || (y_low >= 0 && y_mid <= 0) {
                    x_high = x_mid;
                    y_high = y_mid;
                } else {
                    x_low = x_mid;
                    y_low = y_mid;
                    fraction += 128 >> step;
                }
            }

            // Linear interpolation inside the last bracket.
            if y_low.wrapping_abs() < 65_536 {
                let denominator = y_low - y_high;
                let numerator = (y_low << (8 - BIN_DIV_STEPS)) + (denominator >> 1);
                if denominator != 0 {
                    fraction += numerator / denominator;
                }
            } else {
                // |y_low - y_high| >= |y_low| >= 65536, so this cannot divide by zero.
                fraction += y_low / ((y_low - y_high) >> (8 - BIN_DIV_STEPS));
            }
            nlsf_q15[root_index] =
                (((table_index as i32) << 8) + fraction).min(i32::from(i16::MAX)) as i16;

            root_index += 1;
            if root_index >= order {
                return;
            }
            on_antisymmetric = root_index & 1 == 1;
            // Restart the bracket at the previous table point, with a sign the next root must cross.
            x_low = i32::from(LSF_COS_TAB_Q12[table_index - 1]);
            y_low = (1 - ((root_index as i32) & 2)) << 12;
        } else {
            table_index += 1;
            x_low = x_high;
            y_low = y_high;
            threshold = 0;

            if table_index > LSF_COS_TAB_SIZE {
                expansions += 1;
                if expansions > MAX_A2NLSF_ITERATIONS {
                    // Give up: a flat spectrum, evenly spaced NLSFs.
                    nlsf_q15[0] = ((1i32 << 15) / (order as i32 + 1)) as i16;
                    for index in 1..order {
                        nlsf_q15[index] = crate::opus::silk::fixed::sat16(
                            i32::from(nlsf_q15[index - 1]) + i32::from(nlsf_q15[0]),
                        );
                    }
                    return;
                }

                // Progressively more bandwidth expansion, then start over.
                bwexpander_32(&mut a_q16[..order], 65_536 - (1 << expansions));
                a2nlsf_init(a_q16, &mut symmetric, &mut antisymmetric, half_order);
                on_antisymmetric = false;
                x_low = i32::from(LSF_COS_TAB_Q12[0]);
                y_low = eval_poly(&symmetric, x_low, half_order);
                root_index = if y_low < 0 {
                    nlsf_q15[0] = 0;
                    on_antisymmetric = true;
                    y_low = eval_poly(&antisymmetric, x_low, half_order);
                    1
                } else {
                    0
                };
                table_index = 1;
            }
        }
    }
}

/// `silk_A2NLSF_FLP(NLSF_Q15, pAR, LPC_order)` (`wrappers_FLP.c:37-52`) — the float entry point:
/// scale the coefficients to Q16 with `lrintf` and run the fixed-point [`a2nlsf`].
///
/// The float input is *not* modified; only the internal Q16 copy is bandwidth-expanded.
pub fn a2nlsf_from_float(nlsf_q15: &mut [i16], prediction: &[f32]) {
    let order = prediction.len();
    let mut a_q16 = [0i32; MAX_LPC_ORDER];
    for (slot, &value) in a_q16.iter_mut().zip(prediction.iter()) {
        *slot = float2int(value * 65_536.0);
    }
    a2nlsf(nlsf_q15, &mut a_q16[..order], order);
}

/// `silk_NLSF2A_FLP(pAR, NLSF_Q15, LPC_order, arch)` (`wrappers_FLP.c:54-69`) — the inverse, via the
/// decoder's own [`nlsf_to_lpc_q12`]. Sharing that function is the point: encoder and decoder must
/// agree on the NLSF→LPC map exactly, or the encoder optimises against a filter the decoder will
/// never build.
pub fn nlsf_to_float_lpc(prediction: &mut [f32], nlsf_q15: &[i16]) {
    let order = nlsf_q15.len();
    let mut a_q12 = [0i16; MAX_LPC_ORDER];
    nlsf_to_lpc_q12(&mut a_q12[..order], nlsf_q15);
    for (slot, &value) in prediction.iter_mut().zip(a_q12.iter()) {
        *slot = f32::from(value) * (1.0 / 4096.0);
    }
}

/// Everything [`find_lpc`] needs from the encoder's configuration and cross-frame state.
#[derive(Debug, Clone, Copy)]
pub struct LpcAnalysisConfig {
    /// `psEncC->predictLPCOrder` — 10 (NB/MB) or 16 (WB).
    pub order: usize,
    /// `psEncC->subfr_length` — 5 ms in samples at the internal rate.
    pub subframe_length: usize,
    /// `psEncC->nb_subfr` — 2 (10 ms frame) or 4.
    pub subframe_count: usize,
    /// `psEncC->useInterpolatedNLSFs` — set at complexity 6 and above (`control_codec.c:363`).
    pub use_interpolated_nlsfs: bool,
    /// `psEncC->first_frame_after_reset` — suppresses interpolation for one frame, because the
    /// previous frame's NLSFs are not something a decoder joining here would have.
    pub first_frame_after_reset: bool,
}

/// The result of [`find_lpc`].
#[derive(Debug, Clone, Copy)]
pub struct LpcAnalysis {
    /// The unquantized NLSFs of the frame, in Q15.
    pub nlsf_q15: [i16; MAX_LPC_ORDER],
    /// `indices.NLSFInterpCoef_Q2` — the winning interpolation weight, or
    /// [`NO_INTERPOLATION_Q2`] when interpolation is off or never won.
    pub interpolation_factor_q2: i8,
}

/// `silk_find_LPC_FLP(psEncC, NLSF_Q15, x, minInvGain, arch)` (`find_LPC_FLP.c:37-105`).
///
/// `input` is the gain-normalised signal with each subframe's `order` preceding samples prepended,
/// i.e. `subframe_count` blocks of `order + subframe_length` — the layout
/// [`super::pred_coefs`] builds.
///
/// When interpolation is enabled the search is over the four weights 3, 2, 1, 0 **in that order**,
/// and it breaks out early once the residual energy starts climbing again (`find_LPC_FLP.c:90-93`).
/// The early break is not an optimisation detail: it changes which weight wins on a frame where the
/// energy is not unimodal, so it is reproduced rather than replaced by an exhaustive search.
///
/// The residual energy of the *last 10 ms* is subtracted from the full-frame energy up front, so
/// each candidate is compared on the first 10 ms alone. The C explains the trick at
/// `find_LPC_FLP.c:63-65`.
#[must_use]
pub fn find_lpc(
    input: &[f32],
    min_inv_gain: f32,
    previous_nlsf_q15: &[i16],
    config: &LpcAnalysisConfig,
) -> LpcAnalysis {
    let order = config.order;
    let stacked_subframe_length = config.subframe_length + order;
    let mut nlsf_q15 = [0i16; MAX_LPC_ORDER];
    let mut interpolation_factor_q2 = NO_INTERPOLATION_Q2;

    let mut prediction = [0.0f32; MAX_LPC_ORDER];
    let mut residual_energy = burg_modified(
        &mut prediction[..order],
        input,
        min_inv_gain,
        stacked_subframe_length,
        config.subframe_count,
    );

    if config.use_interpolated_nlsfs
        && !config.first_frame_after_reset
        && config.subframe_count == MAX_NB_SUBFR
    {
        let mut second_half = [0.0f32; MAX_LPC_ORDER];
        residual_energy -= burg_modified(
            &mut second_half[..order],
            &input[(MAX_NB_SUBFR / 2) * stacked_subframe_length..],
            min_inv_gain,
            stacked_subframe_length,
            MAX_NB_SUBFR / 2,
        );

        a2nlsf_from_float(&mut nlsf_q15[..order], &second_half[..order]);

        let mut lpc_residual = [0.0f32; MAX_LPC_INPUT_LENGTH];
        let mut interpolated_q15 = [0i16; MAX_LPC_ORDER];
        let mut candidate = [0.0f32; MAX_LPC_ORDER];
        let mut second_best = f32::MAX;

        for factor in (0..=3i8).rev() {
            interpolate(
                &mut interpolated_q15[..order],
                &previous_nlsf_q15[..order],
                &nlsf_q15[..order],
                factor,
            );
            nlsf_to_float_lpc(&mut candidate[..order], &interpolated_q15[..order]);

            let filtered = 2 * stacked_subframe_length;
            lpc_analysis_filter(
                &mut lpc_residual[..filtered],
                &candidate[..order],
                input,
                filtered,
            );
            let tail = stacked_subframe_length - order;
            let interpolated_energy = (energy(&lpc_residual[order..][..tail])
                + energy(&lpc_residual[order + stacked_subframe_length..][..tail]))
                as f32;

            if interpolated_energy < residual_energy {
                residual_energy = interpolated_energy;
                interpolation_factor_q2 = factor;
            } else if interpolated_energy > second_best {
                // Energies are climbing; nothing below this weight can win.
                break;
            }
            second_best = interpolated_energy;
        }
    }

    if interpolation_factor_q2 == NO_INTERPOLATION_Q2 {
        // Interpolation is off, or never beat the full-frame filter: use the full-frame NLSFs.
        a2nlsf_from_float(&mut nlsf_q15[..order], &prediction[..order]);
    }

    LpcAnalysis {
        nlsf_q15,
        interpolation_factor_q2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::lpc::inverse_prediction_gain_q12;
    use proptest::prelude::*;

    /// A deterministic AR(2) process with a known spectral peak, plus a repeatable pseudo-noise
    /// excitation. No `Instant::now()`, no `rand` — the same input every run.
    fn ar_test_signal(length: usize, pole_radius: f32, pole_frequency: f32) -> Vec<f32> {
        let a1 = 2.0 * pole_radius * pole_frequency.cos();
        let a2 = -pole_radius * pole_radius;
        let mut state = 12_345u32;
        let mut signal = vec![0.0f32; length];
        let mut previous = 0.0f32;
        let mut previous2 = 0.0f32;
        for slot in signal.iter_mut() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let excitation = ((state >> 16) as i32 - 32_768) as f32 / 64.0;
            let value = excitation + a1 * previous + a2 * previous2;
            previous2 = previous;
            previous = value;
            *slot = value;
        }
        signal
    }

    /// Burg on a signal generated by a known AR(2) filter must recover that filter's coefficients.
    /// This is the closed-form check: the estimator has to invert its own generating process.
    #[test]
    fn burg_recovers_a_known_ar2_filter() {
        let pole_radius = 0.9f32;
        let pole_frequency = 0.6f32;
        let signal = ar_test_signal(400, pole_radius, pole_frequency);
        let mut coefficients = [0.0f32; 2];
        let residual = burg_modified(&mut coefficients, &signal, 1e-6, 100, 4);

        let expected_a1 = 2.0 * pole_radius * pole_frequency.cos();
        let expected_a2 = -pole_radius * pole_radius;
        // 400 samples is a short record for an AR(2) estimate, and the C adds `FIND_LPC_COND_FAC`
        // diagonal loading on top, which biases the estimate towards a flatter spectrum. 0.1 is
        // comfortably inside that finite-sample band while still failing on a sign error or a
        // transposed Levinson step.
        assert!(
            (coefficients[0] - expected_a1).abs() < 0.1,
            "a1 {} vs {expected_a1}",
            coefficients[0]
        );
        assert!(
            (coefficients[1] - expected_a2).abs() < 0.1,
            "a2 {} vs {expected_a2}",
            coefficients[1]
        );
        assert!(
            residual > 0.0 && residual.is_finite(),
            "residual {residual}"
        );
    }

    /// Whitening the input with Burg's own answer must leave less energy than the input had —
    /// otherwise the "prediction" is not predicting.
    #[test]
    fn burg_reduces_the_residual_energy() {
        let signal = ar_test_signal(400, 0.92, 0.35);
        let mut coefficients = [0.0f32; 10];
        let residual = burg_modified(&mut coefficients, &signal, 1e-6, 100, 4);
        let input_energy = energy(&signal) as f32;
        assert!(
            residual < input_energy,
            "residual {residual} not below input energy {input_energy}"
        );
    }

    /// The prediction-gain ceiling is the whole reason this is "modified" Burg. A strongly
    /// predictable input with a tight ceiling must come back with a filter whose gain respects it.
    #[test]
    fn burg_honours_the_prediction_gain_ceiling() {
        // Near-unit-circle poles: without the clamp the gain would run to thousands.
        let signal = ar_test_signal(400, 0.995, 0.15);
        let min_inv_gain = 1.0f32 / 100.0;
        let mut coefficients = [0.0f32; 16];
        let residual = burg_modified(&mut coefficients, &signal, min_inv_gain, 100, 4);
        assert!(residual.is_finite());

        let mut a_q12 = [0i16; 16];
        for (slot, &value) in a_q12.iter_mut().zip(coefficients.iter()) {
            *slot = (value * 4096.0).round() as i16;
        }
        let inverse_gain_q30 = inverse_prediction_gain_q12(&a_q12);
        assert!(inverse_gain_q30 > 0, "clamped filter must still be stable");
    }

    /// Digital silence is a real input (a muted leg), and it is exactly the case where the
    /// regularisation earns its keep: every correlation is zero, so the residual energy comes out
    /// as the bare `1e-9` seed of `CAf[0]` rather than as a `0/0`.
    #[test]
    fn burg_of_silence_returns_the_regularisation_seed() {
        let mut coefficients = [1.0f32; 10];
        let residual = burg_modified(&mut coefficients, &[0.0; 400], 1e-4, 100, 4);
        assert!(
            residual.is_finite() && residual >= 0.0,
            "residual {residual}"
        );
        assert!(
            residual < 1e-6,
            "residual {residual} should be the 1e-9 seed"
        );
        assert_eq!(coefficients, [0.0; 10], "silence predicts nothing");
    }

    #[test]
    fn burg_degenerate_shapes_return_early() {
        let mut coefficients = [0.0f32; 10];
        // Zero order, and a subframe no longer than the order, both return early.
        assert_eq!(burg_modified(&mut [], &[1.0; 400], 1e-4, 100, 4), 0.0);
        assert_eq!(
            burg_modified(&mut coefficients, &[1.0; 40], 1e-4, 10, 4),
            0.0
        );
        assert_eq!(
            burg_modified(&mut coefficients, &[1.0; 400], 1e-4, 100, 0),
            0.0
        );
    }

    /// The A2NLSF/NLSF2A pair are documented as "accurate inverses of each other" even though
    /// neither is an accurate NLSF computation. Require exactly that: round-tripping a stable
    /// filter must return it to within a fraction of a Q12 step.
    #[test]
    fn a2nlsf_and_nlsf2a_are_inverses() {
        for &(radius, frequency) in &[(0.85f32, 0.4f32), (0.7, 1.1), (0.5, 2.2)] {
            let mut original = [0.0f32; 10];
            original[0] = 2.0 * radius * frequency.cos();
            original[1] = -radius * radius;

            let mut nlsf_q15 = [0i16; 10];
            a2nlsf_from_float(&mut nlsf_q15, &original);
            let mut recovered = [0.0f32; 10];
            nlsf_to_float_lpc(&mut recovered, &nlsf_q15);

            for (index, (&before, &after)) in original.iter().zip(recovered.iter()).enumerate() {
                assert!(
                    (before - after).abs() < 0.01,
                    "coefficient {index}: {before} -> {after} (nlsf {nlsf_q15:?})"
                );
            }
        }
    }

    /// The NLSFs are frequencies on the unit circle: strictly increasing, inside `[0, 2^15)`.
    #[test]
    fn a2nlsf_produces_ordered_frequencies() {
        let signal = ar_test_signal(400, 0.9, 0.5);
        let mut coefficients = [0.0f32; 16];
        let _ = burg_modified(&mut coefficients, &signal, 1e-4, 100, 4);
        let mut nlsf_q15 = [0i16; 16];
        a2nlsf_from_float(&mut nlsf_q15, &coefficients);
        assert!(nlsf_q15[0] >= 0, "{nlsf_q15:?}");
        for pair in nlsf_q15.windows(2) {
            assert!(pair[1] > pair[0], "not increasing: {nlsf_q15:?}");
        }
    }

    /// An all-zero filter is the degenerate case the root finder cannot bracket; the C's fallback
    /// is a flat spectrum, and it must be evenly spaced rather than garbage.
    #[test]
    fn a2nlsf_of_a_zero_filter_is_a_flat_spectrum() {
        let mut nlsf_q15 = [0i16; 10];
        a2nlsf_from_float(&mut nlsf_q15, &[0.0f32; 10]);
        for pair in nlsf_q15.windows(2) {
            assert!(pair[1] > pair[0], "not increasing: {nlsf_q15:?}");
        }
    }

    fn stacked_input(order: usize, subframe_length: usize, subframe_count: usize) -> Vec<f32> {
        ar_test_signal((order + subframe_length) * subframe_count, 0.9, 0.45)
    }

    /// With interpolation disabled the factor must stay at 4 and the NLSFs must come from the
    /// full-frame Burg pass — the `find_LPC_FLP.c:103` assertion, checked from the outside.
    #[test]
    fn find_lpc_without_interpolation_uses_the_full_frame() {
        let config = LpcAnalysisConfig {
            order: 10,
            subframe_length: 40,
            subframe_count: 4,
            use_interpolated_nlsfs: false,
            first_frame_after_reset: false,
        };
        let input = stacked_input(config.order, config.subframe_length, config.subframe_count);
        let previous = [
            1000i16, 3000, 5000, 7000, 9000, 11000, 13000, 15000, 17000, 19000,
        ];
        let analysis = find_lpc(&input, 1e-4, &previous, &config);
        assert_eq!(analysis.interpolation_factor_q2, NO_INTERPOLATION_Q2);

        let mut coefficients = [0.0f32; 10];
        let _ = burg_modified(&mut coefficients, &input, 1e-4, 50, 4);
        let mut expected = [0i16; 10];
        a2nlsf_from_float(&mut expected, &coefficients);
        assert_eq!(&analysis.nlsf_q15[..10], &expected);
    }

    /// The first frame after a reset must never interpolate, even at a complexity that enables it:
    /// a decoder that joined the stream here has no previous NLSF vector to interpolate from.
    #[test]
    fn find_lpc_suppresses_interpolation_after_a_reset() {
        let config = LpcAnalysisConfig {
            order: 16,
            subframe_length: 80,
            subframe_count: 4,
            use_interpolated_nlsfs: true,
            first_frame_after_reset: true,
        };
        let input = stacked_input(config.order, config.subframe_length, config.subframe_count);
        let previous = [0i16; 16];
        let analysis = find_lpc(&input, 1e-4, &previous, &config);
        assert_eq!(analysis.interpolation_factor_q2, NO_INTERPOLATION_Q2);
    }

    /// A 10 ms frame has two subframes and is never interpolated (`find_LPC_FLP.c:62`).
    #[test]
    fn find_lpc_never_interpolates_a_two_subframe_frame() {
        let config = LpcAnalysisConfig {
            order: 10,
            subframe_length: 40,
            subframe_count: 2,
            use_interpolated_nlsfs: true,
            first_frame_after_reset: false,
        };
        let input = stacked_input(config.order, config.subframe_length, config.subframe_count);
        let previous = [
            2000i16, 4000, 6000, 8000, 10000, 12000, 14000, 16000, 18000, 20000,
        ];
        let analysis = find_lpc(&input, 1e-4, &previous, &config);
        assert_eq!(analysis.interpolation_factor_q2, NO_INTERPOLATION_Q2);
    }

    /// When the previous frame's NLSFs are *identical* to this frame's, interpolating at any weight
    /// reproduces the same filter, so the search must find a candidate at least as good as the
    /// full-frame one and pick a real weight rather than falling through to 4.
    #[test]
    fn find_lpc_interpolation_search_reports_a_legal_weight() {
        let config = LpcAnalysisConfig {
            order: 16,
            subframe_length: 80,
            subframe_count: 4,
            use_interpolated_nlsfs: true,
            first_frame_after_reset: false,
        };
        let input = stacked_input(config.order, config.subframe_length, config.subframe_count);

        // Seed the anchor with the frame's own second-half NLSFs.
        let mut second_half = [0.0f32; 16];
        let _ = burg_modified(
            &mut second_half,
            &input[2 * (config.order + config.subframe_length)..],
            1e-4,
            config.order + config.subframe_length,
            2,
        );
        let mut previous = [0i16; 16];
        a2nlsf_from_float(&mut previous, &second_half);

        let analysis = find_lpc(&input, 1e-4, &previous, &config);
        assert!(
            (0..=4).contains(&analysis.interpolation_factor_q2),
            "factor {}",
            analysis.interpolation_factor_q2
        );
    }

    proptest! {
        /// Whatever the audio, Burg must return a finite residual energy and finite coefficients,
        /// and the filter it produces must be stable once fitted to Q12 — the invariant the whole
        /// rest of the encoder assumes.
        #[test]
        fn burg_always_produces_a_stable_filter(
            samples in prop::collection::vec(-20_000.0f32..20_000.0, 400..=400),
        ) {
            let mut coefficients = [0.0f32; 16];
            let residual = burg_modified(&mut coefficients, &samples, 1.0 / 1e4, 100, 4);
            prop_assert!(residual.is_finite());
            for value in coefficients {
                prop_assert!(value.is_finite(), "coefficient {value}");
            }

            // The A2NLSF round trip is what actually reaches the bitstream; require it to give a
            // strictly increasing, in-range NLSF vector for any input.
            let mut nlsf_q15 = [0i16; 16];
            a2nlsf_from_float(&mut nlsf_q15, &coefficients);
            prop_assert!(nlsf_q15[0] >= 0);
            for pair in nlsf_q15.windows(2) {
                prop_assert!(pair[1] > pair[0], "NLSFs not increasing: {:?}", nlsf_q15);
            }
        }

        /// `silk_A2NLSF` must terminate and stay in range for an *arbitrary* Q16 filter, including
        /// one that is wildly unstable — that is what the bandwidth-expansion retry loop and its
        /// iteration cap are for.
        ///
        /// Ordering is deliberately **not** asserted here. The root finder assumes the symmetric
        /// and antisymmetric polynomials' roots interlace on the unit circle, which holds for a
        /// minimum-phase filter and not for arbitrary coefficients; when it does not, two roots can
        /// land in the same cosine-table interval and come out equal or reversed. libopus does not
        /// guarantee otherwise either — it always follows `silk_A2NLSF` with `silk_NLSF_stabilize`
        /// (`NLSF_encode.c:67`), and that is where the ordering guarantee actually comes from, as
        /// the next property proves.
        #[test]
        fn a2nlsf_terminates_and_stays_in_range_on_any_filter(
            coefficients in prop::collection::vec(-4.0f32..4.0, 10..=10),
        ) {
            let mut nlsf_q15 = [0i16; 10];
            a2nlsf_from_float(&mut nlsf_q15, &coefficients);
            for value in nlsf_q15 {
                prop_assert!(value >= 0, "NLSF out of range: {:?}", nlsf_q15);
            }
        }

        /// The invariant the bitstream depends on: whatever `silk_A2NLSF` produced, the stabiliser
        /// turns it into a strictly increasing vector that honours the codebook's minimum spacing —
        /// which is precisely the condition under which the decoder's NLSF→LPC map yields a stable
        /// filter.
        #[test]
        fn stabilised_a2nlsf_output_always_respects_the_codebook_spacing(
            coefficients in prop::collection::vec(-4.0f32..4.0, 16..=16),
        ) {
            use crate::opus::silk::nlsf::stabilize;
            use crate::opus::silk::nlsf_tables::WB;

            let mut nlsf_q15 = [0i16; 16];
            a2nlsf_from_float(&mut nlsf_q15, &coefficients);
            stabilize(&mut nlsf_q15, WB.delta_min_q15);

            prop_assert!(nlsf_q15[0] >= WB.delta_min_q15[0]);
            for index in 1..16 {
                prop_assert!(
                    i32::from(nlsf_q15[index]) - i32::from(nlsf_q15[index - 1])
                        >= i32::from(WB.delta_min_q15[index]),
                    "spacing at {} violated: {:?}",
                    index,
                    nlsf_q15
                );
            }
            prop_assert!(
                i32::from(nlsf_q15[15]) + i32::from(WB.delta_min_q15[16]) <= 1 << 15
            );
        }
    }
}
