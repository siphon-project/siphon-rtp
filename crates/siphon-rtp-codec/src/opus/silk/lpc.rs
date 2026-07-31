//! Normalized LSFs → short-term LPC coefficients (RFC 6716 §4.2.7.5.8; libopus `silk/NLSF2A.c`),
//! plus the two filters that keep the result usable: `silk_LPC_fit` (fit into Q12 `i16` without
//! wrap-around) and `silk_bwexpander` / `silk_bwexpander_32` (bandwidth expansion).
//!
//! The conversion is a fixed-point evaluation of the classic LSF→LPC identity: an order-`d` monic
//! whitening filter `A(z)` splits into the symmetric `P(z)` and antisymmetric `Q(z)` polynomials
//! whose roots are the even- and odd-indexed line spectral frequencies. Each NLSF is mapped to
//! `2*cos(pi*f)` through a **piecewise-linear** read of [`super::nlsf_tables::LSF_COS_TAB_Q12`], the
//! two polynomials are built by convolution, and `A` is recovered as
//! `a[k] = -(Q[k+1] - Q[k]) - (P[k+1] + P[k])`.
//!
//! Two things are deliberate rather than incidental:
//!
//! * **The cosine map is an approximation, and both directions use the same one.** `NLSF2A.c:33-36`
//!   says so outright: the result is "not accurate LSFs, but the two functions are accurate inverses
//!   of each other". So this must not be "improved" with a real cosine — the encoder's `silk_A2NLSF`
//!   inverts *this* curve.
//! * **The coefficient ordering is a numerical trick, not a permutation of the output.**
//!   `NLSF2A.c:73-80` reorders which NLSF feeds which slot of the convolution, purely to keep the
//!   intermediate polynomial coefficients small. Reproducing it is mandatory: a different ordering
//!   gives a slightly different rounding path and therefore different Q12 output.
//!
//! Arithmetic follows the C's `opus_int32` semantics, including the places where it can wrap. That
//! is not laxity: `NLSF2A.c:124` explicitly notes the intermediates "need to fit in int32" for the
//! inputs SILK actually produces, and a decoder fed a hostile bitstream must still not panic in a
//! debug build. Every such site uses an explicit `wrapping_*`, so it reads as a decision.

use crate::opus::silk::fixed::{
    abs_wrapping, inverse32_var_q, rshift_round, rshift_round64, sat16, smmul, smulww, sub_sat32,
};
use crate::opus::silk::nlsf_tables::{LSF_COS_TAB_Q12, LSF_COS_TAB_SIZE};
use crate::opus::silk::types::{MAX_LPC_ORDER, MIN_LPC_ORDER};

/// `QA` in `NLSF2A.c:41` — the Q domain the `2*cos(NLSF)` values and the polynomials are built in.
const POLY_Q: u32 = 16;

/// Output Q domain of the LPC coefficients (`silk_LPC_fit(..., 12, QA + 1, d)`, `NLSF2A.c:130`).
const LPC_Q: u32 = 12;

/// `MAX_LPC_STABILIZE_ITERATIONS` (`define.h:138`) — how many times `silk_NLSF2A` may bandwidth-expand
/// before giving up on making the filter stable.
const MAX_LPC_STABILIZE_ITERATIONS: usize = 16;

/// `BWE_AFTER_LOSS_Q16` (`define.h:223`) — the chirp factor applied to both LPC coefficient sets
/// after a concealed frame (`decode_parameters.c:81-84`).
pub const BWE_AFTER_LOSS_Q16: i32 = 63_570;

/// `A_LIMIT = SILK_FIX_CONST(0.99975, 24)` (`LPC_inv_pred_gain.c:36`) — a reflection coefficient at
/// or beyond this magnitude means the filter is (too close to) unstable.
const REFLECTION_LIMIT_QA: i32 = 16_773_022;

/// Q domain the inverse-prediction-gain recursion runs in (`LPC_inv_pred_gain.c:35`).
const INV_GAIN_QA: u32 = 24;

/// `SILK_FIX_CONST(1.0f / MAX_PREDICTION_POWER_GAIN, 30)` (`LPC_inv_pred_gain.c:70`) — an inverse
/// prediction gain below this counts as unstable.
const MIN_INVERSE_GAIN_Q30: i32 = 107_374;

/// `ordering16` (`NLSF2A.c:75-77`) — which polynomial slot each of the 16 NLSFs feeds.
const ORDERING_16: [usize; MAX_LPC_ORDER] = [0, 15, 8, 7, 4, 11, 12, 3, 2, 13, 10, 5, 6, 9, 14, 1];

/// `ordering10` (`NLSF2A.c:78-80`).
const ORDERING_10: [usize; MIN_LPC_ORDER] = [0, 9, 6, 3, 4, 5, 8, 1, 2, 7];

/// `silk_bwexpander_32(ar, d, chirp_Q16)` (`bwexpander_32.c:36-50`) — chirp an AR filter held in a
/// wide Q domain, in place. Coefficient `k` is multiplied by `chirp^(k+1)`.
pub fn bwexpander_32(coefficients: &mut [i32], chirp_q16: i32) {
    let order = coefficients.len();
    if order == 0 {
        return;
    }
    let chirp_minus_one_q16 = chirp_q16.wrapping_sub(65_536);
    let mut chirp_q16 = chirp_q16;
    for coefficient in coefficients.iter_mut().take(order - 1) {
        *coefficient = smulww(chirp_q16, *coefficient);
        chirp_q16 = chirp_q16.wrapping_add(rshift_round(
            chirp_q16.wrapping_mul(chirp_minus_one_q16),
            16,
        ));
    }
    coefficients[order - 1] = smulww(chirp_q16, coefficients[order - 1]);
}

/// `silk_bwexpander(ar, d, chirp_Q16)` (`bwexpander.c:35-51`) — the Q12 `i16` form, used after a
/// concealed frame.
///
/// The C's own comment (`bwexpander.c:44-45`) forbids substituting `silk_SMULWB` here: its bias
/// would let the expanded filter come out unstable. So this really is a rounded multiply.
pub fn bwexpander_q12(coefficients: &mut [i16], chirp_q16: i32) {
    let order = coefficients.len();
    if order == 0 {
        return;
    }
    let chirp_minus_one_q16 = chirp_q16.wrapping_sub(65_536);
    let mut chirp_q16 = chirp_q16;
    for coefficient in coefficients.iter_mut().take(order - 1) {
        *coefficient = rshift_round(chirp_q16.wrapping_mul(i32::from(*coefficient)), 16) as i16;
        chirp_q16 = chirp_q16.wrapping_add(rshift_round(
            chirp_q16.wrapping_mul(chirp_minus_one_q16),
            16,
        ));
    }
    coefficients[order - 1] = rshift_round(
        chirp_q16.wrapping_mul(i32::from(coefficients[order - 1])),
        16,
    ) as i16;
}

/// `silk_LPC_fit(a_QOUT, a_QIN, QOUT, QIN, d)` (`LPC_fit.c:36-82`) — shift a wide-Q AR filter down
/// to `i16`, chirping it down first if any coefficient would not fit.
///
/// `input_q` is modified in place exactly as the C's `a_QIN` is: the caller (`silk_NLSF2A`) reuses
/// the chirped version for its stability retries, so writing back is load-bearing, not incidental.
fn lpc_fit(output_q12: &mut [i16], input_qa1: &mut [i32], input_q: u32) {
    let shift = input_q - LPC_Q;
    let mut attempts = 0usize;
    let mut largest_index = 0usize;
    while attempts < 10 {
        let mut largest = 0i32;
        for (index, &coefficient) in input_qa1.iter().enumerate() {
            let magnitude = abs_wrapping(coefficient);
            if magnitude > largest {
                largest = magnitude;
                largest_index = index;
            }
        }
        let largest = rshift_round(largest, shift);
        if largest <= i32::from(i16::MAX) {
            break;
        }
        // "( silk_int32_MAX >> 14 ) + silk_int16_MAX = 163838" (LPC_fit.c:62) — caps the divisor so
        // the Q14 numerator below cannot overflow.
        let largest = largest.min(163_838);
        // SILK_FIX_CONST( 0.999, 16 ) = 65470.
        let chirp_q16 = 65_470
            - ((largest - i32::from(i16::MAX)) << 14)
                / (largest.wrapping_mul(largest_index as i32 + 1) >> 2);
        bwexpander_32(input_qa1, chirp_q16);
        attempts += 1;
    }

    if attempts == 10 {
        // Last iteration reached: clip, and write the clipped value back so the caller's retries
        // start from something representable (LPC_fit.c:71-76).
        for (out, coefficient) in output_q12.iter_mut().zip(input_qa1.iter_mut()) {
            *out = sat16(rshift_round(*coefficient, shift));
            *coefficient = i32::from(*out) << shift;
        }
    } else {
        for (out, &coefficient) in output_q12.iter_mut().zip(input_qa1.iter()) {
            *out = rshift_round(coefficient, shift) as i16;
        }
    }
}

/// `LPC_inverse_pred_gain_QA_c` (`LPC_inv_pred_gain.c:42-119`) — the Levinson-Durbin backward
/// recursion, returning the inverse prediction gain in Q30, or **0** for an unstable filter.
///
/// `coefficients_qa` is scratch and is destroyed.
fn inverse_prediction_gain_qa(coefficients_qa: &mut [i32]) -> i32 {
    let order = coefficients_qa.len();
    if order == 0 {
        return 0;
    }
    let mut inverse_gain_q30: i32 = 1 << 30;

    for stage in (1..order).rev() {
        if coefficients_qa[stage] > REFLECTION_LIMIT_QA
            || coefficients_qa[stage] < -REFLECTION_LIMIT_QA
        {
            return 0;
        }
        // Reflection coefficient = negated AR coefficient, in Q31.
        let reflection_q31 = (coefficients_qa[stage] as u32).wrapping_shl(31 - INV_GAIN_QA) as i32;
        let reflection_q31 = reflection_q31.wrapping_neg();
        let multiplier_q30 = (1i32 << 30).wrapping_sub(smmul(reflection_q31, reflection_q31));
        inverse_gain_q30 = (smmul(inverse_gain_q30, multiplier_q30) as u32).wrapping_shl(2) as i32;
        if inverse_gain_q30 < MIN_INVERSE_GAIN_Q30 {
            return 0;
        }
        let shift = 32 - abs_wrapping(multiplier_q30).leading_zeros() as i32;
        let reciprocal = inverse32_var_q(multiplier_q30, shift + 30);

        for offset in 0..(stage + 1) >> 1 {
            let lower = coefficients_qa[offset];
            let upper = coefficients_qa[stage - offset - 1];
            let Some(new_lower) =
                update_coefficient(lower, upper, reflection_q31, reciprocal, shift)
            else {
                return 0;
            };
            let Some(new_upper) =
                update_coefficient(upper, lower, reflection_q31, reciprocal, shift)
            else {
                return 0;
            };
            coefficients_qa[offset] = new_lower;
            coefficients_qa[stage - offset - 1] = new_upper;
        }
    }

    if coefficients_qa[0] > REFLECTION_LIMIT_QA || coefficients_qa[0] < -REFLECTION_LIMIT_QA {
        return 0;
    }
    let reflection_q31 = (coefficients_qa[0] as u32).wrapping_shl(31 - INV_GAIN_QA) as i32;
    let reflection_q31 = reflection_q31.wrapping_neg();
    let multiplier_q30 = (1i32 << 30).wrapping_sub(smmul(reflection_q31, reflection_q31));
    inverse_gain_q30 = (smmul(inverse_gain_q30, multiplier_q30) as u32).wrapping_shl(2) as i32;
    if inverse_gain_q30 < MIN_INVERSE_GAIN_Q30 {
        return 0;
    }
    inverse_gain_q30
}

/// One `A_QA` update of the recursion (`LPC_inv_pred_gain.c:83-94`). `None` is the C's
/// "does not fit in `opus_int32`" bail-out, which reports the filter as unstable.
#[inline]
fn update_coefficient(
    keep: i32,
    other: i32,
    reflection_q31: i32,
    reciprocal: i32,
    shift: i32,
) -> Option<i32> {
    // MUL32_FRAC_Q( other, rc_Q31, 31 )
    let scaled = rshift_round64(i64::from(other) * i64::from(reflection_q31), 31) as i32;
    let difference = sub_sat32(keep, scaled);
    let wide = rshift_round64(i64::from(difference) * i64::from(reciprocal), shift as u32);
    if wide > i64::from(i32::MAX) || wide < i64::from(i32::MIN) {
        return None;
    }
    Some(wide as i32)
}

/// `silk_LPC_inverse_pred_gain(A_Q12, order)` (`LPC_inv_pred_gain.c:122-141`) — inverse prediction
/// gain in Q30 of a Q12 filter, or **0** when the filter is unstable.
///
/// The DC short-circuit (`DC_resp >= 4096`, i.e. the coefficients sum to >= 1.0 in Q12) is the C's:
/// such a filter has a pole at DC and cannot be stable, so the full recursion is skipped.
#[must_use]
pub fn inverse_prediction_gain_q12(coefficients_q12: &[i16]) -> i32 {
    let mut scratch = [0i32; MAX_LPC_ORDER];
    let order = coefficients_q12.len().min(MAX_LPC_ORDER);
    let mut dc_response: i32 = 0;
    for index in 0..order {
        dc_response = dc_response.wrapping_add(i32::from(coefficients_q12[index]));
        scratch[index] = i32::from(coefficients_q12[index]) << (INV_GAIN_QA - LPC_Q);
    }
    if dc_response >= 4096 {
        return 0;
    }
    inverse_prediction_gain_qa(&mut scratch[..order])
}

/// `silk_NLSF2A_find_poly` (`NLSF2A.c:44-63`) — build one of the two polynomials by convolution.
///
/// `cosines` is the interleaved `2*cos(NLSF)` vector (even entries for `P`, odd for `Q`), read with
/// a stride of 2. `out` receives `half_order + 1` coefficients in [`POLY_Q`].
fn find_polynomial(out: &mut [i32], cosines: &[i32], half_order: usize) {
    out[0] = 1 << POLY_Q;
    out[1] = -cosines[0];
    for stage in 1..half_order {
        let cosine = cosines[2 * stage];
        out[stage + 1] = ((out[stage - 1] as u32).wrapping_shl(1) as i32)
            .wrapping_sub(rshift_round64(i64::from(cosine) * i64::from(out[stage]), POLY_Q) as i32);
        for index in (2..=stage).rev() {
            let correction =
                rshift_round64(i64::from(cosine) * i64::from(out[index - 1]), POLY_Q) as i32;
            out[index] = out[index]
                .wrapping_add(out[index - 2])
                .wrapping_sub(correction);
        }
        out[1] = out[1].wrapping_sub(cosine);
    }
}

/// `silk_NLSF2A(a_Q12, NLSF, d, arch)` (`NLSF2A.c:66-140`) — normalized LSFs in Q15 to the monic
/// whitening filter's Q12 coefficients, bandwidth-expanded until the filter is stable.
///
/// `nlsf_q15` must hold `order` entries with `order` 10 or 16 (`NLSF2A.c:89`), non-negative
/// (`NLSF2A.c:94`) — which is exactly what [`super::nlsf::stabilize`] guarantees. The output is
/// written to `coefficients_q12[..order]`.
pub fn nlsf_to_lpc_q12(coefficients_q12: &mut [i16], nlsf_q15: &[i16]) {
    let order = nlsf_q15.len();
    debug_assert!(order == MIN_LPC_ORDER || order == MAX_LPC_ORDER);
    debug_assert!(coefficients_q12.len() >= order);
    let ordering: &[usize] = if order == MAX_LPC_ORDER {
        &ORDERING_16
    } else {
        &ORDERING_10
    };

    // NLSF -> 2*cos(NLSF), by linear interpolation of the 128-point cosine table.
    let mut cosines_qa = [0i32; MAX_LPC_ORDER];
    for (index, &nlsf) in nlsf_q15.iter().enumerate() {
        // f_int on a scale 0..127 (rounded down), f_frac in 0..255 (NLSF2A.c:96-100). A stabilised
        // NLSF is in 0..=32767, so f_int is in 0..=127 and the `f_int + 1` read below stays inside
        // the table's extra endpoint; clamping here would be a silent deviation, so instead the
        // index is masked to the table's own range and the stabiliser is what makes that a no-op.
        let integer_part = ((i32::from(nlsf) >> (15 - 7)) as usize) & (LSF_COS_TAB_SIZE - 1);
        let fractional_part = i32::from(nlsf) - ((integer_part as i32) << (15 - 7));
        let cosine = i32::from(LSF_COS_TAB_Q12[integer_part]);
        let delta = i32::from(LSF_COS_TAB_Q12[integer_part + 1]) - cosine;
        // silk_RSHIFT_ROUND( silk_LSHIFT( cos_val, 8 ) + silk_MUL( delta, f_frac ), 20 - QA )
        cosines_qa[ordering[index]] = rshift_round(
            (cosine << 8).wrapping_add(delta.wrapping_mul(fractional_part)),
            20 - POLY_Q,
        );
    }

    let half_order = order >> 1;
    let mut even_polynomial = [0i32; MAX_LPC_ORDER / 2 + 1];
    let mut odd_polynomial = [0i32; MAX_LPC_ORDER / 2 + 1];
    find_polynomial(&mut even_polynomial, &cosines_qa[..], half_order);
    find_polynomial(&mut odd_polynomial, &cosines_qa[1..], half_order);

    // A(z) from P(z) and Q(z), in QA+1.
    let mut wide_qa1 = [0i32; MAX_LPC_ORDER];
    for index in 0..half_order {
        let even = even_polynomial[index + 1].wrapping_add(even_polynomial[index]);
        let odd = odd_polynomial[index + 1].wrapping_sub(odd_polynomial[index]);
        wide_qa1[index] = odd.wrapping_neg().wrapping_sub(even);
        wide_qa1[order - index - 1] = odd.wrapping_sub(even);
    }

    lpc_fit(
        &mut coefficients_q12[..order],
        &mut wide_qa1[..order],
        POLY_Q + 1,
    );

    // Bandwidth-expand until stable, with a chirp that tightens on each attempt (NLSF2A.c:132-139).
    let mut attempt = 0usize;
    while inverse_prediction_gain_q12(&coefficients_q12[..order]) == 0
        && attempt < MAX_LPC_STABILIZE_ITERATIONS
    {
        bwexpander_32(&mut wide_qa1[..order], 65_536 - (2 << attempt));
        for index in 0..order {
            coefficients_q12[index] = rshift_round(wide_qa1[index], POLY_Q + 1 - LPC_Q) as i16;
        }
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::nlsf_tables::NlsfCodebook;
    use proptest::prelude::*;

    /// A stabilised NLSF vector taken straight from a stage-1 codebook entry, which is what the
    /// decoder feeds this module when the stage-2 residual is zero.
    fn codebook_nlsf(codebook: &NlsfCodebook, index: usize) -> Vec<i16> {
        codebook
            .cb1_vector_q8(index)
            .iter()
            .map(|&entry| i16::from(entry) << 7)
            .collect()
    }

    #[test]
    fn orderings_are_permutations_of_their_range() {
        let mut seen = [false; MAX_LPC_ORDER];
        for &slot in &ORDERING_16 {
            assert!(slot < MAX_LPC_ORDER);
            assert!(!seen[slot], "ordering16 repeats {slot}");
            seen[slot] = true;
        }
        assert!(seen.iter().all(|&s| s));
        let mut seen = [false; MIN_LPC_ORDER];
        for &slot in &ORDERING_10 {
            assert!(slot < MIN_LPC_ORDER);
            assert!(!seen[slot], "ordering10 repeats {slot}");
            seen[slot] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    /// `silk_bwexpander_32` scales coefficient `k` by `chirp^(k+1)`. With `chirp = 1.0` it is the
    /// identity; below 1.0 it must be a strict, monotonically increasing attenuation.
    #[test]
    fn bwexpander_32_is_identity_at_unity_chirp() {
        let mut coefficients = [1 << 20, -(1 << 19), 1 << 18, -(1 << 17)];
        let original = coefficients;
        bwexpander_32(&mut coefficients, 65_536);
        assert_eq!(coefficients, original);
    }

    #[test]
    fn bwexpander_32_attenuates_more_at_higher_orders() {
        let mut coefficients = [1 << 20; 6];
        bwexpander_32(&mut coefficients, 62_000);
        for index in 1..coefficients.len() {
            assert!(
                coefficients[index] < coefficients[index - 1],
                "coefficient {index} was not attenuated further"
            );
        }
        // chirp^1 on the first coefficient.
        assert_eq!(coefficients[0], smulww(62_000, 1 << 20));
    }

    #[test]
    fn bwexpander_q12_matches_the_wide_form_at_unity() {
        let mut narrow = [4096i16, -2048, 1024, -512];
        let original = narrow;
        bwexpander_q12(&mut narrow, 65_536);
        assert_eq!(narrow, original);

        // The post-loss chirp really does shrink the filter.
        let mut narrow = [4096i16, -2048, 1024, -512];
        bwexpander_q12(&mut narrow, BWE_AFTER_LOSS_Q16);
        for index in 0..narrow.len() {
            assert!(narrow[index].abs() < original[index].abs());
        }
    }

    /// An all-zero filter is perfectly stable and has unity prediction gain (Q30 = 2^30).
    #[test]
    fn inverse_prediction_gain_of_a_flat_filter_is_unity() {
        assert_eq!(inverse_prediction_gain_q12(&[0i16; 10]), 1 << 30);
        assert_eq!(inverse_prediction_gain_q12(&[0i16; 16]), 1 << 30);
    }

    /// A filter whose coefficients sum to >= 1.0 in Q12 has a pole at DC — the C rejects it without
    /// running the recursion at all (`LPC_inv_pred_gain.c:137`).
    #[test]
    fn inverse_prediction_gain_rejects_a_dc_pole() {
        let mut coefficients = [0i16; 10];
        coefficients[0] = 4096;
        assert_eq!(inverse_prediction_gain_q12(&coefficients), 0);
        coefficients[0] = 2048;
        coefficients[1] = 2048;
        assert_eq!(inverse_prediction_gain_q12(&coefficients), 0);
        // Just below the threshold, the recursion runs and finds a stable filter.
        coefficients[1] = 2047;
        assert!(inverse_prediction_gain_q12(&coefficients) > 0);
    }

    /// A single-tap filter `1 - a z^-1` has inverse prediction gain `1 - a^2`, which is the one case
    /// where the Q30 recursion can be checked against closed-form arithmetic.
    #[test]
    fn inverse_prediction_gain_matches_the_closed_form_for_one_tap() {
        for numerator in [1i32, 100, 1000, 2000, 3000, 4000] {
            let coefficient = numerator as i16;
            let gain = inverse_prediction_gain_q12(&[coefficient]);
            let reflection = f64::from(coefficient) / 4096.0;
            let expected = (1.0 - reflection * reflection) * f64::from(1 << 30);
            assert!(
                (f64::from(gain) - expected).abs() <= expected * 0.001 + 64.0,
                "a = {coefficient}: {gain} vs {expected}"
            );
        }
    }

    /// Every stage-1 codebook vector, converted to LPC, must produce a **stable** filter — that is
    /// what the bandwidth-expansion loop at the end of `silk_NLSF2A` exists to guarantee, and it is
    /// checkable without any reference data.
    #[test]
    fn every_codebook_vector_converts_to_a_stable_filter() {
        for (name, codebook) in [
            ("NB_MB", &crate::opus::silk::nlsf_tables::NB_MB),
            ("WB", &crate::opus::silk::nlsf_tables::WB),
        ] {
            for index in 0..codebook.vector_count {
                let nlsf = codebook_nlsf(codebook, index);
                let mut coefficients = [0i16; MAX_LPC_ORDER];
                nlsf_to_lpc_q12(&mut coefficients, &nlsf);
                assert!(
                    inverse_prediction_gain_q12(&coefficients[..codebook.order]) > 0,
                    "{name} vector {index} produced an unstable filter: {:?}",
                    &coefficients[..codebook.order]
                );
            }
        }
    }

    /// RFC 6716 §4.2.7.5.8: the first LPC coefficient tracks the spectral tilt, so a codebook vector
    /// whose NLSFs cluster low (energy at low frequencies) must give a larger `a[0]` than one whose
    /// NLSFs are spread out. This checks the conversion does something meaningful, not merely
    /// something stable.
    #[test]
    fn low_frequency_nlsfs_give_a_stronger_first_coefficient() {
        let order = MIN_LPC_ORDER;
        // Tightly clustered near DC.
        let clustered: Vec<i16> = (0..order).map(|k| 400 + 300 * k as i16).collect();
        // Evenly spread over the whole band.
        let spread: Vec<i16> = (0..order)
            .map(|k| ((k as i32 + 1) * 32767 / (order as i32 + 1)) as i16)
            .collect();
        let mut clustered_lpc = [0i16; MAX_LPC_ORDER];
        let mut spread_lpc = [0i16; MAX_LPC_ORDER];
        nlsf_to_lpc_q12(&mut clustered_lpc, &clustered);
        nlsf_to_lpc_q12(&mut spread_lpc, &spread);
        assert!(
            clustered_lpc[0] > spread_lpc[0],
            "clustered {} vs spread {}",
            clustered_lpc[0],
            spread_lpc[0]
        );
        // The spread vector is close to white, so its filter is near-flat.
        assert!(
            spread_lpc[0].abs() < 1024,
            "a near-white spectrum should not need a strong predictor: {}",
            spread_lpc[0]
        );
    }

    /// `silk_LPC_fit`'s chirp path: a wide filter whose coefficients would not fit in Q12 `i16` is
    /// scaled down rather than clipped, and the result always fits.
    #[test]
    fn lpc_fit_shrinks_oversized_coefficients_instead_of_wrapping() {
        let mut wide = [1i32 << 30, 1 << 29, -(1 << 30), 1 << 28];
        let mut narrow = [0i16; 4];
        lpc_fit(&mut narrow, &mut wide, POLY_Q + 1);
        for &coefficient in &narrow {
            assert!(i32::from(coefficient) <= i32::from(i16::MAX));
        }
        // The relative shape survives: the largest input is still the largest output in magnitude.
        assert!(narrow[0].abs() >= narrow[1].abs());
    }

    #[test]
    fn lpc_fit_is_a_plain_rounded_shift_when_everything_fits() {
        let mut wide = [1i32 << 17, -(1 << 16), 3 << 15, 0];
        let expected: Vec<i16> = wide.iter().map(|&w| rshift_round(w, 5) as i16).collect();
        let mut narrow = [0i16; 4];
        lpc_fit(&mut narrow, &mut wide, POLY_Q + 1);
        assert_eq!(narrow.to_vec(), expected);
    }

    proptest! {
        /// The whole point of the bandwidth-expansion loop: whatever NLSF vector comes out of the
        /// stabiliser, the Q12 filter must be stable. Feed sorted, minimally spaced vectors — the
        /// stabiliser's postcondition — and require a non-zero inverse prediction gain every time.
        #[test]
        fn any_sorted_nlsf_vector_yields_a_stable_filter(
            raw in prop::collection::vec(1i32..32767, MIN_LPC_ORDER),
        ) {
            let mut sorted = raw;
            sorted.sort_unstable();
            // Enforce the minimum spacing the stabiliser guarantees.
            let delta_min = crate::opus::silk::nlsf_tables::NB_MB.delta_min_q15;
            let mut nlsf = vec![0i16; MIN_LPC_ORDER];
            nlsf[0] = sorted[0].max(i32::from(delta_min[0])) as i16;
            for index in 1..MIN_LPC_ORDER {
                let floor = i32::from(nlsf[index - 1]) + i32::from(delta_min[index]);
                nlsf[index] = sorted[index].max(floor).min(32767) as i16;
            }
            let mut coefficients = [0i16; MAX_LPC_ORDER];
            nlsf_to_lpc_q12(&mut coefficients, &nlsf);
            prop_assert!(
                inverse_prediction_gain_q12(&coefficients[..MIN_LPC_ORDER]) > 0,
                "unstable filter from {nlsf:?}: {:?}",
                &coefficients[..MIN_LPC_ORDER]
            );
        }

        /// Arbitrary (even wildly unsorted) NLSF input must not panic — a fuzzed bitstream can
        /// reach the stabiliser with anything, and a debug build must survive it.
        #[test]
        fn arbitrary_nlsf_input_never_panics(raw in prop::collection::vec(0i16..=32767, MAX_LPC_ORDER)) {
            let mut coefficients = [0i16; MAX_LPC_ORDER];
            nlsf_to_lpc_q12(&mut coefficients, &raw);
            let _ = inverse_prediction_gain_q12(&coefficients);
            nlsf_to_lpc_q12(&mut coefficients, &raw[..MIN_LPC_ORDER]);
            let _ = inverse_prediction_gain_q12(&coefficients[..MIN_LPC_ORDER]);
        }

        /// The chirp filters never panic and always keep their output in range.
        #[test]
        fn bandwidth_expansion_never_panics(chirp: i32, seed: i32) {
            let mut wide = [seed, seed / 2, seed / 3, seed / 5];
            bwexpander_32(&mut wide, chirp);
            let mut narrow = [seed as i16, (seed / 2) as i16, (seed / 3) as i16];
            bwexpander_q12(&mut narrow, chirp);
        }
    }
}
