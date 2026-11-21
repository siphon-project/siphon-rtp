//! EVS's own fixed-point math helpers (TS 26.442 `basic_math/math_op.c`): square roots, inverse
//! square roots, `2^x` and the normalised dot product.
//!
//! These share names with the AMR helpers in `crate::amr` and must not be swapped for them: the
//! EVS versions differ in table size, Q format and edge behaviour (`Isqrt_lc` returns `0x7fffffff`
//! for a non-positive input, `Pow2` rounds its final shift with `L_shr_r`, ...), and only this file
//! is proven against the EVS reference.

use crate::evs::basop::l_extract_lc;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::rom::{
    L_TABLE_ISQRT, SHIFT_ISQRT_LC, SQRT_TABLE, TABLE_ISQRT_DIFF, TABLE_POW2, TABLE_POW2_DIFF_X32,
};
use crate::itu::basic_ops::{
    extract_l, l_deposit_h, l_mac, l_msu, l_shl, l_shr, l_shr_r, mult_r, norm_l, round_word, shl,
    sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, lshl, lshr, mac_r};

/// `Isqrt`: `1 / sqrt(L_x)` of a Q0 integer, as a Q31 value.
#[must_use]
pub fn isqrt(l_x: i32) -> i32 {
    let mut exp = norm_l(l_x);
    let l_x = l_shl(l_x, exp);
    exp = sub(31, exp);
    let l_x = isqrt_lc(l_x, &mut exp);
    l_shl(l_x, exp)
}

/// `Isqrt_lc`: `1 / sqrt(frac · 2^exp)` for a normalised mantissa `frac` (Q31), returned as a Q31
/// mantissa with its exponent written back to `exp`. A non-positive `frac` yields `0x7fffffff`
/// with `exp = 0`.
#[must_use]
pub fn isqrt_lc(frac: i32, exp: &mut i16) -> i32 {
    if frac <= 0 {
        *exp = 0;
        return 0x7fff_ffff;
    }
    // An odd exponent shifts one place further, folding the half power of two into the mantissa.
    let l_tmp = l_shr(frac, SHIFT_ISQRT_LC[(*exp & 1) as usize]);
    // exp = -(exp - 1) / 2, rounded.
    *exp = mac_r(32768, *exp, -16384);
    let a = lshr(extract_l(l_tmp), 1);
    // A normalised positive `frac` puts `i` in 0..48 (bits 25..30 of the shifted mantissa, less 16).
    let i = mac_r(l_tmp, -16 * 2 - 1, 16384).clamp(0, 47) as usize;
    l_msu(L_TABLE_ISQRT[i], TABLE_ISQRT_DIFF[i], a)
}

/// `Pow2`: `2^(exponant + fraction)` with `fraction` Q15 in `[0, 1)`, as a Q0 32-bit value
/// (`exponant` in 0..=30).
#[must_use]
pub fn pow2(exponant: i16, fraction: i16) -> i32 {
    // The top five bits of the fraction index the table, the low ten interpolate.
    let i = mac_r(-32768, fraction, 32);
    let a = fraction & 0x3ff;
    // `fraction` < 0 is outside the contract (the reference reads before the table); clamp.
    let i = i.clamp(0, 31) as usize;
    let mut l_x = l_deposit_h(TABLE_POW2[i]);
    l_x = l_mac(l_x, TABLE_POW2_DIFF_X32[i], a);
    let exp = sub(30, exponant);
    l_shr_r(l_x, exp)
}

/// `Dot_product12`: `sum(x[i]·y[i]) · 2 + 1` over `lg` samples, normalised; the mantissa is
/// returned and its exponent (`30 - norm`) written to `exp`.
#[must_use]
pub fn dot_product12(x: &[i16], y: &[i16], lg: i16, exp: &mut i16) -> i32 {
    let mut l_sum = l_mac(1, x[0], y[0]);
    for i in 1..lg as usize {
        l_sum = l_mac(l_sum, x[i], y[i]);
    }
    let sft = norm_l(l_sum);
    l_sum = l_shl(l_sum, sft);
    *exp = sub(30, sft);
    l_sum
}

/// `Sqrt_l`: `sqrt(L_x)` of a 32-bit value, as a Q31 mantissa; the (even) normalisation shift is
/// written to `exp`, so the root is `result · 2^(-exp/2)`. A non-positive input yields 0.
#[must_use]
pub fn sqrt_l(l_x: i32, exp: &mut i16) -> i32 {
    if l_x <= 0 {
        *exp = 0;
        return 0;
    }
    let e = norm_l(l_x) & 0x7ffe;
    let mut l_x = l_shl(l_x, e);
    *exp = e;
    l_x = l_shr(l_x, 9);
    let a = lshr(extract_l(l_x), 1);
    // Bits 25..30 of the (evenly) normalised input, less 16: 0..48 for any positive input.
    let i = mac_r(l_x, -16 * 2 - 1, 16384).clamp(0, 47) as usize;
    let mut l_y = l_deposit_h(SQRT_TABLE[i]);
    let tmp = sub(SQRT_TABLE[i], SQRT_TABLE[i + 1]);
    l_y = l_msu(l_y, tmp, a);
    l_y
}

/// `L_Frac_sqrtQ31`: `sqrt(x)` of a Q31 value in `(0, 1)`, as Q31, through `2^(log2(x) / 2)`.
/// A non-positive input yields 0.
#[must_use]
pub fn l_frac_sqrt_q31(x: i32) -> i32 {
    if x > 0 {
        let log2_int = norm_l(x);
        let log2_frac = log2_norm_lc(l_shl(x, log2_int));
        // log2(x) / 2 + 30 in Q16: (31 + 30 - log2_int) / 2 from the exponent, plus the fraction.
        let mut log2_work = l_msu((31 + 30) * 65536 / 2, 16384, log2_int);
        log2_work = l_mac0(log2_work, log2_frac, 1);
        let (log2_int, log2_frac) = l_extract_lc(log2_work);
        return pow2(log2_int, log2_frac);
    }
    0
}

/// `Frac_sqrt`: `sqrt(x)` of a Q15 value, as Q15.
#[must_use]
pub fn frac_sqrt(x: i16) -> i16 {
    round_word(l_frac_sqrt_q31(l_deposit_h(x)))
}

/// `i_mult2`: the low 16 bits of the integer product `a·b` (wrapping, no saturation, unlike the
/// STL `i_mult`).
#[inline]
#[must_use]
pub const fn i_mult2(a: i16, b: i16) -> i16 {
    extract_l(l_mult0(a, b))
}

/// `Energy_scale`: `1 + Σ 2·x[i]²` over `lg` samples, each sample first scaled by `2^expi`
/// (a negative `expi` through `mult_r` by `lshl(0x8000, expi)`, as the reference does), normalised
/// to a Q31 mantissa; its exponent (`30 - norm`, 0..30) goes to `exp`.
#[must_use]
pub fn energy_scale(x: &[i16], lg: i16, expi: i16, exp: &mut i16) -> i32 {
    let lg = lg.max(1) as usize;
    let mut l_sum: i32 = 0;
    if expi == 0 {
        l_sum = l_mac(1, x[0], x[0]);
        for &value in &x[1..lg] {
            l_sum = l_mac(l_sum, value, value);
        }
    }
    if expi < 0 {
        let sft = lshl(-32768, expi);
        let mut tmp = mult_r(x[0], sft);
        l_sum = l_mac(1, tmp, tmp);
        for &value in &x[1..lg] {
            tmp = mult_r(value, sft);
            l_sum = l_mac(l_sum, tmp, tmp);
        }
    }
    if expi > 0 {
        let mut tmp = shl(x[0], expi);
        l_sum = l_mac(1, tmp, tmp);
        for &value in &x[1..lg] {
            tmp = shl(value, expi);
            l_sum = l_mac(l_sum, tmp, tmp);
        }
    }
    // Normalize acc in Q31
    let sft = norm_l(l_sum);
    l_sum = l_shl(l_sum, sft);
    *exp = sub(30, sft); // exponent = 0..30
    l_sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_positive_inputs_take_the_early_returns() {
        let mut exp = 9;
        assert_eq!(isqrt_lc(0, &mut exp), 0x7fff_ffff);
        assert_eq!(exp, 0);
        let mut exp = 9;
        assert_eq!(sqrt_l(-1, &mut exp), 0);
        assert_eq!(exp, 0);
        assert_eq!(l_frac_sqrt_q31(0), 0);
    }

    #[test]
    fn i_mult2_wraps_instead_of_saturating() {
        assert_eq!(i_mult2(300, 300), (90000_i32 as i16));
        assert_eq!(i_mult2(-3, 7), -21);
    }

    #[test]
    fn pow2_of_an_integer_exponent_is_the_power() {
        assert_eq!(pow2(14, 0), 16384);
        assert_eq!(pow2(0, 0), 1);
    }
}
