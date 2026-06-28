//! Fixed-point math operators for the AMR-WB codec (3GPP TS 26.173 `math_op.c` / `log2.c` /
//! `random.c`), ported bit-exact on top of [`super::basic_ops`].
//!
//! These are the table-and-interpolation approximations the codec uses where 16-bit precision is
//! enough: inverse square root, `2^x`, `log2`, the normalized dot product, and the LCG noise source.
//! They operate on the codec's own validated internal state (never raw network bytes), so they
//! mirror the reference's direct table indexing exactly — diverging would break bit-exactness.

use super::basic_ops::{
    extract_h, extract_l, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, l_shr_r, negate,
    norm_l, shr, sub,
};

/// `1/sqrt` table (TS 26.173 `math_op.c`), 49 entries.
#[rustfmt::skip]
static TABLE_ISQRT: [i16; 49] = [
    32767, 31790, 30894, 30070, 29309, 28602, 27945, 27330, 26755, 26214,
    25705, 25225, 24770, 24339, 23930, 23541, 23170, 22817, 22479, 22155,
    21845, 21548, 21263, 20988, 20724, 20470, 20225, 19988, 19760, 19539,
    19326, 19119, 18919, 18725, 18536, 18354, 18176, 18004, 17837, 17674,
    17515, 17361, 17211, 17064, 16921, 16782, 16646, 16514, 16384,
];

/// `2^x` table (TS 26.173 `math_op.c`), 33 entries.
#[rustfmt::skip]
static TABLE_POW2: [i16; 33] = [
    16384, 16743, 17109, 17484, 17867, 18258, 18658, 19066, 19484, 19911,
    20347, 20792, 21247, 21713, 22188, 22674, 23170, 23678, 24196, 24726,
    25268, 25821, 26386, 26964, 27554, 28158, 28774, 29405, 30048, 30706,
    31379, 32066, 32767,
];

/// `log2` table (TS 26.173 `log2_tab.h`), 33 entries.
#[rustfmt::skip]
static TABLE_LOG2: [i16; 33] = [
    0, 1455, 2866, 4236, 5568, 6863, 8124, 9352, 10549, 11716,
    12855, 13967, 15054, 16117, 17156, 18172, 19167, 20142, 21097, 22033,
    22951, 23852, 24735, 25603, 26455, 27291, 28113, 28922, 29716, 30497,
    31266, 32023, 32767,
];

/// Inverse square root `1/sqrt(value)` of a normalized fraction, in place.
///
/// `frac` is Q31 normalized (`0.5 < frac <= 1.0`) and `exp` its exponent; on return `frac`·2^`exp`
/// is `1/sqrt` of the input. Negative/zero input yields `frac = 0x7fffffff`, `exp = 0`.
pub fn isqrt_n(frac: &mut i32, exp: &mut i16) {
    if *frac <= 0 {
        *exp = 0;
        *frac = 0x7fff_ffff;
        return;
    }
    if (*exp & 1) == 1 {
        *frac = l_shr(*frac, 1); // odd exponent → shift fraction right once
    }
    *exp = negate(shr(sub(*exp, 1), 1));

    *frac = l_shr(*frac, 9);
    let i = extract_h(*frac); // b25-b31
    *frac = l_shr(*frac, 1);
    let a = extract_l(*frac) & 0x7fff; // b10-b24

    let i = sub(i, 16) as usize;
    *frac = l_deposit_h(TABLE_ISQRT[i]);
    let tmp = sub(TABLE_ISQRT[i], TABLE_ISQRT[i + 1]);
    *frac = l_msu(*frac, tmp, a);
}

/// `1/sqrt(L_x)` for a Q0 input, returning a Q31 result (`0 <= val < 1`). Negative/zero → `0x7fffffff`.
#[must_use]
pub fn isqrt(mut l_x: i32) -> i32 {
    let mut exp = norm_l(l_x);
    l_x = l_shl(l_x, exp);
    exp = sub(31, exp);
    isqrt_n(&mut l_x, &mut exp);
    l_shl(l_x, exp)
}

/// `pow(2, exponant.fraction)` as a Q0 integer (`0 <= val <= 0x7fffffff`); `fraction` is Q15.
#[must_use]
pub fn pow2(exponant: i16, fraction: i16) -> i32 {
    let mut l_x = l_mult(fraction, 32); // fraction << 6
    let i = extract_h(l_x); // b10-b15 of fraction
    l_x = l_shr(l_x, 1);
    let a = extract_l(l_x) & 0x7fff; // b0-b9 of fraction

    let i = i as usize;
    l_x = l_deposit_h(TABLE_POW2[i]);
    let tmp = sub(TABLE_POW2[i], TABLE_POW2[i + 1]);
    l_x = l_msu(l_x, tmp, a);

    let exp = sub(30, exponant);
    l_shr_r(l_x, exp)
}

/// `log2` of a pre-normalized `L_x` with its `norm_l` exponent, returning `(integer, fraction)`
/// where the result is `integer + fraction/32768`. Non-positive input → `(0, 0)`.
#[must_use]
pub fn log2_norm(mut l_x: i32, exp: i16) -> (i16, i16) {
    if l_x <= 0 {
        return (0, 0);
    }
    let exponent = sub(30, exp);

    l_x = l_shr(l_x, 9);
    let i = extract_h(l_x); // b25-b31
    l_x = l_shr(l_x, 1);
    let a = extract_l(l_x) & 0x7fff; // b10-b24

    let i = sub(i, 32) as usize;
    let mut l_y = l_deposit_h(TABLE_LOG2[i]);
    let tmp = sub(TABLE_LOG2[i], TABLE_LOG2[i + 1]);
    l_y = l_msu(l_y, tmp, a);

    (exponent, extract_h(l_y))
}

/// `log2(L_x)` for a positive `L_x`, returning `(integer, fraction)`. Non-positive input → `(0, 0)`.
#[must_use]
pub fn log2(l_x: i32) -> (i16, i16) {
    let exp = norm_l(l_x);
    log2_norm(l_shl(l_x, exp), exp)
}

/// Normalized scalar product `sum(x[i]*y[i])`, returning `(mantissa_q31, exponent)` (exponent 0..30).
#[must_use]
pub fn dot_product12(x: &[i16], y: &[i16], lg: usize) -> (i32, i16) {
    let mut l_sum = 1i32;
    for i in 0..lg {
        l_sum = l_mac(l_sum, x[i], y[i]);
    }
    let sft = norm_l(l_sum);
    l_sum = l_shl(l_sum, sft);
    (l_sum, sub(30, sft))
}

/// The codec's LCG noise source: advances `*seed` and returns it (TS 26.173 `random.c`).
pub fn random(seed: &mut i16) -> i16 {
    *seed = extract_l(l_add(l_shr(l_mult(*seed, 31821), 1), 13849));
    *seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow2_of_zero_is_one() {
        // 2^(0 + 0/32768) = 1 (Q0).
        assert_eq!(pow2(0, 0), 1);
    }

    #[test]
    fn pow2_of_thirty_is_two_pow_thirty() {
        // 2^30 with zero fraction → table[0]<<16 then >>0.
        assert_eq!(pow2(30, 0), 0x4000_0000);
    }

    #[test]
    fn log2_of_two_pow_thirty_is_thirty() {
        // L_x = 2^30 (0x40000000) → log2 = 30.0 exactly.
        assert_eq!(log2(0x4000_0000), (30, 0));
    }

    #[test]
    fn log2_and_pow2_are_inverse_on_a_known_point() {
        // log2(2^30) = 30.0, and pow2(30, 0) = 2^30.
        let (int, frac) = log2(0x4000_0000);
        assert_eq!(pow2(int, frac), 0x4000_0000);
    }

    #[test]
    fn isqrt_of_one_is_near_unity_q31() {
        // 1/sqrt(1) = 1.0 → 0x7FFF0000 (the table approximation of 1.0 in Q31).
        assert_eq!(isqrt(1), 0x7fff_0000);
    }

    #[test]
    fn isqrt_of_zero_saturates() {
        assert_eq!(isqrt(0), 0x7fff_ffff);
    }

    #[test]
    fn dot_product12_normalizes_with_exponent() {
        // 0x4000 · 0x4000 = 1 + (0x4000*0x4000<<1) = 0x20000001 → normalized <<1, exp 29.
        let x = [0x4000i16];
        let y = [0x4000i16];
        assert_eq!(dot_product12(&x, &y, 1), (0x4000_0002, 29));
    }

    #[test]
    fn random_advances_deterministically() {
        // seed = extract_l(L_add(L_shr(L_mult(21845, 31821), 1), 13849)) = 3242.
        let mut seed = 21845i16;
        assert_eq!(random(&mut seed), 3242);
        assert_eq!(seed, 3242);
        // Deterministic: same start seed reproduces the sequence.
        let mut a = 1i16;
        let mut b = 1i16;
        for _ in 0..16 {
            assert_eq!(random(&mut a), random(&mut b));
        }
    }
}
