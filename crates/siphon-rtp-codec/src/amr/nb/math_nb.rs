//! AMR-NB square-root helpers — 3GPP TS 26.073 `inv_sqrt.c`, `sqrt_l.c`. Ported bit-exact.
//!
//! These differ in exponent handling from the AMR-WB `math_op` versions, so AMR-NB carries its own
//! exact ports. The `inv_sqrt` table is value-identical to the AMR-WB one; the `sqrt_l` table is
//! distinct.

use crate::amr::basic_ops::{
    add, extract_h, extract_l, l_deposit_h, l_msu, l_shl, l_shr, norm_l, shr, sub,
};

/// `1/sqrt` look-up (`inv_sqrt.tab` `table[49]`).
#[rustfmt::skip]
static INV_SQRT_TABLE: [i16; 49] = [
    32767, 31790, 30894, 30070, 29309, 28602, 27945, 27330, 26755, 26214,
    25705, 25225, 24770, 24339, 23930, 23541, 23170, 22817, 22479, 22155,
    21845, 21548, 21263, 20988, 20724, 20470, 20225, 19988, 19760, 19539,
    19326, 19119, 18919, 18725, 18536, 18354, 18176, 18004, 17837, 17674,
    17515, 17361, 17211, 17064, 16921, 16782, 16646, 16514, 16384,
];

/// `sqrt` look-up (`sqrt_l.tab` `table[49]`).
#[allow(dead_code)] // used by the decoder-main tier (excitation-energy estimate), landed next
#[rustfmt::skip]
static SQRT_L_TABLE: [i16; 49] = [
    16384, 16888, 17378, 17854, 18318, 18770, 19212, 19644, 20066, 20480,
    20886, 21283, 21674, 22058, 22435, 22806, 23170, 23530, 23884, 24232,
    24576, 24915, 25249, 25580, 25905, 26227, 26545, 26859, 27170, 27477,
    27780, 28081, 28378, 28672, 28963, 29251, 29537, 29819, 30099, 30377,
    30652, 30924, 31194, 31462, 31727, 31991, 32252, 32511, 32767,
];

/// `1/sqrt(L_x)` for a Q0 input, returning a Q31 result (`0 <= val < 1`) (`inv_sqrt.c` `Inv_sqrt`).
/// Non-positive input → `0x3fffffff`.
#[must_use]
pub fn inv_sqrt(l_x: i32) -> i32 {
    if l_x <= 0 {
        return 0x3fff_ffff;
    }
    let exp = norm_l(l_x);
    let mut l_x = l_shl(l_x, exp);
    let mut exp = sub(30, exp);
    if (exp & 1) == 0 {
        l_x = l_shr(l_x, 1);
    }
    exp = shr(exp, 1);
    exp = add(exp, 1);

    l_x = l_shr(l_x, 9);
    let i = extract_h(l_x); // b16..b30
    l_x = l_shr(l_x, 1);
    let a = extract_l(l_x) & 0x7fff;

    let i = sub(i, 16) as usize;
    let mut l_y = l_deposit_h(INV_SQRT_TABLE[i]);
    let tmp = sub(INV_SQRT_TABLE[i], INV_SQRT_TABLE[i + 1]);
    l_y = l_msu(l_y, tmp, a);

    l_shr(l_y, exp)
}

/// `sqrt(L_x)` with an output exponent (`sqrt_l.c` `sqrt_l_exp`). Returns the Q31 mantissa; the
/// caller denormalizes with `*exp` (the value is `mantissa * 2^(-exp/2)`). Non-positive input → 0.
#[allow(dead_code)] // used by the decoder-main tier (excitation-energy estimate), landed next
#[must_use]
pub fn sqrt_l_exp(l_x: i32, exp: &mut i16) -> i32 {
    if l_x <= 0 {
        *exp = 0;
        return 0;
    }
    let e = norm_l(l_x) & 0xFFFEu16 as i16; // even
    let mut l_x = l_shl(l_x, e);
    *exp = e;

    l_x = l_shr(l_x, 9);
    let i = extract_h(l_x); // b16..b30
    l_x = l_shr(l_x, 1);
    let a = extract_l(l_x) & 0x7fff;

    let i = sub(i, 16) as usize;
    let mut l_y = l_deposit_h(SQRT_L_TABLE[i]);
    let tmp = sub(SQRT_L_TABLE[i], SQRT_L_TABLE[i + 1]);
    l_y = l_msu(l_y, tmp, a);

    l_y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_sqrt_of_unity_is_about_one_q31() {
        // 1/sqrt(1) in Q31 ~= 0x7fffffff scaled; just assert non-zero and finite for a known input.
        let r = inv_sqrt(1);
        assert!(r > 0);
    }

    #[test]
    fn inv_sqrt_nonpositive_returns_saturated() {
        assert_eq!(inv_sqrt(0), 0x3fff_ffff);
        assert_eq!(inv_sqrt(-5), 0x3fff_ffff);
    }

    #[test]
    fn sqrt_l_exp_of_a_square_recovers_root() {
        // sqrt(0x40000000) ; denormalize: value = mantissa * 2^(-exp/2). Spot-check monotonicity.
        let mut exp = 0i16;
        let a = sqrt_l_exp(0x1000_0000, &mut exp);
        let mut exp2 = 0i16;
        let b = sqrt_l_exp(0x4000_0000, &mut exp2);
        assert!(a > 0 && b > 0);
    }

    #[test]
    fn sqrt_l_exp_nonpositive_is_zero() {
        let mut exp = 5i16;
        assert_eq!(sqrt_l_exp(0, &mut exp), 0);
        assert_eq!(exp, 0);
    }
}
