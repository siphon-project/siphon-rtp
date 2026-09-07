//! G.729's transcendental approximations: `Pow2`, `Log2` and `Inv_sqrt` (ITU-T G.729 Release 3
//! `dspfunc.c`).
//!
//! Each looks up one of the shared interpolation tables in [`crate::itu::tables`] and interpolates
//! linearly between two of its points. The tables are shared with the AMR lineage because they are
//! the same numbers; these wrappers are **not**, because their Q formats, the direction of their
//! denormalising shift and their answers for a non-positive input all differ. That warning is
//! recorded on the tables themselves — this module is the G.729 half of it, ported against G.729's
//! own reference.

use crate::itu::basic_ops::{
    extract_h, extract_l, l_deposit_h, l_mult, l_msu, l_shl, l_shr, l_shr_r, norm_l, sub,
};
use crate::itu::tables::{ISQRT, LOG2, POW2};

/// `2^(exponent + fraction)` as a Q0 integer.
///
/// `exponent` is the integer part (0..=30) and `fraction` the Q15 fractional part (0.0..1.0). The
/// result spans 0..=0x7fff_ffff.
#[must_use]
pub fn pow2(exponent: i16, fraction: i16) -> i32 {
    // Split the Q15 fraction into a 6-bit table index and the 9-bit position between that entry and
    // the next, then interpolate down from the entry by the difference times that position.
    let mut l_x = l_mult(fraction, 32); // fraction << 6
    let i = extract_h(l_x) as usize; // b10-b15 of the fraction
    l_x = l_shr(l_x, 1);
    let a = extract_l(l_x) & 0x7fff; // b0-b9 of the fraction

    l_x = l_deposit_h(POW2[i]);
    let tmp = sub(POW2[i], POW2[i + 1]);
    l_x = l_msu(l_x, tmp, a);

    // Q30 result, brought down to the requested integer exponent. Rounding shift, unlike Log2's.
    let exp = sub(30, exponent);
    l_shr_r(l_x, exp)
}

/// `log2(l_x)` for a positive Q0 input, as an integer part (0..=30) and a Q15 fraction (0.0..1.0).
///
/// A non-positive input yields `(0, 0)` — the reference's own answer, since the logarithm is
/// undefined there and it declines to saturate into a value a caller might use.
#[must_use]
pub fn log2(l_x: i32) -> (i16, i16) {
    if l_x <= 0 {
        return (0, 0);
    }
    let exp = norm_l(l_x);
    let mut l_x = l_shl(l_x, exp);
    let exponent = sub(30, exp);

    l_x = l_shr(l_x, 9);
    let i = extract_h(l_x); // b25-b31
    l_x = l_shr(l_x, 1);
    let a = extract_l(l_x) & 0x7fff; // b10-b24

    let i = sub(i, 32) as usize;
    let mut l_y = l_deposit_h(LOG2[i]);
    let tmp = sub(LOG2[i], LOG2[i + 1]);
    l_y = l_msu(l_y, tmp, a);

    (exponent, extract_h(l_y))
}

/// `1/sqrt(l_x)` for a Q0 input, as a Q30 result in 0..1.
///
/// A non-positive input yields `0x3fff_ffff`, which is 1.0 in Q30 — the reference's answer, and
/// deliberately not AMR-WB's `0x7fff_ffff`, which is 1.0 in *Q31*. The two differ by a factor of
/// two and nothing downstream would notice but the vectors.
#[must_use]
pub fn inv_sqrt(l_x: i32) -> i32 {
    if l_x <= 0 {
        return 0x3fff_ffff;
    }
    let exp = norm_l(l_x);
    let mut l_x = l_shl(l_x, exp);

    // Halve the exponent, since the result is a square root; an even exponent needs the mantissa
    // shifted down first so the halving stays exact.
    let mut exp = sub(30, exp);
    if (exp & 1) == 0 {
        l_x = l_shr(l_x, 1);
    }
    exp = l_shr(i32::from(exp), 1) as i16;
    exp += 1;

    l_x = l_shr(l_x, 9);
    let i = extract_h(l_x); // b25-b31
    l_x = l_shr(l_x, 1);
    let a = extract_l(l_x) & 0x7fff; // b10-b24

    let i = sub(i, 16) as usize;
    let mut l_y = l_deposit_h(ISQRT[i]);
    let tmp = sub(ISQRT[i], ISQRT[i + 1]);
    l_y = l_msu(l_y, tmp, a);

    // Denormalise by shifting *right*, where the AMR-WB routine shifts left.
    l_shr(l_y, exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute error of `value` (Q`q`) against `expected` as a real number, in units of the last
    /// place, so a tolerance can be stated in representable steps rather than in floats.
    fn ulps(value: i32, q: u32, expected: f64) -> f64 {
        let scale = f64::from(1_u32 << q);
        (f64::from(value) - expected * scale).abs()
    }

    #[test]
    fn pow2_reproduces_its_exponent_exactly_at_a_zero_fraction() {
        // 2^n with no fractional part is exact in the table's first entry, so any drift here is a
        // scaling error rather than an interpolation one.
        for exponent in 0..=30_i16 {
            assert_eq!(pow2(exponent, 0), 1_i32 << exponent, "2^{exponent}");
        }
    }

    #[test]
    fn pow2_interpolates_between_table_points() {
        // Half-way up the fraction is 2^(n+0.5) = 2^n * sqrt(2). The result is a Q0 *integer*, so
        // the achievable accuracy is one unit in the last place of that integer, not a relative
        // figure: at 2^4.5 one ulp is already 4% of the value. Two sources of error stack — the
        // linear interpolation between table points, and the rounding shift down to Q0 — so allow
        // 1 ulp of the integer plus the interpolation's own share, which grows with the result.
        for exponent in 4..=30_i16 {
            let expected = f64::from(1_i32 << exponent) * std::f64::consts::SQRT_2;
            let got = f64::from(pow2(exponent, 16_384));
            let tolerance = 1.0 + expected * 1e-3;
            assert!(
                (got - expected).abs() <= tolerance,
                "2^{exponent}.5: got {got}, want {expected} (tolerance {tolerance})"
            );
        }
    }

    #[test]
    fn log2_inverts_pow2_across_the_range() {
        // The two are each other's inverse, which pins their shared table indexing and their
        // differing shifts against each other rather than against a hand-computed constant.
        //
        // Only above 2^12 or so, though: `Pow2` returns a Q0 integer, so round-tripping 2^1.25
        // quantises to the integer 2 and `log2` can only answer 1.0. That is the format doing its
        // job, not a defect, so the sweep starts where one integer step is small against the value.
        for exponent in 12..=30_i16 {
            for fraction in [0_i16, 8_192, 16_384, 24_576, 32_000] {
                let value = pow2(exponent, fraction);
                assert!(value > 0, "2^{exponent}.{fraction} is representable");
                let (back_exponent, back_fraction) = log2(value);
                let want = f64::from(exponent) + f64::from(fraction) / 32_768.0;
                let got = f64::from(back_exponent) + f64::from(back_fraction) / 32_768.0;
                assert!(
                    (got - want).abs() < 0.01,
                    "log2(2^{want}) = {got} (value {value})"
                );
            }
        }
    }

    #[test]
    fn log2_of_a_power_of_two_is_that_power_with_no_fraction() {
        for exponent in 0..=30_i16 {
            let (integer, fraction) = log2(1_i32 << exponent);
            assert_eq!(integer, exponent, "log2(2^{exponent}) integer part");
            assert_eq!(fraction, 0, "log2(2^{exponent}) fractional part");
        }
    }

    #[test]
    fn log2_of_a_non_positive_input_is_zero_rather_than_saturated() {
        assert_eq!(log2(0), (0, 0));
        assert_eq!(log2(-1), (0, 0));
        assert_eq!(log2(i32::MIN), (0, 0));
    }

    #[test]
    fn inv_sqrt_matches_the_real_reciprocal_square_root_in_q30() {
        // Q30, so 1.0 is 0x40000000 — half of AMR-WB's Q31 answer for the same input, which is the
        // difference this module exists to keep.
        for value in [1_i32, 2, 3, 4, 100, 1_000, 65_536, 1_000_000, 1 << 30] {
            let expected = 1.0 / f64::from(value).sqrt();
            let got = inv_sqrt(value);
            let error = ulps(got, 30, expected) / f64::from(1_u32 << 30);
            assert!(
                error < 2e-3,
                "1/sqrt({value}): got {got} (~{}), want {expected}",
                f64::from(got) / f64::from(1_u32 << 30)
            );
        }
    }

    #[test]
    fn inv_sqrt_of_a_non_positive_input_is_one_in_q30_not_q31() {
        // The single most likely way to get this wrong is to borrow AMR-WB's constant, which is
        // 0x7fffffff. That would be 2.0 here and would still decode to something speech-shaped.
        assert_eq!(inv_sqrt(0), 0x3fff_ffff);
        assert_eq!(inv_sqrt(-5), 0x3fff_ffff);
        assert_eq!(inv_sqrt(i32::MIN), 0x3fff_ffff);
    }

    #[test]
    fn inv_sqrt_is_monotonically_decreasing() {
        let mut previous = i32::MAX;
        for value in (1..2_000_000).step_by(9_973) {
            let got = inv_sqrt(value);
            assert!(got <= previous, "1/sqrt fell then rose at {value}");
            previous = got;
        }
    }
}
