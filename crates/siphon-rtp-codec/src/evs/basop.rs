//! The multiply and division helpers EVS builds on the STL operators (TS 26.442 `lib_com/basop_mpy.c`
//! and `basic_math/oper_32b.c` / `math_32.c`).
//!
//! These look like the AMR helpers in [`crate::itu::oper_32b`] and some of them are: `Mpy_32` and
//! the `(hi, lo, n)` form of `Mpy_32_16` have identical bodies in both lineages and are reused from
//! there. What is here is either new to EVS or *differs* from the AMR wrapper of the same name —
//! [`div_32`] is the case in point: AMR subtracts a finished `Mpy_32_16` from `MAX_32`, EVS runs the
//! subtraction through two chained `L_msu` steps, and the two saturate at different points. Sharing
//! the wrapper would be a bit-exactness bug no round trip could see (the `itu` module doc gives the
//! general warning).
//!
//! `ALLOW_40bits` is defined in the reference's `stl.h`, so `Madd_32_16` / `Msub_32_16` take their
//! 40-bit branch: the 32x16 product through `Mpy_32_16_ss`, not the hand-built DPF fallback.

use crate::itu::basic_ops::{div_s, extract_h, extract_l, l_add, l_mac, l_msu, l_shl, l_sub, mult};
use crate::itu::oper_32b::{mpy_32, mpy_32_16};
use crate::itu::stl2009::{lshr, mpy_32_16_ss, mpy_32_32_ss};

/// `x · y` for a Q31 `x` and a Q15 `y`, truncated to Q31 (`Mpy_32_16_1`).
#[inline]
#[must_use]
pub const fn mpy_32_16_1(x: i32, y: i16) -> i32 {
    mpy_32_16_ss(x, y).0
}

/// `x · y` for a Q31 `x` and a Q15 `y`, rounded to Q31 (`Mpy_32_16_r`).
#[inline]
#[must_use]
pub fn mpy_32_16_r(x: i32, y: i16) -> i32 {
    let (high, low) = mpy_32_16_ss(x, y);
    if low & 0x8000 != 0 {
        l_add(high, 1)
    } else {
        high
    }
}

/// `x · y` for two Q31 values, truncated to Q31 (`Mpy_32_32`).
#[inline]
#[must_use]
pub const fn mpy_32_32(x: i32, y: i32) -> i32 {
    mpy_32_32_ss(x, y).0
}

/// `x · y` for two Q31 values, rounded to Q31 (`Mpy_32_32_r`).
#[inline]
#[must_use]
pub fn mpy_32_32_r(x: i32, y: i32) -> i32 {
    let (high, low) = mpy_32_32_ss(x, y);
    if low & 0x8000_0000 != 0 {
        l_add(high, 1)
    } else {
        high
    }
}

/// `L_num + a·b` with the product through [`mpy_32_16_1`] (`Madd_32_16`, `ALLOW_40bits` branch).
#[inline]
#[must_use]
pub fn madd_32_16(l_num: i32, a: i32, b: i16) -> i32 {
    l_add(l_num, mpy_32_16_1(a, b))
}

/// `L_num - a·b` with the product through [`mpy_32_16_1`] (`Msub_32_16`, `ALLOW_40bits` branch).
#[inline]
#[must_use]
pub fn msub_32_16(l_num: i32, a: i32, b: i16) -> i32 {
    l_sub(l_num, mpy_32_16_1(a, b))
}

/// Split a 32-bit value into `(hi, lo)` with `lo` the low half shifted logically right by one
/// (`L_Extract_lc`). Equal to the AMR `L_Extract` for every input; kept under its own name because
/// the EVS division below is written against it.
#[inline]
#[must_use]
pub fn l_extract_lc(l_32: i32) -> (i16, i16) {
    (extract_h(l_32), lshr(extract_l(l_32), 1))
}

/// `L_num + (hi, lo)·n` on a DPF value (`Mac_32_16`).
#[inline]
#[must_use]
pub fn mac_32_16(l_num: i32, hi: i16, lo: i16, n: i16) -> i32 {
    l_mac(l_mac(l_num, hi, n), mult(lo, n), 1)
}

/// `L_num - (hi, lo)·n` on a DPF value (`Msu_32_16`).
#[inline]
#[must_use]
pub fn msu_32_16(l_num: i32, hi: i16, lo: i16, n: i16) -> i32 {
    l_msu(l_msu(l_num, hi, n), mult(lo, n), 1)
}

/// Fractional 32-bit division `L_num / L_denom` with `L_denom = denom_hi<<16 + denom_lo<<1`
/// (EVS `Div_32`, `basic_math/oper_32b.c`).
///
/// Requires `0 <= L_num < L_denom` and a normalised denominator (`0x4000 <= denom_hi`), which every
/// caller establishes. Differs from [`crate::itu::oper_32b::div_32`] in how the Newton step's
/// `2 - L_denom·approx` is formed; see the module doc.
#[must_use]
pub fn div_32(l_num: i32, denom_hi: i16, denom_lo: i16) -> i32 {
    // First approximation: 1 / L_denom = 1 / denom_hi.
    let approx = div_s(0x3fff, denom_hi);
    // 1 / L_denom = approx · (2.0 - L_denom · approx).
    let l_32 = msu_32_16(i32::MAX, denom_hi, denom_lo, approx);
    let (hi, lo) = l_extract_lc(l_32);
    let l_32 = mpy_32_16(hi, lo, approx);
    // L_num · (1 / L_denom).
    let (hi, lo) = l_extract_lc(l_32);
    let (n_hi, n_lo) = l_extract_lc(l_num);
    l_shl(mpy_32(n_hi, n_lo, hi, lo), 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values come from the TS 26.442 C (`basop_mpy.c`, `oper_32b.c`, `math_32.c`) built with
    // `-fwrapv` through `reference/evs/oracle/basop_oracle.c`; `tests/evs_basop_oracle.rs` runs the
    // same build over a large edge-heavy corpus.

    #[test]
    fn mpy_32_16_variants_truncate_or_round_the_q31_product() {
        assert_eq!(mpy_32_16_1(0x4000_0000, 0x4000), 0x2000_0000);
        assert_eq!(mpy_32_16_1(i32::MIN, i16::MIN), i32::MAX);
        assert_eq!(mpy_32_16_1(-1, 1), -1);
        assert_eq!(mpy_32_16_r(-1, 1), 0);
        assert_eq!(mpy_32_16_r(0x1234_5678, -12345), -115_063_740);
    }

    #[test]
    fn mpy_32_32_variants_truncate_or_round_the_q31_product() {
        assert_eq!(mpy_32_32(0x4000_0000, 0x4000_0000), 0x2000_0000);
        assert_eq!(mpy_32_32(i32::MIN, i32::MIN), i32::MAX);
        assert_eq!(mpy_32_32(-1, 1), -1);
        assert_eq!(mpy_32_32_r(-1, 1), 0);
    }

    #[test]
    fn madd_and_msub_saturate_the_accumulation() {
        assert_eq!(madd_32_16(i32::MAX, 0x4000_0000, 0x4000), i32::MAX);
        assert_eq!(msub_32_16(i32::MIN, 0x4000_0000, 0x4000), i32::MIN);
        assert_eq!(madd_32_16(5, 0x4000_0000, 0x4000), 0x2000_0005);
    }

    #[test]
    fn l_extract_lc_matches_the_amr_split() {
        for value in [
            0,
            1,
            -1,
            i32::MAX,
            i32::MIN,
            0x1234_5678,
            -0x1234_5679,
            0x0000_ffff,
        ] {
            assert_eq!(
                l_extract_lc(value),
                crate::itu::oper_32b::l_extract(value),
                "{value:#x}"
            );
        }
    }

    #[test]
    fn div_32_divides_by_a_normalised_dpf_denominator() {
        // 0.25 / 0.5 = 0.5 in Q31, within the routine's ~24-bit precision.
        assert_eq!(div_32(0x2000_0000, 0x4000, 0), 0x3fff_fff8);
        assert_eq!(div_32(0, 0x4000, 0), 0);
    }
}
