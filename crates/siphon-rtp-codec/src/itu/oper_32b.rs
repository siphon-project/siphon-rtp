//! Double-precision-format (DPF) 32-bit operators for the AMR-WB codec (3GPP TS 26.173
//! `oper_32b.c`), ported bit-exact on top of [`super::basic_ops`].
//!
//! A 32-bit value is carried as a `(hi, lo)` pair where `L_32 = hi<<16 + lo<<1` (the low part holds
//! the sign, which makes the multiplies cheap). These give ~24-bit precision where full 32-bit
//! double precision is unnecessary but single precision is not enough — used by the LPC inversion,
//! synthesis filter, and gain prediction.

use super::basic_ops::{
    div_s, extract_h, extract_l, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub, mult,
};

/// Split a 32-bit integer into the DPF pair `(hi, lo)` with `hi = L_32>>16`, `lo = (L_32 - hi<<16)>>1`.
#[must_use]
pub fn l_extract(l_32: i32) -> (i16, i16) {
    let hi = extract_h(l_32);
    let lo = extract_l(l_msu(l_shr(l_32, 1), hi, 16384));
    (hi, lo)
}

/// Compose a 32-bit integer from a DPF pair: `hi<<16 + lo<<1`.
#[must_use]
pub fn l_comp(hi: i16, lo: i16) -> i32 {
    l_mac(l_deposit_h(hi), lo, 1)
}

/// Multiply two DPF numbers (each a Q31), result in Q31 (`(hi1·hi2 + (hi1·lo2 + lo1·hi2)>>15)`).
#[must_use]
pub fn mpy_32(hi1: i16, lo1: i16, hi2: i16, lo2: i16) -> i32 {
    let mut l_32 = l_mult(hi1, hi2);
    l_32 = l_mac(l_32, mult(hi1, lo2), 1);
    l_32 = l_mac(l_32, mult(lo1, hi2), 1);
    l_32
}

/// Multiply a DPF number `(hi, lo)` by a 16-bit `n`, result `(hi·n + (lo·n)>>15)<<1`.
#[must_use]
pub fn mpy_32_16(hi: i16, lo: i16, n: i16) -> i32 {
    let mut l_32 = l_mult(hi, n);
    l_32 = l_mac(l_32, mult(lo, n), 1);
    l_32
}

/// Fractional 32-bit division `L_num / L_denom` (~24-bit precision). Requires `0 < L_num < L_denom`,
/// `L_denom = denom_hi<<16 + denom_lo<<1` with `denom_hi` normalized (`0x4000 < denom_hi < 0x7fff`).
#[must_use]
pub fn div_32(l_num: i32, denom_hi: i16, denom_lo: i16) -> i32 {
    // First approximation: 1/L_denom ≈ 1/denom_hi.
    let approx = div_s(0x3fff, denom_hi);
    // Newton step: 1/L_denom = approx * (2.0 - L_denom * approx).
    let mut l_32 = mpy_32_16(denom_hi, denom_lo, approx);
    l_32 = l_sub(0x7fff_ffff, l_32);
    let (hi, lo) = l_extract(l_32);
    l_32 = mpy_32_16(hi, lo, approx);
    // result = L_num * (1/L_denom).
    let (hi, lo) = l_extract(l_32);
    let (n_hi, n_lo) = l_extract(l_num);
    l_32 = mpy_32(n_hi, n_lo, hi, lo);
    l_shl(l_32, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_then_compose_round_trips() {
        // An even low part round-trips exactly through the DPF split (the low LSB is dropped by >>1).
        let value = 0x1234_5678;
        let (hi, lo) = l_extract(value);
        assert_eq!(hi, 0x1234);
        assert_eq!(l_comp(hi, lo), value);
    }

    #[test]
    fn mpy_32_16_is_q31_times_q15() {
        // 0.5 (Q31 DPF: hi=0x4000, lo=0) × 0.5 (Q15 = 0x4000) = 0.25 (Q31 = 0x20000000).
        assert_eq!(mpy_32_16(0x4000, 0, 0x4000), 0x2000_0000);
    }

    #[test]
    fn mpy_32_multiplies_two_q31() {
        // 0.5 × 0.5 = 0.25 in Q31.
        assert_eq!(mpy_32(0x4000, 0, 0x4000, 0), 0x2000_0000);
    }

    #[test]
    fn div_32_approximates_the_quotient() {
        // 0.25 / 0.5 = 0.5 (Q31 ≈ 0x40000000), within the ~24-bit precision.
        let result = div_32(0x2000_0000, 0x4000, 0);
        assert!(
            (result - 0x4000_0000).abs() < 0x1000,
            "div_32 = {result:#x}, want ~0x40000000"
        );
    }
}
