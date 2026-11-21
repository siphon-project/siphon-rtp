//! Normalised base-2 and base-10 logarithms by table interpolation (TS 26.442
//! `basic_math/log2.c`).

use crate::evs::rom::{LOG2_TAB, L_TABLE_LOG2_NORM_LC, TABLE_DIFF_LOG2_NORM_LC};
use crate::itu::basic_ops::{
    extract_h, extract_l, l_add, l_deposit_h, l_msu, l_mult, l_shl, l_shr, l_sub, norm_l, sub,
};
use crate::itu::stl2009::{l_mult0, lshr, mac_r};

/// `Log2_norm_lc`: the fractional part of `log2(L_x)` (Q15) for a normalised `L_x`
/// (`0x40000000 <= L_x`); a non-positive input is treated as `0x40000000`, whose fraction is 0.
#[must_use]
pub fn log2_norm_lc(l_x: i32) -> i16 {
    let mut l_x = l_x;
    if l_x <= 0 {
        l_x = l_deposit_h(0x4000);
    }
    l_x = l_shr(l_x, 9);
    let a = lshr(extract_l(l_x), 1);
    // i = bits 25..30 of the input, minus 32: the table index of the normalised mantissa.
    let i = mac_r(l_x, -32 * 2 - 1, 16384);
    // A normalised input keeps `i` in 0..32; anything else is the caller's contract broken, and
    // the reference would read outside the table.
    let i = i.clamp(0, 31) as usize;
    mac_r(L_TABLE_LOG2_NORM_LC[i], TABLE_DIFF_LOG2_NORM_LC[i], a)
}

/// `LW_MIN`: what [`log10`] returns for a non-positive input.
const LW_MIN: i32 = i32::MIN;

/// `log10_fx`: `10·log10(Linput)` in Q23 (the PPP coder's gains), from the 33-entry `log2_tab`
/// interpolated on the normalised mantissa; `LW_MIN` for a non-positive input.
#[must_use]
pub fn log10(linput: i32) -> i32 {
    if linput <= 0 {
        return LW_MIN;
    }
    let mut n1 = norm_l(linput);
    let mut ltemp1 = l_shl(linput, n1);

    let mut ltemp2 = l_mult(extract_h(ltemp1), 0x40);
    let frac = extract_l(ltemp2);

    // the normalised mantissa puts extract_h(Ltemp2) in 0x20..=0x3f
    let p1 = LOG2_TAB[(sub(extract_h(ltemp2), 0x20).clamp(0, 31)) as usize];
    let p2 = LOG2_TAB[(sub(extract_h(ltemp2), 0x1F).clamp(1, 32)) as usize];
    ltemp2 = l_mult(n1, 0x200);
    n1 = extract_l(ltemp2);

    ltemp1 = l_add(l_deposit_h(p1), 0x8000); // Add rounding bit

    if frac >= 0 {
        ltemp1 = l_sub(ltemp1, l_mult0(p1, frac));
        ltemp1 = l_add(ltemp1, l_mult0(p2, frac));
    } else {
        // plain C products of a 17-bit unsigned fraction and a table entry (never past 32 bits)
        let mut l_tmp = l_add(65536, i32::from(frac));
        l_tmp = l_tmp.wrapping_mul(i32::from(p1));
        ltemp1 = l_sub(ltemp1, l_tmp);

        l_tmp = l_add(65536, i32::from(frac));
        l_tmp = l_tmp.wrapping_mul(i32::from(p2));
        ltemp1 = l_add(ltemp1, l_tmp);
    }
    let q1 = extract_h(ltemp1);
    ltemp1 = l_mult(q1, 0x6054);
    ltemp1 = l_msu(ltemp1, 0x6054, n1);
    l_shr(ltemp1, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_power_of_two_has_no_fraction() {
        assert_eq!(log2_norm_lc(0x4000_0000), 0);
        assert_eq!(log2_norm_lc(0), 0);
        assert_eq!(log2_norm_lc(-5), 0);
    }
}
