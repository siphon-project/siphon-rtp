//! Range coder bit accounting (TS 26.442 `lib_com/range_com_fx.c`).

use crate::evs::cnst::RCF_INIT_SHIFT;
use crate::itu::basic_ops::{add, extract_l, l_shr, l_sub, shl, sub};
use crate::itu::stl2009::{l_lshr, mpy_32_16_uu, norm_ul};

/// `rangeCoderFinalizationFBits_fx`: the number of fractional (Q3) bits the range coder needs to
/// finalise, from its bit count `brc` and its interval `int_rc`.
#[must_use]
pub fn range_coder_finalization_f_bits(brc: i16, int_rc: u32) -> i16 {
    let f_bits = shl(add(brc, 32), 3);
    let mut b = sub(30, norm_ul(int_rc));
    let x = sub(b, RCF_INIT_SHIFT);
    let mut l_bq15: i32 = 0;
    if x >= 0 {
        // UL_lshr(INTrc, x) = (UWord32)L_lshr((Word32)INTrc, x)
        l_bq15 = l_lshr(int_rc as i32, x);
    }
    let mut e: i16 = 2;
    for _ in 1..4 {
        // u_extract_l(...) = (UWord16)extract_l(...)
        let bq15ui16 = extract_l(l_shr(l_bq15, e & 1)) as u16;
        // UL_lshl(UL_deposit_l(v), 1): a 16-bit value shifted by one never reaches the sign bit.
        let ul_tmp = u32::from(bq15ui16) << 1;
        let (h, _l) = mpy_32_16_uu(ul_tmp, bq15ui16);
        l_bq15 = h as i32;
        e = add(
            shl(b, 1),
            extract_l(l_lshr(l_sub((1 << 16) - 1, l_bq15), 31)),
        );
        b = e;
    }
    sub(f_bits, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_interval_needs_the_fewest_extra_bits() {
        // The result only falls as INTrc grows: a wider interval needs fewer finalisation bits.
        let narrow = range_coder_finalization_f_bits(10, 1 << 16);
        let wide = range_coder_finalization_f_bits(10, u32::MAX);
        assert!(wide < narrow, "{wide} vs {narrow}");
    }
}
