//! Hamming-cosine window (TS 26.442 `lib_com/window.c`).

use crate::evs::com::basop_util::get_cos_word16;
use crate::itu::basic_ops::{add, l_add, l_deposit_l, l_shl, mult_r, round_word, shl, sub};
use crate::itu::stl2009::div_l;

/// `~=round(2*PI*2^21)`
const PI2_10Q21: i32 = 13176795;
/// `~=round(2*PI*2^20)`
const PI2_11Q20: i32 = 6588397;
/// `~=round(0.54*2^15)`
const P54_0Q15: i16 = 17695;
/// `~=round(0.92*2^15)`
const P92_0Q15: i16 = 30147;

/// `ham_cos_window`: a rising Hamming half-window of `n1` samples followed by a quarter cosine of
/// `n2` samples, in `fh[0..n1 + n2]` (Q15). The reference asserts `n1 >= 102` and `n2 >= 26`
/// (below that `div_l` overflows).
pub fn ham_cos_window(fh: &mut [i16], n1: i16, n2: i16) {
    // cte = PI2/(Float32)(2*n1 - 1);
    let mut cte = l_deposit_l(div_l(PI2_10Q21, sub(shl(n1, 1), 1))); // 0Q15
    let mut cc: i32 = 0;
    for value in &mut fh[..n1 as usize] {
        // fh_f[i] = 0.54f - 0.46f * (Float32)cos(cc);
        *value = sub(
            P54_0Q15,
            mult_r(get_cos_word16(round_word(l_shl(cc, 9))), P92_0Q15),
        ); // 0Q15
        cc = l_add(cc, cte); // 0Q15
    }

    // cte = PI2/(Float32)(4*n2 - 1);
    cte = l_deposit_l(div_l(PI2_11Q20, sub(shl(n2, 2), 1))); // 0Q15
    cc = 0;

    for value in &mut fh[n1 as usize..add(n1, n2) as usize] {
        // fh_f[i] = (Float32)cos(cc);
        *value = shl(get_cos_word16(round_word(l_shl(cc, 10))), 1); // 0Q15
        cc = l_add(cc, cte);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_rises_from_the_hamming_floor_and_falls_to_zero() {
        let mut fh = [0i16; 140];
        ham_cos_window(&mut fh, 102, 38);
        // 0.54 - 0.46 = 0.08 at the start of the rise, the full cosine (1.0) at the start of the fall
        assert!((i32::from(fh[0]) - 2621).abs() < 40);
        assert!(i32::from(fh[102]) > 32000);
        assert!(i32::from(fh[139]) < 2000);
    }
}
