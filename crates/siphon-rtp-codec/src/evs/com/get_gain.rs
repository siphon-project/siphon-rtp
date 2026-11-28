//! Codebook gain from the correlation of a target and a filtered codebook vector
//! (TS 26.442 `lib_com/get_gain.c`). Only `get_gain` is ported; `get_gain2` is not reached.

use crate::evs::com::basop_util::{
    basop_util_divide_mant_exp, dot_product16_hq, dot_product_sq16_hq,
};
use crate::itu::basic_ops::{add, l_deposit_l, l_shl, round_word};
use crate::itu::stl2009::StlFlags;

/// `get_gain`: `<x, y> / <y, y>` over `n` samples, in Q16. The 64-bit accumulations go through
/// the carry operators, which is why the decoder's `flags` are threaded through.
pub fn get_gain(x: &[i16], y: &[i16], n: i16, flags: &mut StlFlags) -> i32 {
    let mut exp_c: i16 = 0;
    let mut exp_e: i16 = 0;
    let mut tmp: i16 = 0;
    let mut exp: i16 = 0;

    // Find gain based on inter-correlation product
    let tcorr = dot_product16_hq(0, x, y, n, &mut exp_c, flags);
    let tener = dot_product_sq16_hq(0, y, n, &mut exp_e, flags);

    basop_util_divide_mant_exp(
        round_word(tcorr),
        exp_c,
        round_word(tener).max(1),
        exp_e,
        &mut tmp,
        &mut exp,
    );
    l_shl(l_deposit_l(tmp) /* Q15 */, add(1, exp)) // Q16
}
