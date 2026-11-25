//! Codebook gain from the correlation of a target and a filtered codebook vector
//! (TS 26.442 `lib_com/get_gain.c`): `get_gain` and the signed 16-bit-mantissa `get_gain2`.

use crate::evs::com::basop_util::{
    basop_util_divide_mant_exp, dot_product16_hq, dot_product_sq16_hq,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_abs, l_deposit_l, l_negate, l_shl, round_word, shr, sub,
};
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

/// `get_gain2`: [`get_gain`] with the signed correlation, the quotient formed on 16-bit
/// mantissas (`div_s`) instead of by `BASOP_Util_Divide_MantExp`.
pub fn get_gain2(x: &[i16], y: &[i16], n: i16, flags: &mut StlFlags) -> i32 {
    let mut negative = false;
    let mut q_corr: i16 = 0;
    let mut q_ener: i16 = 0;

    // Find gain based on inter-correlation product
    let mut tcorr = dot_product16_hq(0, x, y, n, &mut q_corr, flags);
    let mut tener = dot_product_sq16_hq(0, y, n, &mut q_ener, flags);

    tener = tener.max(1);

    if tcorr <= 0 {
        negative = true;
    }
    // tcorr may be the most negative value, not critical
    tcorr = l_abs(tcorr);

    let mut m_corr = extract_h(tcorr);
    let m_ener = extract_h(tener);

    if sub(m_corr, m_ener) > 0 {
        m_corr = shr(m_corr, 1);
        q_corr = add(q_corr, 1);
    }
    if m_ener == 0 {
        m_corr = 0x7FFF;
    }
    if m_ener != 0 {
        m_corr = div_s(m_corr, m_ener);
    }

    q_corr = sub(q_corr, q_ener);

    let mut l_gain = l_shl(l_deposit_l(m_corr), add(q_corr, 1)); // Q16

    if negative {
        l_gain = l_negate(l_gain); // Q16
    }

    l_gain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_gain2_is_the_signed_ratio_of_correlation_to_energy() {
        let y: Vec<i16> = (0..64).map(|i| 1000 + 37 * i).collect();
        let half: Vec<i16> = y.iter().map(|&v| v / 2).collect();
        let negative: Vec<i16> = y.iter().map(|&v| -(v / 2)).collect();
        let mut flags = StlFlags::default();
        let gain = get_gain2(&half, &y, 64, &mut flags);
        // 0.5 in Q16, to the precision of the 16-bit division
        assert!((gain - 32768).abs() < 200);
        assert_eq!(get_gain2(&negative, &y, 64, &mut flags), -gain);
    }
}
