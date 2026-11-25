//! LP filter weighting, `ap[i] = a[i] · gamma^i` (TS 26.442 `lib_com/weight_a_fx.c`; TS 26.445
//! §5.1.10 uses it for the perceptual weighting filter and the postfilter).

use crate::evs::cnst::GAMMA16K_INV;
use crate::itu::basic_ops::{add, l_abs, l_mult, l_shl, mult_r, norm_l, round_word, shl, sub};
use crate::itu::stl2009::l_mult0;

/// `weight_a_fx`: weight `a[0..=m]` by successive powers of `gamma` into `ap[0..=m]`, normalising
/// the result so the largest weighted coefficient uses the full Q12 headroom the reference allows.
///
/// `a` and `ap` hold at least `m + 1` coefficients (Q12); `gamma` is Q15.
pub fn weight_a(a: &[i16], ap: &mut [i16], gamma: i16, m: i16) {
    let order = m as usize;
    let mut fac = gamma;
    let mut amax = l_mult(16384, a[0]);
    for &coefficient in &a[1..order] {
        amax = amax.max(l_abs(l_mult0(fac, coefficient)));
        fac = mult_r(fac, gamma);
    }
    amax = amax.max(l_abs(l_mult0(fac, a[order])));
    let shift = norm_l(amax);
    fac = gamma;
    ap[0] = shl(a[0], sub(shift, 1));
    for index in 1..order {
        ap[index] = round_word(l_shl(l_mult0(a[index], fac), shift));
        fac = mult_r(fac, gamma);
    }
    ap[order] = round_word(l_shl(l_mult0(a[order], fac), shift));
}

/// `weight_a_lc_fx`: [`weight_a`] with the powers of gamma taken from a table (`gammatbl[i - 1]` is
/// `gamma^i`, Q15) instead of computed, as the low-complexity paths do.
pub fn weight_a_lc(a: &[i16], ap: &mut [i16], gammatbl: &[i16], m: i16) {
    let order = m as usize;
    let mut amax = l_mult(16384, a[0]);
    for index in 1..order {
        amax = amax.max(l_abs(l_mult0(gammatbl[index - 1], a[index])));
    }
    amax = amax.max(l_abs(l_mult0(gammatbl[order - 1], a[order])));
    let shift = norm_l(amax);
    ap[0] = shl(a[0], sub(shift, 1));
    for index in 1..order {
        ap[index] = round_word(l_shl(l_mult0(a[index], gammatbl[index - 1]), shift));
    }
    ap[order] = round_word(l_shl(l_mult0(a[order], gammatbl[order - 1]), shift));
}

/// `inv_gamma_tab_12k8` of `E_LPC_a_weight_inv`: the first eight Q14, the last eight Q13.
const INV_GAMMA_TAB_12K8: [i16; 16] = [
    17809, 19357, 21041, 22870, 24859, 27020, 29370, 31924, 17350, 18859, 20499, 22281, 24219,
    26325, 28614, 31102,
];
/// `inv_gamma_tab_16k` of `E_LPC_a_weight_inv`: the first eight Q14, the last eight Q13.
const INV_GAMMA_TAB_16K: [i16; 16] = [
    17430, 18542, 19726, 20985, 22324, 23749, 25265, 26878, 14297, 15209, 16180, 17213, 18312,
    19480, 20724, 22047,
];

/// `E_LPC_a_weight_inv`: `ap[i] = a[i] · inv_gamma^i` (`inv_gamma` Q14, one of `GAMMA1_INV`,
/// `GAMMA16k_INV`, or 16384 for a plain copy), normalised to the headroom of the largest
/// coefficient. The reference asserts `m == 16` for the weighted case.
pub fn e_lpc_a_weight_inv(a: &[i16], ap: &mut [i16], inv_gamma: i16, m: i16) {
    if inv_gamma == 16384 {
        ap[..=m as usize].copy_from_slice(&a[..=m as usize]);
        return;
    }

    let mut inv_gamma_tab = &INV_GAMMA_TAB_12K8;
    if sub(inv_gamma, GAMMA16K_INV) == 0 {
        inv_gamma_tab = &INV_GAMMA_TAB_16K;
    }

    let mut a_max = l_mult(16384, a[0]);
    for i in 1..9 {
        a_max = a_max.max(l_abs(l_mult(a[i], inv_gamma_tab[i - 1])));
    }
    for i in 9..17 {
        a_max = a_max.max(l_abs(l_shl(l_mult(a[i], inv_gamma_tab[i - 1]), 1)));
    }
    let mut shift = norm_l(a_max);
    ap[0] = shl(a[0], sub(shift, 1));
    for i in 1..9 {
        let l_tmp = l_mult(a[i], inv_gamma_tab[i - 1]);
        ap[i] = round_word(l_shl(l_tmp, shift));
    }
    shift = add(shift, 1);
    for i in 9..17 {
        let l_tmp = l_mult(a[i], inv_gamma_tab[i - 1]);
        ap[i] = round_word(l_shl(l_tmp, shift));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_gamma_keeps_only_the_normalised_leading_coefficient() {
        // Every power of a zero gamma is zero, so only a[0] survives; its term alone sets the
        // normalisation (L_mult(16384, 4096) = 2^27, norm_l = 3), so a[0] is shifted left by 2.
        let a = [4096, -2048, 1024, 300];
        let mut ap = [7; 4];
        weight_a(&a, &mut ap, 0, 3);
        assert_eq!(ap, [16384, 0, 0, 0]);
        weight_a_lc(&a, &mut ap, &[0, 0, 0], 3);
        assert_eq!(ap, [16384, 0, 0, 0]);
    }
}
