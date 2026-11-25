//! Weighting of the second-stage LPC quantiser (TS 26.442 `lib_com/vlpc_2st_com.c`).

use crate::evs::cnst::{FREQ_MAX, M, W_MODE0, W_MODE1, W_MODE_ELSE};
use crate::evs::com::basop_util::get_sqrt_word32;
use crate::itu::basic_ops::{l_shl, mult_r, sub};
use crate::itu::stl2009::l_mult0;

/// `lsf_weight_2st`: the weighting `w[i] = weight · sqrt(d[i]·d[i+1])` (Q15, ×1.28) of the
/// second-stage quantiser from the spacing `d` of the first-stage LSFs `lsfq` (14Q1, ×1.28);
/// `mode` 0 is the absolute quantiser, 1 the mid-frame one, else the relative.
pub fn lsf_weight_2st(lsfq: &[i16], w: &mut [i16], mode: i16) {
    let mut d = [0i16; M as usize + 1];

    // compute lsf distance
    d[0] = lsfq[0]; // 14Q1*1.28
    for i in 1..M as usize {
        d[i] = sub(lsfq[i], lsfq[i - 1]); // 14Q1*1.28
    }
    d[M as usize] = sub(FREQ_MAX, lsfq[M as usize - 1]); // 14Q1*1.28

    // weighting function
    let mut weight = W_MODE_ELSE; // rel2
    if mode == 0 {
        weight = W_MODE0; // abs
    } else if sub(mode, 1) == 0 {
        weight = W_MODE1; // mid
    }

    for i in 0..M as usize {
        // w[i] = (weight * sqrt(d[i]*d[i+1])));
        w[i] = mult_r(weight, get_sqrt_word32(l_shl(l_mult0(d[i], d[i + 1]), 6)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_spacing_gives_equal_weights_per_mode() {
        let mut lsfq = [0i16; 16];
        for (i, value) in lsfq.iter_mut().enumerate() {
            *value = ((i + 1) * 900) as i16;
        }
        let (mut w0, mut w1, mut w2) = ([0i16; 16], [0i16; 16], [0i16; 16]);
        lsf_weight_2st(&lsfq, &mut w0, 0);
        lsf_weight_2st(&lsfq, &mut w1, 1);
        lsf_weight_2st(&lsfq, &mut w2, 3);
        // The interior weights share the spacing, so the three modes differ by their constants.
        assert!(w0[3] < w2[3] && w2[3] < w1[3]);
    }
}
