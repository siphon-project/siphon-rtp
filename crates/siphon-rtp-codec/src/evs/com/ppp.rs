//! Shared helpers of the PPP (prototype pitch period) coder of SC-VBR (TS 26.442
//! `lib_com/ppp_fx.c`; TS 26.445 §5.4.4 / §6.1.2.3): the per-subframe pitch-lag interpolation and
//! the de-emphasis of the LP coefficients.

use crate::evs::cnst::M;
use crate::itu::basic_ops::{add, l_add, l_mult, l_shr, mult, sub};

/// `Interpol_delay_fx`: three pitch delays (Q4) interpolated between the previous frame's delay
/// `last_fx` and the current one `current_fx` (both Q0), with the weights `frac_fx[sub_num..]`
/// (Q4, `frac_4sf_fx` in the decoder).
pub fn interpol_delay(
    out_fx: &mut [i16],
    last_fx: i16,
    current_fx: i16,
    sub_num: i16,
    frac_fx: &[i16],
) {
    for (i, out) in out_fx.iter_mut().enumerate().take(3) {
        // `frac_fx` has the subframe count plus two entries; the decoder's `sub_num` stays below
        // the subframe count
        let frac = frac_fx
            .get(sub_num.max(0) as usize + i)
            .copied()
            .unwrap_or(0);
        let temp = sub(16, frac); // Q4
        let l_add1 = l_shr(l_mult(last_fx, temp), 1); // Q4
        let l_add2 = l_shr(l_mult(current_fx, frac), 1); // Q4
        *out = l_add(l_add1, l_add2) as i16; // Q4
    }
}

/// `deemph_lpc_fx`: convolve the LP coefficients `p_aq_curr_fx[0..M]` (Q12, the leading 1
/// implied) with `[-PREEMPH_FAC, 1]` into `lpc_de_curr_fx[0..=M]` (Q12); with `deemph_old == 1`
/// the previous frame's `p_aq_old_fx[1..=M]` likewise into `lpc_de_old_fx`.
pub fn deemph_lpc(
    p_aq_curr_fx: &[i16],
    p_aq_old_fx: &[i16],
    lpc_de_curr_fx: &mut [i16],
    lpc_de_old_fx: &mut [i16],
    deemph_old: i16,
) {
    const MU: usize = M as usize;
    let mut b_fx = [0_i16; MU + 2]; // Q12
    let a_fx: [i16; 2] = [-22282, 32767]; // Q15 {-PREEMPH_FAC,1.0}

    b_fx[0] = 4096; // 1 in Q12
    b_fx[1..=MU].copy_from_slice(&p_aq_curr_fx[..MU]); // Q12
    b_fx[MU + 1] = 0;

    for k in 0..=MU {
        // LPC_de_curr[k] = a[0]*b[k] + a[1]*b[k+1]
        let temp = mult(a_fx[0], b_fx[k]); // Q12
        lpc_de_curr_fx[k] = add(temp, b_fx[k + 1]); // Q12
    }

    if sub(deemph_old, 1) == 0 {
        // ignoring the 1st value which is 1.0 in this case
        b_fx[0] = 4096; // 1 in Q12
        b_fx[1..=MU].copy_from_slice(&p_aq_old_fx[1..=MU]);
        b_fx[MU + 1] = 0;

        for k in 0..=MU {
            // LPC_de_old[k] = a[0]*b[k] + a[1]*b[k+1]
            let temp = mult(a_fx[0], b_fx[k]); // Q12
            lpc_de_old_fx[k] = add(temp, b_fx[k + 1]); // Q12
        }
    }
}
