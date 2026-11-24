//! Frame-erasure branch of `swb_bwe_dec_hr_fx` (TS 26.442 `lib_dec/swb_bwe_dec_hr_fx.c`): replicate
//! the last spectrum with an attenuation.

use super::{HrBranch, HrFrame, FULL_FB_COEFS, Q_32_BITS};
use crate::evs::cnst::{
    INACTIVE_CLAS, L_FRAME32K, NUM_NONTRANS_START_FREQ_COEF, NUM_TIME_SWITCHING_BLOCKS,
    NUM_TRANS_START_FREQ_COEF, VOICED_CLAS,
};
use crate::evs::com::math_op::{i_mult2, isqrt_lc};
use crate::evs::com::tools::{copy_scale_sig32_16, find_max_norm32, mul_flt32_q15};
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_deposit_h, l_mult, l_shl, l_shr, norm_l, norm_s, shl, shr,
    sub,
};

/// `swb_bwe_dec_hr_fx` for a lost frame: rebuild `t_audio32` from the saved coefficients scaled by
/// an attenuation chosen from the last frame's class, update the long-term energy, and derive the
/// frame gain from it.
pub(super) fn swb_bwe_dec_hr_erasure(
    st: &mut DecoderState,
    t_audio32: &mut [i32],
    frame: &HrFrame,
) -> HrBranch {
    let output_frame = frame.output_frame;
    let is_transient = st.old_is_transient_hr_bwe;

    // Replication of the last spectrum, with an attenuation
    let (alpha, t_audio_exp): (i16, i16) = if (sub(st.clas_dec, VOICED_CLAS) == 0
        || sub(st.clas_dec, INACTIVE_CLAS) == 0)
        && sub(st.nb_lost_cmpt, 3) <= 0
    {
        (26214, 0) // 0.80
    } else if is_transient != 0 {
        (19661, 2) // 0.15
    } else {
        (19661, 1) // 0.30
    };

    if is_transient != 0 {
        swb_bwe_dec_hr_erasure_transient(st, t_audio32, output_frame, alpha, t_audio_exp);
    } else {
        swb_bwe_dec_hr_erasure_stationary(st, t_audio32, output_frame, alpha, t_audio_exp);
    }

    st.l_mem_energy_lt = mul_flt32_q15(st.l_mem_energy_lt, &mut st.mem_energy_lt_fx_exp, alpha);
    st.mem_energy_lt_fx_exp = add(st.mem_energy_lt_fx_exp, t_audio_exp);

    let exp_l = norm_s(output_frame);
    let inv_l = div_s(shl(1, sub(14, exp_l)), output_frame); // Q(29-exp_L)

    // Q(st_fx->mem_EnergyLT_fx_exp+29-exp_L-15) -> Q(st_fx->mem_EnergyLT_fx_exp-exp_L+14)
    st.l_mem_energy_lt = mul_flt32_q15(st.l_mem_energy_lt, &mut st.mem_energy_lt_fx_exp, inv_l);
    let mut gain_fx: i16 = 0;
    if st.l_mem_energy_lt != 0 {
        let mut exp1 = norm_l(st.l_mem_energy_lt);
        let frac = extract_h(l_shl(st.l_mem_energy_lt, exp1));
        exp1 = sub(exp1, sub(16, sub(st.mem_energy_lt_fx_exp, exp_l)));

        let temp = div_s(16384, frac);
        let l_temp = isqrt_lc(l_deposit_h(temp), &mut exp1);
        gain_fx = extract_l(l_shl(l_temp, sub(exp1, 2))); // Q(31-exp + (exp-3)) -> Q13
    }

    HrBranch {
        is_transient,
        gain_fx,
        env: 512,
    }
}

/// The transient case of the erasure branch: the four time blocks, each from its own saved
/// exponent, then the new coefficients saved for the next frame.
fn swb_bwe_dec_hr_erasure_transient(
    st: &mut DecoderState,
    t_audio32: &mut [i32],
    output_frame: i16,
    alpha: i16,
    t_audio_exp: i16,
) {
    // output_frame == L_FRAME48k
    let mut tmp_s = FULL_FB_COEFS / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_START_FREQ_COEF;
    // set BWE spectrum length
    if sub(output_frame, L_FRAME32K) == 0 {
        tmp_s = L_FRAME32K / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_START_FREQ_COEF;
    }

    let temp = shr(output_frame, 2);
    let mut pos = NUM_TRANS_START_FREQ_COEF;
    let mut ind1: i16 = 0;
    // reconstruct
    let mut len: i16 = 0;
    // Here t_audio was initialy filled with zeros
    // So, after the loop, the Q will be 'Q_32_Bits'
    for k in 0..NUM_TIME_SWITCHING_BLOCKS as usize {
        let mut temp4 = sub(st.t_audio_prev_fx_exp[k], Q_32_BITS);
        temp4 = add(temp4, t_audio_exp);
        for i in 0..tmp_s {
            let l_temp = l_mult(alpha, st.t_audio_prev[(i + ind1) as usize]);
            let l_temp = l_shr(l_temp, temp4);
            t_audio32[(pos + i) as usize] = l_temp;
        }
        ind1 = add(ind1, tmp_s);
        pos = add(pos, temp);
    }
    // Save transform coefficients for the next frame (needed in case of frame erasures)
    for k in 0..NUM_TIME_SWITCHING_BLOCKS as usize {
        let temp = add(NUM_TRANS_START_FREQ_COEF, len) as usize;
        let temp4 = find_max_norm32(&t_audio32[temp..], tmp_s);
        let dest = i_mult2(k as i16, tmp_s) as usize;
        copy_scale_sig32_16(
            &t_audio32[temp..],
            &mut st.t_audio_prev[dest..],
            tmp_s,
            temp4,
        );
        st.t_audio_prev_fx_exp[k] = add(Q_32_BITS, temp4);
        len = add(len, shr(output_frame, 2));
    }
}

/// The stationary case of the erasure branch: one block from the first saved exponent.
fn swb_bwe_dec_hr_erasure_stationary(
    st: &mut DecoderState,
    t_audio32: &mut [i32],
    output_frame: i16,
    alpha: i16,
    t_audio_exp: i16,
) {
    // output_frame == L_FRAME48k
    let mut tmp_s = FULL_FB_COEFS - NUM_NONTRANS_START_FREQ_COEF;
    // set BWE spectrum length
    if sub(output_frame, L_FRAME32K) == 0 {
        tmp_s = L_FRAME32K - NUM_NONTRANS_START_FREQ_COEF;
    }

    // reconstruct
    // Here t_audio was initialy filled with zeros
    // So, after the loop, the Q will be 'Q_32_Bits'
    let mut temp4 = sub(st.t_audio_prev_fx_exp[0], Q_32_BITS);
    temp4 = add(temp4, t_audio_exp);
    let base = NUM_NONTRANS_START_FREQ_COEF as usize;
    for i in 0..tmp_s as usize {
        let l_temp = l_mult(alpha, st.t_audio_prev[i]);
        let l_temp = l_shr(l_temp, temp4);
        t_audio32[base + i] = l_temp;
    }
    // Save transform coefficients for the next frame (needed in case of frame erasures)
    let temp = NUM_NONTRANS_START_FREQ_COEF as usize; // not necessary but improves readability
    let temp4 = find_max_norm32(&t_audio32[temp..], tmp_s);
    copy_scale_sig32_16(&t_audio32[temp..], &mut st.t_audio_prev, tmp_s, temp4);
    st.t_audio_prev_fx_exp[0] = add(Q_32_BITS, temp4);
}
