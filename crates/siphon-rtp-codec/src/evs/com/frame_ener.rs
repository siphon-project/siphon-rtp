//! Frame energy estimates for frame-erasure concealment and classification (TS 26.442
//! `lib_com/frame_ener_fx.c`).

use crate::evs::basop::{mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{LG10, L_SUBFR, ONSET, SIN_ONSET, VOICED_CLAS};
use crate::evs::com::basop_util::{
    basop_util_divide3216_scale, basop_util_log2, dot_product_sq16_hq,
};
use crate::evs::com::math_op::energy_scale;
use crate::evs::com::tools::emaximum;
use crate::itu::basic_ops::{
    add, extract_h, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r,
    norm_l, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::StlFlags;

/// `frame_ener_fx`: pitch-synchronous energy over the last `pitch` samples of a voiced frame
/// (`clas` voiced, onset or sine onset), else the mean energy of the first or (with `offset`)
/// last half frame of `synth` (Q`q_new`), into `enr_q`. The decoder (`enc == 0`) gets it in Q0
/// and a zero exponent; the encoder gets a normalised mantissa and returns its exponent. `shift`
/// is the down-scaling used when the half-frame sum saturates.
pub fn frame_ener(
    l_frame: i16,
    clas: i16,
    synth: &[i16],
    pitch: i16,
    enr_q: &mut i32,
    offset: i16,
    q_new: i16,
    shift: i16,
    enc: i16,
) -> i16 {
    let mut shift = shift;
    let mut exp_enrq: i16 = 0;
    if sub(clas, VOICED_CLAS) == 0 || sub(clas, ONSET) == 0 || sub(clas, SIN_ONSET) == 0 {
        // current frame is voiced: pitch value at the end of frame
        let len = pitch;
        // A lag longer than the frame (never decoded) is clamped to the frame start.
        let start = if offset != 0 {
            sub(l_frame, len).max(0) as usize
        } else {
            0
        };
        // The decoded lag never exceeds the frame; a longer one is cut to the synthesis given.
        let len = len.min((synth.len() - start.min(synth.len())) as i16);
        emaximum(q_new, &synth[start..], len, enr_q); // pitch synchronous E
        if enc != 0 {
            exp_enrq = norm_l(*enr_q);
            *enr_q = l_shl(*enr_q, exp_enrq);
            exp_enrq = sub(exp_enrq, 2);
        }
    } else {
        // current frame is unvoiced
        let l_frame2 = shr(l_frame, 1);
        let mut pos: i16 = 0;
        if offset != 0 {
            pos = sub(l_frame, l_frame2);
        }
        let p = pos.max(0) as usize;
        let mut l_tmp = l_mult(synth[p], synth[p]);
        for i in 1..l_frame2.max(1) as usize {
            l_tmp = l_mac(l_tmp, synth[p + i], synth[p + i]);
        }
        if l_sub(l_tmp, i32::MAX) == 0 || enc != 0 {
            // scale down when overflow occurs
            *enr_q = energy_scale(&synth[p..], l_frame2, shift, &mut exp_enrq);
        } else {
            shift = 0;
            // Normalize acc in Q31 (energy already calculated)
            pos = norm_l(l_tmp);
            l_tmp = l_shl(l_tmp, pos);
            exp_enrq = sub(30, pos); // exponent = 0..30
            *enr_q = l_tmp;
        }

        // enr2 = 1.0f/L_FRAME2 * dot_product(synth, synth, L_FRAME2)
        exp_enrq = sub(exp_enrq, shl(shift, 1));

        if enc != 0 {
            let exp_tmp = add(shl(q_new, 1), -2 + 7); // L_subfr == L_SUBFR
            exp_enrq = sub(exp_enrq, exp_tmp);
            exp_enrq = sub(31, exp_enrq);
            if sub(l_frame, 320) == 0 {
                *enr_q = mult_32_16(*enr_q, 26214); // x 0.8 to get /160
                let i = norm_l(*enr_q);
                *enr_q = l_shl(*enr_q, i);
                exp_enrq = add(i, exp_enrq);
            }
        } else {
            exp_enrq = sub(exp_enrq, add(q_new, q_new));
            let mut exp2: i16 = 0;
            let enr_q_tmp = basop_util_divide3216_scale(*enr_q, l_frame2, &mut exp2); // Q30
            *enr_q = l_shr(l_deposit_l(enr_q_tmp), sub(30, add(exp2, exp_enrq))); // Q0
            *enr_q = l_add(*enr_q, 1);
            exp_enrq = 0;
        }
    }
    exp_enrq
}

/// `frame_energy_fx`: pitch-synchronous energy at the end of the frame, `10·log10(Σ x² / len)`
/// over the last `len` samples of `speech[0..l_frame]` (`len` the mean of the last two pitch
/// values, Q6, doubled when under a subframe), into `frame_ener` (Q8). Returns
/// `frame_ener - lp_speech` (Q8). `flags` carries the `Carry` the 64-bit dot product uses.
pub fn frame_energy(
    l_frame: i16,
    pitch: &[i16],
    speech: &[i16],
    lp_speech: i16,
    frame_ener: &mut i16,
    q_syn: i16,
    flags: &mut StlFlags,
) -> i16 {
    // len = (0.5f * (pitch[2]/64.0 + pitch[3]/64.0) + 0.5f)
    let mut len = mult_r(add(pitch[2], pitch[3]), 256);
    if sub(len, L_SUBFR) < 0 {
        len = shl(len, 1);
    }
    // A lag longer than the frame (never produced by the pitch decoder) would read before the
    // synthesis; it is clamped to the frame.
    let start = sub(l_frame, len).max(0) as usize;
    let pt1 = &speech[start..];

    let mut exp1 = 0i16;
    let mut exp2 = 0i16;
    let mut l_tmp = dot_product_sq16_hq(0, pt1, len, &mut exp1, flags);
    exp1 = sub(exp1, shl(q_syn, 1));
    exp1 = sub(exp1, 1); // compensation of leftshift caused by mac operation in dot_productSq16HQ
    let mut tmp16 = basop_util_divide3216_scale(l_tmp, len, &mut exp2);

    exp1 = add(exp1, exp2);
    exp1 = add(exp1, 1); // compensate result of division Q-1

    let tmp2 = norm_s(tmp16);
    l_tmp = l_shl(l_deposit_h(tmp16), tmp2); // Q31, exp1-tmp2+15

    l_tmp = basop_util_log2(l_tmp); // Q25
    exp1 = sub(exp1.wrapping_add(15), tmp2); // `15+exp1` is plain C int arithmetic

    // add ld(2^exp1)=exp1 but check format, first
    tmp16 = sub(sub(15, norm_s(exp1)), 5); // shift to avoid overflows when adding
    l_tmp = l_shr(l_tmp, tmp16); // Q25, tmp16
    let exp2 = shr(exp1, tmp16); // Q0, tmp16
    l_tmp = l_add(l_tmp, l_shl(l_deposit_l(exp2), 25)); // Q25, tmp16, normalized

    // make 10*log10 out of log2
    l_tmp = mpy_32_16_1(l_tmp, LG10); // Q23, tmp16
    *frame_ener = extract_h(l_shl(l_tmp, add(tmp16, 1))); // Q8
    sub(*frame_ener, lp_speech)
}
