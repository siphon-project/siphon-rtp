//! Pre-echo attenuation of the generic-signal (GSC) audio coder (TS 26.442
//! `lib_com/gs_preech_fx.c`; TS 26.445 §6.1.2.3).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{AUDIO, L_FRAME};
use crate::evs::com::math_op::isqrt;
use crate::evs::com::tools::{maximum_32, sum2, sum32};
use crate::itu::basic_ops::{
    add, div_s, l_mac, l_mult, l_shl, l_shr, l_sub, norm_l, round_word, shl, sub,
};
use crate::itu::stl2009::l_mult0;

/// `ATT_LENGHT` (sic): sections the frame is analysed in.
const ATT_LENGHT: i16 = 64;
/// `ATT_SEG_LEN` = `L_FRAME / ATT_LENGHT`: samples per section.
const ATT_SEG_LEN: i16 = L_FRAME / ATT_LENGHT;

/// `pre_echo_att_fx`: when the encoder signalled an attack in a GSC (AUDIO) frame following one,
/// attenuate the excitation `exc_fx` (Q`q_new`) before the attack to the previous frame's energy;
/// always leave the frame energy in `last_frame_ener_fx` (Q4) for the next frame.
pub fn pre_echo_att(
    last_frame_ener_fx: &mut i32,
    exc_fx: &mut [i16],
    gsc_attack_flag_fx: i16,
    q_new: i16,
    last_coder_type_fx: i16,
) {
    if sub(gsc_attack_flag_fx, 1) == 0 && sub(last_coder_type_fx, AUDIO) == 0 {
        // Find where the onset (attack) occurs by computing the energy per section. The inverse
        // weighting aims to favor the first maxima in case of gradual onset.
        let mut finc_fx = [0_i32; ATT_LENGHT as usize];
        for (i, slot) in finc_fx.iter_mut().enumerate() {
            let i16_i = i as i16;
            let l_tmp = sum2(&exc_fx[shl(i16_i, 2) as usize..], ATT_SEG_LEN); // 2*Q_new+1
            let tmp = div_s(sub(ATT_LENGHT, i16_i), ATT_LENGHT); // Q15
            *slot = mult_32_16(l_tmp, tmp); // 2*Q_new+1
        }

        let mut etmp_fx: i32 = 0;
        let attack_pos_fx = maximum_32(&finc_fx, ATT_LENGHT, &mut etmp_fx);

        // Scaled the maximum energy and allowed 6 dB increase
        etmp_fx = l_shr(etmp_fx, add(2 + 1 - 4, shl(q_new, 1))); // -> Q4
        let etmp1_fx = etmp_fx;
        *last_frame_ener_fx = l_shl(*last_frame_ener_fx, 2); // 2*Q_new+1

        // If the maximum normalized energy > last frame energy + 6dB
        if l_sub(etmp_fx, *last_frame_ener_fx) > 0 && attack_pos_fx > 0 {
            // Find the average energy before the attack
            let mut l_tmp = sum32(&finc_fx, attack_pos_fx); // Q1
            let l_tmp1 = l_shr(l_mult(attack_pos_fx, attack_pos_fx), 1); // Q0
            let tmp = round_word(isqrt(l_tmp1)); // Q15
            l_tmp = l_shr(l_tmp, 2); // Q1 ; ATT_SEG_LEN=4
            etmp_fx = mult_32_16(l_tmp, tmp); // Q1

            etmp_fx = l_shr(etmp_fx, add(1 - 4, shl(q_new, 1))); // in Q4 as *Last_frame_ener_fx
                                                                 // Find the correction factor and apply it before the attack
                                                                 // ratio = (float)sqrt(*Last_frame_ener/etmp) = isqrt(etmp/(*Last_frame_ener))
            etmp_fx = etmp_fx.max(1);
            *last_frame_ener_fx = (*last_frame_ener_fx).max(1);
            let mut n1 = norm_l(etmp_fx);
            let n2 = norm_l(*last_frame_ener_fx);
            n1 = sub(n1, 1);
            let exp = sub(n1, n2);
            let frac1 = round_word(l_shl(etmp_fx, n1));
            let frac2 = round_word(l_shl(*last_frame_ener_fx, n2));

            let mut l_tmp = l_mult0(128, div_s(frac1, frac2)); // s = gain_out / gain_in
            l_tmp = l_shr(l_tmp, exp); // add exponent
            l_tmp = isqrt(l_tmp);
            let mut ratio_fx = round_word(l_shl(l_tmp, 9));

            // Pre-echo atttenuation should never increase the energy
            ratio_fx = ratio_fx.min(8192);
            let end = (attack_pos_fx * ATT_SEG_LEN) as usize;
            for value in &mut exc_fx[..end] {
                // exc_fx[i] *= ratio_fx;
                *value = round_word(l_shl(l_mac(-8192, *value, ratio_fx), 2));
            }
        }
        *last_frame_ener_fx = etmp1_fx;
    } else {
        // In normal cases, just compute the energy of the frame
        let mut etmp_fx = sum2(exc_fx, L_FRAME); // 2*Q_new+1
        etmp_fx = l_shr(etmp_fx, add(8 + 1 - 4, shl(q_new, 1))); // INV_L_FRAME = 1/256 -> Q4
        *last_frame_ener_fx = etmp_fx;
    }
}
