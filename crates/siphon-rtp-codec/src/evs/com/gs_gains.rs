//! Band gains of the generic audio signal coder (GSC) (TS 26.442 `lib_com/gs_gains_fx.c`;
//! TS 26.445 §5.2.3.5.6, §6.1.1.3.3). The encoder's `gsc_gainQ_fx` is not ported.

use crate::evs::basop::l_extract_lc;
use crate::evs::cnst::{
    ACELP_11K60, ACELP_13K20, ACELP_7K20, ACELP_8K00, ACELP_9K60, AUDIO, INACTIVE, MBANDS_GN, NB,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::fft_rel_sas::{fft_rel, ifft_rel};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{i_mult2, pow2};
use crate::evs::com::tools::{calc_energy_autoscaled, copy, mean, set16};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    GAIN_DIC1_NB_FX, GAIN_DIC2_NBHR_FX, GAIN_DIC2_NB_FX, GAIN_DIC3_NBHR_FX, GAIN_DIC3_NB_FX,
    GAIN_MEANNB_FX, GAIN_MEAN_DICNB_FX, MEAN_DIC_NB_FX, MEAN_GAIN_DIC_FX, MEAN_M_FX,
    MFREQ_BINDIV_LOC, YGAIN_DIC1_LR_FX, YGAIN_DIC2_LR_FX, YGAIN_DIC3_LR_FX, YGAIN_MEAN_LR_FX,
    YG_DICMR_1_FX, YG_DICMR_2_FX, YG_DICMR_3_FX, YG_DICMR_4_FX, YG_MEAN16_FX,
};
use crate::itu::basic_ops::{
    add, extract_l, l_mult, l_shl, l_shr, l_sub, mult_r, norm_l, round_word, shl, sub,
};
use crate::itu::oper_32b::mpy_32_16;

/// `Comp_and_apply_gain_fx`: scale each band of `exc_diff_q` (Q`qexc_diff`, rescaled to Q`q_exc`)
/// by its gain. With `re_use_gain == 1` the gain is `ener_per_bd_y_q` as is; otherwise it is
/// `10^(ener_per_bd_i_q - ener_per_bd_y_q)` (Q12 logs), and is written back to `ener_per_bd_y_q`.
pub fn comp_and_apply_gain(
    exc_diff_q: &mut [i16],
    ener_per_bd_i_q: &[i16],
    ener_per_bd_y_q: &mut [i16],
    mbands_gn: i16,
    re_use_gain: i16,
    qexc_diff: i16,
    q_exc: i16,
) {
    // Recreate excitation for local synthesis and decoder
    let mut start_bin: i16 = 0;
    let mut nb_qbins: i16 = 0;

    // In case of reuse, it can be computed outside the loop
    let mut tmp_exp = add(14, sub(q_exc, qexc_diff));
    for i_band in 0..mbands_gn as usize {
        start_bin = add(start_bin, nb_qbins);
        nb_qbins = MFREQ_BINDIV_LOC[i_band];

        if sub(re_use_gain, 1) == 0 {
            let y_gain = ener_per_bd_y_q[i_band];
            for i in start_bin..nb_qbins + start_bin {
                let l32 = l_shl(l_mult(exc_diff_q[i as usize], y_gain), tmp_exp); // Q_exc+16
                exc_diff_q[i as usize] = round_word(l32); // Q_exc
            }
        } else {
            // y_gain = pow(10.0, (Ener_per_bd_iQ[i_band]-Ener_per_bd_yQ[i_band]))
            //        = pow(2, 3.321928*(Ener_per_bd_iQ[i_band]-Ener_per_bd_yQ[i_band]))
            let l16 = sub(ener_per_bd_i_q[i_band], ener_per_bd_y_q[i_band]); // Q12
            let mut l32 = l_mult(l16, 27213); // 3.321928 in Q13 -> Q26
            l32 = l_shr(l32, 10); // From Q26 to Q16
            let (exp1, frac) = l_extract_lc(l32); // Extract exponent of gcode0
                                                  // Put 14 as exponent so that output of Pow2() will be 16384 < Pow2() <= 32767
            let y_gain = extract_l(pow2(14, frac));
            ener_per_bd_y_q[i_band] = shl(y_gain, sub(exp1, 13));

            tmp_exp = add(add(exp1, 1), sub(q_exc, qexc_diff));
            for i in start_bin..nb_qbins + start_bin {
                let l32 = l_mult(exc_diff_q[i as usize], y_gain); // Qexc_diff+15
                exc_diff_q[i as usize] = round_word(l_shl(l32, tmp_exp)); // Q_exc
            }
        }
    }
}

/// `Comp_band_log_ener`: `log10(sqrt(energy << E_sc))` of `pt[0..len]` (Q`q_sc`), Q12.
pub fn comp_band_log_ener(pt: &[i16], len: i16, q_sc: i16, e_sc: i16) -> i16 {
    let mut ener_exp: i16 = 0;
    // for(i = 0; i < 8; i++){etmp += (*pt * *pt);pt++;}
    let mut l_tmp = calc_energy_autoscaled(pt, q_sc, len, &mut ener_exp);

    // y_gain4[j] = (float)log10(sqrt(etmp<<E_sc));
    let mut e_tmp = norm_l(l_tmp);
    let f_tmp = log2_norm_lc(l_shl(l_tmp, e_tmp));
    e_tmp = sub(sub(add(30, e_sc), e_tmp), ener_exp);
    l_tmp = mpy_32_16(e_tmp, f_tmp, 19728); // Q16; log10(2) in Q17
    round_word(l_shl(l_tmp, 12 - 2)) // Q12; -1 is to compensate Q17
}

/// `Ener_per_band_comp_fx`: the log energy (Q12) of each GSC band of `exc_diff` (Q`q_exc`):
/// two 8-bin bands, then 16-bin bands up to `mband`, and a 32-bin top band when `eflag == 1`.
pub fn ener_per_band_comp(
    exc_diff: &[i16],
    y_gain4: &mut [i16],
    q_exc: i16,
    mband: i16,
    eflag: i16,
) {
    let mut pt: usize = 0;
    for gain in y_gain4.iter_mut().take(2) {
        *gain = comp_band_log_ener(&exc_diff[pt..], 8, q_exc, 1);
        pt += 8;
    }

    let mut j: i16 = 1;
    while j < mband - 2 {
        y_gain4[(j + 1) as usize] = comp_band_log_ener(&exc_diff[pt..], 16, q_exc, 0);
        pt += 16;
        j += 1;
    }

    if sub(eflag, 1) == 0 {
        y_gain4[(j + 1) as usize] = comp_band_log_ener(&exc_diff[pt..], 32, q_exc, -1);
    }
}

/// `GSC_gain_adj`: add the mean gain back, decaying it over the bands for inactive frames at low
/// rates to mimic the ACELP inactive-coding gain. The C passes the same buffer as `y_gain_tmp`
/// and `y_gainQ` and reads each element before writing it, so this works in place on `y_gain_q`.
pub fn gsc_gain_adj(
    coder_type: i16,
    core_brate: i32,
    mean_g: i16,
    old_y_gain: &mut [i16],
    y_gain_q: &mut [i16],
) {
    // Gain adjustment to fit ACELP generic inactive coding gain at low rate
    if sub(coder_type, INACTIVE) != 0 {
        for i in 0..MBANDS_GN as usize {
            old_y_gain[i] = y_gain_q[i];
            y_gain_q[i] = add(y_gain_q[i], mean_g);
        }
    } else {
        let mut gain_off: i16 = 0;
        if l_sub(core_brate, i32::from(ACELP_7K20)) <= 0 {
            gain_off = 32767;
        } else if l_sub(core_brate, i32::from(ACELP_8K00)) <= 0 {
            gain_off = 27034;
        } else if l_sub(core_brate, i32::from(ACELP_9K60)) <= 0 {
            gain_off = 19661;
        } else if l_sub(core_brate, i32::from(ACELP_11K60)) <= 0 {
            gain_off = 14336;
        } else if l_sub(core_brate, i32::from(ACELP_13K20)) <= 0 {
            gain_off = 12288;
        }

        // mimic ACELP decay of energy for low rates
        for i in 0..MBANDS_GN {
            let iu = i as usize;
            old_y_gain[iu] = y_gain_q[iu];
            // y_gainQ[i] = y_gain_tmp[i]+mean_4g[0]-(i*(Gain_off/20.f)/((float) Mbands_gn));
            y_gain_q[iu] = add(y_gain_q[iu], sub(mean_g, i_mult2(i, mult_r(gain_off, 102))));
        }
    }
}

/// `gsc_gaindec_fx`: read and dequantise the 16 GSC band gains into `y_gain_q` (Q12) and return
/// the average gain.
pub fn gsc_gaindec(
    st: &mut DecoderState,
    y_gain_q: &mut [i16],
    core_brate: i32,
    old_y_gain: &mut [i16],
    coder_type: i16,
    bwidth: i16,
) -> i16 {
    let mut mean_4g = [0i16; 1];
    let mut y_gain_tmp3 = [0i16; MBANDS_GN as usize];

    if (sub(coder_type, AUDIO) == 0 || sub(coder_type, INACTIVE) == 0) && sub(bwidth, NB) == 0 {
        let idx_g = get_next_indice(st, 6) as i16;
        vdq_vec(&mut mean_4g, &GAIN_MEANNB_FX, &GAIN_MEAN_DICNB_FX, idx_g, 1);
        let idx_g = get_next_indice(st, 6) as i16;
        vdq_vec(y_gain_q, &MEAN_DIC_NB_FX, &GAIN_DIC1_NB_FX, idx_g, 3);

        if l_sub(core_brate, i32::from(ACELP_9K60)) < 0 {
            let idx_g = get_next_indice(st, 5) as i16;
            vdq_vec(
                &mut y_gain_q[3..],
                &MEAN_DIC_NB_FX[3..],
                &GAIN_DIC2_NB_FX,
                idx_g,
                3,
            );
            let idx_g = get_next_indice(st, 4) as i16;
            vdq_vec(
                &mut y_gain_q[6..],
                &MEAN_DIC_NB_FX[6..],
                &GAIN_DIC3_NB_FX,
                idx_g,
                4,
            );
        } else {
            let idx_g = get_next_indice(st, 6) as i16;
            vdq_vec(
                &mut y_gain_q[3..],
                &MEAN_DIC_NB_FX[3..],
                &GAIN_DIC2_NBHR_FX,
                idx_g,
                3,
            );
            let idx_g = get_next_indice(st, 7) as i16;
            vdq_vec(
                &mut y_gain_q[6..],
                &MEAN_DIC_NB_FX[6..],
                &GAIN_DIC3_NBHR_FX,
                idx_g,
                4,
            );
        }

        if l_sub(core_brate, i32::from(ACELP_9K60)) <= 0 && sub(coder_type, INACTIVE) == 0 {
            // Some energy is needed in high band for stat_noise_uv_enc to be functional in
            // inactive speech
            for k in 10..16 {
                y_gain_q[k] = mean(&y_gain_q[k - 4..], 3);
            }
        } else {
            set16(&mut y_gain_q[10..], 0, MBANDS_GN - 10);
        }
    } else {
        let idx_g = get_next_indice(st, 6) as i16;
        vdq_vec(&mut mean_4g, &MEAN_M_FX, &MEAN_GAIN_DIC_FX, idx_g, 1);

        if l_sub(core_brate, i32::from(ACELP_9K60)) <= 0 {
            // UQ of the first 8 bands and half of the last 8 bands
            let idx_g = get_next_indice(st, 5) as i16;
            vdq_vec(y_gain_q, &YGAIN_MEAN_LR_FX, &YGAIN_DIC1_LR_FX, idx_g, 3);
            let idx_g = get_next_indice(st, 5) as i16;
            vdq_vec(
                &mut y_gain_q[3..],
                &YGAIN_MEAN_LR_FX[3..],
                &YGAIN_DIC2_LR_FX,
                idx_g,
                4,
            );

            // Interpolation of the last 4 Q bands to create bands 8-16, and scaling
            let idx_g = get_next_indice(st, 5) as i16;
            vdq_vec(
                &mut y_gain_q[7..],
                &YGAIN_MEAN_LR_FX[7..],
                &YGAIN_DIC3_LR_FX,
                idx_g,
                5,
            );

            copy(&y_gain_q[8..], &mut y_gain_tmp3, 4);
            set16(&mut y_gain_q[12..], 0, 4);
            fft_rel(&mut y_gain_q[8..], 4, 2);

            y_gain_q[15] = y_gain_q[11];
            y_gain_q[11] = 0;

            ifft_rel(&mut y_gain_q[8..], 8, 3);
            for value in &mut y_gain_q[8..16] {
                // y_gainQ_fx[i] *= 1.41f;
                *value = round_word(l_shl(l_mult(*value, 23101), 1)); // Q12
            }

            // Copy the true Q values in the specific bands
            y_gain_q[8] = y_gain_tmp3[0];
            y_gain_q[10] = y_gain_tmp3[1];
            y_gain_q[12] = y_gain_tmp3[2];
            y_gain_q[14] = y_gain_tmp3[3];
        } else {
            let idx_g = get_next_indice(st, 6) as i16;
            vdq_vec(y_gain_q, &YG_MEAN16_FX, &YG_DICMR_1_FX, idx_g, 4);
            let idx_g = get_next_indice(st, 5) as i16;
            vdq_vec(
                &mut y_gain_q[4..],
                &YG_MEAN16_FX[4..],
                &YG_DICMR_2_FX,
                idx_g,
                4,
            );
            let idx_g = get_next_indice(st, 5) as i16;
            vdq_vec(
                &mut y_gain_q[8..],
                &YG_MEAN16_FX[8..],
                &YG_DICMR_3_FX,
                idx_g,
                4,
            );
            let idx_g = get_next_indice(st, 4) as i16;
            vdq_vec(
                &mut y_gain_q[12..],
                &YG_MEAN16_FX[12..],
                &YG_DICMR_4_FX,
                idx_g,
                4,
            );
        }
    }

    // Gain adjustment to fit ACELP generic inactive coding gain at low rate
    gsc_gain_adj(coder_type, core_brate, mean_4g[0], old_y_gain, y_gain_q);

    mean_4g[0]
}

/// `VDQ_vec_fx`: codevector `index` of `dic` (vectors of `vec_en`) plus `mean_dic`, into
/// `qvec_out`; returns `index`. Every call reads an index field exactly as wide as its codebook
/// is long, so the codevector is always inside `dic`.
pub fn vdq_vec(
    qvec_out: &mut [i16],
    mean_dic: &[i16],
    dic: &[i16],
    index: i16,
    vec_en: i16,
) -> i16 {
    let j = i_mult2(index, vec_en) as usize;
    let vec_en = vec_en as usize;
    qvec_out[..vec_en].copy_from_slice(&dic[j..j + vec_en]);
    for i in 0..vec_en {
        qvec_out[i] = add(qvec_out[i], mean_dic[i]);
    }
    index
}
