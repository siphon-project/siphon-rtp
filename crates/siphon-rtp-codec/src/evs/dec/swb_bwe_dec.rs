//! WB and SWB bandwidth-extension decoding (TS 26.442 `lib_dec/swb_bwe_dec_fx.c`; TS 26.445
//! §6.3.4, §6.3.5).
//!
//! `swb_bwe_dec_fx` itself is not here yet: it synthesises the SWB band through
//! `SWB_BWE_decoding_fx`, `time_envelop_shaping_fx` and `time_reduce_pre_echo_fx`
//! (`lib_com/swb_bwe_com_fx.c`), none of which is ported. Everything else in the file is.

use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{
    ACELP_CORE, ALDO_WINDOW, DIM11, DIM12, DIM1ST, DIM2ND, DIM3RD, DIM4TH, DIM_FB, DIM_TR1,
    HARMONIC, HQ_CORE, HQ_GENERIC_SP_EXC, HQ_GEN_FB, L_FRAME16K, L_FRAME48K, MODE1, NORMAL,
    N_WS2N_FRAMES, SHARP_WIDTH, SWB_FENV, SWB_FENV_TRANS, SWB_TENV, WB_BWE,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::math_op::{i_mult2, pow2};
use crate::evs::com::swb_bwe_com::{wb_bwe_decoding, wb_bwe_gain_pred};
use crate::evs::com::tools::{copy_scale_sig32_16, find_max_norm32};
use crate::evs::com::trans_direct::direct_transform;
use crate::evs::com::trans_inv::inverse_transform;
use crate::evs::com::window_ola::window_ola;
use crate::evs::com::wtda::wtda;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    ENVCDBK11_FX, ENVCDBK1ST_FX, ENVCDBK2ND_FX, ENVCDBK3RD_FX, ENVCDBK4TH_FX, ENVCDBKFB_FX,
    ENV_TR_CDBK1_FX, ENV_TR_CDBK2_FX, F_2_5_FX, MEAN_ENV_FB_FX, MEAN_ENV_FX, MEAN_ENV_TR_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_l, l_add, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r,
    norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_msu0, l_mult0};

/// `MAX_Q_NEW_INPUT` (file-local `#define`): the highest Q the MDCT of the core synthesis is
/// scaled to before the 16-bit conversion.
const MAX_Q_NEW_INPUT: i16 = 8;

const FRAME_MAX: usize = L_FRAME48K as usize;

/// `para_pred_bws_fx`: predict the SWB envelope `swb_fenv[0..SWB_FENV]` from the WB spectrum
/// `signal_wb` (Q`q_syn`) during bandwidth switching. Returns the mode (`NORMAL` or `HARMONIC`).
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn para_pred_bws(
    st: &mut DecoderState,
    signal_wb: &[i16],
    swb_fenv: &mut [i16],
    q_syn: i16,
    coder_type: i16,
) -> i16 {
    let mut mode = NORMAL;
    let mut k: i16 = 0;
    let mut mean = [0i32; 7];

    let mut input_hi = SHARP_WIDTH as usize;
    for i in 0..7 {
        let mut peak: i16 = 0;
        mean[i] = 0;
        for _ in 0..SHARP_WIDTH {
            let mag = abs_s(signal_wb[input_hi]);
            peak = peak.max(mag);
            mean[i] = l_add(mean[i], l_deposit_l(mag));
            input_hi += 1;
        }

        if q_syn < 11 || sub(shr(peak, 3), shl(1, q_syn)) > 0 {
            let l_tmp = l_msu0(mult_32_16(l_shl(mean[i], 10), 18432), peak, 4544);
            if l_tmp < 0 {
                k = add(k, 1);
            }
        }
    }

    let mut avrg1: i32 = 0;
    let mut avrg2: i32 = 0;
    for i in 1..4 {
        avrg1 = l_add(avrg1, mean[i]);
        avrg2 = l_add(avrg2, mean[i + 3]);
    }
    avrg1 = mult_32_16(avrg1, 10923);
    avrg2 = mult_32_16(avrg2, 10923); // 1/3 -> Q15 -> 10923

    let mut min = l_add(2_147_483_647, 0); // 2^31
    let mut peak_32: i32 = 0;
    for value in mean.iter_mut().skip(4) {
        if l_sub(*value, l_shl(avrg2, 1)) > 0 {
            let exp = norm_l(*value);
            let mut tmp_den: i16;
            let tmp_num: i16;
            if sub(exp, 16) < 0 {
                tmp_den = extract_l(l_shr(*value, sub(16, exp))); // Qsyn - 16 + exp
                tmp_num = extract_l(l_shr(avrg2, sub(15, exp))); // Qsyn - 16 + exp
            } else {
                tmp_den = extract_l(*value);
                tmp_num = extract_l(l_shl(avrg2, 1));
            }
            tmp_den = div_s(1, tmp_den);
            let tmp = i_mult(tmp_num, tmp_den); // Q15
            *value = mult_32_16(*value, tmp);
        }
        min = min.min(*value);
        peak_32 = peak_32.max(*value);
    }

    if sub(st.tilt_wb, 16384) > 0 {
        if sub(st.tilt_wb, 30720) > 0 {
            min = peak_32;
        } else {
            let tmp = extract_l(l_shr(l_mult0(st.tilt_wb, 17476), 14)); // Q15
            min = mult_32_16(peak_32, tmp);
        }
    }

    if peak_32 == 0 || min == 0 {
        swb_fenv[..SWB_FENV as usize].fill(0);
    } else {
        let exp = norm_l(peak_32);
        let tmp = if sub(exp, 16) < 0 {
            let tmp_den = extract_l(l_shr(peak_32, sub(16, exp))); // Qsyn - 16 + exp
            let inverse = div_s(16384, tmp_den); // Q15+14 - (Qsyn - 16 + exp)
            let tmp_num = extract_l(l_shr(min, sub(16, exp))); // Qsyn - 16 + exp
            extract_l(l_shr(l_mult0(tmp_num, inverse), 14)) // Q15
        } else {
            let tmp_den = extract_l(peak_32); // Qsyn
            let exp = norm_s(tmp_den);
            let inverse = div_s(shl(1, sub(14, exp)), tmp_den); // Q 29-exp - Qsyn
            let tmp_num = extract_l(min); // Qsyn
            extract_l(l_shr(l_mult0(tmp_num, inverse), sub(14, exp))) // Q15
        };

        let mut j = 0;
        let mut mea = 4;
        let l_tmp_max = l_shl(32767, add(q_syn, 5));
        for slot in swb_fenv.iter_mut().take(SWB_FENV as usize) {
            if j == 5 {
                mea += 1;
                j = 0;
            }
            j += 1;
            let l_tmp = mult_32_16(mean[mea], tmp).min(l_tmp_max);
            *slot = extract_l(l_shr(l_tmp, add(q_syn, 5)));
        }
    }

    let mut j: i16 = 0;
    for slot in swb_fenv
        .iter_mut()
        .take(SWB_FENV as usize)
        .skip(shr(SWB_FENV, 1) as usize)
    {
        let tmp = sub(32767, i_mult(j, 2341));
        *slot = mult_r(*slot, tmp);
        j += 1;
    }

    if l_sub(avrg1, l_shl(avrg2, 3)) > 0 {
        for slot in swb_fenv.iter_mut().take(SWB_FENV as usize) {
            *slot = shr(*slot, 1);
        }
    }

    para_pred_bws_smooth(st, swb_fenv, coder_type);

    if sub(k, 3) > 0 {
        mode = HARMONIC;
    }

    let att = i_mult(sub(N_WS2N_FRAMES, st.bws_cnt), 819);
    if sub(st.l_frame, L_FRAME16K) == 0 {
        for slot in swb_fenv.iter_mut().take(4) {
            *slot = mult_r(*slot, att);
        }
    }
    for slot in swb_fenv.iter_mut().take(SWB_FENV as usize).skip(4) {
        *slot = mult_r(*slot, att);
    }
    mode
}

/// The inter-frame smoothing of [`para_pred_bws`] against `prev_SWB_fenv_fx`, with the
/// `attenu_fx` ramp.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
fn para_pred_bws_smooth(st: &mut DecoderState, swb_fenv: &mut [i16], coder_type: i16) {
    let ener_lh_stable = l_sub(st.ener_lh, l_shr(st.prev_ener_lh, 1)) > 0
        && l_sub(l_shr(st.ener_lh, 1), st.prev_ener_lh) < 0;
    let ener_ll_stable = l_sub(st.ener_ll, l_shr(st.prev_ener_ll, 1)) > 0
        && l_sub(l_shr(st.ener_ll, 1), st.prev_ener_ll) < 0;
    let n = SWB_FENV as usize;
    if sub(st.last_core, HQ_CORE) != 0
        && sub(st.last_codec_mode, MODE1) == 0
        && ener_lh_stable
        && ener_ll_stable
    {
        for i in 0..n {
            if sub(st.prev_coder_type, coder_type) != 0
                && sub(mult_r(swb_fenv[i], 16384), st.prev_swb_fenv[i]) > 0
            {
                swb_fenv[i] =
                    round_word(l_mac(l_mult(swb_fenv[i], 3277), st.prev_swb_fenv[i], 29491));
            } else {
                swb_fenv[i] = round_word(l_mac(
                    l_mult(swb_fenv[i], st.attenu),
                    st.prev_swb_fenv[i],
                    sub(32767, st.attenu),
                ));
            }
        }
        if sub(st.attenu, 29491) < 0 {
            st.attenu = add(st.attenu, 1638);
        }
    } else {
        if l_sub(st.core_brate, st.last_core_brate) != 0 || ener_lh_stable || ener_ll_stable {
            for i in 0..n {
                if sub(mult_r(swb_fenv[i], 16384), st.prev_swb_fenv[i]) > 0 {
                    swb_fenv[i] = st.prev_swb_fenv[i];
                }
            }
        }
        for i in 0..n {
            swb_fenv[i] = round_word(l_mac(l_mult(swb_fenv[i], 29491), st.prev_swb_fenv[i], 3277));
        }
        st.attenu = 3277;
    }
}

/// `2^x` of a log-domain envelope value `l_tmp` (Q16), as the Q`(exp + q_out)` mantissa the
/// gain dequantisers below all compute the same way.
fn pow2_q16(l_tmp: i32, q: i16, shift: i16) -> i16 {
    let (exp, frac) = l_extract_lc(l_tmp); // Extract exponent of L_tmp
    let tmp = extract_l(pow2(q, frac));
    let exp = sub(exp, q);
    shl(tmp, add(exp, shift))
}

/// `WB_BWE_gain_deq_fx`: dequantise the two WB BWE envelope values `wb_fenv[0..2]` (Q3).
/// Returns the mode (`NORMAL` or `HARMONIC`).
pub fn wb_bwe_gain_deq(st: &mut DecoderState, wb_fenv: &mut [i16]) -> i16 {
    let index = get_next_indice(st, 5) as i16;
    let mode = add(extract_l(i32::from(get_next_indice(st, 1))), 2);

    // a 5-bit index: always inside the 64 entries of F_2_5_fx
    let index2 = shl(index, 1);
    let mut l_tmp = l_shr(i32::from(F_2_5_FX[index2 as usize]), 1);
    l_tmp = l_shl(l_tmp, 6);
    wb_fenv[0] = pow2_q16(l_tmp, 14, 3);

    let mut l_tmp = l_shr(i32::from(F_2_5_FX[add(index2, 1) as usize]), 1);
    l_tmp = l_shl(l_tmp, 6);
    wb_fenv[1] = pow2_q16(l_tmp, 14, 3);

    mode
}

/// `wb_bwe_dec_fx`: the WB bandwidth extension (6.4–8 kHz) of an ACELP frame, from the core
/// synthesis `synth` (Q`*qpost`, rescaled in place by the MDCT windowing) into `hb_synth`.
/// `*qpost` becomes the Q of the rescaled synthesis; returns the Q of `hb_synth`.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn wb_bwe_dec(
    synth: &mut [i16],
    hb_synth: &mut [i16],
    output_frame: i16,
    coder_type: i16,
    voice_factors: &[i16],
    pitch_buf: &[i16],
    st: &mut DecoderState,
    qpost: &mut i16,
) -> i16 {
    let mut wb_fenv = [0i16; SWB_FENV as usize];
    let mut ysynth = [0i16; FRAME_MAX];
    let mut l_wtda_synth = [0i32; 2 * FRAME_MAX];
    let mut ysynth_32 = [0i32; FRAME_MAX];
    let mut t_audio32_tmp = [0i32; FRAME_MAX];
    let mut q_syn_hb: i16 = 0;

    // MDCT of the core synthesis signal
    let mut new_input_fx_exp = *qpost;
    wtda(
        synth,
        0,
        &mut new_input_fx_exp,
        &mut l_wtda_synth,
        Some(&mut st.l_old_wtda_swb[..]),
        &mut st.old_wtda_swb_fx_exp,
        ALDO_WINDOW,
        ALDO_WINDOW, // window overlap of current frame (0: full, 2: none, or 3: half)
        output_frame,
    );
    *qpost = sub(new_input_fx_exp, 15);
    // DCT of the ACELP core synthesis
    direct_transform(
        &l_wtda_synth,
        &mut ysynth_32,
        0,
        output_frame,
        &mut new_input_fx_exp,
    );

    // Convert to 16 Bits (Calc Shift Required to Stay within MAX_Q_NEW_INPUT)
    let mut q_syn = wb_bwe_dec_to_16(&ysynth_32, &mut ysynth, output_frame, new_input_fx_exp);

    let mode: i16;
    if st.bfi == 0 {
        if l_sub(st.total_brate, 13200) == 0 {
            // de-quantization
            mode = wb_bwe_gain_deq(st, &mut wb_fenv);
            st.last_wb_bwe_ener = mult_r(add(wb_fenv[0], wb_fenv[1]), 16384);
        } else {
            if sub(st.last_extl, WB_BWE) != 0 {
                st.prev_swb_fenv[0] = 0;
            }
            mode = wb_bwe_gain_pred(
                &mut wb_fenv,
                &ysynth,
                coder_type,
                st.prev_coder_type,
                st.prev_swb_fenv[0],
                voice_factors,
                pitch_buf,
                st.last_core_brate,
                st.last_wb_bwe_ener,
                q_syn,
                st.last_extl,
                st.tilt_wb,
            );
        }
    } else {
        // FEC
        mode = NORMAL;
        for i in 0..2 {
            wb_fenv[i] = mult_r(st.prev_swb_fenv[i], 24576);
        }
    }

    if sub(st.last_extl, WB_BWE) != 0 || st.bfi != 0 {
        st.prev_swb_fenv[..2].copy_from_slice(&wb_fenv[..2]);
    }

    let exp = norm_l(st.prev_energy_wb);
    if sub(add(st.prev_q_synth, exp), q_syn) > 0 {
        st.prev_energy_wb = l_shr(st.prev_energy_wb, sub(st.prev_q_synth, q_syn));
    } else {
        q_syn = add(st.prev_q_synth, exp);
        st.prev_energy_wb = l_shl(st.prev_energy_wb, exp);
    }

    wb_bwe_decoding(
        &ysynth,
        &mut wb_fenv,
        &mut ysynth_32,
        L_FRAME16K,
        mode,
        st.last_extl,
        &mut st.prev_energy_wb,
        &mut st.prev_swb_fenv,
        &mut st.prev_l_swb_norm,
        st.extl,
        coder_type,
        st.total_brate,
        &mut st.Seed,
        &mut st.prev_flag,
        st.prev_coder_type,
        q_syn,
        &mut q_syn_hb,
    );

    // Inverse MDCT
    if l_sub(st.output_fs, 32000) == 0 {
        ysynth_32[320..640].fill(0);
    } else if l_sub(st.output_fs, 48000) == 0 {
        ysynth_32[320..960].fill(0);
    }

    inverse_transform(
        &ysynth_32,
        &mut q_syn_hb,
        &mut t_audio32_tmp,
        0,
        output_frame,
        output_frame,
    );
    window_ola(
        &t_audio32_tmp,
        hb_synth,
        &mut q_syn_hb,
        &mut st.mem_imdct,
        &mut st.mem_imdct_exp,
        output_frame,
        ALDO_WINDOW,
        ALDO_WINDOW,
        0,
        0,
        None,
    );

    st.prev_mode = mode;
    st.prev_q_synth = q_syn;
    q_syn_hb
}

/// The 32 → 16-bit conversion of the core MDCT shared by the BWE decoders: upscale as far as the
/// spectrum allows but no higher than Q`MAX_Q_NEW_INPUT`. Returns the Q of `ysynth`.
fn wb_bwe_dec_to_16(
    ysynth_32: &[i32],
    ysynth: &mut [i16],
    output_frame: i16,
    new_input_fx_exp: i16,
) -> i16 {
    let mut scl = sub(16 + MAX_Q_NEW_INPUT, new_input_fx_exp);
    // Possible to Upscale?
    if scl > 0 {
        // Yes: calc room to upscale, staying within MAX_Q_NEW_INPUT
        let q_syn = find_max_norm32(ysynth_32, output_frame);
        scl = q_syn.min(scl);
    }
    copy_scale_sig32_16(ysynth_32, ysynth, output_frame, scl);
    add(sub(new_input_fx_exp, 16), scl)
}

/// `swb_bwe_gain_deq_fx`: dequantise the SWB BWE envelopes: `swb_tenv[0..SWB_TENV]` (Q0) and
/// `swb_fenv[0..SWB_FENV_TRANS]` (Q1) of a transient ACELP frame, else `swb_fenv` (Q1) over
/// `SWB_FENV` bands (`SWB_FENV - 2` at high rate), plus `DIM_FB` more for `HQ_GEN_FB`, which
/// needs `swb_fenv` that long. Returns the BWE class.
pub fn swb_bwe_gain_deq(
    st: &mut DecoderState,
    core: i16,
    swb_tenv: &mut [i16],
    swb_fenv: &mut [i16],
    hr_flag: i16,
    hqswb_clas: i16,
) -> i16 {
    let mut mode: i16;
    if hqswb_clas > 0 {
        mode = get_next_indice(st, 1) as i16;
        if mode == 0 {
            mode = get_next_indice(st, 1) as i16;
        } else {
            mode = HQ_GENERIC_SP_EXC;
        }
    } else {
        mode = get_next_indice(st, 2) as i16;
    }

    // mode 1 = TRANSIENT
    if sub(mode, 1) == 0 && sub(core, ACELP_CORE) == 0 {
        swb_bwe_gain_deq_transient(st, swb_tenv, swb_fenv);
    } else {
        swb_bwe_gain_deq_normal(st, swb_fenv, hr_flag, hqswb_clas);
    }
    mode
}

/// The `TRANSIENT` ACELP branch of [`swb_bwe_gain_deq`]: four time-envelope exponents and the
/// four-band frequency envelope.
fn swb_bwe_gain_deq_transient(st: &mut DecoderState, swb_tenv: &mut [i16], swb_fenv: &mut [i16]) {
    let mut indice = [0i16; 6];
    let mut quant_tmp = [0i16; SWB_FENV as usize / 2];

    for slot in swb_tenv.iter_mut().take(SWB_TENV as usize) {
        let index = get_next_indice(st, 4) as i16;
        *slot = shl(1, index);
    }

    indice[0] = get_next_indice(st, 7) as i16;
    indice[1] = get_next_indice(st, 6) as i16;

    // 7- and 6-bit indices: inside Env_TR_Cdbk1_fx (128 x DIM_TR1) and Env_TR_Cdbk2_fx (64 x DIM_TR2)
    let tmp = shl(indice[0], 1);
    for n_band in 0..DIM_TR1 {
        quant_tmp[2 * n_band as usize] = ENV_TR_CDBK1_FX[add(tmp, n_band) as usize];
    }

    // DIM_TR2 = 2 entries per row
    let tmp = shl(indice[1], 1);
    quant_tmp[1] = add(
        shr(add(quant_tmp[0], quant_tmp[2]), 1),
        ENV_TR_CDBK2_FX[tmp as usize],
    );
    quant_tmp[3] = add(quant_tmp[2], ENV_TR_CDBK2_FX[add(tmp, 1) as usize]);

    for n_band in 0..SWB_FENV_TRANS as usize {
        let tmp = add(quant_tmp[n_band], MEAN_ENV_TR_FX[n_band]); // Q8

        let mut l_tmp = l_mult(tmp, 21771); // 0.0830482 in Q18 -> Q27
        l_tmp = l_shr(l_tmp, 11); // From Q27 to Q16
        swb_fenv[n_band] = pow2_q16(l_tmp, 13, 1);
    }

    // in case of band-width switching, attenuate frame gain
    if st.bws_cnt1 > 0 {
        let tmp = i_mult(st.bws_cnt1, 1638);
        for slot in swb_tenv.iter_mut().take(SWB_TENV as usize) {
            *slot = mult_r(*slot, tmp);
        }
        for slot in swb_fenv.iter_mut().take(SWB_FENV_TRANS as usize) {
            *slot = mult_r(*slot, tmp);
        }
    }
}

/// The non-transient branch of [`swb_bwe_gain_deq`]: the multi-stage split VQ of the
/// frequency envelope.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
fn swb_bwe_gain_deq_normal(
    st: &mut DecoderState,
    swb_fenv: &mut [i16],
    hr_flag: i16,
    hqswb_clas: i16,
) {
    let mut indice = [0i16; 6];
    let mut quant_tmp = [0i16; SWB_FENV as usize / 2];
    let mut quant_tmp2 = [0i16; SWB_FENV as usize / 2];
    let mut nb_bits = [0i16; 6];

    nb_bits[0] = 5;
    nb_bits[1] = 7;
    nb_bits[2] = 6;
    nb_bits[3] = 5;

    let nenv = if sub(hr_flag, 1) == 0 {
        nb_bits[4] = 5;
        SWB_FENV - 2
    } else {
        nb_bits[4] = 6;
        SWB_FENV
    };

    for n_band in 0..5 {
        indice[n_band] = get_next_indice(st, nb_bits[n_band]) as i16;
    }

    if sub(hqswb_clas, HQ_GEN_FB) == 0 {
        indice[5] = get_next_indice(st, 5) as i16;
    }

    // every index is at most as wide as its codebook has rows (5/7/6/5/6 bits against
    // 32/128/64/32/64 rows), so each copy stays inside its table
    let dim11 = DIM11 as usize;
    let dim1st = DIM1ST as usize;
    let dim3rd = DIM3RD as usize;
    let at = i_mult2(indice[0], DIM11) as usize;
    quant_tmp.copy_from_slice(&ENVCDBK11_FX[at..at + dim11]);
    let at = i_mult2(indice[1], DIM1ST) as usize;
    quant_tmp2[..dim1st].copy_from_slice(&ENVCDBK1ST_FX[at..at + dim1st]);
    let at = i_mult2(indice[2], DIM2ND) as usize;
    quant_tmp2[dim1st..].copy_from_slice(&ENVCDBK2ND_FX[at..at + DIM2ND as usize]);

    for n_band in 0..dim11 - 1 {
        quant_tmp[n_band] = add(quant_tmp[n_band], quant_tmp2[n_band]);
        swb_fenv[n_band * 2] = quant_tmp[n_band];
    }

    if sub(hr_flag, 1) == 0 {
        quant_tmp[6] = add(quant_tmp[6], quant_tmp2[6]);
        swb_fenv[11] = quant_tmp[6];

        let at = indice[3] as usize * dim3rd;
        quant_tmp2[..dim3rd].copy_from_slice(&ENVCDBK3RD_FX[at..at + dim3rd]);
        let at = indice[4] as usize * dim3rd;
        quant_tmp2[dim3rd..2 * dim3rd].copy_from_slice(&ENVCDBK3RD_FX[at..at + dim3rd]);

        for n_band in 0..5 {
            swb_fenv[n_band * 2 + 1] = add(
                shr(add(quant_tmp[n_band], quant_tmp[n_band + 1]), 1),
                quant_tmp2[n_band + 1],
            );
        }

        swb_fenv[0] = add(swb_fenv[0], quant_tmp2[0]);
    } else {
        quant_tmp[dim11 - 1] = add(quant_tmp[dim11 - 1], quant_tmp2[dim11 - 1]);
        swb_fenv[(dim11 - 1) * 2] = quant_tmp[dim11 - 1];

        let at = i_mult2(indice[3], DIM3RD) as usize;
        quant_tmp2[..dim3rd].copy_from_slice(&ENVCDBK3RD_FX[at..at + dim3rd]);
        let at = i_mult2(indice[4], DIM4TH) as usize;
        quant_tmp2[dim3rd..].copy_from_slice(&ENVCDBK4TH_FX[at..at + DIM4TH as usize]);

        let dim12 = DIM12 as usize;
        for n_band in 0..dim12 - 1 {
            swb_fenv[n_band * 2 + 1] = add(
                shr(add(quant_tmp[n_band], quant_tmp[n_band + 1]), 1),
                quant_tmp2[n_band],
            );
        }
        let n_band = dim12 - 1;
        swb_fenv[n_band * 2 + 1] = add(quant_tmp[n_band], quant_tmp2[n_band]);
    }

    for n_band in 0..nenv as usize {
        let tmp = add(swb_fenv[n_band], MEAN_ENV_FX[n_band]); // Q8

        let mut l_tmp = l_mult(tmp, 21771); // 0.166096 in Q17 -> Q26
        l_tmp = l_shr(l_tmp, 10); // From Q26 to Q16
                                  // Pow2() with 13 as exponent: 16384 < Pow2() <= 32767
        swb_fenv[n_band] = pow2_q16(l_tmp, 13, 1);
    }

    if sub(hqswb_clas, HQ_GEN_FB) == 0 {
        let dim_fb = DIM_FB as usize;
        let nenv = nenv as usize;
        let at = i_mult2(indice[5], DIM_FB) as usize;
        swb_fenv[nenv..nenv + dim_fb].copy_from_slice(&ENVCDBKFB_FX[at..at + dim_fb]); // Q7
        for n_band in 0..dim_fb {
            let tmp = add(swb_fenv[n_band + nenv], MEAN_ENV_FB_FX[n_band]);
            let mut l_tmp = l_mult(tmp, 21771); // 0.166096 in Q17 -> Q25
            l_tmp = l_shr(l_tmp, 9); // From Q25 to Q16
            swb_fenv[n_band + nenv] = pow2_q16(l_tmp, 13, 1);
        }
    }
}
