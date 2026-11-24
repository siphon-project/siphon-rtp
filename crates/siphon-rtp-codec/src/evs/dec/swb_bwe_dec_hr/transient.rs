//! Transient-frame decoding of `swb_bwe_dec_hr_fx` (TS 26.442 `lib_dec/swb_bwe_dec_hr_fx.c`):
//! four time blocks, each with its own global gain, two-band envelope and AVQ-coded spectrum.

use super::{gain_dequant_hr, HrBranch, HrFrame, FULL_FB_COEFS, Q_32_BITS};
use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    BWE_HR_TRANS_EN_LIMIT1_FX_Q16, BWE_HR_TRANS_EN_LIMIT2_FX_Q16, BWE_HR_TRANS_EN_LIMIT3_FX_Q16,
    FB_BWE_HIGHRATE, L_FRAME32K, L_FRAME48K, MIN_GLOB_GAIN_BWE_HR_FX, NBITS_ENVELOPE_BWE_HR_TR,
    NBITS_GLOB_GAIN_BWE_HR, NBITS_HF_GAIN_BWE_HR, NSV_MAX, NSV_OVERLAP, NUM_ENVLOPE_CODE_HR_TR2,
    NUM_TIME_SWITCHING_BLOCKS, NUM_TRANS_END_FREQ_COEF, NUM_TRANS_END_FREQ_COEF_EFF,
    NUM_TRANS_START_FREQ_COEF, N_BANDS_TRANS_BWE_HR, SWB_BWE_HIGHRATE, WIDTH_BAND,
    WIDTH_TRANS_FREQ_COEF,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::swb_bwe_com_hr::swb_hr_noise_fill;
use crate::evs::com::tools::{copy_scale_sig32_16, find_max_norm32};
use crate::evs::dec::avq_dec::avq_demuxdec;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{OVERLAP_COEFS_48KHZ_FX, OVERLAP_COEFS_FX, SWB_HR_ENV_CODE3_FX};
use crate::itu::basic_ops::{add, l_mult, l_shl, l_shr, mult_r, round_word, shl, shr, sub};
use crate::itu::stl2009::{i_mult, l_mult0, mac_r};

const BAND: usize = WIDTH_BAND as usize;

/// `swb_bwe_dec_hr_fx` for a transient frame: decode the four time blocks into `t_audio32`
/// (Q`Q_32_BITS`) and save their coefficients for a later erasure. Returns the last block's gain
/// and envelope mean.
pub(super) fn swb_bwe_dec_hr_transient(
    st: &mut DecoderState,
    t_audio: &mut [i16],
    t_audio32: &mut [i32],
    frame: &HrFrame,
) -> HrBranch {
    let output_frame = frame.output_frame;
    let mut x_norm = [0i16; NSV_MAX as usize * (BAND + 1)];
    let mut nq = [0i16; NSV_MAX as usize];
    let mut en_band = [0i16; N_BANDS_TRANS_BWE_HR as usize];
    let mut gain_fx: i16 = 0;
    let mut env: i16 = 0;
    let mut ind2: i16 = 0;

    let mut nbits: i16 = -1; // is_transient flag
    let nbits_block = shr(frame.nbits_total, 2);
    nbits = add(nbits, frame.nbits_total & 3);

    // set width of noncoded (blind estimated) spectrum
    let (width_noncoded, tmp_s) =
        if sub(st.extl, SWB_BWE_HIGHRATE) == 0 || sub(output_frame, L_FRAME32K) == 0 {
            (
                L_FRAME32K / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_END_FREQ_COEF,
                L_FRAME32K / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_END_FREQ_COEF_EFF,
            )
        } else {
            // st->extl == FB_BWE_HIGHRATE
            (
                FULL_FB_COEFS / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_END_FREQ_COEF,
                FULL_FB_COEFS / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_END_FREQ_COEF_EFF,
            )
        };

    // transient frames: processing in blocks (subframes)
    let mut len: i16 = 0;
    for k in 0..NUM_TIME_SWITCHING_BLOCKS {
        nbits = add(nbits, nbits_block);

        // global gain and envelope decoding

        // get global gain
        let mut ind1 = get_next_indice(st, NBITS_GLOB_GAIN_BWE_HR) as i16;
        let mut exp1: i16 = 0;
        gain_fx = gain_dequant_hr(
            ind1,
            MIN_GLOB_GAIN_BWE_HR_FX,
            NBITS_GLOB_GAIN_BWE_HR,
            &mut exp1,
        );
        nbits = sub(nbits, NBITS_GLOB_GAIN_BWE_HR);

        // get energy per band
        if k == 0 {
            ind1 = get_next_indice(st, NBITS_ENVELOPE_BWE_HR_TR) as i16;
            ind2 = ind1;
            nbits = sub(nbits, NBITS_ENVELOPE_BWE_HR_TR);
        } else {
            ind1 = get_next_indice(st, NBITS_ENVELOPE_BWE_HR_TR - 1) as i16;
            if sub(ind2, 8) >= 0 {
                ind1 = add(ind1, NUM_ENVLOPE_CODE_HR_TR2);
            }
            nbits = sub(nbits, NBITS_ENVELOPE_BWE_HR_TR - 1);
        }

        let temp = shl(ind1, 1) as usize;
        en_band[0] = SWB_HR_ENV_CODE3_FX[temp];
        en_band[1] = SWB_HR_ENV_CODE3_FX[temp + 1];

        // env = add(shr(en_band[0], 1), shr(en_band[1], 1));
        env = mac_r(l_mult(en_band[0], 16384), en_band[1], 16384);

        // estimate energy of noncoded spectrum (14.4-20kHz)
        let mut en_noncoded = en_band[(N_BANDS_TRANS_BWE_HR - 1) as usize];

        if sub(st.extl, FB_BWE_HIGHRATE) == 0 {
            ind1 = get_next_indice(st, NBITS_HF_GAIN_BWE_HR) as i16;
            nbits = sub(nbits, NBITS_HF_GAIN_BWE_HR);

            if sub(ind1, 1) == 0 {
                en_noncoded = round_word(l_mult0(en_noncoded, BWE_HR_TRANS_EN_LIMIT1_FX_Q16));
            }
            if sub(ind1, 2) == 0 {
                en_noncoded = round_word(l_mult0(en_noncoded, BWE_HR_TRANS_EN_LIMIT2_FX_Q16));
            }
            if sub(ind1, 3) == 0 {
                en_noncoded = round_word(l_mult0(en_noncoded, BWE_HR_TRANS_EN_LIMIT3_FX_Q16));
            }
        }

        // AVQ decoding (dequantize normalized spectrum)
        let nsv = (NUM_TRANS_END_FREQ_COEF - NUM_TRANS_START_FREQ_COEF) / WIDTH_BAND;
        avq_demuxdec(st, &mut x_norm, &mut nbits, nsv, &mut nq);

        swb_bwe_dec_hr_transient_block(
            st,
            t_audio,
            t_audio32,
            frame,
            k,
            len,
            &x_norm,
            &nq,
            &en_band,
            en_noncoded,
            (gain_fx, exp1),
            (width_noncoded, tmp_s),
        );
        len = add(len, shr(output_frame, 2));
    }

    HrBranch {
        is_transient: 1,
        gain_fx,
        env,
    }
}

/// One block of [`swb_bwe_dec_hr_transient`] after the AVQ decode: dequantise, copy up the effective
/// spectrum, denormalise with the envelope, window, apply the global gain, save the coefficients
/// and attenuate on a bandwidth switch.
fn swb_bwe_dec_hr_transient_block(
    st: &mut DecoderState,
    t_audio: &mut [i16],
    t_audio32: &mut [i32],
    frame: &HrFrame,
    k: i16,
    len: i16,
    x_norm: &[i16],
    nq: &[i16],
    en_band: &[i16],
    en_noncoded: i16,
    (gain_fx, exp1): (i16, i16),
    (width_noncoded, tmp_s): (i16, i16),
) {
    let output_frame = frame.output_frame;
    let nsv = (NUM_TRANS_END_FREQ_COEF - NUM_TRANS_START_FREQ_COEF) / WIDTH_BAND;
    let mut temp = add(len, NUM_TRANS_START_FREQ_COEF);
    // 't_audio' in Q8
    let t_audio_exp: i16 = 8;
    for i in 0..(nsv * WIDTH_BAND) as usize {
        t_audio[temp as usize + i] = shl(x_norm[i], t_audio_exp);
    }

    // apply noise-fill
    swb_hr_noise_fill(
        1,
        NUM_TRANS_START_FREQ_COEF,
        NUM_TRANS_END_FREQ_COEF,
        round_word(l_shl(frame.l_tilt_wb, 3)), // Q(24+3-16) -> Q11
        frame.pitch,
        nq,
        nsv,
        &mut st.bwe_highrate_seed,
        &mut t_audio[temp as usize..],
        t_audio_exp,
    );

    // Go from Q't_audio_exp' on 16 Bits to 'Q_32_BITS' on 32 bits
    let temp2 = i_mult2(WIDTH_BAND, nsv);
    let j = shl(1, sub(Q_32_BITS, t_audio_exp));
    for i in 0..temp2 as usize {
        // put in 'Q_32_BITS' in a 32 Bits
        t_audio32[temp as usize + i] = l_mult0(t_audio[temp as usize + i], j);
    }

    // reconstruction
    temp = add(
        temp,
        NUM_TRANS_END_FREQ_COEF_EFF - NUM_TRANS_START_FREQ_COEF,
    );
    let pos = sub(temp, tmp_s);
    // reconstruct 14-16(20) kHz spectrum
    for j in 0..tmp_s as usize {
        t_audio32[temp as usize + j] = l_shr(t_audio32[pos as usize + j], 1);
    }

    temp = i_mult2(shr(output_frame, 2), k);

    let mut temp2 = add(NUM_TRANS_START_FREQ_COEF, temp);
    let mut at = temp2 as usize;
    // envelope denormalization
    for band in en_band.iter().take(N_BANDS_TRANS_BWE_HR as usize) {
        for _ in 0..WIDTH_TRANS_FREQ_COEF {
            let l_temp = mult_32_16(t_audio32[at], *band);
            t_audio32[at] = l_shl(l_temp, 6); // by 6 because 'en_band' is in Q9
            at += 1;
        }
    }

    temp2 = add(NUM_TRANS_END_FREQ_COEF_EFF, temp);
    let mut j = sub(tmp_s, width_noncoded);
    let mut at = add(temp2, j) as usize;
    // envelope denormalization of 14.4-16(20) kHz spectrum
    while j < tmp_s {
        let l_temp = mult_32_16(t_audio32[at], en_noncoded);
        t_audio32[at] = l_shl(l_temp, 6); // by 6 because 'en_noncoded' is in Q9
        at += 1;
        j += 1;
    }

    temp2 = add(NUM_TRANS_START_FREQ_COEF, temp);
    let mut at = temp2 as usize;
    let mut temp4 = i_mult2(NSV_OVERLAP, shr(WIDTH_BAND, 2));
    // overlap region
    let overlap: &[i16] = if sub(output_frame, L_FRAME48K) == 0 {
        &OVERLAP_COEFS_48KHZ_FX
    } else {
        &OVERLAP_COEFS_FX
    };
    for i in 0..temp4 {
        // overlap_coefs_fx in Q15
        t_audio32[at] = mult_32_16(t_audio32[at], overlap[shl(i, 2) as usize]);
        at += 1;
    }

    temp2 = add(NUM_TRANS_START_FREQ_COEF, temp);
    let mut at = temp2 as usize;
    temp4 = add(
        i_mult2(WIDTH_TRANS_FREQ_COEF, N_BANDS_TRANS_BWE_HR),
        width_noncoded,
    );
    let temp3 = sub(15, exp1);
    // apply global gain
    for _ in 0..temp4 {
        let l_temp = mult_32_16(t_audio32[at], gain_fx);
        t_audio32[at] = l_shl(l_temp, temp3);
        at += 1;
    }

    // save transform coefficients for the next frame (needed in case of frame erasures)
    temp = add(NUM_TRANS_START_FREQ_COEF, len);
    let pos = if output_frame == L_FRAME32K {
        L_FRAME32K / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_START_FREQ_COEF
    } else {
        // output_frame == L_FRAME48k
        FULL_FB_COEFS / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_START_FREQ_COEF
    };
    let temp4 = find_max_norm32(&t_audio32[temp as usize..], pos);
    let dest = i_mult2(k, pos) as usize;
    copy_scale_sig32_16(
        &t_audio32[temp as usize..],
        &mut st.t_audio_prev[dest..],
        pos,
        temp4,
    );
    st.t_audio_prev_fx_exp[k as usize] = add(Q_32_BITS, temp4);

    // attenuate HFs in case of band-width switching
    if st.bws_cnt1 > 0 {
        let mut temp = shr(output_frame, 2);
        temp = i_mult(k, temp);
        temp = add(NUM_TRANS_START_FREQ_COEF, temp);
        let temp2 = i_mult(st.bws_cnt1, 1638); // Q15

        let mut j = FULL_FB_COEFS / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_START_FREQ_COEF;
        if output_frame == L_FRAME32K {
            j = L_FRAME32K / NUM_TIME_SWITCHING_BLOCKS - NUM_TRANS_START_FREQ_COEF;
        }

        // `t_audio` is only read by the 32-bit conversion above, so this has no effect on the
        // output; it mirrors the reference.
        for i in 0..j as usize {
            t_audio[temp as usize + i] = mult_r(t_audio[temp as usize + i], temp2);
        }
    }
}
