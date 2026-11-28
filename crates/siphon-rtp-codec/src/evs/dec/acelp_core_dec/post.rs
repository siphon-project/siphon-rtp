//! The post-processing of the synthesis of `acelp_core_dec_fx`: the narrowband post-filter, the
//! de-emphasis and AGC un-scaling, the wideband formant post-filter and the comfort noise
//! addition.

use super::frame::pitch_buf_for_scaling;
use super::{CoreWork, SYN_AT};
use crate::evs::cnst::{
    ACELP_24K40, ACELP_32K, ACELP_CORE, AMR_WB_CORE, AUDIO, FD_CNG, INACTIVE, LP_CNG, L_FRAME,
    L_FRAME16K, L_SUBFR, L_SYN_MEM, M, NB, NB_SUBFR16K, SID_2K40, WB,
};
use crate::evs::com::deemph::deemph;
use crate::evs::com::residu::residu3;
use crate::evs::com::syn_filt::e_util_synthesis;
use crate::evs::com::tools::{copy_scale_sig, set16};
use crate::evs::dec::dec_post::{blend_subfr2, formant_post_filt, nb_post_filt, scale_st};
use crate::evs::dec::fd_cng_dec::{
    apply_fd_cng, generate_masking_noise, noisy_speech_detection, CldfbBuffers,
};
use crate::evs::dec::state::{DecoderState, FdCngDec};
use crate::evs::dec::syn_outp::unscale_agc;
use crate::itu::basic_ops::{add, l_shl, l_sub, mult_r, round_word, shr_r, sub};

/// The part of `acelp_core_dec_fx` between the good / bad frame branches and the resampling.
pub(super) fn post_process(
    st: &mut DecoderState,
    w: &mut CoreWork,
    coder_type: i16,
    pitch_buf: &[i16],
) {
    let l_frame = st.l_frame;
    let frame = l_frame as usize;

    if sub(l_frame, L_FRAME) == 0 {
        st.cur_sub_aq
            .copy_from_slice(&w.aq[2 * (M as usize + 1)..3 * (M as usize + 1)]);
    } else {
        st.cur_sub_aq
            .copy_from_slice(&w.aq[3 * (M as usize + 1)..4 * (M as usize + 1)]);
    }

    // Apply the NB postfilter in case of 8 kHz output
    if sub(st.last_bwidth, NB) == 0 {
        let mut pitch_buf_tmp = [0i16; NB_SUBFR16K as usize];
        pitch_buf_for_scaling(pitch_buf, l_frame, &mut pitch_buf_tmp);

        if sub(st.bwidth, NB) == 0 {
            st.pfstat.on = 1;
            nb_post_filt(
                l_frame,
                &mut st.pfstat,
                &mut st.psf_lp_noise,
                w.tmp_noise,
                &mut w.syn_fx_tmp[SYN_AT..],
                &w.aq,
                &pitch_buf_tmp,
                coder_type,
                st.ber_detect,
                0,
            );
        } else {
            st.pfstat.on = 0;
            nb_post_filt(
                l_frame,
                &mut st.pfstat,
                &mut st.psf_lp_noise,
                w.tmp_noise,
                &mut w.syn_fx_tmp[SYN_AT..],
                &w.aq,
                &pitch_buf_tmp,
                AUDIO,
                st.ber_detect,
                0,
            );
        }
    } else {
        st.psf_lp_noise = round_word(l_shl(st.lp_noise, 1));
    }

    // Perform the fixed de-emphasis through 1/(1 - g*z^-1)

    // Update the old synthesis buffer - needed for the ACELP internal sampling rate switching
    let from = SYN_AT + frame - L_SYN_MEM as usize;
    st.mem_syn_r
        .copy_from_slice(&w.syn_fx_tmp[from..from + L_SYN_MEM as usize]);
    deemph(
        &mut w.syn_fx_tmp[SYN_AT..],
        st.preemph_fac,
        l_frame,
        &mut st.mem_deemph,
    );

    let mut syn_fx_tmp2 = [0i16; L_FRAME16K as usize];
    unscale_agc(
        &w.syn_fx_tmp[SYN_AT..],
        st.q_syn,
        &mut syn_fx_tmp2,
        &mut st.agc_mem,
        l_frame,
    );
    w.syn_fx_tmp[SYN_AT..SYN_AT + frame].copy_from_slice(&syn_fx_tmp2[..frame]);

    // Update the MODE2 memories
    let half = frame / 2;
    copy_scale_sig(
        &w.syn_fx_tmp[SYN_AT + half..],
        &mut st.old_syn_overl,
        l_frame / 2,
        sub(-1, st.q_syn),
    ); // Q-1
    copy_scale_sig(
        &w.syn_fx_tmp[SYN_AT + frame - M as usize - 1..],
        &mut st.syn,
        M + 1,
        sub(0, st.q_syn),
    ); // Q0

    formant_post_filter(st, w);
    comfort_noise_addition(st, w, coder_type);
}

/// The wideband formant post-filter of the high rates, or the fade-out of the post-filter memory
/// in the first subframe when it was on in the previous frame.
fn formant_post_filter(st: &mut DecoderState, w: &mut CoreWork) {
    let syn_fx = SYN_AT;
    if sub(st.last_bwidth, WB) >= 0
        && l_sub(st.core_brate, i32::from(ACELP_24K40)) > 0
        && l_sub(st.core_brate, i32::from(ACELP_32K)) <= 0
    {
        let mut temp_buf = [0i16; L_FRAME16K as usize + L_SYN_MEM as usize];
        let memory = L_SYN_MEM as usize;
        temp_buf[memory..memory + L_FRAME16K as usize]
            .copy_from_slice(&w.syn_fx_tmp[syn_fx..syn_fx + L_FRAME16K as usize]);
        st.pfstat.on = 1;
        formant_post_filt(
            &mut st.pfstat,
            &mut temp_buf,
            memory,
            &w.aq,
            &mut w.syn_fx_tmp[syn_fx..],
            L_FRAME16K,
            st.lp_noise,
            st.total_brate,
            0,
        );
    } else if sub(st.last_bwidth, WB) >= 0 {
        if st.pfstat.on != 0 {
            let order = M as usize;
            let subframe = L_SUBFR as usize;
            let mut temp_buf = [0i16; L_FRAME16K as usize + L_SYN_MEM as usize];
            let memory = L_SYN_MEM as usize;
            temp_buf[..order].copy_from_slice(&st.pfstat.mem_pf_in[memory - order..memory]);
            temp_buf[order..order + subframe]
                .copy_from_slice(&w.syn_fx_tmp[syn_fx..syn_fx + subframe]);
            {
                let (head, tail) = temp_buf.split_at_mut(order + subframe);
                residu3(&w.aq, head, order, tail, L_SUBFR, 1);
            }
            {
                let (head, tail) = temp_buf.split_at_mut(order + subframe);
                e_util_synthesis(
                    1,
                    &w.aq,
                    &tail[..subframe],
                    &mut head[..subframe],
                    L_SUBFR,
                    &mut st.pfstat.mem_stp[memory - order..memory],
                    0,
                    M,
                );
            }
            scale_st(
                &w.syn_fx_tmp[syn_fx..],
                &mut temp_buf,
                &mut st.pfstat.gain_prec,
                L_SUBFR,
            );
            w.syn_fx_tmp[syn_fx..syn_fx + subframe / 2].copy_from_slice(&temp_buf[..subframe / 2]);
            // blend_subfr2( temp_buf + L_SUBFR/2, syn_fx + L_SUBFR/2, syn_fx + L_SUBFR/2 ): the
            // output aliases the second input
            let mut second = [0i16; L_SUBFR as usize / 2];
            second.copy_from_slice(&w.syn_fx_tmp[syn_fx + subframe / 2..syn_fx + subframe]);
            blend_subfr2(
                &temp_buf[subframe / 2..subframe],
                &second,
                &mut w.syn_fx_tmp[syn_fx + subframe / 2..syn_fx + subframe],
            );
        }
        st.pfstat.on = 0;
    }
}

/// Comfort noise addition: the noisy-speech detector, the FD-CNG noise estimate and the masking
/// noise (CNA), and the fade-in of the previous frame's CNA overlap.
fn comfort_noise_addition(st: &mut DecoderState, w: &mut CoreWork, coder_type: i16) {
    let l_frame = st.l_frame;
    let syn_fx = SYN_AT;

    if st.flag_cna != 0
        || (sub(st.cng_type, FD_CNG) == 0 && l_sub(st.total_brate, i32::from(ACELP_32K)) <= 0)
        || (sub(st.cng_type, LP_CNG) == 0 && l_sub(st.total_brate, i32::from(SID_2K40)) <= 0)
    {
        // VAD only for a non-inactive frame
        st.vad = i8::from(st.vad != 0 && coder_type != INACTIVE);

        // Noisy speech detector
        if let Some(mut fd) = st.h_fd_cng_dec.take() {
            let FdCngDec {
                h_fd_cng_com,
                ms_noise_est,
                ms_noise_est_exp,
                psize_shaping_norm,
                psize_shaping_norm_exp,
                n_ff_tpart_shaping,
                lp_noise,
                lp_speech,
                ..
            } = &mut *fd;
            if let Some(com) = h_fd_cng_com.as_mut() {
                noisy_speech_detection(
                    i16::from(st.vad),
                    &w.syn_fx_tmp[syn_fx..],
                    l_frame,
                    st.q_syn,
                    ms_noise_est,
                    *ms_noise_est_exp,
                    psize_shaping_norm,
                    *psize_shaping_norm_exp,
                    *n_ff_tpart_shaping,
                    lp_noise,
                    lp_speech,
                    &mut com.flag_noisy_speech,
                );

                com.likelihood_noisy_speech = mult_r(com.likelihood_noisy_speech, 32440); // 0.99 Q15
                if com.flag_noisy_speech != 0 {
                    com.likelihood_noisy_speech = add(com.likelihood_noisy_speech, 328);
                    // 0.01 Q15
                }
            }
            st.lp_noise = *lp_noise;
            st.h_fd_cng_dec = Some(fd);
        }

        // Noise estimate
        let is_music = i16::from(sub(coder_type, AUDIO) == 0 && st.gsc_noisy_speech == 0);
        apply_fd_cng(
            &w.syn_fx_tmp[syn_fx..],
            st.q_syn,
            Some(CldfbBuffers {
                real: &mut w.real_buffer,
                imag: &mut w.imag_buffer,
                scale: None,
            }),
            st.m_frame_type,
            st,
            0,
            is_music,
        );

        // CNA: generate additional comfort noise to mask potential coding artefacts
        if st.flag_cna != 0 && sub(coder_type, AUDIO) != 0 {
            if let Some(mut fd) = st.h_fd_cng_dec.take() {
                let FdCngDec {
                    h_fd_cng_com,
                    olap_buffer_synth2,
                    ..
                } = &mut *fd;
                if let Some(com) = h_fd_cng_com.as_mut() {
                    let frame_size = com.frame_size;
                    generate_masking_noise(
                        &mut w.syn_fx_tmp[syn_fx..],
                        st.q_syn,
                        com,
                        olap_buffer_synth2,
                        frame_size,
                        0,
                    );
                }
                st.h_fd_cng_dec = Some(fd);
            }
        } else if st.flag_cna != 0
            && coder_type == AUDIO
            && st.last_core == ACELP_CORE
            && st.last_coder_type != AUDIO
        {
            if let Some(fd) = st.h_fd_cng_dec.as_ref() {
                if let Some(com) = fd.h_fd_cng_com.as_ref() {
                    let at = com.olap_buffer_synth2.unwrap_or(0);
                    let frame_size = com.frame_size;
                    for i in 0..(frame_size / 2).max(0) as usize {
                        let index = at + i + 5 * frame_size as usize / 4;
                        w.syn_fx_tmp[syn_fx + i] = add(
                            w.syn_fx_tmp[syn_fx + i],
                            shr_r(
                                mult_r(fd.olap_buffer_synth2[index], com.fftlen_fac),
                                -st.q_syn,
                            ),
                        );
                    }
                }
            }
        }
    }

    if st.flag_cna == 0
        && sub(l_frame, L_FRAME16K) == 0
        && st.last_flag_cna == 1
        && ((st.last_core == ACELP_CORE && st.last_coder_type != AUDIO)
            || st.last_core == AMR_WB_CORE)
    {
        if let Some(fd) = st.h_fd_cng_dec.as_ref() {
            if let Some(com) = fd.h_fd_cng_com.as_ref() {
                let at = com.olap_buffer_synth2.unwrap_or(0);
                for i in 0..(l_frame / 2) as usize {
                    let index = at + i + 5 * l_frame as usize / 4;
                    w.syn_fx_tmp[syn_fx + i] = add(
                        w.syn_fx_tmp[syn_fx + i],
                        shr_r(fd.olap_buffer_synth2[index], -st.q_syn),
                    );
                }
            }
        }
    }

    if st.flag_cna == 0 || sub(coder_type, AUDIO) == 0 {
        if let Some(fd) = st.h_fd_cng_dec.as_mut() {
            if let Some(com) = fd.h_fd_cng_com.as_ref() {
                let at = com.olap_buffer_synth2.unwrap_or(0);
                let fftlen = com.fftlen;
                set16(&mut fd.olap_buffer_synth2[at..], 0, fftlen);
            }
        }
    }
}
