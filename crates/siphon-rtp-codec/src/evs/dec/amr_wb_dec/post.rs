//! The post-processing of the synthesis of `amr_wb_dec_fx`: the narrowband post-filter, the
//! de-emphasis and AGC un-scaling, the wideband formant post-filter and the comfort noise
//! addition.

use super::{AmrWork, SYN_AT};
use crate::evs::cnst::{
    ACELP_CORE, AMR_WB_CORE, AUDIO, AUDIO_CLAS, INACTIVE, L_FRAME, L_FRAME8K, L_SYN_MEM, NB,
    NB_SUBFR,
};
use crate::evs::com::deemph::deemph;
use crate::evs::com::tools::copy_scale_sig;
use crate::evs::dec::dec_post::{formant_post_filt, nb_post_filt};
use crate::evs::dec::fd_cng_dec::{
    apply_fd_cng, generate_masking_noise, generate_masking_noise_update_seed,
    noisy_speech_detection,
};
use crate::evs::dec::state::{DecoderState, FdCngDec};
use crate::evs::dec::syn_outp::unscale_agc;
use crate::itu::basic_ops::{add, l_shl, mult_r, shr_r, sub};

/// The part of `amr_wb_dec_fx` between the good / bad frame branches and the resampling.
pub(super) fn post_process(st: &mut DecoderState, w: &mut AmrWork) {
    nb_post_filter(st, w);

    // Perform the fixed de-emphasis through 1/(1 - g*z^-1)

    // update the old synthesis buffer - needed for the ACELP internal sampling rate switching
    let from = SYN_AT + L_FRAME as usize - L_SYN_MEM as usize;
    st.mem_syn_r
        .copy_from_slice(&w.syn_tmp[from..from + L_SYN_MEM as usize]);

    deemph(
        &mut w.syn_tmp[SYN_AT..],
        crate::evs::cnst::PREEMPH_FAC,
        L_FRAME,
        &mut st.mem_deemph,
    );

    let mut syn_fx_tmp2 = [0i16; L_FRAME as usize];
    unscale_agc(
        &w.syn_tmp[SYN_AT..],
        st.q_syn,
        &mut syn_fx_tmp2,
        &mut st.agc_mem,
        L_FRAME,
    );
    w.syn_tmp[SYN_AT..].copy_from_slice(&syn_fx_tmp2);

    // TCX = Q-1, ACELP2 Q0
    let half = L_FRAME as usize / 2;
    copy_scale_sig(
        &w.syn_tmp[SYN_AT + half..],
        &mut st.old_syn_overl,
        L_FRAME / 2,
        sub(-1, st.q_syn),
    ); // Q_syn
    copy_scale_sig(
        &w.syn_tmp[SYN_AT + L_FRAME as usize - crate::evs::cnst::M as usize - 1..],
        &mut st.syn,
        crate::evs::cnst::M + 1,
        sub(0, st.q_syn),
    ); // Q0

    formant_post_filter(st, w);
    comfort_noise_addition(st, w);
}

/// The NB post-filter: in the 8 kHz output and after a narrowband frame, the pitch is the one of
/// the 12.8 kHz core (Q0 per subframe).
fn nb_post_filter(st: &mut DecoderState, w: &mut AmrWork) {
    if sub(w.output_frame, L_FRAME8K) == 0 || sub(st.last_bwidth, NB) == 0 {
        let mut pitch_buf_tmp = [0i16; NB_SUBFR as usize];
        for i in 0..NB_SUBFR as usize {
            pitch_buf_tmp[i] = mult_r(w.pitch_buf[i], 512);
        }
        if sub(w.output_frame, L_FRAME8K) == 0 {
            st.pfstat.on = 1;
            nb_post_filt(
                L_FRAME,
                &mut st.pfstat,
                &mut st.psf_lp_noise,
                w.tmp_noise,
                &mut w.syn_tmp[SYN_AT..],
                &w.aq,
                &pitch_buf_tmp,
                w.coder_type,
                st.ber_detect,
                0,
            );
        } else {
            st.pfstat.on = 0;
            nb_post_filt(
                L_FRAME,
                &mut st.pfstat,
                &mut st.psf_lp_noise,
                w.tmp_noise,
                &mut w.syn_tmp[SYN_AT..],
                &w.aq,
                &pitch_buf_tmp,
                AUDIO,
                st.ber_detect,
                0,
            );
        }
    }
}

/// The formant post-filter of the wideband output.
fn formant_post_filter(st: &mut DecoderState, w: &mut AmrWork) {
    let memory = L_SYN_MEM as usize;
    let mut tmp_buffer = [0i16; L_FRAME as usize + L_SYN_MEM as usize];
    tmp_buffer[memory..].copy_from_slice(&w.syn_tmp[SYN_AT..]);
    if sub(w.output_frame, L_FRAME8K) != 0 && sub(st.last_bwidth, NB) != 0 {
        st.pfstat.on = 1;
        formant_post_filt(
            &mut st.pfstat,
            &mut tmp_buffer,
            memory,
            &w.aq,
            &mut w.syn_tmp[SYN_AT..],
            L_FRAME,
            l_shl(i32::from(st.psf_lp_noise), 15),
            st.total_brate,
            i16::from(sub(w.amr_io_class, AUDIO_CLAS) == 0),
        );
    }
}

/// Comfort noise addition: the noisy-speech detector, the FD-CNG noise estimate and the masking
/// noise (CNA), and the fade-in of the previous frame's CNA overlap.
fn comfort_noise_addition(st: &mut DecoderState, w: &mut AmrWork) {
    w.flag_cna = 0;
    if sub(st.psf_lp_noise, 15 << 8) >= 0 || w.coder_type == INACTIVE {
        // VAD only for a non-inactive frame
        st.vad = i8::from(st.vad == 1 && sub(w.coder_type, INACTIVE) != 0);
        apply_fd_cng(
            &w.syn_tmp[SYN_AT..],
            st.q_syn,
            None,
            st.m_frame_type,
            st,
            0,
            0,
        );

        if let Some(com) = st
            .h_fd_cng_dec
            .as_mut()
            .and_then(|fd| fd.h_fd_cng_com.as_mut())
        {
            com.frame_type_previous = st.m_frame_type;
        }

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
                    &w.syn_tmp[SYN_AT..],
                    L_FRAME,
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

        if st.flag_cna != 0 && sub(st.psf_lp_noise, 15 << 8) >= 0 {
            w.flag_cna = 1;
            if let Some(mut fd) = st.h_fd_cng_dec.take() {
                let FdCngDec {
                    h_fd_cng_com,
                    olap_buffer_synth2,
                    ..
                } = &mut *fd;
                if let Some(com) = h_fd_cng_com.as_mut() {
                    let frame_size = com.frame_size;
                    generate_masking_noise(
                        &mut w.syn_tmp[SYN_AT..],
                        st.q_syn,
                        com,
                        olap_buffer_synth2,
                        frame_size,
                        AMR_WB_CORE,
                    );
                }
                st.h_fd_cng_dec = Some(fd);
            }
        } else if st.flag_cna != 0 {
            update_masking_seed(st);
        }
    } else if st.flag_cna != 0 {
        update_masking_seed(st);
    }

    if w.flag_cna == 0 {
        if sub(i16::from(st.last_flag_cna), 1) == 0
            && ((sub(st.last_core, ACELP_CORE) == 0 && sub(st.last_coder_type, AUDIO) != 0)
                || sub(st.last_core, AMR_WB_CORE) == 0)
        {
            if let Some(fd) = st.h_fd_cng_dec.as_ref() {
                if let Some(com) = fd.h_fd_cng_com.as_ref() {
                    let at = com.olap_buffer_synth2.unwrap_or(0);
                    for i in 0..(L_FRAME / 2) as usize {
                        let index = at + i + 5 * L_FRAME as usize / 4;
                        w.syn_tmp[SYN_AT + i] = add(
                            w.syn_tmp[SYN_AT + i],
                            shr_r(fd.olap_buffer_synth2[index], -st.q_syn),
                        );
                    }
                }
            }
        }
        if let Some(fd) = st.h_fd_cng_dec.as_mut() {
            if let Some(com) = fd.h_fd_cng_com.as_ref() {
                let at = com.olap_buffer_synth2.unwrap_or(0);
                crate::evs::com::tools::set16(
                    &mut fd.olap_buffer_synth2[at..],
                    0,
                    crate::itu::basic_ops::shl(L_FRAME, 1),
                );
            }
        }
    }
}

/// `generate_masking_noise_update_seed( st->hFdCngDec->hFdCngCom )`.
fn update_masking_seed(st: &mut DecoderState) {
    if let Some(com) = st
        .h_fd_cng_dec
        .as_mut()
        .and_then(|fd| fd.h_fd_cng_com.as_mut())
    {
        generate_masking_noise_update_seed(com);
    }
}
