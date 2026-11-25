//! A good frame (comfort noise or an active frame) and a bad frame of `acelp_core_dec_fx`.

use super::{CoreWork, BWE_EXC_AT, EXC2_AT, EXC_AT, SYN_AT};
use crate::evs::cnst::{
    ACELP_11K60, ACELP_24K40, ACELP_32K, ACELP_7K20, ACELP_8K00, AUDIO, DCT_L_POST, FRAME_NO_DATA,
    GENERIC, HQ_CORE, INACTIVE, INACTIVE_CLAS, LP_CNG, L_EXC_MEM, L_FRAME, L_FRAME16K, L_FRAME32K,
    L_SUBFR, L_SYN_MEM_CLAS_ESTIM, M, MAX_LT, MODE1, NB_SUBFR16K, OFFSET2, ONSET, SID_2K40,
    SIN_ONSET, TRANSITION, UNVOICED, VOICED, VOICED_CLAS, VOICED_TRANSITION,
};
use crate::evs::com::cng_exc::cng_exc;
use crate::evs::com::fd_cng_com::fd_cng_exc;
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::gs_inact_switching::inac_swtch_ematch;
use crate::evs::com::int_lsp::int_lsp4;
use crate::evs::com::lsf_dec_bfi::lsf_dec_bfi;
use crate::evs::com::lsf_tools::lsp2lsf;
use crate::evs::com::scale_mem::{rescale_exc, rescale_mem};
use crate::evs::com::stat_noise_uv_mod::stat_noise_uv_mod;
use crate::evs::com::swb_bwe_com::save_old_syn;
use crate::evs::com::syn_12k8::syn_12k8;
use crate::evs::com::tools::{copy_scale_sig, scale_sig};
use crate::evs::dec::cng_dec::cng_dec;
use crate::evs::dec::dec_gen_voic::decod_gen_voic;
use crate::evs::dec::dec_nelp::decod_nelp;
use crate::evs::dec::dec_ppp::decod_ppp;
use crate::evs::dec::dec_tran::decod_tran;
use crate::evs::dec::dec_uv::decod_unvoiced;
use crate::evs::dec::fd_cng_dec::{fd_cng_decode_sid, generate_comfort_noise_dec};
use crate::evs::dec::fec::fec_exc_estim;
use crate::evs::dec::fec_adapt_codebook::{fec_enh_acb, fec_sin_onset};
use crate::evs::dec::fec_clas_estim::{fec_clas_estim, fec_pos_dec};
use crate::evs::dec::fec_lsf_estim::fec_lsf2lsp_interp;
use crate::evs::dec::fec_pitch_estim::fec_pitch_estim;
use crate::evs::dec::fec_scale_syn::{fec_scale_syn, FecScaleSynParams, FecScaleSynState};
use crate::evs::dec::gain_dec::es_pred_dec;
use crate::evs::dec::gs_dec::decod_audio;
use crate::evs::dec::ld_music_post_filter::{
    ld_music_post_filter, post_music_post_p, prep_music_post_p, LdMusicState, PostMusicMemories,
};
use crate::evs::dec::lsf_dec::lsf_dec;
use crate::evs::dec::stat_noise_uv_dec::stat_noise_uv_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::transition_dec::tc_classif;
use crate::itu::basic_ops::{
    add, l_deposit_h, l_mac, l_shl, l_sub, mult, mult_r, round_word, shr, shr_r, sub,
};

/// `acelp_core_dec_fx`'s `GOOD frame` branch.
pub(super) fn good_frame(
    st: &mut DecoderState,
    w: &mut CoreWork,
    coder_type: i16,
    sharp_flag: i16,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    old_syn_12k8_16k: &mut [i16],
    unbits: &mut i16,
    sid_bw: &mut i16,
) {
    // Decoding of the TC subframe classification
    w.tc_subfr = -1;
    if sub(coder_type, TRANSITION) == 0 {
        let l_frame = st.l_frame;
        w.tc_subfr = tc_classif(st, l_frame);
    }

    // Decoding of the inactive CNG frames
    if st.core_brate == i32::from(FRAME_NO_DATA) || l_sub(st.core_brate, i32::from(SID_2K40)) == 0 {
        good_frame_cng(st, w, pitch_buf, voice_factors, old_syn_12k8_16k, sid_bw);
    } else {
        // Decoding of all other frames
        good_frame_active(
            st,
            w,
            coder_type,
            sharp_flag,
            pitch_buf,
            voice_factors,
            old_syn_12k8_16k,
            unbits,
        );
    }
}

/// The comfort-noise parameters and excitation of an inactive frame (`FRAME_NO_DATA` or SID):
/// LP-CNG (`CNG_dec_fx`, `CNG_exc_fx`) or FD-CNG (`FdCng_exc`), the excitation rescaling and the
/// synthesis of the noise.
fn good_frame_cng(
    st: &mut DecoderState,
    w: &mut CoreWork,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    old_syn_12k8_16k: &mut [i16],
    sid_bw: &mut i16,
) {
    let l_frame = st.l_frame;
    let frame = l_frame as usize;
    let mut allow_cn_step: i16 = 0;

    // decode the CNG parameters
    if sub(st.cng_type, LP_CNG) == 0 {
        let core_brate = st.core_brate;
        cng_dec(
            st,
            l_frame,
            &mut w.aq,
            core_brate,
            &mut w.lsp_new,
            &mut w.lsf_new,
            &mut allow_cn_step,
            sid_bw,
            &mut w.q_env,
        );

        // comfort noise generation
        cng_exc(
            st.core_brate,
            l_frame,
            &mut st.enew,
            &mut st.cng_seed,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            &mut st.lp_ener,
            st.last_core_brate,
            st.first_cng,
            &mut st.cng_ener_seed,
            &mut w.old_bwe_exc[BWE_EXC_AT..],
            allow_cn_step,
            &mut st.last_allow_cn_step,
            st.prev_q_exc,
            st.q_exc,
            st.num_ho,
            &w.q_env,
            &mut st.lp_env,
            &mut st.old_env,
            &mut st.exc_mem,
            &mut st.exc_mem1,
            *sid_bw,
            &mut st.cng_ener_seed1,
            &mut w.exc3,
            st.opt_amr_wb,
        );
    } else {
        if l_sub(st.core_brate, i32::from(SID_2K40)) == 0 {
            fd_cng_decode_sid(st);
            *sid_bw = 0;
        }

        generate_comfort_noise_dec(None, st, 2);

        let fd_cng_dec = st.h_fd_cng_dec.take();
        if let Some(com) = fd_cng_dec.as_ref().and_then(|fd| fd.h_fd_cng_com.as_ref()) {
            fd_cng_exc(
                com,
                &mut st.cng_mode,
                l_frame,
                &st.lsp_old,
                st.first_cng,
                &mut st.lsp_cng,
                &mut w.aq,
                &mut w.lsp_new,
                &mut w.lsf_new,
                &mut w.old_exc[EXC_AT..],
                &mut w.old_exc2[EXC2_AT..],
                &mut w.old_bwe_exc[BWE_EXC_AT..],
            );
        }
        st.h_fd_cng_dec = fd_cng_dec;

        w.exc3[..frame].copy_from_slice(&w.old_exc2[EXC2_AT..EXC2_AT + frame]);
    }

    let mut delta_mem_scale: i16 = 3;
    if l_sub(st.lp_ener, 40) < 0 && sub(st.cng_type, LP_CNG) == 0 {
        // very low energy frames, less than 0.3125
        delta_mem_scale = 0;
    }
    let i = st.q_exc;
    rescale_exc(
        Some(&mut st.dct_post_old_exc),
        &mut w.old_exc,
        EXC_AT,
        Some((&mut w.old_bwe_exc, BWE_EXC_AT)),
        Some(&mut st.last_exc_dct_in),
        l_frame,
        l_frame * 5 / 2, // L_frame * HIBND_ACB_L_FAC
        0,
        &mut st.q_exc,
        &mut st.q_subfr,
        None,
        0,
        INACTIVE,
    );

    rescale_mem(
        st.q_exc,
        &mut st.prev_q_syn,
        &mut st.q_syn,
        &mut st.mem_syn2,
        &mut st.mem_syn_clas_estim,
        delta_mem_scale,
        &mut st.mem_deemph,
        &mut st.pst_old_syn,
        &mut st.pst_mem_deemp_err,
        &mut st.agc_mem[1],
        &mut st.pfstat,
        0,
        0,
        None,
    );
    scale_sig(
        &mut w.old_exc2[EXC2_AT..EXC2_AT + frame],
        l_frame,
        sub(st.q_exc, i),
    );

    // update the past excitation signals for the LD music post-filter
    update_dct_post_old_exc(st, &w.old_exc2[EXC2_AT..]);

    // synthesis at the 12.8 kHz sampling rate
    syn_12k8(
        l_frame,
        &w.aq,
        &w.old_exc2[EXC2_AT..],
        &mut w.syn_fx_tmp[SYN_AT..],
        &mut st.mem_syn2,
        1,
        st.q_exc,
        st.q_syn,
    );
    syn_12k8(
        l_frame,
        &w.aq,
        &w.exc3,
        &mut w.syn1_fx_tmp[2..],
        &mut st.mem_syn3,
        1,
        st.q_exc,
        st.q_syn,
    );

    // reset the decoder
    crate::evs::dec::rst_dec::cng_reset_dec(st, pitch_buf, voice_factors);

    // update mem_syn1 for the ACELP core switching
    st.mem_syn1 = st.mem_syn3;

    // update the old synthesis for classification
    let from = 2 + frame - L_SYN_MEM_CLAS_ESTIM as usize;
    st.mem_syn_clas_estim
        .copy_from_slice(&w.syn1_fx_tmp[from..from + L_SYN_MEM_CLAS_ESTIM as usize]);

    // Update the music post-processing values: filter energies update
    update_filt_lfe(st, 1228);

    // save and delay the synthesis to be used by the SWB BWE
    copy_scale_sig(
        &w.syn1_fx_tmp[2..],
        &mut w.temp_buf_fx,
        l_frame,
        sub(-1, st.q_syn),
    );
    save_old_syn(
        l_frame,
        &w.temp_buf_fx,
        old_syn_12k8_16k,
        &mut st.old_syn_12k8_16k,
        st.preemph_fac,
        &mut st.mem_deemph_old_syn,
    );
}

/// `Copy( dct_post_old_exc + L_FRAME, dct_post_old_exc, DCT_L_POST - L_FRAME - OFFSET2 )` and
/// `Copy( exc2_fx, dct_post_old_exc + (DCT_L_POST - L_FRAME - OFFSET2), L_FRAME )`: slide the
/// past excitation of the LD music post-filter by one frame and append `exc2`.
pub(crate) fn update_dct_post_old_exc(st: &mut DecoderState, exc2: &[i16]) {
    let keep = (DCT_L_POST - L_FRAME - OFFSET2) as usize;
    st.dct_post_old_exc
        .copy_within(L_FRAME as usize..L_FRAME as usize + keep, 0);
    st.dct_post_old_exc[keep..keep + L_FRAME as usize].copy_from_slice(&exc2[..L_FRAME as usize]);
}

/// `filt_lfE[i] = 0.3 + 0.7 * filt_lfE[i]` for the `DCT_L_POST` bins; `offset` is the 0.3 in Q12 as
/// the caller writes it: `1228` in `acelp_core_dec_fx`, `1229` in `amr_wb_dec_fx`.
pub(crate) fn update_filt_lfe(st: &mut DecoderState, offset: i16) {
    for value in st.filt_lf_e.iter_mut().take(DCT_L_POST as usize) {
        *value = round_word(l_mac(l_deposit_h(offset), 22938, *value));
    }
}

/// An active good frame: the LSFs, the FEC side information, the excitation of the coder type,
/// the synthesis and the classification / smoothing for the next frame loss.
fn good_frame_active(
    st: &mut DecoderState,
    w: &mut CoreWork,
    coder_type: i16,
    sharp_flag: i16,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    old_syn_12k8_16k: &mut [i16],
    unbits: &mut i16,
) {
    let l_frame = st.l_frame;

    // After a CNG period, use the most up-to-date LSPs
    if st.last_core_brate == i32::from(FRAME_NO_DATA)
        || l_sub(st.last_core_brate, i32::from(SID_2K40)) == 0
    {
        st.lsp_old = st.lsp_cng;
        lsp2lsf(&st.lsp_cng, &mut st.lsf_old, M, i32::from(w.int_fs));
    }

    // Reset the higher ACELP pre-quantizer in case of switching
    if st.use_acelp_preq == 0 {
        st.mem_preemp_pre_q = 0;
        st.last_nq_pre_q = 0;
    }
    st.use_acelp_preq = 0;

    // LSF de-quantization and interpolation
    let bwidth = st.bwidth;
    lsf_dec(
        st,
        w.tc_subfr,
        l_frame,
        coder_type,
        bwidth,
        &mut w.aq,
        &mut w.lsf_q_prediction,
        &mut w.lsf_new,
        &mut w.lsp_new,
        &mut w.lsp_mid,
    );

    // FEC - first good frame after lost frame(s) (possibility to correct the ACB)
    if l_sub(st.core_brate, i32::from(ACELP_11K60)) >= 0 {
        good_frame_fec_repair(st, w, coder_type);
    }

    // In case of the first frame after an erasure and a transition from voiced to unvoiced or
    // inactive, redo the LPC interpolation
    if st.stab_fac == 0
        && st.old_bfi_cnt > 0
        && sub(st.clas_dec, VOICED_CLAS) != 0
        && sub(st.clas_dec, ONSET) != 0
        && st.relax_prev_lsf_interp == 0
    {
        int_lsp4(
            l_frame,
            &st.lsp_old,
            &w.lsp_mid,
            &w.lsp_new,
            &mut w.aq,
            M,
            2,
        );
    }

    // Decoding of the scaled predicted innovation energy
    if (sub(coder_type, UNVOICED) != 0
        && sub(coder_type, AUDIO) != 0
        && sub(coder_type, INACTIVE) != 0
        && !(l_sub(st.core_brate, i32::from(ACELP_8K00)) <= 0 && sub(coder_type, TRANSITION) != 0))
        || (sub(coder_type, INACTIVE) == 0 && l_sub(st.total_brate, i32::from(ACELP_32K)) >= 0)
    {
        let core_brate = st.core_brate;
        w.es_pred = es_pred_dec(st, coder_type, core_brate);
    }

    good_frame_excitation(
        st,
        w,
        coder_type,
        sharp_flag,
        pitch_buf,
        voice_factors,
        unbits,
    );

    // synthesis for the ACELP core switching and the SWB BWE
    syn_12k8(
        l_frame,
        &w.aq,
        &w.old_exc[EXC_AT..],
        &mut w.temp_buf_fx,
        &mut st.mem_syn1,
        1,
        st.q_exc,
        -1,
    );
    // save and delay the synthesis to be used by the SWB BWE
    save_old_syn(
        l_frame,
        &w.temp_buf_fx,
        old_syn_12k8_16k,
        &mut st.old_syn_12k8_16k,
        st.preemph_fac,
        &mut st.mem_deemph_old_syn,
    );

    // Apply energy matching when switching to inactive frames
    inac_swtch_ematch(
        &mut w.old_exc2[EXC2_AT..],
        &mut w.dct_exc_tmp,
        &mut st.lt_ener_per_band,
        coder_type,
        l_frame,
        st.core_brate,
        st.q_exc,
        st.bfi,
        st.last_core,
        st.last_codec_mode,
    );

    // Decode information and modify the excitation signal of stationary unvoiced frames
    if sub(st.nelp_mode_dec, 1) != 0 {
        stat_noise_uv_dec(
            st,
            coder_type,
            &w.lsp_new,
            &w.lsp_mid,
            &mut w.aq,
            &mut w.old_exc2[EXC2_AT..],
        );
    }

    // Save the filter memory in case the synthesis is redone after scaling; synthesis at the
    // 12.8 kHz sampling rate.
    // update the past excitation signals for the LD music post-filter
    update_dct_post_old_exc(st, &w.old_exc2[EXC2_AT..]);

    good_frame_synthesis(st, w, coder_type, pitch_buf);
}

/// `FEC_pos_dec_fx` and, after a frame loss, the correction of the adaptive codebook
/// (`FEC_SinOnset_fx`, `FEC_enhACB_fx`).
fn good_frame_fec_repair(st: &mut DecoderState, w: &mut CoreWork, coder_type: i16) {
    let l_frame = st.l_frame;
    let mut last_pulse_pos: i16 = 0;
    // (the reference passes &st->clas_dec, which FEC_pos_dec_fx does not read through `st`)
    let mut clas = st.clas_dec;
    let last_good = st.last_good;
    let core_brate = st.core_brate;
    let t0_tmp = fec_pos_dec(
        st,
        coder_type,
        last_good,
        &mut last_pulse_pos,
        &mut clas,
        &mut w.enr_q,
        core_brate,
    );
    st.clas_dec = clas;

    if sub(st.last_core, HQ_CORE) != 0 || (sub(st.last_core, HQ_CORE) == 0 && st.last_con_tcx != 0)
    {
        let history = EXC_AT - L_EXC_MEM as usize;
        if sub(st.clas_dec, SIN_ONSET) == 0 && last_pulse_pos != 0 && sub(st.prev_bfi, 1) == 0 {
            st.q_exc = fec_sin_onset(
                &mut w.old_exc[history..],
                last_pulse_pos,
                t0_tmp,
                w.enr_q,
                &w.aq,
                l_frame,
                st.q_exc,
            );
        } else if (sub(coder_type, GENERIC) == 0 || sub(coder_type, VOICED) == 0)
            && last_pulse_pos != 0
            && sub(st.old_bfi_cnt, 1) == 0
            && sub(w.output_frame, L_FRAME16K) == 0
        {
            w.do_wi = fec_enh_acb(
                l_frame,
                st.last_l_frame,
                &mut w.old_exc[history..],
                t0_tmp,
                last_pulse_pos,
                st.bfi_pitch,
            );
        }
    }
}

/// `Scale_sig(exc_fx - L_EXC_MEM, L_EXC_MEM, -Q_exc); Q_exc = 0` of the NELP and PPP frames.
fn scale_excitation_memory_to_q0(st: &mut DecoderState, w: &mut CoreWork) {
    let from = EXC_AT - L_EXC_MEM as usize;
    scale_sig(
        &mut w.old_exc[from..from + L_EXC_MEM as usize],
        L_EXC_MEM,
        -st.q_exc,
    );
    st.q_exc = 0;
}

/// The excitation of the coder type of a good active frame.
fn good_frame_excitation(
    st: &mut DecoderState,
    w: &mut CoreWork,
    coder_type: i16,
    sharp_flag: i16,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    unbits: &mut i16,
) {
    let l_frame = st.l_frame;

    if sub(st.nelp_mode_dec, 1) == 0 {
        // SC-VBR - NELP frames
        scale_excitation_memory_to_q0(st, w);

        let mut q_exc = st.q_exc;
        decod_nelp(
            st,
            coder_type,
            &mut w.tmp_noise,
            pitch_buf,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            voice_factors,
            &mut w.old_bwe_exc[BWE_EXC_AT..],
            &mut q_exc,
            st.bfi,
            &mut w.gain_buf,
        );
        st.q_exc = q_exc;

        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            &mut w.old_exc,
            EXC_AT,
            None,
            Some(&mut st.last_exc_dct_in),
            L_FRAME,
            0,
            0,
            &mut st.q_exc,
            &mut st.q_subfr,
            Some(&mut w.old_exc2[EXC2_AT..]),
            L_FRAME,
            coder_type,
        );
    } else if sub(coder_type, UNVOICED) == 0 {
        // UNVOICED frames
        decod_unvoiced(
            st,
            &w.aq,
            coder_type,
            &mut w.tmp_noise,
            pitch_buf,
            voice_factors,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            &mut w.old_bwe_exc,
            BWE_EXC_AT,
            &mut w.gain_buf,
        );
    } else if sub(st.ppp_mode_dec, 1) == 0 {
        scale_excitation_memory_to_q0(st, w);
        // SC-VBR - PPP frames
        decod_ppp(
            st,
            &w.aq,
            pitch_buf,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2,
            EXC2_AT,
            st.bfi,
            &mut w.gain_buf,
            voice_factors,
            &mut w.old_bwe_exc[BWE_EXC_AT..],
        );

        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            &mut w.old_exc,
            EXC_AT,
            None,
            Some(&mut st.last_exc_dct_in),
            L_FRAME,
            0,
            0,
            &mut st.q_exc,
            &mut st.q_subfr,
            Some(&mut w.old_exc2[EXC2_AT..]),
            L_FRAME,
            coder_type,
        );
    } else if sub(coder_type, TRANSITION) == 0 {
        decod_tran(
            st,
            l_frame,
            w.tc_subfr,
            &w.aq,
            coder_type,
            w.es_pred,
            pitch_buf,
            voice_factors,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            &mut w.old_bwe_exc,
            BWE_EXC_AT,
            unbits,
            sharp_flag,
            &mut w.gain_buf,
        );
    } else if sub(coder_type, AUDIO) == 0
        || (sub(coder_type, INACTIVE) == 0 && l_sub(st.core_brate, i32::from(ACELP_24K40)) <= 0)
    {
        decod_audio(
            st,
            &mut w.dct_exc_tmp,
            &w.aq,
            coder_type,
            pitch_buf,
            voice_factors,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            &mut w.old_bwe_exc,
            BWE_EXC_AT,
            &w.lsf_new,
            &mut w.gain_buf,
        );
        w.tmp_noise = shr_r(st.lp_gainc, 3); // Q0
    } else {
        decod_gen_voic(
            st,
            l_frame,
            sharp_flag,
            &w.aq,
            coder_type,
            w.es_pred,
            w.do_wi,
            pitch_buf,
            voice_factors,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            &mut w.old_bwe_exc,
            BWE_EXC_AT,
            unbits,
            &mut w.gain_buf,
        );
    }
}

/// `CNA` headroom flag: `k = 1` when the frame is INACTIVE, comfort noise addition is on and the
/// smoothed noise level is close to the post-filter threshold.
pub(super) fn cna_headroom(st: &DecoderState, coder_type: i16) -> i16 {
    i16::from(
        sub(coder_type, INACTIVE) == 0
            && st.flag_cna != 0
            && sub(round_word(l_shl(st.lp_noise, 1)), 15 << 7) >= 0,
    )
}

/// The LP synthesis of the good frame: the LD music post-filter path for GSC frames, the plain
/// 12.8 / 16 kHz synthesis otherwise; then the class and pitch estimation for the next frame loss
/// and the energy smoothing after one.
fn good_frame_synthesis(
    st: &mut DecoderState,
    w: &mut CoreWork,
    coder_type: i16,
    pitch_buf: &mut [i16],
) {
    let l_frame = st.l_frame;
    let mut exc_buffer = [0i16; DCT_L_POST as usize];
    let mut dct_buffer = [0i16; DCT_L_POST as usize];
    exc_buffer[..(DCT_L_POST - OFFSET2) as usize]
        .copy_from_slice(&st.dct_post_old_exc[..(DCT_L_POST - OFFSET2) as usize]);

    if sub(coder_type, AUDIO) == 0 && st.gsc_noisy_speech == 0 {
        // Extrapolation of the last future part, windowing and high resolution DCT transform
        let mut qdct: i16 = 0;
        prep_music_post_p(
            &mut exc_buffer,
            &mut dct_buffer,
            &mut st.filt_lf_e,
            st.last_coder_type,
            pitch_buf,
            &mut st.l_dm_enh_lp_gbin,
            st.q_exc,
            &mut qdct,
        );

        // LD music post-filter
        let min_ns_gain = st.l_dm_enh_min_ns_gain;
        let (core_brate, last_coder_type) = (st.core_brate, st.last_coder_type);
        let mut memories = LdMusicState {
            last_music_flag: &mut st.l_dm_last_music_flag,
            thresh: &mut st.l_dm_thres,
            nb_thr_1: &mut st.l_dm_nb_thr_1,
            nb_thr_3: &mut st.l_dm_nb_thr_3,
            lt_diff_etot: &mut st.l_dm_lt_diff_etot,
            mem_etot: &mut st.l_dm_mem_etot,
            bckr: &mut st.l_dm_bckr_noise,
            lf_eo: &mut st.l_dm_enh_lf_eo,
            lp_gbin: &mut st.l_dm_enh_lp_gbin,
            filt_lfe: &mut st.filt_lf_e,
            last_nonfull_music: &mut st.last_nonfull_music,
            old_ener_q: &mut st.old_ener_q,
        };
        ld_music_post_filter(
            &mut dct_buffer,
            core_brate,
            &mut memories,
            min_ns_gain,
            AUDIO,
            last_coder_type,
            qdct,
        );

        // Inverse DCT transform, retrieval of the aligned excitation, re-synthesis
        let mut memories = PostMusicMemories {
            mem_tmp: None,
            st_mem_syn2: &mut st.mem_syn2,
            mem_syn_clas_estim: &mut st.mem_syn_clas_estim,
            mem_deemph: &mut st.mem_deemph,
            pst_old_syn: &mut st.pst_old_syn,
            pst_mem_deemp_err: &mut st.pst_mem_deemp_err,
            mem_agc: &mut st.agc_mem[1],
            pf_stat: &mut st.pfstat,
            mem_tmp2: Some(&mut w.mem_tmp),
        };
        post_music_post_p(
            &dct_buffer,
            &mut w.old_exc2[EXC2_AT..],
            &mut memories,
            &w.aq,
            &mut w.syn_fx_tmp[SYN_AT..],
            &mut st.q_exc,
            &mut st.prev_q_syn,
            &mut st.q_syn,
            0,
            Some(&w.temp_buf_fx),
        );
    } else {
        // Core synthesis at 12.8 kHz or 16 kHz
        let vad_flag = i16::from(sub(coder_type, INACTIVE) != 0);
        // add extra headroom in case a CNA addition is likely (i.e. psf_lp_noise is close to the
        // threshold)
        let k = cna_headroom(st, coder_type);

        rescale_mem(
            st.q_exc,
            &mut st.prev_q_syn,
            &mut st.q_syn,
            &mut st.mem_syn2,
            &mut st.mem_syn_clas_estim,
            4,
            &mut st.mem_deemph,
            &mut st.pst_old_syn,
            &mut st.pst_mem_deemp_err,
            &mut st.agc_mem[1],
            &mut st.pfstat,
            vad_flag,
            k,
            Some(&w.temp_buf_fx),
        );

        w.mem_tmp = st.mem_syn2;

        syn_12k8(
            l_frame,
            &w.aq,
            &w.old_exc2[EXC2_AT..],
            &mut w.syn_fx_tmp[SYN_AT..],
            &mut st.mem_syn2,
            1,
            st.q_exc,
            st.q_syn,
        );

        update_filt_lfe(st, 1228);
    }

    // FEC - estimate the classification information
    let mut class_para: i16 = 0;
    let (opt_amr_wb, core_brate, last_core_brate, q_syn) =
        (st.opt_amr_wb, st.core_brate, st.last_core_brate, st.q_syn);
    fec_clas_estim(
        st,
        opt_amr_wb,
        l_frame,
        coder_type,
        pitch_buf,
        &w.syn_fx_tmp,
        SYN_AT,
        None,
        None,
        core_brate,
        q_syn,
        Some(&mut class_para),
        0,
        0,
        0,
        last_core_brate,
    );

    // FEC - estimate the pitch
    fec_pitch_estim(
        st.opt_amr_wb,
        st.last_core,
        l_frame,
        st.clas_dec,
        st.last_good,
        pitch_buf,
        &st.old_pitch_buf,
        &mut st.bfi_pitch,
        &mut st.bfi_pitch_frame,
        &mut st.upd_cnt,
        coder_type,
    );

    // FEC - smooth the speech energy evolution when recovering after a BAD frame (smoothing is
    // performed in the excitation domain and the signal is resynthesized after)
    let mut pitch_buf_tmp = [0i16; NB_SUBFR16K as usize];
    pitch_buf_for_scaling(pitch_buf, l_frame, &mut pitch_buf_tmp);

    fec_scale(st, w, coder_type, &pitch_buf_tmp);

    if l_sub(st.total_brate, i32::from(ACELP_7K20)) == 0
        || l_sub(st.total_brate, i32::from(ACELP_8K00)) == 0
    {
        let pitch = pitch_buf_tmp[(sub(shr(l_frame, 6), 1)) as usize];
        frame_ener(
            l_frame,
            st.clas_dec,
            &w.syn_fx_tmp[SYN_AT..],
            pitch,
            &mut st.enr_old,
            l_frame,
            st.q_syn,
            3,
            0,
        );
    }
}

/// `pitch_buf_tmp[k] = mult_r(pitch_buf[k], 512)` for each 64-sample subframe: the pitch in Q0.
pub(crate) fn pitch_buf_for_scaling(pitch_buf: &[i16], l_frame: i16, pitch_buf_tmp: &mut [i16]) {
    let mut k = 0;
    let mut i = 0;
    while i < l_frame {
        pitch_buf_tmp[k] = mult_r(pitch_buf[k], 512);
        k += 1;
        i += L_SUBFR;
    }
}

/// `FEC_scale_syn_fx` on the frame's synthesis and excitation with the decoder's memories.
fn fec_scale(st: &mut DecoderState, w: &mut CoreWork, coder_type: i16, pitch_tmp: &[i16]) {
    let params = FecScaleSynParams {
        l_frame: st.l_frame,
        clas: st.clas_dec,
        last_good: st.last_good,
        l_enr_old: st.enr_old,
        l_enr_q: w.enr_q,
        coder_type,
        lsf_q_prediction: w.lsf_q_prediction,
        bfi: st.bfi,
        total_brate: st.total_brate,
        prev_bfi: st.prev_bfi,
        last_core_brate: st.last_core_brate,
        q_exc: st.q_exc,
        q_syn: st.q_syn,
        avoid_lpc_burst_on_recovery: w.avoid_lpc_burst_on_recovery,
        force_scaling: 0,
    };
    let mut update_flg: i16 = 0;
    let mut state = FecScaleSynState {
        update_flg: &mut update_flg,
        scaling_flag: &mut st.scaling_flag,
        lp_ener_fec_av: &mut st.lp_ener_fec_av,
        lp_ener_fec_max: &mut st.lp_ener_fec_max,
        old_enr_lp: &mut st.old_enr_lp,
    };
    fec_scale_syn(
        &params,
        &mut state,
        &mut w.syn_fx_tmp[SYN_AT..],
        pitch_tmp,
        &mut w.old_exc[EXC_AT..],
        &mut w.old_exc2[EXC2_AT..],
        &w.aq,
        &w.mem_tmp,
        &mut st.mem_syn2,
        &mut st.stl,
    );
}

/// `acelp_core_dec_fx`'s `BAD frame` branch: the concealed LSFs, excitation and synthesis.
pub(super) fn bad_frame(
    st: &mut DecoderState,
    w: &mut CoreWork,
    coder_type: i16,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    old_syn_12k8_16k: &mut [i16],
) {
    let l_frame = st.l_frame;
    let mut fec_pitch: i16;

    // SC-VBR
    if sub(st.last_nelp_mode_dec, 1) == 0 {
        st.nelp_mode_dec = 1;
    }

    // long burst frame erasures
    if sub(st.nb_lost_cmpt, 5) > 0
        && sub(st.clas_dec, VOICED_CLAS) >= 0
        && sub(st.clas_dec, INACTIVE_CLAS) < 0
    {
        st.last_good = VOICED_TRANSITION;
    }

    // LSF estimation and A(z) calculation
    lsf_dec_bfi(
        MODE1,
        &mut w.lsf_new,
        &st.lsf_old,
        &st.lsf_adaptive_mean,
        None,
        &mut st.mem_ma,
        &mut st.mem_ar,
        st.stab_fac,
        st.last_coder_type,
        l_frame,
        st.last_good,
        st.nb_lost_cmpt,
        0,
        None,
        None,
        None,
        st.last_gsc_pit_band_idx,
        st.opt_amr_wb,
        0,
        st.bwidth,
    );

    fec_lsf2lsp_interp(st, l_frame, &mut w.aq, &w.lsf_new, &mut w.lsp_new);

    if sub(st.nelp_mode_dec, 1) == 0 {
        // SC-VBR
        scale_excitation_memory_to_q0(st, w);

        let mut q_exc = st.q_exc;
        decod_nelp(
            st,
            coder_type,
            &mut w.tmp_noise,
            pitch_buf,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            voice_factors,
            &mut w.old_bwe_exc[BWE_EXC_AT..],
            &mut q_exc,
            st.bfi,
            &mut w.gain_buf,
        );
        st.q_exc = q_exc;

        fec_pitch = pitch_buf[3];

        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            &mut w.old_exc,
            EXC_AT,
            None,
            Some(&mut st.last_exc_dct_in),
            L_FRAME,
            0,
            0,
            &mut st.q_exc,
            &mut st.q_subfr,
            Some(&mut w.old_exc2[EXC2_AT..]),
            L_FRAME,
            coder_type,
        );
    } else {
        // calculation of the excitation signal
        fec_pitch = 0;
        fec_exc_estim(
            st,
            l_frame,
            &mut w.old_exc,
            EXC_AT,
            &mut w.old_exc2[EXC2_AT..],
            &mut w.dct_exc_tmp,
            pitch_buf,
            voice_factors,
            &mut fec_pitch,
            &mut w.old_bwe_exc[BWE_EXC_AT..],
            &w.lsf_new,
            st.q_exc,
            &mut w.tmp_noise,
        );

        rescale_exc(
            None,
            &mut w.old_exc,
            EXC_AT,
            Some((&mut w.old_bwe_exc, BWE_EXC_AT)),
            Some(&mut st.last_exc_dct_in),
            l_frame,
            L_FRAME32K,
            0,
            &mut st.q_exc,
            &mut st.q_subfr,
            Some(&mut w.old_exc2[EXC2_AT..]),
            l_frame,
            st.last_coder_type,
        );

        w.tmp_noise = shr_r(st.lp_gainc, 3); // Q0

        // SC-VBR
        st.prev_gain_pit_dec = st.lp_gainp; // Q14
    }

    // synthesis for the ACELP core switching and the SWB BWE
    syn_12k8(
        l_frame,
        &w.aq,
        &w.old_exc[EXC_AT..],
        &mut w.temp_buf_fx,
        &mut st.mem_syn1,
        1,
        st.q_exc,
        -1,
    ); // old_syn_12k8_16k directly in Q-1

    // save and delay the synthesis to be used by the SWB BWE
    save_old_syn(
        l_frame,
        &w.temp_buf_fx,
        old_syn_12k8_16k,
        &mut st.old_syn_12k8_16k,
        st.preemph_fac,
        &mut st.mem_deemph_old_syn,
    );

    // Apply energy matching when switching to inactive frames
    inac_swtch_ematch(
        &mut w.old_exc2[EXC2_AT..],
        &mut w.dct_exc_tmp,
        &mut st.lt_ener_per_band,
        coder_type,
        l_frame,
        st.core_brate,
        st.q_exc,
        st.bfi,
        st.last_core,
        st.last_codec_mode,
    );

    // update the past excitation signals for the LD music post-filter
    update_dct_post_old_exc(st, &w.old_exc2[EXC2_AT..]);

    // synthesis at the 12.8 kHz sampling rate; add extra headroom in case a CNA addition is
    // likely
    let k = cna_headroom(st, coder_type);

    rescale_mem(
        st.q_exc,
        &mut st.prev_q_syn,
        &mut st.q_syn,
        &mut st.mem_syn2,
        &mut st.mem_syn_clas_estim,
        4,
        &mut st.mem_deemph,
        &mut st.pst_old_syn,
        &mut st.pst_mem_deemp_err,
        &mut st.agc_mem[1],
        &mut st.pfstat,
        1,
        k,
        Some(&w.temp_buf_fx),
    );

    let rate_7k2_8k = l_sub(st.total_brate, i32::from(ACELP_7K20)) == 0
        || l_sub(st.total_brate, i32::from(ACELP_8K00)) == 0;
    if rate_7k2_8k {
        w.mem_tmp = st.mem_syn2;
    }
    syn_12k8(
        l_frame,
        &w.aq,
        &w.old_exc2[EXC2_AT..],
        &mut w.syn_fx_tmp[SYN_AT..],
        &mut st.mem_syn2,
        1,
        st.q_exc,
        st.q_syn,
    );

    // update the buffer for the classifier
    let frame = l_frame as usize;
    let exc2_from = EXC2_AT + frame - L_EXC_MEM as usize;
    st.old_exc2
        .copy_from_slice(&w.old_exc2[exc2_from..exc2_from + L_EXC_MEM as usize]);
    let syn_from = SYN_AT + frame - L_EXC_MEM as usize;
    st.old_syn2
        .copy_from_slice(&w.syn_fx_tmp[syn_from..syn_from + L_EXC_MEM as usize]);
    st.prev_q_exc_fr = st.q_exc;
    st.prev_q_syn_fr = st.q_syn;

    let clas_from = SYN_AT + frame - L_SYN_MEM_CLAS_ESTIM as usize;
    st.mem_syn_clas_estim
        .copy_from_slice(&w.syn_fx_tmp[clas_from..clas_from + L_SYN_MEM_CLAS_ESTIM as usize]);

    // Update the music post-processing values: filter energies update
    update_filt_lfe(st, 1228);
    // Update the circular buffer, keep the last energy difference unchanged
    for i in 1..MAX_LT as usize {
        st.l_dm_lt_diff_etot[i - 1] = st.l_dm_lt_diff_etot[i];
    }

    if rate_7k2_8k {
        let mut pitch_buf_tmp = [0i16; NB_SUBFR16K as usize];
        pitch_buf_for_scaling(pitch_buf, l_frame, &mut pitch_buf_tmp);

        // FEC - smooth the speech energy evolution when recovering after a BAD frame (smoothing
        // is performed in the excitation domain and the signal is resynthesized after)
        fec_scale(st, w, coder_type, &pitch_buf_tmp);
    }

    // estimate the pitch-synchronous speech energy per sample to be used when normal operation
    // recovers
    frame_ener(
        l_frame,
        st.last_good,
        &w.syn_fx_tmp[SYN_AT..],
        shr(add(fec_pitch, 32), 6),
        &mut st.enr_old,
        l_frame,
        st.q_syn,
        3,
        0,
    );

    if sub(st.nelp_mode_dec, 1) != 0 {
        // modify the excitation signal of stationary unvoiced frames
        stat_noise_uv_mod(
            coder_type,
            0,
            &st.lsp_old,
            &w.lsp_new,
            &w.lsp_new,
            &mut w.aq,
            &mut w.old_exc2[EXC2_AT..],
            st.q_exc,
            1,
            &mut st.ge_sm,
            &mut st.uv_count,
            &mut st.act_count,
            &mut st.lspold_s,
            &mut st.noimix_seed,
            &mut st.min_alpha,
            &mut st.exc_pe,
            st.core_brate,
            st.bwidth,
            &mut st.q_stat_noise,
            &mut st.q_stat_noise_ge,
        );
    }

    // SC-VBR
    st.fade_scale = mult(st.fade_scale, 24576); // 24576 in Q15
}
