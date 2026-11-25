//! A good frame (comfort noise or an active frame) and a bad frame of `amr_wb_dec_fx`.

use super::{AmrWork, EXC_AT, SYN_AT};
use crate::evs::cnst::{
    AUDIO, DCT_L_POST, FRAME_NO_DATA, GENERIC, INACTIVE, L_FRAME, L_SYN_MEM_CLAS_ESTIM, M, MAX_LT,
    MODE1, MOVING_AVERAGE, NB_SUBFR, OFFSET2, SID_1K75, UNVOICED, UNVOICED_CLAS, VOICED_CLAS,
    VOICED_TRANSITION,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::cng_exc::cng_exc;
use crate::evs::com::frame_ener::{frame_ener, frame_energy};
use crate::evs::com::isf_dec_amr_wb::isf_dec_amr_wb;
use crate::evs::com::lsf_dec_bfi::lsf_dec_bfi;
use crate::evs::com::lsf_tools::e_lpc_isp_isf_conversion;
use crate::evs::com::scale_mem::{rescale_exc, rescale_mem};
use crate::evs::com::syn_12k8::syn_12k8;
use crate::evs::com::tools::{copy_scale_sig, scale_sig};
use crate::evs::dec::acelp_core_dec::{
    pitch_buf_for_scaling, update_dct_post_old_exc, update_filt_lfe,
};
use crate::evs::dec::cng_dec::cng_dec;
use crate::evs::dec::dec_amr_wb::decod_amr_wb;
use crate::evs::dec::fec::fec_exc_estim;
use crate::evs::dec::fec_clas_estim::fec_clas_estim;
use crate::evs::dec::fec_lsf_estim::fec_lsf2lsp_interp;
use crate::evs::dec::fec_pitch_estim::fec_pitch_estim;
use crate::evs::dec::fec_scale_syn::{fec_scale_syn, FecScaleSynParams, FecScaleSynState};
use crate::evs::dec::gs_dec_amr_wb::improv_amr_wb_gs;
use crate::evs::dec::ld_music_post_filter::{
    ld_music_post_filter, post_music_post_p, prep_music_post_p, LdMusicState, PostMusicMemories,
};
use crate::evs::dec::rst_dec::cng_reset_dec;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, l_mac, l_mult, l_sub, round_word, shr, sub};

/// `amr_wb_dec_fx`'s `GOOD frame` branch.
pub(super) fn good_frame(st: &mut DecoderState, w: &mut AmrWork) {
    // Processing of FRAME_NO_DATA frames; decoding of SID frames
    if l_sub(st.core_brate, i32::from(FRAME_NO_DATA)) == 0
        || l_sub(st.core_brate, i32::from(SID_1K75)) == 0
    {
        good_frame_cng(st, w);
    } else {
        // Decoding of all other frames
        good_frame_active(st, w);
    }
}

/// The comfort-noise parameters and excitation of an inactive frame (`FRAME_NO_DATA` or SID),
/// the excitation rescaling and the synthesis of the noise.
fn good_frame_cng(st: &mut DecoderState, w: &mut AmrWork) {
    let mut allow_cn_step: i16 = 0;

    // decode the CNG parameters
    let core_brate = st.core_brate;
    cng_dec(
        st,
        L_FRAME,
        &mut w.aq,
        core_brate,
        &mut w.lsp_new,
        &mut w.lsf_new,
        &mut allow_cn_step,
        &mut w.sid_bw,
        &mut w.q_env,
    );

    // comfort noise generation
    cng_exc(
        st.core_brate,
        L_FRAME,
        &mut st.enew,
        &mut st.cng_seed,
        &mut w.old_exc,
        EXC_AT,
        &mut w.exc2,
        &mut st.lp_ener,
        st.last_core_brate,
        st.first_cng,
        &mut st.cng_ener_seed,
        &mut w.dummy_buf,
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
        w.sid_bw,
        &mut st.cng_ener_seed1,
        &mut [],
        st.opt_amr_wb,
    );

    w.voice_factors = [32767; NB_SUBFR as usize];
    w.class_para = 0;

    if st.first_cng == 0 {
        st.first_cng = 1;
    }

    let mut delta_mem_scale: i16 = 3;
    if l_sub(st.lp_ener, 40) < 0 {
        // very low energy frames, less than 0.3125
        delta_mem_scale = 0;
    }

    let i = st.q_exc;
    rescale_exc(
        Some(&mut st.dct_post_old_exc),
        &mut w.old_exc,
        EXC_AT,
        None,
        Some(&mut st.last_exc_dct_in),
        L_FRAME,
        L_FRAME * 5 / 2, // L_FRAME * HIBND_ACB_L_FAC
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
    scale_sig(&mut w.exc2, L_FRAME, sub(st.q_exc, i));

    // update the past excitation signals for the LD music post-filter
    update_dct_post_old_exc(st, &w.exc2);

    // synthesis at the 12.8 kHz sampling rate
    syn_12k8(
        L_FRAME,
        &w.aq,
        &w.exc2,
        &mut w.syn_tmp[SYN_AT..],
        &mut st.mem_syn2,
        1,
        st.q_exc,
        st.q_syn,
    );
    syn_12k8(
        L_FRAME,
        &w.aq,
        &w.exc2,
        &mut w.dummy_buf,
        &mut st.mem_syn3,
        1,
        st.q_exc,
        st.q_syn,
    );

    // reset the decoder
    cng_reset_dec(st, &mut w.pitch_buf, &mut w.dummy_buf[L_FRAME as usize..]);

    // update mem_syn1 for the ACELP core switching
    copy_scale_sig(&st.mem_syn3, &mut st.mem_syn1, M, sub(-1, st.q_syn)); // Q-1
    if sub(w.output_frame, crate::evs::cnst::L_FRAME8K) != 0 {
        let mut pitch_temp = [0i16; 4];
        pitch_temp[2] = crate::itu::basic_ops::shl(L_FRAME, 6);
        pitch_temp[3] = crate::itu::basic_ops::shl(L_FRAME, 6);
        let mut frame_e: i16 = 0;
        frame_energy(
            L_FRAME,
            &pitch_temp,
            &w.syn_tmp[SYN_AT..],
            0,
            &mut frame_e,
            st.q_syn,
            &mut st.stl,
        );
        // st->psf_lp_noise = 0.99f * st->psf_lp_noise + 0.01f * frame_e
        st.psf_lp_noise = round_word(l_mac(l_mult(32440, st.psf_lp_noise), 328, frame_e));
        // Q8
    }
    // update the old synthesis for classification
    let from = SYN_AT + L_FRAME as usize - L_SYN_MEM_CLAS_ESTIM as usize;
    st.mem_syn_clas_estim
        .copy_from_slice(&w.syn_tmp[from..from + L_SYN_MEM_CLAS_ESTIM as usize]);

    // Update the music post-processing values: filter energies update
    update_filt_lfe(st, 1229);

    w.vad_flag = 0;
}

/// An active good frame: the ISFs, the excitation, the synthesis and the classification /
/// smoothing for the next frame loss.
fn good_frame_active(st: &mut DecoderState, w: &mut AmrWork) {
    // After a CNG period, use the most up-to-date ISPs
    if l_sub(st.last_core_brate, i32::from(FRAME_NO_DATA)) == 0
        || l_sub(st.last_core_brate, i32::from(SID_1K75)) == 0
    {
        st.lsp_old = st.lsp_cng;
        let lsp_cng = st.lsp_cng;
        e_lpc_isp_isf_conversion(&lsp_cng, &mut st.lsf_old, M);
        w.old_exc[..crate::evs::cnst::L_EXC_MEM_DEC as usize].fill(0);
    }

    // Extract the VAD information from the bitstream in the AMR-WB IO mode
    w.vad_flag = get_next_indice(st, 1) as i16;

    w.coder_type = GENERIC;
    if w.vad_flag == 0 {
        w.coder_type = INACTIVE;
    }

    // ISF de-quantization and interpolation
    isf_dec_amr_wb(st, &mut w.aq, &mut w.lsf_new, &mut w.lsp_new);

    // Decode the excitation
    decod_amr_wb(
        st,
        &w.aq,
        &mut w.pitch_buf,
        &mut w.old_exc,
        EXC_AT,
        &mut w.exc2,
        &mut w.hf_gain,
        &mut w.voice_factors,
        &mut w.gain_buf,
    );

    // synthesis for the ACELP core switching and the SWB BWE
    syn_12k8(
        L_FRAME,
        &w.aq,
        &w.old_exc[EXC_AT..],
        &mut w.tmp_buffer,
        &mut st.mem_syn1,
        1,
        st.q_exc,
        -1,
    );

    update_long_term_energies(st, w);

    // Save the filter memory in case the synthesis is redone after scaling; core synthesis at
    // 12.8 kHz. Add extra headroom in case a CNA addition is likely (i.e. psf_lp_noise is close
    // to the threshold)
    let mut tmp16: i16 = 0;
    if sub(w.coder_type, INACTIVE) == 0 && st.flag_cna != 0 && sub(st.psf_lp_noise, 15 << 7) >= 0 {
        tmp16 = 1;
    }
    rescale_mem(
        st.q_exc,
        &mut st.prev_q_syn,
        &mut st.q_syn,
        &mut st.mem_syn2,
        &mut st.mem_syn_clas_estim,
        5,
        &mut st.mem_deemph,
        &mut st.pst_old_syn,
        &mut st.pst_mem_deemp_err,
        &mut st.agc_mem[1],
        &mut st.pfstat,
        w.vad_flag,
        tmp16,
        Some(&w.tmp_buffer),
    );
    w.mem_tmp = st.mem_syn2;
    syn_12k8(
        L_FRAME,
        &w.aq,
        &w.exc2,
        &mut w.syn_tmp[SYN_AT..],
        &mut st.mem_syn2,
        1,
        st.q_exc,
        st.q_syn,
    );

    // FEC - estimate the classification information
    let (core_brate, q_syn, last_core_brate) = (st.core_brate, st.q_syn, st.last_core_brate);
    fec_clas_estim(
        st,
        1,
        L_FRAME,
        w.coder_type,
        &w.pitch_buf,
        &w.syn_tmp,
        SYN_AT,
        Some(&mut w.locattack),
        Some(&mut w.amr_io_class),
        core_brate,
        q_syn,
        Some(&mut w.class_para),
        0,
        0,
        0,
        last_core_brate,
    );

    // update the past excitation signals for the LD music post-filter
    update_dct_post_old_exc(st, &w.exc2);
    w.exc_buffer[..(DCT_L_POST - OFFSET2) as usize]
        .copy_from_slice(&st.dct_post_old_exc[..(DCT_L_POST - OFFSET2) as usize]);

    if sub(w.output_frame, crate::evs::cnst::L_FRAME8K) != 0 && sub(w.coder_type, INACTIVE) == 0 {
        let mut frame_e: i16 = 0;
        frame_energy(
            L_FRAME,
            &w.pitch_buf,
            &w.syn_tmp[SYN_AT..],
            0,
            &mut frame_e,
            st.q_syn,
            &mut st.stl,
        );
        // st->psf_lp_noise = 0.99f * st->psf_lp_noise + 0.01f * frame_e
        st.psf_lp_noise = round_word(l_mac(l_mult(32440, st.psf_lp_noise), 328, frame_e));
        // Q8
    }

    if sub(w.amr_io_class, UNVOICED_CLAS) != 0
        && sub(w.coder_type, INACTIVE) != 0
        && sub(st.psf_lp_noise, 15 << 8) < 0
    {
        music_post_filter(st, w);
    } else {
        // Improvement for unvoiced and audio signals
        improv_amr_wb_gs(
            w.amr_io_class,
            w.coder_type,
            st.core_brate,
            &mut st.seed_tcx,
            &mut st.old_aq,
            &mut st.mem_syn2,
            st.lt_voice_fac,
            w.locattack,
            &mut w.aq,
            &mut w.exc2,
            st.q_exc,
            &w.mem_tmp,
            &mut w.syn_tmp[SYN_AT..],
            st.q_syn,
            &w.pitch_buf,
            st.Last_ener,
            st.rate_switching_reset,
            st.last_coder_type,
        );

        update_filt_lfe(st, 1229);
    }

    // FEC - estimate the pitch
    fec_pitch_estim(
        1,
        st.last_core,
        L_FRAME,
        st.clas_dec,
        st.last_good,
        &w.pitch_buf,
        &st.old_pitch_buf,
        &mut st.bfi_pitch,
        &mut st.bfi_pitch_frame,
        &mut st.upd_cnt,
        GENERIC,
    );

    // FEC - smooth the speech energy evolution when recovering after a BAD frame (smoothing is
    // performed in the excitation domain and the signal is resynthesized after)
    let mut pitch_buf_tmp = [0i16; NB_SUBFR as usize];
    pitch_buf_for_scaling(&w.pitch_buf, L_FRAME, &mut pitch_buf_tmp);

    fec_scale(st, w, &pitch_buf_tmp, w.avoid_lpc_burst_on_recovery);

    frame_ener(
        L_FRAME,
        st.clas_dec,
        &w.syn_tmp[SYN_AT..],
        pitch_buf_tmp[3],
        &mut st.enr_old,
        L_FRAME,
        st.q_syn,
        3,
        0,
    );
}

/// The update of the long-term energies for the FEC and of the ISP vector for the CNG.
fn update_long_term_energies(st: &mut DecoderState, w: &mut AmrWork) {
    if sub(w.coder_type, INACTIVE) == 0 {
        if sub(st.unv_cnt, 20) > 0 {
            // ftmp = st->lp_gainc * st->lp_gainc
            let l_tmp1 = crate::itu::stl2009::l_mult0(st.lp_gainc, st.lp_gainc); // Q3*Q3 -> Q6
                                                                                 // st->lp_ener = 0.7f * st->lp_ener + 0.3f * ftmp
            let l_tmp = crate::evs::basop::mult_32_16(st.lp_ener, 22938);
            st.lp_ener =
                crate::itu::basic_ops::l_add(l_tmp, crate::evs::basop::mult_32_16(l_tmp1, 9830)); // Q6 + Q6
            for i in 0..M as usize {
                let l_tmp = l_mult(3277, w.lsp_new[i]);
                st.lsp_cng[i] = round_word(l_mac(l_tmp, 29491, st.lsp_cng[i]));
            }
        } else {
            st.unv_cnt = add(st.unv_cnt, 1);
        }
    } else {
        st.unv_cnt = 0;
    }
}

/// The LD music post-filter of the active frames of audio content: the extrapolated excitation
/// to the DCT domain, the filter, and the re-synthesis from the modified excitation.
fn music_post_filter(st: &mut DecoderState, w: &mut AmrWork) {
    let mut tmp_coder_type = AUDIO;
    if sub(st.last_coder_type, INACTIVE) == 0 || sub(st.last_coder_type, UNVOICED) == 0 {
        tmp_coder_type = INACTIVE;
    }
    // Extrapolation of the last future part, windowing and high resolution DCT transform
    let mut qdct: i16 = 0;
    prep_music_post_p(
        &mut w.exc_buffer,
        &mut w.dct_buffer,
        &mut st.filt_lf_e,
        st.last_core,
        &w.pitch_buf,
        &mut st.l_dm_enh_lp_gbin,
        st.q_exc,
        &mut qdct,
    );

    // LD music post-filter
    let min_ns_gain = st.l_dm_enh_min_ns_gain;
    let core_brate = st.core_brate;
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
        &mut w.dct_buffer,
        core_brate,
        &mut memories,
        min_ns_gain,
        -1,
        tmp_coder_type,
        qdct,
    );

    // Inverse DCT transform, retrieval of the aligned excitation, re-synthesis
    let mut memories = PostMusicMemories {
        mem_tmp: Some(&w.mem_tmp),
        st_mem_syn2: &mut st.mem_syn2,
        mem_syn_clas_estim: &mut st.mem_syn_clas_estim,
        mem_deemph: &mut st.mem_deemph,
        pst_old_syn: &mut st.pst_old_syn,
        pst_mem_deemp_err: &mut st.pst_mem_deemp_err,
        mem_agc: &mut st.agc_mem[1],
        pf_stat: &mut st.pfstat,
        mem_tmp2: None,
    };
    post_music_post_p(
        &w.dct_buffer,
        &mut w.exc2,
        &mut memories,
        &w.aq,
        &mut w.syn_tmp[SYN_AT..],
        &mut st.q_exc,
        &mut st.prev_q_syn,
        &mut st.q_syn,
        1,
        None,
    );
}

/// `FEC_scale_syn_fx` on the frame's synthesis and excitation with the decoder's memories.
fn fec_scale(
    st: &mut DecoderState,
    w: &mut AmrWork,
    pitch_tmp: &[i16],
    avoid_lpc_burst_on_recovery: i16,
) {
    let params = FecScaleSynParams {
        l_frame: L_FRAME,
        clas: st.clas_dec,
        last_good: st.last_good,
        l_enr_old: st.enr_old,
        l_enr_q: 0, // L_enr_q_fx = L_deposit_l(0): never set in AMR-WB IO mode
        coder_type: -1,
        lsf_q_prediction: MOVING_AVERAGE,
        bfi: st.bfi,
        total_brate: st.total_brate,
        prev_bfi: st.prev_bfi,
        last_core_brate: st.last_core_brate,
        q_exc: st.q_exc,
        q_syn: st.q_syn,
        avoid_lpc_burst_on_recovery,
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
        &mut w.syn_tmp[SYN_AT..],
        pitch_tmp,
        &mut w.old_exc[EXC_AT..],
        &mut w.exc2,
        &w.aq,
        &w.mem_tmp,
        &mut st.mem_syn2,
        &mut st.stl,
    );
}

/// `amr_wb_dec_fx`'s `BAD frame` branch: the concealed ISFs, excitation and synthesis.
pub(super) fn bad_frame(st: &mut DecoderState, w: &mut AmrWork) {
    let mut fec_pitch: i16 = 0;

    // long burst frame erasures
    if sub(st.nb_lost_cmpt, 5) > 0 && sub(st.clas_dec, VOICED_CLAS) >= 0 {
        st.last_good = VOICED_TRANSITION;
    }
    w.vad_flag = st.last_vad;
    w.amr_io_class = st.last_good;
    w.class_para = 0;

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
        st.l_frame,
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

    fec_lsf2lsp_interp(st, st.l_frame, &mut w.aq, &w.lsf_new, &mut w.lsp_new);
    // calculation of the excitation signal
    fec_exc_estim(
        st,
        L_FRAME,
        &mut w.old_exc,
        EXC_AT,
        &mut w.exc2,
        &mut w.tmp_buffer,
        &mut w.pitch_buf,
        &mut w.voice_factors,
        &mut fec_pitch,
        &mut w.dummy_buf,
        &w.lsf_new,
        st.q_exc,
        &mut w.tmp_noise,
    );

    // synthesis for the ACELP core switching and the SWB BWE
    syn_12k8(
        L_FRAME,
        &w.aq,
        &w.old_exc[EXC_AT..],
        &mut w.tmp_buffer,
        &mut st.mem_syn1,
        1,
        st.q_exc,
        -1,
    );

    // update the past excitation signals
    update_dct_post_old_exc(st, &w.exc2);

    // Update the music post-processing values: update the circular buffer, keep the last energy
    // difference unchanged
    for i in 1..MAX_LT as usize {
        st.l_dm_lt_diff_etot[i - 1] = st.l_dm_lt_diff_etot[i];
    }
    // filter energies update
    update_filt_lfe(st, 1229);

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
        0,
        Some(&w.tmp_buffer),
    );

    w.mem_tmp = st.mem_syn2;
    // synthesis at the 12.8 kHz sampling rate
    syn_12k8(
        L_FRAME,
        &w.aq,
        &w.exc2,
        &mut w.syn_tmp[SYN_AT..],
        &mut st.mem_syn2,
        1,
        st.q_exc,
        st.q_syn,
    );

    // update the old synthesis for classification
    let from = SYN_AT + L_FRAME as usize - L_SYN_MEM_CLAS_ESTIM as usize;
    st.mem_syn_clas_estim
        .copy_from_slice(&w.syn_tmp[from..from + L_SYN_MEM_CLAS_ESTIM as usize]);

    let mut pitch_buf_tmp = [0i16; NB_SUBFR as usize];
    pitch_buf_for_scaling(&w.pitch_buf, L_FRAME, &mut pitch_buf_tmp);

    // FEC - smooth the speech energy evolution when recovering after a BAD frame (smoothing is
    // performed in the excitation domain and the signal is resynthesized after)
    fec_scale(st, w, &pitch_buf_tmp, 0);

    // estimate the pitch-synchronous speech energy per sample to be used when normal operation
    // recovers
    frame_ener(
        L_FRAME,
        st.last_good,
        &w.syn_tmp[SYN_AT..],
        shr(fec_pitch, 6),
        &mut st.enr_old,
        L_FRAME,
        st.q_syn,
        3,
        0,
    );
}
