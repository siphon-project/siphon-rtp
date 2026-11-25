//! End-of-frame decoder state updates (TS 26.442 `lib_dec/updt_dec_fx.c`; TS 26.445 §6.9).
//!
//! `updt_IO_switch_dec_fx` (EVS primary ↔ AMR-WB IO switching) lives in the same reference file
//! and is not ported here (AMR-WB IO is out of scope).

use crate::evs::cnst::{
    ACELP_24K40, ACELP_CORE, ACELP_LOOK_NS, ACTIVE_FRAME, ALDO_WINDOW, AUDIO, DELAY_BWE_TOTAL_NS,
    FD_CNG, FRAME_NO_DATA, FRAME_SIZE_NS, GENERIC, HARMONIC, HQ_16K40, HQ_CORE, HQ_HARMONIC,
    HQ_HVQ, INACTIVE, INT_FS_16K_FX, L_EXC_MEM_DEC, L_FRAME, L_FRAME16K, L_FRAME32K, L_FRAME_MAX,
    L_SUBFR, L_SYN_MEM, M, MAX_UPD_CNT, MBANDS_GN, MODE1, MODE2, NB_SUBFR, NB_SUBFR16K,
    NOISE_LEVEL_SP3, N_WS2N_FRAMES, OLD_SYNTH_SIZE_DEC, PIT16K_MAX, RF_TCXFD, RF_TCXTD2, SID_1K75,
    SID_2K40, SWB, TILT_CODE, TRANSITION, UNVOICED, UNVOICED_TRANSITION, WB,
};
use crate::evs::com::basop_util::buffer_copy_fx;
use crate::evs::com::lsf_tools::{e_lpc_a_lsp_conversion, e_lpc_lsp_lsf_conversion, lsp2lsf};
use crate::evs::com::preemph::e_util_f_preemph3;
use crate::evs::com::residu::residu3;
use crate::evs::com::swb_bwe_com::calc_tilt_bwe;
use crate::evs::com::tools::{copy_scale_sig, random, scale_sig, set16};
use crate::evs::dec::fec_clas_estim::fec_clas_estim;
use crate::evs::dec::post_dec::post_decoder;
use crate::evs::dec::state::DecoderState;
use crate::evs::macros::ns2sa_fx2;
use crate::evs::rom::{GEWB2_AVE_FX, GEWB_AVE_FX, INNER_FRAME_TBL};
use crate::itu::basic_ops::{
    add, l_deposit_l, l_shl, l_sub, mult_r, round_word, shl, shr, shr_r, sub,
};
use crate::itu::stl2009::l_mult0;

/// `updt_dec_fx`: the common updates after an ACELP frame (all frame types): excitation and
/// BWE-excitation memories, LSF / LSP, last coder type, GSC and FEC memories, pitch history.
///
/// `old_exc_fx` holds `L_frame + L_EXC_MEM_DEC` samples, `old_bwe_exc_fx` (read unless AMR-WB IO)
/// `L_FRAME32k + 2·PIT16k_MAX`, `pitch_buf_fx` `L_frame / 64` pitch values, `aq` the subframe
/// LP filters, `voice_factors` and `gain_buf` five values each.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn updt_dec(
    st: &mut DecoderState,
    l_frame: i16,
    coder_type: i16,
    old_exc_fx: &[i16],
    pitch_buf_fx: &[i16],
    es_pred: i16,
    aq: &[i16],
    lsf_new_fx: &[i16],
    lsp_new_fx: &[i16],
    voice_factors: &[i16],
    old_bwe_exc_fx: &[i16],
    gain_buf: &[i16],
) {
    let l_frame_us = l_frame.max(0) as usize;
    let m = M as usize;

    // update old excitation buffer
    let exc_len = L_EXC_MEM_DEC as usize;
    st.old_exc[..exc_len].copy_from_slice(&old_exc_fx[l_frame_us..l_frame_us + exc_len]);
    if st.opt_amr_wb == 0 {
        let bwe_len = (PIT16K_MAX * 2) as usize;
        let at = L_FRAME32K as usize;
        st.old_bwe_exc[..bwe_len].copy_from_slice(&old_bwe_exc_fx[at..at + bwe_len]);
    }

    // update old LSP and LSF vector
    st.lsf_old[..m].copy_from_slice(&lsf_new_fx[..m]);
    st.lsp_old[..m].copy_from_slice(&lsp_new_fx[..m]);

    // update last coding type
    st.last_coder_type = coder_type;
    if sub(coder_type, INACTIVE) == 0
        || (sub(st.bpf_off, 1) == 0
            && sub(coder_type, AUDIO) != 0
            && sub(coder_type, TRANSITION) != 0)
    {
        st.last_coder_type = UNVOICED;
    }
    if (sub(coder_type, AUDIO) != 0 || st.last_gsc_noisy_speech_flag != 0)
        && st.last_gsc_pit_band_idx > 0
    {
        // The temporal contribution of the GSC is meaningless after 1 frame lost for inactive &
        // unvoiced content
        st.last_gsc_pit_band_idx = 0;
    }
    // this ensures that last_coder_type is never set to INACTIVE in case of AVQ inactive because
    // the FEC does not distinguish between GSC inactive and AVQ inactive
    if l_sub(st.total_brate, i32::from(ACELP_24K40)) > 0 && sub(coder_type, INACTIVE) == 0 {
        st.last_coder_type = GENERIC;
    }
    if sub(st.opt_amr_wb, 1) == 0
        && sub(coder_type, INACTIVE) == 0
        && l_sub(st.core_brate, i32::from(SID_1K75)) != 0
        && l_sub(st.core_brate, i32::from(FRAME_NO_DATA)) != 0
    {
        // overwrite previous coding type to help FEC
        st.last_coder_type = UNVOICED;
        st.last_voice_factor = voice_factors[NB_SUBFR as usize - 1];
    }

    if st.opt_amr_wb == 0 {
        // update voicing factor of TBE to help FEC
        st.last_voice_factor = voice_factors[NB_SUBFR16K as usize - 1];
        if sub(st.l_frame, L_FRAME) == 0 {
            st.last_voice_factor = voice_factors[NB_SUBFR as usize - 1];
        }
    }

    if coder_type != AUDIO && coder_type != INACTIVE {
        st.noise_lev = NOISE_LEVEL_SP3;
        st.old_y_gain[..MBANDS_GN as usize].fill(0);
        for i in 0..L_FRAME as usize {
            // the seed is a copy, re-taken every sample: all entries get the same value
            let mut tmp_seed = st.seed_tcx;
            st.last_gsc_spectrum[i] = shr_r(random(&mut tmp_seed), 5); // Q10
        }
    }

    // update last GSC SWB speech flag for FEC
    st.last_gsc_noisy_speech_flag = st.gsc_noisy_speech;

    // update counter for FEC pitch estimate
    st.upd_cnt = add(st.upd_cnt, 1);
    st.upd_cnt = st.upd_cnt.min(MAX_UPD_CNT);

    let len = shr(l_frame, 6).max(0) as usize;
    st.old_pitch_buf.copy_within(len..2 * len, 0);
    for i in 0..len {
        st.old_pitch_buf[len + i] = l_mult0(pitch_buf_fx[i], 1 << 10);
    }
    let nb_subfr = (l_frame / L_SUBFR).max(0) as usize;
    // an overlapping copy upwards: the C's Copy runs backwards for it, as copy_within does
    st.mem_pitch_gain.copy_within(2..2 + nb_subfr, nb_subfr + 2);
    if sub(l_frame, L_FRAME) == 0 {
        st.mem_pitch_gain[2] = gain_buf[3];
        st.mem_pitch_gain[3] = gain_buf[2];
        st.mem_pitch_gain[4] = gain_buf[1];
        st.mem_pitch_gain[5] = gain_buf[0];
    } else {
        st.mem_pitch_gain[2] = gain_buf[4];
        st.mem_pitch_gain[3] = gain_buf[3];
        st.mem_pitch_gain[4] = gain_buf[2];
        st.mem_pitch_gain[5] = gain_buf[1];
        st.mem_pitch_gain[6] = gain_buf[0];
    }

    // FEC - update adaptive LSF mean vector
    st.lsfoldbfi1 = st.lsfoldbfi0;
    st.lsfoldbfi0[..m].copy_from_slice(&lsf_new_fx[..m]);

    // update of pitch and voicing information for HQ FEC
    if sub(st.last_core, HQ_CORE) != 0 {
        st.hq_voicing = 1;
        if st.opt_amr_wb == 0 && sub(coder_type, UNVOICED) == 0 {
            st.hq_voicing = 0;
        }
    }

    // SC-VBR
    st.old_ppp_mode = st.last_ppp_mode_dec;
    st.last_ppp_mode_dec = st.ppp_mode_dec;
    st.last_nelp_mode_dec = st.nelp_mode_dec;
    st.last_vbr_hw_bwe_disable_dec = st.vbr_hw_bwe_disable_dec;

    // core switching updates
    let at = ((st.l_frame / L_SUBFR - 1).max(0) as usize) * (m + 1);
    st.old_aq_12_8[..=m].copy_from_slice(&aq[at..=at + m]);
    st.old_es_pred = es_pred;
}

/// `updt_bw_switching_fx`: the bandwidth-switching memories after a frame, `synth` the output
/// synthesis at `qpost` (its tilt is taken only for 32 kHz SWB output).
pub fn updt_bw_switching(st: &mut DecoderState, synth: &[i16], qpost: i16) {
    if st.output_fs == 32000 && st.bwidth == SWB {
        st.tilt_swb = round_word(l_shl(calc_tilt_bwe(synth, qpost, L_FRAME32K), 3));
    }

    st.prev_ener_lh = st.ener_lh;
    st.prev_ener_ll = st.ener_ll;
    st.last_bwidth = st.bwidth;

    if sub(st.core, ACELP_CORE) == 0 {
        st.last_inner_frame = L_FRAME32K;
        if sub(st.bwidth, WB) == 0 && st.bws_cnt == 0 {
            st.last_inner_frame = L_FRAME16K;
        }

        st.prev_weight1 = 16384;
        if sub(st.prev_mode, HARMONIC) == 0 {
            st.prev_weight1 = 6554;
        }
    } else {
        let inner_frame =
            INNER_FRAME_TBL[(st.bwidth.max(0) as usize).min(INNER_FRAME_TBL.len() - 1)];
        if !(sub(st.last_inner_frame, L_FRAME16K) >= 0
            && sub(inner_frame, L_FRAME16K) <= 0
            && st.bws_cnt > 0
            && sub(st.bws_cnt, N_WS2N_FRAMES) < 0)
        {
            st.last_inner_frame = inner_frame;
        }

        if sub(inner_frame, L_FRAME32K) >= 0 || l_sub(st.core_brate, i32::from(HQ_16K40)) <= 0 {
            st.prev_weight1 = 16384;
            if sub(st.prev_hqswb_clas, HQ_HARMONIC) == 0 || sub(st.prev_hqswb_clas, HQ_HVQ) == 0 {
                st.prev_weight1 = 6554;
            }
        }
    }
}

/// `updt_dec_common_fx`: the updates common to MODE1 and MODE2 after every frame: last-frame
/// parameters, bad-frame history, the synthesis kept for core switching, and the LSF quantiser
/// memories reset after an FD-CNG SID / no-data frame (or a TCX-only MODE2 frame).
pub fn updt_dec_common(st: &mut DecoderState, hq_core_type_fx: i16, synth: &[i16]) {
    st.last_codec_mode = st.codec_mode;
    st.last_extl = st.extl;
    st.last_l_frame = st.l_frame;

    st.prev_old_bfi = st.prev_bfi;
    st.prev_bfi = st.bfi;
    st.old_bfi_cnt = st.nb_lost_cmpt;
    st.last_con_tcx = st.con_tcx;
    st.con_tcx = 0;

    st.prev_last_core = st.last_core;

    st.tcx_conceal_recalc_exc = 0;
    if (sub(st.rf_frame_type, RF_TCXFD) >= 0
        && sub(st.rf_frame_type, RF_TCXTD2) <= 0
        && st.use_partial_copy != 0
        && st.bfi != 0)
        || st.bfi == 0
    {
        if st.bfi != 0
            && sub(st.last_good, UNVOICED_TRANSITION) <= 0
            && sub(st.clas_dec, UNVOICED_TRANSITION) > 0
            && st.last_con_tcx != 0
        {
            st.tcx_conceal_recalc_exc = 1;
        }
        st.last_good = st.clas_dec;
    }
    if st.use_partial_copy != 0 {
        st.prev_rf_frame_type = st.rf_frame_type;
    } else {
        st.prev_rf_frame_type = INACTIVE;
    }

    if sub(st.m_frame_type, ACTIVE_FRAME) == 0 && (st.bfi != 1 || st.use_partial_copy != 0) {
        st.rf_flag_last = st.rf_flag;
    }

    if sub(st.codec_mode, MODE1) == 0 {
        if st.bfi == 0 && st.core_brate > i32::from(SID_2K40) {
            st.last_active_brate = st.total_brate;
        }

        st.last_core = st.core;
        st.last_hq_core_type = hq_core_type_fx;
    } else if sub(st.codec_mode, MODE2) == 0 {
        if st.bfi == 0 && st.last_is_cng == 0 {
            st.last_active_brate = st.total_brate;
        }
        // INFO: moved from update_decoder_LPD_cng()
        if sub(st.m_frame_type, ACTIVE_FRAME) != 0 {
            st.last_is_cng = 1;
        }

        if st.bfi == 0 {
            st.last_core = st.core;
        }
        st.last_core_bfi = st.core; // also required for clean channel decoding
    }
    st.last_core_brate = st.core_brate;

    // save synthesis for core switching
    let at = ns2sa_fx2(st.output_fs, ACELP_LOOK_NS + DELAY_BWE_TOTAL_NS).max(0) as usize;
    let len = ns2sa_fx2(
        st.output_fs,
        FRAME_SIZE_NS - ACELP_LOOK_NS - DELAY_BWE_TOTAL_NS,
    );
    copy_scale_sig(&synth[at..], &mut st.old_synth_sw, len, st.q_old_postdec);

    if (l_sub(st.core_brate, i32::from(SID_2K40)) <= 0 && sub(st.cng_type, FD_CNG) == 0)
        || (st.tcxonly != 0 && sub(st.codec_mode, MODE2) == 0)
    {
        // reset LP memories
        st.mem_ma.fill(0);
        if l_sub(st.sr_core, 16000) == 0 {
            st.mem_ar.copy_from_slice(&GEWB2_AVE_FX);
        } else {
            st.mem_ar.copy_from_slice(&GEWB_AVE_FX);
        }
    }
}

/// `update_decoder_LPD_cng`: the MODE2 decoder's end-of-frame update after a CNG (SID / no-data)
/// frame synthesised in the time domain: LP analysis of the synthesis `time_domain_buffer` with
/// `a` (`M + 1` coefficients), the synthesis, excitation and LPC memories, the ACELP / TCX state
/// reset to "ACELP after CNG", the concealment memories, the class estimate and finally the
/// post-filter (`post_decoder`), whose output replaces `time_domain_buffer`.
///
/// `time_domain_buffer` holds the `L_frame` synthesised samples; `bpf_noise_buf` receives the bass
/// post-filter's signal (`L_frame` samples).
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::too_many_lines)]
pub fn update_decoder_lpd_cng(
    st: &mut DecoderState,
    coder_type: i16,
    time_domain_buffer: &mut [i16],
    a: &[i16],
    bpf_noise_buf: &mut [i16],
) {
    let m = M as usize;
    let l_frame = st.l_frame;
    let frame = l_frame.max(0) as usize;
    let old_synth_len = st.old_synth_len.max(0) as usize;
    let mut lsp = [0i16; M as usize];
    let mut lsf = [0i16; M as usize];
    let mut synth_buf = [0i16; M as usize + 1 + L_FRAME_MAX as usize + L_FRAME_MAX as usize / 2];
    let mut buf_synth = [0i16; OLD_SYNTH_SIZE_DEC as usize + L_FRAME_MAX as usize + M as usize];
    let mut pf_pitch = [0i16; NB_SUBFR16K as usize];
    let mut pf_gain = [0i16; NB_SUBFR16K as usize];
    let mut pitch = [0i16; NB_SUBFR16K as usize];
    // `synth` is `synth_buf[SYNTH_AT..]`
    let synth_at = m + 1;

    // LPC -> LSP
    let lsp_old = st.lsp_old;
    e_lpc_a_lsp_conversion(a, &mut lsp, &lsp_old, M);

    // LSP -> LSF
    if sub(l_frame, L_FRAME16K) == 0 {
        lsp2lsf(&lsp, &mut lsf, M, i32::from(INT_FS_16K_FX));
    } else {
        e_lpc_lsp_lsf_conversion(&lsp, &mut lsf, M);
    }

    buf_synth[..old_synth_len].copy_from_slice(&st.old_synth[..old_synth_len]);
    buf_synth[old_synth_len..old_synth_len + frame].copy_from_slice(&time_domain_buffer[..frame]);

    // Update synth memory
    synth_buf[..m + 1].copy_from_slice(&st.syn);
    synth_buf[synth_at..synth_at + frame].copy_from_slice(&time_domain_buffer[..frame]);
    st.syn
        .copy_from_slice(&synth_buf[synth_at + frame - (m + 1)..synth_at + frame]);
    st.old_synth.copy_within(frame..old_synth_len, 0);
    st.old_synth[old_synth_len - frame..old_synth_len]
        .copy_from_slice(&synth_buf[synth_at..synth_at + frame]);
    buffer_copy_fx(
        &synth_buf[synth_at + frame - frame / 2..],
        &mut st.old_syn_overl,
        l_frame / 2,
        0,
        -1,
        0,
        0,
    );

    st.tcxltp_last_gain_unmodified = 0;

    // Update pe-synth memory
    let mut tmp = synth_buf[synth_at - (1 + m)];

    st.q_syn = e_util_f_preemph3(
        &mut synth_buf[synth_at - m..],
        st.preemph_fac,
        add(M, l_frame),
        &mut tmp,
        1,
    );
    // plain C `st->Q_syn - 1`
    st.q_syn = st.q_syn.wrapping_sub(1);
    st.prev_q_syn = st.q_syn;
    st.mem_syn2
        .copy_from_slice(&synth_buf[synth_at + frame - m..synth_at + frame]);
    let mem_len = L_SYN_MEM as usize;
    st.mem_syn_r
        .copy_from_slice(&synth_buf[synth_at + frame - mem_len..synth_at + frame]);

    // Update excitation memory
    if sub(add(st.q_syn, 1), st.q_exc) != 0 {
        scale_sig(
            &mut st.old_exc,
            L_EXC_MEM_DEC,
            sub(add(st.q_syn, 1), st.q_exc),
        );
    }
    st.q_exc = st.q_syn.wrapping_add(1);
    let exc_len = L_EXC_MEM_DEC as usize;
    st.old_exc.copy_within(frame..exc_len, 0);
    residu3(
        a,
        &synth_buf,
        synth_at,
        &mut st.old_exc[exc_len - frame..],
        l_frame,
        1,
    );

    // Update LPC-related memories
    st.lsp_old = lsp;
    st.lsf_old = lsf;
    st.lspold_uw = lsp;
    st.lsfold_uw = lsf;
    st.env_weighted = 0;
    st.old_aq_12_8.copy_from_slice(&a[..m + 1]);
    st.old_es_pred = 0;

    // Reset acelp memories
    st.dm.prev_gain_code = l_deposit_l(0);
    set16(&mut st.dm.prev_gain_pit, 0, 6);
    st.dm.prev_state = 0;

    st.tilt_code = TILT_CODE;
    st.gc_threshold = 0;

    // Update ace/tcx mode
    st.core = ACELP_CORE;
    st.last_is_cng = 1;

    // Reset TCX overlap
    st.tcx_cfg.tcx_curr_overlap_mode = ALDO_WINDOW;
    st.tcx_cfg.tcx_last_overlap_mode = ALDO_WINDOW;

    // For BBWE and Postfilter
    for subframe in 0..4 {
        st.mem_aq[subframe * (m + 1)..(subframe + 1) * (m + 1)].copy_from_slice(&a[..m + 1]);
    }
    if sub(l_frame, L_FRAME16K) == 0 {
        st.mem_aq[4 * (m + 1)..5 * (m + 1)].copy_from_slice(&a[..m + 1]);
    }

    // Update for concealment
    st.nb_lost_cmpt = 0;
    st.prev_old_bfi = 0;

    for i in 0..m {
        // 1.0f/3.0f Q15
        st.lsf_adaptive_mean[i] = add(
            mult_r(st.lsfoldbfi1[i], 10923),
            add(mult_r(st.lsfoldbfi0[i], 10923), mult_r(lsf[i], 10923)),
        );
        st.lsfoldbfi1[i] = st.lsfoldbfi0[i];
        st.lsfoldbfi0[i] = lsf[i];
    }

    set16(&mut pitch, shl(L_SUBFR, 6), NB_SUBFR16K);

    let (q_syn, last_core_brate) = (st.q_syn, st.last_core_brate);
    fec_clas_estim(
        st,
        0,
        l_frame,
        coder_type,
        &pitch,
        &synth_buf,
        synth_at,
        None,
        None,
        // bitrate: not used by the ACELP classifier
        0,
        q_syn,
        None,
        // -1.f Q15
        -32768,
        // CLASSIFIER_ACELP
        0,
        // bfi
        0,
        last_core_brate,
    );

    // Postfiltering
    pf_pitch.fill(L_SUBFR);
    pf_gain.fill(0);
    st.bpf_gain_param = 0;

    post_decoder(
        st,
        coder_type,
        &mut buf_synth,
        &pf_gain,
        &pf_pitch,
        time_domain_buffer,
        bpf_noise_buf,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updt_dec_common_keeps_the_last_core_in_mode1() {
        let mut st = Box::new(DecoderState::zeroed());
        st.codec_mode = MODE1;
        st.core = HQ_CORE;
        st.core_brate = 8000;
        st.total_brate = 8000;
        st.output_fs = 16000;
        let synth = [0i16; 960];
        updt_dec_common(&mut st, 1, &synth);
        assert_eq!(st.last_core, HQ_CORE);
        assert_eq!(st.last_hq_core_type, 1);
        assert_eq!(st.last_active_brate, 8000);
    }
}
