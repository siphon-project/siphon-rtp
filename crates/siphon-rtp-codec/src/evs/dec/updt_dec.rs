//! End-of-frame decoder state updates (TS 26.442 `lib_dec/updt_dec_fx.c`; TS 26.445 §6.9).
//!
//! `updt_IO_switch_dec_fx` (EVS primary ↔ AMR-WB IO switching) and `update_decoder_LPD_cng`
//! (MODE2 CNG) live in the same reference file and are not ported here: the MODE1 7.2 / 8.0 kbit/s
//! decoder does not reach them.

use crate::evs::cnst::{
    ACELP_24K40, ACELP_CORE, ACELP_LOOK_NS, ACTIVE_FRAME, AUDIO, DELAY_BWE_TOTAL_NS, FD_CNG,
    FRAME_NO_DATA, FRAME_SIZE_NS, GENERIC, HARMONIC, HQ_16K40, HQ_CORE, HQ_HARMONIC, HQ_HVQ,
    INACTIVE, L_EXC_MEM_DEC, L_FRAME, L_FRAME16K, L_FRAME32K, L_SUBFR, M, MAX_UPD_CNT, MBANDS_GN,
    MODE1, MODE2, NB_SUBFR, NB_SUBFR16K, NOISE_LEVEL_SP3, N_WS2N_FRAMES, PIT16K_MAX, RF_TCXFD,
    RF_TCXTD2, SID_1K75, SID_2K40, SWB, TRANSITION, UNVOICED, UNVOICED_TRANSITION, WB,
};
use crate::evs::com::swb_bwe_com::calc_tilt_bwe;
use crate::evs::com::tools::{copy_scale_sig, random};
use crate::evs::dec::state::DecoderState;
use crate::evs::macros::ns2sa_fx2;
use crate::evs::rom::{GEWB2_AVE_FX, GEWB_AVE_FX, INNER_FRAME_TBL};
use crate::itu::basic_ops::{add, l_shl, l_sub, round_word, shr, shr_r, sub};
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
