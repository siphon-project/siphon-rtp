//! `bandwidth_switching_detect_fx`, `bw_switching_pre_proc_fx`, `core_switching_pre_dec_fx` and
//! `core_switching_post_dec_fx` (TS 26.442 `lib_dec/core_switching_dec_fx.c`).
//!
//! The bandwidth-switching counters drive the attenuation of the high band across a WB <-> SWB
//! switch (TS 26.445 §6.1.4.2); the pre- and post-processing reset or carry over the memories of
//! the core that was not running in the previous frame, cross-fade the HQ and ACELP syntheses
//! across an ACELP <-> HQ switch, and bring MODE2 (TCX / LPD) memories into MODE1 form.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_13K20, ACELP_8K00, ACELP_8K85, ACELP_9K60, ACELP_CORE, ACTIVE_FRAME,
    ALLPASSSECTIONS_STEEP, AMR_WB_CORE, AUDIO, BANDS_MAX, CNA_MAX_BRATE, DEC, DECMEM_RES2,
    DELAY_BWE_TOTAL_NS, DELAY_CLDFB_NS, DELAY_FD_BWE_ENC_NS, DELAY_SWB_TBE_12K8_NS,
    DELAY_SWB_TBE_16K_NS, FB_BWE, FB_TBE, FD_CNG, FRAME_NO_DATA, GENERIC, HQ_32K, HQ_CORE,
    HQ_DELAY_COMP, HQ_DELTA_MAX, INACTIVE, INTERP_3_2_MEM_LEN, INT_FS_16K, INT_FS_FX,
    LPC_SHB_ORDER, LP_CNG, L_EXC_MEM_DEC, L_FRAME, L_FRAME16K, L_FRAME48K, L_HQ_WB_BWE,
    L_SHB_LAHEAD, L_SUBFR, L_SYN_MEM_CLAS_ESTIM, M, MAX_32, MAX_DELAY_TBE_NS, MAX_UPD_CNT, MODE1,
    MODE2, N16_CORE_SW, NBPSF_PIT_MAX, NORMAL, NUM_SHB_SUBFR, N_NS2W_FRAMES, N_WS2N_FRAMES,
    N_ZERO_8, PIT16K_MAX, PPP_NELP_2K80, SFM_N_WB, SID_2K40, SID_FRAME, SPT_SHORTEN_SBNUM, SWB,
    SWB_BWE, SWB_CNG, SWB_FENV, SWB_TBE, SWITCH_MAX_GAP, TCX_10_CORE, TCX_20_CORE, UNVOICED_CLAS,
    WB, WB_BWE, WB_TBE, ZERO_FRAME,
};
use crate::evs::com::basop_util::idiv1616;
use crate::evs::com::cldfb::{
    cldfb_analysis_filtering, cldfb_reset_memory, cldfb_restore_memory, cldfb_save_memory,
    cldfb_synthesis_filtering, CLDFB_ROW,
};
use crate::evs::com::edct::edct_16fx;
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::lerp::{lerp, lerp_in_place, lerp_within};
use crate::evs::com::lsf_tools::lsf2lsp;
use crate::evs::com::math_op::{i_mult2, isqrt_lc};
use crate::evs::com::swb_bwe_com::calc_tilt_bwe;
use crate::evs::com::swb_tbe_com::{
    fb_tbe_reset_synth, swb_tbe_reset, swb_tbe_reset_synth, wb_tbe_extras_reset,
    wb_tbe_extras_reset_synth,
};
use crate::evs::com::syn_filt::synth_mem_updt2;
use crate::evs::com::tcx_utils::get_inv_frame_len;
use crate::evs::com::tools::{copy, copy_scale_sig, find_max_norm16, scale_sig, set16, set32};
use crate::evs::com::window_ola::core_switching_ola;
use crate::evs::dec::acelp_core_switch_dec::{acelp_core_switch_dec, acelp_core_switch_dec_bfi};
use crate::evs::dec::fd_cng_dec::configure_fd_cng_dec;
use crate::evs::dec::hf_synth::hf_synth_reset;
use crate::evs::dec::init_dec::reset_preecho_dec;
use crate::evs::dec::state::{CldfbScaleFactor, DecoderState};
use crate::evs::macros::{ns2sa, ns2sa_fx2};
use crate::evs::rom::{GEWB2_AVE_FX, GEWB_AVE_FX, INNER_FRAME_TBL, TRWB2_AVE_FX, TRWB_AVE_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_deposit_h, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r,
    negate, norm_l, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// `CLDFB_NO_COL_MAX`: the time slots of the reference's CLDFB scratch.
const CLDFB_COLS: usize = crate::evs::cnst::CLDFB_NO_COL_MAX as usize;
/// `NS2SA(16000, DELAY_CLDFB_NS) + 2`: the overlap-add memory of the ACELP switching subframes.
const MEM_SYNTH_LEN: usize = 22;

/// `bandwidth_switching_detect_fx`: update the bandwidth-switching counters, `bws_cnt1` counting
/// the frames since a WB -> SWB switch (with the rate rising above 9.6 kbit/s) and `bws_cnt` the
/// frames since a SWB -> WB one (with the rate falling below it); each restarts the other from
/// its complement when the bandwidth turns back.
pub fn bandwidth_switching_detect(st: &mut DecoderState) {
    // update band-width switching counter
    if sub(st.bws_cnt1, N_NS2W_FRAMES) >= 0 {
        st.bws_cnt1 = 0;
    } else if l_sub(st.total_brate, i32::from(ACELP_9K60)) > 0
        && l_sub(st.last_core_brate, i32::from(ACELP_9K60)) < 0
        && sub(st.bwidth, SWB) == 0
        && sub(st.last_bwidth, WB) == 0
    {
        st.bws_cnt1 = add(st.bws_cnt1, 1);
    } else if st.bws_cnt1 > 0 {
        if sub(st.bwidth, st.last_bwidth) < 0 {
            st.bws_cnt = sub(shl(sub(N_NS2W_FRAMES, st.bws_cnt1), 1), 1);
        } else {
            st.bws_cnt = 0;
        }

        if sub(st.bwidth, st.last_bwidth) < 0 {
            st.bws_cnt1 = 0;
        } else if sub(st.bwidth, SWB) == 0 {
            st.bws_cnt1 = add(st.bws_cnt1, 1);
        } else {
            st.bws_cnt1 = 0;
        }
    }

    // update band-width switching counter
    if sub(st.bws_cnt, N_WS2N_FRAMES) >= 0 {
        st.bws_cnt = 0;
    } else if l_sub(st.total_brate, i32::from(ACELP_9K60)) < 0
        && l_sub(st.last_core_brate, i32::from(ACELP_9K60)) > 0
        && sub(st.bwidth, st.last_bwidth) < 0
        && sub(st.bwidth, WB) == 0
    {
        st.bws_cnt = add(st.bws_cnt, 1);
    } else if st.bws_cnt > 0 {
        if sub(st.bwidth, st.last_bwidth) > 0 {
            st.bws_cnt1 = shr(sub(N_WS2N_FRAMES, st.bws_cnt), 1);
        } else {
            st.bws_cnt1 = 0;
        }

        if sub(st.bwidth, st.last_bwidth) > 0 {
            st.bws_cnt = 0;
        } else if sub(st.bwidth, WB) == 0 {
            st.bws_cnt = add(st.bws_cnt, 1);
        } else {
            st.bws_cnt = 0;
        }
    }
}

/// `Calc_freq_ener` (file-local): the square root of the band energy `l_tmp` (Q`2*q_syn2`, the
/// caller passes `q_syn2` already doubled), in Q`q_syn2/2 - 1`.
fn calc_freq_ener(l_tmp: i32, q_syn2: i16) -> i32 {
    if l_tmp == 0 {
        return 0;
    }
    let mut exp = norm_l(l_tmp);
    let mut tmp = extract_h(l_shl(l_tmp, exp));
    exp = sub(exp, sub(30, shl(q_syn2, 1)));

    tmp = div_s(16384, tmp);
    let mut l_tmp = l_deposit_h(tmp);
    l_tmp = isqrt_lc(l_tmp, &mut exp); // 31-exp

    l_shr(l_tmp, sub(sub(31, exp), q_syn2)) // st->Q_syn2-1
}

/// The energy of `x[from..to]`, `L_mac0` accumulated, then `L_shr(.., shift)`.
fn band_energy(x: &[i16], from: usize, to: usize, shift: i16) -> i32 {
    let mut l_tmp: i32 = 0;
    for &v in &x[from..to] {
        l_tmp = l_mac0(l_tmp, v, v);
    }
    l_shr(l_tmp, shift)
}

/// `bw_switching_pre_proc_fx`: before the BWE of a frame, the tilt of the ACELP core synthesis
/// `old_syn_12k8_16k` (`L_FRAME16k` samples at 12.8 or 16 kHz) and the energies of its two lower
/// bands (or, after HQ, of the decoded MDCT spectrum `t_audio_q`), and the resets of the SWB
/// envelope memories a bandwidth or extension-layer switch calls for.
pub fn bw_switching_pre_proc(old_syn_12k8_16k: &[i16], st: &mut DecoderState) {
    let q_syn2x2 = shl(st.q_syn2, 1);
    if sub(st.core, ACELP_CORE) == 0 {
        // Calculate tilt of the ACELP core synthesis
        st.tilt_wb = round_word(l_shl(calc_tilt_bwe(old_syn_12k8_16k, -1, st.l_frame), 3));

        // Calculate frequency energy of 0~3.2kHz and 3.2~6.4kHz the ACELP core synthesis
        let mut syn_dct = [0i16; L_FRAME as usize];
        edct_16fx(old_syn_12k8_16k, &mut syn_dct, L_FRAME, 6);

        let half = L_FRAME as usize / 2;
        let l_tmp = band_energy(&syn_dct, 0, half, 7); // 2*(st->Q_syn2-1)
        st.ener_ll = calc_freq_ener(l_tmp, q_syn2x2);
        let l_tmp = band_energy(&syn_dct, half, L_FRAME as usize, 7); // 2*(st->Q_syn2-1)
        st.ener_lh = calc_freq_ener(l_tmp, q_syn2x2);
    } else if st.old_is_transient[0] != 0 {
        let l_tmp = band_energy(&st.t_audio_q, 0, 32, 5); // st->Q_syn2-1
        st.ener_ll = calc_freq_ener(l_tmp, q_syn2x2);
        let l_tmp = band_energy(&st.t_audio_q, 32, 64, 5); // st->Q_syn2-1
        st.ener_lh = calc_freq_ener(l_tmp, q_syn2x2);
    } else {
        let half = L_FRAME as usize / 2;
        let l_tmp = band_energy(&st.t_audio_q, 0, half, 7); // st->Q_syn2-1
        st.ener_ll = calc_freq_ener(l_tmp, q_syn2x2);
        let l_tmp = band_energy(&st.t_audio_q, half, L_FRAME as usize, 7); // st->Q_syn2-1
        st.ener_lh = calc_freq_ener(l_tmp, q_syn2x2);
    }

    if st.last_bwidth == 0 && sub(st.extl, SWB_CNG) <= 0 {
        st.prev_ener_shb = 0;
        set16(&mut st.prev_swb_fenv, 0, SWB_FENV);
    } else if ((sub(st.core, ACELP_CORE) == 0 && sub(st.last_core, HQ_CORE) == 0)
        || (sub(st.core, st.last_core) == 0 && sub(st.extl, st.last_extl) != 0))
        && sub(st.last_bwidth, SWB) >= 0
    {
        st.attenu = 3277;
    }

    if sub(st.last_core, HQ_CORE) == 0
        || (sub(st.last_core, ACELP_CORE) == 0
            && !(sub(st.last_extl, WB_TBE) == 0
                || sub(st.last_extl, SWB_TBE) == 0
                || sub(st.last_extl, FB_TBE) == 0)
            && l_sub(st.core_brate, i32::from(ACELP_8K00)) > 0)
    {
        st.prev_fractive = 0;
    }
}

/// `core_switching_pre_dec_fx`: preparation of the memories for ACELP / HQ core switching and
/// MODE2 -> MODE1 codec switching before the core decoder runs: the MODE2 memories brought to
/// MODE1 form, the classifier memory resampled across an internal-rate change, the ACELP
/// memories reset after HQ and the HQ ones after ACELP, the frame type and comfort-noise
/// addition flags, and the FD-CNG reconfigured on a frame-length or bandwidth change.
/// `output_frame` is the frame length at the output rate.
pub fn core_switching_pre_dec(st: &mut DecoderState, output_frame: i16) {
    // Codec switching
    if sub(st.last_codec_mode, MODE2) == 0 {
        core_switching_pre_dec_mode2(st);
    }

    // FEC
    core_switching_pre_dec_fec(st);

    // Here we only handle cases where last_ppp and last_nelp not updated when coming from CodecB
    // or other cores within ACELP_CORE if switching from another bitarate to vbr, last_ppp and
    // last_nelp is always updated in the previous frame
    if sub(st.core, ACELP_CORE) == 0
        && (sub(st.last_core, ACELP_CORE) != 0 || sub(st.last_codec_mode, MODE2) == 0)
    {
        st.last_ppp_mode_dec = 0;
        st.last_nelp_mode_dec = 0;
    }

    if sub(st.core, ACELP_CORE) == 0
        && (sub(st.last_core, ACELP_CORE) != 0
            || sub(st.last_codec_mode, MODE2) == 0
            || l_sub(st.last_total_brate, i32::from(PPP_NELP_2K80)) <= 0)
    {
        st.act_count = 3;
        st.uv_count = 0;
    }

    if (sub(st.core, ACELP_CORE) == 0 || sub(st.core, AMR_WB_CORE) == 0)
        && sub(st.last_core, HQ_CORE) == 0
    {
        core_switching_pre_dec_acelp_after_hq(st, output_frame);
    }

    if sub(st.core, HQ_CORE) == 0
        && (sub(st.last_core, ACELP_CORE) == 0 || st.last_core == AMR_WB_CORE)
    {
        set32(&mut st.prev_env, 0, SFM_N_WB);
        set32(&mut st.prev_normq, 0, SFM_N_WB);

        set32(&mut st.last_ni_gain, 0, BANDS_MAX);
        set16(&mut st.last_env, 0, BANDS_MAX);
        st.last_max_pos_pulse = 0;

        set16(&mut st.prev_swb_peak_pos, 0, SPT_SHORTEN_SBNUM);
        st.prev_frm_hfe2 = 0;
        st.prev_stab_hfe2 = 0;

        if l_sub(st.output_fs, 16000) > 0 {
            set32(&mut st.prev_coeff_out, 0, L_HQ_WB_BWE);
        }

        set16(&mut st.old_out, 0, output_frame);
        st.q_old_wtda_lb = 15;
        st.q_old_wtda = 15;
    }

    // handle switching cases where preecho_sb was not called in the last frame (memory not up to
    // date); the reference's plain `--` on a Word16
    st.pastpre = st.pastpre.wrapping_sub(1);
    if st.pastpre <= 0 {
        reset_preecho_dec(st);
    }

    if l_sub(st.core_brate, i32::from(FRAME_NO_DATA)) == 0 {
        st.vad = 0;
        st.m_frame_type = ZERO_FRAME;
    } else if l_sub(st.core_brate, i32::from(SID_2K40)) <= 0 {
        st.vad = 0;
        st.m_frame_type = SID_FRAME;
    } else {
        st.vad = 1;
        st.m_frame_type = ACTIVE_FRAME;
    }

    // switch on CNA on active frames
    // (the reference's first two branches, EVS up to CNA_MAX_BRATE and AMR-WB IO up to 8.85
    // kbit/s, both set the flag, so they are one condition here)
    if (sub(st.core, AMR_WB_CORE) != 0
        && st.vad != 0
        && l_sub(st.total_brate, i32::from(CNA_MAX_BRATE)) <= 0)
        || (sub(st.core, AMR_WB_CORE) == 0
            && st.vad != 0
            && l_sub(st.total_brate, i32::from(ACELP_8K85)) <= 0)
    {
        st.flag_cna = 1;
    } else if st.vad != 0 || (sub(st.cng_type, FD_CNG) == 0 && sub(st.l_frame, L_FRAME16K) == 0) {
        st.flag_cna = 0;
    }

    if sub(st.core, AMR_WB_CORE) == 0 {
        st.cng_type = LP_CNG;
    }

    core_switching_pre_dec_fd_cng(st);
}

/// The MODE2 -> MODE1 part of [`core_switching_pre_dec`]: the de-emphasis, synthesis and
/// post-filter memories brought to MODE1 scaling, the BWE, HF and HQ memories reset, a TCX last
/// frame taken as HQ, and, after a lost frame, the concealed ACELP synthesis carried into
/// `fer_samples` for an HQ frame to fade in from.
fn core_switching_pre_dec_mode2(st: &mut DecoderState) {
    st.mem_deemph = st.syn[M as usize];
    set16(&mut st.agc_mem, 0, 2);
    let q_syn = st.q_syn;
    scale_sig(std::slice::from_mut(&mut st.mem_deemph), 1, q_syn); // Brings mem_deemph to Qsyn

    copy_scale_sig(&st.mem_syn2, &mut st.mem_syn1, M, sub(-1, q_syn)); // Q-1

    st.bpf_off = 1;
    scale_sig(&mut st.pfstat.mem_pf_in, L_SUBFR, q_syn); // Post_filter mem
    scale_sig(&mut st.pfstat.mem_res2, DECMEM_RES2, q_syn); // NB post_filter mem
    scale_sig(&mut st.pfstat.mem_stp, L_SUBFR, q_syn); // Post_filter mem
    set16(&mut st.pst_old_syn, 0, NBPSF_PIT_MAX); // BPF mem
                                                  // convert from 15Q16, log2 -> 7Q8 10*log10
    st.pst_lp_ener = round_word(l_shl(mpy_32_16_1(st.lp_error_ener, 0x6054), 2 + 8));
    st.pst_mem_deemp_err = 0;
    st.psf_lp_noise = round_word(l_shl(st.lp_noise, 1));

    // reset old HB synthesis buffer
    if sub(st.last_l_frame, L_FRAME) == 0 {
        st.old_bwe_delay = ns2sa_fx2(st.output_fs, MAX_DELAY_TBE_NS - DELAY_SWB_TBE_12K8_NS);
    } else {
        st.old_bwe_delay = ns2sa_fx2(st.output_fs, MAX_DELAY_TBE_NS - DELAY_SWB_TBE_16K_NS);
    }
    set16(
        &mut st.hb_prev_synth_buffer,
        0,
        ns2sa(48000, DELAY_BWE_TOTAL_NS),
    );
    st.prev_hb_synth_fx_exp = 31;

    // reset upd_cnt
    st.upd_cnt = MAX_UPD_CNT;
    st.igf = 0;

    if sub(st.last_core, ACELP_CORE) != 0 {
        // reset BWE memories
        set16(&mut st.old_bwe_exc, 0, PIT16K_MAX * 2);
        st.bwe_non_lin_prev_scale = 0;
    }

    if l_sub(st.output_fs, 16000) >= 0 {
        hf_synth_reset(
            &mut st.seed2,
            &mut st.mem_hf,
            &mut st.mem_syn_hf,
            &mut st.mem_hp400,
            &mut st.mem_hp_interp,
            &mut st.delay_syn_hf,
        );
    }
    set16(
        &mut st.old_syn_12k8_16k,
        0,
        ns2sa(16000, DELAY_FD_BWE_ENC_NS),
    );

    set32(&mut st.prev_env, 0, SFM_N_WB);
    set32(&mut st.prev_normq, 0, SFM_N_WB);

    set32(&mut st.last_ni_gain, 0, BANDS_MAX);
    set16(&mut st.last_env, 0, BANDS_MAX);
    st.last_max_pos_pulse = 0;

    if l_sub(st.output_fs, 16000) > 0 {
        set32(&mut st.prev_coeff_out, 0, L_HQ_WB_BWE);
    }

    // pre-echo
    st.pastpre = 0;
    // reset the GSC pre echo energy threshold in case of switching
    st.last_frame_ener = MAX_32;

    if sub(st.last_core, TCX_20_CORE) == 0 || sub(st.last_core, TCX_10_CORE) == 0 {
        st.last_core = HQ_CORE;
        copy(
            &st.fbtc_xdelay_buf,
            &mut st.prev_synth_buffer,
            ns2sa(st.output_fs, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS),
        );
        set32(&mut st.last_ni_gain, 0, BANDS_MAX);
        set16(&mut st.last_env, 0, BANDS_MAX);
        st.last_max_pos_pulse = 0;

        set16(&mut st.prev_swb_peak_pos, 0, SPT_SHORTEN_SBNUM);
        st.prev_frm_hfe2 = 0;
        st.prev_stab_hfe2 = 0;
    }

    if st.prev_bfi != 0 {
        // switch off Hq Voicing as it was not updated in MODE2
        st.old_hq_voicing = 0;
        st.hq_voicing = 0;

        let delay_comp = ns2sa_fx2(st.output_fs, DELAY_CLDFB_NS);

        if st.last_con_tcx == 0 && st.last_core_bfi == ACELP_CORE && sub(st.core, HQ_CORE) == 0 {
            core_switching_pre_dec_mode2_cldfb(st, delay_comp);
        }

        if st.last_con_tcx == 0 && st.last_core_bfi == ACELP_CORE && sub(st.core, HQ_CORE) == 0 {
            let half = shr(st.output_frame, 1);
            let dc = delay_comp.max(0) as usize;
            lerp(
                &st.syn_overl,
                &mut st.fer_samples[dc..],
                half,
                shr(st.last_l_frame, 1),
            );
            // Set to zero the remaining part
            let from = (delay_comp + half).max(0) as usize;
            set16(&mut st.fer_samples[from..], 0, half - delay_comp);
        }
    }

    st.use_acelp_preq = 0;
    st.reset_mem_ar = 0;
}

/// The CLDFB analysis of the concealed MODE2 overlap `syn_Overl` and its re-synthesis at the
/// output rate into `fer_samples` (the CLDFB-delay part), both filter banks' states saved and
/// restored around it.
fn core_switching_pre_dec_mode2_cldfb(st: &mut DecoderState, delay_comp: i16) {
    let mut real_buffer = [[0i32; CLDFB_ROW]; CLDFB_COLS];
    let mut imag_buffer = [[0i32; CLDFB_ROW]; CLDFB_COLS];
    let mut scale_factor = CldfbScaleFactor::zeroed();

    // The decoder always holds both filter banks; without them there is nothing to resynthesise.
    let Some(ana) = st.cldfb_ana.as_deref_mut() else {
        return;
    };
    let no_col = ana.no_col.min(idiv1616(
        sub(add(delay_comp, ana.no_channels), 1),
        ana.no_channels,
    ));
    // no_col <= the bank's own column count <= CLDFB_NO_COL_MAX
    let cols = (no_col.max(0) as usize).min(CLDFB_COLS);

    // CLDFB analysis of the synthesis at internal sampling rate
    cldfb_save_memory(ana);
    cldfb_analysis_filtering(
        ana,
        &mut real_buffer[..cols],
        &mut imag_buffer[..cols],
        &mut scale_factor,
        &st.syn_overl,
        0,
        no_col,
    );
    cldfb_restore_memory(ana);

    scale_factor.hb_scale = scale_factor.lb_scale;

    // CLDFB synthesis of the combined signal
    if let Some(syn_bank) = st.cldfb_syn.as_deref_mut() {
        cldfb_save_memory(syn_bank);
        cldfb_synthesis_filtering(
            syn_bank,
            &real_buffer[..cols],
            &imag_buffer[..cols],
            &scale_factor,
            &mut st.fer_samples,
            0,
            no_col,
        );
        cldfb_restore_memory(syn_bank);
    }
}

/// The FEC part of [`core_switching_pre_dec`]: the classifier's synthesis memory resampled
/// across a 12.8 <-> 16 kHz change of the ACELP core, or cleared.
fn core_switching_pre_dec_fec(st: &mut DecoderState) {
    if sub(st.l_frame, L_FRAME16K) > 0 {
        return;
    }
    if sub(st.last_l_frame, L_FRAME16K) <= 0 && sub(st.core, HQ_CORE) != 0 {
        if sub(st.l_frame, st.last_l_frame) != 0 {
            let old_len_clas_buff: i16;
            let new_len_clas_buff: i16;
            if sub(st.l_frame, st.last_l_frame) > 0 {
                old_len_clas_buff = extract_l(l_shr(
                    mpy_32_16_1(
                        l_mult0(st.last_l_frame, get_inv_frame_len(st.l_frame)), // Q21
                        L_SYN_MEM_CLAS_ESTIM,
                    ), // Q6
                    6,
                ));
                new_len_clas_buff = L_SYN_MEM_CLAS_ESTIM;
            } else {
                old_len_clas_buff = L_SYN_MEM_CLAS_ESTIM;
                new_len_clas_buff = extract_l(l_shr(
                    mpy_32_16_1(
                        l_mult0(st.l_frame, get_inv_frame_len(st.last_l_frame)), // Q21
                        L_SYN_MEM_CLAS_ESTIM,
                    ), // Q6
                    6,
                ));
            }
            // both lengths are at most L_SYN_MEM_CLAS_ESTIM (the shorter frame over the longer)
            lerp_within(
                &mut st.mem_syn_clas_estim,
                sub(L_SYN_MEM_CLAS_ESTIM, old_len_clas_buff).max(0) as usize,
                sub(L_SYN_MEM_CLAS_ESTIM, new_len_clas_buff).max(0) as usize,
                new_len_clas_buff,
                old_len_clas_buff,
            );
        }
    } else {
        set16(&mut st.mem_syn_clas_estim, 0, L_SYN_MEM_CLAS_ESTIM);
        st.classifier_q_mem_syn = 0;
    }
}

/// The ACELP (or AMR-WB IO) after HQ part of [`core_switching_pre_dec`]: the LSF / LSP and
/// quantiser memories set to their means, the synthesis, de-emphasis, gain and dispersion
/// memories reset, the concealment energy and gain recomputed from the last output, the CLDFB,
/// TBE and HF memories reset.
fn core_switching_pre_dec_acelp_after_hq(st: &mut DecoderState, output_frame: i16) {
    if sub(st.l_frame, L_FRAME16K) == 0 {
        copy(&TRWB2_AVE_FX, &mut st.lsf_old, M);
        copy(&TRWB2_AVE_FX, &mut st.lsfoldbfi1, M);
        copy(&TRWB2_AVE_FX, &mut st.lsfoldbfi0, M);
        copy(&TRWB2_AVE_FX, &mut st.lsf_adaptive_mean, M);
        lsf2lsp(&st.lsf_old, &mut st.lsp_old, M, i32::from(INT_FS_16K));
    } else {
        copy(&TRWB_AVE_FX, &mut st.lsf_old, M); // init of LSP
        copy(&TRWB_AVE_FX, &mut st.lsfoldbfi1, M);
        copy(&TRWB_AVE_FX, &mut st.lsfoldbfi0, M);
        copy(&TRWB_AVE_FX, &mut st.lsf_adaptive_mean, M);
        lsf2lsp(&st.lsf_old, &mut st.lsp_old, M, i32::from(INT_FS_FX));
    }

    set16(&mut st.agc_mem, 0, 2);
    st.mem_deemph = 0;
    if st.last_con_tcx == 0 {
        set16(&mut st.mem_syn2, 0, M);
    }
    set16(&mut st.mem_syn1, 0, M);
    st.bwe_non_lin_prev_scale = 0;

    // Reset ACELP parameters
    set16(&mut st.mem_ma, 0, M);
    if l_sub(st.sr_core, 16000) == 0 {
        copy(&GEWB2_AVE_FX, &mut st.mem_ar, M);
    } else {
        copy(&GEWB_AVE_FX, &mut st.mem_ar, M);
    }
    st.tilt_code = 0;
    st.gc_threshold = 0;
    st.dm.prev_gain_code = 0;
    set16(&mut st.dm.prev_gain_pit, 0, 6);
    st.dm.prev_state = 0;

    st.last_coder_type = GENERIC;

    frame_ener(
        output_frame,
        UNVOICED_CLAS,
        &st.previoussynth,
        -1,
        &mut st.enr_old,
        1,
        0,
        0,
        0,
    );
    st.lp_gainp = 0;

    // st->lp_gainc_fx = (float)sqrt( st->lp_ener_fx )
    if st.lp_ener != 0 {
        let mut exp = norm_l(st.lp_ener); // In Q6
        let mut tmp = extract_h(l_shl(st.lp_ener, exp));
        exp = sub(exp, 30 - 6);

        tmp = div_s(16384, tmp);
        let mut l_tmp = l_deposit_h(tmp);
        l_tmp = isqrt_lc(l_tmp, &mut exp);

        st.lp_gainc = round_word(l_shl(l_tmp, sub(exp, 12))); // In Q3
    }

    st.last_voice_factor = 0;
    st.last_gsc_noisy_speech_flag = 0;

    // reset CLDFB memories
    for bank in [&mut st.cldfb_ana, &mut st.cldfb_bpf, &mut st.cldfb_syn] {
        if let Some(bank) = bank.as_deref_mut() {
            cldfb_reset_memory(bank);
        }
    }

    // reset TBE memories
    if st.last_con_tcx == 0 {
        set16(&mut st.old_exc, 0, L_EXC_MEM_DEC);
    } else if sub(st.l_frame, L_FRAME16K) < 0 {
        // resample from 16kHz to 12.8kHZ
        synth_mem_updt2(
            st.l_frame,
            L_FRAME16K,
            &mut st.old_exc,
            &mut st.mem_syn_r,
            &mut st.mem_syn2,
            None,
            DEC,
        );
    }

    set16(&mut st.old_bwe_exc, 0, PIT16K_MAX * 2);

    if l_sub(st.output_fs, 16000) >= 0 {
        hf_synth_reset(
            &mut st.seed2,
            &mut st.mem_hf,
            &mut st.mem_syn_hf,
            &mut st.mem_hp400,
            &mut st.mem_hp_interp,
            &mut st.delay_syn_hf,
        );
    }
    set16(
        &mut st.old_syn_12k8_16k,
        0,
        ns2sa(16000, DELAY_FD_BWE_ENC_NS),
    );
}

/// The FD-CNG part of [`core_switching_pre_dec`]: on a change of the frame length, the
/// bandwidth, or in the first frame, reconfigure the FD-CNG and resample its overlap buffers.
fn core_switching_pre_dec_fd_cng(st: &mut DecoderState) {
    let l_frame = st.l_frame;
    let last_l_frame = st.last_l_frame;
    let core = st.core;
    let total_brate = st.total_brate;
    let last_total_brate = st.last_total_brate;
    let bwidth = st.bwidth;
    let last_bwidth = st.last_bwidth;
    let ini_frame = st.ini_frame;
    let rf_flag = st.rf_flag;
    let vad = st.vad;
    let Some(hs) = st.h_fd_cng_dec.as_deref_mut() else {
        return;
    };
    // the decoder's FD-CNG always has its common part (the reference dereferences it)
    let Some(frame_size) = hs.h_fd_cng_com.as_deref().map(|com| com.frame_size) else {
        return;
    };
    if !(sub(last_l_frame, l_frame) != 0
        || sub(frame_size, l_frame) != 0
        || ini_frame == 0
        || sub(bwidth, last_bwidth) != 0)
    {
        return;
    }

    if sub(core, AMR_WB_CORE) != 0 {
        let mut tmp = total_brate;
        if sub(rf_flag, 1) == 0 && l_sub(total_brate, i32::from(ACELP_13K20)) == 0 {
            tmp = i32::from(ACELP_9K60);
        }
        configure_fd_cng_dec(hs, bwidth, tmp, l_frame);
    } else {
        configure_fd_cng_dec(hs, 1, i32::from(ACELP_8K00), l_frame);

        if vad != 0 {
            if let Some(com) = hs.h_fd_cng_com.as_deref_mut() {
                com.cng_bitrate = total_brate;
            }
        }
    }

    if sub(last_l_frame, l_frame) != 0
        && sub(l_frame, L_FRAME16K) <= 0
        && sub(last_l_frame, L_FRAME16K) <= 0
    {
        let Some(com) = hs.h_fd_cng_com.as_deref_mut() else {
            return;
        };
        // olapBufferSynth2 points into the FD-CNG decoder's own buffer (the reference would
        // dereference NULL without it)
        if let Some(at) = com.olap_buffer_synth2 {
            lerp_in_place(
                &mut hs.olap_buffer_synth2[at..],
                l_frame * 2,
                last_l_frame * 2,
            );
        }
        if l_sub(total_brate, i32::from(SID_2K40)) <= 0
            && l_sub(last_total_brate, i32::from(SID_2K40)) <= 0
        {
            lerp_in_place(&mut com.olap_buffer_synth, l_frame * 2, last_l_frame * 2);
            let n = (l_frame.max(0) as usize) * 2;
            if sub(l_frame, L_FRAME) == 0 {
                for v in &mut com.olap_buffer_synth[..n] {
                    *v = mult_r(*v, 20480);
                }
            } else {
                for v in &mut com.olap_buffer_synth[..n] {
                    *v = mult_r(shl(*v, 1), 26214);
                }
            }
        }
    }
}

/// `core_switching_post_dec_fx`: post-processing of the core synthesis `synth` (Q`*qsynth`,
/// `output_frame` samples at the output rate, the buffer at least
/// `output_frame + HQ_DELTA_MAX*HQ_DELAY_COMP` long) for ACELP / HQ core switching: the HQ
/// synthesis delayed to line up with ACELP and cross-faded with the ACELP switching subframes
/// or the concealed ACELP frame, the HQ delay buffer faded into an ACELP frame after HQ, and the
/// BWE / TBE memories reset on an extension-layer or bandwidth change. `core_switching_flag`
/// marks an ACELP -> HQ switching frame, `coder_type` is the ACELP coder type. `*qsynth` is
/// updated to the synthesis' new Q.
pub fn core_switching_post_dec(
    st: &mut DecoderState,
    synth: &mut [i16],
    output_frame: i16,
    core_switching_flag: i16,
    coder_type: i16,
    qsynth: &mut i16,
) {
    // Rescale synthesis in Q0 to avoid multiple rescaling after
    let tmp = find_max_norm16(synth, output_frame);
    scale_sig(synth, output_frame, tmp);
    *qsynth = add(*qsynth, tmp);

    if sub(st.core, ACELP_CORE) == 0 && st.bfi != 0 {
        // the output at Q0; the function never reads st->fer_samples_fx itself
        let mut fer_samples = st.fer_samples;
        acelp_core_switch_dec_bfi(st, &mut fer_samples, coder_type);
        st.fer_samples = fer_samples;
    }

    // set multiplication factor according to the sampling rate
    let tmp = extract_l(l_shr(st.output_fs, 13));
    let fs_khz = shl(add(tmp, 1), 3);

    let mut delta: i16 = 1;
    if sub(output_frame, L_FRAME16K) >= 0 {
        delta = shr(fs_khz, 3);
    }

    // set delay compensation between HQ synthesis and ACELP synthesis
    let delay_comp = i_mult2(delta, HQ_DELAY_COMP);

    if sub(st.core, HQ_CORE) == 0 {
        core_switching_post_dec_hq(
            st,
            synth,
            output_frame,
            core_switching_flag,
            qsynth,
            fs_khz,
            delta,
            delay_comp,
        );
    } else {
        if sub(st.last_core, HQ_CORE) == 0 {
            // MDCT to ACELP transition
            core_switching_post_dec_after_hq(
                st,
                synth,
                output_frame,
                qsynth,
                fs_khz,
                delta,
                delay_comp,
            );
        }

        set16(&mut st.delay_buf_out, 0, HQ_DELTA_MAX * HQ_DELAY_COMP);
        st.old_hq_voicing = 0;

        set16(&mut st.prev_swb_peak_pos, 0, SPT_SHORTEN_SBNUM);
        st.prev_frm_hfe2 = 0;
        st.prev_stab_hfe2 = 0;
    }

    core_switching_post_dec_bwe_reset(st, output_frame, coder_type);
    core_switching_post_dec_tbe_reset(st, output_frame);
}

/// ACELP -> HQ switching with the ACELP side decoded from this frame's bits (after an ACELP or
/// AMR-WB IO frame at an unchanged internal rate).
fn acelp_switch(st: &DecoderState, core_switching_flag: i16) -> bool {
    core_switching_flag != 0
        && sub(st.last_l_frame, st.last_l_frame_ori) == 0
        && (sub(st.last_core, ACELP_CORE) == 0 || sub(st.last_core, AMR_WB_CORE) == 0)
}

/// The HQ branch of [`core_switching_post_dec`].
fn core_switching_post_dec_hq(
    st: &mut DecoderState,
    synth: &mut [i16],
    output_frame: i16,
    core_switching_flag: i16,
    qsynth: &mut i16,
    fs_khz: i16,
    delta: i16,
    delay_comp: i16,
) {
    let mut synth_subfr_out = [0i16; SWITCH_MAX_GAP as usize];
    let mut synth_subfr_bwe = [0i16; SWITCH_MAX_GAP as usize];
    let mut mem_synth = [0i16; MEM_SYNTH_LEN];
    // set by acelp_core_switch_dec_fx on exactly the frames core_switching_OLA_fx reads it
    let mut qsubfr: i16 = 0;

    st.use_acelp_preq = 0;
    st.mem_deemph_old_syn = 0;

    if acelp_switch(st, core_switching_flag) {
        acelp_core_switch_dec(
            st,
            &mut synth_subfr_out,
            &mut synth_subfr_bwe,
            output_frame,
            core_switching_flag,
            &mut mem_synth,
            &mut qsubfr,
        );
    }
    if core_switching_flag != 0 && sub(st.last_core, HQ_CORE) == 0 && st.prev_bfi != 0 {
        copy(&st.delay_buf_out, &mut synth_subfr_out, delay_comp);
        qsubfr = st.q_old_postdec;
    }

    // delay HQ synthesis to synchronize with ACELP synthesis
    // rescaling to the min exp of the 2
    let qtmp = (*qsynth).min(st.q_old_postdec);
    scale_sig(synth, output_frame, sub(qtmp, *qsynth));
    *qsynth = qtmp;
    scale_sig(
        &mut st.delay_buf_out,
        delay_comp,
        sub(qtmp, st.q_old_postdec),
    );
    st.q_old_postdec = qtmp;

    let frame = output_frame.max(0) as usize;
    let dc = delay_comp.max(0) as usize;
    // Copy(synth, &synth[delay_comp], output_frame): an overlapping copy, as memmove
    synth.copy_within(0..frame, dc);
    copy(&st.delay_buf_out, synth, delay_comp);
    copy(&synth[frame..], &mut st.delay_buf_out, delay_comp);

    if acelp_switch(st, core_switching_flag) {
        // mem_over_hp_fx : Qsubfr
        core_switching_ola(
            &mut mem_synth,
            st.last_l_frame,
            st.output_fs,
            synth,
            &mut synth_subfr_out,
            &mut synth_subfr_bwe,
            output_frame,
            st.bwidth,
            qsynth,
            &mut qsubfr,
        );
    } else if core_switching_flag != 0 && sub(st.last_core, HQ_CORE) == 0 && st.prev_bfi != 0 {
        // HQ | ACELP | TRANSITION with ACELP frame lost
        // Overlapp between old->out (stocked in st_fx->fer_samples)and good HQ frame on L/2
        let shift = i_mult2(fs_khz, 10);
        let tmp = i_mult2(delta, shr(N16_CORE_SW, 1));
        scale_sig(&mut st.fer_samples, output_frame, *qsynth);
        cross_fade_fer(st, synth, dc, tmp.max(0) as usize, shift);
    } else if (core_switching_flag == 0
        && sub(st.core, HQ_CORE) == 0
        && (sub(st.last_core, ACELP_CORE) == 0 || sub(st.last_core, AMR_WB_CORE) == 0))
        || (core_switching_flag != 0
            && st.prev_bfi != 0
            && sub(st.last_l_frame, st.last_l_frame_ori) != 0)
    {
        // ACELP | TRANSITION | HQ with TRANSITION lost
        // Overlapp between CELP estimation (BFI) and good HQ frame on L/2
        let shift = i_mult2(fs_khz, 10);
        scale_sig(&mut st.fer_samples, output_frame, *qsynth);
        cross_fade_fer(st, synth, 0, 0, shift);
    }

    st.bwe_non_lin_prev_scale = 0;
    // bwidth is NB..FB (0..3); a value outside (never decoded) takes the NB frame
    let inner_frame = INNER_FRAME_TBL
        .get(st.bwidth.max(0) as usize)
        .copied()
        .unwrap_or(INNER_FRAME_TBL[0]);
    if !(sub(inner_frame, L_FRAME16K) == 0 && l_sub(st.core_brate, i32::from(HQ_32K)) == 0) {
        set32(&mut st.prev_env, 0, SFM_N_WB);
        set32(&mut st.prev_normq, 0, SFM_N_WB);
    }
    // scaling of st_fx->previoussynth_fx set at Q0
    copy_scale_sig(synth, &mut st.previoussynth, output_frame, negate(*qsynth));

    // Set post-filtering flag to zero
    st.pfstat.on = 0;
}

/// The fade from the concealed `fer_samples[from..]` into the HQ `synth[at..]` over `shift`
/// samples (`tmpF` rising by `1/shift`, the old side weighted `32768 - tmpF`, saturating).
fn cross_fade_fer(st: &DecoderState, synth: &mut [i16], at: usize, from: usize, shift: i16) {
    let tmp = div_s(1, shift); // Q15
    let mut tmp_f: i16 = 0;
    for i in 0..shift.max(0) as usize {
        let l_tmp = l_mult(synth[at + i], tmp_f); // Qsynth + 16
        synth[at + i] = round_word(l_mac(
            l_tmp,
            add(sub(24576, tmp_f), 8192),
            st.fer_samples[from + i],
        )); // Qsynth
        tmp_f = add(tmp_f, tmp);
    }
}

/// The MDCT -> ACELP transition of [`core_switching_post_dec`]: the synthesis, the HQ delay
/// buffer and the HQ overlap brought to one Q, the delay buffer put ahead of the ACELP frame,
/// and the HQ overlap (or, after a voiced lost frame, the concealed one) faded out over 3 ms.
fn core_switching_post_dec_after_hq(
    st: &mut DecoderState,
    synth: &mut [i16],
    output_frame: i16,
    qsynth: &mut i16,
    fs_khz: i16,
    delta: i16,
    delay_comp: i16,
) {
    let qtmp = (*qsynth).min(st.q_old_postdec).min(st.q_old_wtda);

    scale_sig(synth, output_frame, sub(qtmp, *qsynth));
    scale_sig(
        &mut st.delay_buf_out,
        delay_comp,
        sub(qtmp, st.q_old_postdec),
    );
    scale_sig(&mut st.old_out, L_FRAME48K, sub(qtmp, st.q_old_wtda));
    *qsynth = qtmp;
    st.q_old_postdec = qtmp;
    st.q_old_wtda = qtmp;

    // copy the HQ/ACELP delay synchroniation buffer at the beginning of ACELP frame
    copy(&st.delay_buf_out, synth, delay_comp);

    let tmp = i_mult2(delta, N_ZERO_8);
    let shift = i_mult2(fs_khz, 3);
    let at = tmp.max(0) as usize;
    if st.prev_bfi != 0 && st.hq_voicing != 0 {
        copy_scale_sig(&st.fer_samples, &mut st.old_out[at..], shift, *qsynth);
    }

    let tmp = div_s(1, shift);
    let dc = delay_comp.max(0) as usize;
    let mut tmp_f: i16 = 0;
    for i in 0..shift.max(0) as usize {
        synth[dc + i] = add(
            mult_r(tmp_f, synth[dc + i]),
            mult_r(sub(32767, tmp_f), st.old_out[at + i]),
        );
        tmp_f = add(tmp_f, tmp);
    }
}

/// The SWB / WB BWE resets of [`core_switching_post_dec`].
fn core_switching_post_dec_bwe_reset(st: &mut DecoderState, output_frame: i16, coder_type: i16) {
    // reset SWB BWE buffers
    if st.bws_cnt == 0
        || (st.bws_cnt > 0 && sub(coder_type, INACTIVE) != 0 && sub(coder_type, AUDIO) != 0)
    {
        st.attenu = 3277;
    }

    if (sub(st.last_extl, SWB_BWE) != 0 && sub(st.extl, SWB_BWE) == 0)
        || (sub(st.last_extl, FB_BWE) != 0 && sub(st.extl, FB_BWE) == 0)
        || ((sub(st.last_core, HQ_CORE) == 0 || sub(st.last_extl, SWB_TBE) == 0)
            && st.extl < 0
            && sub(st.core, HQ_CORE) != 0)
        || (sub(st.last_core, ACELP_CORE) == 0
            && sub(st.core, ACELP_CORE) == 0
            && ((sub(st.prev_coder_type, INACTIVE) != 0 && sub(coder_type, INACTIVE) == 0)
                || (sub(st.prev_coder_type, AUDIO) != 0 && sub(coder_type, AUDIO) == 0))
            && st.bws_cnt > 0)
    {
        set16(&mut st.l_old_wtda_swb, 0, output_frame);
        st.old_wtda_swb_fx_exp = 0;
        if sub(st.last_extl, WB_BWE) != 0 {
            st.prev_mode = NORMAL;
        }

        st.prev_energy = 0;
        st.prev_l_swb_norm = 8;
        st.prev_frica_flag = 0;
        set16(&mut st.mem_imdct, 0, L_FRAME48K);
        st.prev_td_energy = 0;
        st.prev_weight = 6554; // 0.2 in Q15
        st.prev_fb_ener_adjust = 0;
    }

    // reset WB BWE buffers
    if sub(st.last_extl, WB_BWE) != 0 && sub(st.extl, WB_BWE) == 0 {
        set16(&mut st.l_old_wtda_swb, 0, output_frame);

        if sub(st.last_extl, SWB_BWE) != 0 && sub(st.last_extl, FB_BWE) != 0 {
            st.prev_mode = NORMAL;
        }
        st.prev_energy_wb = 0;
        st.prev_l_swb_norm = 8;
        set16(&mut st.mem_imdct, 0, L_FRAME48K);
        st.prev_flag = 0;
    }
}

/// The SWB / FB / WB TBE and 3/2 interpolator resets of [`core_switching_post_dec`].
fn core_switching_post_dec_tbe_reset(st: &mut DecoderState, output_frame: i16) {
    // reset SWB TBE buffers
    if ((sub(st.extl, SWB_TBE) == 0 || sub(st.extl, FB_TBE) == 0 || sub(st.extl, SWB_CNG) == 0)
        && (sub(st.l_frame, st.last_l_frame) != 0
            || (sub(st.last_extl, SWB_TBE) != 0 && sub(st.last_extl, FB_TBE) != 0)
            || sub(st.last_core, HQ_CORE) == 0))
        || (sub(st.bwidth, st.last_bwidth) < 0 && sub(st.last_extl, SWB_TBE) != 0)
        || st.old_ppp_mode != 0
        || ((sub(st.prev_coder_type, AUDIO) == 0 || sub(st.prev_coder_type, INACTIVE) == 0)
            && st.bws_cnt > 0)
        || (st.bws_cnt == 0 && sub(st.prev_bws_cnt, N_WS2N_FRAMES) == 0)
    {
        swb_tbe_reset(
            &mut st.mem_csfilt,
            &mut st.mem_gen_sh_bexc_filt_down_shb,
            &mut st.state_lpc_syn,
            &mut st.syn_overlap,
            &mut st.state_syn_shbexc,
            &mut st.tbe_demph,
            &mut st.tbe_premph,
            &mut st.mem_stp_swb,
            &mut st.gain_prec_swb,
        );

        set16(&mut st.gain_shape_delay, 0, NUM_SHB_SUBFR / 2);
        swb_tbe_reset_synth(
            &mut st.gen_sh_bsynth_hilbert_mem,
            &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local,
        );

        if sub(output_frame, L_FRAME16K) == 0 {
            // reset in case that SWB TBE layer is transmitted, but the output is 16kHz sampled
            set16(&mut st.mem_resamp_hb_32k, 0, 2 * ALLPASSSECTIONS_STEEP + 1);
        }
        set16(&mut st.int_3_over_2_tbemem_dec, 0, INTERP_3_2_MEM_LEN);
    } else if (sub(st.extl, SWB_TBE) == 0 || sub(st.extl, FB_TBE) == 0)
        && (l_sub(st.last_total_brate, st.total_brate) != 0
            || sub(st.last_bwidth, st.bwidth) != 0
            || sub(st.last_codec_mode, MODE1) != 0
            || sub(st.rf_flag, st.rf_flag_last) != 0)
    {
        set16(&mut st.state_lpc_syn, 0, LPC_SHB_ORDER);
        set16(&mut st.state_syn_shbexc, 0, L_SHB_LAHEAD);
        set16(&mut st.mem_stp_swb, 0, LPC_SHB_ORDER);
        set16(&mut st.mem_zero_swb, 0, LPC_SHB_ORDER);
        st.gain_prec_swb = 16384; // Q14 = 1
    }

    // Interp_3_2 CNG buffers reset
    if l_sub(st.output_fs, 48000) == 0
        && l_sub(st.last_core_brate, i32::from(SID_2K40)) > 0
        && (l_sub(st.core_brate, i32::from(FRAME_NO_DATA)) == 0
            || l_sub(st.core_brate, i32::from(SID_2K40)) == 0)
    {
        set16(&mut st.interpol_3_2_cng_dec, 0, INTERP_3_2_MEM_LEN);
    }

    // reset FB TBE buffers
    if sub(st.extl, FB_TBE) == 0
        && (sub(st.last_extl, FB_TBE) != 0 || sub(st.l_frame, st.last_l_frame) != 0)
    {
        set16(&mut st.fb_state_lpc_syn, 0, LPC_SHB_ORDER);
        st.fb_tbe_demph = 0;
        fb_tbe_reset_synth(
            &mut st.fbbwe_hpf_mem,
            &mut st.fbbwe_hpf_mem_fx_q,
            &mut st.prev_fbbwe_ratio,
        );
    }

    // reset WB TBE buffers
    if sub(st.last_extl, WB_TBE) != 0 && sub(st.extl, WB_TBE) == 0 {
        wb_tbe_extras_reset(
            &mut st.mem_gen_sh_bexc_filt_down_wb2,
            &mut st.mem_gen_sh_bexc_filt_down_wb3,
        );
        wb_tbe_extras_reset_synth(
            &mut st.state_lsyn_filt_shb,
            &mut st.state_lsyn_filt_dwn_shb,
            &mut st.state_32and48k_wb_upsample,
            &mut st.mem_resamp_hb,
        );

        set16(&mut st.state_syn_shbexc, 0, L_SHB_LAHEAD / 4);
        set16(&mut st.syn_overlap, 0, L_SHB_LAHEAD);
        set32(&mut st.mem_csfilt, 0, 2);
    }
}
