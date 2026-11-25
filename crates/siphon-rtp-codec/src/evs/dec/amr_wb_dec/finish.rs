//! The end of `amr_wb_dec_fx`: the state updates, the overlap with the old MDCT memory after an
//! HQ frame, the delay of the synthesis to the bandwidth extension layers, the high-pass filter,
//! the TCX-LTP memories and the final output of the synthesis.

use super::AmrWork;
use crate::evs::cnst::{
    ACELP_CORE, ACELP_LOOK_NS, BUF_DEC_RATE, DELAY_BWE_TOTAL_NS, DELAY_CLDFB_NS, FRAME_SIZE_NS,
    HQ_48K, HQ_CORE, L_FRAME, L_FRAME16K, L_FRAME48K, MIN_ACT_CNG_UPD, MODE2, N_ZERO_MDCT_NS,
    SID_1K75, TCXLTP_DELAY_NS, TCX_10_CORE, TCX_20_CORE, TCX_NONTONAL, WB,
};
use crate::evs::com::basop_util::inv16;
use crate::evs::com::hp50::hp20;
use crate::evs::com::tcx_ltp::tcx_ltp_post;
use crate::evs::com::tools::{copy_scale_sig, scale_sig, scale_sig32};
use crate::evs::dec::acelp_core_switch_dec::acelp_core_switch_dec_bfi;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::syn_outp::syn_output;
use crate::evs::dec::updt_dec::updt_dec;
use crate::evs::dec::waveadjust_fec_dec::waveform_adj2_fix;
use crate::evs::macros::ns2sa_fx2;
use crate::itu::basic_ops::{add, extract_l, l_mult, l_sub, negate, shl, sub};
use crate::itu::stl2009::{l_mult0, msu_r};

/// The updates after the frame and the synthesis output.
pub(super) fn update_and_output(st: &mut DecoderState, w: &mut AmrWork, output_sp: &mut [i16]) {
    let output_frame = w.output_frame;

    // Updates
    updt_dec(
        st,
        L_FRAME,
        w.coder_type,
        &w.old_exc,
        &w.pitch_buf,
        0,
        &w.aq,
        &w.lsf_new,
        &w.lsp_new,
        &w.voice_factors,
        &w.dummy_buf,
        &w.gain_buf,
    );

    // update old_Aq[] - needed in improv_amr_wb_gs()
    st.old_aq.copy_from_slice(&w.aq);

    let waveadj_rec = st.bfi == 0
        && st.prev_bfi != 0
        && l_sub(st.last_total_brate, HQ_48K) >= 0
        && sub(st.last_codec_mode, MODE2) == 0
        && (sub(st.last_core_bfi, TCX_20_CORE) == 0 || sub(st.last_core_bfi, TCX_10_CORE) == 0)
        && st.plc_info.concealment_method == TCX_NONTONAL
        && st.plc_info.nb_lost_cmpt < 4;

    // update the main codec parameters
    st.last_core = st.core;
    st.last_extl = -1;
    st.last_codec_mode = st.codec_mode;
    st.last_l_frame = L_FRAME;
    st.last_core_brate = st.core_brate;
    st.last_bwidth = WB;
    st.last_total_brate_ber = st.total_brate;
    st.prev_q_exc = st.q_exc;
    if st.bfi == 0 {
        st.last_total_brate = st.total_brate;
        st.last_good = st.clas_dec;
    }
    st.last_vad = w.vad_flag;
    st.last_flag_cna = w.flag_cna as i8; // 0 or 1

    // Overlap of the ACELP synthesis with the old MDCT memory
    if st.bfi != 0 {
        // calculate another loss frame to fill the gap in case of a switching frame loss
        let mut fer_samples = st.fer_samples;
        acelp_core_switch_dec_bfi(st, &mut fer_samples, w.coder_type);
        st.fer_samples = fer_samples;
    }

    let delay_comp = ns2sa_fx2(st.output_fs, DELAY_CLDFB_NS);
    scale_sig(
        &mut st.delay_buf_out,
        delay_comp,
        sub(st.q_syn2, st.q_old_postdec),
    );
    st.q_old_postdec = st.q_syn2;
    if sub(w.last_core_ori, HQ_CORE) == 0 {
        hq_overlap(st, w, delay_comp);
    }

    st.prev_bfi = st.bfi;
    st.last_con_tcx = st.con_tcx;

    if l_sub(st.core_brate, i32::from(SID_1K75)) > 0 {
        st.last_active_brate = st.total_brate;
    }

    if l_sub(st.core_brate, i32::from(SID_1K75)) > 0 && st.first_cng != 0 {
        if sub(st.act_cnt, BUF_DEC_RATE) >= 0 {
            st.act_cnt = 0;
        }

        st.act_cnt = add(st.act_cnt, 1);

        if sub(st.act_cnt, BUF_DEC_RATE) == 0 && st.ho_hist_size > 0 {
            st.ho_hist_size = sub(st.ho_hist_size, 1);
        }

        st.act_cnt2 = add(st.act_cnt2, 1);
        st.act_cnt2 = st.act_cnt2.min(MIN_ACT_CNG_UPD);
    }
    st.prev_bws_cnt = 0;
    st.bws_cnt = 0;
    st.bws_cnt1 = 0;

    // HP filtering; final synthesis output

    // Delay the ACELP synthesis by DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS
    if sub(output_frame, L_FRAME16K) >= 0 {
        delay_synthesis(st, w);
    }

    if waveadj_rec {
        let mut tmps: i16 = 0;
        if sub(output_frame, L_FRAME16K) >= 0 {
            tmps = ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS);
        }

        let overlap_at = st.tonal_mdc_tconceal.second_last_pcm_out.unwrap_or(0);
        waveform_adj2_fix(
            &mut st.tonal_mdc_tconceal.time_data_buffer[overlap_at..],
            &mut w.synth_out[tmps.max(0) as usize..],
            &mut st.plc_info.data_noise,
            &mut st.plc_info.outx_new_n1,
            &mut st.plc_info.nsapp_gain,
            &mut st.plc_info.nsapp_gain_n,
            &mut st.plc_info.recovery_gain,
            st.plc_info.step_concealgain,
            st.plc_info.pitch,
            st.plc_info.frame_size,
            tmps,
            add(extract_l(st.plc_info.nb_lost_cmpt), 1),
            st.bfi,
        );
    }

    // HP filter
    scale_sig32(
        &mut st.l_mem_hp_out,
        4,
        sub(st.q_syn2, st.qprev_synth_buffer),
    );
    st.qprev_synth_buffer = st.q_syn2;
    hp20(
        &mut w.synth_out,
        1,
        output_frame,
        &mut st.l_mem_hp_out,
        l_mult0(output_frame, 50),
    );

    // save the synthesis for core switching
    let at = ns2sa_fx2(st.output_fs, ACELP_LOOK_NS + DELAY_BWE_TOTAL_NS) as usize;
    copy_scale_sig(
        &w.synth_out[at..],
        &mut st.old_synth_sw,
        ns2sa_fx2(
            st.output_fs,
            FRAME_SIZE_NS - ACELP_LOOK_NS - DELAY_BWE_TOTAL_NS,
        ),
        sub(st.q_old_postdec, st.q_syn2),
    );

    {
        // TCX-LTP postfilter: used in AMR-WB IO to update the memories and to avoid
        // discontinuities when the past frame was TCX
        let delta = ns2sa_fx2(st.output_fs, TCXLTP_DELAY_NS);
        scale_sig(
            &mut st.tcxltp_mem_in,
            delta,
            sub(st.q_syn2, st.qprev_synth_buffer),
        );
        scale_sig(
            &mut st.tcxltp_mem_out,
            output_frame,
            sub(st.q_syn2, st.qprev_synth_buffer),
        );
        tcx_ltp_post(
            st.tcxltp,
            ACELP_CORE,
            output_frame,
            st.l_frame_past,
            0,
            &mut w.synth_out,
            None,
            delta,
            0,
            0,
            0,
            0,
            &mut st.tcxltp_pitch_int_post_prev,
            &mut st.tcxltp_pitch_fr_post_prev,
            &mut st.tcxltp_gain_post_prev,
            &mut st.tcxltp_filt_idx_prev,
            st.pit_res_max,
            &mut st.pit_res_max_past,
            0,
            0,
            &mut st.tcxltp_mem_in,
            &mut st.tcxltp_mem_out,
            st.total_brate,
        );
    }

    // final output of the synthesis signal
    syn_output(
        st.codec_mode,
        &w.synth_out,
        output_frame,
        output_sp,
        st.q_syn2,
    );
}

/// The cross-fade of the first AMR-WB IO frame after an HQ frame: the delay buffer of the HQ
/// core stands at the start of the ACELP frame, and the old MDCT memory fades out over the next
/// 6 ms while the ACELP synthesis fades in.
fn hq_overlap(st: &mut DecoderState, w: &mut AmrWork, delay_comp: i16) {
    scale_sig(&mut st.old_out, L_FRAME48K, sub(st.q_syn2, st.q_old_wtda));
    st.q_old_wtda = st.q_syn2;

    // copy the HQ/ACELP delay synchronisation buffer at the beginning of the ACELP frame
    let delay = delay_comp as usize;
    w.synth_out[..delay].copy_from_slice(&st.delay_buf_out[..delay]);

    let mut i: i16 = 15;
    let tmps = ns2sa_fx2(st.output_fs, 6_000_000);
    let nz = ns2sa_fx2(st.output_fs, N_ZERO_MDCT_NS);
    let mut step = inv16(tmps, &mut i);
    step = shl(step, i);
    let mut alpha: i16 = 0;

    if st.prev_bfi != 0 && st.hq_voicing != 0 {
        copy_scale_sig(
            &st.fer_samples,
            &mut st.old_out[nz as usize..],
            tmps,
            negate(st.q_syn2),
        );
    }

    for i in 0..tmps as usize {
        w.synth_out[i + delay] = msu_r(
            l_mult(w.synth_out[i + delay], alpha),
            st.old_out[i + nz as usize],
            add(alpha, -32768),
        );
        alpha = add(alpha, step);
    }
}

/// Delay the ACELP synthesis by `DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS`: the start of the frame
/// comes from the previous frame's tail.
fn delay_synthesis(st: &mut DecoderState, w: &mut AmrWork) {
    let output = w.output_frame as usize;
    let tmps = ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS);
    scale_sig(
        &mut st.prev_synth_buffer,
        tmps,
        sub(st.q_syn2, st.qprev_synth_buffer),
    );

    let delay = tmps as usize;
    w.tmp_buffer[..output].copy_from_slice(&w.synth_out[..output]);
    w.synth_out[..delay].copy_from_slice(&st.prev_synth_buffer[..delay]);
    w.synth_out[delay..output].copy_from_slice(&w.tmp_buffer[..output - delay]);
    st.prev_synth_buffer[..delay].copy_from_slice(&w.tmp_buffer[output - delay..output]);
}
