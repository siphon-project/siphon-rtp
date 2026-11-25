//! The MODE2 delay alignment of `evs_dec_fx`: the TD-BWE and ACELP / TCX components of the output
//! are cross-faded and delayed to the CLDFB synthesis, the high band is added and the TCX-LTP
//! post-filter runs; and the TBE transitions of an IGF frame.

use super::super::FrameWork;
use crate::evs::cnst::{
    ACELP_CORE, ACELP_LOOK_NS, ACTIVE_FRAME, DELAY_BWE_TOTAL_NS, DELAY_CLDFB_NS, FB, FB_TBE,
    LPC_SHB_ORDER, L_FRAME16K, MODE1, MODE2, NB, N_ZERO_MDCT_NS, SWB, SWB_TBE, TCXLTP_DELAY_NS, WB,
    WB_TBE,
};
use crate::evs::com::basop_util::inv16;
use crate::evs::com::swb_tbe_com::{fb_tbe_reset_synth, swb_tbe_reset, swb_tbe_reset_synth};
use crate::evs::com::tcx_ltp::tcx_ltp_post;
use crate::evs::com::tec_com::proc_tec_tfa_tbe;
use crate::evs::com::tools::{add_vec, copy_scale_sig, scale_sig, set16};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_tbe_dec::{gen_transition, gen_transition_wb};
use crate::evs::macros::{ns2sa, ns2sa_fx2};
use crate::itu::basic_ops::{add, l_mult, negate, shl, shr, sub};
use crate::itu::stl2009::msu_r;

/// The cross-fade of the TBE output out of a MODE2 TBE frame into the (core switching) frame
/// that follows an ACELP frame.
pub(super) fn tbe_transition(st: &mut DecoderState, w: &mut FrameWork) {
    if (sub(st.bwidth, SWB) == 0 || sub(st.bwidth, FB) == 0)
        && ((sub(st.last_extl, SWB_TBE) == 0 || sub(st.last_extl, FB_TBE) == 0)
            && sub(st.last_codec_mode, MODE2) == 0)
    {
        let length = 2 * ns2sa(st.output_fs, DELAY_BWE_TOTAL_NS);
        gen_transition(
            &st.syn_overlap,
            &st.old_tbe_synth,
            length,
            &mut w.hb_synth,
            &mut st.gen_sh_bsynth_hilbert_mem,
            &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local,
            &mut st.mem_resamp_hb_32k,
            &mut st.syn_dm_phase,
            st.output_fs,
            &mut st.int_3_over_2_tbemem_dec,
            st.rf_flag,
            st.total_brate,
        );
        w.hb_synth_exp = st.prev_q_bwe_syn2;
    } else if st.bwidth == WB && st.last_extl == WB_TBE {
        let length = 2 * ns2sa(st.output_fs, DELAY_BWE_TOTAL_NS);
        gen_transition_wb(
            &st.syn_overlap,
            &st.old_tbe_synth,
            st.prev_qx,
            length,
            &mut w.hb_synth,
            &mut st.state_lsyn_filt_shb,
            &mut st.state_lsyn_filt_dwn_shb,
            st.output_fs,
            &mut st.mem_resamp_hb,
        );
        w.hb_synth_exp = st.prev_qx;
    }
}

/// The TBE memories reset on the first MODE2 frame after MODE1 frames.
pub(super) fn tbe_reset_after_mode1(st: &mut DecoderState) {
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
    if sub(st.extl, FB_TBE) == 0 {
        set16(&mut st.fb_state_lpc_syn, 0, LPC_SHB_ORDER);
        st.fb_tbe_demph = 0;
        fb_tbe_reset_synth(
            &mut st.fbbwe_hpf_mem,
            &mut st.fbbwe_hpf_mem_fx_q,
            &mut st.prev_fbbwe_ratio,
        );
    }
    swb_tbe_reset_synth(
        &mut st.gen_sh_bsynth_hilbert_mem,
        &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local,
    );
}

/// `Inv16(len)` as the step of a linear ramp over `len` samples: the mantissa shifted by its
/// exponent.
fn ramp_step(len: i16) -> i16 {
    let mut exponent: i16 = 15;
    let step = inv16(len, &mut exponent);
    shl(step, exponent)
}

/// The synchronisation of the ACELP / TCX output with the TD-BWE and CLDFB delays, the high
/// band, and the TCX-LTP post-filter. `time_in_e` is the exponent the CLDFB synthesis left.
pub(super) fn transitions(
    st: &mut DecoderState,
    w: &mut FrameWork,
    output_sp: &mut [i16],
    pcm_buf_fb: &[i16],
    time_in_e: i16,
) {
    let output_frame = w.output_frame;
    let frame = output_frame.max(0) as usize;
    let delay_comp = ns2sa_fx2(st.output_fs, DELAY_CLDFB_NS);
    let delay_tdbwe = ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS);
    let dc = delay_comp.max(0) as usize;
    let dt = delay_tdbwe.max(0) as usize;
    let qpostd: i16 = 0;

    // MODE1 MDCT to ACELP 2 transition
    scale_sig(&mut st.delay_buf_out, delay_comp, negate(st.q_old_postdec));
    st.q_old_postdec = 0;
    if sub(output_frame, L_FRAME16K) >= 0 {
        scale_sig(
            &mut st.prev_synth_buffer,
            delay_tdbwe,
            sub(qpostd, st.qprev_synth_buffer),
        );
    }

    if sub(st.last_codec_mode, MODE1) == 0 && sub(st.last_core_bfi, ACELP_CORE) > 0 {
        // copy the HQ/ACELP delay synchronization buffer at the beginning of ACELP frame
        copy_scale_sig(&st.delay_buf_out, output_sp, delay_comp, negate(time_in_e));
        if sub(st.core, ACELP_CORE) == 0 {
            let tmps = ns2sa_fx2(st.output_fs, 3_000_000);
            let nz = ns2sa_fx2(st.output_fs, N_ZERO_MDCT_NS);
            let step = ramp_step(tmps);
            let mut alpha: i16 = 0;
            let (tu, nzu) = (tmps.max(0) as usize, nz.max(0) as usize);

            if st.prev_bfi != 0 && st.hq_voicing != 0 {
                st.old_out[nzu..nzu + tu].copy_from_slice(&st.fer_samples[..tu]);
            } else {
                scale_sig(&mut st.old_out, add(nz, tmps), negate(st.q_old_wtda));
            }
            st.q_old_wtda = 0;

            for i in 0..tu {
                output_sp[i + dc] = msu_r(
                    l_mult(output_sp[i + dc], alpha),
                    shr(st.old_out[i + nzu], time_in_e),
                    add(alpha, -32768),
                );
                alpha = add(alpha, step);
            }
        } else if st.output_fs == 8000 {
            st.fbtc_xdelay_buf[..dc].copy_from_slice(&st.delay_buf_out[..dc]);
        } else {
            st.fbtc_xdelay_buf[..dt].copy_from_slice(&st.prev_synth_buffer[..dt]);
            st.fbtc_xdelay_buf[dt..dt + dc].copy_from_slice(&st.delay_buf_out[..dc]);
        }
    }

    // set delay compensation between HQ synthesis and ACELP synthesis
    if sub(st.core, ACELP_CORE) == 0 && st.con_tcx == 0 {
        set16(&mut st.delay_buf_out, 0, delay_comp);
        copy_scale_sig(output_sp, &mut st.previoussynth, output_frame, time_in_e);
    } else {
        let at = st.old_synth_fb + st.old_synth_len_fb.max(0) as usize - dc;
        st.delay_buf_out[..dc].copy_from_slice(&st.synth_history[at..at + dc]);
        if st.output_fs == 8000 {
            st.previoussynth[..dc].copy_from_slice(&st.fbtc_xdelay_buf[..dc]);
        } else {
            st.previoussynth[..dc].copy_from_slice(&st.fbtc_xdelay_buf[dt..dt + dc]);
        }
        let rest = frame - dc;
        st.previoussynth[dc..dc + rest].copy_from_slice(&pcm_buf_fb[..rest]);
    }

    // Delay compensation for TD-BWE
    if sub(output_frame, L_FRAME16K) >= 0 {
        w.tmp_buffer[..frame].copy_from_slice(&output_sp[..frame]);
        copy_scale_sig(
            &st.prev_synth_buffer,
            output_sp,
            delay_tdbwe,
            negate(time_in_e),
        );
        output_sp[dt..frame].copy_from_slice(&w.tmp_buffer[..frame - dt]);
        copy_scale_sig(
            &w.tmp_buffer[frame - dt..],
            &mut st.prev_synth_buffer,
            delay_tdbwe,
            time_in_e,
        );
    }

    add_high_band(st, w, output_sp, time_in_e);
    align_and_postfilter(st, w, output_sp, pcm_buf_fb, time_in_e);
}

/// TEC / TFA of the TBE high band and its addition to the output of an ACELP frame.
fn add_high_band(st: &mut DecoderState, w: &mut FrameWork, output_sp: &mut [i16], time_in_e: i16) {
    let output_frame = w.output_frame;
    let frame = output_frame.max(0) as usize;
    if st.igf == 0 || sub(st.m_frame_type, ACTIVE_FRAME) != 0 {
        return;
    }
    if st.bfi == 0
        && sub(st.core, ACELP_CORE) == 0
        && (st.tec_flag != 0 || st.tfa_flag != 0)
        && st.output_fs > 8000
    {
        let mut tmp16: i16 = 0;
        if sub(st.tec_flag, 2) == 0 {
            tmp16 = 1;
        }
        w.hb_synth_exp = proc_tec_tfa_tbe(
            &mut w.hb_synth,
            w.hb_synth_exp,
            &mut st.tec_dec.p_gain_temp_m,
            &mut st.tec_dec.p_gain_temp_e,
            st.tfa_flag,
            st.last_core,
            shr(output_frame, 4),
            tmp16,
        );
    }

    if (((st.bfi == 0 || sub(st.last_core, ACELP_CORE) == 0) && sub(st.core, ACELP_CORE) == 0)
        || (sub(st.last_core, ACELP_CORE) == 0
            && sub(st.bwidth, NB) != 0
            && sub(st.last_codec_mode, MODE2) == 0))
        && st.output_fs > 8000
    {
        // the sum is per sample: a copy of the input stands in for the aliased argument
        w.tmp_buffer[..frame].copy_from_slice(&output_sp[..frame]);
        add_vec(
            &w.tmp_buffer,
            negate(time_in_e),
            &w.hb_synth,
            w.hb_synth_exp,
            output_sp,
            negate(time_in_e),
            output_frame,
        );
    }
}

/// The TCX output aligned with the CLDFB / TD-BWE delay, and the TCX-LTP post-filter.
fn align_and_postfilter(
    st: &mut DecoderState,
    w: &mut FrameWork,
    output_sp: &mut [i16],
    pcm_buf_fb: &[i16],
    time_in_e: i16,
) {
    let output_frame = w.output_frame;
    let qpostd: i16 = 0;
    let tmps = if st.output_fs == 8000 {
        ns2sa_fx2(st.output_fs, DELAY_CLDFB_NS)
    } else {
        ns2sa_fx2(st.output_fs, DELAY_BWE_TOTAL_NS)
    };
    let delta = ns2sa_fx2(st.output_fs, TCXLTP_DELAY_NS);
    let (tu, du) = (tmps.max(0) as usize, delta.max(0) as usize);
    let l_frame_tcx = st.l_frame_tcx;

    if (st.bfi != 0 && sub(st.last_core, ACELP_CORE) > 0) || sub(st.core, ACELP_CORE) > 0 {
        if sub(st.last_core_bfi, ACELP_CORE) > 0
            || (st.bfi != 0 && st.last_core > ACELP_CORE)
            || (st.prev_bfi != 0 && st.last_con_tcx != 0)
        {
            copy_scale_sig(&st.fbtc_xdelay_buf, output_sp, tmps, negate(time_in_e));
            copy_scale_sig(
                pcm_buf_fb,
                &mut output_sp[tu..],
                sub(l_frame_tcx, tmps),
                negate(time_in_e),
            );
        } else {
            let step = ramp_step(tmps);
            let mut alpha: i16 = 0;
            for i in 0..tu {
                output_sp[i + tu] = msu_r(
                    l_mult(shr(pcm_buf_fb[i], time_in_e), alpha),
                    output_sp[i + tu],
                    add(alpha, -32768),
                );
                alpha = add(alpha, step);
            }
            copy_scale_sig(
                &pcm_buf_fb[tu..],
                &mut output_sp[2 * tu..],
                sub(l_frame_tcx, shl(tmps, 1)),
                negate(time_in_e),
            );
        }

        let tcx = l_frame_tcx.max(0) as usize;
        st.fbtc_xdelay_buf[..tu].copy_from_slice(&pcm_buf_fb[tcx - tu..tcx]);

        if st.bfi != 0 && sub(st.last_core, ACELP_CORE) > 0 {
            if st.output_fs == 8000 {
                let n = ns2sa(st.output_fs, DELAY_CLDFB_NS).max(0) as usize;
                st.delay_buf_out[..n].copy_from_slice(&st.fbtc_xdelay_buf[..n]);
            } else {
                let tdbwe =
                    ns2sa(st.output_fs, DELAY_BWE_TOTAL_NS - DELAY_CLDFB_NS).max(0) as usize;
                let cldfb = ns2sa(st.output_fs, DELAY_CLDFB_NS).max(0) as usize;
                st.prev_synth_buffer[..tdbwe].copy_from_slice(&st.fbtc_xdelay_buf[..tdbwe]);
                st.delay_buf_out[..cldfb]
                    .copy_from_slice(&st.fbtc_xdelay_buf[tdbwe..tdbwe + cldfb]);
            }
        }
    } else if sub(st.last_codec_mode, MODE2) == 0 && sub(st.last_core, ACELP_CORE) > 0 {
        copy_scale_sig(&st.fbtc_xdelay_buf, output_sp, delta, negate(time_in_e));

        let step = ramp_step(sub(tmps, delta));
        let mut alpha: i16 = 0;
        for i in du..tu {
            output_sp[i] = msu_r(
                l_mult(output_sp[i], alpha),
                shr(st.fbtc_xdelay_buf[i], time_in_e),
                add(alpha, -32768),
            );
            alpha = add(alpha, step);
        }
    }

    let rescale = sub(qpostd, w.qpostd_prev);
    scale_sig(&mut st.tcxltp_mem_in, delta, rescale);
    scale_sig(&mut st.tcxltp_mem_out, output_frame, rescale);

    scale_sig(output_sp, output_frame, time_in_e);

    tcx_ltp_post(
        st.tcxltp,
        st.core,
        st.l_frame_tcx,
        st.l_frame,
        add(ns2sa_fx2(st.output_fs, ACELP_LOOK_NS), tmps),
        output_sp,
        Some(&st.fbtc_xdelay_buf),
        delta,
        st.bfi,
        st.tcxltp_pitch_int,
        st.tcxltp_pitch_fr,
        st.tcxltp_gain,
        &mut st.tcxltp_pitch_int_post_prev,
        &mut st.tcxltp_pitch_fr_post_prev,
        &mut st.tcxltp_gain_post_prev,
        &mut st.tcxltp_filt_idx_prev,
        st.pit_res_max,
        &mut st.pit_res_max_past,
        st.damping,
        i16::from(st.total_brate >= 96000),
        &mut st.tcxltp_mem_in,
        &mut st.tcxltp_mem_out,
        st.total_brate,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ramp_step_is_the_reciprocal_of_the_length() {
        // 1/40 in Q15
        assert_eq!(ramp_step(40), 819);
        assert_eq!(ramp_step(20), 1638);
    }
}
