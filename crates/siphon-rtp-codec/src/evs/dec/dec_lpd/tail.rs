//! The end of `decoder_LPD`: the frame classification, the memory updates for the next frame,
//! the CNG parameters and the post-filter.

use super::Lpd;
use crate::evs::cnst::{
    ACELP_CORE, DEC, INACTIVE_CLAS, INT_FS_FX, L_EXC_MEM_DEC, L_FRAME, L_LP, L_SUBFR, M,
    MAX_POST_LEN, NB, NB_SUBFR16K, N_ZERO_MDCT_NS, PH_ECU_LOOKAHEAD_NS, PH_ECU_MEM_NS, TCX_10_CORE,
    TCX_20_CORE, UNVOICED_CLAS, VOICED_TRANSITION,
};
use crate::evs::com::basop_util::imult1616;
use crate::evs::com::cng_exc::cng_params_upd;
use crate::evs::com::enr_1_az::enr_1_az;
use crate::evs::com::frame_ener::frame_ener;
use crate::evs::com::lag_wind::{lag_wind, LAGW_WEAK};
use crate::evs::com::lpc_tools::{autocorr, e_lpc_lev_dur};
use crate::evs::com::lsf_tools::e_lpc_a_lsp_conversion;
use crate::evs::com::preemph::e_util_f_preemph3;
use crate::evs::com::residu::residu3;
use crate::evs::com::tools::copy_scale_sig;
use crate::evs::dec::fec_clas_estim::fec_clas_estim;
use crate::evs::dec::post_dec::post_decoder;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::waveadjust_fec_dec::set_state;
use crate::evs::macros::ns2sa_fx2;
use crate::evs::rom::ASSYM_WINDOW_W16FX;
use crate::itu::basic_ops::{add, l_sub, negate, round_word, shl, shr, sub};

const MU: usize = M as usize;

/// The class estimation, the memory updates and the post-filter that close `decoder_LPD`.
pub(super) fn finish(
    st: &mut DecoderState,
    w: &mut Lpd,
    coder_type: i16,
    signal_out: &mut [i16],
    signal_out_fb: &mut [i16],
) {
    let bfi = w.bfi;
    classify(st, w);

    // END
    if bfi != 0 && sub(st.last_core_bfi, ACELP_CORE) != 0 {
        // Update FEC_scale_syn parameters
        let l_frame = st.l_frame;
        let synth = &w.synth_buf[w.synth_at..];
        if st.tcxltp_gain == 0 {
            frame_ener(
                l_frame,
                UNVOICED_CLAS,
                synth,
                shr(l_frame, 1),
                &mut st.enr_old,
                l_frame,
                0,
                0,
                0,
            );
        } else {
            let pitch_q0 = round_word(st.old_fpitch);
            frame_ener(
                l_frame,
                st.clas_dec,
                synth,
                pitch_q0,
                &mut st.enr_old,
                l_frame,
                0,
                0,
                0,
            );
        }
    }

    if bfi == 0 && sub(st.clas_dec, VOICED_TRANSITION) >= 0 && sub(st.clas_dec, INACTIVE_CLAS) < 0 {
        let offset = if sub(st.core, ACELP_CORE) == 0 {
            imult1616(sub(st.nb_subfr, 1), add(M, 1))
        } else {
            0
        };
        // use latest LPC set; Q3
        st.old_enr_lp = enr_1_az(&w.aq[offset.max(0) as usize..], L_SUBFR);
    }

    update_memories(st, w);
    update_cng(st, w);

    st.last_is_cng = 0;

    // Postfiltering
    let mut bpf_noise_buf = st.bpf_noise_buf;
    post_decoder(
        st,
        coder_type,
        &mut w.synth_buf,
        &w.pit_gain,
        &w.pitch,
        signal_out,
        &mut bpf_noise_buf,
    );
    st.bpf_noise_buf = bpf_noise_buf;

    let l_frame_tcx = st.l_frame_tcx.max(0) as usize;
    let synth_fb_at = w.synth_fb_at;
    signal_out_fb[..l_frame_tcx]
        .copy_from_slice(&w.synth_buf_fb[synth_fb_at..synth_fb_at + l_frame_tcx]);

    if st.enable_plc_waveadjust != 0 {
        if bfi == 0 {
            st.plc_info.nb_lost_cmpt = 0;
        }
        if st.core == 0 {
            set_state(&mut st.plc_info.transient, st.core, MAX_POST_LEN);
        }
    }
}

/// PLC: [Common: Classification].
fn classify(st: &mut DecoderState, w: &mut Lpd) {
    if l_sub(st.sr_core, 16000) > 0 {
        return;
    }
    if sub(st.core, TCX_20_CORE) == 0
        || sub(st.core, TCX_10_CORE) == 0
        || (st.tcxonly != 0 && st.bfi != 0)
    {
        let mut pitch_c = [0i16; NB_SUBFR16K as usize];
        pitch_c.fill(shl(round_word(st.old_fpitch), 6));

        let mut core_ext_mode = crate::evs::cnst::GENERIC;
        if st.tcxonly == 0 {
            core_ext_mode = st.core_ext_mode;
        }

        let mut ltp_gain: i16 = -32768; // -1.0f Q15
        if st.tcxltp != 0 {
            ltp_gain = st.tcxltp_last_gain_unmodified;
        }

        fec_clas_estim(
            st,
            0,
            st.l_frame,
            core_ext_mode,
            &pitch_c,
            &w.synth_buf,
            w.synth_at,
            None,
            None,
            0,
            0,
            None,
            ltp_gain,
            1, // CLASSIFIER_TCX
            w.bfi,
            st.last_core_brate,
        );
    }
}

/// The synthesis, LSP and LSF memories of the next frame.
fn update_memories(st: &mut DecoderState, w: &mut Lpd) {
    let l_frame = st.l_frame.max(0) as usize;
    let l_frame_tcx = st.l_frame_tcx.max(0) as usize;
    let old_synth_len = st.old_synth_len.max(0) as usize;
    let old_synth_len_fb = st.old_synth_len_fb.max(0) as usize;

    // Update
    st.old_synth[..old_synth_len].copy_from_slice(&w.synth_buf[l_frame..l_frame + old_synth_len]);

    let fb = st.old_synth_fb;
    let mem = ns2sa_fx2(st.output_fs, PH_ECU_MEM_NS).max(0) as usize;
    st.synth_history
        .copy_within(fb + l_frame_tcx - mem..fb + l_frame_tcx, 0);
    st.synth_history[fb..fb + old_synth_len_fb]
        .copy_from_slice(&w.synth_buf_fb[l_frame_tcx..l_frame_tcx + old_synth_len_fb]);
    copy_scale_sig(
        &st.old_out[ns2sa_fx2(st.output_fs, N_ZERO_MDCT_NS).max(0) as usize..],
        &mut st.synth_history[fb + old_synth_len_fb..],
        ns2sa_fx2(st.output_fs, PH_ECU_LOOKAHEAD_NS),
        negate(st.q_old_wtda),
    );

    let last = (st.numlpc.max(1) as usize - 1) * MU;
    st.lspold_uw.copy_from_slice(&w.xspnew_uw[last..last + MU]);
    st.lsfold_uw.copy_from_slice(&w.xsfnew_uw[last..last + MU]);

    if w.bfi != 0 {
        st.lsp_old = st.lspold_uw; // for recovery
        st.lsf_old = st.lsfold_uw; // for recovery
    } else {
        let at = st.numlpc.max(0) as usize * MU;
        st.lsp_old.copy_from_slice(&w.lsp[at..at + MU]);
        st.lsf_old.copy_from_slice(&w.lsf[at..at + MU]);
    }
    st.old_lsp_q_cng = st.lsp_q_cng;
    st.old_lsf_q_cng = st.lsf_q_cng;
}

/// Update the LP-CNG parameters in active frames.
fn update_cng(st: &mut DecoderState, w: &mut Lpd) {
    if st.tcxonly != 0 {
        return;
    }
    if sub(st.bwidth, NB) == 0 && st.enable_tcx_lpc != 0 && sub(st.core, ACELP_CORE) != 0 {
        let mut buf = [0i16; L_LP as usize];
        let mut res = [0i16; L_FRAME as usize];
        let mut a = [0i16; MU + 1];
        let mut r_l = [0i16; MU + 1];
        let mut r_h = [0i16; MU + 1];
        let mut lsptmp = [0i16; MU];
        let mut q_r: i16 = 0;
        // `synth + L_FRAME - L_LP` reaches before the frame, into the past synthesis
        let lp = L_LP as usize;
        let frame = L_FRAME as usize;
        let from = w.synth_at + frame - lp;

        buf.copy_from_slice(&w.synth_buf[from..from + lp]);
        let mut tmp = w.synth_buf[from - 1];
        let qexc = e_util_f_preemph3(&mut buf, st.preemph_fac, L_LP, &mut tmp, 1);
        autocorr(
            &buf,
            M,
            &mut r_h,
            &mut r_l,
            &mut q_r,
            L_LP,
            &ASSYM_WINDOW_W16FX,
            0,
            0,
        );
        lag_wind(&mut r_h, &mut r_l, M, i32::from(INT_FS_FX), LAGW_WEAK);
        e_lpc_lev_dur(&r_h, &r_l, &mut a, None, M, None);
        let xsp0: [i16; MU] = w.xspnew_uw[..MU].try_into().unwrap_or([0; MU]);
        e_lpc_a_lsp_conversion(&a, &mut lsptmp, &xsp0, M);
        residu3(&a, &buf, lp - frame, &mut res, L_FRAME, 1);
        cng_params_upd(
            &lsptmp,
            &res,
            st.l_frame,
            &mut st.ho_circ_ptr,
            &mut st.ho_ener_circ,
            &mut st.ho_circ_size,
            &mut st.ho_lsp_circ,
            qexc,
            DEC,
            &mut st.ho_env_circ,
            &mut 0,
            &mut [],
            &mut [],
            &mut [],
            st.last_active_brate,
        );
    } else {
        let lsp_new: [i16; MU] = w.lsp[MU..2 * MU].try_into().unwrap_or([0; MU]);
        let at = L_EXC_MEM_DEC as usize - st.l_frame.max(0) as usize;
        cng_params_upd(
            &lsp_new,
            &st.old_exc[at..],
            st.l_frame,
            &mut st.ho_circ_ptr,
            &mut st.ho_ener_circ,
            &mut st.ho_circ_size,
            &mut st.ho_lsp_circ,
            st.q_exc,
            DEC,
            &mut st.ho_env_circ,
            &mut 0,
            &mut [],
            &mut [],
            &mut [],
            st.last_active_brate,
        );
    }

    // Set 16k LSP flag for CNG buffer
    st.ho_16k_lsp[st.ho_circ_ptr as usize] = 1;
    if sub(st.l_frame, L_FRAME) == 0 {
        st.ho_16k_lsp[st.ho_circ_ptr as usize] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memories_of_the_next_frame_follow_a_good_frame() {
        let mut st = Box::new(DecoderState::zeroed());
        st.l_frame = 256;
        st.l_frame_tcx = 256;
        st.old_synth_len = 8;
        st.old_synth_len_fb = 8;
        st.numlpc = 1;
        st.output_fs = 16000;
        st.lsp_q_cng[0] = 42;
        st.lsf_q_cng[0] = 43;
        let mut w = super::super::tests::work();
        w.synth_buf[256..264].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        w.lsp[16..32].copy_from_slice(&[9; 16]);
        w.lsf[16..32].copy_from_slice(&[10; 16]);
        w.xspnew_uw[..16].copy_from_slice(&[11; 16]);
        update_memories(&mut st, &mut w);
        assert_eq!(st.old_synth[..8], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(st.lsp_old, [9; 16]);
        assert_eq!(st.lsf_old, [10; 16]);
        assert_eq!(st.lspold_uw, [11; 16]);
        assert_eq!((st.old_lsp_q_cng[0], st.old_lsf_q_cng[0]), (42, 43));
    }

    #[test]
    fn a_lost_frame_recovers_from_the_unweighted_old_lsps() {
        let mut st = Box::new(DecoderState::zeroed());
        st.l_frame = 256;
        st.l_frame_tcx = 256;
        st.numlpc = 1;
        st.output_fs = 16000;
        let mut w = super::super::tests::work();
        w.bfi = 1;
        w.xspnew_uw[..16].copy_from_slice(&[11; 16]);
        w.lsp[16..32].copy_from_slice(&[9; 16]);
        update_memories(&mut st, &mut w);
        assert_eq!(st.lsp_old, [11; 16]);
    }

    #[test]
    fn the_cng_parameters_are_left_alone_for_a_tcx_only_stream() {
        let mut st = Box::new(DecoderState::zeroed());
        st.tcxonly = 1;
        st.ho_circ_ptr = 3;
        let mut w = super::super::tests::work();
        update_cng(&mut st, &mut w);
        assert_eq!(st.ho_circ_ptr, 3);
    }
}
