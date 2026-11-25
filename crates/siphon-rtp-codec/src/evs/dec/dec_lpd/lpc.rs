//! The LPC part of `decoder_LPD`: the LSFs / LSPs of a good frame (ACELP, TCX with or without the
//! TCX LPC codebook, the channel-aware partial copy), their concealment for a lost frame, and
//! the rate switching reset.

use super::{Lpd, RF_GENPRED};
use crate::evs::cnst::{
    ACELP_CORE, AUDIO, GENERIC, LSF_GAP_FX, M, RF_TCXFD, RF_TCXTD2, TCX_10_CORE, TCX_20_CORE,
    UNVOICED,
};
use crate::evs::com::dlpc_bfi::dlpc_bfi;
use crate::evs::com::lpc_tools::e_lpc_lsp_unweight;
use crate::evs::com::lsf_dec_bfi::plc_get_lsf_base;
use crate::evs::com::lsf_tools::{
    e_lpc_f_lsp_a_conversion, e_lpc_lsf_lsp_conversion, lsf2lsp, lsf_update_memory, reorder_lsf,
    tcxlpc_get_cdk,
};
use crate::evs::com::v_sort::v_sort;
use crate::evs::dec::dlpc_stoch::lpc_unquantize;
use crate::evs::dec::lsf_msvq_ma_dec::d_lsf_tcxlpc;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::vlpc_1st_dec::vlpc_1st_dec;
use crate::evs::rom::LSF_Q_DIFF_CB_8B_RF;
use crate::itu::basic_ops::{abs_s, add, l_add, l_sub, mult_r, shr, sub};

const MU: usize = M as usize;

/// The LSFs / LSPs of the frame: `lsf` / `lsp` hold the old set, then the `numlpc` new ones, and
/// `xspnew_uw` / `xsfnew_uw` the unweighted new ones.
pub(super) fn decode_lpc(st: &mut DecoderState, w: &mut Lpd, coder_type: i16, param: &[i16]) {
    let param_lpc = &param[super::PARAM_LPC_AT..];
    let partial_copy_tcx =
        w.bfi != 0 && st.use_partial_copy != 0 && sub(st.rf_frame_type, RF_TCXFD) == 0;
    if w.bfi == 0 || partial_copy_tcx {
        if sub(st.use_partial_copy, 1) == 0
            && (sub(st.rf_frame_type, RF_TCXFD) < 0 || sub(st.rf_frame_type, RF_TCXTD2) > 0)
        {
            lpc_partial_copy(st, w, param_lpc);
        } else if (st.enable_tcx_lpc != 0 && sub(st.core, ACELP_CORE) != 0) || partial_copy_tcx {
            lpc_tcx(st, w, coder_type, param_lpc, partial_copy_tcx);
        } else {
            lpc_unquantized(st, w, coder_type, param_lpc);
        }

        // PLC: [LPD: LPC concealment]; built the moving average for the LPC concealment
        const THIRD: i16 = 10923; // 1.0f/3.0f Q15
        for k in 0..st.numlpc.max(0) as usize {
            for i in 0..MU {
                st.lsf_adaptive_mean[i] = add(
                    add(
                        mult_r(st.lsfoldbfi1[i], THIRD),
                        mult_r(st.lsfoldbfi0[i], THIRD),
                    ),
                    mult_r(w.xsfnew_uw[k * MU + i], THIRD),
                );
                st.lsfoldbfi1[i] = st.lsfoldbfi0[i];
                st.lsfoldbfi0[i] = w.xsfnew_uw[k * MU + i];
            }
        }
    } else {
        lpc_conceal(st, w);
    }

    // Rate switching
    if st.rate_switching_reset != 0 {
        let (old, new) = w.lsf.split_at_mut(MU);
        old.copy_from_slice(&new[..MU]);
        st.lsf_old.copy_from_slice(&new[..MU]);
        w.lsfmid.copy_from_slice(&new[..MU]);
        let (old, new) = w.lsp.split_at_mut(MU);
        old.copy_from_slice(&new[..MU]);
        st.lsp_old.copy_from_slice(&new[..MU]);
        w.lspmid.copy_from_slice(&new[..MU]);
        e_lpc_f_lsp_a_conversion(&st.lsp_old, &mut st.old_aq_12_8, M);
    }

    if st.enable_plc_waveadjust != 0 {
        if sub(st.core, ACELP_CORE) == 0 {
            st.tonality_flag = 0;
        }
        if w.bfi != 0 {
            st.plc_info.nb_lost_cmpt += 1;
        }
    }
}

/// The channel-aware partial copy of an ACELP frame: the LSFs from the first stage and a refined
/// second stage of the TCX high rate codebook.
fn lpc_partial_copy(st: &mut DecoderState, w: &mut Lpd, param_lpc: &[i16]) {
    if st.env_weighted == 1 {
        st.lsp_old = st.lspold_uw;
        st.lsf_old = st.lsfold_uw;
        st.env_weighted = 0;
    }

    // first stage VQ, 8 bits; reuse TCX high rate codebook
    let mut lsf_q_1st_rf = [0i16; MU];
    vlpc_1st_dec(param_lpc[0], &mut lsf_q_1st_rf);

    // second stage vq: quantized lsf from two stages
    let mut lsf_q_rf = [0i16; MU];
    // the second stage index is 8 bits, so the row is inside the 256 row table
    let row = usize::try_from(param_lpc[1]).unwrap_or(0) * MU;
    for i in 0..MU {
        // tmp = unquantized lsf difference (2nd VQ) in Q6
        let mut tmp = LSF_Q_DIFF_CB_8B_RF.get(row + i).copied().unwrap_or(0);
        // bring tmp to Qx2.56 for addition
        tmp = shr(mult_r(tmp, 20972), 4);
        lsf_q_rf[i] = add(lsf_q_1st_rf[i], tmp);
    }

    v_sort(&mut lsf_q_rf, 0, M - 1);
    reorder_lsf(&mut lsf_q_rf, LSF_GAP_FX, M, st.sr_core);

    // current n-th ACELP frame and its corresponding partial copy
    let mut lsp_q_rf = [0i16; MU];
    e_lpc_lsf_lsp_conversion(&lsf_q_rf, &mut lsp_q_rf, M);

    // copy the old and current lsfs and lsps into the lsf[] and lsp[] buffer for interpolation
    w.lsf[..MU].copy_from_slice(&st.lsf_old);
    w.lsp[..MU].copy_from_slice(&st.lsp_old);
    w.lsf[MU..2 * MU].copy_from_slice(&lsf_q_rf);
    w.lsp[MU..2 * MU].copy_from_slice(&lsp_q_rf);
    let mut lsp_diff: i32 = 0;
    for i in 0..MU {
        lsp_diff = l_add(lsp_diff, i32::from(abs_s(sub(w.lsp[i + MU], w.lsp[i]))));
    }

    if sub(st.core, ACELP_CORE) == 0
        && sub(st.last_core, ACELP_CORE) == 0
        && l_sub(lsp_diff, 52428) < 0
        && l_sub(lsp_diff, 3932) > 0
        && sub(st.next_coder_type, GENERIC) == 0
        && st.prev_use_partial_copy == 0
        && sub(st.last_coder_type, UNVOICED) == 0
        && sub(st.rf_frame_type, RF_GENPRED) >= 0
    {
        let (old, new) = w.lsp.split_at_mut(MU);
        new[..MU].copy_from_slice(old);
    }

    // update mem_MA and mem_AR memories
    let old_mem_ma = st.mem_ma;
    lsf_update_memory(
        i16::from(st.narrow_band),
        &w.lsf[MU..2 * MU],
        &old_mem_ma,
        &mut st.mem_ma,
        M,
    );
    st.mem_ar.copy_from_slice(&w.lsf[MU..2 * MU]);

    copy_new_sets(st, w);
}

/// `xspnew_uw[k]` / `xsfnew_uw[k]` from the new LSP / LSF set `k + 1`.
fn copy_new_sets(st: &DecoderState, w: &mut Lpd) {
    for k in 0..st.numlpc.max(0) as usize {
        w.xspnew_uw[k * MU..(k + 1) * MU].copy_from_slice(&w.lsp[(k + 1) * MU..(k + 2) * MU]);
        w.xsfnew_uw[k * MU..(k + 1) * MU].copy_from_slice(&w.lsf[(k + 1) * MU..(k + 2) * MU]);
    }
}

/// The LPC of a TCX frame through the TCX LPC codebook (`enableTcxLpc`), or of the RF TCX partial
/// copy.
fn lpc_tcx(
    st: &mut DecoderState,
    w: &mut Lpd,
    coder_type: i16,
    param_lpc: &[i16],
    partial_copy_tcx: bool,
) {
    let tcx_lpc_cdk = if partial_copy_tcx {
        tcxlpc_get_cdk(GENERIC)
    } else {
        tcxlpc_get_cdk(coder_type) // inlined
    };

    w.lsf[..MU].copy_from_slice(&st.lsf_old);
    w.lsp[..MU].copy_from_slice(&st.lsp_old);

    let mem_ma = st.mem_ma;
    d_lsf_tcxlpc(
        param_lpc,
        &mut w.lsf[MU..2 * MU],
        Some(&mut w.lspind),
        i16::from(st.narrow_band),
        tcx_lpc_cdk,
        &mem_ma,
    );

    let new_lsf: [i16; MU] = w.lsf[MU..2 * MU].try_into().unwrap_or([0; MU]);
    e_lpc_lsf_lsp_conversion(&new_lsf, &mut w.lsp[MU..2 * MU], M);

    lsf_update_memory(
        i16::from(st.narrow_band),
        &new_lsf,
        &mem_ma,
        &mut st.mem_ma,
        M,
    );
    st.mem_ar.copy_from_slice(&new_lsf);

    st.env_weighted = 1;

    let new_lsp: [i16; MU] = w.lsp[MU..2 * MU].try_into().unwrap_or([0; MU]);
    e_lpc_lsp_unweight(
        &new_lsp,
        &mut w.xspnew_uw[..MU],
        &mut w.xsfnew_uw[..MU],
        st.inv_gamma,
        M,
    );
}

/// The LPC of an ACELP or TCX frame whose LSFs are quantized without the TCX LPC codebook.
fn lpc_unquantized(st: &mut DecoderState, w: &mut Lpd, coder_type: i16, param_lpc: &[i16]) {
    if st.env_weighted != 0 {
        st.lsp_old = st.lspold_uw;
        st.lsf_old = st.lsfold_uw;
        st.env_weighted = 0;
    }
    let lsf_old = st.lsf_old;
    let lsp_old = st.lsp_old;
    let numlpc = st.numlpc;
    let core = st.core;
    let midlpc = i16::from(st.acelp_cfg.mid_lpc);
    let mut lspmid = w.lspmid;
    let mut lsfmid = w.lsfmid;
    let mut lsf_q_prediction = w.lsf_q_prediction;
    if sub(core, TCX_20_CORE) == 0 {
        lpc_unquantize(
            st,
            &lsf_old,
            &lsp_old,
            &mut w.lsf,
            &mut w.lsp,
            M,
            st.lpc_quantization,
            param_lpc,
            numlpc,
            core,
            &mut lspmid,
            &mut lsfmid,
            AUDIO,
            midlpc,
            st.narrow_band,
            st.sr_core,
            st.prev_bfi,
            &mut lsf_q_prediction,
        );
    } else {
        lpc_unquantize(
            st,
            &lsf_old,
            &lsp_old,
            &mut w.lsf,
            &mut w.lsp,
            M,
            st.lpc_quantization,
            param_lpc,
            numlpc,
            core,
            &mut lspmid,
            &mut lsfmid,
            coder_type,
            midlpc,
            st.narrow_band,
            st.sr_core,
            st.prev_bfi,
            &mut lsf_q_prediction,
        );
        if sub(st.prev_use_partial_copy, 1) == 0
            && sub(st.last_core, ACELP_CORE) == 0
            && sub(core, ACELP_CORE) == 0
            && sub(st.prev_rf_frame_type, RF_GENPRED) >= 0
            && sub(coder_type, UNVOICED) == 0
            && st.lpc_quantization != 0
            && midlpc != 0
        {
            w.lsp[..MU].copy_from_slice(&lspmid);
            lspmid.copy_from_slice(&w.lsp[MU..2 * MU]);
        }
    }
    w.lspmid = lspmid;
    w.lsfmid = lsfmid;
    w.lsf_q_prediction = lsf_q_prediction;

    copy_new_sets(st, w);
}

/// PLC: [LPD: LPC concealment]: the LSFs of a lost frame.
fn lpc_conceal(st: &mut DecoderState, w: &mut Lpd) {
    st.numlpc = 2;
    if st.tcxonly == 0 || sub(st.core, TCX_10_CORE) < 0 {
        st.numlpc = 1;
    }
    if sub(st.nb_lost_cmpt, 1) == 0 {
        st.old_lsf_q_cng = st.lsf_old;
        st.old_lsp_q_cng = st.lsp_old;
    }
    let xsf_base = plc_get_lsf_base(st.lpc_quantization, i16::from(st.narrow_band), st.sr_core);

    let lsfold_uw = st.lsfold_uw;
    let lsf_adaptive_mean = st.lsf_adaptive_mean;
    let lsf_cng = st.lsf_cng;
    let old_lsf_q_cng = st.old_lsf_q_cng;
    let mut lsf_q_cng = st.lsf_q_cng;
    dlpc_bfi(
        st.l_frame,
        &mut w.xsfnew_uw,
        &lsfold_uw,
        st.last_good,
        st.nb_lost_cmpt,
        &mut st.mem_ma,
        &mut st.mem_ar,
        st.stab_fac,
        &lsf_adaptive_mean,
        st.numlpc,
        Some(&lsf_cng),
        st.plc_background_noise_updated,
        Some(&mut lsf_q_cng),
        Some(&old_lsf_q_cng),
        Some(xsf_base),
        st.tcxonly,
    );
    st.lsf_q_cng = lsf_q_cng;

    st.env_weighted = 0;

    w.lsp[..MU].copy_from_slice(&st.lspold_uw);
    w.lsf[..MU].copy_from_slice(&st.lsfold_uw);

    for k in 0..st.numlpc.max(0) as usize {
        let new = &mut w.lsf[(k + 1) * MU..(k + 2) * MU];
        new.copy_from_slice(&w.xsfnew_uw[k * MU..(k + 1) * MU]);
        let new_lsf: [i16; MU] = (&*new).try_into().unwrap_or([0; MU]);

        if st.tcxonly != 0 {
            e_lpc_lsf_lsp_conversion(&new_lsf, &mut w.lsp[(k + 1) * MU..(k + 2) * MU], M);
            let lsf_q_cng = st.lsf_q_cng;
            e_lpc_lsf_lsp_conversion(&lsf_q_cng, &mut st.lsp_q_cng, M);
        } else {
            lsf2lsp(
                &new_lsf,
                &mut w.lsp[(k + 1) * MU..(k + 2) * MU],
                M,
                st.sr_core,
            );
            let lsf_q_cng = st.lsf_q_cng;
            lsf2lsp(&lsf_q_cng, &mut st.lsp_q_cng, M, st.sr_core);
        }

        w.xspnew_uw[k * MU..(k + 1) * MU].copy_from_slice(&w.lsp[(k + 1) * MU..(k + 2) * MU]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_sets_land_in_the_unweighted_buffers() {
        let mut st = DecoderState::zeroed();
        st.numlpc = 2;
        let mut w = super::super::tests::work();
        for (i, value) in w.lsp.iter_mut().enumerate() {
            *value = i as i16;
        }
        for (i, value) in w.lsf.iter_mut().enumerate() {
            *value = 100 + i as i16;
        }
        copy_new_sets(&st, &mut w);
        assert_eq!(w.xspnew_uw[0], 16);
        assert_eq!(w.xspnew_uw[super::super::XSP_LEN - 1], 47);
        assert_eq!(w.xsfnew_uw[0], 116);
    }
}
