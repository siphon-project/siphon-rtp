//! MODE2 LPC dequantisation front end (TS 26.442 `lib_dec/dlpc_stoch.c`; TS 26.445 §6.1.1.1).

use crate::evs::cnst::{
    ACELP_CORE, AUDIO, GENERIC, INT_FS_16K, LSF_GAP_MID_FX, M, TCX_20_CORE, UNVOICED,
};
use crate::evs::com::lsf_msvq_ma::midlsf_dec;
use crate::evs::com::lsf_tools::{e_lpc_lsf_lsp_conversion, lsf2lsp, reorder_lsf};
use crate::evs::dec::dlpc_avq::dlpc_avq;
use crate::evs::dec::lsf_dec::lsf_end_dec;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::extract_l;
use crate::itu::basic_ops::{l_sub, shr, sub};
use crate::itu::stl2009::l_mac0;

/// `lpc_unquantize`: dequantise the LPCs of a MODE2 frame from `param_lpc` into `lsf` / `lsp`
/// (`(numlpc + 1)·m` values: the previous frame's `lsfold` / `lspold` first, then one set per
/// LPC), and the ACELP mid-frame LPC into `lsfmid` / `lspmid`.
///
/// `lpc_quantization` 0 is the variable-rate algebraic quantiser (`dlpc_avq`), 1 the
/// multi-stage MA / AR one (`lsf_end_dec` in MODE2). `lsf_q_prediction` receives the predictor the
/// latter used. Also sets the ACELP random seed `st.seed_acelp` from the parameters.
///
/// The reference's `mem_MA`, `mem_AR`, `seed_acelp`, `mid_lsf_int` and `safety_net` arguments are
/// pointers to fields of `st` at its only call site (`dec_LPD`); they are `st.mem_ma`,
/// `st.mem_ar`, `st.seed_acelp`, `st.mid_lsf_int` and `st.safety_net` here, since the borrow of `st`
/// cannot also be held through them.
pub fn lpc_unquantize(
    st: &mut DecoderState,
    lsfold: &[i16],
    lspold: &[i16],
    lsf: &mut [i16],
    lsp: &mut [i16],
    m: i16,
    lpc_quantization: i16,
    param_lpc: &[i16],
    numlpc: i16,
    core: i16,
    lspmid: &mut [i16],
    lsfmid: &mut [i16],
    coder_type: i16,
    acelp_mid_lpc: i16,
    narrow_band: i8,
    sr_core: i32,
    prev_bfi: i16,
    lsf_q_prediction: &mut i16,
) {
    let mu = m.max(0) as usize;
    let mut nb_indices: i16 = 0;

    lsf[..mu].copy_from_slice(&lsfold[..mu]);
    lsp[..mu].copy_from_slice(&lspold[..mu]);

    if lpc_quantization == 0 {
        nb_indices = dlpc_avq(param_lpc, &mut lsf[mu..], numlpc, st.sr_core);
        for k in 0..numlpc.max(0) as usize {
            let (from, to) = ((k + 1) * mu, (k + 2) * mu);
            e_lpc_lsf_lsp_conversion(&lsf[from..to], &mut lsp[from..to], m);
        }
    } else if sub(lpc_quantization, 1) == 0 {
        let coder = if l_sub(sr_core, i32::from(INT_FS_16K)) == 0 && sub(coder_type, UNVOICED) == 0
        {
            GENERIC
        } else if sub(st.core, TCX_20_CORE) == 0 {
            AUDIO
        } else {
            coder_type
        };
        let mut safety_net = st.safety_net;
        let core_brate = st.core_brate;
        lsf_end_dec(
            st,
            1,
            coder,
            sub(1, i16::from(narrow_band)),
            31,
            &mut lsf[mu..],
            sr_core,
            core_brate,
            &mut safety_net,
            param_lpc,
            lsf_q_prediction,
            Some(&mut nb_indices),
        );
        st.safety_net = safety_net;

        let (head, tail) = (mu, 2 * mu);
        lsf2lsp(&lsf[head..tail], &mut lsp[head..tail], M, sr_core);
    }
    // any other quantiser is the reference's `assert(0)`

    st.seed_acelp = 0;
    for i in (0..nb_indices.max(0) as usize).rev() {
        st.seed_acelp = extract_l(l_mac0(
            l_mac0(13849, shr(st.seed_acelp, 1), 31821),
            param_lpc[i],
            31821,
        ));
    }

    // Decoded mid-frame isf
    if lpc_quantization != 0
        && acelp_mid_lpc != 0
        && core == ACELP_CORE
        && st.rate_switching_reset == 0
    {
        let mid_index = param_lpc
            .get(nb_indices.max(0) as usize)
            .copied()
            .unwrap_or(0);
        let mut mid_lsf_int = st.mid_lsf_int;
        midlsf_dec(
            &lsf[..mu],
            &lsf[mu..2 * mu],
            mid_index,
            lsfmid,
            coder_type,
            Some(&mut mid_lsf_int),
            prev_bfi,
            st.safety_net,
        );
        st.mid_lsf_int = mid_lsf_int;
        reorder_lsf(lsfmid, LSF_GAP_MID_FX, M, sr_core);
        lsf2lsp(lsfmid, lspmid, M, sr_core);
    }
}
