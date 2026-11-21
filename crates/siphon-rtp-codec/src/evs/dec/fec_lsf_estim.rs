//! LSP conversion and interpolation of the concealed LSFs of a lost frame (TS 26.442
//! `lib_dec/FEC_lsf_estim_fx.c`; TS 26.447 §5.4.2.1).

use crate::evs::cnst::{INT_FS_16K_FX, INT_FS_FX, L_FRAME, M};
use crate::evs::com::int_lsp::int_lsp;
use crate::evs::com::lsf_tools::{e_lpc_isf_isp_conversion, lsf2lsp};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{INTERPOL_FRAC_FX, INTERPOL_ISP_AMR_WB_FX};
use crate::itu::basic_ops::sub;

/// `FEC_lsf2lsp_interp`: the LSPs `lsp` of the concealed LSFs `lsf` (ISPs in AMR-WB IO mode), and
/// the LP coefficients `aq` of every subframe interpolated from `st.lsp_old` to them.
pub fn fec_lsf2lsp_interp(
    st: &mut DecoderState,
    l_frame: i16,
    aq: &mut [i16],
    lsf: &[i16],
    lsp: &mut [i16],
) {
    // convert LSFs to LSPs
    if st.opt_amr_wb != 0 {
        e_lpc_isf_isp_conversion(lsf, lsp, M);
    } else if sub(l_frame, L_FRAME) == 0 {
        lsf2lsp(lsf, lsp, M, i32::from(INT_FS_FX));
    } else {
        // L_frame == L_FRAME16k
        lsf2lsp(lsf, lsp, M, i32::from(INT_FS_16K_FX));
    }

    // Interpolate LSP vector and find A(z)
    if st.opt_amr_wb != 0 {
        int_lsp(l_frame, &st.lsp_old, lsp, aq, M, &INTERPOL_ISP_AMR_WB_FX, 1);
    } else {
        int_lsp(l_frame, &st.lsp_old, lsp, aq, M, &INTERPOL_FRAC_FX, 0);
    }
}
