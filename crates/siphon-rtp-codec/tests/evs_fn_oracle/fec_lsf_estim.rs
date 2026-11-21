//! `lib_dec/FEC_lsf_estim_fx.c` (`FEC_lsf2lsp_interp`) against `fn_FEC_lsf_estim`.

use siphon_rtp_codec::evs::dec::fec_lsf_estim::fec_lsf2lsp_interp;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn fec_lsf2lsp_interp_matches_the_reference() {
    let Some(cases) = corpus("FEC_lsf_estim", "fec_lsf2lsp_interp") else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        st.opt_amr_wb = case.i16("opt_amr_wb");
        st.lsp_old.copy_from_slice(&case.i16s("lsp_old"));
        let mut aq = vec![-5i16; 5 * 17];
        let mut lsp = vec![0i16; 16];
        fec_lsf2lsp_interp(
            &mut st,
            case.i16("l_frame"),
            &mut aq,
            &case.i16s("lsf"),
            &mut lsp,
        );
        if let Some(message) = mismatch(case, "aq", &aq, &case.out_i16s("aq")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "lsp", &lsp, &case.out_i16s("lsp")) {
            panic!("{message}");
        }
    }
}
