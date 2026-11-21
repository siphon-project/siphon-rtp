//! `lib_com/lsp_conv_poly_fx.c` against `fn_lsp_conv_poly`. The statics (`powerspect_fx`,
//! `b_inv_sq`, `inv_pow`, `spectautocorr_fx`, `zeros2poly_fx`, `polydecomp_fx`, `cheb2poly_fx`) are
//! proven through `lsp_convert_poly_fx`.

use siphon_rtp_codec::evs::com::lsp_conv_poly::lsp_convert_poly;

use crate::common::{corpus, mismatch};

#[test]
fn lsp_convert_poly_matches_the_reference() {
    let Some(cases) = corpus("lsp_conv_poly", "lsp_convert_poly") else {
        return;
    };
    for case in &cases {
        let mut w = case.i16s("w");
        let flag = lsp_convert_poly(&mut w, case.i16("l_frame"), case.i16("opt_amrwb"));
        if let Some(message) = mismatch(case, "w", &w, &case.out_i16s("w"))
            .or_else(|| mismatch(case, "flag", &flag, &case.out_i16("flag")))
        {
            panic!("{message}");
        }
    }
}
