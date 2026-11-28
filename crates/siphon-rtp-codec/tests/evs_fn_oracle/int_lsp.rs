//! `lib_com/int_lsp_fx.c` (`int_lsp4_fx`, `int_lsp_fx`) against `fn_int_lsp`.

use siphon_rtp_codec::evs::com::int_lsp::{int_lsp, int_lsp4};

use crate::common::{corpus, mismatch};

#[test]
fn int_lsp4_matches_the_reference() {
    let Some(cases) = corpus("int_lsp", "int_lsp4") else {
        return;
    };
    for case in &cases {
        let mut aq = vec![-5i16; 5 * 17];
        int_lsp4(
            case.i16("l_frame"),
            &case.i16s("old"),
            &case.i16s("mid"),
            &case.i16s("new"),
            &mut aq,
            16,
            case.i16("relax"),
        );
        if let Some(message) = mismatch(case, "aq", &aq, &case.out_i16s("aq")) {
            panic!("{message}");
        }
    }
}

#[test]
fn int_lsp_matches_the_reference() {
    let Some(cases) = corpus("int_lsp", "int_lsp") else {
        return;
    };
    for case in &cases {
        let mut aq = vec![-5i16; 5 * 17];
        int_lsp(
            case.i16("l_frame"),
            &case.i16s("old"),
            &case.i16s("new"),
            &mut aq,
            16,
            &case.i16s("coeffs"),
            case.i16("amr"),
        );
        if let Some(message) = mismatch(case, "aq", &aq, &case.out_i16s("aq")) {
            panic!("{message}");
        }
    }
}
