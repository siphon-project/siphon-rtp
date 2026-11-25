//! The TCX-side LPC helpers of `lib_com/lpc_tools_fx.c` against `fn_m2tcx_lpc`.

use siphon_rtp_codec::evs::com::lpc_tools::{
    e_lpc_a_add_tilt, e_lpc_int_lpc_tcx, e_lpc_lsp_unweight, e_lpc_schur,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn e_lpc_schur_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_lpc", "E_LPC_schur") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut r = case.i32s("r");
        let mut refl = vec![0x5555i16; m as usize];
        let mut eps_p = vec![0x5555_5555i32; m as usize + 1];
        let g = e_lpc_schur(&mut r, &mut refl, &mut eps_p, m);
        check(case, "g", &g, &case.out_i32("g"));
        check(case, "r", &r, &case.out_i32s("r"));
        check(case, "refl", &refl, &case.out_i16s("refl"));
        check(case, "eps_p", &eps_p, &case.out_i32s("eps_p"));
    }
}

#[test]
fn e_lpc_lsp_unweight_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_lpc", "E_LPC_lsp_unweight") else {
        return;
    };
    for case in &cases {
        let (mut lsp_uw, mut lsf_uw) = ([0x5555i16; 16], [0x5555i16; 16]);
        let r = e_lpc_lsp_unweight(
            &case.i16s("lsp_w"),
            &mut lsp_uw,
            &mut lsf_uw,
            case.i16("inv_gamma"),
            16,
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "lsp_uw", &lsp_uw.to_vec(), &case.out_i16s("lsp_uw"));
        check(case, "lsf_uw", &lsf_uw.to_vec(), &case.out_i16s("lsf_uw"));
    }
}

#[test]
fn e_lpc_a_add_tilt_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_lpc", "E_LPC_a_add_tilt") else {
        return;
    };
    for case in &cases {
        let mut ap = [0x5555i16; 18];
        e_lpc_a_add_tilt(&case.i16s("a"), &mut ap, case.i16("gamma"), 16);
        check(case, "ap", &ap.to_vec(), &case.out_i16s("ap"));
    }
}

#[test]
fn e_lpc_int_lpc_tcx_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_lpc", "E_LPC_int_lpc_tcx") else {
        return;
    };
    for case in &cases {
        let mut a = [0x5555i16; 17];
        e_lpc_int_lpc_tcx(&case.i16s("lsp_old"), &case.i16s("lsp_new"), &mut a);
        check(case, "a", &a.to_vec(), &case.out_i16s("a"));
    }
}
