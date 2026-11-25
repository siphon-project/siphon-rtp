//! `lib_com/tcx_mdct.c` and `edst_fx` against `fn_m2tcx_mdct`. The two scale-factor helpers are
//! proven through the transforms, which reach every branch (160, 320, 640 and the general case).

use siphon_rtp_codec::evs::com::edct::{edst, edst_in_place};
use siphon_rtp_codec::evs::com::tcx_mdct::{tcx_mdct, tcx_mdct_inverse, tcx_mdst};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn edst_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_mdct", "edst") else {
        return;
    };
    for case in &cases {
        let length = case.i16("length");
        let mut q = case.i16("q");
        let mut x = case.i32s("x");
        let y = if case.i16("in_place") == 1 {
            edst_in_place(&mut x, length, &mut q);
            x
        } else {
            let mut y = vec![0i32; length as usize];
            edst(&x, &mut y, length, &mut q);
            y
        };
        check(case, "y", &y, &case.out_i32s("y"));
        check(case, "q", &q, &case.out_i16("q"));
    }
}

fn forward(function: &str, transform: fn(&[i16], &mut [i32], &mut i16, i16, i16, i16)) {
    let Some(cases) = corpus("m2tcx_mdct", function) else {
        return;
    };
    for case in &cases {
        let (l, m, r) = (case.i16("l"), case.i16("m"), case.i16("r"));
        let length = (l / 2 + m + r / 2) as usize;
        let mut y_e = case.i16("y_e");
        let mut y = vec![0i32; length];
        transform(&case.i16s("x"), &mut y, &mut y_e, l, m, r);
        check(case, "y", &y, &case.out_i32s("y"));
        check(case, "y_e", &y_e, &case.out_i16("y_e"));
    }
}

#[test]
fn tcx_mdct_matches_the_reference() {
    forward("TCX_MDCT", tcx_mdct);
}

#[test]
fn tcx_mdst_matches_the_reference() {
    forward("TCX_MDST", tcx_mdst);
}

#[test]
fn tcx_mdct_inverse_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_mdct", "TCX_MDCT_Inverse") else {
        return;
    };
    for case in &cases {
        let (l, m, r) = (case.i16("l"), case.i16("m"), case.i16("r"));
        let x = case.i32s("x");
        let mut y = vec![0i16; (l + m + r) as usize];
        tcx_mdct_inverse(&x, case.i16("x_e"), &mut y, l, m, r);
        check(case, "y", &y, &case.out_i16s("y"));
        check(case, "x", &x, &case.out_i32s("x"));
    }
}
