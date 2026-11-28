//! `lib_com/edct_fx.c` against `fn_edct`. `get_edct_table` is proven through `edct_fx` at every
//! length it has a table for; half the cases run in place, as `tcx_mdct.c` and `gs_dec_fx.c` call
//! them. `edct_16fx` covers all three lengths it has a table for: 256, 320 and 640.

use siphon_rtp_codec::evs::com::edct::{
    edct, edct_16fx, edct_16fx_in_place, edct_in_place, iedct_short,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn edct_matches_the_reference() {
    let Some(cases) = corpus("edct", "edct") else {
        return;
    };
    for case in &cases {
        let length = case.i16("length");
        let mut q = case.i16("q");
        let mut x = case.i32s("x");
        let y = if case.i16("in_place") == 1 {
            edct_in_place(&mut x, length, &mut q);
            x
        } else {
            let mut y = vec![0i32; length as usize];
            edct(&x, &mut y, length, &mut q);
            y
        };
        check(case, "y", &y, &case.out_i32s("y"));
        check(case, "q", &q, &case.out_i16("q"));
    }
}

#[test]
fn edct_16fx_matches_the_reference() {
    let Some(cases) = corpus("edct", "edct_16fx") else {
        return;
    };
    for case in &cases {
        let (length, bh) = (case.i16("length"), case.i16("bh"));
        let mut x = case.i16s("x");
        let y = if case.i16("in_place") == 1 {
            edct_16fx_in_place(&mut x, length, bh);
            x
        } else {
            let mut y = vec![0i16; length as usize];
            edct_16fx(&x, &mut y, length, bh);
            y
        };
        check(case, "y", &y, &case.out_i16s("y"));
    }
}

#[test]
fn iedct_short_matches_the_reference() {
    let Some(cases) = corpus("edct", "iedct_short") else {
        return;
    };
    for case in &cases {
        let segment_length = case.i16("segment_length");
        let mut q = case.i16("q");
        let mut out = vec![0i32; segment_length as usize];
        iedct_short(&case.i32s("in"), &mut q, &mut out, segment_length);
        check(case, "out", &out, &case.out_i32s("out"));
        check(case, "q", &q, &case.out_i16("q"));
    }
}
