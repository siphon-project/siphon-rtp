//! `lib_com/residu_fx.c` against `fn_residu`.

use siphon_rtp_codec::evs::com::residu::{residu3, residu3_lc};

use crate::common::{corpus, mismatch};

#[test]
fn residu3_matches_the_reference() {
    let Some(cases) = corpus("residu", "residu3") else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let lg = case.i16("lg");
        let mut y = vec![0; lg as usize];
        residu3(&case.i16s("a"), &x, 16, &mut y, lg, case.i16("shift"));
        if let Some(message) = mismatch(case, "y", &y, &case.out_i16s("y")) {
            panic!("{message}");
        }
    }
}

#[test]
fn residu3_lc_matches_the_reference() {
    let Some(cases) = corpus("residu", "residu3_lc") else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let mut y = vec![0; x.len()];
        residu3_lc(
            &case.i16s("a"),
            case.i16("m"),
            &x,
            &mut y,
            case.i16("lg"),
            case.i16("shift"),
        );
        if let Some(message) = mismatch(case, "y", &y, &case.out_i16s("y")) {
            panic!("{message}");
        }
    }
}
