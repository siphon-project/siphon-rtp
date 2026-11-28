//! `lib_com/weight_a_fx.c` against `fn_weight_a`. The template every module here follows.

use siphon_rtp_codec::evs::com::weight_a::{weight_a, weight_a_lc};

use crate::common::{corpus, mismatch};

#[test]
fn weight_a_matches_the_reference() {
    let Some(cases) = corpus("weight_a", "weight_a") else {
        return;
    };
    for case in &cases {
        let a = case.i16s("a");
        let mut ap = vec![0; a.len()];
        weight_a(&a, &mut ap, case.i16("gamma"), case.i16("m"));
        if let Some(message) = mismatch(case, "ap", &ap, &case.out_i16s("ap")) {
            panic!("{message}");
        }
    }
}

#[test]
fn weight_a_lc_matches_the_reference() {
    let Some(cases) = corpus("weight_a", "weight_a_lc") else {
        return;
    };
    for case in &cases {
        let a = case.i16s("a");
        let mut ap = vec![0; a.len()];
        weight_a_lc(&a, &mut ap, &case.i16s("gammatbl"), case.i16("m"));
        if let Some(message) = mismatch(case, "ap", &ap, &case.out_i16s("ap")) {
            panic!("{message}");
        }
    }
}
