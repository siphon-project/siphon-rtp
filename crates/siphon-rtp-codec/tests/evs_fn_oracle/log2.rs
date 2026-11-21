//! `basic_math/log2.c` against `fn_log2`.

use siphon_rtp_codec::evs::com::log2::log2_norm_lc;

use crate::common::{corpus, mismatch};

#[test]
fn log2_norm_lc_matches_the_reference() {
    let Some(cases) = corpus("log2", "log2_norm_lc") else {
        return;
    };
    for case in &cases {
        let y = log2_norm_lc(case.i32("x"));
        if let Some(message) = mismatch(case, "y", &y, &case.out_i16("y")) {
            panic!("{message}");
        }
    }
}
