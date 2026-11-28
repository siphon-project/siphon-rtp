//! `basic_math/math_32.c` against `fn_math_32`.

use siphon_rtp_codec::evs::basop::{mult_32_16, mult_32_32};

use crate::common::{corpus, mismatch};

#[test]
fn mult_32_16_matches_the_reference() {
    let Some(cases) = corpus("math_32", "mult_32_16") else {
        return;
    };
    for case in &cases {
        let y = mult_32_16(case.i32("a"), case.i16("b"));
        if let Some(message) = mismatch(case, "y", &y, &case.out_i32("y")) {
            panic!("{message}");
        }
    }
}

#[test]
fn mult_32_32_matches_the_reference() {
    let Some(cases) = corpus("math_32", "mult_32_32") else {
        return;
    };
    for case in &cases {
        let y = mult_32_32(case.i32("a"), case.i32("b"));
        if let Some(message) = mismatch(case, "y", &y, &case.out_i32("y")) {
            panic!("{message}");
        }
    }
}
