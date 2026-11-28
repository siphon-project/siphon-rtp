//! `lib_com/trans_direct_fx.c` against `fn_trans_direct` (long and four-block transient MDCT).

use siphon_rtp_codec::evs::com::trans_direct::direct_transform;

use crate::common::{corpus, mismatch};

#[test]
fn direct_transform_matches_the_reference() {
    let Some(cases) = corpus("trans_direct", "direct_transform") else {
        return;
    };
    for case in &cases {
        let input = case.i32s("in");
        let mut out = vec![0x5555_5555; input.len()];
        let mut q = case.i16("q");
        direct_transform(
            &input,
            &mut out,
            case.i16("is_transient"),
            case.i16("l"),
            &mut q,
        );
        let rust = (out, q);
        let reference = (case.out_i32s("out"), case.out_i16("q"));
        if let Some(message) = mismatch(case, "out/q", &rust, &reference) {
            panic!("{message}");
        }
    }
}
