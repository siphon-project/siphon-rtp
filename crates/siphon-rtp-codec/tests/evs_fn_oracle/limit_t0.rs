//! `lib_com/limit_t0_fx.c` against `fn_limit_t0`.

use siphon_rtp_codec::evs::com::limit_t0::limit_t0;

use crate::common::{corpus, mismatch};

#[test]
fn limit_t0_matches_the_reference() {
    let Some(cases) = corpus("limit_t0", "limit_t0") else {
        return;
    };
    for case in &cases {
        let (t0_min, t0_max) = limit_t0(
            case.i16("l_frame"),
            case.i16("delta"),
            case.i16("pit_flag"),
            case.i16("limit_flag"),
            case.i16("t0"),
            case.i16("t0_frac"),
        );
        let reference = (case.out_i16("t0_min"), case.out_i16("t0_max"));
        if let Some(message) = mismatch(case, "t0_min/t0_max", &(t0_min, t0_max), &reference) {
            panic!("{message}");
        }
    }
}
