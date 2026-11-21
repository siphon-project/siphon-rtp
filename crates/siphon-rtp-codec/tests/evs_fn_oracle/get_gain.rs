//! `lib_com/get_gain.c` against `fn_get_gain`.

use siphon_rtp_codec::evs::com::get_gain::get_gain;
use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus, mismatch};

#[test]
fn get_gain_matches_the_reference() {
    let Some(cases) = corpus("get_gain", "get_gain") else {
        return;
    };
    for case in &cases {
        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        let gain = get_gain(&case.i16s("x"), &case.i16s("y"), case.i16("n"), &mut flags);
        if let Some(message) = mismatch(case, "gain", &gain, &case.out_i32("gain")).or_else(|| {
            mismatch(
                case,
                "carry",
                &i16::from(flags.carry),
                &case.out_i16("carry"),
            )
        }) {
            panic!("{message}");
        }
    }
}
