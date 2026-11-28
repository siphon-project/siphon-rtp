//! `lib_com/range_com_fx.c` against `fn_range_com`.

use siphon_rtp_codec::evs::com::range_com::range_coder_finalization_f_bits;

use crate::common::{corpus, mismatch};

#[test]
fn range_coder_finalization_f_bits_matches_the_reference() {
    let Some(cases) = corpus("range_com", "fbits") else {
        return;
    };
    for case in &cases {
        let int_rc = case.inputs["int_rc"][0] as u32;
        let rust = range_coder_finalization_f_bits(case.i16("brc"), int_rc);
        if let Some(message) = mismatch(case, "fbits", &rust, &case.out_i16("fbits")) {
            panic!("{message}");
        }
    }
}
