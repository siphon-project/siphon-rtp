//! `lib_dec/re8_dec_fx.c` against `fn_re8_dec`.
//!
//! `re8_decode_base_index_fx` (`lib_dec/lead_deindexing_fx.c`), `re8_k2y_fx`
//! (`lib_com/re8_util_fx.c`) and `re8_PPV_fx` (`lib_com/re8_ppv_fx.c`) are reached only through
//! `re8_dec_fx` and are proven through it, over every codebook number the AVQ demultiplexer can
//! produce.

use siphon_rtp_codec::evs::dec::re8_dec::re8_dec;

use crate::common::{corpus, mismatch};

#[test]
fn re8_dec_matches_the_reference() {
    let Some(cases) = corpus("re8_dec", "re8_dec") else {
        return;
    };
    for case in &cases {
        let mut y = [0_i16; 8];
        re8_dec(case.i16("n"), case.i32("i") as u16, &case.i16s("k"), &mut y);
        if let Some(message) = mismatch(case, "y", &y.to_vec(), &case.out_i16s("y")) {
            panic!("{message}");
        }
    }
}
