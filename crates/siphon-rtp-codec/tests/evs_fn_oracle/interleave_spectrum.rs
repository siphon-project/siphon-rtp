//! `lib_com/interleave_spectrum_fx.c` against `fn_interleave_spectrum`: both directions over the
//! 16, 32 and 48 kHz layouts, the whole 960-coefficient buffer compared.

use siphon_rtp_codec::evs::com::interleave_spectrum::{
    de_interleave_spectrum, interleave_spectrum,
};

use crate::common::{corpus, mismatch};

#[test]
fn interleave_spectrum_matches_the_reference() {
    let Some(cases) = corpus("interleave_spectrum", "interleave_spectrum") else {
        return;
    };
    for case in &cases {
        let mut coefs = case.i32s("coefs");
        interleave_spectrum(&mut coefs, case.i16("length"));
        if let Some(message) = mismatch(case, "coefs", &coefs, &case.out_i32s("coefs")) {
            panic!("{message}");
        }
    }
}

#[test]
fn de_interleave_spectrum_matches_the_reference() {
    let Some(cases) = corpus("interleave_spectrum", "de_interleave_spectrum") else {
        return;
    };
    for case in &cases {
        let mut coefs = case.i32s("coefs");
        de_interleave_spectrum(&mut coefs, case.i16("length"));
        if let Some(message) = mismatch(case, "coefs", &coefs, &case.out_i32s("coefs")) {
            panic!("{message}");
        }
    }
}
