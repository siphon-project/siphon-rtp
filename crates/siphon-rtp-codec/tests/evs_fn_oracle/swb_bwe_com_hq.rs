//! The HQ-core functions of `lib_com/swb_bwe_com_fx.c` against `fn_swb_bwe_com_hq`:
//! `calc_normal_length_fx_32` and `hq_generic_decoding_fx` (HQ GENERIC in SWB and FB frames).
//! `calc_norm_envelop_fx_32` has no caller in the reference and is not ported.

use siphon_rtp_codec::evs::com::swb_bwe_com::{calc_normal_length_32, hq_generic_decoding};

use crate::common::{corpus, mismatch};

#[test]
fn calc_normal_length_32_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com_hq", "calc_normal_length_32") else {
        return;
    };
    for case in &cases {
        let mut norm = -1;
        let mut prev = case.i16("prev");
        calc_normal_length_32(
            case.i16("core"),
            &case.i32s("sp"),
            case.i16("mode"),
            case.i16("extl"),
            &mut norm,
            &mut prev,
        );
        if let Some(message) = [
            mismatch(case, "norm", &norm, &case.out_i16("norm")),
            mismatch(case, "prev", &prev, &case.out_i16("prev")),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            panic!("{message}");
        }
    }
}

#[test]
fn hq_generic_decoding_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com_hq", "hq_generic_decoding") else {
        return;
    };
    for case in &cases {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut prev = case.i16("prev");
        let mut out = case.i32s("out");
        let mut out1 = case.i32s("out1");
        hq_generic_decoding(
            case.i16("hqswb_clas"),
            &mut out1,
            &case.i16s("fenv"),
            &mut out,
            case.i16("offset"),
            &mut prev,
            case.i16("exc"),
            &case.i16s("r"),
        );
        if let Some(message) = [
            mismatch(case, "prev", &prev, &case.out_i16("prev")),
            mismatch(case, "out", &out, &case.out_i32s("out")),
            mismatch(case, "out1", &out1, &case.out_i32s("out1")),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            panic!("{message}");
        }
    }
}
