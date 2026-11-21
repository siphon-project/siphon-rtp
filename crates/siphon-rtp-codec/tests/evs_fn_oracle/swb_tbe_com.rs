//! `lib_com/swb_tbe_com_fx.c` against `fn_swb_tbe_com`. `non_linearity_scaled_copy` (static in
//! the reference) is proven through `non_linearity_fx`, which takes both of its `en_abs` branches;
//! `interp_code_4over2_fx` through `prep_tbe_exc_fx` at `L_frame` 320.

use siphon_rtp_codec::evs::com::swb_tbe_com::{
    calc_rc0_h, interp_code_5over2, non_linearity, prep_tbe_exc, tbe_celp_exc, tbe_celp_exc_offset,
};

use crate::common::{corpus, mismatch};

/// The history the oracle puts before the subframe (`HISTORY` in `fn/swb_tbe_com.c`).
const HISTORY: usize = 700;

#[test]
fn tbe_celp_exc_offset_matches_the_reference() {
    let Some(cases) = corpus("swb_tbe_com", "tbe_celp_exc_offset") else {
        return;
    };
    for case in &cases {
        let offset = tbe_celp_exc_offset(case.i16("t0"), case.i16("t0_frac"), case.i16("l_frame"));
        if let Some(message) = mismatch(case, "offset", &offset, &case.out_i16("offset")) {
            panic!("{message}");
        }
    }
}

#[test]
fn tbe_celp_exc_matches_the_reference() {
    let Some(cases) = corpus("swb_tbe_com", "tbe_celp_exc") else {
        return;
    };
    for case in &cases {
        let mut bwe_exc = case.i16s("bwe_exc");
        let mut error = case.i16("error");
        tbe_celp_exc(
            case.i16("l_frame"),
            case.i16("i_subfr"),
            case.i16("t0"),
            case.i16("t0_frac"),
            &mut error,
            &mut bwe_exc,
            HISTORY,
        );
        if let Some(message) = mismatch(case, "error", &error, &case.out_i16("error"))
            .or_else(|| mismatch(case, "bwe_exc", &bwe_exc, &case.out_i16s("bwe_exc")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn calc_rc0_h_matches_the_reference() {
    let Some(cases) = corpus("swb_tbe_com", "calc_rc0_h") else {
        return;
    };
    for case in &cases {
        let mut rc0 = -99;
        calc_rc0_h(&case.i16s("h"), &mut rc0);
        if let Some(message) = mismatch(case, "rc0", &rc0, &case.out_i16("rc0")) {
            panic!("{message}");
        }
    }
}

#[test]
fn interp_code_5over2_matches_the_reference() {
    let Some(cases) = corpus("swb_tbe_com", "interp_code_5over2") else {
        return;
    };
    for case in &cases {
        let mut out = [0_i16; 160];
        interp_code_5over2(&case.i16s("inp"), &mut out, 64);
        if let Some(message) = mismatch(case, "out", &out.to_vec(), &case.out_i16s("out")) {
            panic!("{message}");
        }
    }
}

#[test]
fn non_linearity_matches_the_reference() {
    let Some(cases) = corpus("swb_tbe_com", "non_linearity") else {
        return;
    };
    for case in &cases {
        let input = case.i16s("input");
        let mut output = vec![0_i32; input.len()];
        let mut prev_scale = case.i32("prev_scale");
        non_linearity(
            &input,
            &mut output,
            input.len() as i16,
            &mut prev_scale,
            case.i16("q_inp"),
            case.i16("coder_type"),
            &case.i16s("voice_factors"),
            case.i16("l_frame"),
        );
        if let Some(message) = mismatch(case, "output", &output, &case.out_i32s("output"))
            .or_else(|| mismatch(case, "prev_scale", &prev_scale, &case.out_i32("prev_scale")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn prep_tbe_exc_matches_the_reference() {
    let Some(cases) = corpus("swb_tbe_com", "prep_tbe_exc") else {
        return;
    };
    for case in &cases {
        let mut bwe_exc = case.i16s("bwe_exc");
        let mut voice_factors = -99;
        prep_tbe_exc(
            case.i16("l_frame"),
            case.i16("i_subfr"),
            case.i16("gain_pit"),
            case.i32("gain_code"),
            &case.i16s("code"),
            case.i16("voice_fac"),
            &mut voice_factors,
            &mut bwe_exc,
            case.i16("gain_pre_q"),
            &case.i16s("code_pre_q"),
            case.i16("q_exc"),
            case.i16("t0"),
            case.i16("t0_frac"),
            case.i16("coder_type"),
            case.i32("core_brate"),
        );
        if let Some(message) = mismatch(
            case,
            "voice_factors",
            &voice_factors,
            &case.out_i16("voice_factors"),
        )
        .or_else(|| mismatch(case, "bwe_exc", &bwe_exc, &case.out_i16s("bwe_exc")))
        {
            panic!("{message}");
        }
    }
}
