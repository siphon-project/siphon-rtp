//! `tcx_hm_modify_envelope`, `tcx_hm_decode` and `tcx_arith_scale_envelope` against
//! `fn_m2arith_env`.

use siphon_rtp_codec::evs::com::ari_hm::envelope::tcx_hm_modify_envelope;
use siphon_rtp_codec::evs::com::arith_coder::envelope::tcx_arith_scale_envelope;
use siphon_rtp_codec::evs::dec::ari_hm_dec::decode::tcx_hm_decode;

use crate::common::{corpus_sized, mismatch};

#[test]
fn tcx_hm_modify_envelope_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_env", "modify", 3000) else {
        return;
    };
    let mut changed = 0;
    for case in &cases {
        let mut env = case.i32s("env");
        let before = env.clone();
        tcx_hm_modify_envelope(
            case.i16("gain"),
            case.i32("lag"),
            case.i16("fract_res"),
            &case.i16s("p"),
            &mut env,
            case.i16("l_frame"),
        );
        changed += usize::from(env != before);
        if let Some(message) = mismatch(case, "env", &env, &case.out_i32s("env")) {
            panic!("{message}");
        }
    }
    assert!(
        changed > 1000,
        "too few cases changed the envelope: {changed}"
    );
}

#[test]
fn tcx_hm_decode_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_env", "decode", 3000) else {
        return;
    };
    let (mut errors, mut changed) = (0, 0);
    for case in &cases {
        let mut env = case.i32s("env");
        let before = env.clone();
        let mut hm_bits = 55;
        tcx_hm_decode(
            case.i16("l_frame"),
            &mut env,
            case.i16("target_bits"),
            case.i16("coder_type"),
            &case.i16s("prm_hm"),
            case.i16("ltp_lag"),
            &mut hm_bits,
        );
        errors += usize::from(hm_bits < 0);
        changed += usize::from(env != before);
        if let Some(message) = mismatch(case, "hm_bits", &hm_bits, &case.out_i16("hm_bits")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "env", &env, &case.out_i32s("env")) {
            panic!("{message}");
        }
    }
    assert!(
        errors > 100 && changed > 1000,
        "errors {errors}, changed {changed}"
    );
}

/// The scaled envelope lands in the half-words of `env` (the reference's `(Word16 *)env`), so the
/// whole 32-bit buffer is compared.
#[test]
fn tcx_arith_scale_envelope_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_env", "scale", 3000) else {
        return;
    };
    for case in &cases {
        let mut env = case.i32s("env");
        let mut e = 0;
        tcx_arith_scale_envelope(
            case.i16("l_spec"),
            case.i16("core"),
            &mut env,
            case.i16("target_bits"),
            case.i16("low_complexity"),
            &mut e,
        );
        if let Some(message) = mismatch(case, "e", &e, &case.out_i16("e")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "env", &env, &case.out_i32s("env")) {
            panic!("{message}");
        }
    }
}
