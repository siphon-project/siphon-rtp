//! `lib_dec/FEC_adapt_codebook_fx.c` and `lib_com/findpulse_fx.c` against `fn_FEC_adapt_codebook`.

use siphon_rtp_codec::evs::com::findpulse::findpulse;
use siphon_rtp_codec::evs::dec::fec_adapt_codebook::{fec_enh_acb, fec_sin_onset, fec_synchro_exc};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn findpulse_matches_the_reference() {
    let Some(cases) = corpus("FEC_adapt_codebook", "findpulse") else {
        return;
    };
    for case in &cases {
        let mut sign = case.i16("sign");
        let r = findpulse(
            case.i16("L_frame"),
            &case.i16s("res"),
            case.i16("T0"),
            case.i16("enc"),
            &mut sign,
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "sign", &sign, &case.out_i16("sign"));
    }
}

#[test]
fn fec_sin_onset_matches_the_reference() {
    let Some(cases) = corpus("FEC_adapt_codebook", "sin_onset") else {
        return;
    };
    for case in &cases {
        let mut exc = vec![-12345i16; 320];
        let q = fec_sin_onset(
            &mut exc,
            case.i16("puls_pos"),
            case.i16("T0"),
            case.i32("enr_q"),
            &case.i16s("Aq"),
            case.i16("L_frame"),
            case.i16("Qold"),
        );
        check(case, "q", &q, &case.out_i16("q"));
        // at L_FRAME the reference copies 64 samples of its own stack before the window: not compared
        let skip = if case.i16("L_frame") == 256 { 64 } else { 0 };
        check(
            case,
            "exc",
            &exc[skip..].to_vec(),
            &case.out_i16s("exc")[skip..].to_vec(),
        );
    }
}

#[test]
fn fec_enh_acb_matches_the_reference() {
    let Some(cases) = corpus("FEC_adapt_codebook", "enh_acb") else {
        return;
    };
    let mut resynchronised = 0;
    for case in &cases {
        let mut exc_io = case.i16s("exc_io");
        let r = fec_enh_acb(
            case.i16("L_frame"),
            case.i16("last_L_frame"),
            &mut exc_io,
            case.i16("new_pit"),
            case.i16("puls_pos"),
            case.i16("bfi_pitch"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "exc_io", &exc_io, &case.out_i16s("exc_io"));
        resynchronised += i32::from(r);
    }
    assert!(resynchronised > 20, "only {resynchronised} resynchronised");
}

#[test]
fn fec_synchro_exc_matches_the_reference() {
    let Some(cases) = corpus("FEC_adapt_codebook", "synchro_exc") else {
        return;
    };
    let mut modified = 0;
    for case in &cases {
        let mut exc = case.i16s("exc");
        let r = fec_synchro_exc(
            case.i16("L_frame"),
            &mut exc,
            case.i16("desire"),
            case.i16("true_pos"),
            case.i16("old_pitch"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "exc", &exc, &case.out_i16s("exc"));
        modified += i32::from(r);
    }
    assert!(modified > 100, "only {modified} modified");
}
