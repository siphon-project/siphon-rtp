//! `lib_com/tcx_ltp.c` against `fn_tcx_ltp`. `tcx_ltp_post` runs three consecutive frames per
//! case, through every transition (the parameter change with its zero-input response included)
//! and the pitch rescaling between core and output rates.

use siphon_rtp_codec::evs::com::tcx_ltp::{
    tcx_ltp_get_lpc, tcx_ltp_get_zir, tcx_ltp_post, tcx_ltp_synth_filter,
};

use crate::common::{corpus, mismatch};

fn check<T: PartialEq + std::fmt::Debug>(
    case: &crate::common::Case,
    name: &str,
    rust: &T,
    reference: &T,
) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn tcx_ltp_synth_filter_matches_the_reference() {
    let Some(cases) = corpus("tcx_ltp", "synth_filter") else {
        return;
    };
    for case in &cases {
        let mut out = case.i16s("out");
        let input = case.i16s("in");
        let zir = case.i16s("zir");
        tcx_ltp_synth_filter(
            &mut out,
            960,
            &input,
            12,
            case.i16("length"),
            case.i16("pitch_int"),
            case.i16("pitch_fr"),
            case.i16("gain"),
            case.i16("pitres"),
            (case.i16("with_zir") != 0).then_some(&zir[..]),
            case.i16("fade"),
            case.i16("filt_idx"),
        );
        check(case, "out", &out, &case.out_i16s("out"));
    }
}

#[test]
fn tcx_ltp_get_zir_matches_the_reference() {
    let Some(cases) = corpus("tcx_ltp", "get_zir") else {
        return;
    };
    for case in &cases {
        let length = case.i16("length");
        let mut zir = vec![0i16; length as usize];
        tcx_ltp_get_zir(
            &mut zir,
            length,
            &case.i16s("out"),
            960 - 24,
            &case.i16s("in"),
            12 + 100 - 24,
            &case.i16s("A"),
            24,
            case.i16("gain"),
            case.i16("pitch_int"),
            case.i16("pitch_fr"),
            case.i16("pitres"),
            case.i16("filt_idx"),
        );
        check(case, "zir", &zir, &case.out_i16s("zir"));
    }
}

#[test]
fn tcx_ltp_post_matches_the_reference() {
    let Some(cases) = corpus("tcx_ltp", "post") else {
        return;
    };
    for case in &cases {
        let l_frame = case.i16("L_frame");
        let pitres = case.i16("pitres");
        let mut pitch_int_past = case.i16("pitch_int_past");
        let mut pitch_fr_past = case.i16("pitch_fr_past");
        let mut gain_past = case.i16("gain_past");
        let mut filt_idx_past = case.i16("filt_idx_past");
        let mut pitres_past = pitres;
        let mut mem_in = case.i16s("mem_in");
        let mut mem_out = case.i16s("mem_out");
        for f in 0..3 {
            let get = |name: &str| case.i16(&format!("{name}{f}"));
            let mut sig = case.i16s(&format!("sig{f}"));
            let tcx_buf = case.i16s(&format!("tcx_buf{f}"));
            tcx_ltp_post(
                case.i16("tcxltp_on") as i8,
                get("core"),
                l_frame,
                case.i16("L_frame_core"),
                get("delay"),
                &mut sig,
                Some(&tcx_buf),
                case.i16("tcx_buf_len"),
                get("bfi"),
                get("pitch_int"),
                get("pitch_fr"),
                get("gain"),
                &mut pitch_int_past,
                &mut pitch_fr_past,
                &mut gain_past,
                &mut filt_idx_past,
                pitres,
                &mut pitres_past,
                get("damping"),
                get("side_info_only"),
                &mut mem_in,
                &mut mem_out,
                case.i32("bitrate"),
            );
            let name = format!("sig{f}");
            check(case, &name, &sig, &case.out_i16s(&name));
        }
        for (name, rust) in [
            ("pitch_int_past", pitch_int_past),
            ("pitch_fr_past", pitch_fr_past),
            ("gain_past", gain_past),
            ("filt_idx_past", filt_idx_past),
            ("pitres_past", pitres_past),
        ] {
            check(case, name, &rust, &case.out_i16(name));
        }
        check(case, "mem_in", &mem_in, &case.out_i16s("mem_in"));
        check(case, "mem_out", &mem_out, &case.out_i16s("mem_out"));
    }
}

#[test]
fn tcx_ltp_get_lpc_matches_the_reference() {
    let Some(cases) = corpus("tcx_ltp", "get_lpc") else {
        return;
    };
    for case in &cases {
        let mut a = vec![0i16; 25];
        tcx_ltp_get_lpc(&case.i16s("x"), case.i16("L"), &mut a, 24);
        check(case, "A", &a, &case.out_i16s("A"));
    }
}
