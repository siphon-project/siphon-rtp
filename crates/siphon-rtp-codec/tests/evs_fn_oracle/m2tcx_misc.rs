//! The small helpers of the MODE2 TCX bundle against `fn_m2tcx_misc`: `ISqrt16`, `getCosWord16`,
//! `ham_cos_window`, `get_gain2` and `E_LPC_a_weight_inv`.

use siphon_rtp_codec::evs::com::basop_util::{get_cos_word16, isqrt16};
use siphon_rtp_codec::evs::com::get_gain::get_gain2;
use siphon_rtp_codec::evs::com::weight_a::e_lpc_a_weight_inv;
use siphon_rtp_codec::evs::com::window::ham_cos_window;
use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn isqrt16_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_misc", "ISqrt16") else {
        return;
    };
    for case in &cases {
        let mut exponent = case.i16("exponent");
        let r = isqrt16(case.i16("mantissa"), &mut exponent);
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "exponent", &exponent, &case.out_i16("exponent"));
    }
}

#[test]
fn get_cos_word16_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_misc", "getCosWord16") else {
        return;
    };
    for case in &cases {
        check(
            case,
            "r",
            &get_cos_word16(case.i16("theta")),
            &case.out_i16("r"),
        );
    }
}

#[test]
fn ham_cos_window_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_misc", "ham_cos_window") else {
        return;
    };
    for case in &cases {
        let (n1, n2) = (case.i16("n1"), case.i16("n2"));
        let mut fh = vec![0i16; (n1 + n2) as usize];
        ham_cos_window(&mut fh, n1, n2);
        check(case, "fh", &fh, &case.out_i16s("fh"));
    }
}

#[test]
fn get_gain2_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_misc", "get_gain2") else {
        return;
    };
    for case in &cases {
        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        let gain = get_gain2(&case.i16s("x"), &case.i16s("y"), case.i16("n"), &mut flags);
        check(case, "gain", &gain, &case.out_i32("gain"));
        check(
            case,
            "carry",
            &i16::from(flags.carry),
            &case.out_i16("carry"),
        );
    }
}

#[test]
fn e_lpc_a_weight_inv_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_misc", "E_LPC_a_weight_inv") else {
        return;
    };
    for case in &cases {
        let mut ap = [0i16; 17];
        e_lpc_a_weight_inv(&case.i16s("a"), &mut ap, case.i16("inv_gamma"), 16);
        check(case, "ap", &ap.to_vec(), &case.out_i16s("ap"));
    }
}
