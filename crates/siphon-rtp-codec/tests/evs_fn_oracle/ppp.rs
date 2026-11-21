//! The PPP coder's helpers against `fn_ppp`: `Interpol_delay_fx` and `deemph_lpc_fx`
//! (`lib_com/ppp_fx.c`), `log10_fx` and `find_remd`.

use siphon_rtp_codec::evs::com::log2::log10;
use siphon_rtp_codec::evs::com::ppp::{deemph_lpc, interpol_delay};
use siphon_rtp_codec::evs::com::tools::find_remd;
use siphon_rtp_codec::evs::rom::FRAC_4SF_FX;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn interpol_delay_matches_the_reference() {
    let Some(cases) = corpus("ppp", "interpol_delay") else {
        return;
    };
    for case in &cases {
        let mut out = vec![-7i16; 3];
        interpol_delay(
            &mut out,
            case.i16("last"),
            case.i16("cur"),
            case.i16("sub"),
            &FRAC_4SF_FX,
        );
        check(case, "out", &out, &case.out_i16s("out"));
    }
}

#[test]
fn deemph_lpc_matches_the_reference() {
    let Some(cases) = corpus("ppp", "deemph_lpc") else {
        return;
    };
    for case in &cases {
        let (mut de_curr, mut de_old) = (vec![-7i16; 17], vec![-7i16; 17]);
        deemph_lpc(
            &case.i16s("curr"),
            &case.i16s("old"),
            &mut de_curr,
            &mut de_old,
            case.i16("flag"),
        );
        check(case, "de_curr", &de_curr, &case.out_i16s("de_curr"));
        check(case, "de_old", &de_old, &case.out_i16s("de_old"));
    }
}

#[test]
fn log10_matches_the_reference() {
    let Some(cases) = corpus("ppp", "log10") else {
        return;
    };
    for case in &cases {
        check(case, "r", &log10(case.i32("x")), &case.out_i32("r"));
    }
}

#[test]
fn find_remd_matches_the_reference() {
    let Some(cases) = corpus("ppp", "find_remd") else {
        return;
    };
    for case in &cases {
        let mut rem = -7;
        let q = find_remd(case.i32("n"), case.i32("m"), &mut rem);
        check(case, "q", &q, &case.out_i32("q"));
        check(case, "rem", &rem, &case.out_i32("rem"));
    }
}
