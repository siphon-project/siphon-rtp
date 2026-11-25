//! The spectral half of `lib_com/tcx_utils.c` against `fn_m2tcx_spectrum`: `lpc2mdct`, the MDCT
//! shaping functions, the low-frequency de-emphasis and the noise filling. The helpers
//! `BASOP_Util_Sqrt_InvSqrt_MantExp` and `compMantExp16Unorm` are proven through them.

use siphon_rtp_codec::evs::com::tcx_utils::{
    adapt_low_freq_deemph, lpc2mdct, mdct_noise_shaping_interp, mdct_shaping, mdct_shaping_16,
    psych_adapt_low_freq_deemph, tcx_noise_filling, Lpc2MdctOutputs,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn lpc2mdct_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_spectrum", "lpc2mdct") else {
        return;
    };
    for case in &cases {
        let mask = case.i16("mask");
        let mut gains = [0x5555i16; 64];
        let mut gains_exp = [0x5555i16; 64];
        let mut inv_gains = [0x5555i16; 64];
        let mut inv_gains_exp = [0x5555i16; 64];
        lpc2mdct(
            &case.i16s("a"),
            case.i16("order"),
            &mut Lpc2MdctOutputs {
                mdct_gains: (mask & 1 != 0).then_some(&mut gains[..]),
                mdct_gains_exp: (mask & 2 != 0).then_some(&mut gains_exp[..]),
                mdct_inv_gains: (mask & 4 != 0).then_some(&mut inv_gains[..]),
                mdct_inv_gains_exp: (mask & 8 != 0).then_some(&mut inv_gains_exp[..]),
            },
        );
        check(case, "g", &gains.to_vec(), &case.out_i16s("g"));
        check(case, "ge", &gains_exp.to_vec(), &case.out_i16s("ge"));
        check(case, "ig", &inv_gains.to_vec(), &case.out_i16s("ig"));
        check(case, "ige", &inv_gains_exp.to_vec(), &case.out_i16s("ige"));
    }
}

#[test]
fn mdct_shaping_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_spectrum", "mdct_shaping") else {
        return;
    };
    for case in &cases {
        let mut x = case.i32s("x");
        mdct_shaping(&mut x, case.i16("lg"), &case.i16s("g"), &case.i16s("ge"));
        check(case, "x", &x, &case.out_i32s("x"));
    }
}

#[test]
fn mdct_shaping_16_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_spectrum", "mdct_shaping_16") else {
        return;
    };
    for case in &cases {
        let lg_total = case.i16("lg_total");
        let mut y = vec![0x5555_5555i32; lg_total as usize];
        mdct_shaping_16(
            &case.i16s("x"),
            case.i16("lg"),
            lg_total,
            &case.i16s("g"),
            &case.i16s("ge"),
            case.i16("max_exp"),
            &mut y,
        );
        check(case, "y", &y, &case.out_i32s("y"));
    }
}

#[test]
fn mdct_noise_shaping_interp_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_spectrum", "mdct_noiseShaping_interp") else {
        return;
    };
    for case in &cases {
        let mut x = case.i32s("x");
        let gains = case.i16s("g");
        mdct_noise_shaping_interp(
            &mut x,
            case.i16("lg"),
            (case.i16("null_gains") == 0).then_some(&gains[..]),
            &case.i16s("ge"),
        );
        check(case, "x", &x, &case.out_i32s("x"));
    }
}

#[test]
fn psych_adapt_low_freq_deemph_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_spectrum", "PsychAdaptLowFreqDeemph") else {
        return;
    };
    for case in &cases {
        let mut x = case.i32s("x");
        let mut lf = case.i16s("lf");
        psych_adapt_low_freq_deemph(
            &mut x,
            &case.i16s("g"),
            &case.i16s("ge"),
            (case.i16("with_lf") != 0).then_some(&mut lf[..]),
        );
        check(case, "x", &x, &case.out_i32s("x"));
        check(case, "lf", &lf, &case.out_i16s("lf"));
    }
}

#[test]
fn adapt_low_freq_deemph_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_spectrum", "AdaptLowFreqDeemph") else {
        return;
    };
    for case in &cases {
        let mut x = case.i32s("x");
        let lg = case.i16("lg");
        let mut lf = vec![0x4000i16; lg as usize];
        adapt_low_freq_deemph(
            &mut x,
            case.i16("x_e"),
            case.i16("shaped"),
            &case.i16s("g"),
            &case.i16s("ge"),
            lg,
            (case.i16("with_lf") != 0).then_some(&mut lf[..]),
        );
        check(case, "x", &x, &case.out_i32s("x"));
        check(case, "lf", &lf, &case.out_i16s("lf"));
    }
}

#[test]
fn tcx_noise_filling_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_spectrum", "tcx_noise_filling") else {
        return;
    };
    for case in &cases {
        let mut q = case.i32s("q");
        let mut info = vec![0i16; q.len()];
        tcx_noise_filling(
            &mut q,
            case.i16("q_e"),
            case.i16("seed"),
            case.i16("first"),
            case.i16("lowpass"),
            case.i16("trans_width"),
            case.i16("l_frame"),
            case.i16("tilt"),
            case.i16("fac_ns"),
            (case.i16("with_info") != 0).then_some(&mut info[..]),
        );
        check(case, "q", &q, &case.out_i32s("q"));
        if case.i16("with_info") != 0 {
            check(case, "info", &info, &case.out_i16s("info"));
        }
    }
}
