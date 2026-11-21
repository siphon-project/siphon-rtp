//! `lib_com/hq2_bit_alloc_fx.c` against `fn_hq2_bit_alloc`: `hq2_bit_alloc_fx`,
//! `hq2_bit_alloc_har_fx` (on SWB harmonic layouts from `hq2_core_configure_fx`) and
//! `Bits2indvsb_fx` (single groups).

use siphon_rtp_codec::evs::com::hq2_bit_alloc::{bits2indvsb, hq2_bit_alloc, hq2_bit_alloc_har};

use crate::common::{corpus, mismatch};

#[test]
fn hq2_bit_alloc_matches_the_reference() {
    let Some(cases) = corpus("hq2_bit_alloc", "hq2_bit_alloc") else {
        return;
    };
    for case in &cases {
        let energy = case.i32s("energy");
        let mut p2a = case.i16s("p2a");
        let mut rk = vec![0x5a5a_5a5a; energy.len()];
        let mut budget = case.i16("budget");
        let r = hq2_bit_alloc(
            &energy,
            energy.len() as i16,
            &mut rk,
            &mut budget,
            &mut p2a,
            case.i16("weight"),
            &case.i16s("width"),
            case.i16("num_bits"),
            case.i16("clas"),
            case.i16("bwidth"),
            case.i16("transient"),
        );
        let message = mismatch(case, "r", &r, &case.out_i32("r"))
            .or_else(|| mismatch(case, "rk", &rk, &case.out_i32s("rk")))
            .or_else(|| mismatch(case, "budget", &budget, &case.out_i16("budget")))
            .or_else(|| mismatch(case, "p2a", &p2a, &case.out_i16s("p2a")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

#[test]
fn hq2_bit_alloc_har_matches_the_reference() {
    let Some(cases) = corpus("hq2_bit_alloc", "hq2_bit_alloc_har") else {
        return;
    };
    for case in &cases {
        let energy = case.i32s("energy");
        let bands = energy.len();
        let mut rk = vec![0x5a5a_5a5a; bands];
        let mut p2a = vec![1i16; bands];
        hq2_bit_alloc_har(
            &energy,
            case.i16("budget"),
            bands as i16,
            &mut rk,
            case.i16("p2a_bands"),
            case.i32("brate"),
            &mut p2a,
            &case.i16s("width"),
        );
        for (name, ok) in [
            ("rk", mismatch(case, "rk", &rk, &case.out_i32s("rk"))),
            ("p2a", mismatch(case, "p2a", &p2a, &case.out_i16s("p2a"))),
        ] {
            if let Some(message) = ok {
                panic!("{name}: {message}");
            }
        }
    }
}

#[test]
fn bits2indvsb_matches_the_reference() {
    let Some(cases) = corpus("hq2_bit_alloc", "bits2indvsb") else {
        return;
    };
    for case in &cases {
        let mut rk = case.i32s("rk");
        let mut p2a = case.i16s("p2a");
        bits2indvsb(
            &case.i32s("energy"),
            case.i16("start"),
            case.i16("end"),
            case.i16("bits"),
            case.i32("needed"),
            &mut rk,
            &mut p2a,
        );
        if let Some(message) = mismatch(case, "rk", &rk, &case.out_i32s("rk")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "p2a", &p2a, &case.out_i16s("p2a")) {
            panic!("{message}");
        }
    }
}
