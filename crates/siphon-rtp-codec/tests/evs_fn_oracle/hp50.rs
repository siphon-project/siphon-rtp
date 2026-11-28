//! `lib_com/hp50.c` against `fn_hp50`.

use siphon_rtp_codec::evs::com::hp50::{
    filter_2nd_order, hp20, hp50_mode2_mpy_32_16_fix, hp50_mpy_32_32_fix,
};

use crate::common::{corpus, mismatch};

#[test]
fn hp50_multiplies_match_the_reference() {
    let Some(cases) = corpus("hp50", "mpy") else {
        return;
    };
    for case in &cases {
        let r32 = hp50_mpy_32_32_fix(case.i32("a"), case.i32("b"));
        let r16 = hp50_mode2_mpy_32_16_fix(case.i32("a"), case.i16("c"));
        if let Some(message) = mismatch(case, "r32", &r32, &case.out_i32("r32"))
            .or_else(|| mismatch(case, "r16", &r16, &case.out_i32("r16")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn hp20_matches_the_reference() {
    let Some(cases) = corpus("hp50", "hp20") else {
        return;
    };
    for case in &cases {
        let mut signal = case.i16s("signal");
        let mut mem = case.i32s("mem");
        let lg = signal.len() as i16;
        hp20(&mut signal, 1, lg, &mut mem, case.i32("sfreq"));
        if let Some(message) = mismatch(case, "signal", &signal, &case.out_i16s("signal"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i32s("mem")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn filter_2nd_order_matches_the_reference() {
    let Some(cases) = corpus("hp50", "filter_2nd_order") else {
        return;
    };
    for case in &cases {
        let mut signal = case.i16s("signal");
        let mut mem = case.i32s("mem");
        let stride = case.i16("stride");
        let lg = signal.len() as i16 / stride;
        filter_2nd_order(
            &mut signal,
            stride,
            case.i16("prescale"),
            lg,
            &mut mem,
            case.i32("a1"),
            case.i32("a2"),
            case.i32("b1"),
            case.i32("b2"),
        );
        if let Some(message) = mismatch(case, "signal", &signal, &case.out_i16s("signal"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i32s("mem")))
        {
            panic!("{message}");
        }
    }
}
