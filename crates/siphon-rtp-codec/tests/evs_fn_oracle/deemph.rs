//! `lib_com/deemph_fx.c` against `fn_deemph`.

use siphon_rtp_codec::evs::com::deemph::{deemph, e_util_deemph2};

use crate::common::{corpus, mismatch};

#[test]
fn deemph_matches_the_reference() {
    let Some(cases) = corpus("deemph", "deemph") else {
        return;
    };
    for case in &cases {
        let mut signal = case.i16s("signal");
        let mut mem = case.i16("mem");
        deemph(&mut signal, case.i16("mu"), case.i16("l"), &mut mem);
        if let Some(message) = mismatch(case, "signal", &signal, &case.out_i16s("signal"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16("mem")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn e_util_deemph2_matches_the_reference() {
    let Some(cases) = corpus("deemph", "deemph2") else {
        return;
    };
    for case in &cases {
        let mut signal = case.i16s("signal");
        let mut mem = case.i16("mem");
        e_util_deemph2(
            case.i16("shift"),
            &mut signal,
            case.i16("mu"),
            case.i16("l"),
            &mut mem,
        );
        if let Some(message) = mismatch(case, "signal", &signal, &case.out_i16s("signal"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16("mem")))
        {
            panic!("{message}");
        }
    }
}
