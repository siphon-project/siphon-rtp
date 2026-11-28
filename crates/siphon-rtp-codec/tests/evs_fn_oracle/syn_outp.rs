//! `lib_dec/syn_outp_fx.c` against `fn_syn_outp`.

use siphon_rtp_codec::evs::dec::syn_outp::{syn_output, unscale_agc};

use crate::common::{corpus, mismatch};

#[test]
fn syn_output_matches_the_reference() {
    let Some(cases) = corpus("syn_outp", "syn_output") else {
        return;
    };
    for case in &cases {
        let synth = case.i16s("synth");
        let mut out = vec![0; synth.len()];
        syn_output(
            case.i16("mode"),
            &synth,
            case.i16("frame"),
            &mut out,
            case.i16("q"),
        );
        if let Some(message) = mismatch(case, "out", &out, &case.out_i16s("out")) {
            panic!("{message}");
        }
    }
}

#[test]
fn unscale_agc_matches_the_reference() {
    let Some(cases) = corpus("syn_outp", "unscale_agc") else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let mut mem = case.i16s("mem");
        let mut y = vec![0; x.len()];
        unscale_agc(&x, case.i16("qx"), &mut y, &mut mem, x.len() as i16);
        if let Some(message) = mismatch(case, "y", &y, &case.out_i16s("y"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16s("mem")))
        {
            panic!("{message}");
        }
    }
}
