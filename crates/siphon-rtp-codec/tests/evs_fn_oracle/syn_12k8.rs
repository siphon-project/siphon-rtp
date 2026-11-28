//! `lib_com/syn_12k8_fx.c` against `fn_syn_12k8`.

use siphon_rtp_codec::evs::com::syn_12k8::syn_12k8;

use crate::common::{corpus, mismatch};

#[test]
fn syn_12k8_matches_the_reference() {
    let Some(cases) = corpus("syn_12k8", "syn_12k8") else {
        return;
    };
    for case in &cases {
        let exc = case.i16s("exc");
        let mut synth = vec![0; exc.len()];
        let mut mem = case.i16s("mem");
        syn_12k8(
            case.i16("l_frame"),
            &case.i16s("aq"),
            &exc,
            &mut synth,
            &mut mem,
            case.i16("update_m"),
            case.i16("q_exc"),
            case.i16("q_syn"),
        );
        for (name, rust, reference) in [
            ("synth", &synth, case.out_i16s("synth")),
            ("mem", &mem, case.out_i16s("mem")),
        ] {
            if let Some(message) = mismatch(case, name, rust, &reference) {
                panic!("{message}");
            }
        }
    }
}
