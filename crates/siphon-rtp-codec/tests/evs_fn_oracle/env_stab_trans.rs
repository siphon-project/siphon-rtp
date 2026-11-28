//! `lib_com/env_stab_trans_fx.c` against `fn_env_stab_trans`: HVQ, transient and other frames of 640
//! coefficients, with long-term energies from silent to loud.

use siphon_rtp_codec::evs::com::env_stab_trans::env_stab_transient_detect;

use crate::common::{corpus, mismatch};

#[test]
fn env_stab_transient_detect_matches_the_reference() {
    let Some(cases) = corpus("env_stab_trans", "env_stab_transient_detect") else {
        return;
    };
    let mut armed = 0;
    for case in &cases {
        let mut hangover = case.i16("hangover");
        let mut energy_lt = case.i32("energy_lt");
        env_stab_transient_detect(
            case.i16("is_transient"),
            640,
            &case.i16s("norm"),
            &mut hangover,
            &mut energy_lt,
            case.i16("mode"),
            case.i16("bin_th"),
            &case.i32s("coeff"),
            12,
        );
        armed += i32::from(hangover > case.i16("hangover"));
        if let Some(message) = [
            mismatch(case, "hangover", &hangover, &case.out_i16("hangover")),
            mismatch(case, "energy_lt", &energy_lt, &case.out_i32("energy_lt")),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            panic!("{message}");
        }
    }
    assert!(armed > 20, "hangover armed {armed}");
}
