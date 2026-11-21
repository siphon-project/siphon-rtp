//! `lib_com/env_adj_fx.c` against `fn_env_adj`: 640 coefficient frames (noise-filled band attenuation)
//! and 320 coefficient frames (low-accuracy band attenuation).

use siphon_rtp_codec::evs::com::env_adj::env_adj;

use crate::common::{corpus, mismatch};

#[test]
fn env_adj_matches_the_reference() {
    let Some(cases) = corpus("env_adj", "env_adj") else {
        return;
    };
    let (mut short, mut long) = (0, 0);
    for case in &cases {
        let mut adj = vec![-7i16; 44];
        env_adj(
            &case.i16s("pulses"),
            case.i16("length"),
            case.i16("last_sfm"),
            &mut adj,
            case.i16("env_stab"),
            &case.i16s("sfmsize"),
        );
        short += i32::from(case.i16("length") == 320);
        long += i32::from(case.i16("length") == 640);
        if let Some(message) = mismatch(case, "adj", &adj, &case.out_i16s("adj")) {
            panic!("{message}");
        }
    }
    assert!(short > 200 && long > 200, "short {short}, long {long}");
}
