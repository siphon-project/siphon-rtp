//! `lib_com/est_tilt_fx.c` against `fn_est_tilt`.

use siphon_rtp_codec::evs::com::est_tilt::est_tilt;

use crate::common::{corpus, mismatch};

#[test]
fn est_tilt_matches_the_reference() {
    let Some(cases) = corpus("est_tilt", "est_tilt") else {
        return;
    };
    for case in &cases {
        let mut voice_fac = -99;
        let tilt = est_tilt(
            &case.i16s("exc"),
            case.i16("gain_pit"),
            &case.i16s("code"),
            case.i32("gain_code"),
            &mut voice_fac,
            case.i16("q_exc"),
        );
        if let Some(message) = mismatch(case, "tilt", &tilt, &case.out_i16("tilt"))
            .or_else(|| mismatch(case, "voice_fac", &voice_fac, &case.out_i16("voice_fac")))
        {
            panic!("{message}");
        }
    }
}
