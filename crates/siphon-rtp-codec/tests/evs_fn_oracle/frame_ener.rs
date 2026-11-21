//! `lib_com/frame_ener_fx.c` against `fn_frame_ener`.

use siphon_rtp_codec::evs::com::frame_ener::{frame_ener, frame_energy};
use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus, mismatch};

#[test]
fn frame_energy_matches_the_reference() {
    let Some(cases) = corpus("frame_ener", "frame_energy") else {
        return;
    };
    for case in &cases {
        let mut frame_ener = 0;
        let mut flags = StlFlags::default();
        let r = frame_energy(
            case.i16("l_frame"),
            &case.i16s("pitch"),
            &case.i16s("speech"),
            case.i16("lp_speech"),
            &mut frame_ener,
            case.i16("q_syn"),
            &mut flags,
        );
        if let Some(message) = mismatch(case, "r", &r, &case.out_i16("r"))
            .or_else(|| mismatch(case, "frame_ener", &frame_ener, &case.out_i16("frame_ener")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn frame_ener_matches_the_reference() {
    let Some(cases) = corpus("frame_ener", "frame_ener") else {
        return;
    };
    for case in &cases {
        let mut enr_q = 0;
        let r = frame_ener(
            case.i16("l_frame"),
            case.i16("clas"),
            &case.i16s("synth"),
            case.i16("pitch"),
            &mut enr_q,
            case.i16("offset"),
            case.i16("q_new"),
            case.i16("shift"),
            case.i16("enc"),
        );
        if let Some(message) = mismatch(case, "r", &r, &case.out_i16("r"))
            .or_else(|| mismatch(case, "enr_q", &enr_q, &case.out_i32("enr_q")))
        {
            panic!("{message}");
        }
    }
}
