//! `lib_com/cb_shape_fx.c` against `fn_cb_shape`.

use siphon_rtp_codec::evs::com::cb_shape::{cb_shape, e_gain_f_pitch_sharpening};

use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus, mismatch};

#[test]
fn cb_shape_matches_the_reference() {
    let Some(cases) = corpus("cb_shape", "cb_shape") else {
        return;
    };
    for case in &cases {
        let mut code = case.i16s("code");
        let mut flags = StlFlags {
            overflow: false,
            carry: case.i16("carry") != 0,
        };
        cb_shape(
            case.i16("preemph"),
            case.i16("pitch"),
            case.i16("scrambling"),
            case.i16("sharp"),
            case.i16("tilt"),
            case.i16("g1"),
            case.i16("g2"),
            &case.i16s("a"),
            &mut code,
            case.i16("tilt_code"),
            case.i16("pt_pitch"),
            case.i16("shift"),
            &mut flags,
        );
        if let Some(message) = mismatch(case, "code", &code, &case.out_i16s("code")).or_else(|| {
            mismatch(
                case,
                "carry",
                &i16::from(flags.carry),
                &case.out_i16("carry"),
            )
        }) {
            panic!("{message}");
        }
    }
}

#[test]
fn pitch_sharpening_matches_the_reference() {
    let Some(cases) = corpus("cb_shape", "pitch_sharpening") else {
        return;
    };
    for case in &cases {
        let mut x = case.i16s("x");
        e_gain_f_pitch_sharpening(&mut x, case.i16("lag"), 64);
        if let Some(message) = mismatch(case, "x", &x, &case.out_i16s("x")) {
            panic!("{message}");
        }
    }
}
