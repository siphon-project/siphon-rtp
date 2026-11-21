//! `lib_com/pred_lt4_fx.c` against `fn_pred_lt4`.

use siphon_rtp_codec::evs::cnst::{
    L_INTERPOL2, L_SUBFR, PIT_L_INTERPOL6_2, PIT_UP_SAMP, PIT_UP_SAMP6,
};
use siphon_rtp_codec::evs::com::pred_lt4::{pred_lt4, pred_lt4_tc};
use siphon_rtp_codec::evs::rom::{INTER4_2_FX, PITCH_INTER4_2, PITCH_INTER6_2};

use crate::common::{corpus, mismatch};

/// The excitation history the oracle keeps before `exc`.
const HIST: usize = 320;

#[test]
fn pred_lt4_matches_the_reference() {
    let Some(cases) = corpus("pred_lt4", "pred_lt4") else {
        return;
    };
    for case in &cases {
        let mut exc = case.i16s("exc");
        let (win, nb, up): (&[i16], i16, i16) = if case.i16("six") != 0 {
            (&PITCH_INTER6_2, PIT_L_INTERPOL6_2, PIT_UP_SAMP6)
        } else {
            (&PITCH_INTER4_2, L_INTERPOL2, PIT_UP_SAMP)
        };
        pred_lt4(
            &mut exc,
            HIST,
            case.i16("t0"),
            case.i16("frac"),
            case.i16("lsub"),
            win,
            nb,
            up,
        );
        if let Some(message) = mismatch(case, "exc", &exc, &case.out_i16s("exc")) {
            panic!("{message}");
        }
    }
}

#[test]
fn pred_lt4_tc_matches_the_reference() {
    let Some(cases) = corpus("pred_lt4", "pred_lt4_tc") else {
        return;
    };
    for case in &cases {
        let mut exc = case.i16s("exc");
        pred_lt4_tc(
            &mut exc,
            L_SUBFR as usize,
            case.i16("t0"),
            case.i16("frac"),
            &INTER4_2_FX,
            case.i16("imp_pos"),
            case.i16("i_subfr"),
        );
        if let Some(message) = mismatch(case, "exc", &exc, &case.out_i16s("exc")) {
            panic!("{message}");
        }
    }
}
