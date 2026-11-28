//! `lib_dec/pitch_extr.c` (`pitch_pred_linear_fit`) against `fn_pitch_extr`.

use siphon_rtp_codec::evs::dec::pitch_extr::pitch_pred_linear_fit;

use crate::common::{corpus, mismatch};

#[test]
fn pitch_pred_linear_fit_matches_the_reference() {
    let Some(cases) = corpus("pitch_extr", "pitch_pred_linear_fit") else {
        return;
    };
    let mut extrapolated = 0;
    for case in &cases {
        let mut t0 = -12345;
        let mut failed = -1;
        pitch_pred_linear_fit(
            case.i16("bfi_cnt"),
            case.i16("last_good"),
            &case.i32s("old_pitch_buf"),
            case.i32("old_fpitch"),
            &mut t0,
            case.i16("pit_min"),
            case.i16("pit_max"),
            &case.i16s("mem_pitch_gain"),
            case.i16("limitation"),
            case.i16("future") as i8,
            &mut failed,
            case.i16("nb_subfr"),
        );
        if let Some(message) = mismatch(
            case,
            "t0/failed",
            &(t0, failed),
            &(case.out_i32("t0"), case.out_i16("failed")),
        ) {
            panic!("{message}");
        }
        extrapolated += usize::from(failed == 0);
    }
    // the corpus must exercise the fit itself, not only its early exits
    assert!(extrapolated > cases.len() / 5, "only {extrapolated} fits");
}
