//! `lib_dec/FEC_pitch_estim_fx.c` against `fn_FEC_pitch_estim`.

use siphon_rtp_codec::evs::dec::fec_pitch_estim::fec_pitch_estim;

use crate::common::{corpus, mismatch};

#[test]
fn fec_pitch_estim_matches_the_reference() {
    let Some(cases) = corpus("FEC_pitch_estim", "fec_pitch_estim") else {
        return;
    };
    for case in &cases {
        let (mut bfi_pitch, mut bfi_pitch_frame, mut upd_cnt) = (
            case.i16("bfi_pitch"),
            case.i16("bfi_pitch_frame"),
            case.i16("upd_cnt"),
        );
        fec_pitch_estim(
            case.i16("opt_amr_wb"),
            case.i16("last_core"),
            case.i16("l_frame"),
            case.i16("clas"),
            case.i16("last_good"),
            &case.i16s("pitch_buf"),
            &case.i32s("old_pitch_buf"),
            &mut bfi_pitch,
            &mut bfi_pitch_frame,
            &mut upd_cnt,
            case.i16("coder_type"),
        );
        let reference = [
            case.out_i16("bfi_pitch"),
            case.out_i16("bfi_pitch_frame"),
            case.out_i16("upd_cnt"),
        ];
        let rust = [bfi_pitch, bfi_pitch_frame, upd_cnt];
        if let Some(message) = mismatch(case, "bfi_pitch/frame/upd_cnt", &rust, &reference) {
            panic!("{message}");
        }
    }
}
