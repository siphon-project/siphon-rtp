//! `lib_com/swb_bwe_com_lr_fx.c` against `fn_swb_bwe_com_lr`.

use siphon_rtp_codec::evs::com::swb_bwe_com_lr::updat_prev_frm;

use crate::common::{corpus, mismatch};

#[test]
fn updat_prev_frm_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com_lr", "updat_prev_frm") else {
        return;
    };
    for case in &cases {
        let mut t_audio = case.i32s("t_audio");
        let mut peak = case.i16s("peak");
        let (mut prev_clas, mut hfe2, mut stab) =
            (case.i16("prev_clas"), case.i16("hfe2"), case.i16("stab"));
        updat_prev_frm(
            &case.i32s("y2"),
            &mut t_audio,
            case.i32("rate"),
            case.i16("length"),
            case.i16("inner"),
            case.i16("bands"),
            case.i16("bwidth"),
            case.i16("transient"),
            case.i16("clas"),
            &mut prev_clas,
            &mut peak,
            &case.i16s("peak_tmp"),
            &mut hfe2,
            &mut stab,
            case.i16("bws"),
        );
        let message = mismatch(case, "t_audio", &t_audio, &case.out_i32s("t_audio"))
            .or_else(|| mismatch(case, "peak", &peak, &case.out_i16s("peak")))
            .or_else(|| mismatch(case, "prev_clas", &prev_clas, &case.out_i16("prev_clas")))
            .or_else(|| mismatch(case, "hfe2", &hfe2, &case.out_i16("hfe2")))
            .or_else(|| mismatch(case, "stab", &stab, &case.out_i16("stab")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}
