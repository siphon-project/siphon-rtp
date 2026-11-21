//! `lib_com/stab_est_fx.c` against `fn_stab_est`.

use siphon_rtp_codec::evs::com::stab_est::stab_est;

use crate::common::{corpus, mismatch};

#[test]
fn stab_est_matches_the_reference() {
    let Some(cases) = corpus("stab_est", "stab_est") else {
        return;
    };
    for case in &cases {
        let mut lt_diff_etot = case.i16s("lt_diff_etot");
        let mut mem_etot = case.i16("mem_etot");
        let mut nb_thr_3 = case.i16("nb_thr_3");
        let mut nb_thr_1 = case.i16("nb_thr_1");
        let mut thresh = case.i16s("thresh");
        let mut last_music_flag = case.i16("last_music_flag");
        let flag = stab_est(
            case.i16("etot"),
            &mut lt_diff_etot,
            &mut mem_etot,
            &mut nb_thr_3,
            &mut nb_thr_1,
            &mut thresh,
            &mut last_music_flag,
            case.i16("vad_flag"),
        );
        let failure = mismatch(case, "flag", &flag, &case.out_i16("flag"))
            .or_else(|| {
                mismatch(
                    case,
                    "lt_diff_etot",
                    &lt_diff_etot,
                    &case.out_i16s("lt_diff_etot"),
                )
            })
            .or_else(|| mismatch(case, "mem_etot", &mem_etot, &case.out_i16("mem_etot")))
            .or_else(|| mismatch(case, "nb_thr_3", &nb_thr_3, &case.out_i16("nb_thr_3")))
            .or_else(|| mismatch(case, "nb_thr_1", &nb_thr_1, &case.out_i16("nb_thr_1")))
            .or_else(|| mismatch(case, "thresh", &thresh, &case.out_i16s("thresh")))
            .or_else(|| {
                mismatch(
                    case,
                    "last_music_flag",
                    &last_music_flag,
                    &case.out_i16("last_music_flag"),
                )
            });
        if let Some(message) = failure {
            panic!("{message}");
        }
    }
}
