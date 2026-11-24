//! `lib_com/swb_bwe_com_hr_fx.c` against `fn_swb_bwe_com_hr`.

use siphon_rtp_codec::evs::com::swb_bwe_com_hr::swb_hr_noise_fill;

use crate::common::{corpus, mismatch};

#[test]
fn swb_hr_noise_fill_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com_hr", "swb_hr_noise_fill") else {
        return;
    };
    for case in &cases {
        let mut t_audio = case.i16s("t_audio");
        let mut seed = case.i16("seed");
        swb_hr_noise_fill(
            case.i16("transient"),
            case.i16("start"),
            case.i16("end"),
            case.i16("tilt"),
            case.i16("pitch"),
            &case.i16s("nq"),
            case.i16("nsv"),
            &mut seed,
            &mut t_audio,
            case.i16("q_audio"),
        );
        if let Some(message) = mismatch(case, "t_audio", &t_audio, &case.out_i16s("t_audio")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "seed", &seed, &case.out_i16("seed")) {
            panic!("{message}");
        }
    }
}
