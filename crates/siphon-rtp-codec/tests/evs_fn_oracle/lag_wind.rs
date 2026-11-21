//! `lib_com/lag_wind.c` (`lag_wind`) and `lib_com/interpol_fx.c` (`Interpol_lc_fx`) against
//! `fn_lag_wind`.

use siphon_rtp_codec::evs::com::interpol::interpol_lc;
use siphon_rtp_codec::evs::com::lag_wind::lag_wind;
use siphon_rtp_codec::evs::rom::RESAMPLING_CFG_TBL_FX;

use crate::common::{corpus, mismatch};

#[test]
fn lag_wind_matches_the_reference() {
    let Some(cases) = corpus("lag_wind", "lag_wind") else {
        return;
    };
    for case in &cases {
        let mut r_h = case.i16s("r_h");
        let mut r_l = case.i16s("r_l");
        lag_wind(
            &mut r_h,
            &mut r_l,
            case.i16("m"),
            case.i32("sr"),
            case.i16("strength"),
        );
        let message = mismatch(case, "r_h", &r_h, &case.out_i16s("r_h"))
            .or_else(|| mismatch(case, "r_l", &r_l, &case.out_i16s("r_l")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

#[test]
fn interpol_lc_matches_the_reference() {
    let Some(cases) = corpus("lag_wind", "interpol_lc") else {
        return;
    };
    for case in &cases {
        let cfg = &RESAMPLING_CFG_TBL_FX[case.i16("k") as usize];
        let r = interpol_lc(
            &case.i16s("x"),
            64,
            cfg.filter_fx,
            case.i16("frac"),
            cfg.fac_num_fx,
            case.i16("nb_coef"),
        );
        if let Some(message) = mismatch(case, "r", &r, &case.out_i32("r")) {
            panic!("{message}");
        }
    }
}
