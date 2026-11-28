//! `limit_band_noise_level_calc_fx` and `find_last_band_fx` (`lib_com/hq_tools_fx.c`) against
//! `fn_hq_tools_alloc`.

use siphon_rtp_codec::evs::com::hq_tools::{find_last_band, limit_band_noise_level_calc};

use crate::common::{corpus, mismatch};

#[test]
fn limit_band_noise_level_calc_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_alloc", "limit_band_noise_level_calc") else {
        return;
    };
    for case in &cases {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut limit = case.i16("limit");
        let mut noise_level = -7;
        limit_band_noise_level_calc(
            &case.i16s("wnorm"),
            &mut limit,
            case.i32("core_brate"),
            &mut noise_level,
        );
        if let Some(message) = [
            mismatch(case, "limit", &limit, &case.out_i16("limit")),
            mismatch(
                case,
                "noise_level",
                &noise_level,
                &case.out_i16("noise_level"),
            ),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            panic!("{message}");
        }
    }
}

#[test]
fn find_last_band_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_alloc", "find_last_band") else {
        return;
    };
    for case in &cases {
        let core_sfm = find_last_band(&case.i16s("bitalloc"), case.i16("nb_sfm"));
        if let Some(message) = mismatch(case, "core_sfm", &core_sfm, &case.out_i16("core_sfm")) {
            panic!("{message}");
        }
    }
}
