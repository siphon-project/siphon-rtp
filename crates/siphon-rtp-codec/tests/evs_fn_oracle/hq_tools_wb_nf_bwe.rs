//! `hq_wb_nf_bwe_fx` (`lib_com/hq_tools_fx.c`) against `fn_hq_tools_wb_nf_bwe`: 320 coefficient frames
//! at 32 kbit/s, normal and transient, with previous-frame memories near and far from the current
//! norms.

use siphon_rtp_codec::evs::com::hq_tools::hq_wb_nf_bwe;

use crate::common::{corpus, mismatch};

#[test]
fn hq_wb_nf_bwe_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_wb_nf_bwe", "hq_wb_nf_bwe") else {
        return;
    };
    let (mut transient, mut normal) = (0, 0);
    for case in &cases {
        // the bit allocation (or the function) did not return in the reference: printed as skip
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut prev_normq = case.i32s("prev_normq");
        let mut prev_env = case.i32s("prev_env");
        let mut seed = case.i16("seed");
        let mut prev_coeff_out = case.i32s("prev_coeff_out");
        let mut prev_r = case.i16("prev_r");
        let mut prev_env_q = case.i16s("prev_env_q");
        let mut out = case.i32s("out");
        let transient_frame = case.i16("is_transient") != 0;
        transient += i32::from(transient_frame);
        normal += i32::from(!transient_frame);
        hq_wb_nf_bwe(
            &case.i16s("coeff"),
            case.i16("is_transient"),
            case.i16("prev_bfi"),
            &case.i32s("normq"),
            case.i16("num_sfm"),
            &case.i16s("sfm_start"),
            &case.i16s("sfm_end"),
            &case.i16s("sfmsize"),
            case.i16("last_sfm"),
            &case.i16s("r"),
            case.i16("prev_is_transient"),
            &mut prev_normq,
            &mut prev_env,
            &mut seed,
            &mut prev_coeff_out,
            &mut prev_r,
            &mut out,
            &mut prev_env_q,
        );
        if let Some(message) = [
            mismatch(
                case,
                "prev_normq",
                &prev_normq,
                &case.out_i32s("prev_normq"),
            ),
            mismatch(case, "prev_env", &prev_env, &case.out_i32s("prev_env")),
            mismatch(case, "seed", &seed, &case.out_i16("seed")),
            mismatch(
                case,
                "prev_coeff_out",
                &prev_coeff_out,
                &case.out_i32s("prev_coeff_out"),
            ),
            mismatch(case, "prev_r", &prev_r, &case.out_i16("prev_r")),
            mismatch(
                case,
                "prev_env_q",
                &prev_env_q,
                &case.out_i16s("prev_env_q"),
            ),
            mismatch(case, "out", &out, &case.out_i32s("out")),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            panic!("{message}");
        }
    }
    assert!(transient > 500 && normal > 500, "{transient} / {normal}");
}
