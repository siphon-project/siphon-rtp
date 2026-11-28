//! `hq_pred_hb_bws_fx` (`lib_dec/hq_hr_dec_fx.c`) against `fn_hq_pred_hb_bws`: the whole decoder state
//! after the call, over frame lengths, classes, rates and `last_inner_frame` on both sides of the
//! thresholds.

use siphon_rtp_codec::evs::dec::hq_hr_dec::hq_pred_hb_bws;

use crate::common::corpus;
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

#[test]
fn hq_pred_hb_bws_matches_the_reference() {
    let Some(cases) = corpus("hq_pred_hb_bws", "hq_pred_hb_bws") else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        hq_pred_hb_bws(
            &mut st,
            &case.i16s("ynrm"),
            case.i16("length"),
            case.i16("hqswb_clas"),
            &case.i16s("swb_fenv"),
        );
        let context = format!(
            "case {index}: length {}, class {}, rate {}",
            case.i16("length"),
            case.i16("hqswb_clas"),
            st.core_brate
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}
