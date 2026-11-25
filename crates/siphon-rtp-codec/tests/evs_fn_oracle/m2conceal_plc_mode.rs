//! `GetPLCModeDecision` (`lib_dec/er_util.c`) against `fn_m2conceal_plc_mode`: the decision and
//! the whole decoder state after it, with the tonal MDCT concealment fed two good frames so that
//! its detection of tonal components runs.

use siphon_rtp_codec::evs::dec::er_util::get_plc_mode_decision;

use crate::common::{corpus_sized, mismatch, Case};
use crate::m2conceal_common::lpd_decoder_before;
use crate::state_case::state_after;
use crate::state_dump;

const COUNT: usize = 400;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn get_plc_mode_decision_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_plc_mode", "plc_mode", COUNT) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = lpd_decoder_before(case);
        let context = format!(
            "case {index}: last_core {}, second_last_core {}, nbLostCmpt {}, bitrate {}",
            st.last_core,
            st.second_last_core,
            st.nb_lost_cmpt,
            case.i32("bitrate")
        );
        let core = get_plc_mode_decision(&mut st);
        check(
            case,
            &format!("{context}: core"),
            &core,
            &case.out_i16("core"),
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}
