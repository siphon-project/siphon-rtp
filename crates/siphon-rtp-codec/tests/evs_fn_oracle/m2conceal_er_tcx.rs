//! `lib_dec/er_dec_tcx.c` (`con_tcx`, and through it `calcGainc` and `calcGainc2`) against
//! `fn_m2conceal_er_tcx`: one lost TCX frame on a MODE2 decoder with a randomised concealment
//! state and a pitched or noisy past output, the whole synthesis buffer and the whole decoder
//! state after the call.

use siphon_rtp_codec::evs::dec::er_dec_tcx::con_tcx;

use crate::common::{corpus_sized, mismatch, Case};
use crate::m2conceal_common::lpd_decoder_before;
use crate::state_case::state_after;
use crate::state_dump;

const COUNT: usize = 300;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn con_tcx_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_er_tcx", "con_tcx", COUNT) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = lpd_decoder_before(case);
        let context = format!(
            "case {index}: L_frame {}, L_frameTCX {}, last_good {}, nbLostCmpt {}, recalc {}, bitrate {}, bandwidth {}, partial copy {}",
            st.l_frame,
            st.l_frame_tcx,
            st.last_good,
            st.nb_lost_cmpt,
            st.tcx_conceal_recalc_exc,
            case.i32("bitrate"),
            case.i16("bandwidth"),
            st.use_partial_copy
        );
        let history = case.i16("history") as usize;
        let mut synth = case.i16s("synth");
        con_tcx(&mut st, &mut synth, history);
        check(
            case,
            &format!("{context}: synth"),
            &synth,
            &case.out_i16s("synth"),
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}
