//! `lib_com/gs_preech_fx.c` (`pre_echo_att_fx`) against `fn_gs_preech`.

use siphon_rtp_codec::evs::com::gs_preech::pre_echo_att;

use crate::common::{corpus, mismatch};

#[test]
fn pre_echo_att_matches_the_reference() {
    let Some(cases) = corpus("gs_preech", "pre_echo_att") else {
        return;
    };
    for case in &cases {
        let mut exc = case.i16s("exc");
        let mut last_ener = case.i32("last_ener");
        pre_echo_att(
            &mut last_ener,
            &mut exc,
            case.i16("attack"),
            case.i16("q_new"),
            case.i16("last_coder_type"),
        );
        if let Some(message) = mismatch(case, "exc", &exc, &case.out_i16s("exc")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "last_ener", &last_ener, &case.out_i32("last_ener")) {
            panic!("{message}");
        }
    }
}
