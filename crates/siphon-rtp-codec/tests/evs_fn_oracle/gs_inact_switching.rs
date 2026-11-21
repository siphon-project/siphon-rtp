//! `lib_com/gs_inact_switching_fx.c` (`Inac_swtch_ematch_fx`) against `fn_gs_inact_switching`.

use siphon_rtp_codec::evs::com::gs_inact_switching::inac_swtch_ematch;

use crate::common::{corpus, mismatch};

#[test]
fn inac_swtch_ematch_matches_the_reference() {
    let Some(cases) = corpus("gs_inact_switching", "inac_swtch_ematch") else {
        return;
    };
    for case in &cases {
        let mut exc2 = case.i16s("exc2");
        let mut dct = case.i16s("dct");
        let mut lt = case.i16s("lt");
        inac_swtch_ematch(
            &mut exc2,
            &mut dct,
            &mut lt,
            case.i16("coder_type"),
            case.i16("l_frame"),
            case.i32("core_brate"),
            case.i16("q_exc"),
            case.i16("bfi"),
            case.i16("last_core"),
            case.i16("last_codec_mode"),
        );
        for (name, rust) in [("exc2", &exc2), ("dct", &dct), ("lt", &lt)] {
            if let Some(message) = mismatch(case, name, rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
