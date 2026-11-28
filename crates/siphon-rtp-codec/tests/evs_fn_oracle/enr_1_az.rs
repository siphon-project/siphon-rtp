//! `lib_com/enr_1_az_fx.c` against `fn_enr_1_az`.

use siphon_rtp_codec::evs::com::enr_1_az::enr_1_az;

use crate::common::{corpus, mismatch};

#[test]
fn enr_1_az_matches_the_reference() {
    let Some(cases) = corpus("enr_1_az", "enr_1_az") else {
        return;
    };
    for case in &cases {
        let enr = enr_1_az(&case.i16s("aq"), case.i16("len"));
        if let Some(message) = mismatch(case, "enr", &enr, &case.out_i16("enr")) {
            panic!("{message}");
        }
    }
}
