//! `lib_com/reordvct_fx.c` (`reordvct_fx`) against `fn_reordvct`.

use siphon_rtp_codec::evs::com::reordvct::reordvct;

use crate::common::{corpus, mismatch};

#[test]
fn reordvct_matches_the_reference() {
    let Some(cases) = corpus("reordvct", "reordvct") else {
        return;
    };
    for case in &cases {
        let mut y = case.i16s("y");
        let mut idx = case.i16s("idx");
        reordvct(&mut y, case.i16("n"), &mut idx);
        for (name, rust) in [("y", &y), ("idx", &idx)] {
            if let Some(message) = mismatch(case, name, rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
