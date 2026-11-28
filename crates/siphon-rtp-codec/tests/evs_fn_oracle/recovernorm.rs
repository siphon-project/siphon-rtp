//! `lib_com/recovernorm_fx.c` against `fn_recovernorm`.

use siphon_rtp_codec::evs::com::recovernorm::recovernorm;

use crate::common::{corpus, mismatch};

#[test]
fn recovernorm_matches_the_reference() {
    let Some(cases) = corpus("recovernorm", "recovernorm") else {
        return;
    };
    for case in &cases {
        let mut ynrm = vec![-3i16; 44];
        let mut normqlg2 = vec![-4i16; 44];
        recovernorm(
            &case.i16s("idxbuf"),
            &mut ynrm,
            &mut normqlg2,
            case.i16("nb_sfm"),
        );
        for (name, rust) in [("ynrm", &ynrm), ("normqlg2", &normqlg2)] {
            if let Some(message) = mismatch(case, name, rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
