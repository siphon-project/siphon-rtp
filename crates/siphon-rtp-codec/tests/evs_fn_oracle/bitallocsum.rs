//! `lib_com/bitallocsum_fx.c` against `fn_bitallocsum`: integer allocations on the HQ band layouts
//! of 16, 32 and 48 kHz frames, with the budget above and below what the allocation takes.

use siphon_rtp_codec::evs::com::bitallocsum::bitallocsum;

use crate::common::{corpus, mismatch};

#[test]
fn bitallocsum_matches_the_reference() {
    let Some(cases) = corpus("bitallocsum", "bitallocsum") else {
        return;
    };
    for case in &cases {
        let nb_sfm = case.i16("nb_sfm");
        let mut sum = -7;
        let mut rsubband = [-7i16; 44];
        bitallocsum(
            &case.i16s("r"),
            nb_sfm,
            &mut sum,
            &mut rsubband,
            case.i16("v"),
            case.i16("length"),
            &case.i16s("sfmsize"),
        );
        if let Some(message) = [
            mismatch(case, "sum", &sum, &case.out_i16("sum")),
            mismatch(
                case,
                "rsubband",
                &rsubband[..nb_sfm as usize].to_vec(),
                &case.out_i16s("rsubband"),
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
