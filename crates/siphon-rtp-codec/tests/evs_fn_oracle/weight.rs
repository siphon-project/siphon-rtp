//! `lib_com/weight_fx.c` against `fn_weight`: the perceptual weighting of the 44 norms of a 48 kHz
//! frame, transient and not.

use siphon_rtp_codec::evs::com::weight::map_quant_weight;

use crate::common::{corpus, mismatch};

#[test]
fn map_quant_weight_matches_the_reference() {
    let Some(cases) = corpus("weight", "map_quant_weight") else {
        return;
    };
    for case in &cases {
        let mut wnorm = [-7i16; 44];
        map_quant_weight(&case.i16s("normqlg2"), &mut wnorm, case.i16("is_transient"));
        if let Some(message) = mismatch(case, "wnorm", &wnorm.to_vec(), &case.out_i16s("wnorm")) {
            panic!("{message}");
        }
    }
}
