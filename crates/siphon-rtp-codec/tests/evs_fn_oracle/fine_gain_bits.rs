//! `lib_com/fine_gain_bits_fx.c` against `fn_fine_gain_bits` (`subband_gain_bits_fx` through its
//! only caller).

use siphon_rtp_codec::evs::com::fine_gain_bits::assign_gain_bits;

use crate::common::{corpus, mismatch};

#[test]
fn assign_gain_bits_matches_the_reference() {
    let Some(cases) = corpus("fine_gain_bits", "assign_gain_bits") else {
        return;
    };
    for case in &cases {
        let width = case.i16s("band_width");
        let mut rk = case.i16s("rk");
        let mut bits = vec![0; rk.len()];
        let mut rcalc = 0;
        let r = assign_gain_bits(
            case.i16("core"),
            rk.len() as i16,
            &width,
            &mut rk,
            &mut bits,
            &mut rcalc,
        );
        let message = mismatch(case, "r", &r, &case.out_i16("r"))
            .or_else(|| mismatch(case, "rk", &rk, &case.out_i16s("rk")))
            .or_else(|| mismatch(case, "bits", &bits, &case.out_i16s("bits")))
            .or_else(|| mismatch(case, "rcalc", &rcalc, &case.out_i16("rcalc")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}
