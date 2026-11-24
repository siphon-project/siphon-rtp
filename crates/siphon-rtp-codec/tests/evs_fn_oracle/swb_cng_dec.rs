//! `lib_dec/cng_dec_fx.c` (`swb_CNG_dec_fx`, through its local `shb_CNG_decod_fx`) against
//! `fn_cng_dec`. Each case is a whole decoder state (before and after) at 32 or 48 kHz with the SHB
//! comfort-noise memories, the core synthesis and the SID flag.

use siphon_rtp_codec::evs::dec::cng_dec::swb_cng_dec;

use crate::common::{corpus_sized, mismatch};
use crate::state_case::{decoder_before, state_after};

#[test]
fn swb_cng_dec_matches_the_reference() {
    // each case carries two whole decoder states: a smaller corpus keeps the run short
    let Some(cases) = corpus_sized("cng_dec", "swb_cng_dec", 150) else {
        return;
    };
    let mut synthesised = 0;
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let mut shb_synth = vec![-7i16; 960];
        swb_cng_dec(
            &mut st,
            &case.i16s("synth"),
            &mut shb_synth,
            case.i16("sid_bw"),
            case.i16("qsyn"),
        );
        if let Some(message) = mismatch(case, "shb_synth", &shb_synth, &case.out_i16s("shb_synth"))
        {
            panic!("{message}");
        }
        crate::state_dump::check(
            &mut st,
            &state_after(case),
            "st.",
            &format!("swb_cng_dec case {index}"),
        );
        synthesised += i32::from(st.shb_dtx_count > 0);
    }
    assert!(
        synthesised > 20,
        "only {synthesised} cases ran the SHB comfort noise"
    );
}
