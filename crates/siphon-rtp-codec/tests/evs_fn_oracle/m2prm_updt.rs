//! `lib_dec/updt_dec_fx.c` `update_decoder_LPD_cng` against `fn_m2prm_updt`, on the whole decoder
//! state (it runs the LP analysis, `FEC_clas_estim_fx` and `post_decoder` of the CNG frame).

use siphon_rtp_codec::evs::dec::updt_dec::update_decoder_lpd_cng;

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn update_decoder_lpd_cng_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("m2prm_updt", "update_decoder_LPD_cng", 300) else {
        return;
    };
    let (mut at_16k, mut at_12k8) = (0, 0);
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let l_frame = case.i16("l_frame");
        if l_frame == 320 {
            at_16k += 1;
        } else {
            at_12k8 += 1;
        }
        let mut buffer = case.i16s("buffer");
        let mut noise = vec![0x5a5a_i16; 960];
        update_decoder_lpd_cng(
            &mut st,
            case.i16("coder_type"),
            &mut buffer,
            &case.i16s("a"),
            &mut noise,
        );
        noise.truncate(l_frame as usize);
        check(case, "buffer", &buffer, &case.out_i16s("buffer"));
        check(case, "noise", &noise, &case.out_i16s("noise"));
        let context = format!("update_decoder_LPD_cng case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
    assert!(at_16k > 50 && at_12k8 > 50, "{at_16k} {at_12k8}");
}
