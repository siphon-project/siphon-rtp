//! `lib_dec/er_dec_acelp.c` (`con_acelp`, and through it `memsynPrecission`) against
//! `fn_m2conceal_er_acelp`: one lost ACELP frame on a MODE2 decoder with a randomised concealment
//! state, every output of the call and the whole decoder state after it.

use siphon_rtp_codec::evs::dec::er_dec_acelp::con_acelp;

use crate::common::{corpus_sized, mismatch, Case};
use crate::m2conceal_common::lpd_decoder_before;
use crate::state_case::state_after;
use crate::state_dump;

const COUNT: usize = 300;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn con_acelp_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_er_acelp", "con_acelp", COUNT) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = lpd_decoder_before(case);
        let context = format!(
            "case {index}: L_frame {}, last_good {}, nbLostCmpt {}, bitrate {}, bandwidth {}, guided {}",
            st.l_frame,
            st.last_good,
            st.nb_lost_cmpt,
            case.i32("bitrate"),
            case.i16("bandwidth"),
            st.flag_guided_acelp
        );
        let mut synth = vec![-1i16; 336];
        let mut p_t = vec![-1i16; 5];
        let mut pgain_t = vec![-1i16; 5];
        let mut pitch_buffer = vec![-1i16; 5];
        let mut voice_factors = vec![-1i16; 5];
        let mut bwe_exc = vec![-1i16; 648];
        con_acelp(
            &case.i16s("a"),
            case.i16("coder_type"),
            &mut synth,
            &mut p_t,
            &mut pgain_t,
            case.i16("stab_fac"),
            &mut st,
            &mut pitch_buffer,
            &mut voice_factors,
            &mut bwe_exc,
        );
        let what = |name: &str| format!("{context}: {name}");
        check(case, &what("synth"), &synth, &case.out_i16s("synth"));
        check(case, &what("p_t"), &p_t, &case.out_i16s("p_t"));
        check(case, &what("pgain_t"), &pgain_t, &case.out_i16s("pgain_t"));
        check(
            case,
            &what("pitch_buffer"),
            &pitch_buffer,
            &case.out_i16s("pitch_buffer"),
        );
        check(
            case,
            &what("voice_factors"),
            &voice_factors,
            &case.out_i16s("voice_factors"),
        );
        check(case, &what("bwe_exc"), &bwe_exc, &case.out_i16s("bwe_exc"));
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}
