//! `lib_dec/rst_dec_fx.c` against `fn_rst_dec`: `CNG_reset_dec_fx` at both internal rates.

use siphon_rtp_codec::evs::dec::rst_dec::cng_reset_dec;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn cng_reset_dec_matches_the_reference() {
    let Some(cases) = corpus("rst_dec", "cng_reset_dec") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        st.l_frame = case.i16("l_frame");
        st.lp_ener = case.i32("lp_ener");
        st.mem_ma = [5; 16];
        st.clas_dec = 3;
        st.last_good = 3;
        st.bpf_off = 0;
        st.act_cnt2 = 4;
        st.tilt_code = 9;
        st.lp_gainp = 9;
        let mut pitch_buf = vec![-7i16; 5];
        let mut voice_factors = vec![-7i16; 5];
        cng_reset_dec(&mut st, &mut pitch_buf, &mut voice_factors);
        let s = vec![
            st.lp_gainc,
            st.lp_gainp,
            st.tilt_code,
            st.clas_dec,
            st.last_good,
            st.bpf_off,
            st.act_cnt2,
        ];
        for (name, rust) in [
            ("pitch_buf", pitch_buf),
            ("voice_factors", voice_factors),
            ("st", s),
            ("mem_ar", st.mem_ar.to_vec()),
            ("mem_ma", st.mem_ma.to_vec()),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
