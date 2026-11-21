//! `lib_dec/dec4t64_fx.c` against `fn_dec4t64` (`D_ACELP_decode_43bit` and its helpers).

use siphon_rtp_codec::evs::dec::dec4t64::{d_acelp_decode_43bit, dec_acelp_4t64};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

/// `dec_acelp_4t64_fx` on random bitstreams; proves `dec_1p_N1` ... `dec_6p_6N2` through it.
#[test]
fn dec_acelp_4t64_matches_the_reference() {
    let Some(cases) = corpus("dec4t64", "acelp_4t64") else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        let bits = case.i32s("bits");
        st.bit_stream.fill(0);
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.next_bit_pos = case.i16("next_bit_pos");
        st.ber_detect = 0;
        let mut code = case.i16s("code");
        dec_acelp_4t64(
            &mut st,
            case.i16("nbbits"),
            &mut code,
            case.i16("opt_amr_wb"),
        );
        for (name, rust) in [
            ("code", code),
            ("next_bit_pos", vec![st.next_bit_pos]),
            ("ber_detect", vec![st.ber_detect]),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}

#[test]
fn d_acelp_decode_43bit_matches_the_reference() {
    let Some(cases) = corpus("dec4t64", "decode_43bit") else {
        return;
    };
    for case in &cases {
        let idxs: Vec<u16> = case.i32s("idxs").iter().map(|&v| v as u16).collect();
        let mut code = vec![0x1234; 64];
        d_acelp_decode_43bit(&idxs, &mut code, &[3, 3, 2, 2]);
        if let Some(message) = mismatch(case, "code", &code, &case.out_i16s("code")) {
            panic!("{message}");
        }
    }
}
