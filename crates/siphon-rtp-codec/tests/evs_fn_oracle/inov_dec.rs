//! `lib_dec/inov_dec_fx.c` against `fn_inov_dec`.

use siphon_rtp_codec::evs::dec::inov_dec::inov_decode;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

/// `inov_decode_fx` over every bit-allocation row of both ACELP cores and every AMR-WB IO rate;
/// proves the codebook dispatch, the formant-sharpening gains and the `cb_shape_fx` call.
#[test]
fn inov_decode_matches_the_reference() {
    let Some(cases) = corpus("inov_dec", "inov_decode") else {
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
        st.stl.carry = case.i16("carry") != 0;
        let mut code = case.i16s("code");
        inov_decode(
            &mut st,
            case.i32("core_brate"),
            case.i16("opt_amr_wb"),
            case.i16("l_frame"),
            case.i16("coder_type"),
            case.i16("sharp"),
            case.i16("i_subfr"),
            case.i16("tc_subfr"),
            &case.i16s("a"),
            case.i16("tilt_code"),
            case.i16("pt_pitch"),
            &mut code,
        );
        for (name, rust) in [
            ("code", code),
            ("next_bit_pos", vec![st.next_bit_pos]),
            ("ber_detect", vec![st.ber_detect]),
            ("carry", vec![i16::from(st.stl.carry)]),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
