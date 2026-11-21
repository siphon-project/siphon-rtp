//! `lib_dec/dec2t32_fx.c` against `fn_dec2t32`.

use siphon_rtp_codec::evs::dec::dec2t32::{dec_acelp_1t64, dec_acelp_2t32};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch, Case};

fn state(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    let bits = case.i16s("bits");
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
        *slot = bit as u16;
    }
    st.total_num_bits = bits.len() as i16;
    st.next_bit_pos = case.i16("next_bit_pos");
    st.codec_mode = 1;
    st
}

fn check(function: &str, decode: fn(&mut DecoderState, &mut [i16])) {
    let Some(cases) = corpus("dec2t32", function) else {
        return;
    };
    for case in &cases {
        let mut st = state(case);
        let mut code = [0x5555i16; 64];
        decode(&mut st, &mut code);
        let rust = [code.to_vec(), vec![st.next_bit_pos, st.ber_detect]].concat();
        let reference = [
            case.out_i16s("code"),
            vec![case.out_i16("next_bit_pos"), case.out_i16("ber_detect")],
        ]
        .concat();
        if let Some(message) = mismatch(case, "code/next_bit_pos/ber_detect", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn dec_acelp_2t32_matches_the_reference() {
    check("acelp_2t32", dec_acelp_2t32);
}

#[test]
fn dec_acelp_1t64_matches_the_reference() {
    check("acelp_1t64", dec_acelp_1t64);
}
