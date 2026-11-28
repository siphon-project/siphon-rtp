//! `lib_dec/lp_exc_d_fx.c` against `fn_lp_exc_d`.

use siphon_rtp_codec::evs::dec::lp_exc_d::lp_filt_exc_dec;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

/// Where the harness points the C's `exc` inside its buffer.
const EXC_AT: usize = 8;

#[test]
fn lp_filt_exc_dec_matches_the_reference() {
    let Some(cases) = corpus("lp_exc_d", "lp_filt_exc_dec") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.next_bit_pos = case.i16("next_bit_pos");
        st.codec_mode = case.i16("codec_type");
        let mut exc = case.i16s("exc");
        lp_filt_exc_dec(
            &mut st,
            case.i16("codec_type"),
            case.i32("core_brate"),
            case.i16("opt_amr_wb"),
            case.i16("coder_type"),
            case.i16("i_subfr"),
            case.i16("l_subfr"),
            case.i16("l_frame"),
            case.i16("lp_flag"),
            &mut exc,
            EXC_AT,
        );
        let rust = [exc, vec![st.next_bit_pos, st.ber_detect]].concat();
        let reference = [
            case.out_i16s("exc"),
            vec![case.out_i16("next_bit_pos"), case.out_i16("ber_detect")],
        ]
        .concat();
        if let Some(message) = mismatch(case, "exc/next_bit_pos/ber_detect", &rust, &reference) {
            panic!("{message}");
        }
    }
}
