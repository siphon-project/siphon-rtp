//! `lib_dec/pvq_decode_fx.c` against `fn_pvq_decode`: four consecutive PVQ codewords read from one
//! range-coded segment, the decoded vectors and the coder / BER state compared after each.

use siphon_rtp_codec::evs::dec::pvq_decode::pvq_decode;
use siphon_rtp_codec::evs::dec::range_dec::rc_dec_init;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn pvq_decode_matches_the_reference() {
    let Some(cases) = corpus("pvq_decode", "pvq_decode") else {
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
        st.codec_mode = 1;
        st.ber_occured_in_pvq = case.i16("ber_pvq");
        let (dim, k, gain) = (case.i16s("dim"), case.i16s("k"), case.i16s("gain"));
        rc_dec_init(&mut st, case.i16("tot_bits"));
        let mut trace = Vec::new();
        for c in 0..dim.len() {
            let mut xq = vec![-7i16; 64];
            let mut y = vec![-7i16; 64];
            pvq_decode(&mut st, &mut xq, &mut y, k[c], dim[c], gain[c]);
            for (name, rust) in [(format!("xq{c}"), &xq), (format!("y{c}"), &y)] {
                if let Some(message) = mismatch(case, &name, rust, &case.out_i16s(&name)) {
                    panic!("{message}");
                }
            }
            trace.extend_from_slice(&[
                st.rc_low as i32,
                st.rc_range as i32,
                i32::from(st.rc_num_bits),
                i32::from(st.rc_offset),
                i32::from(st.next_bit_pos),
                i32::from(st.ber_detect),
                i32::from(st.ber_occured_in_pvq),
                st.rc_help as i32,
            ]);
        }
        if let Some(message) = mismatch(case, "trace", &trace, &case.out_i32s("trace")) {
            panic!("{message}");
        }
    }
}
