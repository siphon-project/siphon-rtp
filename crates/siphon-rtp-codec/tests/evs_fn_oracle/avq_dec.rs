//! `lib_dec/avq_dec_fx.c` (`AVQ_demuxdec_fx`) against `fn_avq_dec`.

use siphon_rtp_codec::evs::cnst::MODE1;
use siphon_rtp_codec::evs::dec::avq_dec::avq_demuxdec;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

/// Random bitstreams biased towards long unary codes, so every codebook number, the Voronoi
/// extensions, the budget-exhausted stop bit and the corrupt-frame branch are reached.
#[test]
fn avq_demuxdec_matches_the_reference() {
    let Some(cases) = corpus("avq_dec", "avq_demuxdec") else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        let bits = case.i32s("bits");
        st.bit_stream.fill(0);
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = case.i16("total_num_bits");
        st.next_bit_pos = case.i16("next_bit_pos");
        st.codec_mode = MODE1;
        st.ber_detect = 0;
        let mut xriq = case.i16s("xriq");
        let mut nq = [7_i16; 8];
        let mut nb_bits = case.i16("nb_bits");
        avq_demuxdec(&mut st, &mut xriq, &mut nb_bits, case.i16("nsv"), &mut nq);
        for (name, rust) in [
            ("xriq", xriq),
            ("nq", nq.to_vec()),
            ("nb_bits", vec![nb_bits]),
            ("next_bit_pos", vec![st.next_bit_pos]),
            ("ber_detect", vec![st.ber_detect]),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
