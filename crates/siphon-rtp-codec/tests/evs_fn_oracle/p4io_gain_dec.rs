//! `gain_dec_amr_wb_fx` (`lib_dec/gain_dec_fx.c`) against `fn_p4io_gain_dec`.

use siphon_rtp_codec::evs::dec::gain_dec::gain_dec_amr_wb;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn gain_dec_amr_wb_matches_the_reference() {
    let Some(cases) = corpus("p4io_gain_dec", "gain_dec_amr_wb") else {
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
        st.past_qua_en.copy_from_slice(&case.i16s("past_qua_en"));
        let (mut gain_pit, mut gain_code, mut gain_inov, mut norm_gain_code) = (0, 0, 0, 0);
        gain_dec_amr_wb(
            &mut st,
            case.i32("core_brate"),
            &mut gain_pit,
            &mut gain_code,
            &mut gain_inov,
            &case.i16s("code"),
            &mut norm_gain_code,
        );
        let message = mismatch(case, "gain_pit", &gain_pit, &case.out_i16("gain_pit"))
            .or_else(|| mismatch(case, "gain_code", &gain_code, &case.out_i32("gain_code")))
            .or_else(|| mismatch(case, "gain_inov", &gain_inov, &case.out_i16("gain_inov")))
            .or_else(|| {
                mismatch(
                    case,
                    "norm_gain_code",
                    &norm_gain_code,
                    &case.out_i32("norm_gain_code"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "past_qua_en",
                    &st.past_qua_en.to_vec(),
                    &case.out_i16s("past_qua_en"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "next_bit_pos",
                    &st.next_bit_pos,
                    &case.out_i16("next_bit_pos"),
                )
            });
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}
