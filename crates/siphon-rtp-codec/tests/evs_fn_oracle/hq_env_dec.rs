//! `lib_dec/hq_env_dec_fx.c` (`decode_envelope_indices_fx`, `dequantize_norms_fx`) against
//! `fn_hq_env_dec`.

use siphon_rtp_codec::evs::dec::hq_env_dec::{decode_envelope_indices, dequantize_norms};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn decode_envelope_indices_matches_the_reference() {
    let Some(cases) = corpus("hq_env_dec", "decode_envelope_indices") else {
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
        let mut difidx = vec![-7i16; 44];
        let hcode_l = decode_envelope_indices(
            &mut st,
            case.i16("start_norm"),
            case.i16("num_sfm"),
            case.i16("numnrmibits"),
            &mut difidx,
            case.i16("flag_hq2"),
            case.i16("is_transient"),
        );
        let rust = [vec![hcode_l], difidx, vec![st.next_bit_pos, st.ber_detect]].concat();
        let reference = [
            vec![case.out_i16("hcode_l")],
            case.out_i16s("difidx"),
            vec![case.out_i16("next_bit_pos"), case.out_i16("ber_detect")],
        ]
        .concat();
        if let Some(message) = mismatch(
            case,
            "hcode_l/difidx/next_bit_pos/ber_detect",
            &rust,
            &reference,
        ) {
            panic!("{message}");
        }
    }
}

#[test]
fn dequantize_norms_matches_the_reference() {
    let Some(cases) = corpus("hq_env_dec", "dequantize_norms") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let mut ynrm = case.i16s("ynrm");
        let mut normqlg2 = vec![-4i16; 44];
        dequantize_norms(
            &mut st,
            case.i16("start_norm"),
            case.i16("num_sfm"),
            case.i16("is_transient"),
            &mut ynrm,
            &mut normqlg2,
        );
        for (name, rust) in [
            ("ynrm", ynrm.clone()),
            ("normqlg2", normqlg2.clone()),
            ("ber_detect", vec![st.ber_detect]),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
