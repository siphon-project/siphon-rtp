//! `lib_dec/dec_higher_acelp_fx.c` against `fn_dec_higher_acelp`.

use siphon_rtp_codec::evs::dec::dec_higher_acelp::{gain_dequant, transf_cdbk_dec};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn gain_dequant_matches_the_reference() {
    let Some(cases) = corpus("dec_higher_acelp", "gain_dequant") else {
        return;
    };
    for case in &cases {
        let mut expg = -99;
        let gain = gain_dequant(
            case.i16("index"),
            case.i16("min"),
            case.i16("max"),
            case.i16("bits"),
            &mut expg,
        );
        if let Some(message) = mismatch(case, "gain", &gain, &case.out_i16("gain"))
            .or_else(|| mismatch(case, "expg", &expg, &case.out_i16("expg")))
        {
            panic!("{message}");
        }
    }
}

/// `transf_cdbk_dec_fx` above 24.4 kbit/s; proves the AVQ demultiplexing, the 64-point
/// `edct2_fx`, the preemphasis and the normalised gain on decoded frames.
#[test]
fn transf_cdbk_dec_matches_the_reference() {
    let Some(cases) = corpus("dec_higher_acelp", "transf_cdbk_dec") else {
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
        st.codec_mode = 1;
        st.ber_detect = 0;
        st.last_nq_pre_q = case.i16("last_nq_preq");
        st.use_acelp_preq = 0;
        let mut mem_preemp = case.i16("mem_preemp");
        let mut unbits = case.i16("unbits");
        let mut gain_pre_q = -1;
        let mut norm_gain_pre_q = -1;
        let mut code_pre_q = case.i16s("code_preq");
        transf_cdbk_dec(
            &mut st,
            case.i32("core_brate"),
            case.i16("coder_type"),
            case.i16("harm_flag"),
            case.i16("i_subfr"),
            case.i16("tc_subfr"),
            case.i16("es_pred"),
            case.i32("gain_code"),
            &mut mem_preemp,
            &mut gain_pre_q,
            &mut norm_gain_pre_q,
            &mut code_pre_q,
            &mut unbits,
        );
        let scalars = [
            ("gain_preq", i32::from(gain_pre_q)),
            ("norm_gain_preq", norm_gain_pre_q),
            ("mem_preemp", i32::from(mem_preemp)),
            ("unbits", i32::from(unbits)),
            ("last_nq_preq", i32::from(st.last_nq_pre_q)),
            ("use_acelp_preq", i32::from(st.use_acelp_preq)),
            ("next_bit_pos", i32::from(st.next_bit_pos)),
            ("ber_detect", i32::from(st.ber_detect)),
        ];
        for (name, rust) in scalars {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i32(name)) {
                panic!("{message}");
            }
        }
        if let Some(message) = mismatch(case, "code_preq", &code_pre_q, &case.out_i16s("code_preq"))
        {
            panic!("{message}");
        }
    }
}
