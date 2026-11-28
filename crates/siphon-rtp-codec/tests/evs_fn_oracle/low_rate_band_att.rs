//! `lib_com/low_rate_band_att_fx.c` against `fn_low_rate_band_att`.

use siphon_rtp_codec::evs::com::low_rate_band_att::{
    fine_gain_dec, fine_gain_pred, get_max_pulses,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn fine_gain_pred_matches_the_reference() {
    let Some(cases) = corpus("low_rate_band_att", "fine_gain_pred") else {
        return;
    };
    for case in &cases {
        let sort = case.i16s("i_sort");
        let r = case.i16s("r");
        let (mut xq, mut y, mut fg_pred) = (case.i16s("xq"), case.i16s("y"), case.i16s("fg_pred"));
        fine_gain_pred(
            &case.i16s("sfm_start"),
            &case.i16s("sfm_end"),
            &case.i16s("sfm_size"),
            &sort,
            &case.i16s("k"),
            &case.i16s("maxpulse"),
            (case.i16("use_r") != 0).then_some(r.as_slice()),
            sort.len() as i16,
            &mut xq,
            &mut y,
            &mut fg_pred,
            case.i16("core"),
        );
        let rust = [xq, y, fg_pred].concat();
        let reference = [
            case.out_i16s("xq"),
            case.out_i16s("y"),
            case.out_i16s("fg_pred"),
        ]
        .concat();
        if let Some(message) = mismatch(case, "xq/y/fg_pred", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn get_max_pulses_matches_the_reference() {
    let Some(cases) = corpus("low_rate_band_att", "get_max_pulses") else {
        return;
    };
    for case in &cases {
        let sort = case.i16s("k_sort");
        let mut maxpulse = case.i16s("maxpulse");
        get_max_pulses(
            &case.i16s("band_start"),
            &case.i16s("band_end"),
            &sort,
            &case.i16s("npulses"),
            sort.len() as i16,
            &case.i16s("inp_vector"),
            &mut maxpulse,
        );
        if let Some(message) = mismatch(case, "maxpulse", &maxpulse, &case.out_i16s("maxpulse")) {
            panic!("{message}");
        }
    }
}

#[test]
fn fine_gain_dec_matches_the_reference() {
    let Some(cases) = corpus("low_rate_band_att", "fine_gain_dec") else {
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
        let ord = case.i16s("ord");
        let mut fg_pred = case.i16s("fg_pred");
        fine_gain_dec(
            &mut st,
            &ord,
            ord.len() as i16,
            &case.i16s("gain_bits"),
            &mut fg_pred,
        );
        let rust = [fg_pred, vec![st.next_bit_pos, st.ber_detect]].concat();
        let reference = [
            case.out_i16s("fg_pred"),
            vec![case.out_i16("next_bit_pos"), case.out_i16("ber_detect")],
        ]
        .concat();
        if let Some(message) = mismatch(case, "fg_pred/next_bit_pos/ber_detect", &rust, &reference)
        {
            panic!("{message}");
        }
    }
}
