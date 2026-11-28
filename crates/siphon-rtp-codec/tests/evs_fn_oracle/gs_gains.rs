//! `lib_com/gs_gains_fx.c` (decoder side) against `fn_gs_gains`. `Comp_band_log_ener` is proven
//! through `Ener_per_band_comp`, `GSC_gain_adj` and `VDQ_vec` through `gsc_gaindec`.

use siphon_rtp_codec::evs::com::gs_gains::{comp_and_apply_gain, ener_per_band_comp, gsc_gaindec};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

#[test]
fn comp_and_apply_gain_matches_the_reference() {
    let Some(cases) = corpus("gs_gains", "comp_and_apply_gain") else {
        return;
    };
    for case in &cases {
        let mut exc = case.i16s("exc_diff_q");
        let mut ener_y = case.i16s("ener_y");
        comp_and_apply_gain(
            &mut exc,
            &case.i16s("ener_i"),
            &mut ener_y,
            case.i16("mbands_gn"),
            case.i16("re_use_gain"),
            case.i16("qexc_diff"),
            case.i16("q_exc"),
        );
        let rust = [exc, ener_y].concat();
        let reference = [case.out_i16s("exc_diff_q"), case.out_i16s("ener_y")].concat();
        if let Some(message) = mismatch(case, "exc_diff_q/ener_y", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn ener_per_band_comp_matches_the_reference() {
    let Some(cases) = corpus("gs_gains", "ener_per_band_comp") else {
        return;
    };
    for case in &cases {
        let mut y_gain4 = vec![-12345i16; 18];
        ener_per_band_comp(
            &case.i16s("exc_diff"),
            &mut y_gain4,
            case.i16("q_exc"),
            case.i16("mband"),
            case.i16("eflag"),
        );
        if let Some(message) = mismatch(case, "y_gain4", &y_gain4, &case.out_i16s("y_gain4")) {
            panic!("{message}");
        }
    }
}

#[test]
fn gsc_gaindec_matches_the_reference() {
    let Some(cases) = corpus("gs_gains", "gsc_gaindec") else {
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
        let mut y_gain_q = case.i16s("y_gain_q");
        let mut old_y_gain = case.i16s("old_y_gain");
        let mean = gsc_gaindec(
            &mut st,
            &mut y_gain_q,
            case.i32("core_brate"),
            &mut old_y_gain,
            case.i16("coder_type"),
            case.i16("bwidth"),
        );
        let rust = [vec![mean], y_gain_q, old_y_gain, vec![st.next_bit_pos]].concat();
        let reference = [
            vec![case.out_i16("mean")],
            case.out_i16s("y_gain_q"),
            case.out_i16s("old_y_gain"),
            vec![case.out_i16("next_bit_pos")],
        ]
        .concat();
        if let Some(message) = mismatch(
            case,
            "mean/y_gain_q/old_y_gain/next_bit_pos",
            &rust,
            &reference,
        ) {
            panic!("{message}");
        }
    }
}
