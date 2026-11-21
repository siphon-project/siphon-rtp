//! `lib_dec/decision_matrix_dec_fx.c` against `fn_decision_matrix_dec`.

use siphon_rtp_codec::evs::dec::decision_matrix_dec::decision_matrix_dec;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

/// Every state field the oracle prints, by its oracle name.
macro_rules! fields {
    ($m:ident) => {
        $m!(
            core,
            core_brate,
            extl,
            extl_brate,
            ppp_mode_dec,
            nelp_mode_dec,
            igf,
            vbr_hw_bwe_disable_dec,
            mdct_sw,
            total_brate,
            cng_type,
            l_frame,
            bwidth,
            output_fs,
            prev_bfi,
            bfi,
            last_cng_l_frame,
            fscale,
            ini_frame,
            last_l_frame,
            last_core,
            last_core_brate,
            last_extl,
            ber_detect,
            last_total_brate,
            last_coder_type,
            last_bwidth,
            last_total_brate_ber,
            last_core_bfi,
            codec_mode,
            last_l_frame_ori,
            first_cng,
            act_cnt2,
            nb_subfr,
            next_bit_pos
        )
    };
}

#[test]
fn decision_matrix_dec_matches_the_reference() {
    let Some(cases) = corpus("decision_matrix_dec", "decision_matrix") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        macro_rules! set {
            ($($name:ident),*) => {
                $( st.$name = case.inputs[stringify!($name)][0] as _; )*
            };
        }
        fields!(set);
        let mut coder_type = case.i16("coder_type");
        let mut sharp_flag = case.i16("sharp_flag");
        let mut hq_core_type = case.i16("hq_core_type");
        let mut core_switching_flag = case.i16("core_switching_flag");
        decision_matrix_dec(
            &mut st,
            &mut coder_type,
            &mut sharp_flag,
            &mut hq_core_type,
            &mut core_switching_flag,
        );
        let mut rust: Vec<(&str, i64)> = vec![
            ("coder_type", coder_type.into()),
            ("sharp_flag", sharp_flag.into()),
            ("hq_core_type", hq_core_type.into()),
            ("core_switching_flag", core_switching_flag.into()),
        ];
        macro_rules! get {
            ($($name:ident),*) => {
                $( rust.push((stringify!($name), i64::from(st.$name))); )*
            };
        }
        fields!(get);
        for (name, value) in rust {
            if let Some(message) = mismatch(case, name, &value, &case.outputs[name][0]) {
                panic!("{message}");
            }
        }
    }
}
