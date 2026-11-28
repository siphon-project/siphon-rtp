//! `lib_dec/FEC_clas_estim_fx.c` against `fn_FEC_clas_estim`.

use siphon_rtp_codec::evs::dec::fec_clas_estim::{corre, fec_clas_estim, fec_pos_dec};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch, Case};

fn check(case: &Case, name: &str, rust: &[i16]) {
    if let Some(message) = mismatch(case, name, &rust.to_vec(), &case.out_i16s(name)) {
        panic!("{message}");
    }
}

/// `FEC_clas_estim_fx` in all four caller configurations (MODE1 ACELP, MODE1 AMR-WB IO, the MODE2
/// ACELP and TCX classifiers), after zero to three warm-up calls on the same state.
#[test]
fn fec_clas_estim_matches_the_reference() {
    let Some(cases) = corpus("FEC_clas_estim", "clas_estim") else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        st.codec_mode = case.i16("codec_mode");
        st.tcxonly = case.i16("tcxonly") as i8;
        st.narrow_band = case.i16("narrow_band") as i8;
        st.preemph_fac = case.i16("preemph_fac");
        st.last_l_frame = case.i16("last_l_frame");
        st.l_frame = case.i16("l_frame");
        st.clas_dec = case.i16("clas");
        st.lp_ener_fer = case.i16("lp_ener_fer");
        st.decision_hyst = case.i16("decision_hyst");
        st.uv_cnt = case.i16("uv_cnt");
        st.lt_uv_cnt = case.i16("lt_uv_cnt");
        st.last_ener = case.i16("last_ener");
        st.lt_diff_etot.copy_from_slice(&case.i16s("lt_diff_etot"));
        st.mem_syn_clas_estim.copy_from_slice(&case.i16s("mem"));
        st.classifier_q_mem_syn = case.i16("q_mem_syn");
        st.stl.carry = case.i16("carry") != 0;
        let mut locattack = case.i16("locattack");
        let mut amr_io_class = case.i16("amr_io_class");
        let mut class_para = case.i16("class_para");
        let opt_amr_wb = case.i16("opt_amr_wb");
        let mode1 = st.codec_mode == 1;
        fec_clas_estim(
            &mut st,
            opt_amr_wb,
            case.i16("l_frame"),
            case.i16("coder_type"),
            &case.i16s("pitch"),
            &case.i16s("syn"),
            1,
            (opt_amr_wb != 0).then_some(&mut locattack),
            (opt_amr_wb != 0).then_some(&mut amr_io_class),
            case.i32("bitrate"),
            case.i16("q_syn"),
            mode1.then_some(&mut class_para),
            case.i16("ltp_gain"),
            case.i16("mode"),
            case.i16("bfi"),
            case.i32("last_core_brate"),
        );
        check(case, "clas", &[st.clas_dec]);
        check(case, "lp_ener_fer", &[st.lp_ener_fer]);
        check(case, "decision_hyst", &[st.decision_hyst]);
        check(case, "uv_cnt", &[st.uv_cnt]);
        check(case, "lt_uv_cnt", &[st.lt_uv_cnt]);
        check(case, "last_ener", &[st.last_ener]);
        check(case, "lt_diff_etot", &st.lt_diff_etot);
        check(case, "mem", &st.mem_syn_clas_estim);
        check(case, "q_mem_syn", &[st.classifier_q_mem_syn]);
        check(case, "carry", &[i16::from(st.stl.carry)]);
        check(case, "locattack", &[locattack]);
        check(case, "amr_io_class", &[amr_io_class]);
        check(case, "class_para", &[class_para]);
    }
}

#[test]
fn corre_matches_the_reference() {
    let Some(cases) = corpus("FEC_clas_estim", "corre") else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let gain = corre(&x, &case.i16s("y"), x.len() as i16);
        check(case, "gain", &[gain]);
    }
}

/// `FEC_pos_dec_fx` on random bitstreams; proves `FEC_dec_class_fx` through it.
#[test]
fn fec_pos_dec_matches_the_reference() {
    let Some(cases) = corpus("FEC_clas_estim", "pos_dec") else {
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
        st.ber_detect = case.i16("ber_detect");
        st.bwidth = case.i16("bwidth");
        let mut last_pulse_pos = case.i16("last_pulse_pos");
        let mut clas = case.i16("clas");
        let mut enr_q = case.i32("enr_q");
        let t0 = fec_pos_dec(
            &mut st,
            case.i16("coder_type"),
            case.i16("last_good"),
            &mut last_pulse_pos,
            &mut clas,
            &mut enr_q,
            case.i32("core_brate"),
        );
        check(case, "t0", &[t0]);
        check(case, "last_pulse_pos", &[last_pulse_pos]);
        check(case, "clas", &[clas]);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
        check(case, "ber_detect", &[st.ber_detect]);
        if let Some(message) = mismatch(case, "enr_q", &enr_q, &case.out_i32("enr_q")) {
            panic!("{message}");
        }
    }
}
