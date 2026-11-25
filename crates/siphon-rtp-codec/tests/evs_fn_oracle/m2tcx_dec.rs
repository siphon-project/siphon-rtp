//! The TCX decoder helpers (`lib_dec/tcx_utils_dec.c`, `tcx_ltp_decode_params` of
//! `lib_com/tcx_ltp.c`) against `fn_m2tcx_dec`.

use siphon_rtp_codec::evs::com::tcx_ltp::tcx_ltp_decode_params;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::tcx_utils_dec::{
    tcx_ari_res_inv_q_spec, tcx_decoder_memory_update, tcx_res_inv_q_gain, tcx_res_inv_q_spec,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn tcx_decoder_memory_update_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_dec", "tcx_decoder_memory_update") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        st.preemph_fac = case.i16("preemph_fac");
        st.tcxonly = case.i16("tcxonly") as i8;
        st.q_exc = case.i16("q_exc");
        st.q_syn = case.i16("q_syn");
        st.q_subfr.copy_from_slice(&case.i16s("q_subfr"));
        st.old_exc.copy_from_slice(&case.i16s("old_exc"));
        st.mem_syn2.copy_from_slice(&case.i16s("mem_syn2"));
        st.mem_syn_r.copy_from_slice(&case.i16s("mem_syn_r"));
        st.old_aq_12_8.copy_from_slice(&case.i16s("old_aq"));
        st.prev_q_syn = case.i16("prev_q_syn");
        let l_frame = case.i16("l_frame");
        let mut synthout = vec![0i16; l_frame as usize];
        let mut syn = case.i16s("syn");
        let xn_buf = case.i16s("xn_buf");
        tcx_decoder_memory_update(
            &xn_buf,
            &mut synthout,
            l_frame,
            &case.i16s("a"),
            &mut st,
            &mut syn,
            case.i16("fb") as i8,
        );
        check(case, "synthout", &synthout, &case.out_i16s("synthout"));
        check(case, "syn", &syn, &case.out_i16s("syn"));
        check(case, "q_syn", &st.q_syn, &case.out_i16("q_syn"));
        check(
            case,
            "prev_q_syn",
            &st.prev_q_syn,
            &case.out_i16("prev_q_syn"),
        );
        check(
            case,
            "mem_syn2",
            &st.mem_syn2.to_vec(),
            &case.out_i16s("mem_syn2"),
        );
        check(
            case,
            "mem_syn_r",
            &st.mem_syn_r.to_vec(),
            &case.out_i16s("mem_syn_r"),
        );
        check(case, "q_exc", &st.q_exc, &case.out_i16("q_exc"));
        check(
            case,
            "q_subfr",
            &st.q_subfr.to_vec(),
            &case.out_i16s("q_subfr"),
        );
        check(
            case,
            "old_exc",
            &st.old_exc.to_vec(),
            &case.out_i16s("old_exc"),
        );
        check(
            case,
            "old_aq",
            &st.old_aq_12_8.to_vec(),
            &case.out_i16s("old_aq"),
        );
        check(case, "xn_buf", &xn_buf, &case.out_i16s("xn_buf"));
    }
}

#[test]
fn tcx_ari_res_inv_q_spec_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_dec", "tcx_ari_res_invQ_spec") else {
        return;
    };
    for case in &cases {
        let mut x = case.i32s("x");
        let used = tcx_ari_res_inv_q_spec(
            &mut x,
            case.i16("x_e"),
            case.i16("l_frame"),
            &case.i16s("prm"),
            case.i16("target_bits"),
            case.i16("bits"),
            case.i16("deadzone"),
            &case.i16s("x_fac"),
        );
        check(case, "used", &used, &case.out_i16("used"));
        check(case, "x", &x, &case.out_i32s("x"));
    }
}

#[test]
fn tcx_res_inv_q_gain_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_dec", "tcx_res_invQ_gain") else {
        return;
    };
    for case in &cases {
        let (mut gain, mut gain_e) = (case.i16("gain"), case.i16("gain_e"));
        let used = tcx_res_inv_q_gain(
            &mut gain,
            &mut gain_e,
            &case.i16s("prm"),
            case.i16("res_q_bits"),
        );
        check(case, "used", &used, &case.out_i16("used"));
        check(case, "gain", &gain, &case.out_i16("gain"));
        check(case, "gain_e", &gain_e, &case.out_i16("gain_e"));
    }
}

#[test]
fn tcx_res_inv_q_spec_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_dec", "tcx_res_invQ_spec") else {
        return;
    };
    for case in &cases {
        let mut x = case.i32s("x");
        let lf = case.i16s("lf");
        let used = tcx_res_inv_q_spec(
            &mut x,
            case.i16("x_e"),
            case.i16("l_frame"),
            &case.i16s("prm"),
            case.i16("res_q_bits"),
            case.i16("bits"),
            case.i16("sq_round"),
            (case.i16("with_lf") != 0).then_some(&lf[..]),
        );
        check(case, "used", &used, &case.out_i16("used"));
        check(case, "x", &x, &case.out_i32s("x"));
    }
}

#[test]
fn tcx_ltp_decode_params_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_dec", "tcx_ltp_decode_params") else {
        return;
    };
    for case in &cases {
        let param = case.i16s("param");
        let core = case.i16s("core");
        let (mut pitch_int, mut pitch_fr, mut gain) = (0x1111, 0x2222, 0x3333);
        let r = tcx_ltp_decode_params(
            (case.i16("null_param") == 0).then_some(&param[..]),
            &mut pitch_int,
            &mut pitch_fr,
            &mut gain,
            core[0],
            core[1],
            core[2],
            core[3],
            core[4],
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "pitch_int", &pitch_int, &case.out_i16("pitch_int"));
        check(case, "pitch_fr", &pitch_fr, &case.out_i16("pitch_fr"));
        check(case, "gain", &gain, &case.out_i16("gain"));
    }
}
