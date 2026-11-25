//! The MODE2 LPC dequantisation front end against `fn_m2lpc_lpc`: `AVQ_dec_lpc`, `vlpc_1st_dec`,
//! `vlpc_2st_dec` (with `lsf_weight_2st`), `dlpc_avq`, `decode_lpc_avq`, `lpc_unquantize`,
//! `dlpc_bfi` and the guided-PLC helpers `modify_lsf`, `reorder_lsfs` and
//! `RecLpcSpecPowDiffuseLc`.

use siphon_rtp_codec::evs::com::dlpc_bfi::dlpc_bfi;
use siphon_rtp_codec::evs::com::guided_plc_util::{
    modify_lsf, rec_lpc_spec_pow_diffuse_lc, reorder_lsfs,
};
use siphon_rtp_codec::evs::com::mslvq_com::init_lvq;
use siphon_rtp_codec::evs::com::vlpc_2st_com::lsf_weight_2st;
use siphon_rtp_codec::evs::dec::avq_dec::avq_dec_lpc;
use siphon_rtp_codec::evs::dec::dlpc_avq::{decode_lpc_avq, dlpc_avq};
use siphon_rtp_codec::evs::dec::dlpc_stoch::lpc_unquantize;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::vlpc_1st_dec::vlpc_1st_dec;
use siphon_rtp_codec::evs::dec::vlpc_2st_dec::vlpc_2st_dec;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("m2lpc_lpc", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

fn stream(case: &Case, total_bits: i16) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.inputs["bits"]) {
        *slot = bit as u16;
    }
    st.total_num_bits = total_bits;
    st.next_bit_pos = case.i16("start");
    st.codec_mode = 2;
    st
}

#[test]
fn avq_dec_lpc_matches_the_reference() {
    each("avq_dec_lpc", |case| {
        let mut nvecq = vec![4321i16; 16];
        avq_dec_lpc(&case.i16s("indx"), &mut nvecq, 2);
        check(case, "nvecq", &nvecq, &case.out_i16s("nvecq"));
    });
}

#[test]
fn vlpc_1st_dec_matches_the_reference() {
    each("vlpc_1st", |case| {
        let mut lsfq = case.i16s("lsfq");
        vlpc_1st_dec(case.i16("index"), &mut lsfq);
        check(case, "lsfq", &lsfq, &case.out_i16s("lsfq"));
    });
}

#[test]
fn lsf_weight_2st_matches_the_reference() {
    each("weight", |case| {
        let mut w = vec![4321i16; 16];
        lsf_weight_2st(&case.i16s("lsfq"), &mut w, case.i16("mode"));
        check(case, "w", &w, &case.out_i16s("w"));
    });
}

#[test]
fn vlpc_2st_dec_matches_the_reference() {
    each("vlpc_2st", |case| {
        let mut lsfq = case.i16s("lsfq");
        vlpc_2st_dec(
            &mut lsfq,
            &case.i16s("indx"),
            case.i16("mode"),
            case.i32("sr_core"),
        );
        check(case, "lsfq", &lsfq, &case.out_i16s("lsfq"));
    });
}

#[test]
fn decode_lpc_avq_matches_the_reference() {
    each("decode_lpc_avq", |case| {
        let mut st = stream(case, 640);
        let mut param = vec![77i16; 136];
        let r = decode_lpc_avq(&mut st, case.i16("numlpc"), &mut param);
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "param", &param, &case.out_i16s("param"));
        check(case, "pos", &st.next_bit_pos, &case.out_i16("pos"));
        check(case, "ber", &st.ber_detect, &case.out_i16("ber"));
    });
}

#[test]
fn dlpc_avq_matches_the_reference() {
    each("dlpc_avq", |case| {
        let numlpc = case.i16("numlpc");
        let mut lsf_q = vec![4321i16; 32];
        let r = dlpc_avq(&case.i16s("param"), &mut lsf_q, numlpc, case.i32("sr_core"));
        check(case, "r", &r, &case.out_i16("r"));
        check(
            case,
            "lsf_q",
            &lsf_q[..16 * numlpc as usize].to_vec(),
            &case.out_i16s("lsf_q"),
        );
    });
}

#[test]
fn lpc_unquantize_matches_the_reference() {
    each("lpc_unquantize", |case| {
        let mut st = Box::new(DecoderState::zeroed());
        let st_ref = &mut *st;
        init_lvq(
            &mut st_ref.offset_scale1,
            &mut st_ref.offset_scale2,
            &mut st_ref.offset_scale1_p,
            &mut st_ref.offset_scale2_p,
            &mut st_ref.no_scales,
            &mut st_ref.no_scales_p,
        );
        st.sr_core = case.i32("sr_core");
        st.core = case.i16("core");
        st.core_brate = case.i32("core_brate");
        st.total_brate = st.core_brate;
        st.lsf_old.copy_from_slice(&case.i16s("lsf_old"));
        st.lsp_old.copy_from_slice(&case.i16s("lsp_old"));
        st.mem_ar.copy_from_slice(&case.i16s("mem_ar"));
        st.mem_ma.copy_from_slice(&case.i16s("mem_ma"));
        st.reset_mem_ar = case.i16("reset_mem_ar");
        st.mid_lsf_int = case.i16("mid_lsf_int");
        st.safety_net = case.i16("safety_net");
        st.rate_switching_reset = case.i16("rate_switching_reset");
        st.seed_acelp = case.i16("seed");
        st.numlpc = case.i16("numlpc");
        st.lpc_quantization = case.i16("lpcq");
        st.narrow_band = case.i16("narrow_band") as i8;

        let (lsf_old, lsp_old) = (st.lsf_old, st.lsp_old);
        let mut lsf = vec![-3i16; 48];
        let mut lsp = vec![-3i16; 48];
        let mut lspmid = vec![-4i16; 16];
        let mut lsfmid = vec![-4i16; 16];
        let mut pred = -7;
        lpc_unquantize(
            &mut st,
            &lsf_old,
            &lsp_old,
            &mut lsf,
            &mut lsp,
            16,
            case.i16("lpcq"),
            &case.i16s("param"),
            case.i16("numlpc"),
            case.i16("core"),
            &mut lspmid,
            &mut lsfmid,
            case.i16("coder_type"),
            case.i16("mid_lpc"),
            case.i16("narrow_band") as i8,
            case.i32("sr_core"),
            case.i16("prev_bfi"),
            &mut pred,
        );
        check(case, "lsf", &lsf, &case.out_i16s("lsf"));
        check(case, "lsp", &lsp, &case.out_i16s("lsp"));
        check(case, "lspmid", &lspmid, &case.out_i16s("lspmid"));
        check(case, "lsfmid", &lsfmid, &case.out_i16s("lsfmid"));
        check(case, "pred", &pred, &case.out_i16("pred"));
        check(case, "seed", &st.seed_acelp, &case.out_i16("seed"));
        check(
            case,
            "mid_lsf_int",
            &st.mid_lsf_int,
            &case.out_i16("mid_lsf_int"),
        );
        check(
            case,
            "safety_net",
            &st.safety_net,
            &case.out_i16("safety_net"),
        );
        check(
            case,
            "mem_ar",
            &st.mem_ar.to_vec(),
            &case.out_i16s("mem_ar"),
        );
        check(
            case,
            "mem_ma",
            &st.mem_ma.to_vec(),
            &case.out_i16s("mem_ma"),
        );
        check(
            case,
            "reset_mem_ar",
            &st.reset_mem_ar,
            &case.out_i16("reset_mem_ar"),
        );
    });
}

#[test]
fn dlpc_bfi_matches_the_reference() {
    each("dlpc_bfi", |case| {
        let mut lsf_q = vec![-1i16; 32];
        let mut mem_ma = case.i16s("mem_ma");
        let mut mem_ar = case.i16s("mem_ar");
        let mut lsf_q_cng = vec![-1i16; 16];
        let (have_cng, have_q_cng) = (case.i16("have_cng") != 0, case.i16("have_q_cng") != 0);
        let (lsf_cng, old_q_cng) = (case.i16s("lsf_cng"), case.i16s("old_q_cng"));
        dlpc_bfi(
            case.i16("l_frame"),
            &mut lsf_q,
            &case.i16s("lsfold"),
            case.i16("last_good"),
            case.i16("lost"),
            &mut mem_ma,
            &mut mem_ar,
            case.i16("stab_fac"),
            &case.i16s("mean"),
            case.i16("numlpc"),
            have_cng.then_some(&lsf_cng[..]),
            case.i16("plc_updated") as i8,
            have_q_cng.then_some(&mut lsf_q_cng[..]),
            have_q_cng.then_some(&old_q_cng[..]),
            Some(&case.i16s("base")),
            case.i16("tcxonly") as i8,
        );
        check(case, "lsf_q", &lsf_q, &case.out_i16s("lsf_q"));
        check(case, "mem_ma", &mem_ma, &case.out_i16s("mem_ma"));
        check(case, "mem_ar", &mem_ar, &case.out_i16s("mem_ar"));
        check(case, "lsf_q_cng", &lsf_q_cng, &case.out_i16s("lsf_q_cng"));
    });
}

#[test]
fn modify_lsf_matches_the_reference() {
    each("modify_lsf", |case| {
        let mut lsf = case.i16s("lsf");
        modify_lsf(&mut lsf, 16, case.i32("sr_core"), case.i16("reset_q"));
        check(case, "lsf", &lsf, &case.out_i16s("lsf"));
    });
}

#[test]
fn reorder_lsfs_matches_the_reference() {
    each("reorder_lsfs", |case| {
        let mut lsf = case.i16s("lsf");
        reorder_lsfs(&mut lsf, case.i16("min_dist"), 16, case.i32("sr_core"));
        check(case, "lsf", &lsf, &case.out_i16s("lsf"));
    });
}

#[test]
fn rec_lpc_spec_pow_diffuse_lc_matches_the_reference() {
    each("rec_lpc", |case| {
        let mut st = Box::new(DecoderState::zeroed());
        st.sr_core = case.i32("sr_core");
        st.lpc_quantization = case.i16("lpcq");
        st.narrow_band = case.i16("narrow_band") as i8;
        st.lsf_old.copy_from_slice(&case.i16s("lsf_old"));
        st.mem_ma.copy_from_slice(&case.i16s("mem_ma"));
        let mut lspq = vec![-1i16; 16];
        let mut lsp_old = vec![-1i16; 16];
        let mut lsfq = case.i16s("lsfq");
        rec_lpc_spec_pow_diffuse_lc(&mut lspq, &mut lsp_old, &mut lsfq, &st, case.i16("reset_q"));
        check(case, "lspq", &lspq, &case.out_i16s("lspq"));
        check(case, "lsp_old", &lsp_old, &case.out_i16s("lsp_old"));
        check(case, "lsfq", &lsfq, &case.out_i16s("lsfq"));
    });
}
