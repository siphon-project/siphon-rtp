//! The MODE2 LSF quantisation helpers against `fn_m2lpc_lsf`: the ISP / ISF conversions, `msvq_dec`
//! and the MA memory update (`lib_com/lsf_tools_fx.c`), `midlsf_dec` / `lsf_ind_is_active`
//! (`lib_com/lsf_msvq_ma.c`) and the index readers and TCX LPC dequantiser of
//! `lib_dec/lsf_msvq_ma_dec.c`.

use siphon_rtp_codec::evs::com::lsf_msvq_ma::{lsf_ind_is_active, midlsf_dec};
use siphon_rtp_codec::evs::com::lsf_tools::{
    e_lpc_a_isp_conversion, e_lpc_isp_isf_conversion, isf2lsf, isp2lsp, lsf2isf, lsf_update_memory,
    lsp2isp, msvq_dec, tcxlpc_get_cdk,
};
use siphon_rtp_codec::evs::dec::lsf_msvq_ma_dec::{
    d_lsf_tcxlpc, dec_lsf_tcxlpc, lsf_bctcvq_decprm, lsf_msvq_ma_decprm,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::rom::{
    LSF_CODEBOOK, LSF_DIMS, LSF_IND_CODEBOOK, LSF_IND_DIMS, LSF_IND_OFFS, LSF_MEANS, LSF_OFFS,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("m2lpc_lsf", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

fn stream(case: &Case, total_bits: i16, brate: i32) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.inputs["bits"]) {
        *slot = bit as u16;
    }
    st.total_num_bits = total_bits;
    st.next_bit_pos = case.i16("start");
    st.codec_mode = 2;
    st.total_brate = brate;
    st
}

#[test]
fn e_lpc_a_isp_conversion_matches_the_reference() {
    each("a_isp", |case| {
        let mut isp = vec![4321i16; 16];
        e_lpc_a_isp_conversion(&case.i16s("a"), &mut isp, &case.i16s("old_isp"), 16);
        check(case, "isp", &isp, &case.out_i16s("isp"));
    });
}

#[test]
fn e_lpc_isp_isf_conversion_matches_the_reference() {
    each("isp_isf", |case| {
        let mut isf = vec![777i16; 16];
        e_lpc_isp_isf_conversion(&case.i16s("isp"), &mut isf, case.i16("m"));
        check(case, "isf", &isf, &case.out_i16s("isf"));
    });
}

#[test]
fn lsp2isp_matches_the_reference() {
    each("lsp2isp", |case| {
        let mut isp = vec![4321i16; 16];
        let mut stable = case.i16s("stable");
        lsp2isp(&case.i16s("lsp"), &mut isp, &mut stable, 16);
        check(case, "isp", &isp, &case.out_i16s("isp"));
        check(case, "stable", &stable, &case.out_i16s("stable"));
    });
}

#[test]
fn isp2lsp_matches_the_reference() {
    each("isp2lsp", |case| {
        let mut lsp = vec![4321i16; 16];
        let mut stable = case.i16s("stable");
        isp2lsp(&case.i16s("isp"), &mut lsp, &mut stable, 16);
        check(case, "lsp", &lsp, &case.out_i16s("lsp"));
        check(case, "stable", &stable, &case.out_i16s("stable"));
    });
}

#[test]
fn lsf2isf_matches_the_reference() {
    each("lsf2isf", |case| {
        let mut isf = vec![4321i16; 16];
        let mut stable = case.i16s("stable");
        lsf2isf(&case.i16s("lsf"), &mut isf, &mut stable, 16);
        check(case, "isf", &isf, &case.out_i16s("isf"));
        check(case, "stable", &stable, &case.out_i16s("stable"));
    });
}

#[test]
fn isf2lsf_matches_the_reference() {
    each("isf2lsf", |case| {
        let mut lsf = vec![4321i16; 16];
        let mut stable = case.i16s("stable");
        isf2lsf(&case.i16s("isf"), &mut lsf, &mut stable);
        check(case, "lsf", &lsf, &case.out_i16s("lsf"));
        check(case, "stable", &stable, &case.out_i16s("stable"));
    });
}

#[test]
fn lsf_update_memory_matches_the_reference() {
    each("update_memory", |case| {
        let mut mem = vec![5555i16; 16];
        lsf_update_memory(
            case.i16("narrowband"),
            &case.i16s("qlsf"),
            &case.i16s("old_mem"),
            &mut mem,
            case.i16("order"),
        );
        check(case, "mem", &mem, &case.out_i16s("mem"));
    });
}

#[test]
fn tcxlpc_get_cdk_matches_the_reference() {
    each("get_cdk", |case| {
        check(
            case,
            "r",
            &tcxlpc_get_cdk(case.i16("mode")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn msvq_dec_matches_the_reference() {
    each("msvq", |case| {
        let (nb, cdk) = (case.i16("nb") as usize, case.i16("cdk") as usize);
        let idx = case.i16s("idx");
        let mut uq = vec![999i16; 16];
        match case.i16("variant") {
            0 => msvq_dec(
                &LSF_CODEBOOK[nb][cdk],
                Some(&LSF_DIMS),
                Some(&LSF_OFFS),
                3,
                16,
                16,
                &idx,
                &mut uq,
            ),
            1 => msvq_dec(
                &LSF_IND_CODEBOOK[nb][cdk],
                Some(&LSF_IND_DIMS),
                Some(&LSF_IND_OFFS),
                1,
                16,
                16,
                &idx,
                &mut uq,
            ),
            2 => msvq_dec(&LSF_CODEBOOK[nb][cdk], None, None, 1, 16, 16, &idx, &mut uq),
            _ => msvq_dec(
                &LSF_CODEBOOK[nb][cdk],
                Some(&LSF_DIMS),
                None,
                1,
                16,
                16,
                &idx,
                &mut uq,
            ),
        }
        check(case, "uq", &uq, &case.out_i16s("uq"));
    });
}

#[test]
fn midlsf_dec_matches_the_reference() {
    each("midlsf", |case| {
        let mut q = vec![4321i16; 16];
        let mut mid = case.i16("mid");
        midlsf_dec(
            &case.i16s("q0"),
            &case.i16s("q1"),
            case.i16("idx"),
            &mut q,
            case.i16("coder_type"),
            (case.i16("decoder") != 0).then_some(&mut mid),
            case.i16("prev_bfi"),
            case.i16("safety_net"),
        );
        check(case, "q", &q, &case.out_i16s("q"));
        check(case, "mid", &mid, &case.out_i16("mid"));
    });
}

#[test]
fn lsf_ind_is_active_matches_the_reference() {
    each("ind_active", |case| {
        let nb = case.i16("nb");
        let r = lsf_ind_is_active(&case.i16s("q"), LSF_MEANS[nb as usize], nb, case.i16("cdk"));
        check(case, "r", &r, &case.out_i16("r"));
    });
}

#[test]
fn lsf_msvq_ma_decprm_matches_the_reference() {
    each("decprm", |case| {
        let mut st = stream(case, 300, case.i32("total_brate"));
        let mut param = vec![77i16; 10];
        let r = lsf_msvq_ma_decprm(
            &mut st,
            &mut param,
            case.i16("core"),
            case.i16("acelp_mode"),
            case.i16("mid_lpc"),
            case.i16("narrow"),
            case.i32("sr_core"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "param", &param, &case.out_i16s("param"));
        check(case, "pos", &st.next_bit_pos, &case.out_i16("pos"));
        check(case, "ber", &st.ber_detect, &case.out_i16("ber"));
    });
}

#[test]
fn lsf_bctcvq_decprm_matches_the_reference() {
    each("bctcvq", |case| {
        let mut st = stream(case, case.i16("total"), 24400);
        let mut param = vec![77i16; 12];
        let r = lsf_bctcvq_decprm(&mut st, &mut param);
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "param", &param, &case.out_i16s("param"));
        check(case, "pos", &st.next_bit_pos, &case.out_i16("pos"));
        check(case, "ber", &st.ber_detect, &case.out_i16("ber"));
    });
}

#[test]
fn d_lsf_tcxlpc_matches_the_reference() {
    each("d_lsf_tcxlpc", |case| {
        let mut lsf_q = vec![111i16; 16];
        let mut lsp = vec![222i16; 16];
        let r = d_lsf_tcxlpc(
            &case.i16s("indices"),
            &mut lsf_q,
            (case.i16("with_lsp") != 0).then_some(&mut lsp[..]),
            case.i16("nb"),
            case.i16("cdk"),
            &case.i16s("mem"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "lsf_q", &lsf_q, &case.out_i16s("lsf_q"));
        check(case, "lsp", &lsp, &case.out_i16s("lsp"));
    });
}

#[test]
fn dec_lsf_tcxlpc_matches_the_reference() {
    each("dec_lsf_tcxlpc", |case| {
        let mut st = stream(case, 300, 9600);
        let mut storage = vec![77i16; 8];
        let mut indices: &mut [i16] = &mut storage;
        let r = dec_lsf_tcxlpc(&mut st, &mut indices, case.i16("nb"), case.i16("cdk"));
        let advance = (8 - indices.len()) as i16;
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "storage", &storage, &case.out_i16s("storage"));
        check(case, "advance", &advance, &case.out_i16("advance"));
        check(case, "pos", &st.next_bit_pos, &case.out_i16("pos"));
    });
}
