//! `lib_dec/hdecnrm_fx.c` against `fn_hdecnrm`.

use siphon_rtp_codec::evs::cnst::{
    HVQ_CP_HUFF_MAX_CODE, HVQ_CP_HUFF_NUM_LEN, MAX_PG_HUFFLEN, NUM_PG_HUFFLEN,
};
use siphon_rtp_codec::evs::dec::hdecnrm::{
    decode_huff_context, hdecnrm, hdecnrm_context, hdecnrm_resize, hdecnrm_tran, huff_dec,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::rom::{
    hvq_cp_huff_offset, HETABLE_FX, HNTABLE_FX, HVQ_CP_HUFF_TAB, HVQ_CP_HUFF_THRES,
    HVQ_PG_HUFF_OFFSET, HVQ_PG_HUFF_TAB, HVQ_PG_HUFF_THRES,
};

use crate::common::{corpus, mismatch, Case};

fn stream(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    let bits = case.i16s("bits");
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
        *slot = bit as u16;
    }
    st.total_num_bits = bits.len() as i16;
    st.codec_mode = 1;
    st
}

fn check(case: &Case, name: &str, rust: &[i16]) {
    if let Some(message) = mismatch(case, name, &rust.to_vec(), &case.out_i16s(name)) {
        panic!("{message}");
    }
}

#[test]
fn hdecnrm_context_matches_the_reference() {
    let Some(cases) = corpus("hdecnrm", "context") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let n = case.i16("n");
        let mut index = vec![0i16; n as usize];
        index[0] = case.i16("index0");
        let mut n_length = case.i16("n_length");
        hdecnrm_context(&mut st, n, &mut index, &mut n_length);
        check(case, "index", &index);
        check(case, "n_length", &[n_length]);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
        check(case, "ber_detect", &[st.ber_detect]);
    }
}

#[test]
fn hdecnrm_resize_matches_the_reference() {
    let Some(cases) = corpus("hdecnrm", "resize") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let n = case.i16("n");
        let mut index = vec![0i16; n as usize];
        hdecnrm_resize(&mut st, n, &mut index);
        check(case, "index", &index);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
        check(case, "ber_detect", &[st.ber_detect]);
    }
}

#[test]
fn decode_huff_context_matches_the_reference() {
    let Some(cases) = corpus("hdecnrm", "huff") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut rbits = case.i16("rbits");
        let table: &[i16] = if case.i16("table") != 0 {
            &HETABLE_FX
        } else {
            &HNTABLE_FX
        };
        let symbol = decode_huff_context(&mut st, table, &mut rbits);
        check(case, "symbol", &[symbol]);
        check(case, "rbits", &[rbits]);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
    }
}

fn check_fixed(function: &str, decode: fn(&mut DecoderState, i16, &mut [i16])) {
    let Some(cases) = corpus("hdecnrm", function) else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let n = case.i16("n");
        let mut index = vec![-7i16; n as usize];
        decode(&mut st, n, &mut index);
        check(case, "index", &index);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
        check(case, "ber_detect", &[st.ber_detect]);
    }
}

#[test]
fn hdecnrm_matches_the_reference() {
    check_fixed("fixed", hdecnrm);
}

#[test]
fn hdecnrm_tran_matches_the_reference() {
    check_fixed("tran", hdecnrm_tran);
}

#[test]
fn huff_dec_matches_the_reference() {
    let Some(cases) = corpus("hdecnrm", "huff_dec") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        st.next_bit_pos = case.i16("next_bit_pos");
        let mut index = vec![-9i16; 64];
        if case.i16("table") != 0 {
            huff_dec(
                &mut st,
                case.i16("n"),
                MAX_PG_HUFFLEN,
                NUM_PG_HUFFLEN,
                &HVQ_PG_HUFF_THRES,
                &HVQ_PG_HUFF_OFFSET,
                &HVQ_PG_HUFF_TAB,
                &mut index,
            );
        } else {
            huff_dec(
                &mut st,
                case.i16("n"),
                HVQ_CP_HUFF_MAX_CODE,
                HVQ_CP_HUFF_NUM_LEN,
                &HVQ_CP_HUFF_THRES,
                &hvq_cp_huff_offset,
                &HVQ_CP_HUFF_TAB,
                &mut index,
            );
        }
        check(case, "index", &index);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
        check(case, "ber_detect", &[st.ber_detect]);
    }
}
