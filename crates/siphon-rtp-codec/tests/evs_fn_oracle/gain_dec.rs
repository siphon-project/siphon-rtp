//! `lib_dec/gain_dec_fx.c` (MODE1 gain decoders) against `fn_gain_dec`.

use siphon_rtp_codec::evs::dec::gain_dec::{
    es_pred_dec, gain_dec_gaus, gain_dec_lbr, gain_dec_mless, gain_dec_sq, gain_dec_tc,
    lp_gain_updt,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch, Case};

fn state(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    let bits = case.i16s("bits");
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
        *slot = bit as u16;
    }
    st.total_num_bits = bits.len() as i16;
    st.next_bit_pos = case.i16("next_bit_pos");
    st.codec_mode = 1;
    st
}

fn compare(case: &Case, names: &[&str], rust: &[i32]) {
    let reference: Vec<i32> = names.iter().map(|name| case.out_i32(name)).collect();
    if let Some(message) = mismatch(case, &names.join("/"), &rust.to_vec(), &reference) {
        panic!("{message}");
    }
}

#[test]
fn es_pred_dec_matches_the_reference() {
    let Some(cases) = corpus("gain_dec", "es_pred_dec") else {
        return;
    };
    for case in &cases {
        let mut st = state(case);
        let es_pred = es_pred_dec(&mut st, case.i16("coder_type"), case.i32("core_brate"));
        compare(
            case,
            &["es_pred", "next_bit_pos", "ber_detect"],
            &[
                i32::from(es_pred),
                i32::from(st.next_bit_pos),
                i32::from(st.ber_detect),
            ],
        );
    }
}

const GAINS: [&str; 5] = [
    "gain_pit",
    "gain_code",
    "gain_inov",
    "norm_gain_code",
    "next_bit_pos",
];

#[test]
fn gain_dec_tc_matches_the_reference() {
    let Some(cases) = corpus("gain_dec", "gain_dec_tc") else {
        return;
    };
    for case in &cases {
        let mut st = state(case);
        let (mut gain_pit, mut gain_code, mut gain_inov, mut norm_gain_code) =
            (-1i16, -1i32, -1i16, -1i32);
        gain_dec_tc(
            &mut st,
            case.i32("core_brate"),
            &case.i16s("code"),
            case.i16("l_frame"),
            case.i16("i_subfr"),
            case.i16("tc_subfr"),
            case.i16("es_pred"),
            &mut gain_pit,
            &mut gain_code,
            &mut gain_inov,
            &mut norm_gain_code,
        );
        compare(
            case,
            &GAINS,
            &[
                i32::from(gain_pit),
                gain_code,
                i32::from(gain_inov),
                norm_gain_code,
                i32::from(st.next_bit_pos),
            ],
        );
    }
}

#[test]
fn gain_dec_mless_matches_the_reference() {
    let Some(cases) = corpus("gain_dec", "gain_dec_mless") else {
        return;
    };
    for case in &cases {
        let mut st = state(case);
        let (mut gain_pit, mut gain_code, mut gain_inov, mut norm_gain_code) =
            (-1i16, -1i32, -1i16, -1i32);
        gain_dec_mless(
            &mut st,
            case.i32("core_brate"),
            case.i16("l_frame"),
            case.i16("coder_type"),
            case.i16("i_subfr"),
            case.i16("tc_subfr"),
            &case.i16s("code"),
            case.i16("es_pred"),
            &mut gain_pit,
            &mut gain_code,
            &mut gain_inov,
            &mut norm_gain_code,
        );
        compare(
            case,
            &GAINS,
            &[
                i32::from(gain_pit),
                gain_code,
                i32::from(gain_inov),
                norm_gain_code,
                i32::from(st.next_bit_pos),
            ],
        );
    }
}

#[test]
fn gain_dec_lbr_matches_the_reference() {
    let Some(cases) = corpus("gain_dec", "gain_dec_lbr") else {
        return;
    };
    for case in &cases {
        let mut st = state(case);
        let code = case.i16s("code");
        let mut gp_mem = case.i16s("gp_mem");
        let mut gc_mem = case.i32s("gc_mem");
        let (mut gain_pit, mut gain_inov) = (vec![-1i16; 4], vec![-1i16; 4]);
        let (mut gain_code, mut norm_gain_code) = (vec![-1i32; 4], vec![-1i32; 4]);
        for s in 0..4 {
            gain_dec_lbr(
                &mut st,
                case.i32("core_brate"),
                case.i16("coder_type"),
                (s * 64) as i16,
                &code[s * 64..(s + 1) * 64],
                &mut gain_pit[s],
                &mut gain_code[s],
                &mut gain_inov[s],
                &mut norm_gain_code[s],
                &mut gc_mem,
                &mut gp_mem,
            );
        }
        let widen = |v: &[i16]| v.iter().map(|&x| i32::from(x)).collect::<Vec<i32>>();
        let rust = [
            widen(&gain_pit),
            gain_code,
            widen(&gain_inov),
            norm_gain_code,
            widen(&gp_mem),
            gc_mem,
            vec![i32::from(st.next_bit_pos)],
        ]
        .concat();
        let reference = [
            case.out_i32s("gain_pit"),
            case.out_i32s("gain_code"),
            case.out_i32s("gain_inov"),
            case.out_i32s("norm_gain_code"),
            case.out_i32s("gp_mem"),
            case.out_i32s("gc_mem"),
            vec![case.out_i32("next_bit_pos")],
        ]
        .concat();
        if let Some(message) = mismatch(case, "gains/mem/next_bit_pos", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn lp_gain_updt_matches_the_reference() {
    let Some(cases) = corpus("gain_dec", "lp_gain_updt") else {
        return;
    };
    for case in &cases {
        let gain_pit = case.i16s("gain_pit");
        let norm_gain_code = case.i32s("norm_gain_code");
        let (mut lp_gainp, mut lp_gainc) = (case.i16("lp_gainp"), case.i16("lp_gainc"));
        let (mut out_p, mut out_c) = (Vec::new(), Vec::new());
        for s in 0..gain_pit.len() {
            lp_gain_updt(
                (s * 64) as i16,
                gain_pit[s],
                norm_gain_code[s],
                &mut lp_gainp,
                &mut lp_gainc,
                case.i16("l_frame"),
            );
            out_p.push(lp_gainp);
            out_c.push(lp_gainc);
        }
        let rust = [out_p, out_c].concat();
        let reference = [case.out_i16s("lp_gainp"), case.out_i16s("lp_gainc")].concat();
        if let Some(message) = mismatch(case, "lp_gainp/lp_gainc", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn gain_dec_gaus_matches_the_reference() {
    let Some(cases) = corpus("gain_dec", "gain_dec_gaus") else {
        return;
    };
    for case in &cases {
        let mut norm = -1;
        let gain = gain_dec_gaus(
            case.i16("index"),
            case.i16("bits"),
            case.i16("low_bound"),
            case.i16("top_bound"),
            case.i16("inv_gain_inov"),
            &mut norm,
        );
        compare(case, &["gain", "norm_gain_code"], &[gain, norm]);
    }
}

/// `gain_dec_SQ_fx` at the 16 kHz core's rates, every coder type and subframe with a gain row.
#[test]
fn gain_dec_sq_matches_the_reference() {
    let Some(cases) = corpus("gain_dec", "gain_dec_sq") else {
        return;
    };
    for case in &cases {
        let mut st = state(case);
        let (mut gain_pit, mut gain_code, mut gain_inov, mut norm_gain_code) =
            (-1i16, -1i32, -1i16, -1i32);
        gain_dec_sq(
            &mut st,
            case.i32("core_brate"),
            case.i16("coder_type"),
            case.i16("i_subfr"),
            -1,
            &case.i16s("code"),
            case.i16("es_pred"),
            &mut gain_pit,
            &mut gain_code,
            &mut gain_inov,
            &mut norm_gain_code,
        );
        compare(
            case,
            &GAINS,
            &[
                i32::from(gain_pit),
                gain_code,
                i32::from(gain_inov),
                norm_gain_code,
                i32::from(st.next_bit_pos),
            ],
        );
    }
}
