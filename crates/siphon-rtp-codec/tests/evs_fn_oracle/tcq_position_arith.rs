//! `lib_com/tcq_position_arith_fx.c` against `fn_tcq_position_arith`.
//!
//! `bitstream_load_bit`, `bitstream_rollback`, `ar_decoder_start`, `ar_decode`, `ar_decoder_done`,
//! `decode_position_ari`, `decode_magnitude_usq`, `decode_mangitude_tcq`, `decode_signs` and
//! `load_tcq_data` are proven together by `decode_bands`: a whole low-rate HQ band sequence decoded
//! from random bits, comparing every band's positions and magnitudes and the final coder and
//! bitstream state.

use siphon_rtp_codec::evs::com::tcq_position_arith::{
    ar_decode, ar_decoder_done, ar_decoder_start, ar_div, ar_make_model, decode_magnitude_usq,
    decode_mangitude_tcq, decode_position_ari, decode_signs, get_bits_from_pulses, get_scale,
    load_tcq_data, quantize, restore_tcq_dec, srt_vec_ind, tcq_lsb_dec, ArCodec,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn ar_div_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "ar_div") else {
        return;
    };
    for case in &cases {
        let r = ar_div(case.i32("num"), case.i32("denum"));
        check(case, "r", &r, &case.out_i32("r"));
    }
}

#[test]
fn get_bits_from_pulses_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "get_bits_from_pulses") else {
        return;
    };
    for case in &cases {
        let r = get_bits_from_pulses(case.i16("m"), case.i16("n"));
        check(case, "r", &r, &case.out_i32("r"));
    }
}

#[test]
fn get_scale_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "get_scale") else {
        return;
    };
    for case in &cases {
        let mut surplus = case.i32("surplus");
        let pulses = get_scale(case.i16("blen"), case.i32("bits"), Some(&mut surplus));
        check(case, "pulses", &pulses, &case.out_i16("pulses"));
        check(case, "surplus", &surplus, &case.out_i32("surplus"));
    }
}

#[test]
fn quantize_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "quantize") else {
        return;
    };
    for case in &cases {
        let r = quantize(case.i16("val"), case.i16("d"));
        check(case, "r", &r, &case.out_i16("r"));
    }
}

#[test]
fn ar_make_model_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "ar_make_model") else {
        return;
    };
    for case in &cases {
        let freq = case.i16s("freq");
        let mut model = case.i16s("model");
        let r = ar_make_model(&freq, &mut model, freq.len() as i16);
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "model", &model, &case.out_i16s("model"));
    }
}

#[test]
fn srt_vec_ind_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "srt_vec_ind") else {
        return;
    };
    for case in &cases {
        let linear = case.i32s("linear");
        let mut srt = vec![0; linear.len()];
        let mut index = vec![0; linear.len()];
        srt_vec_ind(&linear, &mut srt, &mut index, linear.len() as i16);
        check(case, "srt", &srt, &case.out_i32s("srt"));
        check(case, "i", &index, &case.out_i16s("i"));
    }
}

#[test]
fn tcq_lsb_dec_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "tcq_lsb_dec") else {
        return;
    };
    for case in &cases {
        let bcount = case.i16("bcount");
        let mut mbuffer = vec![7; bcount as usize];
        tcq_lsb_dec(&case.i16s("dpath"), &mut mbuffer, bcount);
        check(case, "mbuffer", &mbuffer, &case.out_i16s("mbuffer"));
    }
}

#[test]
fn restore_tcq_dec_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "restore_tcq_dec") else {
        return;
    };
    for case in &cases {
        let mut magn = case.i16s("magn");
        let mut bcount = case.i16("bcount");
        let mut mbuffer = case.i16s("mbuffer");
        restore_tcq_dec(&mut magn, case.i16("size"), &mut bcount, &mut mbuffer);
        check(case, "magn", &magn, &case.out_i16s("magn"));
        check(case, "bcount", &bcount, &case.out_i16("bcount"));
        check(case, "mbuffer", &mbuffer, &case.out_i16s("mbuffer"));
    }
}

#[test]
fn decode_bands_matches_the_reference() {
    let Some(cases) = corpus("tcq_position_arith", "decode_bands") else {
        return;
    };
    for case in &cases {
        let bytes = case.i16s("bytes");
        let sizes = case.i16s("size");
        let npulses = case.i16s("npulses");
        let usq = case.i16s("usq");
        let lsb = case.i16("lsb");

        let mut ar = Box::new(ArCodec::new());
        for (slot, &byte) in ar.bs_inst.buf.iter_mut().zip(&bytes) {
            *slot = byte as u8;
        }
        ar.bs_inst.cur_pos = 7;
        ar.bs_inst.max_bytes = bytes.len() as i32 + 2;
        ar_decoder_start(&mut ar);

        let mut surplus = 0;
        for (band, &size) in sizes.iter().enumerate() {
            let mut positions = vec![9_i16; size as usize];
            let mut out = case.i16s(&format!("init{band}"));
            let mut nz = -7;
            decode_position_ari(&mut ar, size, npulses[band], &mut nz, &mut positions);
            if usq[band] != 0 {
                decode_magnitude_usq(&mut ar, size, npulses[band], nz, &positions, &mut out);
            } else {
                decode_mangitude_tcq(
                    &mut ar,
                    size,
                    npulses[band],
                    nz,
                    &positions,
                    &mut out,
                    &mut surplus,
                );
            }
            decode_signs(&mut ar, size, &mut out);
            check(
                case,
                &format!("nz{band}"),
                &nz,
                &case.out_i16(&format!("nz{band}")),
            );
            check(
                case,
                &format!("pos{band}"),
                &positions,
                &case.out_i16s(&format!("pos{band}")),
            );
            check(
                case,
                &format!("out{band}"),
                &out,
                &case.out_i16s(&format!("out{band}")),
            );
        }
        let mut dpath = vec![0; lsb as usize];
        let mut mbuffer = vec![0; 2 * lsb as usize];
        load_tcq_data(&mut ar, &mut dpath, lsb);
        tcq_lsb_dec(&dpath, &mut mbuffer, 2 * lsb);
        ar_decoder_done(&mut ar);
        check(case, "surplus", &surplus, &case.out_i32("surplus"));
        check(case, "dpath", &dpath, &case.out_i16s("dpath"));
        check(case, "mbuffer", &mbuffer, &case.out_i16s("mbuffer"));
        check(case, "low", &ar.low, &case.out_i32("low"));
        check(case, "high", &ar.high, &case.out_i32("high"));
        check(case, "value", &ar.value, &case.out_i32("value"));
        check(
            case,
            "cur_pos",
            &ar.bs_inst.cur_pos,
            &case.out_i16("cur_pos"),
        );
        check(
            case,
            "num_byte",
            &ar.bs_inst.num_byte,
            &case.out_i32("num_byte"),
        );
        check(
            case,
            "numbits",
            &ar.bs_inst.numbits,
            &case.out_i32("numbits"),
        );
    }
}

/// `ar_decode` on a model whose scan would run past its end (a state the coder cannot reach)
/// stays in bounds.
#[test]
fn ar_decode_stays_in_bounds_on_an_unreachable_state() {
    let mut ar = ArCodec::new();
    ar.low = 1000;
    ar.high = 500;
    ar.value = 0;
    let symbol = ar_decode(&mut ar, &[16383, 8191, 0]);
    assert!((0..=1).contains(&symbol));
}
