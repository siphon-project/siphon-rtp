//! `lib_com/ari_hm.c`, `ACcontextMapping.c`, `lib_dec/ACcontextMapping_dec.c`,
//! `ari_hm_dec.c` (`DecodeIndex`, `tcx_hm_dequantize_gain`) and `arith_coder.c` (`expfp`)
//! against `fn_m2arith_acctx`.

use siphon_rtp_codec::evs::cnst::MODE2;
use siphon_rtp_codec::evs::com::ac_context_mapping::update_mixed_context;
use siphon_rtp_codec::evs::com::ari_hm::{
    configure_context_hm, count_index_bits, tcx_hm_render, unmap_index, ContextHmConfig,
};
use siphon_rtp_codec::evs::com::arith_coder::expfp;
use siphon_rtp_codec::evs::dec::ac_context_mapping_dec::ac_context_mapping_decode2_no_mem_s17_lc;
use siphon_rtp_codec::evs::dec::ari_hm_dec::{decode_index, tcx_hm_dequantize_gain};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus_sized, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// The context-based arithmetic decoder in the mapped (harmonic model) and unmapped domains,
/// over random bitstreams, budgets and periodicity indices.
#[test]
fn ac_context_mapping_decode_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_acctx", "acctx", 4000) else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    let (mut decoded, mut mapped_cases) = (0, 0);
    for case in &cases {
        st.bit_stream.fill(0);
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.i32s("bits")) {
            *slot = bit as u16;
        }
        st.total_num_bits = case.i16("total_num_bits");
        st.next_bit_pos = case.i16("start");
        st.codec_mode = MODE2;
        st.ber_detect = 0;
        let nt = case.i16("nt");
        let resq = case.i16("resq");
        let mut x = vec![0_i16; 1300];
        for (slot, &value) in x.iter_mut().zip(&case.i16s("x_in")) {
            *slot = value;
        }
        let mut buffer = vec![0_i16; 4000];
        let mut hm_cfg = ContextHmConfig::new(&mut buffer);
        let mapped = case.i16("mapped") == 1;
        if mapped {
            configure_context_hm(
                nt,
                case.i16("target_bits"),
                case.i16("periodicity"),
                case.i16("ltp_lag"),
                &mut hm_cfg,
            );
            mapped_cases += 1;
        }
        let result = ac_context_mapping_decode2_no_mem_s17_lc(
            &mut st,
            &mut x,
            nt,
            case.i16("nbbits"),
            resq,
            if mapped { Some(&mut hm_cfg) } else { None },
        );
        decoded += usize::from(result > 0);
        check(
            case,
            "x",
            &x[..(nt + resq) as usize].to_vec(),
            &case.out_i16s("x"),
        );
        check(case, "result", &result, &case.out_i16("result"));
        check(
            case,
            "next_bit_pos",
            &st.next_bit_pos,
            &case.out_i16("next_bit_pos"),
        );
        check(
            case,
            "ber_detect",
            &st.ber_detect,
            &case.out_i16("ber_detect"),
        );
        if mapped {
            check(
                case,
                "num_peak",
                &hm_cfg.num_peak_indices,
                &case.out_i16("num_peak"),
            );
            check(
                case,
                "num_hole",
                &hm_cfg.num_hole_indices,
                &case.out_i16("num_hole"),
            );
            check(
                case,
                "hole_at",
                &(hm_cfg.hole_indices_at as i16),
                &case.out_i16("hole_at"),
            );
            let used = (hm_cfg.num_peak_indices + hm_cfg.num_hole_indices + 1) as usize;
            check(
                case,
                "index_buffer",
                &hm_cfg.index_buffer[..used].to_vec(),
                &case.out_i16s("index_buffer"),
            );
        }
    }
    assert!(mapped_cases > 500, "too few mapped cases: {mapped_cases}");
    assert!(
        decoded > 300,
        "too few cases decoded residual bits: {decoded}"
    );
}

/// `UnmapIndex`, `ConfigureContextHm`, `CountIndexBits` and `tcx_hm_render` for one index.
#[test]
fn harmonic_model_configuration_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_acctx", "hm", 4000) else {
        return;
    };
    for case in &cases {
        let periodicity = case.i16("periodicity");
        let ltp_lag = case.i16("ltp_lag");
        let num_coeffs = case.i16("num_coeffs");
        let bandwidth = case.i16("bandwidth");
        let mut buffer = vec![0_i16; 4000];
        let mut hm_cfg = ContextHmConfig::new(&mut buffer);
        configure_context_hm(
            num_coeffs,
            case.i16("target_bits"),
            periodicity,
            ltp_lag,
            &mut hm_cfg,
        );
        let (mut fract_res, mut lag) = (0, 0);
        // The harness draws SmallerLags at random; the output is replayed with the same draw by
        // trying both and requiring one to match the reference.
        let mut matched = false;
        for smaller_lags in [0, 1] {
            unmap_index(
                periodicity,
                bandwidth as i8,
                ltp_lag,
                smaller_lags,
                &mut fract_res,
                &mut lag,
            );
            matched |= fract_res == case.out_i16("fract_res") && lag == case.out_i32("lag");
        }
        assert!(matched, "unmap_index differs: {}", case.line);
        check(
            case,
            "bits",
            &count_index_bits(bandwidth, periodicity),
            &case.out_i16("bits"),
        );
        check(
            case,
            "num_peak",
            &hm_cfg.num_peak_indices,
            &case.out_i16("num_peak"),
        );
        check(
            case,
            "num_hole",
            &hm_cfg.num_hole_indices,
            &case.out_i16("num_hole"),
        );
        let used = (hm_cfg.num_peak_indices + hm_cfg.num_hole_indices + 1) as usize;
        check(
            case,
            "index_buffer",
            &hm_cfg.index_buffer[..used].to_vec(),
            &case.out_i16s("index_buffer"),
        );
        let mut p = [12345_i16; 9];
        let error = tcx_hm_render(case.out_i32("lag"), case.out_i16("fract_res"), &mut p);
        check(case, "render", &i16::from(error), &case.out_i16("render"));
        check(case, "p", &p.to_vec(), &case.out_i16s("p"));
    }
}

#[test]
fn tcx_hm_render_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_acctx", "render", 4000) else {
        return;
    };
    let mut errors = 0;
    for case in &cases {
        let mut p = [12345_i16; 9];
        let error = tcx_hm_render(case.i32("lag"), case.i16("fract_res"), &mut p);
        errors += usize::from(error);
        check(case, "render", &i16::from(error), &case.out_i16("render"));
        check(case, "p", &p.to_vec(), &case.out_i16s("p"));
    }
    assert!(errors > 0 && errors < cases.len());
}

#[test]
fn decode_index_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_acctx", "decode_index", 3000) else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        st.bit_stream.fill(0);
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.i32s("bits")) {
            *slot = bit as u16;
        }
        st.total_num_bits = 64;
        st.codec_mode = MODE2;
        st.next_bit_pos = case.i16("next_bit_pos");
        st.tcx_hm_ltp_pitch_lag = case.i16("lag");
        st.tcxltp_gain = case.i16("gain");
        let mut index = 5;
        let bits = decode_index(&mut st, case.i16("bandwidth"), &mut index);
        check(case, "bits", &bits, &case.out_i16("bits"));
        check(case, "index", &index, &case.out_i16("index"));
        check(
            case,
            "next_bit_pos",
            &st.next_bit_pos,
            &case.out_i16("next_bit_pos"),
        );
    }
}

#[test]
fn small_functions_match_the_reference() {
    if let Some(cases) = corpus_sized("m2arith_acctx", "gain", 500) {
        for case in &cases {
            let mut gain = 77;
            let error = tcx_hm_dequantize_gain(case.i16("coder"), case.i16("idx"), &mut gain);
            check(case, "err", &i16::from(error), &case.out_i16("err"));
            check(case, "gain", &gain, &case.out_i16("gain"));
        }
    }
    if let Some(cases) = corpus_sized("m2arith_acctx", "mixed", 3000) {
        for case in &cases {
            check(
                case,
                "out",
                &update_mixed_context(case.i16("ctx"), case.i16("a")),
                &case.out_i16("out"),
            );
        }
    }
    if let Some(cases) = corpus_sized("m2arith_acctx", "expfp", 5000) {
        for case in &cases {
            check(
                case,
                "y",
                &expfp(case.i16("x"), case.i16("e")),
                &case.out_i32("y"),
            );
        }
    }
}
