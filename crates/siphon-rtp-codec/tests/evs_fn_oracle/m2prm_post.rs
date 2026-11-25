//! `lib_dec/post_dec.c` against `fn_m2prm_post`: `post_decoder` and `cldfb_synth_set_bandsToZero`
//! on the whole decoder state (`state_capture.h`), `bass_pf_1sf_delay` directly.

use siphon_rtp_codec::evs::com::cldfb::CLDFB_ROW;
use siphon_rtp_codec::evs::dec::post_dec::{
    bass_pf_1sf_delay, cldfb_synth_set_bands_to_zero, post_decoder,
};
use siphon_rtp_codec::evs::dec::state::CldfbScaleFactor;

use crate::common::{corpus, corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

const MODULE: &str = "m2prm_post";

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn rows(case: &Case, name: &str) -> Vec<[i32; CLDFB_ROW]> {
    case.i32s(name)
        .chunks(CLDFB_ROW)
        .map(|chunk| {
            let mut row = [0i32; CLDFB_ROW];
            row.copy_from_slice(chunk);
            row
        })
        .collect()
}

#[test]
fn bass_pf_1sf_delay_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "bass_pf_1sf_delay") else {
        return;
    };
    let mut filtered = 0;
    for case in &cases {
        let l_frame = case.i16("l_frame");
        let syn = case.i16s("syn");
        let history = syn.len() - l_frame as usize;
        let mut noise = vec![0x5a5a_i16; 320];
        let mut lp_error_ener = case.i32("lp_error_ener");
        let mut mem_error = case.i32("mem_error");
        bass_pf_1sf_delay(
            &syn,
            history,
            &case.i16s("t_sf"),
            &case.i16s("gain"),
            l_frame,
            64,
            &mut noise,
            &case.i16s("factor"),
            case.i16("disable_bpf") as i8,
            &mut lp_error_ener,
            &mut mem_error,
        );
        noise.truncate(l_frame as usize);
        let expected = case.out_i16s("noise");
        if expected.iter().any(|&sample| sample != 0) {
            filtered += 1;
        }
        check(case, "noise", &noise, &expected);
        check(
            case,
            "lp_error_ener",
            &lp_error_ener,
            &case.out_i32("lp_error_ener"),
        );
        check(case, "mem_error", &mem_error, &case.out_i32("mem_error"));
    }
    assert!(filtered > cases.len() / 5, "filtered {filtered}");
}

#[test]
fn post_decoder_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized(MODULE, "post_decoder", 300) else {
        return;
    };
    let (mut tcx_only, mut narrow, mut wide) = (0, 0, 0);
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let l_frame = case.i16("l_frame");
        let mut synth_buf = vec![0i16; 1920 + 960 + 16];
        let given = case.i16s("synth_buf");
        synth_buf[..given.len()].copy_from_slice(&given);
        let mut out = vec![0x4b4b_i16; 960];
        let mut noise = vec![0x5a5a_i16; 960];
        if st.tcxonly != 0 {
            tcx_only += 1;
        } else if st.last_bwidth == 0 {
            narrow += 1;
        } else {
            wide += 1;
        }
        post_decoder(
            &mut st,
            case.i16("coder_type"),
            &mut synth_buf,
            &case.i16s("pit_gain"),
            &case.i16s("pitch"),
            &mut out,
            &mut noise,
        );
        synth_buf.truncate(given.len());
        out.truncate(l_frame as usize);
        let expected_noise = case.out_i16s("noise");
        noise.truncate(expected_noise.len());
        let context = format!("post_decoder case {index}");
        check(case, "synth_buf", &synth_buf, &case.out_i16s("synth_buf"));
        check(case, "out", &out, &case.out_i16s("out"));
        check(case, "noise", &noise, &expected_noise);
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
    assert!(
        tcx_only > 20 && narrow > 20 && wide > 20,
        "{tcx_only} {narrow} {wide}"
    );
}

#[test]
fn cldfb_synth_set_bands_to_zero_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized(MODULE, "bands_to_zero", 300) else {
        return;
    };
    let mut changed = 0;
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let mut scale = CldfbScaleFactor::zeroed();
        scale.lb_scale = case.i16("lb_scale");
        let before = st.last_active_bands_to_zero_bwdec;
        cldfb_synth_set_bands_to_zero(
            &mut st,
            &rows(case, "real"),
            &rows(case, "imag"),
            16,
            &scale,
        );
        if st.last_active_bands_to_zero_bwdec != before {
            changed += 1;
        }
        let context = format!("bands_to_zero case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
    assert!(changed > 5, "changed {changed}");
}
