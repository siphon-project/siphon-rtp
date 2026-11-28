//! `core_switching_hq_prepare_dec_fx` (`lib_dec/core_switching_dec_fx.c`) against
//! `fn_core_switching_hq_prepare`: random switching-frame states, and the ACELP->HQ switching
//! frames of the conformance bitstreams.

use siphon_rtp_codec::evs::dec::core_switching_dec::core_switching_hq_prepare_dec;

use crate::common::{corpus_sized, mismatch, Case};
use crate::hq_state::{decoder_with, each_stream_call, keep_unloadable, overlay, state_after};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn replay(case: &Case, context: &str) {
    let before = overlay(case, "\u{0}never");
    let mut expected = state_after(case);
    let mut st = decoder_with(case, &before);
    keep_unloadable(&mut st, &before, &mut expected);
    let mut num_bits = case.i16("num_bits_in");
    core_switching_hq_prepare_dec(&mut st, &mut num_bits, case.i16("call_output_frame"));
    check(
        case,
        &format!("{context} num_bits"),
        &num_bits,
        &case.out_i16("num_bits"),
    );
    crate::hq_state::check_state(&mut st, &expected, context);
}

#[test]
fn core_switching_hq_prepare_dec_matches_the_reference() {
    let Some(cases) = corpus_sized(
        "core_switching_hq_prepare",
        "core_switching_hq_prepare_dec",
        300,
    ) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        replay(case, &format!("case {index}"));
    }
}

/// Every ACELP->HQ switching frame of the switching sequences (NB, WB, SWB and FB, clean and with
/// frame loss).
#[test]
fn core_switching_hq_prepare_dec_matches_the_reference_on_conformance_bitstreams() {
    let mut checked = 0;
    for (name, rate) in [
        ("nb/stv8c_sw_72_244_8kHz.COD", 8000),
        ("nb/stv8c_sw_72_244_8kHz.f06.COD", 8000),
        ("wb/stv16c_sw_72_1280_16kHz.COD", 16000),
        ("wb/stv16c_sw_72_1280_16kHz.f06.COD", 16000),
        ("swb/stv32c_sw_72_164_32kHz.COD", 32000),
        ("swb/stv32c_sw_72_164_32kHz.b10.COD", 32000),
        ("swb/stv32c_sw_96_1280_32kHz.COD", 32000),
        ("fb/stv48c_sw_164_1280_48kHz.COD", 48000),
        ("fb/stv48c_sw_164_1280_48kHz.b10.COD", 48000),
        ("fb/stv48c_sw_72_244_48kHz.COD", 48000),
        ("fb/stv48c_sw_72_244_48kHz.f06.COD", 48000),
    ] {
        let calls = each_stream_call("core_switching_hq_prepare", name, rate, 1, |index, case| {
            replay(case, &format!("{name} line {index}"));
        });
        checked += calls.unwrap_or(0);
    }
    eprintln!("core_switching_hq_prepare_dec checked on {checked} conformance calls");
}
