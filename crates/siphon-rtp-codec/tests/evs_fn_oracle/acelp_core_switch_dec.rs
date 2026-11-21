//! `lib_dec/acelp_core_switch_dec_fx.c` against `fn_acelp_core_switch_dec`:
//! `acelp_core_switch_dec_fx` (and the file-local `decod_gen_voic_core_switch_fx` through it) and
//! `acelp_core_switch_dec_bfi_fx` (on a randomised concealment state, `fn/conceal_state.h`).
//!
//! Each case is a decoder built by `init_decoder_fx` whose per-frame state was randomised; the
//! oracle prints the whole state before the call and the fields that changed after it (see
//! `state_dump.rs`); the whole state after is compared, so every field the function writes, and
//! every field it must leave alone, is checked.

use siphon_rtp_codec::evs::dec::acelp_core_switch_dec::{
    acelp_core_switch_dec, acelp_core_switch_dec_bfi,
};
use siphon_rtp_codec::evs::dec::fd_cng_dec::configure_fd_cng_dec;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_case::state_after;
use crate::state_dump;

/// The decoder the case's "before" dump describes.
fn state_before(case: &Case) -> Box<DecoderState> {
    let brate = case.i32("in.core_brate_fx");
    let l_frame = case.i16("in.last_L_frame_fx");
    state_before_configured(case, brate, l_frame)
}

/// [`state_before`] with the FD-CNG configured at `cna_brate` / `cna_l_frame` (the values the
/// oracle configured it with, before it changed the rate and frame length).
fn state_before_configured(case: &Case, cna_brate: i32, cna_l_frame: i16) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);
    // the ROM pointers the FD-CNG configuration sets are not in the dump's loadable fields
    if case.i16("in.flag_cna") != 0 {
        let hs = st.h_fd_cng_dec.as_deref_mut().unwrap();
        configure_fd_cng_dec(hs, case.i16("cna_bandwidth"), cna_brate, cna_l_frame);
    }
    state_dump::load(&mut st, &case.inputs, "in.");
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.inputs["bits"]) {
        *slot = bit as u16;
    }
    st
}

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn acelp_core_switch_dec_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("acelp_core_switch_dec", "acelp_core_switch_dec", 300) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = state_before(case);
        let mut synth_subfr_out = case.i16s("synth_subfr_out");
        let mut tmp_synth_bwe = case.i16s("tmp_synth_bwe");
        let mut mem_synth = case.i16s("mem_synth");
        let mut q_syn = case.i16("q_syn");
        let output_frame = st.output_frame;
        acelp_core_switch_dec(
            &mut st,
            &mut synth_subfr_out,
            &mut tmp_synth_bwe,
            output_frame,
            case.i16("core_switching_flag"),
            &mut mem_synth,
            &mut q_syn,
        );
        let context = format!(
            "case {index}: output {} Hz, last_L_frame {}, last_core {}, core_brate {}",
            st.output_fs,
            case.i16("in.last_L_frame_fx"),
            case.i16("in.last_core_fx"),
            case.i32("in.core_brate_fx")
        );
        check(
            case,
            "synth_subfr_out",
            &synth_subfr_out,
            &case.out_i16s("synth_subfr_out"),
        );
        check(
            case,
            "tmp_synth_bwe",
            &tmp_synth_bwe,
            &case.out_i16s("tmp_synth_bwe"),
        );
        check(case, "mem_synth", &mem_synth, &case.out_i16s("mem_synth"));
        check(case, "q_syn", &q_syn, &case.out_i16("q_syn"));
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}

#[test]
fn acelp_core_switch_dec_bfi_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("acelp_core_switch_dec", "acelp_core_switch_dec_bfi", 400)
    else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = state_before_configured(case, case.i32("cna_brate"), case.i16("cna_l_frame"));
        let mut synth_out = vec![-3i16; 960];
        acelp_core_switch_dec_bfi(&mut st, &mut synth_out, case.i16("coder_type"));
        let context = format!(
            "case {index}: output {} Hz, L_frame {}, last_good {}, last_coder_type {}, nelp {}, \
             AMR-WB {}",
            st.output_fs,
            st.l_frame,
            st.last_good,
            st.last_coder_type,
            case.i16("in.last_nelp_mode_dec_fx"),
            st.opt_amr_wb
        );
        check(
            case,
            &format!("{context}: synth_out"),
            &synth_out,
            &case.out_i16s("synth_out"),
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}
