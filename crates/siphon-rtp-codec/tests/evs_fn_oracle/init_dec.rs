//! `lib_dec/init_dec_fx.c` against `fn_init_dec`: `init_decoder_fx` and `reset_preecho_dec_fx`
//! compared on the WHOLE decoder state (every field of every struct the state reaches, the CLDFB
//! banks and FD-CNG through their handles; see `state_dump.rs`).

use siphon_rtp_codec::evs::dec::init_dec::{destroy_decoder, init_decoder, reset_preecho_dec};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::corpus_sized;
use crate::state_dump;

#[test]
fn init_decoder_matches_the_reference_on_the_whole_state() {
    // Each output rate on a zeroed state, then on a pattern-filled one.
    let Some(cases) = corpus_sized("init_dec", "init_decoder", 8) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        if case.i32("filled") != 0 {
            state_dump::fill(&mut st, case.i32("pattern") as u32);
        }
        st.output_fs = case.i32("output_fs");
        st.output_frame = case.i16("output_frame");
        init_decoder(&mut st);
        let context = format!(
            "init_decoder at {} Hz, filled {}",
            st.output_fs,
            case.i32("filled")
        );
        state_dump::check(&mut st, &case.outputs, "st.", &context);
        destroy_decoder(&mut st);
        assert!(st.cldfb_ana.is_none() && st.cldfb_syn.is_none() && st.h_fd_cng_dec.is_none());
    }
}

#[test]
fn reset_preecho_dec_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("init_dec", "reset_preecho", 4) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        state_dump::fill(&mut st, case.i32("pattern") as u32);
        reset_preecho_dec(&mut st);
        state_dump::check(&mut st, &case.outputs, "st.", "reset_preecho_dec");
    }
}
