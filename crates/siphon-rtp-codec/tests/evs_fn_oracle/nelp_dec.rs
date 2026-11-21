//! `lib_dec/nelp_dec_fx.c` (`nelp_decoder_fx`, `normalize_arr`) against `fn_nelp_dec`.
//!
//! `nelp_decoder_fx` runs over a sequence of good frames then lost ones on a decoder built by
//! `init_decoder_fx` with randomised NELP state (`fn/nelp_common.h`); every frame's outputs are
//! compared, and the whole state after the sequence (see `state_case.rs`).

use siphon_rtp_codec::evs::dec::nelp_dec::{nelp_decoder, normalize_arr};

use crate::common::{corpus, corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn normalize_arr_matches_the_reference() {
    let Some(cases) = corpus("nelp_dec", "normalize_arr") else {
        return;
    };
    for case in &cases {
        let mut arr = case.i16s("arr");
        let mut qf = 0;
        normalize_arr(&mut arr, &mut qf, case.i16("size"), case.i16("hdr"));
        check(case, "arr", &arr, &case.out_i16s("arr"));
        check(case, "qf", &qf, &case.out_i16("qf"));
    }
}

#[test]
fn nelp_decoder_matches_the_reference_over_good_and_lost_frames() {
    let Some(cases) = corpus_sized("nelp_dec", "nelp_decoder", 600) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let subfr = 64usize;
        let mut exc_buf = vec![0i16; subfr + 256];
        exc_buf[..subfr].copy_from_slice(&case.i16s("exc_history"));
        let mut q_exc = case.i16("q_exc");
        let bfi = case.i16s("bfi");
        for (frame, &frame_bfi) in bfi.iter().enumerate() {
            let mut exc_nelp = vec![0i16; 256];
            let mut gain_buf = vec![-1i16; 5];
            nelp_decoder(
                &mut st,
                &mut exc_nelp,
                &exc_buf,
                subfr,
                &mut q_exc,
                frame_bfi,
                case.i16("coder_type"),
                &mut gain_buf,
            );
            let key = |name: &str| format!("f{frame}.{name}");
            check(
                case,
                &key("exc_nelp"),
                &exc_nelp,
                &case.out_i16s(&key("exc_nelp")),
            );
            check(case, &key("q_exc"), &q_exc, &case.out_i16(&key("q_exc")));
            check(
                case,
                &key("gain_buf"),
                &gain_buf,
                &case.out_i16s(&key("gain_buf")),
            );
            exc_buf[subfr..].copy_from_slice(&exc_nelp);
            if frame + 1 < bfi.len() {
                exc_buf.copy_within(256..256 + subfr, 0);
                st.last_nelp_mode_dec = 1;
                st.last_bwidth = st.bwidth;
            }
        }
        let context = format!("case {index}: bfi {bfi:?}, bwidth {}", st.bwidth);
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}
