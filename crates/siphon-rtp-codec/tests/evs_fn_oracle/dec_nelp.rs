//! `lib_dec/dec_nelp_fx.c` (`decod_nelp_fx`) against `fn_dec_nelp`, over a sequence of good
//! frames then lost ones (`fn/nelp_common.h`); every frame's outputs are compared, and the whole
//! state after the sequence (see `state_case.rs`).

use siphon_rtp_codec::evs::dec::dec_nelp::decod_nelp;

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn decod_nelp_matches_the_reference_over_good_and_lost_frames() {
    let Some(cases) = corpus_sized("dec_nelp", "decod_nelp", 600) else {
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
            let mut exc2 = vec![0i16; 256];
            let mut pitch_buf = vec![-1i16; 5];
            let mut voice_factors = vec![-1i16; 5];
            let mut bwe_exc = vec![-1i16; 256 * 5 / 2 + 8];
            let mut gain_buf = vec![-1i16; 5];
            let mut tmp_noise = -1;
            decod_nelp(
                &mut st,
                case.i16("coder_type"),
                &mut tmp_noise,
                &mut pitch_buf,
                &mut exc_buf,
                subfr,
                &mut exc2,
                &mut voice_factors,
                &mut bwe_exc,
                &mut q_exc,
                frame_bfi,
                &mut gain_buf,
            );
            let key = |name: &str| format!("f{frame}.{name}");
            check(
                case,
                &key("exc"),
                &exc_buf[subfr..].to_vec(),
                &case.out_i16s(&key("exc")),
            );
            check(case, &key("exc2"), &exc2, &case.out_i16s(&key("exc2")));
            check(case, &key("q_exc"), &q_exc, &case.out_i16(&key("q_exc")));
            check(
                case,
                &key("tmp_noise"),
                &tmp_noise,
                &case.out_i16(&key("tmp_noise")),
            );
            check(
                case,
                &key("pitch_buf"),
                &pitch_buf,
                &case.out_i16s(&key("pitch_buf")),
            );
            check(
                case,
                &key("voice_factors"),
                &voice_factors,
                &case.out_i16s(&key("voice_factors")),
            );
            check(
                case,
                &key("bwe_exc"),
                &bwe_exc,
                &case.out_i16s(&key("bwe_exc")),
            );
            check(
                case,
                &key("gain_buf"),
                &gain_buf,
                &case.out_i16s(&key("gain_buf")),
            );
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
