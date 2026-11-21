//! `lib_dec/FEC_fx.c` (`FEC_exc_estim_fx`, `gain_dec_bfi_fx`, `pulseRes_preCalc`) against
//! `fn_FEC`.
//!
//! `FEC_exc_estim_fx` runs over one to three consecutive lost frames on a decoder built by
//! `init_decoder_fx` with a randomised concealment state (`fn/conceal_state.h`): every frame's
//! outputs are compared, and the whole state after the sequence (see `state_case.rs`).

use siphon_rtp_codec::evs::dec::fec::{fec_exc_estim, gain_dec_bfi, pulse_res_pre_calc};

use crate::common::{corpus, corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// `L_EXC_MEM_DEC`, where the current frame starts in the excitation buffer.
const EXC_AT: usize = 480;

#[test]
fn fec_exc_estim_matches_the_reference_over_consecutive_lost_frames() {
    let Some(cases) = corpus_sized("FEC", "fec_exc_estim", 1500) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let mut old_exc = case.i16s("old_exc");
        let lsf_new = case.i16s("lsf_new");
        let frames = case.i16("frames") as usize;
        let context = format!(
            "case {index}: L_frame {}, last_good {}, last_coder_type {}, nbLostCmpt {}, AMR-WB {}",
            st.l_frame, st.last_good, st.last_coder_type, st.nb_lost_cmpt, st.opt_amr_wb
        );
        for frame in 0..frames {
            let mut exc2 = vec![-1i16; 320];
            let mut exc_dct_in = vec![-1i16; 320];
            let mut pitch_buf = vec![-1i16; 5];
            let mut voice_factors = vec![-1i16; 5];
            let mut bwe_exc = vec![-1i16; 648];
            let (mut tmp_tc, mut tmp_noise) = (-1, -1);
            let (l_frame, q_exc) = (st.l_frame, st.q_exc);
            fec_exc_estim(
                &mut st,
                l_frame,
                &mut old_exc,
                EXC_AT,
                &mut exc2,
                &mut exc_dct_in,
                &mut pitch_buf,
                &mut voice_factors,
                &mut tmp_tc,
                &mut bwe_exc,
                &lsf_new,
                q_exc,
                &mut tmp_noise,
            );
            let key = |name: &str| format!("f{frame}.{name}");
            let what = |name: &str| format!("{context}: f{frame}.{name}");
            check(
                case,
                &what("old_exc"),
                &old_exc,
                &case.out_i16s(&key("old_exc")),
            );
            check(case, &what("exc2"), &exc2, &case.out_i16s(&key("exc2")));
            check(
                case,
                &what("exc_dct_in"),
                &exc_dct_in,
                &case.out_i16s(&key("exc_dct_in")),
            );
            check(
                case,
                &what("pitch_buf"),
                &pitch_buf,
                &case.out_i16s(&key("pitch_buf")),
            );
            check(
                case,
                &what("voice_factors"),
                &voice_factors,
                &case.out_i16s(&key("voice_factors")),
            );
            check(
                case,
                &what("tmp_tc"),
                &tmp_tc,
                &case.out_i16(&key("tmp_tc")),
            );
            check(
                case,
                &what("bwe_exc"),
                &bwe_exc,
                &case.out_i16s(&key("bwe_exc")),
            );
            check(
                case,
                &what("tmp_noise"),
                &tmp_noise,
                &case.out_i16(&key("tmp_noise")),
            );
            if frame + 1 < frames {
                let shift = l_frame as usize;
                old_exc.copy_within(shift..shift + EXC_AT, 0);
                st.nb_lost_cmpt += 1;
            }
        }
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}

#[test]
fn pulse_res_pre_calc_matches_the_reference() {
    let Some(cases) = corpus("FEC", "pulse_res_pre_calc") else {
        return;
    };
    for case in &cases {
        let (mut cond1, mut cond2, mut cond3) = (-1, -1, -1);
        pulse_res_pre_calc(
            &mut cond1,
            &mut cond2,
            &mut cond3,
            case.i16("new_pit"),
            case.i16("tc"),
            case.i16("l_frame"),
        );
        let reference = (
            case.out_i16("cond1"),
            case.out_i16("cond2"),
            case.out_i32("cond3"),
        );
        if let Some(message) = mismatch(case, "conds", &(cond1, cond2, cond3), &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn gain_dec_bfi_matches_the_reference() {
    let Some(cases) = corpus("FEC", "gain_dec_bfi") else {
        return;
    };
    for case in &cases {
        let mut past_qua_en = case.i16s("past_qua_en");
        gain_dec_bfi(&mut past_qua_en);
        if let Some(message) = mismatch(
            case,
            "past_qua_en",
            &past_qua_en,
            &case.out_i16s("past_qua_en"),
        ) {
            panic!("{message}");
        }
    }
}
