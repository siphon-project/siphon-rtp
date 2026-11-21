//! `lib_dec/transition_dec_fx.c` against `fn_transition_dec`: `tc_classif_fx` alone, and a whole
//! TRANSITION frame (`transition_dec_fx` for every subframe, reaching `tc_dec_fx` in the TC
//! subframe) with the pitch state traced after each subframe.

use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::transition_dec::{tc_classif, transition_dec};

use crate::common::{corpus, corpus_sized, mismatch, Case};

/// `L_EXC_MEM_DEC` and `PIT16k_MAX * 2`: where the frame starts in the excitation buffers.
const EXC_AT: usize = 480;
const BWE_AT: usize = 578;

fn stream(case: &Case) -> Box<DecoderState> {
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

fn check(case: &Case, name: &str, rust: &[i16]) {
    if let Some(message) = mismatch(case, name, &rust.to_vec(), &case.out_i16s(name)) {
        panic!("{message}");
    }
}

#[test]
fn tc_classif_matches_the_reference() {
    let Some(cases) = corpus("transition_dec", "tc_classif") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let tc = tc_classif(&mut st, case.i16("l_frame"));
        check(case, "tc", &[tc]);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
        check(case, "ber_detect", &[st.ber_detect]);
    }
}

#[test]
fn transition_dec_matches_the_reference() {
    // Each case carries the full excitation buffers; a smaller corpus keeps the run short.
    let Some(cases) = corpus_sized("transition_dec", "transition_dec", 1000) else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let l_frame = case.i16("l_frame");
        let core_brate = case.i32("core_brate");
        let coder_type = case.i16("coder_type");
        let q_exc = case.i16("q_exc");
        st.q_exc = q_exc;
        let tc_subfr = if case.i16("classify") != 0 {
            tc_classif(&mut st, l_frame)
        } else {
            case.i16("tc_subfr")
        };
        assert_eq!(tc_subfr, case.i16("tc_subfr"), "{}", case.line);
        let mut jopt = case.i16("jopt");
        let (mut t0, mut t0_frac) = (case.i16("t0"), case.i16("t0_frac"));
        let (mut t0_min, mut t0_max) = (case.i16("t0_min"), case.i16("t0_max"));
        let mut position = case.i16("position");
        let mut exc = case.i16s("exc");
        let mut bwe = case.i16s("bwe");
        let mut pitch = vec![-1i16; 5];
        let mut pt_pitch = 0usize;
        let mut trace = Vec::new();
        let mut i_subfr = 0;
        while i_subfr < l_frame {
            transition_dec(
                &mut st,
                core_brate,
                0,
                l_frame,
                i_subfr,
                coder_type,
                tc_subfr,
                &mut jopt,
                &mut exc,
                EXC_AT,
                &mut t0,
                &mut t0_frac,
                &mut t0_min,
                &mut t0_max,
                &mut pitch,
                &mut pt_pitch,
                &mut position,
                &mut bwe,
                BWE_AT,
                q_exc,
            );
            trace.extend_from_slice(&[
                jopt,
                t0,
                t0_frac,
                t0_min,
                t0_max,
                position,
                pt_pitch as i16,
                st.next_bit_pos,
            ]);
            pt_pitch += 1;
            i_subfr += 64;
        }
        check(case, "trace", &trace);
        check(case, "pitch", &pitch);
        check(case, "exc", &exc);
        check(case, "bwe", &bwe);
        check(case, "ber_detect", &[st.ber_detect]);
    }
}
