//! `lib_dec/gs_dec_fx.c` against `fn_gs_dec`: `decod_audio_fx` over one to four consecutive
//! AUDIO / INACTIVE frames, and `gsc_dec_fx` in the form the FEC concealment calls it.
//!
//! Each case is a decoder built by `init_decoder_fx` whose GSC, FEC-gain and excitation state was
//! randomised; the oracle prints the whole state before the first frame ("in.") and, after each
//! frame, the fields that changed since then ("s<f>." / "st."). The Rust replay overlays those on
//! the "before" state and compares the whole state after every frame, so every field the decoder
//! writes, and every field it must leave alone, is checked.

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::cnst::{
    INACTIVE, L_EXC_MEM_DEC, L_FRAME, L_SUBFR, PIT16K_MAX, UNVOICED,
};
use siphon_rtp_codec::evs::dec::gs_dec::{decod_audio, gsc_dec};
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus_sized, Case};
use crate::state_dump;

const FRAME: usize = L_FRAME as usize;

const BWE_AT: usize = PIT16K_MAX as usize * 2;

fn state_before(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);
    state_dump::load(&mut st, &case.inputs, "in.");
    st
}

/// The whole state after a frame: the "before" state with the changed fields (`pre`) overlaid.
fn state_after(case: &Case, pre: &str) -> BTreeMap<String, Vec<i64>> {
    let mut after: BTreeMap<String, Vec<i64>> = case
        .inputs
        .iter()
        .filter_map(|(key, values)| {
            key.strip_prefix("in.")
                .map(|rest| (format!("{pre}{rest}"), values.clone()))
        })
        .collect();
    for (key, values) in &case.outputs {
        if key.starts_with(pre) {
            after.insert(key.clone(), values.clone());
        }
    }
    after
}

fn check<T: PartialEq + std::fmt::Debug>(context: &str, name: &str, rust: &T, reference: &T) {
    assert!(
        rust == reference,
        "{context}: {name} differs\n rust {rust:?}\n  ref {reference:?}"
    );
}

#[test]
fn decod_audio_matches_the_reference_over_consecutive_frames() {
    replay_decod_audio("decod_audio", 300);
}

/// 8 kbit/s WB cases in which a good frame codes the last bins of band 9, the only frames that set
/// `bitallocation_exc` (the oracle draws until it finds one).
#[test]
fn decod_audio_matches_the_reference_when_band_9_reaches_the_8k_edge() {
    replay_decod_audio("decod_audio_band9", 30);
}

fn replay_decod_audio(function: &str, count: usize) {
    let Some(cases) = corpus_sized("gs_dec", function, count) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = state_before(case);
        st.stl.carry = case.i16("carry") != 0;
        let mut old_exc = case.i16s("old_exc");
        let mut old_bwe = case.i16s("old_bwe");
        let mut exc2 = case.i16s("exc2");
        let mut dct_epit = case.i16s("dct_epit");
        let mut pitch_buf = case.i16s("pitch_buf");
        let mut voice_factors = case.i16s("voice_factors");
        let mut gain_buf = case.i16s("gain_buf");
        let frames = case.i16("frames") as usize;
        let mut last_coder_type = 0;
        for f in 0..frames {
            if f > 0 {
                old_exc.copy_within(FRAME.., 0);
                old_bwe.copy_within(2 * FRAME.., 0);
                st.last_coder_type = if last_coder_type == INACTIVE {
                    UNVOICED
                } else {
                    last_coder_type
                };
                st.last_gsc_noisy_speech_flag = st.gsc_noisy_speech;
            }
            for (slot, &bit) in st
                .bit_stream
                .iter_mut()
                .zip(&case.inputs[&format!("bits{f}")])
            {
                *slot = bit as u16;
            }
            st.next_bit_pos = case.i16(&format!("next_bit_pos{f}"));
            st.total_num_bits = case.i16(&format!("total_num_bits{f}"));
            st.bfi = case.i16(&format!("bfi{f}"));
            st.ber_detect = case.i16(&format!("ber{f}"));
            st.last_good = case.i16(&format!("last_good{f}"));
            let coder_type = case.i16(&format!("coder_type{f}"));
            last_coder_type = coder_type;
            let context = format!(
                "{function} case {index} frame {f}: total {} core {} bwidth {} coder_type {coder_type}",
                st.total_brate, st.core_brate, st.bwidth
            );

            decod_audio(
                &mut st,
                &mut dct_epit,
                &case.i16s(&format!("aq{f}")),
                coder_type,
                &mut pitch_buf,
                &mut voice_factors,
                &mut old_exc,
                L_EXC_MEM_DEC as usize,
                &mut exc2,
                &mut old_bwe,
                BWE_AT,
                &case.i16s(&format!("lsf_new{f}")),
                &mut gain_buf,
            );

            for (name, rust) in [
                ("old_exc", &old_exc),
                ("old_bwe", &old_bwe),
                ("exc2", &exc2),
                ("dct_epit", &dct_epit),
                ("pitch_buf", &pitch_buf),
                ("voice_factors", &voice_factors),
                ("gain_buf", &gain_buf),
            ] {
                check(&context, name, rust, &case.out_i16s(&format!("{name}{f}")));
            }
            check(
                &context,
                "carry",
                &i16::from(st.stl.carry),
                &case.out_i16(&format!("carry{f}")),
            );
            let pre = format!("s{f}.");
            state_dump::check(&mut st, &state_after(case, &pre), &pre, &context);
        }
    }
}

#[test]
fn gsc_dec_matches_the_reference_as_the_concealment_calls_it() {
    let Some(cases) = corpus_sized("gs_dec", "gsc_dec", 300) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = state_before(case);
        let mut exc_dct_in = case.i16s("exc_dct_in");
        let mut last_bin = case.i16("last_bin");
        let pit_band_idx = st.last_gsc_pit_band_idx;
        let (nb_subfr, coder_type, q_exc) = (st.l_frame / L_SUBFR, st.last_coder_type, st.q_exc);
        gsc_dec(
            &mut st,
            &mut exc_dct_in,
            pit_band_idx,
            case.i16("diff_len"),
            0,
            nb_subfr,
            coder_type,
            &mut last_bin,
            &case.i16s("lsf_new"),
            None,
            q_exc,
        );
        let context = format!(
            "case {index}: core {} bwidth {} last_coder_type {coder_type} ber {}",
            st.core_brate,
            st.bwidth,
            case.i16("in.BER_detect")
        );
        check(
            &context,
            "exc_dct_in",
            &exc_dct_in,
            &case.out_i16s("exc_dct_in"),
        );
        check(&context, "last_bin", &last_bin, &case.out_i16("last_bin"));
        state_dump::check(&mut st, &state_after(case, "st."), "st.", &context);
    }
}
