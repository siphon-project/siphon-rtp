//! `lib_dec/pit_dec.c` (MODE1 pitch decoding) against `fn_pit_dec`.

use siphon_rtp_codec::evs::dec::pit_dec::{
    abs_pit_dec, delta_pit_dec, pit16k_q_dec, pit_decode, pit_q_dec,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch, Case};

fn compare(case: &Case, names: &[&str], rust: &[i16]) {
    let reference: Vec<i16> = names.iter().map(|name| case.out_i16(name)).collect();
    if let Some(message) = mismatch(case, &names.join("/"), &rust.to_vec(), &reference) {
        panic!("{message}");
    }
}

#[test]
fn pit_decode_matches_the_reference() {
    let Some(cases) = corpus("pit_dec", "pit_decode") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.next_bit_pos = case.i16("next_bit_pos");
        st.codec_mode = 1;
        let (mut limit_flag, mut t0, mut t0_frac, mut t0_min, mut t0_max) = (
            case.i16("limit_flag"),
            case.i16("t0"),
            case.i16("t0_frac"),
            case.i16("t0_min"),
            case.i16("t0_max"),
        );
        let pitch = pit_decode(
            &mut st,
            case.i32("core_brate"),
            case.i16("opt_amr_wb"),
            case.i16("l_frame"),
            case.i16("i_subfr"),
            case.i16("coder_type"),
            &mut limit_flag,
            &mut t0,
            &mut t0_frac,
            &mut t0_min,
            &mut t0_max,
            case.i16("l_subfr"),
        );
        compare(
            case,
            &[
                "pitch",
                "limit_flag",
                "t0",
                "t0_frac",
                "t0_min",
                "t0_max",
                "ber_detect",
                "next_bit_pos",
            ],
            &[
                pitch,
                limit_flag,
                t0,
                t0_frac,
                t0_min,
                t0_max,
                st.ber_detect,
                st.next_bit_pos,
            ],
        );
    }
}

#[test]
fn pit_q_dec_matches_the_reference() {
    let Some(cases) = corpus("pit_dec", "pit_q_dec") else {
        return;
    };
    for case in &cases {
        let (mut t0, mut t0_frac, mut t0_min, mut t0_max, mut ber) = (
            case.i16("t0"),
            case.i16("t0_frac"),
            case.i16("t0_min"),
            case.i16("t0_max"),
            case.i16("ber_detect"),
        );
        pit_q_dec(
            case.i16("opt_amr_wb"),
            case.i16("pitch_index"),
            case.i16("n_bits"),
            case.i16("delta"),
            case.i16("pit_flag"),
            case.i16("limit_flag"),
            &mut t0,
            &mut t0_frac,
            &mut t0_min,
            &mut t0_max,
            &mut ber,
        );
        compare(
            case,
            &["t0", "t0_frac", "t0_min", "t0_max", "ber_detect"],
            &[t0, t0_frac, t0_min, t0_max, ber],
        );
    }
}

#[test]
fn pit16k_q_dec_matches_the_reference() {
    let Some(cases) = corpus("pit_dec", "pit16k_q_dec") else {
        return;
    };
    for case in &cases {
        let (mut t0, mut t0_frac, mut t0_min, mut t0_max, mut ber) = (
            case.i16("t0"),
            case.i16("t0_frac"),
            case.i16("t0_min"),
            case.i16("t0_max"),
            0,
        );
        pit16k_q_dec(
            case.i16("pitch_index"),
            case.i16("n_bits"),
            case.i16("limit_flag"),
            &mut t0,
            &mut t0_frac,
            &mut t0_min,
            &mut t0_max,
            &mut ber,
        );
        compare(
            case,
            &["t0", "t0_frac", "t0_min", "t0_max", "ber_detect"],
            &[t0, t0_frac, t0_min, t0_max, ber],
        );
    }
}

#[test]
fn abs_and_delta_pit_dec_match_the_reference() {
    let Some(cases) = corpus("pit_dec", "abs_delta") else {
        return;
    };
    for case in &cases {
        let fr_steps = case.i16("fr_steps");
        let pitch_index = case.i16("pitch_index");
        let (mut abs_t0, mut abs_t0_frac) = (case.i16("t0"), case.i16("t0_frac"));
        abs_pit_dec(
            fr_steps,
            pitch_index,
            case.i16("limit_flag"),
            &mut abs_t0,
            &mut abs_t0_frac,
        );
        let (mut t0, mut t0_frac) = (case.i16("t0"), case.i16("t0_frac"));
        delta_pit_dec(
            fr_steps,
            pitch_index & 63,
            &mut t0,
            &mut t0_frac,
            case.i16("t0_min"),
        );
        compare(
            case,
            &["abs_t0", "abs_t0_frac", "delta_t0", "delta_t0_frac"],
            &[abs_t0, abs_t0_frac, t0, t0_frac],
        );
    }
}
