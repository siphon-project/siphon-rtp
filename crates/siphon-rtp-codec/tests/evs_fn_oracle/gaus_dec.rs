//! `lib_dec/gaus_dec_fx.c` against `fn_gaus_dec`: a whole unvoiced frame (four `gaus_dec_fx`
//! calls carrying the excitation buffers and the decoder's Q / gain memories), and
//! `gaus_dec2v_fx` (with `dec_2pos_fx`) alone.

use siphon_rtp_codec::evs::dec::gaus_dec::{gaus_dec, gaus_dec2v};
use siphon_rtp_codec::evs::dec::state::DecoderState;

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
fn gaus_dec_matches_the_reference() {
    // Each case carries the full excitation buffers; a smaller corpus keeps the run short.
    let Some(cases) = corpus_sized("gaus_dec", "gaus_dec", 500) else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let core_brate = case.i32("core_brate");
        st.core_brate = core_brate;
        st.l_frame = case.i16("l_frame");
        st.q_exc = case.i16("q_exc");
        st.q_subfr.copy_from_slice(&case.i16s("q_subfr"));
        st.lp_gainp = case.i16("lp_gainp");
        st.lp_gainc = case.i16("lp_gainc");
        st.tilt_code = case.i16("tilt_code");
        st.dct_post_old_exc.copy_from_slice(&case.i16s("dct_post"));
        st.last_exc_dct_in.copy_from_slice(&case.i16s("last_dct"));
        let mut exc = case.i16s("exc");
        let mut bwe = case.i16s("bwe");
        let mut exc2 = case.i16s("exc2");

        let mut code = vec![0i16; 4 * 64];
        let mut scalars = Vec::new();
        let mut gains = Vec::new();
        for s in 0..4 {
            let mut norm_gain: i32 = 0x1234;
            let mut gain_code: i32 = 0x4321;
            let (mut inv_gain, mut voice_fac, mut gain_pit, mut pitch) = (7i16, 7i16, 7i16, 7i16);
            gaus_dec(
                &mut st,
                core_brate,
                (s * 64) as i16,
                &mut code[s * 64..(s + 1) * 64],
                &mut norm_gain,
                &mut inv_gain,
                &mut voice_fac,
                &mut gain_pit,
                &mut pitch,
                &mut exc,
                EXC_AT,
                &mut gain_code,
                &mut exc2,
                &mut bwe,
                BWE_AT,
            );
            scalars.extend_from_slice(&[
                inv_gain,
                voice_fac,
                gain_pit,
                pitch,
                st.q_exc,
                st.ber_detect,
            ]);
            gains.extend_from_slice(&[norm_gain, gain_code]);
        }
        check(case, "code", &code);
        check(case, "scalars", &scalars);
        if let Some(message) = mismatch(case, "gains", &gains, &case.out_i32s("gains")) {
            panic!("{message}");
        }
        check(case, "exc", &exc);
        check(case, "bwe", &bwe);
        check(case, "exc2", &exc2);
        check(case, "dct_post", &st.dct_post_old_exc);
        check(case, "last_dct", &st.last_exc_dct_in);
        check(case, "q_subfr", &st.q_subfr);
        check(case, "lp_gainp", &[st.lp_gainp]);
        check(case, "lp_gainc", &[st.lp_gainc]);
        check(case, "tilt_code", &[st.tilt_code]);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
    }
}

#[test]
fn gaus_dec2v_matches_the_reference() {
    let Some(cases) = corpus("gaus_dec", "gaus_dec2v") else {
        return;
    };
    for case in &cases {
        let mut st = stream(case);
        let mut code = vec![-3i16; 64];
        gaus_dec2v(&mut st, &mut code, case.i16("lg"), case.i16("nb_bits"));
        check(case, "code", &code);
        check(case, "next_bit_pos", &[st.next_bit_pos]);
        check(case, "ber_detect", &[st.ber_detect]);
    }
}
