//! `lib_dec/dec_tran_fx.c` against `fn_dec_tran`: `decod_tran_fx` over a whole TRANSITION frame
//! (after `tc_classif_fx`), at both internal rates and across the 24.4 / 32 kbit/s branches.

use siphon_rtp_codec::evs::dec::dec_tran::decod_tran;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::transition_dec::tc_classif;

use crate::common::{corpus_sized, mismatch, Case};

/// `L_EXC_MEM_DEC` and `PIT16k_MAX * 2`: where the frame starts in the excitation buffers.
const EXC_AT: usize = 480;
const BWE_AT: usize = 578;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn load_state(case: &Case, st: &mut DecoderState) {
    let s = case.i16s("st");
    st.tilt_code = s[0];
    st.prev_gain_pit_dec = s[1];
    st.lp_gainp = s[2];
    st.lp_gainc = s[3];
    st.q_exc = s[4];
    st.next_bit_pos = s[5];
    st.ber_detect = s[6];
    st.dm.prev_state = s[7];
    st.stab_fac = s[8];
    st.mem_preemp_pre_q = s[9];
    st.last_nq_pre_q = s[10];
    st.use_acelp_preq = s[11];
    st.stl.carry = s[12] != 0;
    let l = case.i32s("l");
    st.gc_threshold = l[0];
    st.dm.prev_gain_code = l[1];
    st.dm
        .prev_gain_pit
        .copy_from_slice(&case.i16s("prev_gain_pit"));
    st.tilt_code_dec
        .copy_from_slice(&case.i16s("tilt_code_dec"));
    st.q_subfr.copy_from_slice(&case.i16s("q_subfr"));
    st.dct_post_old_exc.copy_from_slice(&case.i16s("dct_post"));
    st.last_exc_dct_in.copy_from_slice(&case.i16s("last_dct"));
}

fn check_state(case: &Case, st: &DecoderState) {
    let s = vec![
        st.tilt_code,
        st.prev_gain_pit_dec,
        st.lp_gainp,
        st.lp_gainc,
        st.q_exc,
        st.next_bit_pos,
        st.ber_detect,
        st.dm.prev_state,
        st.stab_fac,
        st.mem_preemp_pre_q,
        st.last_nq_pre_q,
        st.use_acelp_preq,
        i16::from(st.stl.carry),
    ];
    check(case, "st", &s, &case.out_i16s("st"));
    check(
        case,
        "l",
        &vec![st.gc_threshold, st.dm.prev_gain_code],
        &case.out_i32s("l"),
    );
    for (name, rust) in [
        ("prev_gain_pit", st.dm.prev_gain_pit.to_vec()),
        ("tilt_code_dec", st.tilt_code_dec.to_vec()),
        ("q_subfr", st.q_subfr.to_vec()),
        ("dct_post", st.dct_post_old_exc.to_vec()),
        ("last_dct", st.last_exc_dct_in.to_vec()),
    ] {
        check(case, name, &rust, &case.out_i16s(name));
    }
}

#[test]
fn decod_tran_matches_the_reference() {
    // Each case carries the full excitation buffers; a smaller corpus keeps the run short.
    let Some(cases) = corpus_sized("dec_tran", "decod_tran", 1000) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.codec_mode = 1;
        let l_frame = case.i16("l_frame");
        st.l_frame = l_frame;
        st.core_brate = case.i32("core_brate");
        load_state(case, &mut st);
        let mut exc = case.i16s("exc");
        let mut bwe = case.i16s("bwe");
        let mut exc2 = case.i16s("exc2");
        let mut pitch_buf = vec![-7i16; 5];
        let mut voice_factors = vec![-7i16; 5];
        let mut gain_buf = vec![-7i16; 5];
        let mut unbits = case.i16("unbits");
        let tc_subfr = tc_classif(&mut st, l_frame);
        check(case, "tc_subfr", &tc_subfr, &case.out_i16("tc_subfr"));
        decod_tran(
            &mut st,
            l_frame,
            tc_subfr,
            &case.i16s("aq"),
            4, // TRANSITION
            case.i16("es_pred"),
            &mut pitch_buf,
            &mut voice_factors,
            &mut exc,
            EXC_AT,
            &mut exc2,
            &mut bwe,
            BWE_AT,
            &mut unbits,
            case.i16("sharp"),
            &mut gain_buf,
        );
        check(case, "pitch_buf", &pitch_buf, &case.out_i16s("pitch_buf"));
        check(
            case,
            "voice_factors",
            &voice_factors,
            &case.out_i16s("voice_factors"),
        );
        check(case, "gain_buf", &gain_buf, &case.out_i16s("gain_buf"));
        check(case, "unbits", &unbits, &case.out_i16("unbits"));
        check(case, "exc", &exc, &case.out_i16s("exc"));
        check(case, "bwe", &bwe, &case.out_i16s("bwe"));
        check(case, "exc2", &exc2, &case.out_i16s("exc2"));
        check_state(case, &st);
    }
}
