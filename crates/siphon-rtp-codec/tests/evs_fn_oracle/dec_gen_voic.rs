//! `lib_dec/dec_gen_voic_fx.c` (`decod_gen_voic_fx`) against `fn_dec_gen_voic`.
//!
//! Each case is one to three consecutive frames on one decoder state (the oracle shifts the
//! excitation histories between frames as `acelp_core_dec_fx` does, and so does this replay), over
//! every MODE1 rate, frame length and coder type the function is called with, with and without
//! the FEC fast recovery (`do_WI`).

use siphon_rtp_codec::evs::cnst::{
    L_EXC_DEC, L_EXC_MEM, L_EXC_MEM_DEC, L_FRAME16K, L_SUBFR16K, MODE1, NB_SUBFR16K, PIT16K_MAX,
};
use siphon_rtp_codec::evs::dec::dec_gen_voic::decod_gen_voic;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus_sized, mismatch, Case};

const BWE_LEN: usize = (PIT16K_MAX as usize + (L_FRAME16K as usize + 1) + L_SUBFR16K as usize) * 2;
const BWE_AT: usize = PIT16K_MAX as usize * 2;
const EXC_AT: usize = L_EXC_MEM_DEC as usize;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn load_state(case: &Case, st: &mut DecoderState) {
    *st = DecoderState::zeroed();
    st.codec_mode = MODE1;
    st.core_brate = case.i32("core_brate");
    st.l_frame = case.i16("l_frame");
    st.output_fs = case.i32("output_fs");
    st.q_exc = case.i16("q_exc");
    st.q_subfr.copy_from_slice(&case.i16s("q_subfr"));
    st.q_syn = case.i16("q_syn");
    st.prev_q_exc_fr = case.i16("prev_q_exc_fr");
    st.prev_q_syn_fr = case.i16("prev_q_syn_fr");
    let dct = case.i16s("dct_post_old_exc");
    st.dct_post_old_exc[..dct.len()].copy_from_slice(&dct);
    st.last_exc_dct_in
        .copy_from_slice(&case.i16s("last_exc_dct_in"));
    st.lp_gainp = case.i16("lp_gainp");
    st.lp_gainc = case.i16("lp_gainc");
    st.tilt_code = case.i16("tilt_code");
    st.stab_fac = case.i16("stab_fac");
    st.gc_threshold = case.i32("gc_threshold");
    st.dm.prev_state = case.i16("dm_prev_state");
    st.dm.prev_gain_code = case.i32("dm_prev_gain_code");
    st.dm
        .prev_gain_pit
        .copy_from_slice(&case.i16s("dm_prev_gain_pit"));
    st.mem_preemp_pre_q = case.i16("mem_preemp_preq");
    st.last_nq_pre_q = case.i16("last_nq_preq");
    st.use_acelp_preq = 0;
    st.bfi_pitch = case.i16("bfi_pitch");
    st.old_exc2.copy_from_slice(&case.i16s("old_exc2"));
    st.old_syn2.copy_from_slice(&case.i16s("old_syn2"));
    st.mem_syn2.copy_from_slice(&case.i16s("mem_syn2"));
    st.stl.carry = case.i16("carry") != 0;
}

#[test]
fn decod_gen_voic_matches_the_reference() {
    let Some(cases) = corpus_sized("dec_gen_voic", "decod_gen_voic", 300) else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        load_state(case, &mut st);
        let l_frame = case.i16("l_frame");
        let lf = l_frame as usize;
        let coder_type = case.i16("coder_type");
        let mut old_exc = case.i16s("old_exc");
        assert_eq!(old_exc.len(), L_EXC_DEC as usize);
        let mut old_bwe = case.i16s("old_bwe");
        assert_eq!(old_bwe.len(), BWE_LEN);
        let mut exc2 = case.i16s("exc2");
        let mut pitch_buf = case.i16s("pitch_buf");
        let mut voice_factors = case.i16s("voice_factors");
        let mut gain_buf = case.i16s("gain_buf");
        let mut unbits = case.i16("unbits");
        let frames = case.i32("frames") as usize;

        for f in 0..frames {
            let bits = case.i32s(&format!("bits{f}"));
            st.bit_stream.fill(0);
            for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
                *slot = bit as u16;
            }
            st.total_num_bits = bits.len() as i16;
            st.next_bit_pos = case.i16(&format!("next_bit_pos{f}"));
            st.ber_detect = 0;
            let aq = case.i16s(&format!("aq{f}"));
            decod_gen_voic(
                &mut st,
                l_frame,
                case.i16(&format!("sharp{f}")),
                &aq,
                coder_type,
                case.i16(&format!("es_pred{f}")),
                case.i16(&format!("do_wi{f}")),
                &mut pitch_buf,
                &mut voice_factors,
                &mut old_exc,
                EXC_AT,
                &mut exc2,
                &mut old_bwe,
                BWE_AT,
                &mut unbits,
                &mut gain_buf,
            );
            check(
                case,
                &format!("pitch_buf{f}"),
                &pitch_buf,
                &case.out_i16s(&format!("pitch_buf{f}")),
            );
            check(
                case,
                &format!("voice_factors{f}"),
                &voice_factors,
                &case.out_i16s(&format!("voice_factors{f}")),
            );
            check(
                case,
                &format!("gain_buf{f}"),
                &gain_buf,
                &case.out_i16s(&format!("gain_buf{f}")),
            );
            check(
                case,
                &format!("exc2_{f}"),
                &exc2,
                &case.out_i16s(&format!("exc2_{f}")),
            );
            for (name, rust) in [
                ("unbits", unbits),
                ("next_bit_pos", st.next_bit_pos),
                ("ber_detect", st.ber_detect),
                ("q_exc", st.q_exc),
            ] {
                let name = format!("{name}{f}");
                check(case, &name, &rust, &case.out_i16(&name));
            }
            if f + 1 == frames {
                break;
            }
            // next frame: shift the excitation histories, as acelp_core_dec_fx's updates do
            old_exc.copy_within(lf.., 0);
            old_bwe.copy_within(2 * lf.., 0);
            let mem = L_EXC_MEM as usize;
            st.old_exc2.copy_within(lf.., 0);
            st.old_exc2[mem - lf..].copy_from_slice(&exc2[..lf]);
            st.prev_q_exc_fr = st.q_exc;
        }

        check(case, "q_exc", &st.q_exc, &case.out_i16("q_exc"));
        check(
            case,
            "q_subfr",
            &st.q_subfr.to_vec(),
            &case.out_i16s("q_subfr"),
        );
        let dct = case.out_i16s("dct_post_old_exc");
        check(
            case,
            "dct_post_old_exc",
            &st.dct_post_old_exc[..dct.len()].to_vec(),
            &dct,
        );
        check(
            case,
            "last_exc_dct_in",
            &st.last_exc_dct_in.to_vec(),
            &case.out_i16s("last_exc_dct_in"),
        );
        for (name, rust) in [
            ("lp_gainp", st.lp_gainp),
            ("lp_gainc", st.lp_gainc),
            ("tilt_code", st.tilt_code),
            ("dm_prev_state", st.dm.prev_state),
            ("mem_preemp_preq", st.mem_preemp_pre_q),
            ("last_nq_preq", st.last_nq_pre_q),
            ("use_acelp_preq", st.use_acelp_preq),
            ("prev_gain_pit_dec", st.prev_gain_pit_dec),
            ("prev_tilt_code_dec", st.prev_tilt_code_dec),
            ("carry", i16::from(st.stl.carry)),
        ] {
            check(case, name, &rust, &case.out_i16(name));
        }
        check(
            case,
            "gc_threshold",
            &st.gc_threshold,
            &case.out_i32("gc_threshold"),
        );
        check(
            case,
            "dm_prev_gain_code",
            &st.dm.prev_gain_code,
            &case.out_i32("dm_prev_gain_code"),
        );
        check(
            case,
            "dm_prev_gain_pit",
            &st.dm.prev_gain_pit.to_vec(),
            &case.out_i16s("dm_prev_gain_pit"),
        );
        check(
            case,
            "old_exc2",
            &st.old_exc2.to_vec(),
            &case.out_i16s("old_exc2"),
        );
        check(
            case,
            "mem_syn2",
            &st.mem_syn2.to_vec(),
            &case.out_i16s("mem_syn2"),
        );
        check(case, "old_exc", &old_exc, &case.out_i16s("old_exc"));
        check(case, "old_bwe", &old_bwe, &case.out_i16s("old_bwe"));
        assert_eq!(pitch_buf.len(), NB_SUBFR16K as usize);
    }
}
