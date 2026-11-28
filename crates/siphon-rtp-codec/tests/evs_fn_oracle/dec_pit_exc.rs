//! `lib_dec/dec_pit_exc_fx.c` (`dec_pit_exc_fx`) against `fn_dec_pit_exc`.
//!
//! Each case is one to three consecutive frames on one decoder state (the oracle shifts the
//! excitation histories between frames as `acelp_core_dec_fx` does, and so does this replay), over
//! the GSC coder's subframe counts 1, 2 and 4, noisy speech or not, and every 12.8 kHz GSC rate.

use siphon_rtp_codec::evs::cnst::{
    L_EXC_DEC, L_EXC_MEM_DEC, L_FRAME, L_FRAME16K, L_SUBFR16K, MODE1, PIT16K_MAX,
};
use siphon_rtp_codec::evs::dec::dec_pit_exc::dec_pit_exc;
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

#[test]
fn dec_pit_exc_matches_the_reference() {
    let Some(cases) = corpus_sized("dec_pit_exc", "dec_pit_exc", 1000) else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        *st = DecoderState::zeroed();
        st.codec_mode = MODE1;
        st.core_brate = case.i32("core_brate");
        st.l_frame = L_FRAME;
        st.gsc_noisy_speech = case.i16("noisy");
        st.q_exc = case.i16("q_exc");
        st.q_subfr.copy_from_slice(&case.i16s("q_subfr"));
        let dct = case.i16s("dct_post_old_exc");
        st.dct_post_old_exc[..dct.len()].copy_from_slice(&dct);
        st.last_exc_dct_in
            .copy_from_slice(&case.i16s("last_exc_dct_in"));
        st.lp_gainp = case.i16("lp_gainp");
        st.lp_gainc = case.i16("lp_gainc");
        st.tilt_code = case.i16("tilt_code");
        st.stl.carry = case.i16("carry") != 0;

        let nb_subfr = case.i16("nb_subfr");
        let coder_type = case.i16("coder_type");
        let mut old_exc = case.i16s("old_exc");
        assert_eq!(old_exc.len(), L_EXC_DEC as usize);
        let mut old_bwe = case.i16s("old_bwe");
        assert_eq!(old_bwe.len(), BWE_LEN);
        let mut code = case.i16s("code");
        let mut pitch_buf = case.i16s("pitch_buf");
        let mut gain_buf = case.i16s("gain_buf");
        let frames = case.i32("frames") as usize;

        for f in 0..frames {
            let bits = case.i32s(&format!("bits{f}"));
            st.bit_stream.fill(0);
            for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
                *slot = bit as u16;
            }
            st.total_num_bits = bits.len() as i16;
            st.next_bit_pos = case.i16(&format!("next_bit_pos{f}"));
            st.ber_detect = case.i16(&format!("ber{f}"));
            dec_pit_exc(
                &mut st,
                &case.i16s(&format!("aq{f}")),
                coder_type,
                case.i16(&format!("es_pred{f}")),
                &mut pitch_buf,
                &mut code,
                &mut old_exc,
                EXC_AT,
                &mut old_bwe,
                BWE_AT,
                nb_subfr,
                &mut gain_buf,
            );
            for (name, rust) in [
                ("pitch_buf", pitch_buf.clone()),
                ("gain_buf", gain_buf.clone()),
                ("code", code.clone()),
                ("next_bit_pos", vec![st.next_bit_pos]),
                ("ber_detect", vec![st.ber_detect]),
                ("q_exc", vec![st.q_exc]),
                ("lp_gainp", vec![st.lp_gainp]),
                ("lp_gainc", vec![st.lp_gainc]),
                ("tilt_code", vec![st.tilt_code]),
            ] {
                let name = format!("{name}{f}");
                check(case, &name, &rust, &case.out_i16s(&name));
            }
            if f + 1 == frames {
                break;
            }
            // next frame: shift the excitation histories, as acelp_core_dec_fx's updates do
            old_exc.copy_within(L_FRAME as usize.., 0);
            old_bwe.copy_within(2 * L_FRAME as usize.., 0);
        }

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
        check(
            case,
            "carry",
            &i16::from(st.stl.carry),
            &case.out_i16("carry"),
        );
        check(case, "old_exc", &old_exc, &case.out_i16s("old_exc"));
        check(case, "old_bwe", &old_bwe, &case.out_i16s("old_bwe"));
    }
}
