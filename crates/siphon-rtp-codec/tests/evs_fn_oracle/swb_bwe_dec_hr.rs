//! `lib_dec/swb_bwe_dec_hr_fx.c` against `fn_swb_bwe_dec_hr`. Three frames run on one state, so the
//! coefficients, long-term energy and overlap memory one frame leaves are what the next (or a lost)
//! one reads. `Gain_Dequant_HR` and `TD_Postprocess` are file-local and proven through it.

use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::swb_bwe_dec_hr::swb_bwe_dec_hr;

use crate::common::{corpus_sized, mismatch, Case};

const FRAMES: usize = 3;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn check_state(case: &Case, prefix: &str, st: &DecoderState) {
    let state = vec![
        st.prev_ener_shb,
        st.prev_swb_fenv[0],
        st.prev_swb_fenv[13],
        st.q_old_wtda,
        st.old_is_transient_hr_bwe,
        st.mem_energy_lt_fx_exp,
        st.bwe_highrate_seed,
        st.next_bit_pos,
        st.ber_detect,
        st.t_audio_prev_fx_exp[0],
        st.t_audio_prev_fx_exp[1],
        st.t_audio_prev_fx_exp[2],
        st.t_audio_prev_fx_exp[3],
    ];
    check(
        case,
        &format!("{prefix}_state"),
        &state,
        &case.out_i16s(&format!("{prefix}_state")),
    );
    check(
        case,
        &format!("{prefix}_energy_lt"),
        &st.l_mem_energy_lt,
        &case.out_i32(&format!("{prefix}_energy_lt")),
    );
    check(
        case,
        &format!("{prefix}_wtda"),
        &st.l_old_wtda_swb.to_vec(),
        &case.out_i16s(&format!("{prefix}_wtda")),
    );
    check(
        case,
        &format!("{prefix}_prev"),
        &st.t_audio_prev.to_vec(),
        &case.out_i16s(&format!("{prefix}_prev")),
    );
}

#[test]
fn swb_bwe_dec_hr_matches_the_reference() {
    // each case is three 48 kHz-sized frames of state: a smaller corpus keeps the run short
    let Some(cases) = corpus_sized("swb_bwe_dec_hr", "swb_bwe_dec_hr", 400) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let output_frame = case.i16("output_frame");
        let cfg = case.i16s("cfg");
        st.extl = cfg[0];
        st.q_old_wtda = cfg[1];
        st.old_is_transient_hr_bwe = cfg[2];
        st.mem_energy_lt_fx_exp = cfg[3];
        st.bws_cnt1 = cfg[4];
        st.l_mem_energy_lt = case.i32("init_energy_lt");
        st.t_audio_prev_fx_exp
            .copy_from_slice(&case.i16s("init_exps"));
        st.t_audio_prev.copy_from_slice(&case.i16s("init_prev"));
        st.l_old_wtda_swb.copy_from_slice(&case.i16s("init_wtda"));
        for f in 0..FRAMES {
            let in16 = case.i16s(&format!("f{f}_in16"));
            let (exp, unbits) = (in16[0], in16[1]);
            st.bfi = in16[2];
            st.last_core = in16[3];
            st.last_extl = in16[4];
            st.clas_dec = in16[5];
            st.nb_lost_cmpt = in16[6];
            st.bws_cnt1 = in16[7];
            for (slot, bit) in st
                .bit_stream
                .iter_mut()
                .zip(case.i16s(&format!("f{f}_bits")))
            {
                *slot = bit as u16;
            }
            st.total_num_bits = 1280;
            st.next_bit_pos = 0;
            st.codec_mode = 1;
            let mut hb = vec![-7i16; 960];
            let hb_exp = swb_bwe_dec_hr(
                &mut st,
                &case.i16s(&format!("f{f}_syn")),
                exp,
                &mut hb,
                output_frame,
                unbits,
                &case.i16s(&format!("f{f}_pitch")),
            );
            check(
                case,
                &format!("f{f}_exp"),
                &hb_exp,
                &case.out_i16(&format!("f{f}_exp")),
            );
            check(
                case,
                &format!("f{f}_hb"),
                &hb[..output_frame as usize].to_vec(),
                &case.out_i16s(&format!("f{f}_hb")),
            );
            check_state(case, &format!("f{f}"), &st);
        }
    }
}
