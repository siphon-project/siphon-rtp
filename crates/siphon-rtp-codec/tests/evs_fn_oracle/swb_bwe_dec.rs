//! `lib_dec/swb_bwe_dec_fx.c` against `fn_swb_bwe_dec`. The decoder-state functions replay three
//! consecutive frames on one state, so the BWE memories one frame leaves are what the next reads.

use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::swb_bwe_dec::{
    para_pred_bws, swb_bwe_dec, swb_bwe_gain_deq, wb_bwe_dec, wb_bwe_gain_deq,
};

use crate::common::{corpus, corpus_sized, mismatch, Case};

const FRAMES: usize = 3;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn load_bits(st: &mut DecoderState, bits: &[i16], next_bit_pos: i16) {
    for (slot, &bit) in st.bit_stream.iter_mut().zip(bits) {
        *slot = bit as u16;
    }
    st.total_num_bits = bits.len() as i16;
    st.next_bit_pos = next_bit_pos;
    st.codec_mode = 1;
}

#[test]
fn para_pred_bws_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_dec", "para_pred_bws") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        st.tilt_wb = case.i16("tilt_wb");
        st.attenu = case.i16("attenu");
        st.bws_cnt = case.i16("bws_cnt");
        st.l_frame = case.i16("l_frame");
        st.prev_swb_fenv
            .copy_from_slice(&case.i16s("prev_swb_fenv"));
        for f in 0..FRAMES {
            let signal = case.i16s(&format!("f{f}_signal"));
            let frame = case.i16s(&format!("f{f}_frame"));
            let frame32 = case.i32s(&format!("f{f}_frame32"));
            let (q_syn, coder_type) = (frame[0], frame[1]);
            st.last_core = frame[2];
            st.last_codec_mode = frame[3];
            st.prev_coder_type = frame[4];
            st.core_brate = frame32[0];
            st.last_core_brate = frame32[1];
            st.ener_lh = frame32[2];
            st.prev_ener_lh = frame32[3];
            st.ener_ll = frame32[4];
            st.prev_ener_ll = frame32[5];
            let mut fenv = [-7i16; 14];
            let mode = para_pred_bws(&mut st, &signal, &mut fenv, q_syn, coder_type);
            let rust = [vec![mode, st.attenu], fenv.to_vec()].concat();
            check(
                case,
                &format!("f{f}_out"),
                &rust,
                &case.i16s(&format!("f{f}_out")),
            );
        }
    }
}

#[test]
fn wb_bwe_gain_deq_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_dec", "wb_bwe_gain_deq") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        load_bits(&mut st, &case.i16s("bits"), case.i16("next_bit_pos"));
        let mut fenv = [-7i16; 2];
        let mode = wb_bwe_gain_deq(&mut st, &mut fenv);
        check(case, "mode", &mode, &case.out_i16("mode"));
        check(case, "fenv", &fenv.to_vec(), &case.out_i16s("fenv"));
        check(
            case,
            "next_bit_pos/ber_detect",
            &vec![st.next_bit_pos, st.ber_detect],
            &vec![case.out_i16("next_bit_pos"), case.out_i16("ber_detect")],
        );
    }
}

#[test]
fn swb_bwe_gain_deq_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_dec", "swb_bwe_gain_deq") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        load_bits(&mut st, &case.i16s("bits"), case.i16("next_bit_pos"));
        st.bws_cnt1 = case.i16("bws_cnt1");
        let mut tenv = [-7i16; 4];
        let mut fenv = [-7i16; 17];
        let mode = swb_bwe_gain_deq(
            &mut st,
            case.i16("core"),
            &mut tenv,
            &mut fenv,
            case.i16("hr_flag"),
            case.i16("hqswb_clas"),
        );
        check(case, "mode", &mode, &case.out_i16("mode"));
        check(case, "tenv", &tenv.to_vec(), &case.out_i16s("tenv"));
        check(case, "fenv", &fenv.to_vec(), &case.out_i16s("fenv"));
        check(
            case,
            "next_bit_pos/ber_detect",
            &vec![st.next_bit_pos, st.ber_detect],
            &vec![case.out_i16("next_bit_pos"), case.out_i16("ber_detect")],
        );
    }
}

fn wb_state(st: &DecoderState) -> Vec<i16> {
    vec![
        st.old_wtda_swb_fx_exp,
        st.mem_imdct_exp,
        st.prev_q_synth,
        st.prev_l_swb_norm,
        st.Seed,
        st.prev_flag,
        st.last_wb_bwe_ener,
        st.prev_mode,
    ]
}

fn check_wb_state(case: &Case, prefix: &str, st: &DecoderState) {
    check(
        case,
        &format!("{prefix}_state"),
        &wb_state(st),
        &case.i16s(&format!("{prefix}_state")),
    );
    check(
        case,
        &format!("{prefix}_energy"),
        &st.prev_energy_wb,
        &case.i32(&format!("{prefix}_energy")),
    );
    check(
        case,
        &format!("{prefix}_fenv"),
        &st.prev_swb_fenv.to_vec(),
        &case.i16s(&format!("{prefix}_fenv")),
    );
    check(
        case,
        &format!("{prefix}_wtda"),
        &st.l_old_wtda_swb.to_vec(),
        &case.i16s(&format!("{prefix}_wtda")),
    );
    check(
        case,
        &format!("{prefix}_imdct"),
        &st.mem_imdct.to_vec(),
        &case.i16s(&format!("{prefix}_imdct")),
    );
}

#[test]
fn wb_bwe_dec_matches_the_reference() {
    // each case is three 48 kHz-sized frames of state: a smaller corpus keeps the run short
    let Some(cases) = corpus_sized("swb_bwe_dec", "wb_bwe_dec", 300) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let output_frame = case.i16("output_frame");
        st.output_fs = case.i32("output_fs");
        let init = case.i16s("init_state");
        st.old_wtda_swb_fx_exp = init[0];
        st.mem_imdct_exp = init[1];
        st.prev_q_synth = init[2];
        st.prev_l_swb_norm = init[3];
        st.Seed = init[4];
        st.prev_flag = init[5];
        st.last_wb_bwe_ener = init[6];
        st.prev_mode = init[7];
        st.prev_energy_wb = case.i32("init_energy");
        st.prev_swb_fenv.copy_from_slice(&case.i16s("init_fenv"));
        st.l_old_wtda_swb.copy_from_slice(&case.i16s("init_wtda"));
        st.mem_imdct.copy_from_slice(&case.i16s("init_imdct"));
        for f in 0..FRAMES {
            let in16 = case.i16s(&format!("f{f}_in16"));
            let in32 = case.i32s(&format!("f{f}_in32"));
            let mut qpost = in16[0];
            let coder_type = in16[1];
            st.bfi = in16[2];
            st.last_extl = in16[3];
            st.prev_coder_type = in16[4];
            st.tilt_wb = in16[5];
            st.total_brate = in32[0];
            st.last_core_brate = in32[1];
            st.extl = 6; // WB_BWE
            load_bits(&mut st, &case.i16s(&format!("f{f}_bits")), in16[6]);
            let mut synth = case.i16s(&format!("f{f}_synth"));
            let mut hb = vec![-7i16; 960];
            let q_hb = wb_bwe_dec(
                &mut synth,
                &mut hb,
                output_frame,
                coder_type,
                &case.i16s(&format!("f{f}_voice")),
                &case.i16s(&format!("f{f}_pitch")),
                &mut st,
                &mut qpost,
            );
            check(
                case,
                &format!("f{f}_q"),
                &vec![q_hb, qpost, st.next_bit_pos],
                &case.i16s(&format!("f{f}_q")),
            );
            check(
                case,
                &format!("f{f}_osynth"),
                &synth,
                &case.i16s(&format!("f{f}_osynth")),
            );
            check(
                case,
                &format!("f{f}_hb"),
                &hb[..output_frame as usize].to_vec(),
                &case.i16s(&format!("f{f}_hb")),
            );
            check_wb_state(case, &format!("f{f}"), &st);
        }
    }
}

/// The BWE memories `swb_bwe_dec` reads and writes, in the order the harness prints them.
fn swb_state(st: &DecoderState) -> Vec<i16> {
    vec![
        st.old_wtda_swb_fx_exp,
        st.mem_imdct_exp,
        st.prev_l_swb_norm,
        st.Seed,
        st.prev_mode,
        st.prev_energy,
        st.prev_weight,
        st.prev_frica_flag,
        st.prev_td_energy,
        st.prev_fb_ener_adjust,
        st.prev_ener_shb,
        st.attenu,
        st.bws_cnt,
        st.bws_cnt1,
        st.next_bit_pos,
        st.ber_detect,
    ]
}

fn check_swb_state(case: &Case, prefix: &str, st: &DecoderState) {
    check(
        case,
        &format!("{prefix}_state"),
        &swb_state(st),
        &case.i16s(&format!("{prefix}_state")),
    );
    check(
        case,
        &format!("{prefix}_fenv"),
        &st.prev_swb_fenv.to_vec(),
        &case.i16s(&format!("{prefix}_fenv")),
    );
    check(
        case,
        &format!("{prefix}_wtda"),
        &st.l_old_wtda_swb.to_vec(),
        &case.i16s(&format!("{prefix}_wtda")),
    );
    check(
        case,
        &format!("{prefix}_imdct"),
        &st.mem_imdct.to_vec(),
        &case.i16s(&format!("{prefix}_imdct")),
    );
}

#[test]
fn swb_bwe_dec_matches_the_reference() {
    // each case is three 48 kHz-sized frames of state: a smaller corpus keeps the run short
    let Some(cases) = corpus_sized("swb_bwe_dec", "swb_bwe_dec", 400) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let output_frame = case.i16("output_frame");
        let cfg = case.i16s("init_cfg");
        st.extl = cfg[0];
        st.l_frame = cfg[1];
        st.tilt_wb = cfg[2];
        let init = case.i16s("init_state");
        st.old_wtda_swb_fx_exp = init[0];
        st.mem_imdct_exp = init[1];
        st.prev_l_swb_norm = init[2];
        st.Seed = init[3];
        st.prev_mode = init[4];
        st.prev_energy = init[5];
        st.prev_weight = init[6];
        st.prev_frica_flag = init[7];
        st.prev_td_energy = init[8];
        st.prev_fb_ener_adjust = init[9];
        st.prev_ener_shb = init[10];
        st.attenu = init[11];
        st.bws_cnt = init[12];
        st.bws_cnt1 = init[13];
        st.prev_swb_fenv.copy_from_slice(&case.i16s("init_fenv"));
        st.l_old_wtda_swb.copy_from_slice(&case.i16s("init_wtda"));
        st.mem_imdct.copy_from_slice(&case.i16s("init_imdct"));
        for f in 0..FRAMES {
            let in16 = case.i16s(&format!("f{f}_in16"));
            let in32 = case.i32s(&format!("f{f}_in32"));
            let mut qpost = in16[0];
            let coder_type = in16[1];
            st.bfi = in16[2];
            st.last_extl = in16[3];
            st.prev_coder_type = in16[4];
            st.last_core = in16[5];
            st.last_codec_mode = in16[6];
            st.tilt_wb = in16[8];
            st.core_brate = in32[0];
            st.last_core_brate = in32[1];
            st.ener_lh = in32[2];
            st.prev_ener_lh = in32[3];
            st.ener_ll = in32[4];
            st.prev_ener_ll = in32[5];
            load_bits(&mut st, &case.i16s(&format!("f{f}_bits")), in16[7]);
            let mut synth = case.i16s(&format!("f{f}_synth"));
            let mut hb = vec![-7i16; 960];
            let q_hb = swb_bwe_dec(
                &mut st,
                &mut synth,
                &mut hb,
                output_frame,
                &mut qpost,
                coder_type,
            );
            check(
                case,
                &format!("f{f}_q"),
                &vec![q_hb, qpost],
                &case.i16s(&format!("f{f}_q")),
            );
            check(
                case,
                &format!("f{f}_osynth"),
                &synth,
                &case.i16s(&format!("f{f}_osynth")),
            );
            check(
                case,
                &format!("f{f}_hb"),
                &hb[..output_frame as usize].to_vec(),
                &case.i16s(&format!("f{f}_hb")),
            );
            check_swb_state(case, &format!("f{f}"), &st);
        }
    }
}
