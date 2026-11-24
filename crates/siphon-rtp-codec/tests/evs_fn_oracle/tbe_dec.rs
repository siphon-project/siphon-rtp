//! The TBE decoder of `lib_dec/swb_tbe_dec_fx.c` against `fn_tbe_dec`: every case loads the fields
//! the oracle printed into a [`DecoderState`], calls the port and compares every field afterwards
//! (so a field the port forgets to write, or writes when it should not, is a difference), together
//! with the function's own outputs.

use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::swb_tbe_dec::{
    dequantize_shb_params_9_1, fb_tbe_dec, find_max_mem_dec, find_max_mem_wb, gen_transition,
    gen_transition_wb, gradient_gain_shape, rescale_gen_shb_mem_dec, rescale_gen_wb_mem,
    swb_tbe_dec, tbe_read_bitstream, tbe_reset_dec, wb_tbe_dec,
};

use crate::common::{corpus, corpus_sized, mismatch, Case};

const MODULE: &str = "tbe_dec";

macro_rules! tbe_fields {
    ($mac:ident, $st:ident, $case:ident) => {
        $mac!(
            $st,
            $case,
            "old_bwe_exc_extended",
            old_bwe_exc_extended,
            a16
        );
        $mac!(
            $st,
            $case,
            "mem_gen_sh_bexc_filt_down_shb",
            mem_gen_sh_bexc_filt_down_shb,
            a16
        );
        $mac!(
            $st,
            $case,
            "mem_gen_sh_bexc_filt_down_wb2",
            mem_gen_sh_bexc_filt_down_wb2,
            a16
        );
        $mac!(
            $st,
            $case,
            "mem_gen_sh_bexc_filt_down_wb3",
            mem_gen_sh_bexc_filt_down_wb3,
            a16
        );
        $mac!($st, $case, "state_lpc_syn", state_lpc_syn, a16);
        $mac!($st, $case, "state_syn_shbexc", state_syn_shbexc, a16);
        $mac!($st, $case, "mem_stp_swb", mem_stp_swb, a16);
        $mac!($st, $case, "fb_state_lpc_syn", fb_state_lpc_syn, a16);
        $mac!($st, $case, "syn_overlap", syn_overlap, a16);
        $mac!(
            $st,
            $case,
            "gen_sh_bsynth_state_lsyn_filt_shb_local",
            gen_sh_bsynth_state_lsyn_filt_shb_local,
            a16
        );
        $mac!(
            $st,
            $case,
            "int_3_over_2_tbemem_dec",
            int_3_over_2_tbemem_dec,
            a16
        );
        $mac!($st, $case, "mem_resamp_hb_32k", mem_resamp_hb_32k, a16);
        $mac!($st, $case, "mem_resamp_hb", mem_resamp_hb, a16);
        $mac!($st, $case, "state_lsyn_filt_shb", state_lsyn_filt_shb, a16);
        $mac!(
            $st,
            $case,
            "state_lsyn_filt_dwn_shb",
            state_lsyn_filt_dwn_shb,
            a16
        );
        $mac!(
            $st,
            $case,
            "state_32and48k_wb_upsample",
            state_32and48k_wb_upsample,
            a16
        );
        $mac!($st, $case, "lsp_prevfrm", lsp_prevfrm, a16);
        $mac!($st, $case, "prev_lpc_wb", prev_lpc_wb, a16);
        $mac!($st, $case, "bwe_seed", bwe_seed, a16);
        $mac!($st, $case, "old_tbe_synth", old_tbe_synth, a16);
        $mac!($st, $case, "gain_shape_delay", gain_shape_delay, a16);
        $mac!($st, $case, "lsf_idx", lsf_idx, a16);
        $mac!($st, $case, "idx_res_gs", idx_res_gs, a16);
        $mac!($st, $case, "mem_csfilt", mem_csfilt, a32);
        $mac!(
            $st,
            $case,
            "gen_sh_bsynth_hilbert_mem",
            gen_sh_bsynth_hilbert_mem,
            a32
        );
        $mac!($st, $case, "fbbwe_hpf_mem", fbbwe_hpf_mem, m32);
        $mac!($st, $case, "fbbwe_hpf_mem_fx_q", fbbwe_hpf_mem_fx_q, a16);
        $mac!($st, $case, "tbe_demph", tbe_demph, s16);
        $mac!($st, $case, "tbe_premph", tbe_premph, s16);
        $mac!($st, $case, "fb_tbe_demph", fb_tbe_demph, s16);
        $mac!($st, $case, "extl", extl, s16);
        $mac!($st, $case, "l_frame", l_frame, s16);
        $mac!($st, $case, "bfi", bfi, s16);
        $mac!($st, $case, "prev_bfi", prev_bfi, s16);
        $mac!($st, $case, "bws_cnt", bws_cnt, s16);
        $mac!($st, $case, "use_partial_copy", use_partial_copy, s16);
        $mac!($st, $case, "last_extl", last_extl, s16);
        $mac!($st, $case, "rf_frame_type", rf_frame_type, s16);
        $mac!($st, $case, "rf_indx_tbe_gain_fr", rf_indx_tbe_gain_fr, s16);
        $mac!($st, $case, "core", core, s16);
        $mac!($st, $case, "last_core", last_core, s16);
        $mac!(
            $st,
            $case,
            "prev_use_partial_copy",
            prev_use_partial_copy,
            s16
        );
        $mac!($st, $case, "prev_coder_type", prev_coder_type, s16);
        $mac!($st, $case, "last_coder_type", last_coder_type, s16);
        $mac!($st, $case, "prev_tilt_code_dec", prev_tilt_code_dec, s16);
        $mac!($st, $case, "codec_mode", codec_mode, s16);
        $mac!($st, $case, "prev_q_bwe_exc", prev_q_bwe_exc, s16);
        $mac!($st, $case, "prev_qx", prev_qx, s16);
        $mac!($st, $case, "prev_frame_pow_exp", prev_frame_pow_exp, s16);
        $mac!($st, $case, "last_wb_bwe_ener", last_wb_bwe_ener, s16);
        $mac!($st, $case, "igf", igf, s16);
        $mac!($st, $case, "gain_attn", gain_attn, s16);
        $mac!($st, $case, "prev_fbbwe_ratio", prev_fbbwe_ratio, s16);
        $mac!($st, $case, "rf_flag", rf_flag, s16);
        $mac!($st, $case, "rf_flag_last", rf_flag_last, s16);
        $mac!($st, $case, "last_good", last_good, s16);
        $mac!($st, $case, "nb_lost_cmpt", nb_lost_cmpt, s16);
        $mac!($st, $case, "ber_detect", ber_detect, s16);
        $mac!($st, $case, "bwidth", bwidth, s16);
        $mac!($st, $case, "lsf_wb", lsf_wb, s16);
        $mac!($st, $case, "g_frame_wb", g_frame_wb, s16);
        $mac!($st, $case, "idx_sub_gains", idx_sub_gains, s16);
        $mac!($st, $case, "idx_frame_gain", idx_frame_gain, s16);
        $mac!($st, $case, "idx_shb_fr_gain", idx_shb_fr_gain, s16);
        $mac!($st, $case, "idx_mix_fac", idx_mix_fac, s16);
        $mac!($st, $case, "m_idx", m_idx, s16);
        $mac!($st, $case, "grid_idx", grid_idx, s16);
        $mac!($st, $case, "idx_gain", idx_gain, s16);
        $mac!($st, $case, "tec_tfa", tec_tfa, s16);
        $mac!($st, $case, "tec_flag", tec_flag, s16);
        $mac!($st, $case, "tfa_flag", tfa_flag, s16);
        $mac!($st, $case, "next_bit_pos", next_bit_pos, s16);
        $mac!($st, $case, "total_num_bits", total_num_bits, s16);
        $mac!($st, $case, "prev_fb_ener_adjust", prev_fb_ener_adjust, s16);
        $mac!($st, $case, "gain_prec_swb", gain_prec_swb, s16);
        $mac!(
            $st,
            $case,
            "bwe_non_lin_prev_scale",
            bwe_non_lin_prev_scale,
            s32
        );
        $mac!($st, $case, "total_brate", total_brate, s32);
        $mac!($st, $case, "last_total_brate", last_total_brate, s32);
        $mac!($st, $case, "output_fs", output_fs, s32);
        $mac!($st, $case, "extl_brate", extl_brate, s32);
        $mac!($st, $case, "gain_frame_prevfrm", gain_frame_prevfrm, s32);
        $mac!(
            $st,
            $case,
            "prev_wb_bwe_frame_pow",
            prev_wb_bwe_frame_pow,
            s32
        );
        $mac!($st, $case, "lsp_shb_prev", lsp_shb_prev, a16);
        $mac!($st, $case, "lsp_shb_prev_prev", lsp_shb_prev_prev, a16);
        $mac!($st, $case, "swb_lsp_prev_interp", swb_lsp_prev_interp, a16);
        $mac!($st, $case, "prev_lsf_diff", prev_lsf_diff, a16);
        $mac!($st, $case, "cur_sub_aq", cur_sub_aq, a16);
        $mac!($st, $case, "prev_swb_fenv", prev_swb_fenv, a16);
        $mac!($st, $case, "mem_zero_swb", mem_zero_swb, a16);
        $mac!($st, $case, "clas_dec", clas_dec, s16);
        $mac!($st, $case, "tilt_wb", tilt_wb, s16);
        $mac!($st, $case, "tilt_swb", tilt_swb, s16);
        $mac!($st, $case, "prev_fractive", prev_fractive, s16);
        $mac!($st, $case, "prev_gain_shape", prev_gain_shape, s16);
        $mac!($st, $case, "prev_tilt_para", prev_tilt_para, s16);
        $mac!($st, $case, "bws_cnt1", bws_cnt1, s16);
        $mac!($st, $case, "prev_res_shb_gshape", prev_res_shb_gshape, s16);
        $mac!($st, $case, "prev_mix_factors", prev_mix_factors, s16);
        $mac!($st, $case, "tilt_mem", tilt_mem, s16);
        $mac!($st, $case, "prev_q_bwe_exc_fb", prev_q_bwe_exc_fb, s16);
        $mac!($st, $case, "prev_q_bwe_syn", prev_q_bwe_syn, s16);
        $mac!($st, $case, "prev_q_bwe_syn2", prev_q_bwe_syn2, s16);
        $mac!($st, $case, "prev_ener_fx_q", prev_ener_fx_q, s16);
        $mac!($st, $case, "prev_ener_shb", prev_ener_shb, s16);
        $mac!($st, $case, "tilt_swb_fec", tilt_swb_fec, s16);
        $mac!($st, $case, "next_coder_type", next_coder_type, s16);
        $mac!($st, $case, "cummulative_damping", cummulative_damping, s16);
        $mac!($st, $case, "q_syn2", q_syn2, s16);
        $mac!($st, $case, "shb_dtx_count", shb_dtx_count, s16);
        $mac!($st, $case, "ener_lh", ener_lh, s32);
        $mac!($st, $case, "ener_ll", ener_ll, s32);
        $mac!($st, $case, "prev_ener_lh", prev_ener_lh, s32);
        $mac!($st, $case, "prev_ener_ll", prev_ener_ll, s32);
        $mac!($st, $case, "last_core_brate", last_core_brate, s32);
        $mac!($st, $case, "core_brate", core_brate, s32);
        $mac!($st, $case, "prev1_shb_ener_sf", prev1_shb_ener_sf, s32);
        $mac!($st, $case, "prev2_shb_ener_sf", prev2_shb_ener_sf, s32);
        $mac!($st, $case, "prev3_shb_ener_sf", prev3_shb_ener_sf, s32);
        $mac!($st, $case, "prev_ener", prev_ener, s32);
        $mac!(
            $st,
            $case,
            "prev_swb_bwe_frame_pow",
            prev_swb_bwe_frame_pow,
            s32
        );
    };
}

macro_rules! load_field {
    ($st:ident, $case:ident, $name:literal, $field:ident, a16) => {
        $st.$field.copy_from_slice(&$case.i16s($name));
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, a32) => {
        $st.$field.copy_from_slice(&$case.i32s($name));
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, s16) => {
        $st.$field = $case.i16($name);
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, s32) => {
        $st.$field = $case.i32($name);
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, m32) => {
        for (row, values) in $st.$field.iter_mut().zip($case.i32s($name).chunks(4)) {
            row.copy_from_slice(values);
        }
    };
}

macro_rules! compare_field {
    ($st:ident, $case:ident, $name:literal, $field:ident, a16) => {
        check($case, $name, $st.$field.to_vec(), $case.out_i16s($name));
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, a32) => {
        check($case, $name, $st.$field.to_vec(), $case.out_i32s($name));
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, s16) => {
        check($case, $name, $st.$field, $case.out_i16($name));
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, s32) => {
        check($case, $name, $st.$field, $case.out_i32($name));
    };
    ($st:ident, $case:ident, $name:literal, $field:ident, m32) => {
        check(
            $case,
            $name,
            $st.$field.iter().flatten().copied().collect::<Vec<i32>>(),
            $case.out_i32s($name),
        );
    };
}

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: T, reference: T) {
    if let Some(message) = mismatch(case, name, &rust, &reference) {
        panic!("{message}");
    }
}

fn load(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    tbe_fields!(load_field, st, case);
    // `ptr_mem_stp_swb_fx` points at `mem_stp_swb_fx + LPC_SHB_ORDER - 1`
    st.ptr_mem_stp_swb = 9;
    if let Some(bits) = case.inputs.get("bits") {
        for (slot, &bit) in st.bit_stream.iter_mut().zip(bits) {
            *slot = bit as u16;
        }
    }
    st
}

fn compare(case: &Case, st: &DecoderState) {
    tbe_fields!(compare_field, st, case);
}

#[test]
fn find_max_mem_dec_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "find_max_mem_dec") else {
        return;
    };
    for case in &cases {
        let st = load(case);
        let (mut n_mem, mut n_mem2, mut n_mem3) = (0, 0, 0);
        find_max_mem_dec(&st, &mut n_mem, &mut n_mem2, &mut n_mem3);
        check(case, "n_mem", n_mem, case.out_i16("n_mem"));
        check(case, "n_mem2", n_mem2, case.out_i16("n_mem2"));
        check(case, "n_mem3", n_mem3, case.out_i16("n_mem3"));
        compare(case, &st);
    }
}

#[test]
fn rescale_gen_shb_mem_dec_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "rescale_gen_shb_mem") else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        rescale_gen_shb_mem_dec(&mut st, case.i16("sf"));
        compare(case, &st);
    }
}

#[test]
fn find_max_mem_wb_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "find_max_mem_wb") else {
        return;
    };
    for case in &cases {
        let st = load(case);
        let mut n_mem = 0;
        find_max_mem_wb(&st, &mut n_mem);
        check(case, "n_mem", n_mem, case.out_i16("n_mem"));
        compare(case, &st);
    }
}

#[test]
fn rescale_gen_wb_mem_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "rescale_gen_wb_mem") else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        rescale_gen_wb_mem(&mut st, case.i16("sf"));
        compare(case, &st);
    }
}

#[test]
fn tbe_reset_dec_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "tbe_reset_dec") else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        tbe_reset_dec(&mut st, case.i16("bandwidth"));
        compare(case, &st);
    }
}

#[test]
fn tbe_read_bitstream_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "tbe_read_bitstream") else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        tbe_read_bitstream(&mut st);
        compare(case, &st);
    }
}

#[test]
fn dequantize_shb_params_9_1_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "dequantize") else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        let mut lsf = [0x5a5ai16; 10];
        let mut subgain = [0x5a5ai16; 16];
        let mut res_gshape = [0x5a5ai16; 5];
        let (mut framegain, mut shb_ener) = (0x5a5a_5a5a, 0x5a5a_5a5a);
        let (mut uv_flag, mut mix) = (0i16, 0x5a5ai16);
        dequantize_shb_params_9_1(
            &mut st,
            case.i16("extl"),
            case.i32("extl_brate_arg"),
            &mut lsf,
            &mut subgain,
            &mut framegain,
            &mut uv_flag,
            &mut shb_ener,
            &mut res_gshape,
            &mut mix,
        );
        check(case, "lsf", lsf.to_vec(), case.out_i16s("lsf"));
        check(case, "subgain", subgain.to_vec(), case.out_i16s("subgain"));
        check(case, "framegain", framegain, case.out_i32("framegain"));
        check(case, "uv_flag", uv_flag, case.out_i16("uv_flag"));
        check(case, "shb_ener", shb_ener, case.out_i32("shb_ener"));
        check(
            case,
            "res_gshape",
            res_gshape.to_vec(),
            case.out_i16s("res_gshape"),
        );
        check(case, "mix", mix, case.out_i16("mix"));
        compare(case, &st);
    }
}

#[test]
fn gradient_gain_shape_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "gradient_gain_shape") else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        let mut gain_shape = [0x5a5ai16; 16];
        let mut gain_frame = 0x5a5a_5a5a;
        gradient_gain_shape(&mut st, &mut gain_shape, &mut gain_frame);
        check(
            case,
            "gain_shape",
            gain_shape.to_vec(),
            case.out_i16s("gain_shape"),
        );
        check(case, "gain_frame", gain_frame, case.out_i32("gain_frame"));
        compare(case, &st);
    }
}

#[test]
fn wb_tbe_dec_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "wb_tbe_dec", 600) else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        let mut synth = case.i16s("synth");
        let mut q_synth = 0x5a5a;
        wb_tbe_dec(
            &mut st,
            case.i16("coder_type"),
            &case.i32s("exc"),
            case.i16("q_exc"),
            &case.i16s("vf"),
            &mut synth,
            &mut q_synth,
        );
        compare(case, &st);
        check(case, "synth_out", synth, case.out_i16s("synth_out"));
        check(case, "q_synth", q_synth, case.out_i16("q_synth"));
    }
}

#[test]
fn fb_tbe_dec_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "fb_tbe_dec", 300) else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        let (mut hb1, mut hb2) = (case.i16s("hb1"), case.i16s("hb2"));
        fb_tbe_dec(
            &mut st,
            &case.i16s("exc1"),
            case.i16("q_fb"),
            &mut hb1,
            case.i16("exp1"),
        );
        st.bfi = case.i16("bfi2");
        fb_tbe_dec(
            &mut st,
            &case.i16s("exc2"),
            case.i16("q_fb"),
            &mut hb2,
            case.i16("exp1"),
        );
        check(case, "hb1_out", hb1, case.out_i16s("hb1_out"));
        check(case, "hb2_out", hb2, case.out_i16s("hb2_out"));
        compare(case, &st);
    }
}

#[test]
fn gen_transition_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "gen_transition") else {
        return;
    };
    for case in &cases {
        let mut output = case.i16s("output");
        let mut local = case.i16s("local");
        let mut resamp = case.i16s("resamp");
        let mut up_mem = case.i16s("up_mem");
        let mut hilbert = case.i32s("hilbert");
        let mut phase = case.i16("phase");
        gen_transition(
            &case.i16s("input"),
            &case.i16s("old_hb"),
            case.i16("length"),
            &mut output,
            &mut hilbert,
            &mut local,
            &mut resamp,
            &mut phase,
            case.i32("target_fs"),
            &mut up_mem,
            case.i16("rf_flag"),
            case.i32("bitrate"),
        );
        check(case, "output_out", output, case.out_i16s("output_out"));
        check(case, "local_out", local, case.out_i16s("local_out"));
        check(case, "resamp_out", resamp, case.out_i16s("resamp_out"));
        check(case, "up_mem_out", up_mem, case.out_i16s("up_mem_out"));
        check(case, "hilbert_out", hilbert, case.out_i32s("hilbert_out"));
        check(case, "phase_out", phase, case.out_i16("phase_out"));
    }
}

#[test]
fn gen_transition_wb_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "gen_transition_wb") else {
        return;
    };
    for case in &cases {
        let mut output = case.i16s("output");
        let (mut state1, mut state2) = (case.i16s("state1"), case.i16s("state2"));
        let mut up_mem = case.i16s("up_mem");
        gen_transition_wb(
            &case.i16s("input"),
            &case.i16s("old_hb"),
            case.i16("prev_qx"),
            case.i16("length"),
            &mut output,
            &mut state1,
            &mut state2,
            case.i32("output_fs"),
            &mut up_mem,
        );
        check(case, "output_out", output, case.out_i16s("output_out"));
        check(case, "state1_out", state1, case.out_i16s("state1_out"));
        check(case, "state2_out", state2, case.out_i16s("state2_out"));
        check(case, "up_mem_out", up_mem, case.out_i16s("up_mem_out"));
    }
}

#[test]
fn decimate_allpass_steep_in_place_matches_the_reference() {
    use siphon_rtp_codec::evs::com::modif_fs::decimate_allpass_steep_in_place;
    let Some(cases) = corpus(MODULE, "decimate_in_place") else {
        return;
    };
    for case in &cases {
        let mut buffer = case.i16s("buffer");
        let mut state = case.i16s("state");
        decimate_allpass_steep_in_place(&mut buffer, &mut state, 640);
        check(
            case,
            "buffer_out",
            buffer[..320].to_vec(),
            case.out_i16s("buffer_out"),
        );
        check(case, "state_out", state, case.out_i16s("state_out"));
    }
}

#[test]
fn swb_tbe_dec_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "swb_tbe_dec", 600) else {
        return;
    };
    for case in &cases {
        let mut st = load(case);
        let mut white = case.i16s("white");
        let mut q_white = case.i16("q_white");
        let mut synth = case.i16s("synth");
        let mut q_synth = 0x5a5a;
        swb_tbe_dec(
            &mut st,
            case.i16("coder_type"),
            &case.i32s("exc"),
            case.i16("q_exc"),
            &case.i16s("vf"),
            &case.i16s("old_syn"),
            &mut white,
            &mut q_white,
            &mut synth,
            &mut q_synth,
            &case.i16s("pitch"),
        );
        compare(case, &st);
        check(case, "synth_out", synth, case.out_i16s("synth_out"));
        check(case, "q_synth", q_synth, case.out_i16("q_synth"));
        check(case, "white_out", white, case.out_i16s("white_out"));
        check(case, "q_white_out", q_white, case.out_i16("q_white_out"));
    }
}
