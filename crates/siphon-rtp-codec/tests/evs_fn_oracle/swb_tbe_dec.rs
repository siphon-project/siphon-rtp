//! `lib_dec/swb_tbe_dec_fx.c` against `fn_swb_tbe_dec` (buffer initialisation and reset).

use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::swb_tbe_dec::{init_swb_dec_buffer, reset_shb_buffer_dec};

use crate::common::{corpus, Case};

fn load(case: &Case, st: &mut DecoderState) {
    st.mem_csfilt.copy_from_slice(&case.i32s("mem_csfilt"));
    st.state_syn_shbexc
        .copy_from_slice(&case.i16s("state_syn_shbexc"));
    st.state_lpc_syn
        .copy_from_slice(&case.i16s("state_lpc_syn"));
    st.fb_state_lpc_syn
        .copy_from_slice(&case.i16s("fb_state_lpc_syn"));
    st.fb_tbe_demph = case.i16("fb_tbe_demph");
    for (row, values) in st
        .fbbwe_hpf_mem
        .iter_mut()
        .zip(case.i32s("fbbwe_hpf_mem").chunks(4))
    {
        row.copy_from_slice(values);
    }
    st.fbbwe_hpf_mem_fx_q
        .copy_from_slice(&case.i16s("fbbwe_hpf_mem_fx_q"));
    st.prev_fbbwe_ratio = case.i16("prev_fbbwe_ratio");
    st.mem_gen_sh_bexc_filt_down_shb
        .copy_from_slice(&case.i16s("mem_gen_sh_bexc_filt_down_shb"));
    st.mem_gen_sh_bexc_filt_down_wb2
        .copy_from_slice(&case.i16s("mem_gen_sh_bexc_filt_down_wb2"));
    st.mem_gen_sh_bexc_filt_down_wb3
        .copy_from_slice(&case.i16s("mem_gen_sh_bexc_filt_down_wb3"));
    st.state_lsyn_filt_shb
        .copy_from_slice(&case.i16s("state_lsyn_filt_shb"));
    st.state_lsyn_filt_dwn_shb
        .copy_from_slice(&case.i16s("state_lsyn_filt_dwn_shb"));
    st.state_32and48k_wb_upsample
        .copy_from_slice(&case.i16s("state_32and48k_wb_upsample"));
    st.syn_overlap.copy_from_slice(&case.i16s("syn_overlap"));
    st.lsp_prevfrm.copy_from_slice(&case.i16s("lsp_prevfrm"));
    st.gain_frame_prevfrm = case.i32("gain_frame_prevfrm");
    st.gain_attn = case.i16("gain_attn");
    st.tbe_demph = case.i16("tbe_demph");
    st.tbe_premph = case.i16("tbe_premph");
    st.mem_stp_swb.copy_from_slice(&case.i16s("mem_stp_swb"));
    st.gain_prec_swb = case.i16("gain_prec_swb");
    st.gain_shape_delay
        .copy_from_slice(&case.i16s("gain_shape_delay"));
    st.old_core_synth
        .copy_from_slice(&case.i16s("old_core_synth"));
    st.old_tbe_synth
        .copy_from_slice(&case.i16s("old_tbe_synth"));
    st.tilt_swb_fec = case.i16("tilt_swb_fec");
    st.old_bwe_exc.copy_from_slice(&case.i16s("old_bwe_exc"));
    st.bwe_seed.copy_from_slice(&case.i16s("bwe_seed"));
    st.old_bwe_exc_extended
        .copy_from_slice(&case.i16s("old_bwe_exc_extended"));
    st.bwe_non_lin_prev_scale = case.i32("bwe_non_lin_prev_scale");
    st.last_voice_factor = case.i16("last_voice_factor");
    st.gen_sh_bsynth_hilbert_mem
        .copy_from_slice(&case.i32s("gen_sh_bsynth_hilbert_mem"));
    st.gen_sh_bsynth_state_lsyn_filt_shb_local
        .copy_from_slice(&case.i16s("gen_sh_bsynth_state_lsyn_filt_shb_local"));
    st.syn_dm_phase = case.i16("syn_dm_phase");
    st.prev_wb_bwe_frame_pow = case.i32("prev_wb_bwe_frame_pow");
    st.prev_swb_bwe_frame_pow = case.i32("prev_swb_bwe_frame_pow");
    st.prev_fb_ener_adjust = case.i16("prev_fb_ener_adjust");
    st.prev_lpc_wb.copy_from_slice(&case.i16s("prev_lpc_wb"));
    st.prev_q_bwe_exc = case.i16("prev_q_bwe_exc");
    st.prev_ener_fx_q = case.i16("prev_ener_fx_q");
    st.prev_qx = case.i16("prev_qx");
    st.prev_frame_pow_exp = case.i16("prev_frame_pow_exp");
    st.prev_q_bwe_syn = case.i16("prev_q_bwe_syn");
    st.prev_q_bwe_syn2 = case.i16("prev_q_bwe_syn2");
}

fn fields(st: &DecoderState) -> Vec<(&'static str, Vec<i64>)> {
    vec![
        (
            "mem_csfilt",
            st.mem_csfilt.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "state_syn_shbexc",
            st.state_syn_shbexc.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "state_lpc_syn",
            st.state_lpc_syn.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "fb_state_lpc_syn",
            st.fb_state_lpc_syn.iter().map(|&v| i64::from(v)).collect(),
        ),
        ("fb_tbe_demph", vec![i64::from(st.fb_tbe_demph)]),
        (
            "fbbwe_hpf_mem",
            st.fbbwe_hpf_mem
                .iter()
                .flatten()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "fbbwe_hpf_mem_fx_q",
            st.fbbwe_hpf_mem_fx_q
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        ("prev_fbbwe_ratio", vec![i64::from(st.prev_fbbwe_ratio)]),
        (
            "mem_gen_sh_bexc_filt_down_shb",
            st.mem_gen_sh_bexc_filt_down_shb
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "mem_gen_sh_bexc_filt_down_wb2",
            st.mem_gen_sh_bexc_filt_down_wb2
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "mem_gen_sh_bexc_filt_down_wb3",
            st.mem_gen_sh_bexc_filt_down_wb3
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "state_lsyn_filt_shb",
            st.state_lsyn_filt_shb
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "state_lsyn_filt_dwn_shb",
            st.state_lsyn_filt_dwn_shb
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "state_32and48k_wb_upsample",
            st.state_32and48k_wb_upsample
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "syn_overlap",
            st.syn_overlap.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "lsp_prevfrm",
            st.lsp_prevfrm.iter().map(|&v| i64::from(v)).collect(),
        ),
        ("gain_frame_prevfrm", vec![i64::from(st.gain_frame_prevfrm)]),
        ("gain_attn", vec![i64::from(st.gain_attn)]),
        ("tbe_demph", vec![i64::from(st.tbe_demph)]),
        ("tbe_premph", vec![i64::from(st.tbe_premph)]),
        (
            "mem_stp_swb",
            st.mem_stp_swb.iter().map(|&v| i64::from(v)).collect(),
        ),
        ("gain_prec_swb", vec![i64::from(st.gain_prec_swb)]),
        (
            "gain_shape_delay",
            st.gain_shape_delay.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "old_core_synth",
            st.old_core_synth.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "old_tbe_synth",
            st.old_tbe_synth.iter().map(|&v| i64::from(v)).collect(),
        ),
        ("tilt_swb_fec", vec![i64::from(st.tilt_swb_fec)]),
        (
            "old_bwe_exc",
            st.old_bwe_exc.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "bwe_seed",
            st.bwe_seed.iter().map(|&v| i64::from(v)).collect(),
        ),
        (
            "old_bwe_exc_extended",
            st.old_bwe_exc_extended
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "bwe_non_lin_prev_scale",
            vec![i64::from(st.bwe_non_lin_prev_scale)],
        ),
        ("last_voice_factor", vec![i64::from(st.last_voice_factor)]),
        (
            "gen_sh_bsynth_hilbert_mem",
            st.gen_sh_bsynth_hilbert_mem
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        (
            "gen_sh_bsynth_state_lsyn_filt_shb_local",
            st.gen_sh_bsynth_state_lsyn_filt_shb_local
                .iter()
                .map(|&v| i64::from(v))
                .collect(),
        ),
        ("syn_dm_phase", vec![i64::from(st.syn_dm_phase)]),
        (
            "prev_wb_bwe_frame_pow",
            vec![i64::from(st.prev_wb_bwe_frame_pow)],
        ),
        (
            "prev_swb_bwe_frame_pow",
            vec![i64::from(st.prev_swb_bwe_frame_pow)],
        ),
        (
            "prev_fb_ener_adjust",
            vec![i64::from(st.prev_fb_ener_adjust)],
        ),
        (
            "prev_lpc_wb",
            st.prev_lpc_wb.iter().map(|&v| i64::from(v)).collect(),
        ),
        ("prev_q_bwe_exc", vec![i64::from(st.prev_q_bwe_exc)]),
        ("prev_ener_fx_q", vec![i64::from(st.prev_ener_fx_q)]),
        ("prev_qx", vec![i64::from(st.prev_qx)]),
        ("prev_frame_pow_exp", vec![i64::from(st.prev_frame_pow_exp)]),
        ("prev_q_bwe_syn", vec![i64::from(st.prev_q_bwe_syn)]),
        ("prev_q_bwe_syn2", vec![i64::from(st.prev_q_bwe_syn2)]),
    ]
}

fn run(function: &str, call: fn(&mut DecoderState)) {
    let Some(cases) = corpus("swb_tbe_dec", function) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        st.extl = case.i16("extl");
        load(case, &mut st);
        call(&mut st);
        for (name, rust) in fields(&st) {
            assert_eq!(
                rust, case.outputs[name],
                "{name} differs\n  case: {}",
                case.line
            );
        }
    }
}

#[test]
fn init_swb_dec_buffer_matches_the_reference() {
    run("init", init_swb_dec_buffer);
}

#[test]
fn reset_shb_buffer_dec_matches_the_reference() {
    run("reset", reset_shb_buffer_dec);
}
