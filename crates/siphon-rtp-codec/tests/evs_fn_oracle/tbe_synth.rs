//! The TBE synthesis helpers of `swb_tbe_com_fx.c` against `fn_tbe_synth`. The static Hilbert
//! stages are proven through `flip_and_downmix_generic`, `filt_mu` / `scale_st_swb` /
//! `calc_st_filt_tbe` through `post_short_term`, `flip_spectrum` through `gen_wb_synth`.

use siphon_rtp_codec::evs::com::swb_tbe_com::{
    create_random_vector, estimate_mix_factors, flip_and_downmix_generic,
    flip_spectrum_and_decimby4, gen_shaped_shb_excitation, gen_shaped_wb_excitation, gen_shb_synth,
    gen_wb_synth, post_short_term, scale_shaped_shb, scale_shaped_wb, swb_formant_fac,
    synthesise_fb_high_band,
};
use siphon_rtp_codec::evs::rom::{FULL_BAND_BPF_1_FX, FULL_BAND_BPF_3_FX};

use crate::common::{corpus, corpus_sized, mismatch, Case};

const MODULE: &str = "tbe_synth";

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: T, reference: T) {
    if let Some(message) = mismatch(case, name, &rust, &reference) {
        panic!("{message}");
    }
}

fn to_matrix(values: [Vec<i32>; 4]) -> [[i32; 4]; 4] {
    let mut matrix = [[0i32; 4]; 4];
    for (row, source) in matrix.iter_mut().zip(values) {
        row.copy_from_slice(&source);
    }
    matrix
}

#[test]
fn flip_and_downmix_generic_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "flip_and_downmix", 400) else {
        return;
    };
    for case in &cases {
        let mut input = case.i16s("input");
        let mut output = vec![0i16; 640];
        let (mut mem1, mut mem2, mut mem3) =
            (case.i32s("mem1"), case.i32s("mem2"), case.i32s("mem3"));
        let mut phase = case.i16("phase");
        flip_and_downmix_generic(
            &mut input,
            &mut output,
            640,
            &mut mem1,
            &mut mem2,
            &mut mem3,
            &mut phase,
        );
        check(case, "input_out", input, case.out_i16s("input_out"));
        check(case, "output", output, case.out_i16s("output"));
        check(case, "mem1_out", mem1, case.out_i32s("mem1_out"));
        check(case, "mem2_out", mem2, case.out_i32s("mem2_out"));
        check(case, "mem3_out", mem3, case.out_i32s("mem3_out"));
        check(case, "phase_out", phase, case.out_i16("phase_out"));
    }
}

#[test]
fn flip_spectrum_and_decimby4_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "flip_spectrum_and_decimby4") else {
        return;
    };
    for case in &cases {
        let mut output = vec![0i16; 80];
        let (mut mem1, mut mem2) = (case.i16s("mem1"), case.i16s("mem2"));
        flip_spectrum_and_decimby4(
            &case.i16s("input"),
            &mut output,
            320,
            &mut mem1,
            &mut mem2,
            case.i16("ramp"),
        );
        check(case, "output", output, case.out_i16s("output"));
        check(case, "mem1_out", mem1, case.out_i16s("mem1_out"));
        check(case, "mem2_out", mem2, case.out_i16s("mem2_out"));
    }
}

#[test]
fn create_random_vector_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "create_random_vector") else {
        return;
    };
    for case in &cases {
        let length = case.i16("length");
        let mut output = vec![0i16; 320];
        let mut seed = case.i16s("seed");
        create_random_vector(&mut output, length, &mut seed);
        check(
            case,
            "output",
            output[..length as usize].to_vec(),
            case.out_i16s("output"),
        );
        check(case, "seed_out", seed, case.out_i16s("seed_out"));
    }
}

#[test]
fn post_short_term_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "post_short_term") else {
        return;
    };
    for case in &cases {
        let sig = case.i16s("sig");
        let mut out = vec![0i16; 80];
        let mut mem_stp = case.i16s("mem_stp");
        let mut gain = case.i16("gain");
        let mut mem_zero = vec![0i16; 10];
        post_short_term(
            &sig,
            10,
            &case.i16s("lpc"),
            &mut out,
            &mut mem_stp,
            9,
            &mut gain,
            &mut mem_zero,
            case.i16("formant_fac"),
        );
        check(case, "out", out, case.out_i16s("out"));
        check(case, "mem_stp_out", mem_stp, case.out_i16s("mem_stp_out"));
        check(case, "gain_out", gain, case.out_i16("gain_out"));
        check(
            case,
            "mem_zero_out",
            mem_zero,
            case.out_i16s("mem_zero_out"),
        );
    }
}

#[test]
fn swb_formant_fac_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "swb_formant_fac") else {
        return;
    };
    for case in &cases {
        let mut tilt = case.i16("tilt");
        let result = swb_formant_fac(case.i16("lpc2"), &mut tilt);
        check(case, "result", result, case.out_i16("result"));
        check(case, "tilt_out", tilt, case.out_i16("tilt_out"));
    }
}

#[test]
fn gen_wb_synth_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "gen_wb_synth") else {
        return;
    };
    for case in &cases {
        let mut output = vec![0i16; 320];
        let (mut state1, mut state2) = (case.i16s("state1"), case.i16s("state2"));
        gen_wb_synth(&case.i16s("input"), &mut output, &mut state1, &mut state2);
        check(case, "output", output, case.out_i16s("output"));
        check(case, "state1_out", state1, case.out_i16s("state1_out"));
        check(case, "state2_out", state2, case.out_i16s("state2_out"));
    }
}

#[test]
fn gen_shb_synth_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "gen_shb_synth", 400) else {
        return;
    };
    for case in &cases {
        let mut output = vec![0i16; 640];
        let (mut hilbert, mut allpass) = (case.i32s("hilbert"), case.i16s("allpass"));
        let mut phase = case.i16("phase");
        gen_shb_synth(
            &case.i16s("input"),
            &mut output,
            &mut hilbert,
            &mut allpass,
            case.i16("l_frame"),
            &mut phase,
        );
        check(case, "output", output, case.out_i16s("output"));
        check(case, "allpass_out", allpass, case.out_i16s("allpass_out"));
        check(case, "hilbert_out", hilbert, case.out_i32s("hilbert_out"));
        check(case, "phase_out", phase, case.out_i16("phase_out"));
    }
}

#[test]
fn gen_shaped_wb_excitation_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "gen_shaped_wb_excitation") else {
        return;
    };
    for case in &cases {
        let mut exc_shb = vec![0i16; 80];
        let mut exc4k = vec![0i16; 80];
        let mut mem_csfilt = case.i32s("mem_csfilt");
        let (mut down1, mut down2, mut down3) =
            (case.i16s("down1"), case.i16s("down2"), case.i16s("down3"));
        let mut state_lpc = case.i16s("state_lpc");
        let mut seed = case.i16s("seed");
        gen_shaped_wb_excitation(
            &mut exc_shb,
            &case.i16s("lpc"),
            &mut exc4k,
            &mut mem_csfilt,
            &mut down1,
            &mut down2,
            &mut down3,
            &mut state_lpc,
            case.i16("coder_type"),
            &case.i16s("bwe"),
            case.i16("q_bwe_exc"),
            &mut seed,
            &case.i16s("voice"),
            case.i16("uv_flag"),
            case.i16("igf_flag"),
        );
        check(case, "exc_shb", exc_shb, case.out_i16s("exc_shb"));
        check(case, "exc4k", exc4k, case.out_i16s("exc4k"));
        check(
            case,
            "mem_csfilt_out",
            mem_csfilt,
            case.out_i32s("mem_csfilt_out"),
        );
        check(case, "down1_out", down1, case.out_i16s("down1_out"));
        check(case, "down2_out", down2, case.out_i16s("down2_out"));
        check(case, "down3_out", down3, case.out_i16s("down3_out"));
        check(
            case,
            "state_lpc_out",
            state_lpc,
            case.out_i16s("state_lpc_out"),
        );
        check(case, "seed_out", seed, case.out_i16s("seed_out"));
    }
}

#[test]
fn scale_shaped_shb_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "scale_shaped_shb") else {
        return;
    };
    for case in &cases {
        let length = case.i16("length");
        let mut syn = case.i16s("syn");
        let mut overlap = case.i16s("overlap");
        let mut q_bwe_exc = case.i16("q_bwe_exc");
        let mut qx = 0;
        scale_shaped_shb(
            length,
            &mut syn,
            &mut overlap,
            &case.i16s("subgain"),
            case.i32("frame_gain"),
            &case.i16s("win"),
            &case.i16s("subwin"),
            &mut q_bwe_exc,
            &mut qx,
            case.i16("n_mem3"),
            case.i16("prev"),
        );
        let produced = if length == 10 { 80 } else { 320 };
        check(
            case,
            "syn_out",
            syn[..produced].to_vec(),
            case.out_i16s("syn_out"),
        );
        check(case, "overlap_out", overlap, case.out_i16s("overlap_out"));
        check(
            case,
            "q_bwe_exc_out",
            q_bwe_exc,
            case.out_i16("q_bwe_exc_out"),
        );
        check(case, "qx", qx, case.out_i16("qx"));
    }
}

#[test]
fn scale_shaped_wb_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "scale_shaped_wb") else {
        return;
    };
    for case in &cases {
        let length = case.i16("length");
        let mut syn = case.i16s("syn");
        let mut overlap = case.i16s("overlap");
        let mut qx = 0;
        scale_shaped_wb(
            length,
            &mut syn,
            &mut overlap,
            &case.i16s("subgain"),
            case.i32("frame_gain"),
            &case.i16s("win"),
            &case.i16s("subwin"),
            case.i16("q_bwe_exc"),
            case.i16("l_frame"),
            case.i16("dynq"),
            &mut qx,
            case.i16("prev_qx"),
            &case.i32s("hilbert"),
        );
        let produced = if length == 10 { 80 } else { 320 };
        check(
            case,
            "syn_out",
            syn[..produced].to_vec(),
            case.out_i16s("syn_out"),
        );
        check(case, "overlap_out", overlap, case.out_i16s("overlap_out"));
        check(case, "qx", qx, case.out_i16("qx"));
    }
}

#[test]
fn estimate_mix_factors_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "estimate_mix_factors") else {
        return;
    };
    for case in &cases {
        let mut vf = vec![0i16; 5];
        let mut vf_ind = 0;
        estimate_mix_factors(
            &case.i16s("shb_res"),
            case.i16("q_shb"),
            &case.i16s("exc"),
            case.i16("q_bwe_exc"),
            &case.i16s("white"),
            case.i16("q_frac"),
            case.i32("pow1"),
            case.i16("q_pow1"),
            case.i32("pow22"),
            case.i16("q_pow22"),
            &mut vf,
            &mut vf_ind,
        );
        check(case, "vf", vf, case.out_i16s("vf"));
        check(case, "vf_ind", vf_ind, case.out_i16("vf_ind"));
    }
}

#[test]
fn elliptic_bpf_48k_generic_matches_the_reference() {
    use siphon_rtp_codec::evs::com::swb_tbe_com::elliptic_bpf_48k_generic;
    let Some(cases) = corpus_sized(MODULE, "elliptic_bpf", 60) else {
        return;
    };
    for case in &cases {
        let table = if case.i16("table3") != 0 {
            &FULL_BAND_BPF_3_FX
        } else {
            &FULL_BAND_BPF_1_FX
        };
        let mut memory = [[0i32; 4]; 4];
        let mut memory_q = [0i16; 4];
        let mut q_in = case.i16("q_in");
        let mut out1 = vec![0i16; 960];
        elliptic_bpf_48k_generic(
            &case.i16s("in1"),
            &mut q_in,
            &mut out1,
            &mut memory,
            &mut memory_q,
            table,
        );
        check(case, "out1", out1, case.out_i16s("out1"));
        check(case, "q_mid", q_in, case.out_i16("q_mid"));
        let mut q2 = case.i16("q2_in");
        let mut out2 = vec![0i16; 960];
        elliptic_bpf_48k_generic(
            &case.i16s("in2"),
            &mut q2,
            &mut out2,
            &mut memory,
            &mut memory_q,
            table,
        );
        check(case, "out2", out2, case.out_i16s("out2"));
        check(case, "q2", q2, case.out_i16("q2"));
        check(
            case,
            "memory",
            memory.to_vec(),
            to_matrix([
                case.out_i32s("mem0"),
                case.out_i32s("mem1"),
                case.out_i32s("mem2"),
                case.out_i32s("mem3"),
            ])
            .to_vec(),
        );
        check(
            case,
            "memory_q",
            memory_q.to_vec(),
            case.out_i16s("memory_q"),
        );
    }
}

#[test]
fn synthesise_fb_high_band_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "synthesise_fb", 120) else {
        return;
    };
    for case in &cases {
        let mut memory = [[0i32; 4]; 4];
        let mut memory_q = [0i16; 4];
        let mut prev_ratio = 0;
        let mut out1 = vec![0i16; 960];
        let l_frame = case.i16("l_frame");
        synthesise_fb_high_band(
            &case.i16s("exc1"),
            case.i16("q_fb"),
            &mut out1,
            case.i32("energy1"),
            case.i16("ratio1"),
            l_frame,
            case.i16("bfi1"),
            &mut prev_ratio,
            &mut memory,
            &mut memory_q,
            case.i16("q_out"),
        );
        check(case, "out1", out1, case.out_i16s("out1"));
        check(case, "prev_mid", prev_ratio, case.out_i16("prev_mid"));
        let mut out2 = vec![0i16; 960];
        synthesise_fb_high_band(
            &case.i16s("exc2"),
            case.i16("q_fb"),
            &mut out2,
            case.i32("energy2"),
            case.i16("ratio2"),
            l_frame,
            case.i16("bfi2"),
            &mut prev_ratio,
            &mut memory,
            &mut memory_q,
            case.i16("q_out"),
        );
        check(case, "out2", out2, case.out_i16s("out2"));
        check(case, "prev_ratio", prev_ratio, case.out_i16("prev_ratio"));
        check(
            case,
            "memory",
            memory.to_vec(),
            to_matrix([
                case.out_i32s("mem0"),
                case.out_i32s("mem1"),
                case.out_i32s("mem2"),
                case.out_i32s("mem3"),
            ])
            .to_vec(),
        );
        check(
            case,
            "memory_q",
            memory_q.to_vec(),
            case.out_i16s("memory_q"),
        );
    }
}

#[test]
fn gen_shaped_shb_excitation_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "gen_shaped_shb_excitation", 600) else {
        return;
    };
    for case in &cases {
        let mut exc_shb = case.i16s("exc_shb");
        let mut white_fb = vec![0i16; 320];
        let mut mem_csfilt = vec![case.i32("mem_csfilt"), 0];
        let mut down = case.i16s("down");
        let mut state_lpc = case.i16s("state_lpc");
        let mut seed = case.i16s("seed");
        let mut voice = case.i16s("voice");
        let (mut demph, mut premph) = (case.i16("demph"), case.i16("premph"));
        let mut vf_ind = case.i16("vf_ind");
        let mut fb_state = case.i16s("fb_state");
        let mut fb_demph = case.i16("fb_demph");
        let (mut q_bwe_exc, mut q_fb) = (case.i16("q_bwe_exc"), case.i16("q_fb"));
        gen_shaped_shb_excitation(
            &mut exc_shb,
            20,
            &case.i16s("lpc"),
            &mut white_fb,
            &mut mem_csfilt,
            &mut down,
            &mut state_lpc,
            case.i16("coder_type"),
            &case.i16s("bwe"),
            &mut seed,
            &mut voice,
            case.i16("extl"),
            &mut demph,
            &mut premph,
            &case.i16s("lpc_sf"),
            case.i32("ener"),
            &case.i16s("gshape"),
            &case.i16s("shb_res"),
            &mut vf_ind,
            case.i16("formant"),
            &mut fb_state,
            &mut fb_demph,
            &mut q_bwe_exc,
            &mut q_fb,
            case.i16("q_shb"),
            case.i16("n_mem2"),
            case.i16("prev_q_syn"),
            case.i32("bitrate"),
            case.i16("prev_bfi"),
        );
        check(case, "exc_shb_out", exc_shb, case.out_i16s("exc_shb_out"));
        check(case, "white_fb", white_fb, case.out_i16s("white_fb"));
        check(
            case,
            "mem_csfilt_out",
            mem_csfilt[0],
            case.out_i32("mem_csfilt_out"),
        );
        check(case, "down_out", down, case.out_i16s("down_out"));
        check(
            case,
            "state_lpc_out",
            state_lpc,
            case.out_i16s("state_lpc_out"),
        );
        check(case, "seed_out", seed, case.out_i16s("seed_out"));
        check(case, "voice_out", voice, case.out_i16s("voice_out"));
        check(case, "demph_out", demph, case.out_i16("demph_out"));
        check(case, "premph_out", premph, case.out_i16("premph_out"));
        check(case, "vf_ind_out", vf_ind, case.out_i16("vf_ind_out"));
        check(
            case,
            "fb_state_out",
            fb_state,
            case.out_i16s("fb_state_out"),
        );
        check(case, "fb_demph_out", fb_demph, case.out_i16("fb_demph_out"));
        check(
            case,
            "q_bwe_exc_out",
            q_bwe_exc,
            case.out_i16("q_bwe_exc_out"),
        );
        check(case, "q_fb_out", q_fb, case.out_i16("q_fb_out"));
    }
}
