//! `lib_dec/FEC_HQ_core_fx.c` (`HQ_FEC_Mem_update_fx`) against `fn_fec_hq_core`: three consecutive
//! good frames through one decoder state.

use siphon_rtp_codec::evs::cnst::{MAX_SB_NB, SFM_N_NB};
use siphon_rtp_codec::evs::dec::fec_hq_core::hq_fec_mem_update;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn flat(values: &[[i32; 7]; 3]) -> Vec<i32> {
    values.iter().flatten().copied().collect()
}

#[test]
fn hq_fec_mem_update_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus("fec_hq_core", "hq_fec_mem_update") else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        *st = DecoderState::zeroed();
        st.prev_sign_switch
            .copy_from_slice(&case.i16s("prev_sign_switch"));
        st.prev_sign_switch_2
            .copy_from_slice(&case.i16s("prev_sign_switch_2"));
        st.old_coeffs.copy_from_slice(&case.i32s("old_coeffs"));
        for (row, chunk) in st
            .ynrm_values
            .iter_mut()
            .zip(case.i32s("ynrm_values").chunks(7))
        {
            row.copy_from_slice(chunk);
        }
        st.norm_gain.copy_from_slice(&case.i16s("norm_gain"));
        st.energy_ma_curr
            .copy_from_slice(&case.i16s("energy_ma_curr"));
        st.diff_energy = case.i16("diff_energy");
        st.stat_mode_old = case.i16("stat_mode_old");
        st.stat_mode_out = case.i16("stat_mode_out");
        st.old_min_ind = case.i16("old_min_ind");
        st.phase_mat_flag = case.i16("phase_mat_flag");
        st.old_is_transient
            .copy_from_slice(&case.i16s("old_is_transient"));

        for frame in 0..3 {
            let name = |base: &str| format!("{base}{frame}");
            let mut normq = vec![-1_i32; 44];
            let mut ynrm = case.i16s(&name("ynrm"));
            let mut mean_en_high = -77;
            st.bfi = case.i16(&name("bfi"));
            st.prev_bfi = case.i16(&name("prev_bfi"));
            st.prev_old_bfi = case.i16(&name("prev_old_bfi"));
            st.last_core = case.i16(&name("last_core"));
            st.core = case.i16(&name("core"));
            st.prev_last_core = case.i16(&name("prev_last_core"));
            hq_fec_mem_update(
                &mut st,
                &case.i32s(&name("t_audio")),
                &mut normq,
                &mut ynrm,
                &[8, 8, 2],
                case.i16(&name("is_transient")),
                case.i16(&name("hqswb_clas")),
                case.i16(&name("c_switching")),
                SFM_N_NB,
                MAX_SB_NB,
                &mut mean_en_high,
                case.i16(&name("hq_core_type")),
                case.i16(&name("output_frame")),
            );
            let nb = SFM_N_NB as usize;
            check(
                case,
                &name("normq"),
                &normq[..nb].to_vec(),
                &case.out_i32s(&name("normq")),
            );
            check(
                case,
                &name("ynrm"),
                &ynrm[..nb].to_vec(),
                &case.out_i16s(&name("ynrm")),
            );
            check(
                case,
                &name("mean_en_high"),
                &mean_en_high,
                &case.out_i16(&name("mean_en_high")),
            );
            check(
                case,
                &name("prev_sign_switch_fx"),
                &st.prev_sign_switch.to_vec(),
                &case.out_i16s(&name("prev_sign_switch_fx")),
            );
            check(
                case,
                &name("prev_sign_switch_2_fx"),
                &st.prev_sign_switch_2.to_vec(),
                &case.out_i16s(&name("prev_sign_switch_2_fx")),
            );
            check(
                case,
                &name("old_coeffs_fx"),
                &st.old_coeffs.to_vec(),
                &case.out_i32s(&name("old_coeffs_fx")),
            );
            check(
                case,
                &name("ynrm_values_fx"),
                &flat(&st.ynrm_values),
                &case.out_i32s(&name("ynrm_values_fx")),
            );
            check(
                case,
                &name("Norm_gain_fx"),
                &st.norm_gain.to_vec(),
                &case.out_i16s(&name("Norm_gain_fx")),
            );
            check(
                case,
                &name("energy_MA_Curr_fx"),
                &st.energy_ma_curr.to_vec(),
                &case.out_i16s(&name("energy_MA_Curr_fx")),
            );
            let scalars = [
                ("diff_energy_fx", st.diff_energy),
                ("stat_mode_old_fx", st.stat_mode_old),
                ("stat_mode_out_fx", st.stat_mode_out),
                ("old_Min_ind_fx", st.old_min_ind),
                ("phase_mat_flag_fx", st.phase_mat_flag),
            ];
            for (field, value) in scalars {
                check(case, &name(field), &value, &case.out_i16(&name(field)));
            }
            check(
                case,
                &name("old_is_transient_fx"),
                &st.old_is_transient.to_vec(),
                &case.out_i16s(&name("old_is_transient_fx")),
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The concealment: array helpers on random vectors, then whole frame sequences.

use siphon_rtp_codec::evs::cnst::N_LEAD_NB;
use siphon_rtp_codec::evs::dec::fec_hq_core::*;

const NLEAD: usize = N_LEAD_NB as usize;

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("fec_hq_core", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

fn pha_from(values: &[i16]) -> [[i16; NLEAD]; 2] {
    let mut pha = [[0i16; NLEAD]; 2];
    pha[0].copy_from_slice(&values[..NLEAD]);
    pha[1].copy_from_slice(&values[NLEAD..]);
    pha
}

fn pha_flat(pha: &[[i16; NLEAD]; 2]) -> Vec<i16> {
    pha.iter().flatten().copied().collect()
}

#[test]
fn common_overlapping_matches_the_reference() {
    each("common_overlapping", |case| {
        let mut au_out = vec![-7_i16; 320];
        common_overlapping(
            &mut au_out,
            &case.i16s("win"),
            &case.i16s("old"),
            case.i16("end1"),
            case.i16("offset1"),
            case.i16("start2"),
            case.i16("end2"),
            case.i16("offset_i2"),
            case.i16("offset2"),
        );
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
    });
}

#[test]
fn smoothing_vector_nb_matches_the_reference() {
    each("smoothing_vector_nb", |case| {
        let mut au_out = vec![-7_i16; 200];
        smoothing_vector_nb(
            &case.i16s("old"),
            &case.i16s("win"),
            &case.i16s("smoothing"),
            &mut au_out,
            case.i16("ol_size"),
        );
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
    });
}

#[test]
fn smoothing_vector_scaledown_nb_matches_the_reference() {
    each("smoothing_vector_scaledown_nb", |case| {
        let mut au_out = vec![-7_i16; 200];
        smoothing_vector_scaledown_nb(
            &case.i16s("old"),
            &case.i16s("win"),
            &case.i16s("smoothing"),
            &mut au_out,
            case.i16("ol_size"),
        );
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
    });
}

#[test]
fn windowing_1st_nb_matches_the_reference() {
    each("windowing_1st_nb", |case| {
        let mut out = vec![-7_i16; 320];
        let smoothing = case.i16s("smoothing");
        windowing_1st_nb(
            &mut out,
            &case.i32s("imdct"),
            &case.i16s("win"),
            (case.i16("with_smoothing") != 0).then_some(&smoothing[..]),
        );
        check(case, "out", &out, &case.out_i16s("out"));
    });
}

#[test]
fn windowing_2nd_nb_matches_the_reference() {
    each("windowing_2nd_nb", |case| {
        let mut out = case.i16s("out_in");
        windowing_2nd_nb(&mut out, &case.i32s("imdct"), &case.i16s("win"));
        check(case, "out", &out, &case.out_i16s("out"));
    });
}

#[test]
fn scaledown_matches_the_reference() {
    each("scaledown", |case| {
        let mut y = vec![-7_i16; 160];
        scaledown(&case.i16s("x"), &mut y, case.i16("scale"), case.i16("n"));
        check(case, "y", &y, &case.out_i16s("y"));
    });
}

#[test]
fn next_good_after_burst_erasures_matches_the_reference() {
    each("next_good_after_burst_erasures", |case| {
        let mut au_out = vec![-7_i16; 160];
        let mut old = case.i16s("old");
        next_good_after_burst_erasures(
            &case.i32s("imdct"),
            &mut au_out,
            &mut old,
            case.i16("ol_size"),
        );
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
        check(case, "old", &old, &case.out_i16s("old"));
    });
}

#[test]
fn fec_phase_matching_nextgood_matches_the_reference() {
    each("fec_phase_matching_nextgood", |case| {
        let mut au_out = vec![-7_i16; 160];
        let mut old = case.i16s("old");
        let mut pha = pha_from(&case.i16s("pha"));
        fec_phase_matching_nextgood(
            &case.i32s("imdct"),
            &mut au_out,
            &mut old,
            &mut pha,
            case.i16("mean_en_high"),
        );
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
        check(case, "old", &old, &case.out_i16s("old"));
        check(case, "pha", &pha_flat(&pha), &case.out_i16s("pha"));
    });
}

#[test]
fn fec_phase_matching_burst_matches_the_reference() {
    each("fec_phase_matching_burst", |case| {
        let mut au_out = vec![-7_i16; 160];
        let mut old = case.i16s("old");
        let mut prev_old = case.i16s("prev_old");
        let mut pha = pha_from(&case.i16s("pha"));
        fec_phase_matching_burst(
            &case.i32s("imdct"),
            &mut au_out,
            &mut old,
            &mut pha,
            &mut prev_old,
        );
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
        check(case, "old", &old, &case.out_i16s("old"));
        check(case, "prev_old", &prev_old, &case.out_i16s("prev_old"));
        check(case, "pha", &pha_flat(&pha), &case.out_i16s("pha"));
    });
}

#[test]
fn repetition_smoothing_nextgood_matches_the_reference() {
    each("repetition_smoothing_nextgood", |case| {
        let mut au_out = vec![-7_i16; 160];
        let mut old = case.i16s("old");
        repetition_smoothing_nextgood(
            &case.i32s("imdct"),
            &mut au_out,
            &case.i32s("old_imdct"),
            &mut old,
            case.i16("flag"),
            N_LEAD_NB,
        );
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
        check(case, "old", &old, &case.out_i16s("old"));
    });
}

#[test]
fn repetition_smoothing_matches_the_reference() {
    each("repetition_smoothing", |case| {
        let mut au_out = vec![-7_i16; 160];
        let mut old = case.i16s("old");
        let mut prev_old = case.i16s("prev_old");
        let ret = repetition_smoothing(
            &case.i32s("imdct"),
            &mut au_out,
            &case.i32s("old_imdct"),
            &mut old,
            160,
            &mut prev_old,
            N_LEAD_NB,
        );
        check(case, "ret", &ret, &case.out_i16("ret"));
        check(case, "au_out", &au_out, &case.out_i16s("au_out"));
        check(case, "old", &old, &case.out_i16s("old"));
        check(case, "prev_old", &prev_old, &case.out_i16s("prev_old"));
    });
}

#[test]
fn regression_anal_matches_the_reference() {
    each("regression_anal", |case| {
        let mut r_p = [-7_i32; 2];
        regression_anal(&case.i32s("values"), &mut r_p, case.i16("num_pgf"));
        check(case, "r_p", &r_p.to_vec(), &case.out_i32s("r_p"));
    });
}

#[test]
fn fec_scaling_matches_the_reference() {
    each("fec_scaling", |case| {
        let mut t_audio = vec![-7_i32; 160];
        let mut seed = case.i16("seed");
        fec_scaling(
            &case.i32s("old_coeffs"),
            &mut t_audio,
            &case.i16s("norm_gain"),
            &mut seed,
            case.i16("nb_sfm"),
            &case.i16s("start"),
            &case.i16s("end"),
        );
        check(case, "t_audio", &t_audio, &case.out_i32s("t_audio"));
        check(case, "seed", &seed, &case.out_i16("seed"));
    });
}

#[test]
fn find_best_delay_matches_the_reference() {
    each("find_best_delay", |case| {
        let mut false_flag = -7;
        let d1m = find_best_delay(
            &case.i16s("mu_o"),
            case.i16("in_at") as usize,
            case.i16("mind1"),
            case.i16("maxd1"),
            case.i16("lin"),
            case.i16("delta"),
            &mut false_flag,
        );
        check(case, "d1m", &d1m, &case.out_i16("d1m"));
        check(case, "false_flag", &false_flag, &case.out_i16("false_flag"));
    });
}

#[test]
fn search_max_corr_matches_the_reference() {
    each("search_max_corr", |case| {
        let pos = search_max_corr(&case.i16s("mu_o"), case.i16("old_min_ind"), 160);
        check(case, "pos", &pos, &case.out_i16("pos"));
    });
}

/// Replay one concealment call of an 8 kHz-output frame: `frame` is the sequence frame, `second`
/// the time-domain stage.
fn nb_first_stage(case: &Case, st: &mut DecoderState, frame: usize) {
    use siphon_rtp_codec::evs::dec::hq_conf_fec::hq_configure_bfi;
    let name = |base: &str| format!("f{frame}_{base}");
    let mut nb_sfm = 0;
    let mut num_sb = 0;
    let mut num_bands_p = [0i16; 3];
    let (mut sfmsize, mut sfm_start, mut sfm_end): (&[i16], &[i16], &[i16]) = (&[], &[], &[]);
    hq_configure_bfi(
        &mut nb_sfm,
        &mut num_sb,
        &mut num_bands_p,
        &mut sfmsize,
        &mut sfm_start,
        &mut sfm_end,
    );
    let context = format!("frame {frame}");
    if case.i16(&name("bfi")) == 0 {
        let mut normq = vec![-1_i32; 44];
        let mut ynrm = case.i16s(&name("ynrm"));
        let mut mean_en_high = 0;
        let is_transient = case.i16(&name("is_transient"));
        hq_fec_mem_update(
            st,
            &case.i32s(&name("t_audio")),
            &mut normq,
            &mut ynrm,
            &num_bands_p,
            is_transient,
            is_transient,
            0,
            nb_sfm,
            num_sb,
            &mut mean_en_high,
            0,
            160,
        );
        check(
            case,
            &format!("{context} normq"),
            &normq[..SFM_N_NB as usize].to_vec(),
            &case.i32s(&name("normq")),
        );
        check(
            case,
            &format!("{context} ynrm"),
            &ynrm[..SFM_N_NB as usize].to_vec(),
            &case.i16s(&name("ynrm_out")),
        );
        check(
            case,
            &format!("{context} mean_en_high"),
            &mean_en_high,
            &case.i16(&name("mean_en_high")),
        );
    } else {
        let is_transient = st.old_is_transient[0];
        let mut t_audio = vec![0_i32; 960];
        hq_fec_processing(
            st,
            &mut t_audio,
            is_transient,
            num_sb,
            nb_sfm,
            &num_bands_p,
            160,
            sfm_start,
            sfm_end,
        );
        st.old_is_transient[2] = st.old_is_transient[1];
        st.old_is_transient[1] = st.old_is_transient[0];
        check(
            case,
            &format!("{context} t_audio"),
            &t_audio[..160].to_vec(),
            &case.i32s(&name("t_audio_out")),
        );
    }
}

/// `HQ_FEC_Mem_update_fx` / `HQ_FEC_processing_fx`, then `time_domain_FEC_HQ_fx` or `window_ola_fx`,
/// over eight frames of good and lost data with the whole state compared after every call.
#[test]
fn nb_frame_loss_sequences_match_the_reference() {
    use crate::hq_state::{decoder_with, keep_unloadable, overlay, reload};
    use siphon_rtp_codec::evs::com::window_ola::window_ola;

    let Some(cases) = crate::common::corpus_sized("fec_hq_core", "nb_sequence", 80) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let initial = overlay(case, "\u{0}never");
        let mut st = decoder_with(case, &initial);
        for frame in 0..8 {
            let context = format!("case {index} frame {frame}");
            let before = overlay(case, &format!("f{frame}a_pre."));
            reload(&mut st, &before);
            let mut expected = overlay(case, &format!("f{frame}a."));
            keep_unloadable(&mut st, &before, &mut expected);
            nb_first_stage(case, &mut st, frame);
            crate::hq_state::check_state(&mut st, &expected, &format!("{context} stage a"));

            let before = overlay(case, &format!("f{frame}b_pre."));
            reload(&mut st, &before);
            let mut expected = overlay(case, &format!("f{frame}b."));
            keep_unloadable(&mut st, &before, &mut expected);
            let wtda = case.i32s(&format!("f{frame}_wtda"));
            let mut synth = vec![-7_i16; 960];
            let mut q_synth = case.i16(&format!("f{frame}_q_synth_in"));
            if case.i16(&format!("f{frame}_time_domain")) != 0 {
                time_domain_fec_hq(
                    &mut st,
                    &wtda,
                    &mut synth,
                    case.i16(&format!("f{frame}_mean_en_high_for_time_domain")),
                    160,
                    &mut q_synth,
                );
            } else {
                window_ola(
                    &wtda,
                    &mut synth,
                    &mut q_synth,
                    &mut st.old_out,
                    &mut st.q_old_wtda,
                    160,
                    st.tcx_cfg.tcx_last_overlap_mode,
                    st.tcx_cfg.tcx_curr_overlap_mode,
                    st.prev_bfi,
                    st.old_hq_voicing,
                    Some(&mut st.oldgapsynth),
                );
                st.phase_mat_next = 0;
            }
            check(
                case,
                &format!("{context} synth"),
                &synth[..160].to_vec(),
                &case.i16s(&format!("f{frame}_synth")),
            );
            check(
                case,
                &format!("{context} q_synth"),
                &q_synth,
                &case.i16(&format!("f{frame}_q_synth")),
            );
            crate::hq_state::check_state(&mut st, &expected, &format!("{context} stage b"));
        }
    }
}

/// `HQ_FEC_processing_fx` and `time_domain_FEC_HQ_fx` exactly where the reference decoder calls
/// them on the TS 26.444 conformance bitstreams with frame loss (NB, HQ rates): `fn_fec_hq_core
/// stream` runs the whole reference decoder and prints, for each call, the whole state before it,
/// the arguments and, after the arrow, the outputs and the state fields the call changed.
#[test]
fn hq_frame_loss_concealment_matches_the_reference_on_conformance_bitstreams() {
    use crate::hq_state::{decoder_with, each_stream_call, keep_unloadable, overlay, state_after};
    let mut checked = 0;
    for (name, every) in [
        ("nb/stv8c_7200_8kHz.b10.COD", 4),
        ("nb/stv8c_8000_8kHz.b10.COD", 4),
        ("nb/stv8c_13200_8kHz.f06.COD", 3),
        ("nb/stv8c_13200_8kHz.b10.COD", 3),
        ("nb/stv8c_16400_8kHz.b10.COD", 1),
        ("nb/stv8c_16400_8kHz.f06.COD", 1),
    ] {
        let calls = each_stream_call("fec_hq_core", name, 8000, every, |index, case| {
            let before = overlay(case, "\u{0}never");
            let mut expected = state_after(case);
            let mut st = decoder_with(case, &before);
            keep_unloadable(&mut st, &before, &mut expected);
            let context = format!("{name} line {index}");
            if case.inputs.contains_key("t_audio_in") {
                let mut t_audio = case.i32s("t_audio_in");
                t_audio.resize(960, 0);
                hq_fec_processing(
                    &mut st,
                    &mut t_audio,
                    case.i16("is_transient"),
                    case.i16("num_sb"),
                    case.i16("nb_sfm"),
                    &case.i16s("num_bands_p"),
                    case.i16("call_output_frame"),
                    &case.i16s("sfm_start"),
                    &case.i16s("sfm_end"),
                );
                check(
                    case,
                    &format!("{context} t_audio"),
                    &t_audio[..160].to_vec(),
                    &case.out_i32s("t_audio"),
                );
            } else {
                let mut out = case.i16s("out_in");
                out.resize(960, 0);
                let mut q_synth = case.i16("q_synth_in");
                time_domain_fec_hq(
                    &mut st,
                    &case.i32s("wtda_in"),
                    &mut out,
                    case.i16("mean_en_high"),
                    case.i16("call_output_frame"),
                    &mut q_synth,
                );
                check(
                    case,
                    &format!("{context} out"),
                    &out[..160].to_vec(),
                    &case.out_i16s("out"),
                );
                check(
                    case,
                    &format!("{context} q_synth"),
                    &q_synth,
                    &case.out_i16("q_synth"),
                );
            }
            crate::hq_state::check_state(&mut st, &expected, &context);
        });
        checked += calls.unwrap_or(0);
    }
    eprintln!("hq frame-loss concealment checked on {checked} conformance calls");
}
