//! `lib_dec/tonalMDCTconcealment.c` (everything but `TonalMDCTConceal_Init`, which
//! `tonal_mdct_concealment.rs` covers) against `fn_m2tonal_conceal`: one state driven through the
//! calls of a decoder (init, good frames, lost frames with and without the tonal concealment) on
//! harmonic and noise signals, the whole state compared after every call.

use siphon_rtp_codec::evs::com::tcx_utils::init_tcx_config;
use siphon_rtp_codec::evs::dec::state::{TcxConfig, Tonalmdctconceal};
use siphon_rtp_codec::evs::dec::tonal_mdct_concealment::{
    tonal_mdct_conceal_apply, tonal_mdct_conceal_detect, tonal_mdct_conceal_init,
    tonal_mdct_conceal_insert_noise, tonal_mdct_conceal_save_freq_signal,
    tonal_mdct_conceal_save_time_signal, tonal_mdct_conceal_update_state,
};

use crate::common::{corpus_sized, mismatch, Case};

const OP_INIT: i16 = 0;
const OP_SAVE_FREQ: i16 = 1;
const OP_SAVE_TIME: i16 = 2;
const OP_UPDATE: i16 = 3;
const OP_DETECT: i16 = 4;
const OP_NOISE: i16 = 5;
const OP_APPLY: i16 = 6;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn buffer(slot: Option<usize>) -> i64 {
    slot.map_or(-1, |value| value as i64)
}

fn widen<T: Copy + Into<i64>>(values: &[T]) -> Vec<i64> {
    values.iter().map(|&value| value.into()).collect()
}

/// Every piece of state the reference prints after a call, under the reference's names.
fn state_of(c: &Tonalmdctconceal, core: usize) -> Vec<(String, Vec<i64>)> {
    let mut fields: Vec<(String, Vec<i64>)> = vec![
        ("s_n_samples".into(), vec![c.n_samples.into()]),
        ("s_n_samples_core".into(), vec![c.n_samples_core.into()]),
        ("s_n_non_zero".into(), vec![c.n_non_zero_samples.into()]),
        ("s_n_scale_factors".into(), vec![c.n_scale_factors.into()]),
        ("s_last_pitch_lag".into(), vec![c.last_pitch_lag.into()]),
        ("s_n_frames_lost".into(), vec![c.n_frames_lost.into()]),
    ];
    for (tag, block) in [
        ("last_", &c.last_block_data),
        ("second_", &c.second_last_block_data),
    ] {
        let mut add = |name: &str, value: i64| fields.push((format!("{tag}{name}"), vec![value]));
        add("n_samples", block.n_samples.into());
        add("n_samples_core", block.n_samples_core.into());
        add("spectral", buffer(block.spectral_data));
        add("spectral_exp", block.spectral_data_exp.into());
        add("sf", buffer(block.scale_factors));
        add("sf_exp_ptr", buffer(block.scale_factors_exp));
        add("sf_max_e", block.scale_factors_max_e.into());
        add("gain_tcx_exp", block.gain_tcx_exp.into());
        add("valid", block.block_is_valid.into());
        add("concealed", block.block_is_concealed.into());
        add("tonal", block.tonal_concealment_active.into());
    }
    fields.push((
        "s_second_power".into(),
        vec![buffer(c.second_last_power_spectrum)],
    ));
    fields.push((
        "s_second_power_exp".into(),
        vec![c.second_last_power_spectrum_exp.into()],
    ));
    fields.push(("s_last_pcm_out".into(), vec![buffer(c.last_pcm_out)]));
    fields.push((
        "s_second_last_pcm_out".into(),
        vec![buffer(c.second_last_pcm_out)],
    ));
    fields.push(("s_spectral0".into(), widen(&c.spectral_data_buffers[0])));
    fields.push(("s_spectral1".into(), widen(&c.spectral_data_buffers[1])));
    fields.push(("s_sf0".into(), widen(&c.scale_factors_buffers[0])));
    fields.push(("s_sf1".into(), widen(&c.scale_factors_buffers[1])));
    fields.push(("s_sf_exp0".into(), widen(&c.scale_factors_buffers_exp[0])));
    fields.push(("s_sf_exp1".into(), widen(&c.scale_factors_buffers_exp[1])));
    fields.push(("s_time".into(), widen(&c.time_data_buffer)));
    let _ = core;
    fields
}

#[derive(Default)]
struct Coverage {
    detects: usize,
    detected: usize,
    tonal_noise: usize,
    plain_noise: usize,
    applies: usize,
    refined: usize,
}

#[test]
fn tonal_mdct_concealment_matches_the_reference() {
    let Some(cases) = corpus_sized("m2tonal_conceal", "run", 4000) else {
        return;
    };
    let mut conceal = Box::new(Tonalmdctconceal::zeroed());
    let mut tcx_cfg = TcxConfig::zeroed();
    let mut coverage = Coverage::default();
    let mut previous_concealed_tonal = false;
    for case in &cases {
        let n_samples = usize::try_from(conceal.n_samples).unwrap();
        match case.i16("op") {
            OP_INIT => {
                tcx_cfg = TcxConfig::zeroed();
                init_tcx_config(
                    &mut tcx_cfg,
                    case.i16("l_frame"),
                    case.i16("fscale"),
                    case.i16("l_frame_tcx"),
                    case.i16("fscale_fb"),
                );
                tcx_cfg.tcx_offset_fb = tcx_cfg.tcx_mdct_window_delay_fb >> 1;
                // core_dec_init's pre-initialisation.
                conceal.n_scale_factors = 0;
                conceal.n_samples = 0;
                conceal.last_pcm_out = None;
                conceal.last_block_data.tonal_concealment_active = 0;
                conceal.last_block_data.n_samples = 0;
                tonal_mdct_conceal_init(
                    &mut conceal,
                    case.i16("l_frame_tcx"),
                    case.i16("l_frame"),
                    64,
                )
                .unwrap();
            }
            OP_SAVE_FREQ => {
                let (new_samples, new_samples_core) = (conceal.n_samples, conceal.n_samples_core);
                tonal_mdct_conceal_save_freq_signal(
                    &mut conceal,
                    &case.i32s("x"),
                    case.i16("x_e"),
                    new_samples,
                    new_samples_core,
                    &case.i16s("sf"),
                    &case.i16s("sf_exp"),
                    case.i16("gain_tcx_e"),
                );
            }
            OP_SAVE_TIME => {
                tonal_mdct_conceal_save_time_signal(
                    &mut conceal,
                    &case.i16s("synth"),
                    case.i16("n_new"),
                );
            }
            OP_UPDATE => {
                tonal_mdct_conceal_update_state(
                    &mut conceal,
                    case.i16("n_new"),
                    case.i32("pitch"),
                    case.i16("bfi"),
                    case.i16("tonal") as i8,
                );
                previous_concealed_tonal = case.i16("tonal") != 0;
            }
            OP_DETECT => {
                let mut count = -1i16;
                tonal_mdct_conceal_detect(&mut conceal, &tcx_cfg, case.i32("pitch"), &mut count);
                check(case, "count", &count, &case.out_i16("count"));
                coverage.detects += 1;
                coverage.detected += usize::from(count > 0);
                coverage.refined += usize::from(
                    count > 0
                        && conceal.last_block_data.block_is_concealed == 0
                        && conceal.second_last_block_data.tonal_concealment_active != 0,
                );
            }
            OP_NOISE => {
                let mut x = vec![0i32; 2 * 960];
                x[..n_samples].copy_from_slice(&case.i32s("x_in"));
                let mut x_e = case.i16("x_e_in");
                let mut seed = case.i16("seed_in");
                let active = case.i16("active") as i8;
                tonal_mdct_conceal_insert_noise(
                    &mut conceal,
                    &mut x,
                    &mut x_e,
                    active,
                    &mut seed,
                    case.i16("tilt"),
                    case.i16("crossfade"),
                    case.i16("cross_over"),
                );
                check(case, "x", &x[..n_samples].to_vec(), &case.out_i32s("x"));
                check(case, "x_e", &x_e, &case.out_i16("x_e"));
                check(case, "seed", &seed, &case.out_i16("seed"));
                coverage.tonal_noise += usize::from(active != 0);
                coverage.plain_noise += usize::from(active == 0);
                let _ = previous_concealed_tonal;
            }
            OP_APPLY => {
                let mut x = vec![0i32; 2 * 960];
                x[..n_samples].copy_from_slice(&case.i32s("x_in"));
                tonal_mdct_conceal_apply(&mut conceal, &mut x, case.i16("x_e_in"));
                check(case, "x", &x[..n_samples].to_vec(), &case.out_i32s("x"));
                coverage.applies += 1;
            }
            op => panic!("unknown op {op}"),
        }
        for (name, value) in state_of(&conceal, 0) {
            check(case, &name, &value, &case.outputs[&name]);
        }
    }
    eprintln!(
        "m2tonal_conceal: {} detects ({} found, {} refined), {} tonal and {} plain noise fills, {} applies",
        coverage.detects, coverage.detected, coverage.refined, coverage.tonal_noise, coverage.plain_noise, coverage.applies
    );
    assert!(
        coverage.detects > 40,
        "too few Detect calls: {}",
        coverage.detects
    );
    assert!(
        coverage.detected > 20,
        "Detect found nothing often enough: {}",
        coverage.detected
    );
    assert!(
        coverage.tonal_noise > 20,
        "too few tonal InsertNoise calls: {}",
        coverage.tonal_noise
    );
    assert!(
        coverage.plain_noise > 20,
        "too few plain InsertNoise calls: {}",
        coverage.plain_noise
    );
    assert!(
        coverage.applies > 20,
        "too few Apply calls: {}",
        coverage.applies
    );
    assert!(
        coverage.refined > 0,
        "RefineTonalComponents never ran: {}",
        coverage.refined
    );
}
