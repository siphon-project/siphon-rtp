//! The MODE2 ACELP parameter decoders against `fn_m2lpc_acelp`: `limit_T0_voiced`,
//! `Mode2_pit_decode` (with `Mode2_abs_pit_dec` and `Mode2_delta_pit_dec`), `calc_gain_inov`,
//! `decode_acelp_gains` and `d_gain_pred` (with the static gain decoders of `d_gain2p.c`),
//! `gaus_L2_dec`, `E_UTIL_voice_factor` and `E_UTIL_enhancer` (with `phase_dispersion`).

use siphon_rtp_codec::evs::com::core_com_config::init_pitch_lag_parameters;
use siphon_rtp_codec::evs::com::enhancer::e_util_enhancer;
use siphon_rtp_codec::evs::com::est_tilt::e_util_voice_factor;
use siphon_rtp_codec::evs::com::gain_inov::calc_gain_inov;
use siphon_rtp_codec::evs::com::limit_t0::limit_t0_voiced;
use siphon_rtp_codec::evs::dec::d_gain2p::{d_gain_pred, decode_acelp_gains};
use siphon_rtp_codec::evs::dec::gaus_dec::gaus_l2_dec;
use siphon_rtp_codec::evs::dec::pit_dec::mode2_pit_decode;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("m2lpc_acelp", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

#[test]
fn limit_t0_voiced_matches_the_reference() {
    each("limit_t0_voiced", |case| {
        let (t0_min, t0_min_frac, t0_max, t0_max_frac) = limit_t0_voiced(
            case.i16("nbits"),
            case.i16("res"),
            case.i16("t0"),
            case.i16("t0_frac"),
            case.i16("t0_res"),
            case.i16("pit_min"),
            case.i16("pit_max"),
        );
        check(case, "t0_min", &t0_min, &case.out_i16("t0_min"));
        check(
            case,
            "t0_min_frac",
            &t0_min_frac,
            &case.out_i16("t0_min_frac"),
        );
        check(case, "t0_max", &t0_max, &case.out_i16("t0_max"));
        check(
            case,
            "t0_max_frac",
            &t0_max_frac,
            &case.out_i16("t0_max_frac"),
        );
    });
}

#[test]
fn mode2_pit_decode_matches_the_reference() {
    each("pitch_frame", |case| {
        let nsub = case.i16("nsub") as usize;
        let indices = case.i16s("indices");
        let parameters = init_pitch_lag_parameters(case.i32("sr_core"));
        let mut prm: &[i16] = &indices;
        let (mut t0, mut t0_frac, mut t0_res) = (0i16, 0i16, 1i16);
        let (mut t0_min, mut t0_min_frac, mut t0_max, mut t0_max_frac) = (0i16, 0i16, 0i16, 0i16);
        let mut seen: [Vec<i16>; 9] = Default::default();
        for i in 0..nsub {
            let pitch = mode2_pit_decode(
                case.i16("mode"),
                (i * 64) as i16,
                64,
                &mut prm,
                &mut t0,
                &mut t0_frac,
                &mut t0_res,
                &mut t0_min,
                &mut t0_min_frac,
                &mut t0_max,
                &mut t0_max_frac,
                parameters.pit_min,
                parameters.pit_fr1,
                parameters.pit_fr1b,
                parameters.pit_fr2,
                parameters.pit_max,
                parameters.pit_res_max,
            );
            seen[0].push((pitch >> 16) as i16);
            seen[1].push(pitch as i16);
            seen[2].push(t0);
            seen[3].push(t0_frac);
            seen[4].push(t0_res);
            seen[5].push(t0_min);
            seen[6].push(t0_min_frac);
            seen[7].push(t0_max);
            seen[8].push(t0_max_frac);
        }
        let names = [
            "pitch_hi",
            "pitch_lo",
            "t0",
            "frac",
            "res",
            "t0_min",
            "t0_min_frac",
            "t0_max",
            "t0_max_frac",
        ];
        for (name, values) in names.iter().zip(&seen) {
            check(case, name, values, &case.out_i16s(name));
        }
        check(
            case,
            "consumed",
            &((indices.len() - prm.len()) as i16),
            &case.out_i16("consumed"),
        );
    });
}

#[test]
fn decode_acelp_gains_matches_the_reference() {
    each("gains", |case| {
        let code = case.i16s("code");
        let code2 = case.i16s("code2");
        let one = [case.i16("index"), 1234];
        let mut prm: &[i16] = &one;
        let mut gain_pit = case.i16("gain_pit");
        let mut gain_code = case.i32("gain_code");
        let mut past_gpit = case.i16("past_gpit");
        let mut past_gcode = case.i32("past_gcode");
        let mut gain_inov = case.i16("gain_inov");
        let mut gain_code2 = case.i32("gain_code2");
        decode_acelp_gains(
            &code,
            case.i16("gains_mode"),
            case.i16("mean_ener"),
            &mut gain_pit,
            &mut gain_code,
            &mut prm,
            &mut past_gpit,
            &mut past_gcode,
            &mut gain_inov,
            case.i16("lcode"),
            &code2,
            &mut gain_code2,
        );
        check(case, "gain_pit", &gain_pit, &case.out_i16("gain_pit"));
        check(case, "gain_code", &gain_code, &case.out_i32("gain_code"));
        check(case, "past_gpit", &past_gpit, &case.out_i16("past_gpit"));
        check(case, "past_gcode", &past_gcode, &case.out_i32("past_gcode"));
        check(case, "gain_inov", &gain_inov, &case.out_i16("gain_inov"));
        check(case, "gain_code2", &gain_code2, &case.out_i32("gain_code2"));
        check(
            case,
            "consumed",
            &((one.len() - prm.len()) as i16),
            &case.out_i16("consumed"),
        );
    });
}

#[test]
fn d_gain_pred_matches_the_reference() {
    each("gain_pred", |case| {
        let one = [case.i16("index"), 99];
        let mut prm: &[i16] = &one;
        let mut es_pred = case.i16("es_pred");
        d_gain_pred(case.i16("nrg_mode"), &mut es_pred, &mut prm);
        check(case, "es_pred", &es_pred, &case.out_i16("es_pred"));
        check(
            case,
            "consumed",
            &((one.len() - prm.len()) as i16),
            &case.out_i16("consumed"),
        );
    });
}

#[test]
fn calc_gain_inov_matches_the_reference() {
    each("gain_inov", |case| {
        let (mut dotp, mut dotp_e) = (-1, -1);
        let code = case.i16s("code");
        let lcode = case.i16("lcode");
        let r = if case.i16("with_out") != 0 {
            calc_gain_inov(&code, lcode, Some(&mut dotp), Some(&mut dotp_e))
        } else {
            calc_gain_inov(&code, lcode, None, None)
        };
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "dotp", &dotp, &case.out_i32("dotp"));
        check(case, "dotp_e", &dotp_e, &case.out_i16("dotp_e"));
    });
}

#[test]
fn gaus_l2_dec_matches_the_reference() {
    each("gaus_l2", |case| {
        let mut code = vec![5555i16; 64];
        let mut seed = case.i16("seed");
        gaus_l2_dec(
            &mut code,
            case.i16("tilt"),
            &case.i16s("a"),
            case.i16("formant_enh"),
            &mut seed,
        );
        check(case, "code", &code, &case.out_i16s("code"));
        check(case, "seed", &seed, &case.out_i16("seed"));
    });
}

#[test]
fn e_util_voice_factor_matches_the_reference() {
    each("voice_factor", |case| {
        let (mut voice_fac, mut tilt_code) = (-99, -99);
        e_util_voice_factor(
            &case.i16s("exc"),
            case.i16("i_subfr"),
            &case.i16s("code"),
            case.i16("gain_pit"),
            case.i32("gain_code"),
            &mut voice_fac,
            &mut tilt_code,
            64,
            case.i16("flag_tilt"),
            case.i16("q_new"),
            case.i16("shift"),
        );
        check(case, "voice_fac", &voice_fac, &case.out_i16("voice_fac"));
        check(case, "tilt_code", &tilt_code, &case.out_i16("tilt_code"));
    });
}

#[test]
fn e_util_enhancer_matches_the_reference() {
    each("enhancer", |case| {
        let mut gc_threshold = case.i32("gc_threshold");
        let mut code = case.i16s("code");
        let mut exc2 = case.i16s("exc2");
        let mut prev_gain_code = case.i32("prev_gain_code");
        let mut prev_gain_pit = case.i16s("prev_gain_pit");
        let mut prev_state = case.i16("prev_state");
        let r = e_util_enhancer(
            case.i16("voice_fac"),
            case.i16("stab_fac"),
            case.i32("gain_code"),
            case.i16("gain_inov"),
            &mut gc_threshold,
            &mut code,
            &mut exc2,
            case.i16("gain_pit"),
            &mut prev_gain_code,
            &mut prev_gain_pit,
            &mut prev_state,
            case.i16("coder_type"),
            case.i16("cdk_index"),
            64,
            case.i16("l_frame"),
            case.i16("q_new"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(
            case,
            "gc_threshold",
            &gc_threshold,
            &case.out_i32("gc_threshold"),
        );
        check(case, "code", &code, &case.out_i16s("code"));
        check(case, "exc2", &exc2, &case.out_i16s("exc2"));
        check(
            case,
            "prev_gain_code",
            &prev_gain_code,
            &case.out_i32("prev_gain_code"),
        );
        check(
            case,
            "prev_gain_pit",
            &prev_gain_pit,
            &case.out_i16s("prev_gain_pit"),
        );
        check(case, "prev_state", &prev_state, &case.out_i16("prev_state"));
    });
}
