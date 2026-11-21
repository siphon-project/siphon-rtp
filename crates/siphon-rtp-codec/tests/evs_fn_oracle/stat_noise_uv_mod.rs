//! `lib_com/stat_noise_uv_mod_fx.c` against `fn_stat_noise_uv_mod`: `stat_noise_uv_mod_fx` over
//! runs of consecutive frames with its state carried, and `calc_tilt_fx` / `L_Sqrt_Q0` alone.

use siphon_rtp_codec::evs::com::stat_noise_uv_mod::{calc_tilt, l_sqrt_q0, stat_noise_uv_mod};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn stat_noise_uv_mod_matches_the_reference() {
    let Some(cases) = corpus("stat_noise_uv_mod", "stat_noise_uv_mod") else {
        return;
    };
    for case in &cases {
        let mut ge_sm = case.i32("ge_sm");
        let mut uv_count = case.i16("uv_count");
        let mut act_count = case.i16("act_count");
        let mut lspold_s = case.i16s("lspold_s");
        let mut seed = case.i16("seed");
        let mut min_alpha = case.i16("min_alpha");
        let mut exc_pe = case.i16("exc_pe");
        let mut q_stat_noise = case.i16("q_stat_noise");
        let mut q_stat_noise_ge = 6;
        for f in 0..case.i32("frames") {
            let params = case.i16s(&format!("f{f}"));
            let mut aq = vec![-5i16; 4 * 17];
            let mut exc2 = case.i16s(&format!("exc{f}"));
            stat_noise_uv_mod(
                params[0],
                params[1],
                &case.i16s(&format!("old{f}")),
                &case.i16s(&format!("new{f}")),
                &case.i16s(&format!("mid{f}")),
                &mut aq,
                &mut exc2,
                params[4],
                params[2],
                &mut ge_sm,
                &mut uv_count,
                &mut act_count,
                &mut lspold_s,
                &mut seed,
                &mut min_alpha,
                &mut exc_pe,
                i32::from(params[5]) * 100,
                params[3],
                &mut q_stat_noise,
                &mut q_stat_noise_ge,
            );
            check(
                case,
                &format!("aq{f}"),
                &aq,
                &case.out_i16s(&format!("aq{f}")),
            );
            check(
                case,
                &format!("exc{f}"),
                &exc2,
                &case.out_i16s(&format!("exc{f}")),
            );
            check(
                case,
                &format!("lspold_s{f}"),
                &lspold_s,
                &case.out_i16s(&format!("lspold_s{f}")),
            );
            check(
                case,
                &format!("ge_sm{f}"),
                &ge_sm,
                &case.out_i32(&format!("ge_sm{f}")),
            );
            let state = vec![
                uv_count,
                act_count,
                seed,
                min_alpha,
                exc_pe,
                q_stat_noise,
                q_stat_noise_ge,
            ];
            check(
                case,
                &format!("state{f}"),
                &state,
                &case.out_i16s(&format!("state{f}")),
            );
        }
    }
}

#[test]
fn calc_tilt_matches_the_reference() {
    let Some(cases) = corpus("stat_noise_uv_mod", "calc_tilt") else {
        return;
    };
    for case in &cases {
        let tilt = calc_tilt(&case.i16s("x"), case.i16("q_shift"), 64);
        check(case, "tilt", &tilt, &case.out_i16("tilt"));
    }
}

#[test]
fn l_sqrt_q0_matches_the_reference() {
    let Some(cases) = corpus("stat_noise_uv_mod", "l_sqrt_q0") else {
        return;
    };
    for case in &cases {
        check(case, "r", &l_sqrt_q0(case.i32("x")), &case.out_i32("r"));
    }
}
