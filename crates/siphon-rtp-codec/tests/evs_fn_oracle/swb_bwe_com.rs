//! `lib_com/swb_bwe_com_fx.c` against `fn_swb_bwe_com`.

use siphon_rtp_codec::evs::cnst::{L_FRAME16K, WB_BWE};
use siphon_rtp_codec::evs::com::swb_bwe_com::{
    calc_norm_envelop, calc_normal_length, calc_tilt_bwe, save_old_syn, wb_bwe_decoding,
    wb_bwe_gain_pred,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn wb_bwe_gain_pred_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com", "wb_bwe_gain_pred") else {
        return;
    };
    for case in &cases {
        let mut fenv = [-1_i16; 2];
        let mode = wb_bwe_gain_pred(
            &mut fenv,
            &case.i16s("freq"),
            case.i16("coder_type"),
            case.i16("prev_coder_type"),
            case.i16("prev_fenv"),
            &case.i16s("voice"),
            &case.i16s("pitch"),
            case.i32("last_core_brate"),
            case.i16("last_ener"),
            case.i16("q_syn"),
            case.i16("last_extl"),
            case.i16("tilt"),
        );
        check(case, "mode", &mode, &case.out_i16("mode"));
        check(case, "fenv", &fenv.to_vec(), &case.out_i16s("fenv"));
    }
}

#[test]
fn calc_normal_length_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com", "calc_normal_length") else {
        return;
    };
    for case in &cases {
        let mut norm = -1;
        let mut prev = case.i16("prev");
        calc_normal_length(
            case.i16("core"),
            &case.i16s("sp"),
            case.i16("mode"),
            case.i16("extl"),
            &mut norm,
            &mut prev,
            case.i16("q_syn"),
        );
        check(case, "norm", &norm, &case.out_i16("norm"));
        check(case, "prev", &prev, &case.out_i16("prev"));
    }
}

#[test]
fn calc_tilt_bwe_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com", "calc_tilt_bwe") else {
        return;
    };
    for case in &cases {
        let sp = case.i16s("sp");
        let tilt = calc_tilt_bwe(&sp, case.i16("exp_sp"), sp.len() as i16);
        check(case, "tilt", &tilt, &case.out_i32("tilt"));
    }
}

#[test]
fn calc_norm_envelop_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com", "calc_norm_envelop") else {
        return;
    };
    for case in &cases {
        let signal = case.i16s("signal");
        let mut envelope = vec![-1; signal.len()];
        calc_norm_envelop(
            &signal,
            &mut envelope,
            case.i16("norm"),
            case.i16("flength"),
            case.i16("offset"),
        );
        check(case, "envelope", &envelope, &case.out_i32s("envelope"));
    }
}

#[test]
fn wb_bwe_decoding_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus("swb_bwe_com", "wb_bwe_decoding") else {
        return;
    };
    for case in &cases {
        let mut prev_energy = case.i32("prev_energy");
        let mut prev_fenv = case.i16s("prev_fenv");
        let mut prev_norm = case.i16("prev_norm");
        let mut seed = case.i16("seed");
        let mut prev_flag = case.i16("prev_flag");
        for frame in 0..3 {
            let mut signal = vec![12345; L_FRAME16K as usize];
            let mut fenv = case.i16s(&format!("fenv{frame}"));
            let mut q_hb = -99;
            wb_bwe_decoding(
                &case.i16s(&format!("freq{frame}")),
                &mut fenv,
                &mut signal,
                L_FRAME16K,
                case.i16(&format!("mode{frame}")),
                case.i16(&format!("last_extl{frame}")),
                &mut prev_energy,
                &mut prev_fenv,
                &mut prev_norm,
                WB_BWE,
                case.i16(&format!("coder_type{frame}")),
                case.i32("total_brate"),
                &mut seed,
                &mut prev_flag,
                case.i16(&format!("prev_ct{frame}")),
                case.i16("q_syn"),
                &mut q_hb,
            );
            let out = |name: &str| format!("{name}{frame}");
            check(
                case,
                &out("signal"),
                &signal,
                &case.out_i32s(&out("signal")),
            );
            check(case, &out("fenv"), &fenv, &case.out_i16s(&out("fenv")));
            check(case, &out("q_hb"), &q_hb, &case.out_i16(&out("q_hb")));
            check(
                case,
                &out("prev_energy"),
                &prev_energy,
                &case.out_i32(&out("prev_energy")),
            );
            check(
                case,
                &out("prev_fenv"),
                &prev_fenv,
                &case.out_i16s(&out("prev_fenv")),
            );
            check(
                case,
                &out("prev_norm"),
                &prev_norm,
                &case.out_i16(&out("prev_norm")),
            );
            check(case, &out("seed"), &seed, &case.out_i16(&out("seed")));
            check(
                case,
                &out("prev_flag"),
                &prev_flag,
                &case.out_i16(&out("prev_flag")),
            );
        }
    }
}

#[test]
fn save_old_syn_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com", "save_old_syn") else {
        return;
    };
    for case in &cases {
        let syn = case.i16s("syn");
        let mut old_syn = vec![0; syn.len()];
        let mut mem = case.i16s("mem");
        let mut mem_deemph = case.i16("mem_deemph");
        save_old_syn(
            syn.len() as i16,
            &syn,
            &mut old_syn,
            &mut mem,
            case.i16("fac"),
            &mut mem_deemph,
        );
        check(case, "old_syn", &old_syn, &case.out_i16s("old_syn"));
        check(case, "mem", &mem, &case.out_i16s("mem"));
        check(case, "mem_deemph", &mem_deemph, &case.out_i16("mem_deemph"));
    }
}
