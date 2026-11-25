//! `lib_com/tec_com.c` (decoder side) against `fn_m2prm_tec`.

use siphon_rtp_codec::evs::com::cldfb::CLDFB_ROW;
use siphon_rtp_codec::evs::com::tec_com::{
    calc_gain_linear_tbe, calc_gain_temp_tbe, calc_lo_buffer_dec, calc_lo_temp_env_ns_tbe,
    calc_lo_temp_env_tbe, calc_subfr_nrg, calc_sum, proc_tec, proc_tec_tfa_tbe, proc_tfa,
    set_subfr_config,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn rows(case: &Case, name: &str) -> Vec<[i32; CLDFB_ROW]> {
    case.i32s(name)
        .chunks(CLDFB_ROW)
        .map(|chunk| {
            let mut row = [0i32; CLDFB_ROW];
            row.copy_from_slice(chunk);
            row
        })
        .collect()
}

#[test]
fn calc_lo_buffer_dec_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "calc_lo_buffer_dec") else {
        return;
    };
    for case in &cases {
        let mut lo_buffer = case.i16s("lo_buffer");
        calc_lo_buffer_dec(
            &rows(case, "real"),
            &rows(case, "imag"),
            &mut lo_buffer,
            6,
            case.i16("start"),
            case.i16("columns"),
            case.i16("offset"),
            case.i16("scale"),
        );
        check(case, "lo_buffer", &lo_buffer, &case.out_i16s("lo_buffer"));
    }
}

#[test]
fn calc_lo_temp_env_tbe_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "calc_lo_temp_env_tbe") else {
        return;
    };
    for case in &cases {
        let columns = case.i16("columns");
        let mut env = vec![0i16; 16];
        calc_lo_temp_env_tbe(
            &case.i16s("lo_buffer"),
            6,
            columns,
            &mut env,
            case.i16("adj"),
        );
        env.truncate(columns as usize);
        check(case, "env", &env, &case.out_i16s("env"));
    }
}

#[test]
fn calc_lo_temp_env_ns_tbe_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "calc_lo_temp_env_ns_tbe") else {
        return;
    };
    for case in &cases {
        let columns = case.i16("columns");
        let mut env = vec![0i16; 16];
        calc_lo_temp_env_ns_tbe(&case.i16s("lo_buffer"), 6, columns, &mut env);
        env.truncate(columns as usize);
        check(case, "env", &env, &case.out_i16s("env"));
    }
}

#[test]
fn calc_gain_linear_tbe_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "calc_gain_linear_tbe") else {
        return;
    };
    for case in &cases {
        let (mut gain_m, mut gain_e) = (vec![0x5a5a_i16; 16], vec![0x5a5a_i16; 16]);
        calc_gain_linear_tbe(
            &case.i16s("env"),
            case.i16("start"),
            case.i16("stop"),
            &mut gain_m,
            &mut gain_e,
        );
        check(case, "gain_m", &gain_m, &case.out_i16s("gain_m"));
        check(case, "gain_e", &gain_e, &case.out_i16s("gain_e"));
    }
}

#[test]
fn calc_gain_temp_tbe_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "calc_gain_temp_tbe") else {
        return;
    };
    for case in &cases {
        let mut lo_buffer = case.i16s("lo_buffer");
        let (mut gain_m, mut gain_e) = (vec![0x5a5a_i16; 16], vec![0x5a5a_i16; 16]);
        calc_gain_temp_tbe(
            &rows(case, "real"),
            &rows(case, "imag"),
            case.i16("cldfb_exp"),
            &mut lo_buffer,
            0,
            case.i16("columns"),
            case.i16("low_subband"),
            &mut gain_m,
            &mut gain_e,
            case.i16("code"),
        );
        check(case, "lo_buffer", &lo_buffer, &case.out_i16s("lo_buffer"));
        check(case, "gain_m", &gain_m, &case.out_i16s("gain_m"));
        check(case, "gain_e", &gain_e, &case.out_i16s("gain_e"));
    }
}

#[test]
fn set_subfr_config_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "set_subfr_config") else {
        return;
    };
    for case in &cases {
        let (k_offset, n_subfr) = set_subfr_config(case.i16("offset"), case.i16("l_subfr"));
        check(case, "k_offset", &k_offset, &case.out_i16("k_offset"));
        check(case, "n_subfr", &n_subfr, &case.out_i16("n_subfr"));
    }
}

#[test]
fn calc_sum_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "calc_sum") else {
        return;
    };
    for case in &cases {
        let mut sum_m = 0i16;
        let sum_e = calc_sum(
            &case.i16s("m"),
            &case.i16s("e"),
            case.i16("len"),
            &mut sum_m,
        );
        check(case, "sum_m", &sum_m, &case.out_i16("sum_m"));
        check(case, "sum_e", &sum_e, &case.out_i16("sum_e"));
    }
}

#[test]
fn calc_subfr_nrg_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "calc_subfr_nrg") else {
        return;
    };
    for case in &cases {
        let l_subfr = case.i16("l_subfr");
        let offset = case.i16("offset");
        let (mut enr_m, mut enr_e) = (vec![0x5a5a_i16; 16], vec![0x5a5a_i16; 16]);
        let mut sum_m = 0i16;
        let sum_e = calc_subfr_nrg(
            &case.i16s("synth"),
            case.i16("exp_syn"),
            offset,
            &mut enr_m,
            &mut enr_e,
            offset * l_subfr,
            &mut sum_m,
            l_subfr,
        );
        check(case, "enr_m", &enr_m, &case.out_i16s("enr_m"));
        check(case, "enr_e", &enr_e, &case.out_i16s("enr_e"));
        check(case, "sum_m", &sum_m, &case.out_i16("sum_m"));
        check(case, "sum_e", &sum_e, &case.out_i16("sum_e"));
    }
}

#[test]
fn proc_tec_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "proc_tec") else {
        return;
    };
    for case in &cases {
        let mut synth = case.i16s("synth");
        let (mut gain_m, mut gain_e) = (case.i16s("gain_m"), case.i16s("gain_e"));
        let r = proc_tec(
            &mut synth,
            case.i16("exp_syn"),
            &mut gain_m,
            &mut gain_e,
            case.i16("offset"),
            case.i16("l_subfr"),
            case.i16("code"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "synth", &synth, &case.out_i16s("synth"));
        check(case, "gain_m", &gain_m, &case.out_i16s("gain_m"));
        check(case, "gain_e", &gain_e, &case.out_i16s("gain_e"));
    }
}

#[test]
fn proc_tfa_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "proc_tfa") else {
        return;
    };
    for case in &cases {
        let mut synth = case.i16s("synth");
        let r = proc_tfa(
            &mut synth,
            case.i16("exp_syn"),
            case.i16("offset"),
            case.i16("l_subfr"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "synth", &synth, &case.out_i16s("synth"));
    }
}

#[test]
fn proc_tec_tfa_tbe_matches_the_reference() {
    let Some(cases) = corpus("m2prm_tec", "proc_tec_tfa_tbe") else {
        return;
    };
    for case in &cases {
        let mut synth = case.i16s("synth");
        let (mut gain_m, mut gain_e) = (case.i16s("gain_m"), case.i16s("gain_e"));
        let r = proc_tec_tfa_tbe(
            &mut synth,
            case.i16("exp"),
            &mut gain_m,
            &mut gain_e,
            case.i16("flat"),
            case.i16("last_core"),
            case.i16("l_subfr"),
            case.i16("code"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "synth", &synth, &case.out_i16s("synth"));
        check(case, "gain_m", &gain_m, &case.out_i16s("gain_m"));
        check(case, "gain_e", &gain_e, &case.out_i16s("gain_e"));
    }
}
