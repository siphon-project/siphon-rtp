//! `lib_com/env_stab_fx.c` against `fn_env_stab`: `env_stability_fx` (including the saturated
//! `Overflow` branch) and `env_stab_smo_fx` with its state.

use siphon_rtp_codec::evs::com::env_stab::{env_stab_smo, env_stability};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn env_stability_matches_the_reference() {
    let Some(cases) = corpus("env_stab", "env_stability") else {
        return;
    };
    let mut results = std::collections::BTreeSet::new();
    for case in &cases {
        let mut mem_norm = case.i16s("mem_norm");
        let mut mem_env_delta = case.i16("mem_env_delta");
        let result = env_stability(
            &case.i16s("ynrm"),
            case.i16("nb_sfm"),
            &mut mem_norm,
            &mut mem_env_delta,
        );
        check(case, "result", &result, &case.out_i16("result"));
        check(case, "mem_norm", &mem_norm, &case.out_i16s("mem_norm"));
        check(
            case,
            "mem_env_delta",
            &mem_env_delta,
            &case.out_i16("mem_env_delta"),
        );
        results.insert(result);
    }
    // the stability table has 10 levels, mirrored around one half
    assert!(
        results.len() > 12,
        "only {} distinct results",
        results.len()
    );
}

#[test]
fn env_stab_smo_matches_the_reference() {
    let Some(cases) = corpus("env_stab", "env_stab_smo") else {
        return;
    };
    for case in &cases {
        let mut p = case.i16s("p");
        let mut ho_cnt = case.i16("ho_cnt");
        let state = env_stab_smo(case.i16("env_stab"), &mut p, &mut ho_cnt);
        check(case, "state", &state, &case.out_i16("state"));
        check(case, "p", &p, &case.out_i16s("p"));
        check(case, "ho_cnt", &ho_cnt, &case.out_i16("ho_cnt"));
    }
}
