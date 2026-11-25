//! `lib_dec/er_util.c` (`minimumStatistics`, `getLevelSynDeemph`, `genPlcFiltBWAdap`,
//! `highPassFiltering`) and `lib_dec/er_scale_syn.c` (`Damping_fact`) against
//! `fn_m2conceal_er_util`.

use siphon_rtp_codec::evs::dec::er_scale_syn::damping_fact;
use siphon_rtp_codec::evs::dec::er_util::{
    gen_plc_filt_bw_adap, get_level_syn_deemph, high_pass_filtering, minimum_statistics,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn damping_fact_matches_the_reference() {
    let Some(cases) = corpus("m2conceal_er_util", "damping_fact") else {
        return;
    };
    for case in &cases {
        let mut lp_gainp = case.i32("lp_gainp");
        let alpha = damping_fact(
            case.i16("coder_type"),
            case.i16("nb_lost"),
            case.i16("last_good"),
            case.i16("stab_fac"),
            &mut lp_gainp,
            case.i16("core"),
        );
        check(case, "alpha", &alpha, &case.out_i16("alpha"));
        check(case, "lp_gainp", &lp_gainp, &case.out_i32("lp_gainp"));
    }
}

#[test]
fn gen_plc_filt_bw_adap_matches_the_reference() {
    let Some(cases) = corpus("m2conceal_er_util", "gen_plc_filt_bw_adap") else {
        return;
    };
    for case in &cases {
        let mut taps = [-1i16; 3];
        gen_plc_filt_bw_adap(
            case.i32("sr_core"),
            &mut taps,
            case.i16("type"),
            case.i16("alpha"),
        );
        check(case, "taps", &taps.to_vec(), &case.out_i16s("taps"));
    }
}

#[test]
fn high_pass_filtering_matches_the_reference() {
    let Some(cases) = corpus("m2conceal_er_util", "high_pass_filtering") else {
        return;
    };
    for case in &cases {
        let mut exc2 = case.i16s("exc2");
        high_pass_filtering(
            case.i16("last_good"),
            case.i16("length"),
            &mut exc2,
            &case.i16s("hp_filt"),
            case.i16("l_fir"),
        );
        check(case, "exc2", &exc2, &case.out_i16s("exc2"));
    }
}

#[test]
fn get_level_syn_deemph_matches_the_reference() {
    let Some(cases) = corpus("m2conceal_er_util", "get_level_syn_deemph") else {
        return;
    };
    for case in &cases {
        let mut h1_init = case.i16s("h1_init");
        let mut exp = -1i16;
        let level = get_level_syn_deemph(
            &mut h1_init,
            &case.i16s("a"),
            16,
            case.i16("length"),
            case.i16("preemph_fac"),
            case.i16("loops"),
            &mut exp,
        );
        check(case, "level", &level, &case.out_i16("level"));
        check(case, "exp", &exp, &case.out_i16("exp"));
        check(case, "h1_init", &h1_init, &case.out_i16s("h1_init"));
    }
}

#[test]
fn minimum_statistics_matches_the_reference() {
    let Some(cases) = corpus("m2conceal_er_util", "minimum_statistics") else {
        return;
    };
    for case in &cases {
        let mut memory = case.i16s("memory");
        let mut memory_e = case.i16s("memory_e");
        let mut noise_index = case.i16("noise_index");
        let mut curr_index = case.i16("curr_index");
        let mut noise_estimate = case.i16("noise_estimate");
        let mut last_level = case.i16("last_level");
        let mut last_level_e = case.i16("last_level_e");
        let mut new_e = 0i16;
        minimum_statistics(
            &mut memory,
            &mut noise_index,
            &mut curr_index,
            &mut noise_estimate,
            &mut last_level,
            case.i16("current_level"),
            &mut memory_e,
            case.i16("noise_estimate_e"),
            &mut new_e,
            &mut last_level_e,
            case.i16("current_level_e"),
        );
        check(case, "memory", &memory, &case.out_i16s("memory"));
        check(case, "memory_e", &memory_e, &case.out_i16s("memory_e"));
        check(
            case,
            "noise_index",
            &noise_index,
            &case.out_i16("noise_index"),
        );
        check(case, "curr_index", &curr_index, &case.out_i16("curr_index"));
        check(
            case,
            "noise_estimate",
            &noise_estimate,
            &case.out_i16("noise_estimate"),
        );
        check(case, "last_level", &last_level, &case.out_i16("last_level"));
        check(case, "new_e", &new_e, &case.out_i16("new_e"));
        check(
            case,
            "last_level_e",
            &last_level_e,
            &case.out_i16("last_level_e"),
        );
    }
}
