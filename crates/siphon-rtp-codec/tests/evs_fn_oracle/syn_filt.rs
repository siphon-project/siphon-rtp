//! `lib_com/syn_filt_fx.c` against `fn_syn_filt`. The static `syn_kern_2/4/6/8/10/24` are proven
//! through `E_UTIL_synthesis` at the orders that select them (6, 10, 16, 24).

use siphon_rtp_codec::evs::com::syn_filt::{
    e_util_synthesis, e_util_synthesis_in_place, syn_filt_s, syn_filt_s_lc, syn_filt_s_lc_in_place,
    syn_kern_16, synth_mem_updt2,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn synthesis(function: &str) {
    let Some(cases) = corpus("syn_filt", function) else {
        return;
    };
    for case in &cases {
        let (shift, a, x) = (case.i16("shift"), case.i16s("a"), case.i16s("x"));
        let (lg, update, m) = (case.i16("lg"), case.i16("update"), case.i16("m"));
        let mut mem = case.i16s("mem");
        let mut y = vec![0; x.len()];
        match function {
            "e_util_synthesis" => e_util_synthesis(shift, &a, &x, &mut y, lg, &mut mem, update, m),
            "syn_filt_s" => syn_filt_s(shift, &a, m, &x, &mut y, lg, &mut mem, update),
            _ => {
                y.clone_from(&x);
                e_util_synthesis_in_place(shift, &a, &mut y, lg, &mut mem, update, m);
            }
        }
        check(case, "y", &y, &case.out_i16s("y"));
        check(case, "mem", &mem, &case.out_i16s("mem"));
    }
}

#[test]
fn e_util_synthesis_matches_the_reference() {
    synthesis("e_util_synthesis");
}

#[test]
fn e_util_synthesis_in_place_matches_the_reference() {
    synthesis("e_util_synthesis_in_place");
}

#[test]
fn syn_filt_s_matches_the_reference() {
    synthesis("syn_filt_s");
}

fn lc(function: &str) {
    let Some(cases) = corpus("syn_filt", function) else {
        return;
    };
    for case in &cases {
        let (shift, a, x, lg) = (
            case.i16("shift"),
            case.i16s("a"),
            case.i16s("x"),
            case.i16("lg"),
        );
        let mut y = vec![0; x.len()];
        if function == "syn_filt_s_lc" {
            syn_filt_s_lc(shift, &a, &x, &mut y, lg);
        } else {
            y.clone_from(&x);
            syn_filt_s_lc_in_place(shift, &a, &mut y, lg);
        }
        check(case, "y", &y, &case.out_i16s("y"));
    }
}

#[test]
fn syn_filt_s_lc_matches_the_reference() {
    lc("syn_filt_s_lc");
}

#[test]
fn syn_filt_s_lc_in_place_matches_the_reference() {
    lc("syn_filt_s_lc_in_place");
}

#[test]
fn syn_kern_16_matches_the_reference() {
    let Some(cases) = corpus("syn_filt", "syn_kern_16") else {
        return;
    };
    for case in &cases {
        let out = syn_kern_16(case.i32("l_tmp"), &case.i16s("a"), &case.i16s("y"), 16);
        check(case, "out", &out, &case.out_i32("out"));
    }
}

#[test]
fn synth_mem_updt2_matches_the_reference() {
    let Some(cases) = corpus("syn_filt", "synth_mem_updt2") else {
        return;
    };
    for case in &cases {
        let mut old_exc = case.i16s("old_exc");
        let mut mem_syn_r = case.i16s("mem_syn_r");
        let mut mem_syn = case.i16s("mem_syn");
        let mut mem_syn2 = [0i16; 16];
        synth_mem_updt2(
            case.i16("l_frame"),
            case.i16("last_l_frame"),
            &mut old_exc,
            &mut mem_syn_r,
            &mut mem_syn2,
            (case.i16("with_mem_syn") != 0).then_some(&mut mem_syn[..]),
            case.i16("dec"),
        );
        check(case, "old_exc", &old_exc, &case.out_i16s("old_exc"));
        check(case, "mem_syn_r", &mem_syn_r, &case.out_i16s("mem_syn_r"));
        check(
            case,
            "mem_syn2",
            &mem_syn2.to_vec(),
            &case.out_i16s("mem_syn2"),
        );
        check(case, "mem_syn", &mem_syn, &case.out_i16s("mem_syn"));
    }
}
