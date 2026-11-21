//! `lib_com/preemph_fx.c` against `fn_preemph`.

use siphon_rtp_codec::evs::com::preemph::{
    e_util_f_preemph2, e_util_f_preemph3, preemph_copy, preemph_copy_in_place,
};

use crate::common::{corpus, mismatch};

fn replay(function: &str) {
    let Some(cases) = corpus("preemph", function) else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let (mu, lg) = (case.i16("mu"), case.i16("lg"));
        let mut mem = case.i16("mem");
        let mut y = vec![0; x.len()];
        if function == "preemph_copy" {
            preemph_copy(&x, &mut y, mu, lg, &mut mem);
        } else {
            y.clone_from(&x);
            preemph_copy_in_place(&mut y, mu, lg, &mut mem);
        }
        if let Some(message) = mismatch(case, "y", &y, &case.out_i16s("y"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16("mem")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn preemph_copy_matches_the_reference() {
    replay("preemph_copy");
}

#[test]
fn preemph_copy_in_place_matches_the_reference() {
    replay("preemph_copy_in_place");
}

fn replay23(function: &str) {
    let Some(cases) = corpus("preemph", function) else {
        return;
    };
    for case in &cases {
        let mut y = case.i16s("x");
        let (mu, lg) = (case.i16("mu"), case.i16("lg"));
        let mut mem = case.i16("mem");
        let mut q = -99;
        if function == "preemph3" {
            q = e_util_f_preemph3(&mut y, mu, lg, &mut mem, case.i16("bits"));
        } else {
            e_util_f_preemph2(case.i16("shift"), &mut y, mu, lg, &mut mem);
        }
        if let Some(message) = mismatch(case, "y", &y, &case.out_i16s("y"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16("mem")))
            .or_else(|| mismatch(case, "q", &q, &case.out_i16("q")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn e_util_f_preemph2_matches_the_reference() {
    replay23("preemph2");
}

#[test]
fn e_util_f_preemph3_matches_the_reference() {
    replay23("preemph3");
}
