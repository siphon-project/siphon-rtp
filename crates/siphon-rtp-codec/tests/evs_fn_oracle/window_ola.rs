//! `lib_com/window_ola_fx.c` against `fn_window_ola`. `window_ola` runs two consecutive frames
//! through one overlap memory, the second one optionally through the concealment window.

use siphon_rtp_codec::evs::com::window_ola::{core_switching_ola, sinq, window_ola};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn sinq_matches_the_reference() {
    let Some(cases) = corpus("window_ola", "sinq") else {
        return;
    };
    for case in &cases {
        let n = case.i16("n");
        let mut x = vec![0i16; n as usize];
        sinq(case.i16("tmp"), case.i16("phi"), n, &mut x);
        check(case, "x", &x, &case.out_i16s("x"));
    }
}

#[test]
fn window_ola_matches_the_reference() {
    let Some(cases) = corpus("window_ola", "window_ola") else {
        return;
    };
    for case in &cases {
        let l = case.i16("L");
        let lu = l as usize;
        let mut old_out = case.i16s("old_out");
        let mut q_old = case.i16("q_old");
        for f in 0..2 {
            let wtda = case.i32s(&format!("wtda{f}"));
            let mut gap = case.i16s(&format!("gap{f}"));
            let mut q_sig = case.i16(&format!("q_sig{f}"));
            let mut out = vec![-12345i16; lu];
            window_ola(
                &wtda,
                &mut out,
                &mut q_sig,
                &mut old_out,
                &mut q_old,
                l,
                case.i16(&format!("right{f}")),
                case.i16(&format!("left{f}")),
                case.i16(&format!("bfi{f}")),
                case.i16(&format!("voicing{f}")),
                Some(&mut gap),
            );
            check(
                case,
                &format!("out{f}"),
                &out,
                &case.out_i16s(&format!("out{f}")),
            );
            check(
                case,
                &format!("old_out{f}"),
                &old_out,
                &case.out_i16s(&format!("old_out{f}")),
            );
            check(
                case,
                &format!("gap{f}"),
                &gap,
                &case.out_i16s(&format!("gap{f}")),
            );
            check(
                case,
                &format!("q_sig{f}"),
                &q_sig,
                &case.out_i16(&format!("q_sig{f}")),
            );
            check(
                case,
                &format!("q_old{f}"),
                &q_old,
                &case.out_i16(&format!("q_old{f}")),
            );
        }
    }
}

#[test]
fn core_switching_ola_matches_the_reference() {
    let Some(cases) = corpus("window_ola", "core_switching_ola") else {
        return;
    };
    for case in &cases {
        let mut mem = case.i16s("mem");
        let mut synth = case.i16s("synth");
        let mut subfr = case.i16s("subfr");
        let mut bwe = case.i16s("bwe");
        let mut qsynth = case.i16("qsynth");
        let mut qsubfr = case.i16("qsubfr");
        core_switching_ola(
            &mut mem,
            case.i16("last_L_frame"),
            case.i32("output_fs"),
            &mut synth,
            &mut subfr,
            &mut bwe,
            case.i16("output_frame"),
            case.i16("bwidth"),
            &mut qsynth,
            &mut qsubfr,
        );
        check(case, "mem", &mem, &case.out_i16s("mem"));
        check(case, "synth", &synth, &case.out_i16s("synth"));
        check(case, "subfr", &subfr, &case.out_i16s("subfr"));
        check(case, "bwe", &bwe, &case.out_i16s("bwe"));
        check(case, "qsynth", &qsynth, &case.out_i16("qsynth"));
        check(case, "qsubfr", &qsubfr, &case.out_i16("qsubfr"));
    }
}
