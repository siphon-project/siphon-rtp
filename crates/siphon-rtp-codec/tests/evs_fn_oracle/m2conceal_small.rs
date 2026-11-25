//! `get_subframe_pitch` (`lib_dec/pitch_extr.c`) and the lower case `rescale_mem`
//! (`lib_com/scale_mem_fx.c`) against `fn_m2conceal_small`.

use siphon_rtp_codec::evs::com::scale_mem::rescale_mem_syn;
use siphon_rtp_codec::evs::dec::pitch_extr::get_subframe_pitch;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn get_subframe_pitch_matches_the_reference() {
    let Some(cases) = corpus("m2conceal_small", "get_subframe_pitch") else {
        return;
    };
    for case in &cases {
        let mut buf = [-1i32; 5];
        get_subframe_pitch(case.i16("n"), case.i32("start"), case.i32("end"), &mut buf);
        check(case, "buf", &buf.to_vec(), &case.out_i32s("buf"));
    }
}

#[test]
fn rescale_mem_syn_matches_the_reference() {
    let Some(cases) = corpus("m2conceal_small", "rescale_mem") else {
        return;
    };
    for case in &cases {
        let mut prev_q = case.i16("prev_q");
        let mut q_syn = case.i16("q_syn");
        let mut mem = case.i16s("mem");
        let mut syn = case.i16s("syn");
        let shift = rescale_mem_syn(
            case.i16("q_exc"),
            &mut prev_q,
            &mut q_syn,
            &mut mem,
            (case.i16("with_syn") != 0).then_some(&mut syn[..]),
            case.i16("mem_len"),
            case.i16("i_subfr"),
        );
        check(case, "shift", &shift, &case.out_i16("shift"));
        check(case, "prev_q", &prev_q, &case.out_i16("prev_q"));
        check(case, "q_syn", &q_syn, &case.out_i16("q_syn"));
        check(case, "mem", &mem, &case.out_i16s("mem"));
        check(case, "syn", &syn, &case.out_i16s("syn"));
    }
}
