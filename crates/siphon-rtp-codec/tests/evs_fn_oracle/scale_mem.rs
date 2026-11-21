//! `lib_com/scale_mem_fx.c` against `fn_scale_mem`.

use siphon_rtp_codec::evs::cnst::{L_EXC_MEM_DEC, PIT16K_MAX};
use siphon_rtp_codec::evs::com::scale_mem::{rescale_exc, rescale_mem};
use siphon_rtp_codec::evs::dec::state::Pfstat;

use crate::common::{corpus, mismatch};

#[test]
fn rescale_exc_matches_the_reference() {
    let Some(cases) = corpus("scale_mem", "rescale_exc") else {
        return;
    };
    for case in &cases {
        let mut exc = case.i16s("exc");
        let mut bwe = case.i16s("bwe");
        let mut dct = case.i16s("dct");
        let mut last = case.i16s("last");
        let mut exc2 = case.i16s("exc2");
        let mut sq_subfr = case.i16s("sq_subfr");
        let mut sq_exc = case.i16("sq_exc");
        let r = rescale_exc(
            (case.i16("has_dct") != 0).then_some(dct.as_mut_slice()),
            &mut exc,
            L_EXC_MEM_DEC as usize,
            (case.i16("has_bwe") != 0).then_some((bwe.as_mut_slice(), PIT16K_MAX as usize * 2)),
            (case.i16("has_last") != 0).then_some(last.as_mut_slice()),
            case.i16("lg"),
            case.i16("lg32"),
            case.i32("gain"),
            &mut sq_exc,
            &mut sq_subfr,
            (case.i16("has_exc2") != 0).then_some(exc2.as_mut_slice()),
            case.i16("i_subfr"),
            case.i16("coder_type"),
        );
        let message = mismatch(case, "r", &r, &case.out_i16("r"))
            .or_else(|| mismatch(case, "exc", &exc, &case.out_i16s("exc")))
            .or_else(|| mismatch(case, "bwe", &bwe, &case.out_i16s("bwe")))
            .or_else(|| mismatch(case, "dct", &dct, &case.out_i16s("dct")))
            .or_else(|| mismatch(case, "last", &last, &case.out_i16s("last")))
            .or_else(|| mismatch(case, "exc2", &exc2, &case.out_i16s("exc2")))
            .or_else(|| mismatch(case, "sq_subfr", &sq_subfr, &case.out_i16s("sq_subfr")))
            .or_else(|| mismatch(case, "sq_exc", &sq_exc, &case.out_i16("sq_exc")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

#[test]
fn rescale_mem_matches_the_reference() {
    let Some(cases) = corpus("scale_mem", "rescale_mem") else {
        return;
    };
    for case in &cases {
        let mut mem_syn2 = case.i16s("mem_syn2");
        let mut clas = case.i16s("clas");
        let mut pst = case.i16s("pst");
        let tmpbuf = case.i16s("tmpbuf");
        let mut pf = Pfstat::zeroed();
        pf.mem_pf_in.copy_from_slice(&case.i16s("pf_in"));
        pf.mem_res2.copy_from_slice(&case.i16s("pf_res2"));
        pf.mem_stp.copy_from_slice(&case.i16s("pf_stp"));
        let (mut deemph, mut err, mut agc) = (case.i16("deemph"), case.i16("err"), case.i16("agc"));
        let (mut prev_q_syn, mut q_syn) = (case.i16("prev_q_syn"), case.i16("q_syn"));
        rescale_mem(
            case.i16("q_exc"),
            &mut prev_q_syn,
            &mut q_syn,
            &mut mem_syn2,
            &mut clas,
            case.i16("max_scaling"),
            &mut deemph,
            &mut pst,
            &mut err,
            &mut agc,
            &mut pf,
            case.i16("vad"),
            case.i16("cna"),
            (case.i16("has_tmp") != 0).then_some(tmpbuf.as_slice()),
        );
        let message = mismatch(case, "mem_syn2", &mem_syn2, &case.out_i16s("mem_syn2"))
            .or_else(|| mismatch(case, "clas", &clas, &case.out_i16s("clas")))
            .or_else(|| mismatch(case, "pst", &pst, &case.out_i16s("pst")))
            .or_else(|| {
                mismatch(
                    case,
                    "pf_in",
                    &pf.mem_pf_in.to_vec(),
                    &case.out_i16s("pf_in"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "pf_res2",
                    &pf.mem_res2.to_vec(),
                    &case.out_i16s("pf_res2"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "pf_stp",
                    &pf.mem_stp.to_vec(),
                    &case.out_i16s("pf_stp"),
                )
            })
            .or_else(|| mismatch(case, "deemph", &deemph, &case.out_i16("deemph")))
            .or_else(|| mismatch(case, "err", &err, &case.out_i16("err")))
            .or_else(|| mismatch(case, "agc", &agc, &case.out_i16("agc")))
            .or_else(|| mismatch(case, "prev_q_syn", &prev_q_syn, &case.out_i16("prev_q_syn")))
            .or_else(|| mismatch(case, "q_syn", &q_syn, &case.out_i16("q_syn")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}
