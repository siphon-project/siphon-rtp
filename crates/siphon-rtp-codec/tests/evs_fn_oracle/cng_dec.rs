//! `lib_dec/cng_dec_fx.c` (`CNG_dec_fx`) and `lib_com/isf_dec_amr_wb_fx.c` against `fn_cng_dec`.
//!
//! Each case randomises the CNG state (previous rates and frame lengths, LSF memories, the CNG
//! and hangover histories and circular buffers) and the bits of a SID or no-data frame, in the
//! EVS (2.4 kbit/s SID) and the AMR-WB IO (1.75 kbit/s SID) forms; the oracle prints the whole
//! decoder state before the call and the outputs and changed fields after it.

use siphon_rtp_codec::evs::com::isf_dec_amr_wb::isf_dec_amr_wb;
use siphon_rtp_codec::evs::dec::cng_dec::cng_dec;

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn cng_dec_cases(function: &str) {
    let Some(cases) = corpus_sized("cng_dec", function, 400) else {
        return;
    };
    let mut averaged = 0;
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let context = format!("{function} case {index}");
        let mut aq = vec![-12345i16; 85];
        let mut lsp_new = vec![-12345i16; 16];
        let mut lsf_new = vec![-12345i16; 16];
        let mut allow_cn_step = -7;
        let mut sid_bw = case.i16("sid_bw");
        let mut q_env = vec![-777i32; 20];
        let (l_frame, core_brate) = (st.l_frame, st.core_brate);
        cng_dec(
            &mut st,
            l_frame,
            &mut aq,
            core_brate,
            &mut lsp_new,
            &mut lsf_new,
            &mut allow_cn_step,
            &mut sid_bw,
            &mut q_env,
        );
        check(case, "Aq", &aq, &case.out_i16s("Aq"));
        check(case, "lsp_new", &lsp_new, &case.out_i16s("lsp_new"));
        check(case, "lsf_new", &lsf_new, &case.out_i16s("lsf_new"));
        check(
            case,
            "allow_cn_step",
            &allow_cn_step,
            &case.out_i16("allow_cn_step"),
        );
        check(case, "sid_bw", &sid_bw, &case.out_i16("sid_bw_out"));
        check(case, "q_env", &q_env, &case.out_i32s("q_env"));
        crate::state_dump::check(&mut st, &state_after(case), "st.", &context);
        averaged += i32::from(st.num_ho > 1);
    }
    assert!(
        averaged > 20,
        "only {averaged} cases averaged the hangover history"
    );
}

#[test]
fn cng_dec_matches_the_reference() {
    cng_dec_cases("cng_dec");
}

#[test]
fn cng_dec_matches_the_reference_in_amr_wb_io() {
    cng_dec_cases("cng_dec_amr_wb");
}

#[test]
fn isf_dec_amr_wb_matches_the_reference() {
    let Some(cases) = corpus_sized("cng_dec", "isf_dec_amr_wb", 400) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let mut aq = vec![-12345i16; 68];
        let mut isf_new = vec![-12345i16; 16];
        let mut isp_new = vec![-12345i16; 16];
        isf_dec_amr_wb(&mut st, &mut aq, &mut isf_new, &mut isp_new);
        check(case, "Aq", &aq, &case.out_i16s("Aq"));
        check(case, "isf_new", &isf_new, &case.out_i16s("isf_new"));
        check(case, "isp_new", &isp_new, &case.out_i16s("isp_new"));
        crate::state_dump::check(
            &mut st,
            &state_after(case),
            "st.",
            &format!("isf_dec_amr_wb case {index}"),
        );
    }
}
