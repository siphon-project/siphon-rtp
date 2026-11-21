//! `lib_com/cng_exc_fx.c` (`cng_params_upd_fx`) against `fn_cng_exc`: three consecutive calls
//! through one hangover memory.

use siphon_rtp_codec::evs::cnst::{HO_HIST_SIZE, L_FFT};
use siphon_rtp_codec::evs::com::cng_exc::cng_params_upd;

use crate::common::{corpus_sized, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn cng_params_upd_matches_the_reference_over_consecutive_frames() {
    // Each case prints three frames of the whole hangover memory; 1000 keeps the corpus small.
    let Some(cases) = corpus_sized("cng_exc", "cng_params_upd", 1000) else {
        return;
    };
    for case in &cases {
        let mut ho_circ_ptr = case.i16("ho_circ_ptr");
        let mut ho_circ_size = case.i16("ho_circ_size");
        let mut cng_buf_cnt = case.i16("cng_buf_cnt");
        let mut ho_ener_circ = case.i32s("ho_ener_circ");
        let mut ho_env_circ = case.i32s("ho_env_circ");
        let mut cng_brate_buf = case.i32s("cng_brate_buf");
        let mut cng_qexc_buf = case.i16s("cng_qexc_buf");
        let mut ho_lsp_circ = case.i16s("ho_lsp_circ");
        let mut cng_exc2_buf: Vec<i16> = (0..(HO_HIST_SIZE * L_FFT) as usize)
            .map(|i| i as i16)
            .collect();
        for frame in 0..3 {
            let name = |base: &str| format!("{base}{frame}");
            let exc = case.i16s(&name("exc"));
            cng_params_upd(
                &case.i16s(&name("lsp")),
                &exc,
                exc.len() as i16,
                &mut ho_circ_ptr,
                &mut ho_ener_circ,
                &mut ho_circ_size,
                &mut ho_lsp_circ,
                case.i16(&name("q_exc")),
                case.i16(&name("flag")),
                &mut ho_env_circ,
                &mut cng_buf_cnt,
                &mut cng_exc2_buf,
                &mut cng_qexc_buf,
                &mut cng_brate_buf,
                case.i32(&name("brate")),
            );
            check(
                case,
                &name("ho_circ_ptr"),
                &ho_circ_ptr,
                &case.out_i16(&name("ho_circ_ptr")),
            );
            check(
                case,
                &name("ho_circ_size"),
                &ho_circ_size,
                &case.out_i16(&name("ho_circ_size")),
            );
            check(
                case,
                &name("cng_buf_cnt"),
                &cng_buf_cnt,
                &case.out_i16(&name("cng_buf_cnt")),
            );
            check(
                case,
                &name("ho_ener_circ"),
                &ho_ener_circ,
                &case.out_i32s(&name("ho_ener_circ")),
            );
            check(
                case,
                &name("ho_env_circ"),
                &ho_env_circ,
                &case.out_i32s(&name("ho_env_circ")),
            );
            check(
                case,
                &name("ho_lsp_circ"),
                &ho_lsp_circ,
                &case.out_i16s(&name("ho_lsp_circ")),
            );
            check(
                case,
                &name("cng_brate_buf"),
                &cng_brate_buf,
                &case.out_i32s(&name("cng_brate_buf")),
            );
            check(
                case,
                &name("cng_qexc_buf"),
                &cng_qexc_buf,
                &case.out_i16s(&name("cng_qexc_buf")),
            );
            let slot = ho_circ_ptr as usize * L_FFT as usize;
            check(
                case,
                &name("cng_exc2_slot"),
                &cng_exc2_buf[slot..slot + L_FFT as usize].to_vec(),
                &case.out_i16s(&name("cng_exc2_slot")),
            );
        }
    }
}

/// `CNG_exc_fx` over three consecutive frames through one set of CNG memories.
#[test]
fn cng_exc_matches_the_reference_over_consecutive_frames() {
    use siphon_rtp_codec::evs::com::cng_exc::cng_exc;

    let Some(cases) = corpus_sized("cng_exc", "cng_exc", 1500) else {
        return;
    };
    for case in &cases {
        let l_frame = case.i16("L_frame");
        let frame = l_frame as usize;
        let mut excbuf = case.i16s("excbuf");
        let mut seed = case.i16("seed");
        let mut cng_ener_seed = case.i16("cng_ener_seed");
        let mut cng_ener_seed1 = case.i16("cng_ener_seed1");
        let mut last_allow_cn_step = case.i16("last_allow_cn_step");
        let mut exc_mem = case.i16s("exc_mem");
        let mut exc_mem1 = case.i16s("exc_mem1");
        let mut enew = case.i32("Enew");
        let mut lp_ener = case.i32("lp_ener");
        let q_env = case.i32s("q_env");
        let mut lp_env = case.i32s("lp_env");
        let mut old_env = case.i32s("old_env");
        let sid_bw = case.i16("sid_bw");
        for f in 0..3 {
            let name = |base: &str| format!("{base}{f}");
            let mut exc2 = vec![-12345i16; 320];
            let mut exc3 = vec![-12345i16; 320];
            let mut bwe_exc = vec![-12345i16; 648];
            cng_exc(
                case.i32(&name("core")),
                l_frame,
                &mut enew,
                &mut seed,
                &mut excbuf,
                289,
                &mut exc2,
                &mut lp_ener,
                case.i32(&name("last_core")),
                case.i16(&name("first")),
                &mut cng_ener_seed,
                &mut bwe_exc,
                case.i16(&name("allow")),
                &mut last_allow_cn_step,
                case.i16(&name("old_q")),
                case.i16(&name("q")),
                case.i16(&name("num_ho")),
                &q_env,
                &mut lp_env,
                &mut old_env,
                &mut exc_mem,
                &mut exc_mem1,
                sid_bw,
                &mut cng_ener_seed1,
                &mut exc3,
                case.i16("opt_amr_wb"),
            );
            check(case, &name("Enew"), &enew, &case.out_i32(&name("Enew")));
            check(case, &name("seed"), &seed, &case.out_i16(&name("seed")));
            check(
                case,
                &name("exc"),
                &excbuf[289..289 + frame].to_vec(),
                &case.out_i16s(&name("exc")),
            );
            check(
                case,
                &name("exc2"),
                &exc2,
                &case.out_i16s(&format!("exc2_{f}")),
            );
            check(
                case,
                &name("exc3"),
                &exc3,
                &case.out_i16s(&format!("exc3_{f}")),
            );
            check(
                case,
                &name("lp_ener"),
                &lp_ener,
                &case.out_i32(&name("lp_ener")),
            );
            check(
                case,
                &name("cng_ener_seed"),
                &cng_ener_seed,
                &case.out_i16(&name("cng_ener_seed")),
            );
            check(
                case,
                &name("cng_ener_seed1"),
                &cng_ener_seed1,
                &case.out_i16(&format!("cng_ener_seed1_{f}")),
            );
            check(
                case,
                &name("bwe_exc"),
                &bwe_exc,
                &case.out_i16s(&name("bwe_exc")),
            );
            check(
                case,
                &name("last_allow"),
                &last_allow_cn_step,
                &case.out_i16(&name("last_allow")),
            );
            check(
                case,
                &name("lp_env"),
                &lp_env,
                &case.out_i32s(&name("lp_env")),
            );
            check(
                case,
                &name("old_env"),
                &old_env,
                &case.out_i32s(&name("old_env")),
            );
            check(
                case,
                &name("exc_mem"),
                &exc_mem,
                &case.out_i16s(&name("exc_mem")),
            );
            check(
                case,
                &name("exc_mem1"),
                &exc_mem1,
                &case.out_i16s(&format!("exc_mem1_{f}")),
            );
        }
    }
}
