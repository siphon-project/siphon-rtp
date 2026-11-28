//! `lib_com/lsf_dec_bfi_fx.c` (`lsf_dec_bfi`, `PlcGetLsfBase`) against `fn_lsf_dec_bfi`.

use siphon_rtp_codec::evs::com::lsf_dec_bfi::{lsf_dec_bfi, plc_get_lsf_base};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn lsf_dec_bfi_matches_the_reference() {
    let Some(cases) = corpus("lsf_dec_bfi", "lsf_dec_bfi") else {
        return;
    };
    for case in &cases {
        let mut lsf = vec![-1i16; 16];
        let mut mem_ma = case.i16s("mem_ma");
        let mut mem_ar = case.i16s("mem_ar");
        let mut lsf_q_cng = vec![-1i16; 16];
        let base = (case.i16("have_base") != 0).then(|| case.i16s("lsf_base"));
        let have_q_cng = case.i16("have_q_cng") != 0;
        let lsf_cng = case.i16s("lsf_cng");
        let old_lsf_q_cng = case.i16s("old_lsf_q_cng");
        lsf_dec_bfi(
            case.i16("codec_mode"),
            &mut lsf,
            &case.i16s("lsfold"),
            &case.i16s("lsf_adaptive_mean"),
            base.as_deref(),
            &mut mem_ma,
            &mut mem_ar,
            case.i16("stab_fac"),
            case.i16("last_coder_type"),
            case.i16("l_frame"),
            case.i16("last_good"),
            case.i16("nb_lost_cmpt"),
            case.i16("plc_updated") as i8,
            have_q_cng.then_some(&mut lsf_q_cng[..]),
            (case.i16("have_cng") != 0).then_some(&lsf_cng[..]),
            have_q_cng.then_some(&old_lsf_q_cng[..]),
            case.i16("gsc_idx"),
            case.i16("opt_amr_wb"),
            case.i16("tcxonly") as i8,
            case.i16("bwidth"),
        );
        check(case, "lsf", &lsf, &case.out_i16s("lsf"));
        check(case, "mem_ma", &mem_ma, &case.out_i16s("mem_ma"));
        check(case, "mem_ar", &mem_ar, &case.out_i16s("mem_ar"));
        check(case, "lsf_q_cng", &lsf_q_cng, &case.out_i16s("lsf_q_cng"));
    }
}

#[test]
fn plc_get_lsf_base_matches_the_reference() {
    let Some(cases) = corpus("lsf_dec_bfi", "plc_get_lsf_base") else {
        return;
    };
    for case in &cases {
        let base = plc_get_lsf_base(
            case.i16("lpc_quantization"),
            case.i16("narrow_band"),
            case.i32("sr_core"),
        );
        check(case, "base", &base.to_vec(), &case.out_i16s("base"));
    }
}
