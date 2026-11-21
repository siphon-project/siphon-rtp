//! `lib_com/gs_noisefill_fx.c` against `fn_gs_noisefill`: the noise fill (`gs_noisf_fx`,
//! `EstimateNoiseLevel_fx` with its inner helper), the high-band reshaping
//! (`Decreas_freqPeak_fx`, `envelop_modify_fx`), `freq_dnw_scaling_fx`, and the whole
//! `highband_exc_dct_in_fx` (which also proves `Apply_NoiseFill_fx`).

use siphon_rtp_codec::evs::com::gs_noisefill::{
    decreas_freq_peak, envelop_modify, estimate_noise_level, freq_dnw_scaling, gs_noisf,
    highband_exc_dct_in,
};
use siphon_rtp_codec::evs::rom::MFREQ_BINDIV_LOC;

use crate::common::{corpus, mismatch, Case};

fn check(case: &Case, name: &str, rust: &[i16]) {
    if let Some(message) = mismatch(case, name, &rust.to_vec(), &case.out_i16s(name)) {
        panic!("{message}");
    }
}

#[test]
fn gs_noisf_matches_the_reference() {
    let Some(cases) = corpus("gs_noisefill", "gs_noisf") else {
        return;
    };
    for case in &cases {
        let mut x = case.i16s("x");
        let mut seed = case.i16("seed");
        gs_noisf(
            case.i16("start"),
            case.i16("nb_qbins"),
            case.i16("noise_fac"),
            &mut x,
            &mut seed,
            case.i16("coder_type"),
            case.i16("q"),
        );
        check(case, "x", &x);
        check(case, "seed", &[seed]);
    }
}

#[test]
fn estimate_noise_level_matches_the_reference() {
    let Some(cases) = corpus("gs_noisefill", "estimate_noise_level") else {
        return;
    };
    for case in &cases {
        let mut noisepb = case.i16s("noisepb");
        estimate_noise_level(
            &mut noisepb,
            case.i32("bitrate"),
            case.i16("diff_len"),
            case.i16("mbands"),
            case.i16("coder_type"),
            case.i16("noise_lev"),
            case.i16("pit_band_idx"),
            case.i16("last_bin"),
            case.i16("bwidth"),
        );
        check(case, "noisepb", &noisepb);
    }
}

#[test]
fn decreas_freq_peak_matches_the_reference() {
    let Some(cases) = corpus("gs_noisefill", "decreas_freq_peak") else {
        return;
    };
    for case in &cases {
        let mut x = case.i16s("x");
        decreas_freq_peak(&case.i16s("lsf"), &mut x, case.i16("rat"));
        check(case, "x", &x);
    }
}

#[test]
fn envelop_modify_matches_the_reference() {
    let Some(cases) = corpus("gs_noisefill", "envelop_modify") else {
        return;
    };
    for case in &cases {
        let mut x = case.i16s("x");
        let mut seed = case.i16("seed");
        let mut q_hb: i16 = 77;
        envelop_modify(
            &mut x,
            &mut seed,
            case.i16("last_bin"),
            &case.i16s("ener"),
            case.i16("q_exc"),
            &mut q_hb,
        );
        check(case, "x", &x);
        check(case, "seed", &[seed]);
        check(case, "q_hb", &[q_hb]);
    }
}

#[test]
fn freq_dnw_scaling_matches_the_reference() {
    let Some(cases) = corpus("gs_noisefill", "freq_dnw_scaling") else {
        return;
    };
    for case in &cases {
        let mut x = case.i16s("x");
        freq_dnw_scaling(
            case.i16("cor"),
            case.i16("coder_type"),
            case.i16("noise_lev"),
            case.i32("core_brate"),
            &mut x,
            case.i16("qx"),
        );
        check(case, "x", &x);
    }
}

#[test]
fn highband_exc_dct_in_matches_the_reference() {
    let Some(cases) = corpus("gs_noisefill", "highband") else {
        return;
    };
    for case in &cases {
        let mut exc_diffq = case.i16s("exc_diffq");
        let mut seed = case.i16("seed");
        let mut ener_iq = case.i16s("ener_iq");
        let mut exc_dct_in = case.i16s("exc_dct_in");
        let mut last_dct = case.i16s("last_dct");
        let mut last_ener = case.i16("last_ener");
        let mut last_band = case.i16s("last_band");
        let mut wo_nf = vec![-11i16; 256];
        let mut lt = case.i16s("lt");
        let with_wo_nf = case.i16("with_wo_nf") != 0;
        highband_exc_dct_in(
            case.i32("core_brate"),
            &MFREQ_BINDIV_LOC,
            case.i16("last_bin"),
            case.i16("diff_len"),
            case.i16("noise_lev"),
            case.i16("pit_band_idx"),
            &mut exc_diffq,
            &mut seed,
            &mut ener_iq,
            case.i16("nb_subfr"),
            &mut exc_dct_in,
            case.i16("last_coder_type"),
            &case.i16s("band"),
            &case.i16s("lsf"),
            &mut last_dct,
            &mut last_ener,
            &mut last_band,
            &case.i16s("exc_alloc"),
            case.i16("bfi"),
            case.i16("coder_type"),
            case.i16("bwidth"),
            with_wo_nf.then_some(&mut wo_nf[..]),
            case.i16("q_diff"),
            case.i16("q_exc"),
            case.i16("noisy"),
            &mut lt,
        );
        check(case, "exc_diffq", &exc_diffq[..256]);
        check(case, "seed", &[seed]);
        check(case, "ener_iq", &ener_iq);
        check(case, "exc_dct_in", &exc_dct_in);
        check(case, "last_dct", &last_dct);
        check(case, "last_ener", &[last_ener]);
        check(case, "last_band", &last_band);
        check(case, "wo_nf", &wo_nf);
        check(case, "lt", &lt);
    }
}
