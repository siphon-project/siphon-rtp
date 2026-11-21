//! The noise-fill codebook, noise-fill gain, HQ generic fine structure / BWE and envelope
//! application of `lib_com/hq_tools_fx.c` against `fn_hq_tools_noisefill`, on scenarios shaped like
//! `fill_spectrum_fx`'s (all HQ classes but HVQ, 320 / 640 / 960 coefficients, 24.4 .. 128 kbit/s).

use siphon_rtp_codec::evs::com::hq_tools::{
    apply_envelope, apply_nf_gain, apply_noisefill_hq, build_nf_codebook, hq_bwe, hq_generic_fine,
};

use crate::common::{corpus, mismatch};

fn report(messages: impl IntoIterator<Item = Option<String>>) {
    if let Some(message) = messages.into_iter().flatten().next() {
        panic!("{message}");
    }
}

#[test]
fn build_nf_codebook_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_noisefill", "build_nf_codebook") else {
        return;
    };
    let mut flagged = 0;
    for case in &cases {
        let mut cb = vec![-7i16; 800];
        let mut cbm = vec![-7i16; 800];
        let size = build_nf_codebook(
            case.i16("flag"),
            &case.i16s("coeff"),
            &case.i16s("sfm_start"),
            &case.i16s("sfmsize"),
            &case.i16s("sfm_end"),
            case.i16("last_sfm"),
            &case.i16s("r"),
            &mut cb,
            &mut cbm,
        );
        flagged += i32::from(case.i16("flag") != 0 && size > 0);
        report([
            mismatch(case, "size", &size, &case.out_i16("size")),
            mismatch(case, "cb", &cb, &case.out_i16s("cb")),
            mismatch(case, "cbm", &cbm, &case.out_i16s("cbm")),
        ]);
    }
    assert!(flagged > 100, "flagged {flagged}");
}

#[test]
fn apply_noisefill_hq_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_noisefill", "apply_noisefill_hq") else {
        return;
    };
    for case in &cases {
        let mut coeff = case.i16s("coeff");
        apply_noisefill_hq(
            &case.i16s("r"),
            case.i16("length"),
            case.i16("flag"),
            case.i32("core_brate"),
            case.i16("last_sfm"),
            &case.i16s("cb"),
            &case.i16s("cbm"),
            case.i16("size"),
            &case.i16s("sfm_start"),
            &case.i16s("sfm_end"),
            &case.i16s("sfmsize"),
            &mut coeff,
        );
        report([mismatch(case, "coeff", &coeff, &case.out_i16s("coeff"))]);
    }
}

#[test]
fn apply_nf_gain_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_noisefill", "apply_nf_gain") else {
        return;
    };
    for case in &cases {
        let mut coeff = case.i16s("coeff");
        apply_nf_gain(
            case.i16("nf_idx"),
            case.i16("last_sfm"),
            &case.i16s("r"),
            &case.i16s("sfm_start"),
            &case.i16s("sfm_end"),
            &mut coeff,
        );
        report([mismatch(case, "coeff", &coeff, &case.out_i16s("coeff"))]);
    }
}

#[test]
fn hq_generic_fine_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_noisefill", "hq_generic_fine") else {
        return;
    };
    for case in &cases {
        let mut seed = case.i16("seed");
        let mut out = vec![-7i16; 960];
        hq_generic_fine(
            &case.i16s("coeff"),
            case.i16("last_sfm"),
            &case.i16s("sfm_start"),
            &case.i16s("sfm_end"),
            &mut seed,
            &mut out,
        );
        report([
            mismatch(case, "seed", &seed, &case.out_i16("seed")),
            mismatch(case, "out", &out, &case.out_i16s("out")),
        ]);
    }
}

#[test]
fn apply_envelope_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_noisefill", "apply_envelope") else {
        return;
    };
    for case in &cases {
        let mut normq_v = vec![-7i32; 44];
        let mut out = vec![-7i32; 960];
        let mut out1 = vec![-7i32; 960];
        apply_envelope(
            &case.i16s("coeff"),
            &case.i16s("norm"),
            &case.i16s("norm_adj"),
            case.i16("num_sfm"),
            case.i16("last_sfm"),
            case.i16("hqswb_clas"),
            case.i16("length"),
            &case.i16s("sfm_start"),
            &case.i16s("sfm_end"),
            &mut normq_v,
            &mut out,
            &case.i16s("fine"),
            &mut out1,
        );
        report([
            mismatch(case, "normq_v", &normq_v, &case.out_i32s("normq_v")),
            mismatch(case, "out", &out, &case.out_i32s("out")),
            mismatch(case, "out1", &out1, &case.out_i32s("out1")),
        ]);
    }
}

#[test]
fn hq_bwe_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_noisefill", "hq_bwe") else {
        return;
    };
    for case in &cases {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut prev = case.i16("prev");
        let mut out = case.i32s("out");
        let mut out1 = case.i32s("out1");
        hq_bwe(
            case.i16("hqswb_clas"),
            &mut out1,
            &case.i16s("fenv"),
            &mut out,
            case.i16("offset"),
            &mut prev,
            case.i16("exc"),
            &case.i16s("sfm_end"),
            case.i16("num_sfm"),
            case.i16("num_env_bands"),
            &case.i16s("r"),
        );
        report([
            mismatch(case, "prev", &prev, &case.out_i16("prev")),
            mismatch(case, "out", &out, &case.out_i32s("out")),
            mismatch(case, "out1", &out1, &case.out_i32s("out1")),
        ]);
    }
}
