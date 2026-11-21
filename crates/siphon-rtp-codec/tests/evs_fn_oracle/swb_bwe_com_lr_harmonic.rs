//! The harmonic analysis, envelope smoothing and HF synthesis of `lib_com/swb_bwe_com_lr_fx.c`
//! against `fn_swb_bwe_com_lr_harmonic`.

use siphon_rtp_codec::evs::com::swb_bwe_com_lr::{
    convert_lag_indices_pls2smp, div_s_ss, est_freq_har_decis, find_n_biggest2_simple_fx_har,
    genhf_noise, get_predicted_signal, get_sigma_fx_har, get_synthesized_spec_thin_out,
    getlag_gains, har_est, post_hq2_swb, preset_hq2_swb, spectrum_smoothing,
    spectrumsmooth_noiseton, GainItemFx,
};

use crate::common::{corpus, mismatch, Case};

const MODULE: &str = "swb_bwe_com_lr_harmonic";
const SWB_BWE_LR_QBE: i16 = 14;

fn items(values: &[i16]) -> Vec<GainItemFx> {
    values
        .chunks(2)
        .map(|pair| GainItemFx {
            nmr_value: pair[0],
            gain_index: pair[1],
        })
        .collect()
}

fn fail(message: Option<String>) {
    if let Some(message) = message {
        panic!("{message}");
    }
}

/// A zero-padded copy of `values` at `length`, for a buffer the corpus prints only in part.
fn padded<T: Copy + Default>(values: &[T], length: usize) -> Vec<T> {
    let mut buffer = vec![T::default(); length.max(values.len())];
    buffer[..values.len()].copy_from_slice(values);
    buffer
}

#[test]
fn harmonic_div_s_ss_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "div_s_ss") else {
        return;
    };
    for case in &cases {
        let result = div_s_ss(case.i16("n"), case.i16("d"));
        fail(mismatch(case, "r", &result, &case.out_i16("r")));
    }
}

#[test]
fn harmonic_get_predicted_signal_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "get_predicted_signal") else {
        return;
    };
    for case in &cases {
        let mut out = case.i32s("out");
        get_predicted_signal(
            &case.i16s("pred"),
            &mut out,
            case.i16("lag"),
            case.i16("len"),
            case.i16("gain"),
            case.i16("qgain"),
        );
        fail(mismatch(case, "out", &out, &case.out_i32s("out")));
    }
}

#[test]
fn harmonic_est_freq_har_decis_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "est_freq_har_decis") else {
        return;
    };
    for case in &cases {
        let (mut est1, mut est2, mut prev) = (case.i16("est1"), case.i16("est2"), case.i16("prev"));
        est_freq_har_decis(
            &mut est1,
            &mut est2,
            case.i16("sharp"),
            case.i16("sharp1"),
            case.i16("c1"),
            case.i16("c2"),
            case.i16("k"),
            case.i16("k1"),
            case.i16("k2"),
            &mut prev,
        );
        fail(
            mismatch(case, "est1", &est1, &case.out_i16("est1"))
                .or_else(|| mismatch(case, "est2", &est2, &case.out_i16("est2")))
                .or_else(|| mismatch(case, "prev", &prev, &case.out_i16("prev"))),
        );
    }
}

#[test]
fn harmonic_har_est_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "har_est") else {
        return;
    };
    for case in &cases {
        let (mut est1, mut est2, mut flag) = (case.i16("est1"), case.i16("est2"), case.i16("flag"));
        let (mut prev, mut stab) = (case.i16("prev"), case.i16("stab"));
        let result = har_est(
            &case.i32s("spectra"),
            case.i16("n"),
            &mut est1,
            &mut est2,
            &mut flag,
            &mut prev,
            &case.i16s("offs"),
            &case.i16s("widths"),
            &mut stab,
        );
        fail(
            mismatch(case, "r", &result, &case.out_i16("r"))
                .or_else(|| mismatch(case, "est1", &est1, &case.out_i16("est1")))
                .or_else(|| mismatch(case, "est2", &est2, &case.out_i16("est2")))
                .or_else(|| mismatch(case, "flag", &flag, &case.out_i16("flag")))
                .or_else(|| mismatch(case, "prev", &prev, &case.out_i16("prev")))
                .or_else(|| mismatch(case, "stab", &stab, &case.out_i16("stab"))),
        );
    }
}

#[test]
fn harmonic_genhf_noise_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "genhf_noise") else {
        return;
    };
    for case in &cases {
        let mut xsynth = case.i32s("xsynth");
        let mut pul_res = case.i16s("pul_res");
        let mut pk = items(&case.i16s("pk"));
        genhf_noise(
            &case.i16s("noise_flr"),
            case.i16("qss"),
            &mut xsynth,
            case.i16("qsl"),
            &case.i16s("pred"),
            case.i16("bands"),
            case.i16("har_bands"),
            case.i16("est2"),
            case.i16("pos_max"),
            &mut pul_res,
            &mut pk,
            case.i16("low"),
            case.i16("high"),
            &case.i16s("widths"),
            &case.i16s("lag"),
            &case.i16s("offsets"),
            &case.i16s("search"),
        );
        fail(
            mismatch(case, "xsynth", &xsynth, &case.out_i32s("xsynth"))
                .or_else(|| mismatch(case, "pul_res", &pul_res, &case.out_i16s("pul_res")))
                .or_else(|| mismatch(case, "pk", &pk, &items(&case.out_i16s("pk")))),
        );
    }
}

#[test]
fn harmonic_spectrum_smoothing_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "spectrum_smoothing") else {
        return;
    };
    for case in &cases {
        let mut out = case.i16s("out");
        let mut qss = 0;
        spectrum_smoothing(
            &case.i32s("in"),
            &mut out,
            &mut qss,
            case.i16("len"),
            case.i16("th"),
        );
        fail(
            mismatch(case, "out", &out, &case.out_i16s("out"))
                .or_else(|| mismatch(case, "qss", &qss, &case.out_i16("qss"))),
        );
    }
}

#[test]
fn harmonic_spectrumsmooth_noiseton_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "spectrumsmooth_noiseton") else {
        return;
    };
    for case in &cases {
        let reference_ss = case.out_i16s("ss");
        let length = reference_ss.len();
        // the untouched tails were printed only on the output side
        let mut ss = reference_ss.clone();
        let mut sdiff = case.out_i16s("sdiff");
        let mut sni = case.out_i16s("sni");
        let len = usize::try_from(case.i16("len")).unwrap();
        ss[..len].fill(0x5a5a);
        sdiff[..len].fill(0x5a5a);
        sni[..len].fill(0x5a5a);
        let (mut qss, mut seed) = (0, case.i16("seed"));
        let result = spectrumsmooth_noiseton(
            &padded(&case.i32s("spectra"), length),
            &padded(&case.i32s("ni"), length),
            &mut ss,
            &mut sdiff,
            &mut sni,
            &mut qss,
            case.i16("len"),
            &mut seed,
        );
        fail(
            mismatch(case, "r", &result, &case.out_i16("r"))
                .or_else(|| mismatch(case, "ss", &ss, &reference_ss))
                .or_else(|| mismatch(case, "sdiff", &sdiff, &case.out_i16s("sdiff")))
                .or_else(|| mismatch(case, "sni", &sni, &case.out_i16s("sni")))
                .or_else(|| mismatch(case, "qss", &qss, &case.out_i16("qss")))
                .or_else(|| mismatch(case, "seed", &seed, &case.out_i16("seed"))),
        );
    }
}

#[test]
fn harmonic_convert_lag_indices_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "convert_lag_indices") else {
        return;
    };
    for case in &cases {
        let mut out = case.i16s("out");
        convert_lag_indices_pls2smp(
            &case.i16s("in"),
            case.i16("nbands"),
            &mut out,
            &case.i16s("ss"),
            &case.i16s("widths"),
            case.i16("low"),
        );
        fail(mismatch(case, "out", &out, &case.out_i16s("out")));
    }
}

#[test]
fn harmonic_getlag_gains_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "getlag_gains") else {
        return;
    };
    for case in &cases {
        let mut gains = case.i16s("gains");
        let mut qgains = case.i16s("qgains");
        getlag_gains(
            &case.i16s("pred"),
            case.i16("qss"),
            &case.i32s("energy"),
            SWB_BWE_LR_QBE,
            case.i16("nbands"),
            &case.i16s("widths"),
            &case.i16s("lags"),
            case.i16("low"),
            &mut gains,
            &mut qgains,
        );
        fail(
            mismatch(case, "gains", &gains, &case.out_i16s("gains"))
                .or_else(|| mismatch(case, "qgains", &qgains, &case.out_i16s("qgains"))),
        );
    }
}

#[test]
fn harmonic_get_synthesized_spec_thin_out_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "get_synthesized_spec_thin_out") else {
        return;
    };
    for case in &cases {
        let mut out = case.i32s("out");
        get_synthesized_spec_thin_out(
            &case.i16s("pred"),
            10,
            &mut out,
            case.i16("qsl"),
            case.i16("nbands"),
            &case.i16s("widths"),
            &case.i16s("lags"),
            &case.i16s("gains"),
            &case.i16s("qgains"),
            case.i16("low"),
        );
        fail(mismatch(case, "out", &out, &case.out_i32s("out")));
    }
}

#[test]
fn harmonic_get_sigma_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "get_sigma") else {
        return;
    };
    for case in &cases {
        let (mut sigma, mut qsigma) = (0, 0);
        get_sigma_fx_har(
            &case.i32s("x"),
            case.i16("qi"),
            case.i16("avg"),
            case.i16("qavg"),
            case.i16("len"),
            &mut sigma,
            &mut qsigma,
        );
        fail(
            mismatch(case, "sigma", &sigma, &case.out_i16("sigma"))
                .or_else(|| mismatch(case, "qsigma", &qsigma, &case.out_i16("qsigma"))),
        );
    }
}

#[test]
fn harmonic_find_n_biggest2_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "find_n_biggest2") else {
        return;
    };
    for case in &cases {
        let mut pk = items(&case.i16s("pk"));
        let mut n = 0;
        find_n_biggest2_simple_fx_har(
            &case.i32s("x"),
            case.i16("q"),
            &mut pk,
            case.i16("len"),
            &mut n,
            case.i16("nsearch"),
        );
        fail(
            mismatch(case, "pk", &pk, &items(&case.out_i16s("pk")))
                .or_else(|| mismatch(case, "n", &n, &case.out_i16("n"))),
        );
    }
}

fn check_preset_post(case: &Case) {
    let clas = case.i16("clas");
    let band_start = case.i16s("band_start");
    let band_end = case.i16s("band_end");
    let bands = case.i16("bands");
    let mut har_bands = case.i16("har_bands");
    let (mut low, mut high) = (0, 0);
    let mut m = case.i32s("m");
    preset_hq2_swb(
        clas,
        &band_end,
        &mut har_bands,
        case.i16("p2a_bands"),
        case.i16("length"),
        bands,
        &mut low,
        &mut high,
        &mut m,
    );
    fail(
        mismatch(case, "har_bands", &har_bands, &case.out_i16("har_bands"))
            .or_else(|| mismatch(case, "low", &low, &case.out_i16("low")))
            .or_else(|| mismatch(case, "high", &high, &case.out_i16("high")))
            .or_else(|| mismatch(case, "m", &m, &case.out_i32s("m"))),
    );
    let mut y2 = case.i32s("y2");
    let mut npulses = case.i16s("npulses");
    post_hq2_swb(
        &case.out_i32s("m2"),
        low,
        high,
        clas,
        har_bands,
        bands,
        &case.i16s("p2a"),
        &band_start,
        &band_end,
        &mut y2,
        &mut npulses,
    );
    fail(
        mismatch(case, "y2", &y2, &case.out_i32s("y2"))
            .or_else(|| mismatch(case, "npulses", &npulses, &case.out_i16s("npulses"))),
    );
}

#[test]
fn harmonic_preset_and_post_hq2_swb_match_the_reference() {
    let Some(cases) = corpus(MODULE, "preset_post") else {
        return;
    };
    for case in &cases {
        check_preset_post(case);
    }
}
