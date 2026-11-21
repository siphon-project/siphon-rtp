//! The noise extraction / injection half of `lib_com/swb_bwe_com_lr_fx.c` against
//! `fn_swb_bwe_com_lr_noise`. The SWB BWE cases (`noise_extr_corcod`, `ton_ene_est`, `noiseinj_hf`,
//! and most `spectrum_smoothing_nss` cases) are driven by the decoder's own chain in the reference
//! (`DecodeSWBSubbands_fx`) on SWB 13.2 / 16.4 kbit/s band layouts, two frames through the state each
//! carries; see the harness.

use siphon_rtp_codec::evs::com::swb_bwe_com_lr::{
    get20_log10_spec, get_usebit_npswb, hf_parinitiz, noise_extr_corcod, noiseinj_hf,
    norm_vec_32_16_scale, return_bits_normal2, smooth_spec, spectrum_smoothing_nss, sqrt_32n_16,
    ton_ene_est, GainItemFx,
};
use siphon_rtp_codec::evs::rom::{
    BITS_LAGINDICES_MODENORMAL_FX, SUBBAND_OFFSETS_12KBPS, SUBBAND_OFFSETS_16KBPS,
    SUBBAND_OFFSETS_SUB5_13P2KBPS_HAR_FX, SUBBAND_OFFSETS_SUB5_16P4KBPS_HAR_FX,
    SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX, SUBBAND_SEARCH_OFFSETS_16P4KBPS_HAR_FX,
    SUBBAND_SEARCH_OFFSETS_FX,
};

use crate::common::{corpus, mismatch, Case};

const MODULE: &str = "swb_bwe_com_lr_noise";
const QS: i16 = 12; // SWB_BWE_LR_Qs
const QBE: i16 = 14; // SWB_BWE_LR_Qbe

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn sqrt_32n_16_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "sqrt_32n_16") else {
        return;
    };
    for case in &cases {
        let (mut out, mut qout) = (0, 0);
        sqrt_32n_16(case.i32("l_in"), case.i16("qin"), &mut out, &mut qout);
        check(case, "out", &out, &case.out_i16("out"));
        check(case, "qout", &qout, &case.out_i16("qout"));
    }
}

#[test]
fn norm_vec_32_16_scale_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "norm_vec_32_16_scale") else {
        return;
    };
    for case in &cases {
        let x = case.i32s("x");
        let mut out = vec![0i16; x.len()];
        let mut qout = 0;
        norm_vec_32_16_scale(
            &x,
            case.i16("qin"),
            x.len() as i16,
            &mut out,
            &mut qout,
            case.i16("exp_safe"),
        );
        check(case, "out", &out, &case.out_i16s("out"));
        check(case, "qout", &qout, &case.out_i16("qout"));
    }
}

#[test]
fn get20_log10_spec_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "get20_log10_spec") else {
        return;
    };
    for case in &cases {
        let x = case.i32s("x");
        let mut out = vec![0i16; x.len()];
        get20_log10_spec(&x, &mut out, x.len() as i16, case.i16("q"));
        check(case, "out", &out, &case.out_i16s("out"));
    }
}

#[test]
fn smooth_spec_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "smooth_spec") else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let mut out = vec![0i16; x.len()];
        smooth_spec(&x, &mut out, x.len() as i16);
        check(case, "out", &out, &case.out_i16s("out"));
    }
}

#[test]
fn spectrum_smoothing_nss_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "spectrum_smoothing_nss") else {
        return;
    };
    for case in &cases {
        let x = case.i32s("x");
        let mut out = vec![0i16; x.len()];
        let mut qss = 0;
        spectrum_smoothing_nss(&x, &mut out, &mut qss, x.len() as i16);
        check(case, "out", &out, &case.out_i16s("out"));
        check(case, "qss", &qss, &case.out_i16("qss"));
    }
}

#[test]
fn hf_parinitiz_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "hf_parinitiz") else {
        return;
    };
    // the harness's numbering of the reference tables
    let tables: [&[i16]; 7] = [
        &SUBBAND_OFFSETS_SUB5_13P2KBPS_HAR_FX,
        &SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX,
        &SUBBAND_OFFSETS_SUB5_16P4KBPS_HAR_FX,
        &SUBBAND_SEARCH_OFFSETS_16P4KBPS_HAR_FX,
        &SUBBAND_OFFSETS_12KBPS,
        &SUBBAND_OFFSETS_16KBPS,
        &SUBBAND_SEARCH_OFFSETS_FX,
    ];
    let id = |table: &[i16]| {
        tables
            .iter()
            .position(|candidate| std::ptr::eq(candidate.as_ptr(), table.as_ptr()))
            .map_or(-1, |i| i as i16)
    };
    for case in &cases {
        let mut wbands = case.i16s("wbands");
        let mut search: &'static [i16] = &SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX;
        let mut offsets: &'static [i16] = &SUBBAND_OFFSETS_SUB5_13P2KBPS_HAR_FX;
        let (mut nb, mut nbs, mut low, mut high) = (-7, -7, -7, -7);
        hf_parinitiz(
            case.i32("rate"),
            case.i16("clas"),
            case.i16("low"),
            case.i16("high"),
            &mut wbands,
            &mut search,
            &mut offsets,
            &mut nb,
            &mut nbs,
            &mut low,
            &mut high,
        );
        check(case, "wbands", &wbands, &case.out_i16s("wbands"));
        check(case, "search", &id(search), &case.out_i16("search"));
        check(case, "offsets", &id(offsets), &case.out_i16("offsets"));
        check(case, "n_bands", &nb, &case.out_i16("n_bands"));
        check(
            case,
            "n_bands_search",
            &nbs,
            &case.out_i16("n_bands_search"),
        );
        check(case, "swb_low", &low, &case.out_i16("swb_low"));
        check(case, "swb_high", &high, &case.out_i16("swb_high"));
    }
}

#[test]
fn get_usebit_npswb_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "get_usebit_npswb") else {
        return;
    };
    for case in &cases {
        let bits = get_usebit_npswb(case.i16("clas"));
        check(case, "bits", &bits, &case.out_i16("bits"));
    }
}

#[test]
fn return_bits_normal2_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "return_bits_normal2") else {
        return;
    };
    for case in &cases {
        let mut budget = case.i16("budget");
        return_bits_normal2(
            &mut budget,
            &case.i16s("flags"),
            case.i16("bands"),
            &BITS_LAGINDICES_MODENORMAL_FX,
        );
        check(case, "budget", &budget, &case.out_i16("budget"));
    }
}

#[test]
fn noise_extr_corcod_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus(MODULE, "noise_extr_corcod") else {
        return;
    };
    for case in &cases {
        let mut prev_ni_ratio = case.i16("prev_ni_ratio");
        for frame in 0..2 {
            let name = |base: &str| format!("{base}{frame}");
            let spectra = case.i32s(&name("spectra"));
            let n = spectra.len();
            let (mut ss, mut ss_diff, mut ss_ni) = (vec![0i16; n], vec![0i16; n], vec![0i16; n]);
            let mut qss = 0;
            noise_extr_corcod(
                &spectra,
                &case.i32s(&name("spectra_ni")),
                &mut ss,
                &mut ss_diff,
                &mut ss_ni,
                n as i16,
                case.i16(&name("clas")),
                &mut prev_ni_ratio,
                &mut qss,
            );
            check(case, &name("ss"), &ss, &case.out_i16s(&name("ss")));
            check(
                case,
                &name("ss_diff"),
                &ss_diff,
                &case.out_i16s(&name("ss_diff")),
            );
            check(case, &name("ss_ni"), &ss_ni, &case.out_i16s(&name("ss_ni")));
            check(case, &name("qss"), &qss, &case.out_i16(&name("qss")));
            check(
                case,
                &name("prev_ni_ratio"),
                &prev_ni_ratio,
                &case.out_i16(&name("prev_ni_ratio")),
            );
        }
    }
}

#[test]
fn ton_ene_est_matches_the_reference_on_the_harmonic_chain() {
    let Some(cases) = corpus(MODULE, "ton_ene_est") else {
        return;
    };
    for case in &cases {
        let bands = case.i16("bands");
        let (band_start, band_end, band_width) = (
            case.i16s("band_start"),
            case.i16s("band_end"),
            case.i16s("band_width"),
        );
        for frame in 0..2 {
            let name = |base: &str| format!("{base}{frame}");
            let mut xsynth = case.i32s(&name("xsynth"));
            let pk_sf: Vec<GainItemFx> = case
                .i16s(&name("nmr"))
                .into_iter()
                .zip(case.i16s(&name("gidx")))
                .map(|(nmr_value, gain_index)| GainItemFx {
                    nmr_value,
                    gain_index,
                })
                .collect();
            let mut be_tonal = vec![0i32; bands as usize];
            let mut qbel = -99;
            ton_ene_est(
                &mut xsynth,
                QS,
                &mut be_tonal,
                &mut qbel,
                &case.i32s(&name("band_energy")),
                QBE,
                &band_start,
                &band_end,
                &band_width,
                case.i16(&name("low")),
                case.i16(&name("high")),
                bands,
                case.i16(&name("har_bands")),
                case.i16(&name("g")),
                &pk_sf,
                case.i16(&name("qss")),
                &case.i16s(&name("pul_res")),
            );
            check(
                case,
                &name("xsynth"),
                &xsynth,
                &case.out_i32s(&name("xsynth")),
            );
            check(
                case,
                &name("be_tonal"),
                &be_tonal,
                &case.out_i32s(&name("be_tonal")),
            );
            check(case, &name("qbel"), &qbel, &case.out_i16(&name("qbel")));
        }
    }
}

#[test]
fn noiseinj_hf_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus(MODULE, "noiseinj_hf") else {
        return;
    };
    for case in &cases {
        let bands = case.i16("bands");
        let (band_start, band_end) = (case.i16s("band_start"), case.i16s("band_end"));
        let mut prev_en_sb = case.i16s("prev_en_sb");
        for frame in 0..2 {
            let name = |base: &str| format!("{base}{frame}");
            let mut xsynth = case.i32s(&name("xsynth"));
            noiseinj_hf(
                &mut xsynth,
                QS,
                &case.i32s(&name("th_g")),
                &case.i32s(&name("band_energy")),
                QBE,
                &mut prev_en_sb,
                &case.i16s(&name("flags")),
                bands,
                &band_start,
                &band_end,
                case.i16(&name("low")),
                case.i16(&name("high")),
            );
            check(
                case,
                &name("xsynth"),
                &xsynth,
                &case.out_i32s(&name("xsynth")),
            );
            check(
                case,
                &name("prev_en_sb"),
                &prev_en_sb,
                &case.out_i16s(&name("prev_en_sb")),
            );
        }
    }
}
