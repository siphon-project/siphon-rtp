//! `lib_com/hq_conf_fx.c` against `fn_hq_conf`: every length / class / rate combination, with the
//! outputs preset to a sentinel so the reference's unset outputs are compared too.

use std::ptr::eq;

use siphon_rtp_codec::evs::com::hq_conf::hq_configure;
use siphon_rtp_codec::evs::rom::{
    BAND_END_HARM, BAND_END_HQ, BAND_END_WB, BAND_LEN_HARM, BAND_LEN_HQ, BAND_LEN_WB,
    BAND_START_HARM, BAND_START_HQ, BAND_START_WB,
};

use crate::common::{corpus, mismatch};

/// 1 = HQ table, 2 = harmonic, 3 = WB, -1 = none (the sentinel).
fn id(slice: &[i16], hq: &[i16], harm: &[i16], wb: &[i16]) -> i16 {
    if eq(slice.as_ptr(), hq.as_ptr()) {
        1
    } else if eq(slice.as_ptr(), harm.as_ptr()) {
        2
    } else if eq(slice.as_ptr(), wb.as_ptr()) {
        3
    } else {
        -1
    }
}

#[test]
fn hq_configure_matches_the_reference() {
    let Some(cases) = corpus("hq_conf", "hq_configure") else {
        return;
    };
    let mut seen = std::collections::BTreeSet::new();
    for case in &cases {
        let (mut num_sfm, mut nb_sfm, mut start_norm, mut num_env_bands) = (-7, -7, -7, -7);
        let (mut numnrmibits, mut offset) = (-7, -7);
        let mut sfmsize: &'static [i16] = &[];
        let mut sfm_start: &'static [i16] = &[];
        let mut sfm_end: &'static [i16] = &[];
        hq_configure(
            case.i16("length"),
            case.i16("clas"),
            case.i32("brate"),
            &mut num_sfm,
            &mut nb_sfm,
            &mut start_norm,
            &mut num_env_bands,
            &mut numnrmibits,
            &mut offset,
            &mut sfmsize,
            &mut sfm_start,
            &mut sfm_end,
        );
        let got = vec![
            num_sfm,
            nb_sfm,
            start_norm,
            num_env_bands,
            numnrmibits,
            offset,
            id(sfmsize, &BAND_LEN_HQ, &BAND_LEN_HARM, &BAND_LEN_WB),
            id(sfm_start, &BAND_START_HQ, &BAND_START_HARM, &BAND_START_WB),
            id(sfm_end, &BAND_END_HQ, &BAND_END_HARM, &BAND_END_WB),
        ];
        let want = vec![
            case.out_i16("num_sfm"),
            case.out_i16("nb_sfm"),
            case.out_i16("start_norm"),
            case.out_i16("num_env_bands"),
            case.out_i16("numnrmibits"),
            case.out_i16("offset"),
            case.out_i16("sfmsize"),
            case.out_i16("sfm_start"),
            case.out_i16("sfm_end"),
        ];
        if let Some(message) = mismatch(case, "outputs", &got, &want) {
            panic!("{message}");
        }
        seen.insert((case.i16("length"), case.i16("clas"), case.i32("brate")));
    }
    assert!(seen.len() > 100, "only {} combinations", seen.len());
}
