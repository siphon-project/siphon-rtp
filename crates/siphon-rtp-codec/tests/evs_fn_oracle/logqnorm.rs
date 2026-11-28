//! `lib_com/logqnorm_fx.c` against `fn_logqnorm`.

use siphon_rtp_codec::evs::com::logqnorm::{calc_norm, logqnorm, logqnorm_2};
use siphon_rtp_codec::evs::rom::{BAND_LEN_HQ, BAND_START_HQ};

use crate::common::{corpus, mismatch};

#[test]
fn logqnorm_matches_the_reference() {
    let Some(cases) = corpus("logqnorm", "logqnorm") else {
        return;
    };
    for case in &cases {
        let k = logqnorm(
            &case.i32s("x"),
            case.i16("qx"),
            case.i16("l"),
            case.i16("n"),
            case.i16("hvq"),
        );
        if let Some(message) = mismatch(case, "k", &k, &case.out_i16("k")) {
            panic!("{message}");
        }
    }
}

#[test]
fn logqnorm_2_matches_the_reference() {
    let Some(cases) = corpus("logqnorm", "logqnorm_2") else {
        return;
    };
    for case in &cases {
        let n = (case.i16("nb") - case.i16("n_env")) as usize;
        let mut ynrm = vec![-7i16; 44];
        let mut normqlg2 = vec![-7i16; 44];
        logqnorm_2(
            &case.i32s("env"),
            case.i16("l"),
            case.i16("n_env"),
            case.i16("nb"),
            &mut ynrm,
            &mut normqlg2,
            &case.i32s("thren"),
        );
        for (name, got) in [("ynrm", &ynrm), ("normqlg2", &normqlg2)] {
            if let Some(message) = mismatch(case, name, &got[..n].to_vec(), &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}

#[test]
fn calc_norm_matches_the_reference() {
    let Some(cases) = corpus("logqnorm", "calc_norm") else {
        return;
    };
    for case in &cases {
        let (start, num) = (case.i16("start") as usize, case.i16("num") as usize);
        let mut norm = vec![-7i16; 44];
        let mut normlg = vec![-7i16; 44];
        calc_norm(
            &case.i32s("x"),
            case.i16("qx"),
            &mut norm,
            &mut normlg,
            start as i16,
            num as i16,
            &BAND_LEN_HQ,
            &BAND_START_HQ,
        );
        if let Some(message) = mismatch(
            case,
            "norm",
            &norm[..start + num].to_vec(),
            &case.out_i16s("norm"),
        ) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(
            case,
            "normlg",
            &normlg[start..start + num].to_vec(),
            &case.out_i16s("normlg"),
        ) {
            panic!("{message}");
        }
    }
}
