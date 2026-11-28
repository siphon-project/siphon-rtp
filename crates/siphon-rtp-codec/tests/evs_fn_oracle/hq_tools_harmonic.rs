//! The harmonic and HVQ bandwidth extensions of `lib_com/hq_tools_fx.c` against
//! `fn_hq_tools_harmonic`: harmonic layouts of 31 / 33 bands at 24.4 and 32 kbit/s, spectra from
//! silent to full scale, fine structures from the `*_fine` functions or random.

use siphon_rtp_codec::evs::com::hq_tools::{
    harm_bwe, harm_bwe_fine, hq_swb_harmonic_calc_norm_envelop, hvq_bwe, hvq_bwe_fine, noise_mix,
};
use siphon_rtp_codec::evs::rom::{BAND_END_HARM, BAND_LEN_HARM, BAND_START_HARM};

use crate::common::{corpus, mismatch};

fn report(messages: impl IntoIterator<Item = Option<String>>) {
    if let Some(message) = messages.into_iter().flatten().next() {
        panic!("{message}");
    }
}

#[test]
fn hq_swb_harmonic_calc_norm_envelop_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_harmonic", "hq_swb_harmonic_calc_norm_envelop") else {
        return;
    };
    for case in &cases {
        let sig = case.i32s("sig");
        let mut env = vec![-7i32; 960];
        hq_swb_harmonic_calc_norm_envelop(&sig, &mut env, case.i16("norm"), case.i16("len"));
        env.truncate(sig.len());
        report([mismatch(case, "env", &env, &case.out_i32s("env"))]);
    }
}

#[test]
fn harm_bwe_fine_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_harmonic", "harm_bwe_fine") else {
        return;
    };
    for case in &cases {
        let mut prev = case.i16("prev");
        let mut out = case.i32s("out");
        let mut fine = vec![-7i16; 960];
        harm_bwe_fine(
            &case.i16s("r"),
            case.i16("last_sfm"),
            case.i16("high_sfm"),
            case.i16("num_sfm"),
            &case.i16s("norm"),
            &BAND_START_HARM,
            &BAND_END_HARM,
            &mut prev,
            &case.i16s("coeff"),
            &mut out,
            &mut fine,
        );
        report([
            mismatch(case, "prev", &prev, &case.out_i16("prev")),
            mismatch(case, "out", &out, &case.out_i32s("out")),
            mismatch(case, "fine", &fine, &case.out_i16s("fine")),
        ]);
    }
}

#[test]
fn hvq_bwe_fine_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_harmonic", "hvq_bwe_fine") else {
        return;
    };
    for case in &cases {
        let mut prev = case.i16("prev");
        let mut peak_pos = vec![0i16; 202];
        let mut bwe_peaks = vec![0i16; 960];
        let mut fine = vec![-7i16; 960];
        hvq_bwe_fine(
            case.i16("last_sfm"),
            case.i16("num_sfm"),
            &BAND_END_HARM,
            &case.i16s("peak_idx"),
            case.i16("npeaks"),
            &mut peak_pos,
            &mut prev,
            &case.i32s("x"),
            &mut bwe_peaks,
            &mut fine,
        );
        report([
            mismatch(case, "prev", &prev, &case.out_i16("prev")),
            mismatch(case, "peak_pos", &peak_pos, &case.out_i16s("peak_pos")),
            mismatch(case, "bwe_peaks", &bwe_peaks, &case.out_i16s("bwe_peaks")),
            mismatch(case, "fine", &fine, &case.out_i16s("fine")),
        ]);
    }
}

#[test]
fn harm_bwe_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_harmonic", "harm_bwe") else {
        return;
    };
    for case in &cases {
        let mut nl = case.i16s("nl");
        let mut pnl = case.i16s("pnl");
        let mut seed = case.i16("seed");
        let mut out = case.i32s("out");
        harm_bwe(
            &case.i16s("fine"),
            &case.i16s("coeff"),
            case.i16("num_sfm"),
            &BAND_START_HARM,
            &BAND_END_HARM,
            case.i16("last_sfm"),
            &case.i16s("r"),
            case.i16("prev_mode"),
            &case.i16s("norm"),
            &mut nl,
            &mut pnl,
            &mut seed,
            &mut out,
        );
        report([
            mismatch(case, "nl", &nl, &case.out_i16s("nl")),
            mismatch(case, "pnl", &pnl, &case.out_i16s("pnl")),
            mismatch(case, "seed", &seed, &case.out_i16("seed")),
            mismatch(case, "out", &out, &case.out_i32s("out")),
        ]);
    }
}

#[test]
fn hvq_bwe_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_harmonic", "hvq_bwe") else {
        return;
    };
    for case in &cases {
        let mut norm = case.i16s("norm");
        let mut nl = case.i16s("nl");
        let mut pnl = case.i16s("pnl");
        let mut seed = case.i16("seed");
        let mut out = case.i32s("out");
        hvq_bwe(
            &case.i16s("fine"),
            &BAND_START_HARM,
            &BAND_END_HARM,
            &BAND_LEN_HARM,
            case.i16("last_sfm"),
            case.i16("prev_mode"),
            &case.i16s("bwe_peaks"),
            case.i16("bin_th"),
            case.i16("num_sfm"),
            case.i32("core_brate"),
            &case.i16s("r"),
            &mut norm,
            &mut nl,
            &mut pnl,
            &mut seed,
            &mut out,
            15,
            12,
        );
        report([
            mismatch(case, "norm", &norm, &case.out_i16s("norm")),
            mismatch(case, "nl", &nl, &case.out_i16s("nl")),
            mismatch(case, "pnl", &pnl, &case.out_i16s("pnl")),
            mismatch(case, "seed", &seed, &case.out_i16("seed")),
            mismatch(case, "out", &out, &case.out_i32s("out")),
        ]);
    }
}

#[test]
fn noise_mix_matches_the_reference() {
    let Some(cases) = corpus("hq_tools_harmonic", "noise_mix") else {
        return;
    };
    for case in &cases {
        let mut seed = case.i16("seed");
        let mut out = case.i32s("out");
        noise_mix(
            &case.i16s("fine"),
            -isize::from(case.i16("offset")),
            case.i32("l_e"),
            case.i32("normq"),
            &mut seed,
            case.i16("istart"),
            case.i16("iend"),
            case.i16("nl"),
            &mut out,
            15,
            12,
        );
        report([
            mismatch(case, "seed", &seed, &case.out_i16("seed")),
            mismatch(case, "out", &out, &case.out_i32s("out")),
        ]);
    }
}
