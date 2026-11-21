//! `lib_com/nelp_fx.c` (`dequantize_uvg_fx`, `generate_nelp_excitation_fx`) against `fn_nelp`.

use siphon_rtp_codec::evs::com::nelp::{dequantize_uvg, generate_nelp_excitation};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn dequantize_uvg_matches_the_reference() {
    let Some(cases) = corpus("nelp", "dequantize_uvg") else {
        return;
    };
    for case in &cases {
        let mut g = vec![-7i16; 10];
        let q = dequantize_uvg(
            case.i16("i_g1"),
            &case.i16s("i_g2"),
            &mut g,
            case.i16("bwidth"),
            case.i16("do_scale"),
        );
        check(case, "q", &q, &case.out_i16("q"));
        check(case, "g", &g, &case.out_i16s("g"));
    }
}

#[test]
fn generate_nelp_excitation_matches_the_reference() {
    let Some(cases) = corpus("nelp", "generate_nelp_excitation") else {
        return;
    };
    for case in &cases {
        let mut seed = case.i16("seed");
        let mut output = vec![-3i16; 256];
        generate_nelp_excitation(
            &mut seed,
            &case.i16s("gains"),
            &mut output,
            case.i16("gain_fac"),
        );
        check(case, "seed", &seed, &case.out_i16("seed"));
        check(case, "output", &output, &case.out_i16s("output"));
    }
}
