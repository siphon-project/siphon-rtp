//! `lib_dec/arith_coder_dec.c` (`tcx_arith_decode`) against `fn_m2arith_arith_dec`.

use siphon_rtp_codec::evs::dec::arith_coder_dec::tcx_arith_decode;
use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus_sized, mismatch};

/// Spectra decoded against random envelopes (bases 0.05 to 0.9), parameter bits and budgets,
/// with a random incoming `Carry` and the occasional zero envelope line (the bit-error exit).
#[test]
fn tcx_arith_decode_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_arith_dec", "tcx_arith_decode", 3000) else {
        return;
    };
    let (mut errors, mut nonzero) = (0, 0);
    for case in &cases {
        let l_frame = case.i16("l_frame");
        let mut q_spectrum = case.i32s("q_in");
        let mut q_spectrum_e = 77;
        let mut nf_seed = 77;
        let mut flags = StlFlags {
            overflow: false,
            carry: case.i16("carry") != 0,
        };
        let bits = tcx_arith_decode(
            l_frame,
            &case.i16s("envelope"),
            case.i16("envelope_e"),
            case.i16("target_bits"),
            &case.i16s("prm"),
            &mut q_spectrum,
            &mut q_spectrum_e,
            &mut nf_seed,
            &mut flags,
        );
        errors += usize::from(bits < 0);
        nonzero += q_spectrum.iter().filter(|&&q| q != 0).count();
        for (name, rust, reference) in [
            ("bits", bits, case.out_i16("bits")),
            ("q_e", q_spectrum_e, case.out_i16("q_e")),
            ("seed", nf_seed, case.out_i16("seed")),
            ("carry", i16::from(flags.carry), case.out_i16("carry")),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &reference) {
                panic!("{message}");
            }
        }
        if let Some(message) = mismatch(case, "q", &q_spectrum, &case.out_i32s("q")) {
            panic!("{message}");
        }
    }
    assert!(errors > 0, "no case reached the bit-error exit");
    assert!(nonzero > 1000, "too few non-zero lines: {nonzero}");
}
