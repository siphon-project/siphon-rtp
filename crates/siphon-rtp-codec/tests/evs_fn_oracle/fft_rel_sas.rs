//! `lib_com/fft_rel_sas_fx.c` against `fn_fft_rel_sas`.

use siphon_rtp_codec::evs::com::fft_rel_sas::{fft_rel, ifft_rel};

use crate::common::{corpus, mismatch};

fn replay(function: &str) {
    let Some(cases) = corpus("fft_rel_sas", function) else {
        return;
    };
    for case in &cases {
        let mut x = case.i16s("x");
        let (n, m) = (case.i16("n"), case.i16("m"));
        if function == "fft_rel" {
            fft_rel(&mut x, n, m);
        } else {
            ifft_rel(&mut x, n, m);
        }
        if let Some(message) = mismatch(case, "x", &x, &case.out_i16s("x")) {
            panic!("{message}");
        }
    }
}

#[test]
fn fft_rel_matches_the_reference() {
    replay("fft_rel");
}

#[test]
fn ifft_rel_matches_the_reference() {
    replay("ifft_rel");
}
