//! `lib_com/fft_rel_fx.c` against `fn_fft_rel`. `c_fft_fx` is static in the reference and is
//! proven through `r_fft_fx_lc`, which runs it in both directions.

use siphon_rtp_codec::evs::com::fft_rel::{r_fft_fx_lc, r_fft_fx_lc_in_place};
use siphon_rtp_codec::evs::rom::{FFT_W128, FFT_W256, FFT_W64, PHS_TBL_DEC};

use crate::common::{corpus, mismatch};

#[test]
fn r_fft_fx_lc_matches_the_reference() {
    let Some(cases) = corpus("fft_rel", "r_fft_fx_lc") else {
        return;
    };
    for case in &cases {
        let size = case.i16("size");
        let table: &[i16] = match size {
            64 => &PHS_TBL_DEC,
            128 => &FFT_W64,
            256 => &FFT_W128,
            _ => &FFT_W256,
        };
        let input = case.i16s("in");
        let (stages, isign) = (case.i16("stages"), case.i16("isign"));
        let out = if case.i16("inplace") == 1 {
            let mut x = input.clone();
            r_fft_fx_lc_in_place(table, size, size / 2, stages, &mut x, isign);
            x
        } else {
            let mut out = vec![0; input.len()];
            r_fft_fx_lc(table, size, size / 2, stages, &input, &mut out, isign);
            out
        };
        if let Some(message) = mismatch(case, "out", &out, &case.out_i16s("out")) {
            panic!("{message}");
        }
    }
}
