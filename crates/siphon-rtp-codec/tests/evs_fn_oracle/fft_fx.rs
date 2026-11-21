//! The 16-bit FFTs of `lib_com/fft_fx.c` against `fn_fft_fx`.
//!
//! `bitrv2_SR_16fx`, `cftfsub_16fx`, `cft1st_16fx` and `cftmdl_16fx` are proven through
//! `cdftForw_16fx` at every length the decoder uses (64, 128 and 256).

use siphon_rtp_codec::evs::com::fft_fx::*;
use siphon_rtp_codec::evs::rom::{
    IDX_DORTFT160, IDX_DORTFT320_16FX, IP_FFT128_16FX, IP_FFT32_16FX, IP_FFT64_16FX, W_FFT128_16FX,
    W_FFT32_16FX, W_FFT64_16FX,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("fft_fx", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

fn check_xy(case: &Case, x: &[i16], y: &[i16]) {
    check(case, "x", &x.to_vec(), &case.out_i16s("x"));
    check(case, "y", &y.to_vec(), &case.out_i16s("y"));
}

#[test]
fn do_rtft128_matches_the_reference() {
    each("do_rtft128", |case| {
        let (mut x, mut y) = (case.i16s("x"), case.i16s("y"));
        do_rtft128_16fx(&mut x, &mut y);
        check_xy(case, &x, &y);
    });
}

#[test]
fn do_rtft320_matches_the_reference() {
    each("do_rtft320", |case| {
        let (mut x, mut y) = (case.i16s("x"), case.i16s("y"));
        do_rtft320_16fx(&mut x, &mut y);
        check_xy(case, &x, &y);
    });
}

#[test]
fn cdft_forw_matches_the_reference() {
    each("cdft_forw", |case| {
        let n = case.i16("n");
        let mut a = case.i16s("a");
        match n {
            256 => cdft_forw_16fx(n, &mut a, &IP_FFT128_16FX, &W_FFT128_16FX),
            128 => cdft_forw_16fx(n, &mut a, &IP_FFT64_16FX, &W_FFT64_16FX),
            _ => cdft_forw_16fx(n, &mut a, &IP_FFT32_16FX, &W_FFT32_16FX),
        }
        check(case, "a", &a, &case.out_i16s("a"));
    });
}

#[test]
fn fft64_matches_the_reference() {
    each("fft64", |case| {
        let (mut x, mut y) = (case.i16s("x"), case.i16s("y"));
        let j = case.i16("j") as usize;
        fft64_16fx(&mut x, &mut y, &IDX_DORTFT320_16FX[64 * j..]);
        check_xy(case, &x, &y);
    });
}

#[test]
fn fft5_shift4_matches_the_reference() {
    each("fft5_shift4", |case| {
        let (mut x, mut y) = (case.i16s("x"), case.i16s("y"));
        let j = case.i16("j") as usize;
        fft5_shift4_16fx(64, &mut x, &mut y, &IDX_DORTFT320_16FX[j..]);
        check_xy(case, &x, &y);
    });
}

#[test]
fn do_rtft160_matches_the_reference() {
    each("do_rtft160", |case| {
        let (mut x, mut y) = (case.i16s("x"), case.i16s("y"));
        do_rtft160_16fx(&mut x, &mut y);
        check_xy(case, &x, &y);
    });
}

#[test]
fn fft32_5_matches_the_reference() {
    each("fft32_5", |case| {
        let (mut x, mut y) = (case.i16s("x"), case.i16s("y"));
        let j = case.i16("j") as usize;
        fft32_5_16fx(&mut x, &mut y, &IDX_DORTFT160[32 * j..]);
        check_xy(case, &x, &y);
    });
}

#[test]
fn fft5_32_matches_the_reference() {
    each("fft5_32", |case| {
        let (mut x, mut y) = (case.i16s("x"), case.i16s("y"));
        let j = case.i16("j") as usize;
        fft5_32_16fx(&mut x, &mut y, &IDX_DORTFT160[j..]);
        check_xy(case, &x, &y);
    });
}

/// `edct2_fx` at length 64 in both directions; proves the 32-bit split-radix kernels
/// (`bitrv2_SR_fx`, `cftfsub_fx`, `cftbsub_fx`, `cft1st_fx`, `cftmdl_fx`, `rftfsub_fx`,
/// `rftbsub_fx`, `dctsub_fx`) through it.
#[test]
fn edct2_matches_the_reference() {
    use siphon_rtp_codec::evs::rom::{IP_EDCT2_64_FX, W_EDCT2_64_FX};
    each("edct2", |case| {
        let input = case.i16s("in");
        let mut a = [0_i32; 64];
        let mut q = 0;
        edct2(
            64,
            case.i16("isgn"),
            &input,
            &mut a,
            &mut q,
            &IP_EDCT2_64_FX,
            &W_EDCT2_64_FX,
        );
        check(case, "a", &a.to_vec(), &case.out_i32s("a"));
        check(case, "q", &q, &case.out_i16("q"));
    });
}

#[test]
fn fft3_matches_the_reference() {
    each("fft3", |case| {
        let mut x = case.i16s("x");
        fft3(&mut x, case.i16("n"));
        check(case, "x", &x, &case.out_i16s("x"));
    });
}

#[test]
fn ifft3_matches_the_reference() {
    each("ifft3", |case| {
        let mut x = case.i16s("x");
        ifft3(&mut x, case.i16("n"));
        check(case, "x", &x, &case.out_i16s("x"));
    });
}

/// `DoRTFTn_fx`, which also proves `cdftForw_fx` (and the 32-bit split-radix kernels under it)
/// at every length from 16 to 512.
#[test]
fn do_rtftn_matches_the_reference() {
    each("do_rtftn", |case| {
        let (mut x, mut y) = (case.i32s("x"), case.i32s("y"));
        do_rtftn(&mut x, &mut y, case.i16("n"));
        check(case, "x", &x, &case.out_i32s("x"));
        check(case, "y", &y, &case.out_i32s("y"));
    });
}
