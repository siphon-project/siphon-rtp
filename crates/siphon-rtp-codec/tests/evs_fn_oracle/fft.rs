//! `lib_com/fft.c` against `fn_fft`. The static kernels (`fft5` .. `fft32`) and `fftN2` are proven
//! through `BASOP_cfft`, whose corpus covers every length it dispatches (each kernel directly, and
//! each composite length through `fftN2`), at stride 1 on split arrays and stride 2 interleaved.

use siphon_rtp_codec::evs::com::fft::{
    basop_cfft, basop_rfft, fft16, Interleaved, Split, BASOP_CFFT_WORK_LENGTH,
};

use crate::common::{corpus, mismatch};

fn check<T: PartialEq + std::fmt::Debug>(
    case: &crate::common::Case,
    name: &str,
    rust: &T,
    reference: &T,
) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn basop_cfft_matches_the_reference() {
    let Some(cases) = corpus("fft", "basop_cfft") else {
        return;
    };
    let mut work = [0i32; BASOP_CFFT_WORK_LENGTH];
    for case in &cases {
        let size = case.i16("size");
        let mut scale = case.i16("scale");
        let (mut re, mut im) = (case.i32s("re"), case.i32s("im"));
        if case.i16("stride") == 1 {
            let mut data = Split {
                re: &mut re,
                im: &mut im,
            };
            basop_cfft(&mut data, size, 1, &mut scale, &mut work);
        } else {
            let mut data: Vec<i32> = re.iter().zip(&im).flat_map(|(&r, &i)| [r, i]).collect();
            basop_cfft(
                &mut Interleaved {
                    data: &mut data,
                    at: 0,
                },
                size,
                2,
                &mut scale,
                &mut work,
            );
            re = data.iter().step_by(2).copied().collect();
            im = data.iter().skip(1).step_by(2).copied().collect();
        }
        check(case, "re", &re, &case.out_i32s("re"));
        check(case, "im", &im, &case.out_i32s("im"));
        check(case, "scale", &scale, &case.out_i16("scale"));
    }
}

#[test]
fn fft16_matches_the_reference() {
    let Some(cases) = corpus("fft", "fft16") else {
        return;
    };
    for case in &cases {
        let (mut re, mut im) = (case.i32s("re"), case.i32s("im"));
        fft16(
            &mut Split {
                re: &mut re,
                im: &mut im,
            },
            1,
            case.i16("bscale"),
        );
        check(case, "re", &re, &case.out_i32s("re"));
        check(case, "im", &im, &case.out_i32s("im"));
    }
}

#[test]
fn basop_rfft_matches_the_reference() {
    let Some(cases) = corpus("fft", "basop_rfft") else {
        return;
    };
    for case in &cases {
        let mut x = case.i32s("x");
        let mut scale = case.i16("scale");
        basop_rfft(&mut x, case.i16("size"), &mut scale, case.i16("isign"));
        check(case, "x", &x, &case.out_i32s("x"));
        check(case, "scale", &scale, &case.out_i16("scale"));
    }
}
