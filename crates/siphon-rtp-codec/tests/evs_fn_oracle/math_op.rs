//! `basic_math/math_op.c` against `fn_math_op`.

use siphon_rtp_codec::evs::com::math_op::{
    dot_product12, energy_scale, frac_sqrt, i_mult2, isqrt, isqrt_lc, l_frac_sqrt_q31, pow2, sqrt_l,
};

use crate::common::{corpus, mismatch};

fn check<T: PartialEq + std::fmt::Debug>(
    case: &crate::common::Case,
    name: &str,
    rust: T,
    reference: T,
) {
    if let Some(message) = mismatch(case, name, &rust, &reference) {
        panic!("{message}");
    }
}

#[test]
fn isqrt_matches_the_reference() {
    let Some(cases) = corpus("math_op", "isqrt") else {
        return;
    };
    for case in &cases {
        check(case, "y", isqrt(case.i32("x")), case.out_i32("y"));
    }
}

#[test]
fn isqrt_lc_matches_the_reference() {
    let Some(cases) = corpus("math_op", "isqrt_lc") else {
        return;
    };
    for case in &cases {
        let mut exp = case.i16("exp");
        let y = isqrt_lc(case.i32("frac"), &mut exp);
        check(case, "y", y, case.out_i32("y"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn pow2_matches_the_reference() {
    let Some(cases) = corpus("math_op", "pow2") else {
        return;
    };
    for case in &cases {
        let y = pow2(case.i16("exponant"), case.i16("fraction"));
        check(case, "y", y, case.out_i32("y"));
    }
}

#[test]
fn dot_product12_matches_the_reference() {
    let Some(cases) = corpus("math_op", "dot_product12") else {
        return;
    };
    for case in &cases {
        let mut exp = 0;
        let sum = dot_product12(&case.i16s("x"), &case.i16s("y"), case.i16("lg"), &mut exp);
        check(case, "sum", sum, case.out_i32("sum"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn sqrt_l_matches_the_reference() {
    let Some(cases) = corpus("math_op", "sqrt_l") else {
        return;
    };
    for case in &cases {
        let mut exp = 7;
        let y = sqrt_l(case.i32("x"), &mut exp);
        check(case, "y", y, case.out_i32("y"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn l_frac_sqrt_q31_matches_the_reference() {
    let Some(cases) = corpus("math_op", "l_frac_sqrt_q31") else {
        return;
    };
    for case in &cases {
        check(case, "y", l_frac_sqrt_q31(case.i32("x")), case.out_i32("y"));
    }
}

#[test]
fn frac_sqrt_matches_the_reference() {
    let Some(cases) = corpus("math_op", "frac_sqrt") else {
        return;
    };
    for case in &cases {
        check(case, "y", frac_sqrt(case.i16("x")), case.out_i16("y"));
    }
}

#[test]
fn i_mult2_matches_the_reference() {
    let Some(cases) = corpus("math_op", "i_mult2") else {
        return;
    };
    for case in &cases {
        check(
            case,
            "y",
            i_mult2(case.i16("a"), case.i16("b")),
            case.out_i16("y"),
        );
    }
}

#[test]
fn energy_scale_matches_the_reference() {
    let Some(cases) = corpus("math_op", "energy_scale") else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let mut exp = 0;
        let r = energy_scale(&x, x.len() as i16, case.i16("expi"), &mut exp);
        check(case, "r", r, case.out_i32("r"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}
