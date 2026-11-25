//! MODE2 leftovers of `lib_com/basop_util.c` and `lib_com/tools_fx.c` against `fn_m2lpc_basop`.

use siphon_rtp_codec::evs::com::basop_util::*;
use siphon_rtp_codec::evs::com::tools::{dot_prod_satcontr, exp32_array, invert16};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("m2lpc_basop", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

#[test]
fn sqrt16norm_matches_the_reference() {
    each("sqrt16norm", |case| {
        let mut e = case.i16("e");
        let r = sqrt16norm(case.i16("m"), &mut e);
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn isqrt16_matches_the_reference() {
    each("isqrt16", |case| {
        let mut e = case.i16("e");
        let r = isqrt16(case.i16("m"), &mut e);
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn sqrt32norm_matches_the_reference() {
    each("sqrt32norm", |case| {
        let mut e = case.i16("e");
        let r = sqrt32norm(case.i32("m"), &mut e);
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn isqrt32norm_matches_the_reference() {
    each("isqrt32norm", |case| {
        let mut e = case.i16("e");
        let r = isqrt32norm(case.i32("m"), &mut e);
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn sqrt_inv_sqrt_mant_exp_matches_the_reference() {
    each("sqrt_invsqrt", |case| {
        let (mut sm, mut se, mut im, mut ie) = (0, 0, 0, 0);
        basop_util_sqrt_inv_sqrt_mant_exp(
            case.i16("m"),
            case.i16("e"),
            &mut sm,
            &mut se,
            &mut im,
            &mut ie,
        );
        check(case, "sm", &sm, &case.out_i16("sm"));
        check(case, "se", &se, &case.out_i16("se"));
        check(case, "im", &im, &case.out_i16("im"));
        check(case, "ie", &ie, &case.out_i16("ie"));
    });
}

#[test]
fn get_cos_word16_matches_the_reference() {
    each("get_cos", |case| {
        check(
            case,
            "r",
            &get_cos_word16(case.i16("t")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn imult3216_matches_the_reference() {
    each("imult3216", |case| {
        check(
            case,
            "r",
            &imult3216(case.i32("x"), case.i16("y")),
            &case.out_i32("r"),
        );
    });
}

#[test]
fn norm32_norm_matches_the_reference() {
    each("norm32norm", |case| {
        let mut e = 0;
        let r = norm32_norm(
            &case.i32s("x"),
            case.i16("headroom"),
            case.i16("length"),
            &mut e,
        );
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn get_norm_reciprocal_word16_scale_matches_the_reference() {
    each("norm_reciprocal_scale", |case| {
        check(
            case,
            "r",
            &get_norm_reciprocal_word16_scale(case.i16("x"), case.i16("s")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn f_pow_matches_the_reference() {
    each("fpow", |case| {
        let mut e = 0;
        let r = basop_util_f_pow(
            case.i32("base_m"),
            case.i16("base_e"),
            case.i32("exp_m"),
            case.i16("exp_e"),
            &mut e,
        );
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn dot_product12_offs_matches_the_reference() {
    each("dot12", |case| {
        let mut e = -99;
        let with_exp = case.i32("with_exp") != 0;
        let r = dot_product12_offs(
            &case.i16s("x"),
            &case.i16s("y"),
            case.i16("lg"),
            with_exp.then_some(&mut e),
            case.i32("off"),
        );
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn dot_product15_offs_matches_the_reference() {
    each("dot15", |case| {
        let mut e = 0;
        let r = dot_product15_offs(
            &case.i16s("x"),
            &case.i16s("y"),
            case.i16("lg"),
            &mut e,
            case.i32("off"),
        );
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "e", &e, &case.out_i16("e"));
    });
}

#[test]
fn buffer_copy_fx_matches_the_reference() {
    each("buffer_copy", |case| {
        let length = case.i16("length");
        let src = case.i16s("src");
        let mut dest = vec![77i16; usize::try_from(length).unwrap() + 1];
        buffer_copy_fx(
            &src,
            &mut dest,
            length,
            case.i16("qf_src"),
            case.i16("qf_dest"),
            case.i16("q_src"),
            case.i16("q_dest"),
        );
        check(case, "dest", &dest, &case.out_i16s("dest"));
    });
}

#[test]
fn atan_matches_the_reference() {
    each("atan", |case| {
        check(
            case,
            "r",
            &basop_util_atan(case.i32("x")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn atan2_matches_the_reference() {
    each("atan2", |case| {
        check(
            case,
            "r",
            &basop_util_atan2(case.i32("y"), case.i32("x"), case.i16("e")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn comp_mant_exp16_unorm_matches_the_reference() {
    each("comp_mant_exp", |case| {
        check(
            case,
            "r",
            &comp_mant_exp16_unorm(
                case.i16("m1"),
                case.i16("e1"),
                case.i16("m2"),
                case.i16("e2"),
            ),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn exp32_array_matches_the_reference() {
    each("exp32array", |case| {
        check(
            case,
            "r",
            &exp32_array(case.i16("n"), &case.i32s("sx")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn invert16_matches_the_reference() {
    each("invert16", |case| {
        let mut exp = case.i16("exp");
        let r = invert16(case.i16("val"), &mut exp);
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "exp", &exp, &case.out_i16("exp"));
    });
}

#[test]
fn dot_prod_satcontr_matches_the_reference() {
    each("dot_prod_satcontr", |case| {
        let mut qo = -99;
        let r = dot_prod_satcontr(
            &case.i16s("x"),
            &case.i16s("y"),
            case.i16("qx"),
            case.i16("qy"),
            &mut qo,
            case.i16("len"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "qo", &qo, &case.out_i16("qo"));
    });
}
