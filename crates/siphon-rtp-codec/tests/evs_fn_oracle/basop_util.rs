//! `lib_com/basop_util.c` against `fn_basop_util`.
//!
//! `Sqrt32_common` is proven through `Sqrt32`, `ISqrt32_common` through `ISqrt32`, `fixp_sin_cos_residual_16` both directly and through
//! `getCosWord16R2`, and `norm_llQ31` both directly and through `Dot_productSq16HQ`. `set_zero_Word8`
//! has no arithmetic and is covered by a unit test.

use siphon_rtp_codec::evs::com::basop_util::*;
use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("basop_util", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

#[test]
fn log2_matches_the_reference() {
    each("log2", |case| {
        check(
            case,
            "r",
            &basop_util_log2(case.i32("x")),
            &case.out_i32("r"),
        );
    });
}

#[test]
fn inv_log2_matches_the_reference() {
    each("inv_log2", |case| {
        check(
            case,
            "r",
            &basop_util_inv_log2(case.i32("x")),
            &case.out_i32("r"),
        );
    });
}

#[test]
fn divide_mant_exp_matches_the_reference() {
    each("divide_mant_exp", |case| {
        let (mut m, mut e) = (0, 0);
        basop_util_divide_mant_exp(
            case.i16("a_m"),
            case.i16("a_e"),
            case.i16("b_m"),
            case.i16("b_e"),
            &mut m,
            &mut e,
        );
        check(
            case,
            "m/e",
            &(m, e),
            &(case.out_i16("m"), case.out_i16("e")),
        );
    });
}

#[test]
fn sqrt32_matches_the_reference() {
    each("sqrt32", |case| {
        let mut exponent = case.i16("exponent");
        let mantissa = sqrt32(case.i32("mantissa"), &mut exponent);
        check(
            case,
            "mantissa/exponent",
            &(mantissa, exponent),
            &(case.out_i32("mantissa"), case.out_i16("exponent")),
        );
    });
}

#[test]
fn get_scale_factor_matches_the_reference() {
    each("get_scale_factor", |case| {
        let len = case.i16("len");
        check(
            case,
            "s16",
            &get_scale_factor16(&case.i16s("x16"), len),
            &case.out_i16("s16"),
        );
        check(
            case,
            "s32",
            &get_scale_factor32(&case.i32s("x32"), len),
            &case.out_i16("s32"),
        );
    });
}

#[test]
fn divisions_match_the_reference() {
    each("divide3232_uu_1616", |case| {
        let mut s = 0;
        let z = basop_util_divide3232_uu_1616_scale(case.i32("x"), case.i32("y"), &mut s);
        check(
            case,
            "z/s",
            &(z, s),
            &(case.out_i16("z"), case.out_i16("s")),
        );
    });
    each("divide3232", |case| {
        let mut s = 0;
        let z = basop_util_divide3232_scale(case.i32("x"), case.i32("y"), &mut s);
        check(
            case,
            "z/s",
            &(z, s),
            &(case.out_i16("z"), case.out_i16("s")),
        );
    });
    each("divide3216", |case| {
        let mut s = 0;
        let z = basop_util_divide3216_scale(case.i32("x"), case.i16("y"), &mut s);
        check(
            case,
            "z/s",
            &(z, s),
            &(case.out_i16("z"), case.out_i16("s")),
        );
    });
}

#[test]
fn sin_cos_residual_and_cos_r2_match_the_reference() {
    each("sin_cos", |case| {
        let x = case.i16("x");
        let (mut sine, mut cosine) = (0, 0);
        let residual = fixp_sin_cos_residual_16(
            x,
            case.i16("scale"),
            &mut sine,
            &mut cosine,
            case.i16("flag") as i8,
        );
        check(
            case,
            "residual/sine/cosine/cos_r2",
            &(residual, sine, cosine, get_cos_word16_r2(x)),
            &(
                case.out_i16("residual"),
                case.out_i16("sine"),
                case.out_i16("cosine"),
                case.out_i16("cos_r2"),
            ),
        );
    });
}

#[test]
fn idiv1616_and_imult1616_match_the_reference() {
    each("integer", |case| {
        check(
            case,
            "quotient/product",
            &(
                idiv1616(case.i16("x"), case.i16("y")),
                imult1616(case.i16("a"), case.i16("b")),
            ),
            &(case.out_i16("quotient"), case.out_i16("product")),
        );
    });
}

#[test]
fn norm_ll_q31_matches_the_reference() {
    each("norm_llq31", |case| {
        let mut flags = StlFlags::default();
        let mut exp = 0;
        let r = norm_ll_q31(case.i32("l_c"), case.i32("l_sum"), &mut exp, &mut flags);
        check(
            case,
            "r/exp/carry",
            &(r, exp, i16::from(flags.carry)),
            &(
                case.out_i32("r"),
                case.out_i16("exp"),
                case.out_i16("carry"),
            ),
        );
    });
}

#[test]
fn dot_product_sq16_hq_matches_the_reference() {
    each("dot_product_sq16_hq", |case| {
        // The oracle randomises the incoming Carry; the function clears it, so start from set.
        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        let mut exp = 0;
        let r = dot_product_sq16_hq(
            case.i32("l_off"),
            &case.i16s("x"),
            case.i16("lg"),
            &mut exp,
            &mut flags,
        );
        check(
            case,
            "r/exp/carry",
            &(r, exp, i16::from(flags.carry)),
            &(
                case.out_i32("r"),
                case.out_i16("exp"),
                case.out_i16("carry"),
            ),
        );
    });
}

#[test]
fn dotp_s_matches_the_reference() {
    each("dotp_s", |case| {
        check(
            case,
            "r",
            &dotp_s(
                &case.i16s("x"),
                &case.i16s("y"),
                case.i16("n"),
                case.i16("s"),
            ),
            &case.out_i32("r"),
        );
    });
}

#[test]
fn get_norm_reciprocal_word16_matches_the_reference() {
    each("norm_reciprocal", |case| {
        check(
            case,
            "r",
            &get_norm_reciprocal_word16(case.i16("x")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn add_mant32_exp_matches_the_reference() {
    each("add_mant32_exp", |case| {
        let mut exp = 0;
        let r = basop_util_add_mant32_exp(
            case.i32("a_m"),
            case.i16("a_e"),
            case.i32("b_m"),
            case.i16("b_e"),
            &mut exp,
        );
        check(
            case,
            "r/exp",
            &(r, exp),
            &(case.out_i32("r"), case.out_i16("exp")),
        );
    });
}

#[test]
fn dot_word32_16_mant32_exp_matches_the_reference() {
    each("dot_word32_16", |case| {
        let mut exp = 0;
        let r = dot_word32_16_mant32_exp(
            &case.i32s("x"),
            case.i16("x_exp"),
            &case.i16s("y"),
            case.i16("y_exp"),
            case.i16("len"),
            &mut exp,
        );
        check(
            case,
            "r/exp",
            &(r, exp),
            &(case.out_i32("r"), case.out_i16("exp")),
        );
    });
}

#[test]
fn idiv1616_u_matches_the_reference() {
    each("idiv1616u", |case| {
        check(
            case,
            "quotient",
            &siphon_rtp_codec::evs::com::basop_util::idiv1616_u(case.i16("x"), case.i16("y")),
            &case.out_i16("quotient"),
        );
    });
}

#[test]
fn dot_product16_hq_matches_the_reference() {
    each("dot_product16_hq", |case| {
        // The oracle randomises the incoming Carry; the function clears it, so start from set.
        let mut flags = StlFlags {
            overflow: false,
            carry: true,
        };
        let mut exp = 0;
        let r = siphon_rtp_codec::evs::com::basop_util::dot_product16_hq(
            case.i32("l_off"),
            &case.i16s("x"),
            &case.i16s("y"),
            case.i16("lg"),
            &mut exp,
            &mut flags,
        );
        check(
            case,
            "r/exp/carry",
            &(r, exp, i16::from(flags.carry)),
            &(
                case.out_i32("r"),
                case.out_i16("exp"),
                case.out_i16("carry"),
            ),
        );
    });
}

#[test]
fn divide3232_matches_the_reference() {
    each("divide3232_plain", |case| {
        check(
            case,
            "z",
            &divide3232(case.i32("num"), case.i32("denom")),
            &case.out_i16("z"),
        );
    });
}

#[test]
fn isqrt32_matches_the_reference() {
    each("isqrt32", |case| {
        let mut exponent = case.i16("exponent");
        let mantissa = isqrt32(case.i32("mantissa"), &mut exponent);
        check(
            case,
            "mantissa/exponent",
            &(mantissa, exponent),
            &(case.out_i32("mantissa"), case.out_i16("exponent")),
        );
    });
}

#[test]
fn basop_util_pow2_matches_the_reference() {
    each("pow2", |case| {
        let mut result_e = -99;
        let r = basop_util_pow2(case.i32("exp_m"), case.i16("exp_e"), &mut result_e);
        check(
            case,
            "r/result_e",
            &(r, result_e),
            &(case.out_i32("r"), case.out_i16("result_e")),
        );
    });
}

#[test]
fn basop_util_norm_s_bands2shift_matches_the_reference() {
    each("norm_s_bands2shift", |case| {
        let r = basop_util_norm_s_bands2shift(case.i16("x"));
        check(case, "r", &r, &case.out_i16("r"));
    });
}

#[test]
fn divide1616_scale_matches_the_reference() {
    each("divide1616", |case| {
        let mut s = 0;
        let z = basop_util_divide1616_scale(case.i16("x"), case.i16("y"), &mut s);
        check(
            case,
            "z/s",
            &(z, s),
            &(case.out_i16("z"), case.out_i16("s")),
        );
    });
}

#[test]
fn add_mant_exp_matches_the_reference() {
    each("add_mant_exp", |case| {
        let mut m = 0;
        let e = basop_util_add_mant_exp(
            case.i16("a_m"),
            case.i16("a_e"),
            case.i16("b_m"),
            case.i16("b_e"),
            &mut m,
        );
        check(
            case,
            "m/e",
            &(m, e),
            &(case.out_i16("m"), case.out_i16("e")),
        );
    });
}

#[test]
fn inv16_matches_the_reference() {
    each("inv16", |case| {
        let mut e = case.i16("e");
        let r = inv16(case.i16("m"), &mut e);
        check(
            case,
            "r/e",
            &(r, e),
            &(case.out_i16("r"), case.out_i16("e")),
        );
    });
}
