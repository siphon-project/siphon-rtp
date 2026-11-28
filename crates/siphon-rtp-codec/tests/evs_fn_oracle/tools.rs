//! `lib_com/tools_fx.c` against `fn_tools`.
//!
//! `Copy`, `Copy32`, `set16_fx` and `set32_fx` move values without arithmetic and are covered by
//! the unit tests in `src/evs/com/tools.rs`.

use siphon_rtp_codec::evs::com::tools::*;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("tools", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

#[test]
fn usdequant_matches_the_reference() {
    each("usdequant", |case| {
        let g = usdequant(case.i16("idx"), case.i16("qlow"), case.i16("delta"));
        check(case, "g", &g, &case.out_i16("g"));
    });
}

#[test]
fn dot_product_matches_the_reference() {
    each("dot_product", |case| {
        let sum = dot_product(&case.i16s("x"), &case.i16s("y"), case.i16("lg"));
        check(case, "sum", &sum, &case.out_i32("sum"));
    });
}

#[test]
fn sum2_matches_the_reference() {
    each("sum2", |case| {
        let sum = sum2(&case.i16s("vec"), case.i16("lvec"));
        check(case, "sum", &sum, &case.out_i32("sum"));
    });
}

#[test]
fn copy_scale_sig_matches_the_reference() {
    each("copy_scale_sig", |case| {
        let x = case.i16s("x");
        let mut y = vec![0; x.len()];
        copy_scale_sig(&x, &mut y, case.i16("lg"), case.i16("exp0"));
        check(case, "y", &y, &case.out_i16s("y"));
    });
}

#[test]
fn copy_scale_sig_32_16_matches_the_reference() {
    each("copy_scale_sig_32_16", |case| {
        let x = case.i32s("x");
        let mut y = vec![0; x.len()];
        copy_scale_sig_32_16(&x, &mut y, case.i16("lg"), case.i16("exp0"));
        check(case, "y", &y, &case.out_i16s("y"));
    });
}

#[test]
fn copy_scale_sig_16_32_matches_the_reference() {
    each("copy_scale_sig_16_32", |case| {
        let x = case.i16s("x");
        let mut y = vec![0; x.len()];
        copy_scale_sig_16_32(&x, &mut y, case.i16("lg"), case.i16("exp0"));
        check(case, "y", &y, &case.out_i32s("y"));
    });
}

#[test]
fn own_random2_matches_the_reference() {
    each("own_random2", |case| {
        check(
            case,
            "r",
            &own_random2(case.i16("seed")),
            &case.out_i16("r"),
        );
    });
}

#[test]
fn copy_scale_sig32_16_matches_the_reference() {
    each("copy_scale_sig32_16", |case| {
        let x = case.i32s("x");
        let mut y = vec![0; x.len()];
        copy_scale_sig32_16(&x, &mut y, case.i16("lg"), case.i16("exp0"));
        check(case, "y", &y, &case.out_i16s("y"));
    });
}

#[test]
fn scale_sig32_matches_the_reference() {
    each("scale_sig32", |case| {
        let mut x = case.i32s("x");
        scale_sig32(&mut x, case.i16("lg"), case.i16("exp0"));
        check(case, "x", &x, &case.out_i32s("x"));
    });
}

#[test]
fn scale_sig_matches_the_reference() {
    each("scale_sig", |case| {
        let mut x = case.i16s("x");
        scale_sig(&mut x, case.i16("lg"), case.i16("exp0"));
        check(case, "x", &x, &case.out_i16s("x"));
    });
}

#[test]
fn random_fill_matches_the_reference() {
    each("random_fill", |case| {
        let mut seed = case.i16("seed");
        let n = case.i16("n");
        let mut y = vec![0; n as usize];
        random_fill(&mut seed, n, &mut y, case.i16("scaling"));
        check(case, "seed", &seed, &case.out_i16("seed"));
        check(case, "y", &y, &case.out_i16s("y"));
    });
}

#[test]
fn random_matches_the_reference() {
    each("random", |case| {
        let mut seed = case.i16("seed");
        let r = random(&mut seed);
        check(case, "seed", &seed, &case.out_i16("seed"));
        check(case, "r", &r, &case.out_i16("r"));
    });
}

#[test]
fn mean_matches_the_reference() {
    each("mean", |case| {
        let m = mean(&case.i16s("vec"), case.i16("lvec"));
        check(case, "mean", &m, &case.out_i16("mean"));
    });
}

#[test]
fn vr_add_and_vr_subt_match_the_reference() {
    each("vr_add", |case| {
        let a = case.i16s("in1");
        let mut out = vec![0; a.len()];
        vr_add(&a, &case.i16s("in2"), &mut out, case.i16("n"));
        check(case, "out", &out, &case.out_i16s("out"));
    });
    each("vr_subt", |case| {
        let a = case.i16s("x1");
        let mut out = vec![0; a.len()];
        vr_subt(&a, &case.i16s("x2"), &mut out, case.i16("n"));
        check(case, "y", &out, &case.out_i16s("y"));
    });
}

#[test]
fn sort_matches_the_reference() {
    each("sort", |case| {
        let mut r = case.i16s("r");
        sort(&mut r, case.i16("lo"), case.i16("up"));
        check(case, "r", &r, &case.out_i16s("r"));
    });
}

#[test]
fn minimum_and_maximum_match_the_reference() {
    each("minmax", |case| {
        let vec = case.i16s("vec");
        let lvec = case.i16("lvec");
        let (mut min_fx, mut max_fx) = (0, 0);
        let imin = minimum(&vec, lvec, &mut min_fx);
        let imax = maximum(&vec, lvec, &mut max_fx);
        check(
            case,
            "min",
            &(imin, min_fx, imax, max_fx),
            &(
                case.out_i16("imin"),
                case.out_i16("min"),
                case.out_i16("imax"),
                case.out_i16("max"),
            ),
        );
    });
}

#[test]
fn emaximum_matches_the_reference() {
    each("emaximum", |case| {
        let mut ener = 0;
        let ind = emaximum(
            case.i16("qvec"),
            &case.i16s("vec"),
            case.i16("lvec"),
            &mut ener,
        );
        check(
            case,
            "ind/ener",
            &(ind, ener),
            &(case.out_i16("ind"), case.out_i32("ener")),
        );
    });
}

#[test]
fn sum16_and_sum16_32_match_the_reference() {
    each("sums", |case| {
        let vec = case.i16s("vec");
        let lvec = case.i16("lvec");
        check(case, "sum32", &sum16_32(&vec, lvec), &case.out_i32("sum32"));
        check(case, "sum16", &sum16(&vec, lvec), &case.out_i16("sum16"));
    });
}

#[test]
fn add_vec_matches_the_reference() {
    each("add_vec", |case| {
        let x1 = case.i16s("x1");
        let mut y = vec![0; x1.len()];
        add_vec(
            &x1,
            case.i16("qx1"),
            &case.i16s("x2"),
            case.i16("qx2"),
            &mut y,
            case.i16("qy"),
            case.i16("n"),
        );
        check(case, "y", &y, &case.out_i16s("y"));
    });
}

#[test]
fn calc_energy_autoscaled_matches_the_reference() {
    let (mut seen, mut rescaled) = (0, 0);
    each("calc_energy_autoscaled", |case| {
        let mut energy_exp = 0;
        let energy = calc_energy_autoscaled(
            &case.i16s("signal"),
            case.i16("signal_exp"),
            case.i16("len"),
            &mut energy_exp,
        );
        check(
            case,
            "energy/exp",
            &(energy, energy_exp),
            &(case.out_i32("energy"), case.out_i16("energy_exp")),
        );
        seen += 1;
        // The Overflow-driven rescale fired iff the exponent is below 2·signal_exp - 2.
        if energy_exp < 2 * case.i16("signal_exp") - 2 {
            rescaled += 1;
        }
    });
    if seen > 0 {
        assert!(
            rescaled > 50,
            "corpus exercised the overflow rescale only {rescaled} times"
        );
    }
}

#[test]
fn find_max_norm_matches_the_reference() {
    each("find_max_norm", |case| {
        let len = case.i16("len");
        check(
            case,
            "norm16",
            &find_max_norm16(&case.i16s("src16"), len),
            &case.out_i16("norm16"),
        );
        check(
            case,
            "norm32",
            &find_max_norm32(&case.i32s("src32"), len),
            &case.out_i16("norm32"),
        );
    });
}

#[test]
fn acelp_dec_total_exc_matches_the_reference() {
    each("acelp_dec_total_exc", |case| {
        let mut exc = case.i16s("exc");
        let mut exc2 = case.i16s("exc2");
        acelp_dec_total_exc(
            &mut exc,
            &mut exc2,
            case.i16("gain_code"),
            case.i16("gain_pit"),
            case.i16("i_subfr"),
            &case.i16s("code"),
        );
        check(case, "exc", &exc, &case.out_i16s("exc"));
        check(case, "exc2", &exc2, &case.out_i16s("exc2"));
    });
}

#[test]
fn ul_inverse_and_ul_div_match_the_reference() {
    each("ul", |case| {
        let value = |name: &str| case.inputs[name][0] as u32;
        let mut exp = 0;
        let inverse = ul_inverse(value("val"), &mut exp);
        let quotient = ul_div(value("num"), value("den"));
        check(
            case,
            "inverse/exp/div",
            &(i64::from(inverse), exp, i64::from(quotient)),
            &(
                case.outputs["inverse"][0],
                case.out_i16("exp"),
                case.outputs["div"][0],
            ),
        );
    });
}

#[test]
fn hp400_12k8_matches_the_reference() {
    each("hp400_12k8", |case| {
        let mut signal = case.i16s("signal");
        let mut mem = case.i16s("mem");
        hp400_12k8(&mut signal, case.i16("lg"), &mut mem);
        check(case, "signal", &signal, &case.out_i16s("signal"));
        check(case, "mem", &mem, &case.out_i16s("mem"));
    });
}

#[test]
fn idiv_and_mod_32_matches_the_reference() {
    each("idiv_and_mod_32", |case| {
        let (mut q, mut m) = (0, 0);
        idiv_and_mod_32(
            case.i32("numer"),
            case.i16("denom"),
            &mut q,
            &mut m,
            case.i16("rshift"),
        );
        check(case, "q", &q, &case.out_i32("q"));
        check(case, "m", &m, &case.out_i32("m"));
    });
}

#[test]
fn sqrt_ratio32_matches_the_reference() {
    each("sqrt_ratio32", |case| {
        let mut exp = 0;
        let r = sqrt_ratio32(
            case.i32("v1"),
            case.i16("e1"),
            case.i32("v2"),
            case.i16("e2"),
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
fn ratio_matches_the_reference() {
    let Some(cases) = corpus("tools", "ratio") else {
        return;
    };
    for case in &cases {
        let mut e = 0;
        let q = ratio(case.i32("numer"), case.i32("denom"), &mut e);
        check(case, "q", &q, &case.out_i16("q"));
        check(case, "e", &e, &case.out_i16("e"));
    }
}

#[test]
fn find_rem_matches_the_reference() {
    each("find_rem", |case| {
        let mut r = 0;
        let q = find_rem(case.i16("n"), case.i16("m"), &mut r);
        check(
            case,
            "q/r",
            &(q, r),
            &(case.out_i16("q"), case.out_i16("r")),
        );
    });
}

#[test]
fn rint_new_matches_the_reference() {
    each("rint_new", |case| {
        check(case, "a", &rint_new(case.i32("x")), &case.out_i16("a"));
    });
}

#[test]
fn exp16_array_matches_the_reference() {
    each("exp16_array", |case| {
        let x = case.i16s("x");
        check(
            case,
            "e",
            &exp16_array(x.len() as i16, &x),
            &case.out_i16("e"),
        );
    });
}

#[test]
fn fir_matches_the_reference() {
    each("fir", |case| {
        let l = case.i16("l");
        let mut y = vec![0i16; l as usize];
        let mut mem = case.i16s("mem");
        fir(
            &case.i16s("x"),
            &case.i16s("h"),
            &mut y,
            &mut mem,
            l,
            case.i16("k"),
            case.i16("upd"),
            case.i16("shift"),
        );
        check(case, "y", &y, &case.out_i16s("y"));
        check(case, "mem", &mem, &case.out_i16s("mem"));
    });
}

#[test]
fn floating_point_add_matches_the_reference() {
    each("floating_point_add", |case| {
        let mut mx = case.i32("mx");
        let mut ex = case.i16("ex");
        floating_point_add(&mut mx, &mut ex, case.i32("my"), case.i16("ey"));
        check(
            case,
            "mx/ex",
            &(mx, ex),
            &(case.out_i32("mx"), case.out_i16("ex")),
        );
    });
}

#[test]
fn pz_filter_sp_matches_the_reference() {
    each("pz_filter_sp", |case| {
        let n = case.i16("n");
        let mut y = vec![0i16; n as usize];
        let mut buf = case.i16s("buf");
        pz_filter_sp(
            &case.i16s("b"),
            &case.i16s("a"),
            &case.i16s("x"),
            &mut y,
            &mut buf,
            case.i16("pnr"),
            case.i16("pdr"),
            n,
            case.i16("qa"),
        );
        check(case, "y", &y, &case.out_i16s("y"));
        check(case, "buf", &buf, &case.out_i16s("buf"));
    });
}

#[test]
fn pz_filter_dp_matches_the_reference() {
    each("pz_filter_dp", |case| {
        let n = case.i16("n");
        let mut y = vec![0i16; n as usize];
        let mut buf = case.i32s("buf");
        pz_filter_dp(
            &case.i16s("b"),
            &case.i16s("a"),
            &case.i16s("x"),
            &mut y,
            &mut buf,
            case.i16("pnr"),
            case.i16("pdr"),
            n,
            case.i16("qa"),
        );
        check(case, "y", &y, &case.out_i16s("y"));
        check(case, "buf", &buf, &case.out_i32s("buf"));
    });
}
