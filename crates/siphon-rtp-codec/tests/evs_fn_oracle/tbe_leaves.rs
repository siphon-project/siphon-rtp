//! The leaf functions the TBE decoder calls, against `fn_tbe_leaves`: `tools_fx.c` (`root_a*`,
//! `*_flt32_*`), `residu_fx.c`, `modif_fs_fx.c` and `lsf_tools_fx.c`.

use siphon_rtp_codec::evs::com::lsf_tools::{
    a2rc, compute_poly_product, lsp2lpc, poscos, space_lsfs,
};
use siphon_rtp_codec::evs::com::modif_fs::{
    decimate_allpass_steep, interpolate_3_over_2_allpass, interpolate_3_over_2_allpass_in_place,
};
use siphon_rtp_codec::evs::com::residu::residu3_10;
use siphon_rtp_codec::evs::com::tools::{
    add_flt32_flt32, div_flt32_flt32, mul_flt32_q15, root_a, root_a_over_b, sum2_mod, usquant,
};
use siphon_rtp_codec::evs::rom::ALLPASS_POLES_3_OV_2;

use crate::common::{corpus, mismatch};

const MODULE: &str = "tbe_leaves";

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
fn root_a_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "root_a") else {
        return;
    };
    for case in &cases {
        let mut exp = 0;
        let r = root_a(case.i32("a"), case.i16("q_a"), &mut exp);
        check(case, "r", r, case.out_i32("r"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn root_a_over_b_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "root_a_over_b") else {
        return;
    };
    for case in &cases {
        let mut exp = 0;
        let r = root_a_over_b(
            case.i32("a"),
            case.i16("q_a"),
            case.i32("b"),
            case.i16("q_b"),
            &mut exp,
        );
        check(case, "r", r, case.out_i32("r"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn add_flt32_flt32_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "add_flt32") else {
        return;
    };
    for case in &cases {
        let mut exp = 0;
        let r = add_flt32_flt32(
            case.i32("a"),
            case.i16("exp_a"),
            case.i32("b"),
            case.i16("exp_b"),
            &mut exp,
        );
        check(case, "r", r, case.out_i32("r"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn mul_flt32_q15_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "mul_flt32_q15") else {
        return;
    };
    for case in &cases {
        let mut exp = case.i16("exp_v");
        let r = mul_flt32_q15(case.i32("value"), &mut exp, case.i16("frac"));
        check(case, "r", r, case.out_i32("r"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn div_flt32_flt32_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "div_flt32") else {
        return;
    };
    for case in &cases {
        let mut exp = 0;
        let r = div_flt32_flt32(
            case.i32("a"),
            case.i16("exp_a"),
            case.i32("b"),
            case.i16("exp_b"),
            &mut exp,
        );
        check(case, "r", r, case.out_i32("r"));
        check(case, "exp", exp, case.out_i16("exp"));
    }
}

#[test]
fn residu3_10_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "residu3_10") else {
        return;
    };
    for case in &cases {
        let mut y = vec![0i16; 80];
        let lg = case.i16("lg");
        residu3_10(
            &case.i16s("a"),
            &case.i16s("x"),
            10,
            &mut y,
            lg,
            case.i16("shift"),
        );
        check(case, "y", y[..lg as usize].to_vec(), case.out_i16s("y"));
    }
}

#[test]
fn decimate_allpass_steep_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "decimate") else {
        return;
    };
    for case in &cases {
        let n = case.i16("n");
        let mut state = case.i16s("state");
        let mut out = vec![0i16; n as usize / 2];
        decimate_allpass_steep(&case.i16s("in"), &mut state, n, &mut out);
        check(case, "out", out, case.out_i16s("out"));
        check(case, "state_out", state, case.out_i16s("state_out"));
    }
}

#[test]
fn interpolate_3_over_2_allpass_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "interpolate_3_over_2") else {
        return;
    };
    for case in &cases {
        let len = case.i16("len");
        let produced = (len as usize * 3) / 2;
        let mut mem = case.i16s("mem");
        let mut out = vec![0i16; 960];
        interpolate_3_over_2_allpass(
            &case.i16s("in"),
            len,
            &mut out,
            &mut mem,
            &ALLPASS_POLES_3_OV_2,
        );
        check(case, "out", out[..produced].to_vec(), case.out_i16s("out"));
        check(case, "mem_out", mem.clone(), case.out_i16s("mem_out"));

        // the aliased form must give the same result
        let mut mem = case.i16s("mem");
        let mut io = vec![0i16; 960];
        io[..len as usize].copy_from_slice(&case.i16s("in"));
        interpolate_3_over_2_allpass_in_place(&mut io, len, &mut mem, &ALLPASS_POLES_3_OV_2);
        check(
            case,
            "out (in place)",
            io[..produced].to_vec(),
            case.out_i16s("out"),
        );
        check(case, "mem_out (in place)", mem, case.out_i16s("mem_out"));
    }
}

#[test]
fn lsp2lpc_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "lsp2lpc") else {
        return;
    };
    for case in &cases {
        let order = case.i16("order");
        let mut a = vec![0x5a5ai16; 10];
        lsp2lpc(&mut a, &case.i16s("freq"), &case.i16s("prev_a"), order);
        check(case, "a", a[..order as usize].to_vec(), case.out_i16s("a"));
    }
}

#[test]
fn a2rc_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "a2rc") else {
        return;
    };
    for case in &cases {
        let lpcorder = case.i16("lpcorder");
        let mut refl = vec![0x5a5ai16; 16];
        a2rc(&case.i16s("buffer"), 1, &mut refl, lpcorder);
        check(
            case,
            "refl",
            refl[..lpcorder as usize].to_vec(),
            case.out_i16s("refl"),
        );
    }
}

#[test]
fn space_lsfs_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "space_lsfs") else {
        return;
    };
    for case in &cases {
        let mut lsfs = case.i16s("lsfs");
        space_lsfs(&mut lsfs, 10);
        check(case, "lsfs_out", lsfs, case.out_i16s("lsfs_out"));
    }
}

#[test]
fn poscos_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "poscos") else {
        return;
    };
    for case in &cases {
        check(case, "r", poscos(case.i16("w")), case.out_i32("r"));
    }
}

#[test]
fn compute_poly_product_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "compute_poly_product") else {
        return;
    };
    for case in &cases {
        let order = case.i16("order");
        let mut p = vec![0x5a5a_5a5ai32; 10];
        compute_poly_product(&case.i16s("coef"), &mut p, order);
        check(
            case,
            "p",
            p[..order as usize / 2 + 1].to_vec(),
            case.out_i32s("p"),
        );
    }
}

#[test]
fn usquant_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "usquant") else {
        return;
    };
    for case in &cases {
        let mut xq = 0;
        let idx = usquant(case.i16("x"), &mut xq, 4096, 2048, 8);
        check(case, "idx", idx, case.out_i16("idx"));
        check(case, "xq", xq, case.out_i16("xq"));
    }
}

#[test]
fn sum2_mod_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "sum2_mod") else {
        return;
    };
    for case in &cases {
        let v = case.i16s("v");
        check(case, "r", sum2_mod(&v, v.len() as i16), case.out_i32("r"));
    }
}

#[test]
fn syn_filt_s_orders_6_and_10_match_the_reference_with_saturating_coefficients() {
    use siphon_rtp_codec::evs::com::syn_filt::syn_filt_s;
    let Some(cases) = corpus(MODULE, "syn_filt") else {
        return;
    };
    for case in &cases {
        let lg = case.i16("lg");
        let mut y = vec![0i16; 80];
        let mut mem = case.i16s("mem");
        syn_filt_s(
            0,
            &case.i16s("a"),
            case.i16("m"),
            &case.i16s("x"),
            &mut y,
            lg,
            &mut mem,
            1,
        );
        check(case, "y", y[..lg as usize].to_vec(), case.out_i16s("y"));
        check(case, "mem_out", mem, case.out_i16s("mem_out"));
    }
}
