//! `lib_com/wi_fx.c` against `fn_wi`.
//!
//! `WIsyn_fx` is replayed in both alignment modes, which proves `DTFS_copy_fx`,
//! `DTFS_alignment_weight_fx`, `DTFS_alignment_full_fx` (FR), `DTFS_adjustLag_fx`,
//! `DTFS_getEngy_fx`, `DTFS_setEngy_fx`, `DTFS_zeroPadd_fx`, `poleFilter_setup_fx`,
//! `DTFS_poleFilter_fx_9`, `DTFS_zeroFilter_fx`, `DTFS_phaseShift_fx`, `cubicPhase_fx`,
//! `DTFS_transform_fx`, `DTFS_fast_fs_inv_fx` and the inverse `r_fft_4_fx` / `c_fft_wi_fx`
//! through it. The forward FFT and the non-FR full alignment, which no decoder path reaches,
//! are replayed directly, and so are the pieces whose faults `WIsyn_fx`'s output can hide (their
//! results are renormalised, or only steer an arg-max there): `cubicPhase_fx`,
//! `DTFS_transform_fx`, `DTFS_adjustLag_fx`, the pole / zero filters and
//! `DTFS_alignment_weight_fx`.

use siphon_rtp_codec::evs::cnst::{M, MAXLAG_WI, PIT_MAX};
use siphon_rtp_codec::evs::com::wi::{
    copy_phase, cubic_phase, dtfs_adjust_lag, dtfs_alignment_full, dtfs_alignment_weight,
    dtfs_car2pol, dtfs_copy, dtfs_dequant_cw, dtfs_new, dtfs_pole_filter_9, dtfs_set_engy_harm,
    dtfs_to_erb, dtfs_to_fs, dtfs_transform, dtfs_zero_filter, get_sin_cos_tab, pole_filter_setup,
    q2phase_shift, r_fft_4, rshift_harm_band, wi_syn, DtfsStructure,
};

use crate::common::{corpus, mismatch, Case};

const TAB: usize = PIT_MAX as usize * 4 + 1;
const LAG_MAX: usize = MAXLAG_WI as usize;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("wi", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

fn dtfs_from(a: &[i16], b: &[i16], s: &[i16]) -> DtfsStructure {
    let mut x = dtfs_new();
    x.a.copy_from_slice(&a[..LAG_MAX]);
    x.b.copy_from_slice(&b[..LAG_MAX]);
    x.lag = s[0];
    x.nh = s[1];
    x.nh_4khz = s[2];
    x.upper_cut_off_freq_of_interest = s[3];
    x.upper_cut_off_freq = s[4];
    x.fs = s[5];
    x.q = s[6];
    x
}

fn input_dtfs(case: &Case, prefix: &str) -> DtfsStructure {
    dtfs_from(
        &case.i16s(&format!("{prefix}_a")),
        &case.i16s(&format!("{prefix}_b")),
        &case.i16s(&format!("{prefix}_s")),
    )
}

fn check_dtfs(case: &Case, prefix: &str, rust: &DtfsStructure) {
    let reference = dtfs_from(
        &case.out_i16s(&format!("{prefix}_a")),
        &case.out_i16s(&format!("{prefix}_b")),
        &case.out_i16s(&format!("{prefix}_s")),
    );
    check(case, prefix, rust, &reference);
}

/// The sin / cos tables of `S_fx` / `C_fx` for the lag `l`.
fn tables(l: i16) -> (Box<[i16; TAB]>, Box<[i16; TAB]>) {
    let (mut s, mut c) = (Box::new([0_i16; TAB]), Box::new([0_i16; TAB]));
    get_sin_cos_tab(l, &mut s[..], &mut c[..]);
    (s, c)
}

#[test]
fn get_sin_cos_tab_matches_the_reference() {
    each("get_sin_cos_tab", |case| {
        let l = case.i16("l");
        let (s, c) = tables(l);
        let n = 4 * l as usize;
        check(case, "s", &s[..n].to_vec(), &case.out_i16s("s"));
        check(case, "c", &c[..n].to_vec(), &case.out_i16s("c"));
    });
}

#[test]
fn dtfs_to_fs_matches_the_reference() {
    each("dtfs_to_fs", |case| {
        let x = case.i16s("x");
        let n = x.len() as i16;
        let (s, c) = tables(n);
        let mut dtfs = dtfs_new();
        dtfs_to_fs(
            &x,
            n,
            &mut dtfs,
            case.i16("fs"),
            case.i16("fr_flag"),
            &s[..],
            &c[..],
        );
        check_dtfs(case, "x", &dtfs);
    });
}

#[test]
fn wi_syn_matches_the_reference() {
    each("wi_syn", |case| {
        let prev = input_dtfs(case, "prev");
        let mut curr = input_dtfs(case, "curr");
        let (s, c) = tables(curr.lag);
        let n = case.i16("n");
        let lpc = case.i16s("lpc");
        assert_eq!(lpc.len(), M as usize + 1);
        let mut out = vec![0_i16; n as usize];
        let mut ph_offset = case.i16("ph_offset");
        let (mut pf_temp1, mut pf_temp2, mut pf_temp, mut pf_n2) = (
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
        );
        wi_syn(
            prev,
            &mut curr,
            &lpc,
            &mut ph_offset,
            &mut out,
            n,
            case.i16("fr_flag"),
            &s[..],
            &c[..],
            &mut pf_temp1,
            &mut pf_temp2,
            &mut pf_temp,
            &mut pf_n2,
        );
        check(case, "out", &out, &case.out_i16s("out"));
        check(case, "ph_offset", &ph_offset, &case.out_i16("ph_offset"));
        check_dtfs(case, "curr", &curr);
    });
}

#[test]
fn dtfs_alignment_full_matches_the_reference() {
    each("dtfs_alignment_full", |case| {
        let x1 = input_dtfs(case, "x1");
        let x2 = input_dtfs(case, "x2");
        let (s, c) = tables(x2.lag);
        let shift = dtfs_alignment_full(
            x1,
            x2,
            case.i16("ph_offset"),
            &s[..],
            &c[..],
            case.i16("fr_flag"),
        );
        check(case, "shift", &shift, &case.out_i16("shift"));
    });
}

#[test]
fn r_fft_4_matches_the_reference() {
    each("r_fft_4", |case| {
        let mut x = case.i16s("x");
        x.push(0);
        r_fft_4(&mut x, 256, 7, case.i16("isign"));
        check(case, "x", &x[..256].to_vec(), &case.out_i16s("x"));
    });
}

#[test]
fn cubic_phase_matches_the_reference() {
    each("cubic_phase", |case| {
        let n = case.i16("n");
        let mut ph = [0x5a5a_5a5a_i32; 512];
        cubic_phase(
            case.i16("ph1"),
            case.i16("ph2"),
            case.i16("l1"),
            case.i16("l2"),
            n,
            &mut ph,
        );
        check(case, "ph", &ph[..n as usize].to_vec(), &case.out_i32s("ph"));
    });
}

#[test]
fn dtfs_transform_matches_the_reference() {
    each("dtfs_transform", |case| {
        let x = input_dtfs(case, "x");
        let x2 = input_dtfs(case, "x2");
        let n = case.i16("n");
        let phase = case.i32s("phase");
        let mut out = vec![0_i16; n as usize];
        dtfs_transform(&x, &x2, &phase, &mut out, n, case.i16("fr_flag"));
        check(case, "out", &out, &case.out_i16s("out"));
    });
}

#[test]
fn dtfs_adjust_lag_matches_the_reference() {
    each("dtfs_adjust_lag", |case| {
        let mut x = input_dtfs(case, "x");
        dtfs_adjust_lag(&mut x, case.i16("n"));
        check_dtfs(case, "x", &x);
    });
}

#[test]
fn pole_and_zero_filters_match_the_reference() {
    each("pole_zero_filter", |case| {
        let mut x = input_dtfs(case, "x");
        let mut y = dtfs_new();
        dtfs_copy(&mut y, &x);
        let lpc = case.i16s("lpc");
        let (s, c) = tables(x.lag);
        let (mut pf_temp1, mut pf_temp2, mut pf_temp, mut pf_n2) = (
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
        );
        pole_filter_setup(
            &lpc,
            M + 1,
            &x,
            &s[..],
            &c[..],
            &mut pf_temp1,
            &mut pf_temp2,
            &mut pf_temp,
            &mut pf_n2,
        );
        dtfs_pole_filter_9(&mut x, &pf_temp1, &pf_temp2, &pf_temp, &pf_n2);
        dtfs_zero_filter(&mut y, &lpc, M + 1, &s[..], &c[..]);
        let h = case.out_i16s("pf_temp1").len();
        check(
            case,
            "pf_temp1",
            &pf_temp1[..h].to_vec(),
            &case.out_i16s("pf_temp1"),
        );
        check(
            case,
            "pf_temp2",
            &pf_temp2[..h].to_vec(),
            &case.out_i16s("pf_temp2"),
        );
        check(
            case,
            "pf_temp",
            &pf_temp[..h].to_vec(),
            &case.out_i16s("pf_temp"),
        );
        check(case, "pf_n2", &pf_n2[..h].to_vec(), &case.out_i16s("pf_n2"));
        check_dtfs(case, "pole", &x);
        check_dtfs(case, "zero", &y);
    });
}

#[test]
fn dtfs_alignment_weight_matches_the_reference() {
    each("dtfs_alignment_weight", |case| {
        let x1 = input_dtfs(case, "x1");
        let x2 = input_dtfs(case, "x2");
        let (s, c) = tables(x2.lag);
        let (mut pf_temp1, mut pf_temp2, mut pf_temp, mut pf_n2) = (
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
            [0_i16; LAG_MAX],
        );
        let shift = dtfs_alignment_weight(
            &x1,
            x2,
            case.i16("eshift"),
            &case.i16s("lpc1"),
            &case.i16s("lpc2"),
            &s[..],
            &c[..],
            &mut pf_temp1,
            &mut pf_temp2,
            &mut pf_temp,
            &mut pf_n2,
        );
        check(case, "shift", &shift, &case.out_i16("shift"));
        check_dtfs(case, "x1", &x1);
    });
}

// ---- the QPPP prototype dequantiser (SC-VBR PPP frames) and its spectral helpers ----

#[test]
fn ppp_car2pol_matches_the_reference() {
    each("ppp_car2pol", |case| {
        let mut x = input_dtfs(case, "x");
        dtfs_car2pol(&mut x);
        check_dtfs(case, "x", &x);
    });
}

#[test]
fn ppp_set_engy_harm_matches_the_reference() {
    each("ppp_set_engy_harm", |case| {
        let mut x = input_dtfs(case, "x");
        let mut qa = -99;
        let r = dtfs_set_engy_harm(
            case.i16("f1"),
            case.i16("f2"),
            case.i16("g1"),
            case.i16("g2"),
            case.i32("en2"),
            case.i16("qen2"),
            &mut qa,
            &mut x,
        );
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "qa", &qa, &case.out_i16("qa"));
        check_dtfs(case, "x", &x);
    });
}

#[test]
fn ppp_rshift_harm_band_matches_the_reference() {
    each("ppp_rshift_harm_band", |case| {
        let mut x = input_dtfs(case, "x");
        rshift_harm_band(
            &mut x,
            case.i16("lband"),
            case.i16("hband"),
            case.i16("shift"),
        );
        check_dtfs(case, "x", &x);
    });
}

#[test]
fn ppp_to_erb_matches_the_reference() {
    each("ppp_to_erb", |case| {
        let x = input_dtfs(case, "x");
        let mut out = vec![-777i16; 24];
        dtfs_to_erb(&x, &mut out);
        check(case, "out", &out, &case.out_i16s("out"));
    });
}

#[test]
fn ppp_q2phase_shift_matches_the_reference() {
    each("ppp_q2phase_shift", |case| {
        let mut x = input_dtfs(case, "x");
        let (mut s, mut c) = (vec![0i16; TAB], vec![0i16; TAB]);
        get_sin_cos_tab(x.lag, &mut s, &mut c);
        let lag = x.lag;
        q2phase_shift(&mut x, case.i16("ph"), lag, &s, &c);
        check_dtfs(case, "x", &x);
    });
}

#[test]
fn ppp_copy_phase_matches_the_reference() {
    each("ppp_copy_phase", |case| {
        let x1 = input_dtfs(case, "x1");
        let x2 = input_dtfs(case, "x2");
        let mut ret = dtfs_new();
        copy_phase(&x1, x2, &mut ret);
        check_dtfs(case, "ret", &ret);
    });
}

#[test]
fn ppp_dequant_cw_matches_the_reference() {
    each("ppp_dequant_cw", |case| {
        let mut x = input_dtfs(case, "x");
        let mut last_l = case.i16("last_l");
        let mut last_h = case.i16("last_h");
        let mut lasterb = case.i16s("lasterb");
        dtfs_dequant_cw(
            case.i16("pl"),
            case.i16("power_idx"),
            &case.i16s("amp_idx"),
            &mut last_l,
            &mut last_h,
            &mut lasterb,
            &mut x,
            case.i16("num_erb"),
        );
        check_dtfs(case, "x", &x);
        check(case, "last_l", &last_l, &case.out_i16("last_l"));
        check(case, "last_h", &last_h, &case.out_i16("last_h"));
        check(case, "lasterb", &lasterb, &case.out_i16s("lasterb"));
    });
}
