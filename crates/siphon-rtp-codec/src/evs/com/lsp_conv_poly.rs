//! Conversion of an LSP (or AMR-WB ISP) vector between the 12.8 kHz and 16 kHz internal sampling
//! rates through the LP power spectrum (TS 26.442 `lib_com/lsp_conv_poly_fx.c`; TS 26.445
//! §5.1.9.8 / §6.1.4.2): the spectrum of the old filter is sampled on the grid of the new rate,
//! turned into an autocorrelation, and a new filter of the same order is fitted by Levinson-Durbin.

use crate::evs::cnst::{L_FRAME, M};
use crate::evs::com::lpc_tools::e_lpc_lev_dur;
use crate::evs::com::lsf_tools::{
    e_lpc_a_lsp_conversion, e_lpc_f_isp_a_conversion, e_lpc_f_lsp_a_conversion,
};
use crate::evs::rom::{GRID40_FX, GRID50_FX, STABLE_LSP_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_l, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub, mult_r,
    negate, norm_l, norm_s, shl, sub,
};
use crate::itu::oper_32b::l_extract;
use crate::itu::stl2009::mpy_32_16_ss;

/// `N50`: grid points of the 16 kHz power spectrum (`GRID50_POINTS`).
const N50: usize = 51;
/// `N40`: grid points of the 12.8 kHz power spectrum (`GRID40_POINTS`).
const N40: usize = 41;
/// `M/2`, the order of the sum and difference polynomials.
const NC: usize = (M / 2) as usize;
/// `M + 1`.
const M1: usize = M as usize + 1;

/// `lsp_convert_poly_fx`: converts the LSPs (ISPs with `opt_amrwb`) `w[0..M]` in place from the
/// other internal sampling rate to the one of the new frame length `l_frame`: for `L_FRAME`
/// (12.8 kHz) the old 16 kHz filter's power spectrum is sampled on the 50-point grid and refitted
/// on the 40-point one, otherwise the reverse. Returns `E_LPC_lev_dur`'s flag: 1 when the fitted
/// filter was unstable and the old one was kept.
pub fn lsp_convert_poly(w: &mut [i16], l_frame: i16, opt_amrwb: i16) -> i16 {
    let mut g = [0i32; N50];
    let mut a = [0i16; M1];
    let mut r = [0i32; NC + 1];
    let mut s = [0i32; NC + 1];
    let mut eps_p = [0i32; M1];
    let mut rh = [0i16; M1];
    let mut rl = [0i16; M1];
    let mut old_a = [0i16; M1 + 2];

    // Find the representation where we have a polynomial for the cosine domain
    if opt_amrwb != 0 {
        e_lpc_f_isp_a_conversion(w, &mut old_a, M);
        polydecomp(&old_a, &mut r, &mut s);
    } else {
        e_lpc_f_lsp_a_conversion(w, &mut old_a, M);
        zeros2poly(w, &mut r, &mut s);
    }

    // Starting from the 12.8 kHz sampling rate, sample the power spectrum at the frequencies of the
    // other grid, and turn it into an autocorrelation
    if sub(l_frame, L_FRAME) == 0 {
        powerspect(&GRID50_FX, N50, &r, &s, &mut g, 0);
        spectautocorr(&GRID40_FX, N40, &g, &mut rh, &mut rl);
    } else {
        powerspect(&GRID40_FX, N40, &r, &s, &mut g, 1);
        let last = g[N40 - 1];
        g[N40..N50].fill(last);
        spectautocorr(&GRID50_FX, N50, &g, &mut rh, &mut rl);
    }

    // Compute the linear prediction coefficients from the autocorrelation function
    let flag = e_lpc_lev_dur(&rh, &rl, &mut a, Some(&mut eps_p), M, Some(&mut old_a));

    // Transform the predictor coefficients back to LSP (ISP) domain
    e_lpc_a_lsp_conversion(&a, w, &STABLE_LSP_FX, M);

    flag
}

/// `powerspect_fx`: the inverse LP power spectrum `1/|A|^2` (one value per grid point) at the cosine
/// grid `x` of `n` points, from the sum and difference polynomials `r`, `s` in the cosine domain.
/// `mode` 0 is the 16 kHz grid (the first fifth evaluated directly), 1 the 12.8 kHz grid (which
/// includes the Nyquist point).
pub fn powerspect(x: &[i16], n: usize, r: &[i32], s: &[i32], g: &mut [i32], mode: i16) {
    let iuni;
    let imid;

    // init
    if mode == 0 {
        iuni = (N50 - 1) / 5 - 1;
        imid = (N50 - 1) / 2;
    } else {
        iuni = 0;
        imid = (N40 - 1) / 2;
        // Nyquist frequency
        g[n - 1] = s[0];
        for &sj in &s[1..=NC] {
            g[n - 1] = l_sub(sj, g[n - 1]);
        }
        g[n - 1] = b_inv_sq(g[n - 1], 19);
    }

    // DC component
    g[0] = r[0];
    for &rj in &r[1..=NC] {
        g[0] = l_add(rj, g[0]);
    }
    g[0] = b_inv_sq(g[0].max(1), 19);

    // Account for the pi/2 component
    g[imid] = inv_pow(r[NC], s[NC], 0);

    // Polynomial evaluations at points over the first quarter of the frequency range
    let mut i = 1usize;
    while i <= iuni {
        let xi = x[i - 1];
        let (mh, _) = mpy_32_16_ss(r[0], xi);
        let mut r0 = l_add(r[1], mh);
        let (mh, _) = mpy_32_16_ss(s[0], xi);
        let mut s0 = l_add(s[1], mh);

        for j in 2..=NC {
            let (mh, _) = mpy_32_16_ss(r0, xi);
            r0 = l_add(r[j], mh);
            let (mh, _) = mpy_32_16_ss(s0, xi);
            s0 = l_add(s[j], mh);
        }

        g[i] = inv_pow(r0, s0, xi);
        i += 1;
    }

    // Polynomial evaluations by symmetry with respect to x = 0
    while i < imid {
        let xi = x[i - 1];
        let x2 = mult_r(xi, xi);

        let (mh, _) = mpy_32_16_ss(r[0], x2);
        let mut re = l_add(r[2], mh);
        let (mh, _) = mpy_32_16_ss(r[1], x2);
        let mut ro = l_add(r[3], mh);
        let (mh, _) = mpy_32_16_ss(s[0], x2);
        let mut se = l_add(s[2], mh);
        let (mh, _) = mpy_32_16_ss(s[1], x2);
        let mut so = l_add(s[3], mh);

        let mut j = 4usize;
        while j < NC {
            let (mh, _) = mpy_32_16_ss(re, x2);
            re = l_add(r[j], mh);
            let (mh, _) = mpy_32_16_ss(ro, x2);
            ro = l_add(r[j + 1], mh);
            let (mh, _) = mpy_32_16_ss(se, x2);
            se = l_add(s[j], mh);
            let (mh, _) = mpy_32_16_ss(so, x2);
            so = l_add(s[j + 1], mh);
            j += 2;
        }

        let (mh, _) = mpy_32_16_ss(re, x2);
        let l_tmp = l_add(r[j], mh);
        let (mh, _) = mpy_32_16_ss(ro, xi);
        re = l_add(l_tmp, mh);
        ro = l_sub(l_tmp, mh);

        let (mh, _) = mpy_32_16_ss(se, x2);
        let l_tmp = l_add(s[j], mh);
        let (mh, _) = mpy_32_16_ss(so, xi);
        se = l_add(l_tmp, mh);
        so = l_sub(l_tmp, mh);

        g[i] = inv_pow(re, se, xi);
        g[n - i - 1] = inv_pow(so, ro, xi);
        i += 1;
    }
}

/// `b_inv_sq`: `1 / in32^2`, `in32` in Q(`exp_in`).
fn b_inv_sq(in32: i32, exp_in: i16) -> i32 {
    let mut exp_den = norm_l(in32);
    let mut m_den = extract_h(l_shl(in32, exp_den));
    exp_den = add(sub(30, exp_den), sub(16, exp_in));

    m_den = mult_r(m_den, m_den);
    exp_den = shl(exp_den, 1);

    let div_out = div_s(8192, m_den);
    l_shl(i32::from(div_out), add(sub(30 - 13, exp_den), 15)) // Q15
}

/// `inv_pow`: `1 / ((1 + x) re^2 + (1 - x) se^2)`, `MAX_32` when the sum vanishes.
fn inv_pow(re: i32, se: i32, x: i16) -> i32 {
    let mut exp1;
    let mut exp2;
    let mut r0;
    let mut s0;

    if re == 0 {
        exp1 = 30;
        r0 = l_deposit_l(0);
    } else {
        exp1 = norm_l(re);
        let tmp = extract_h(l_shl(re, exp1));
        let l_tmp = l_shr(l_mult(tmp, tmp), 1);
        let (mh, _) = mpy_32_16_ss(l_tmp, x);
        r0 = l_add(l_tmp, mh);
    }

    if se == 0 {
        exp2 = 30;
        s0 = l_deposit_l(0);
    } else {
        exp2 = norm_l(se);
        let tmp = extract_h(l_shl(se, exp2));
        let l_tmp = l_shr(l_mult(tmp, tmp), 1);
        let (mh, _) = mpy_32_16_ss(l_tmp, x);
        s0 = l_sub(l_tmp, mh);
    }

    if exp1 > exp2 {
        exp1 = shl(sub(exp1, exp2), 1);
        r0 = l_shr(r0, exp1);
        exp2 = add(add(exp2, exp2), 8);
    } else {
        exp2 = shl(sub(exp2, exp1), 1);
        s0 = l_shr(s0, exp2);
        exp2 = add(add(exp1, exp1), 8);
    }
    r0 = l_add(r0, s0);
    exp1 = norm_l(r0);
    let l_tmp = l_shl(r0, exp1);
    let mut tmp = extract_h(l_tmp);
    if tmp == 0 {
        return 0x7fff_ffff;
    }
    tmp = div_s((1 << 14) - 1, tmp);
    exp1 = add(exp1, exp2);
    l_shr(i32::from(tmp), sub(31, exp1))
}

/// `spectautocorr_fx`: the autocorrelation `r[0..=M]` (DPF, `rh`/`rl`, normalised) of the power
/// spectrum `g[0..n]` sampled on the cosine grid `x`, by the Chebyshev recursion
/// `cos(k w) = 2 cos(w) cos((k-1) w) - cos((k-2) w)`.
pub fn spectautocorr(x: &[i16], n: usize, g: &[i32], rh: &mut [i16], rl: &mut [i16]) {
    let mut c = [0i16; M1];
    let mut r = [0i32; M1];
    let m = M as usize;

    let imid = (n - 1) / 2;

    // initialize the autocorrelation coefficients
    r[0] = g[1];
    for &gi in &g[2..n - 1] {
        r[0] = l_add(r[0], gi);
    }

    r[1] = l_deposit_l(0);
    // plain C `-` in the reference (not `L_negate`), which wraps under the build's -fwrapv
    r[2] = g[imid].wrapping_neg();
    let mut i = 3;
    while i < m {
        r[i] = l_deposit_l(0);
        r[i + 1] = r[i - 1].wrapping_neg();
        i += 2;
    }

    // Compute the autocorrelation coefficients
    c[0] = 32767;
    for i in 1..imid {
        let xi = x[i - 1];
        let gp = l_add(g[i], g[n - i - 1]);
        let gn = l_sub(g[i], g[n - i - 1]);

        let (mh, _) = mpy_32_16_ss(gn, xi);
        r[1] = l_add(r[1], mh);
        c[1] = xi;

        let mut j = 2;
        while j < m {
            c[j] = mult_r(c[j - 1], xi);
            c[j] = add(c[j], sub(c[j], c[j - 2]));
            let (mh, _) = mpy_32_16_ss(gp, c[j]);
            r[j] = l_add(r[j], mh);

            c[j + 1] = mult_r(c[j], xi);
            c[j + 1] = add(c[j + 1], sub(c[j + 1], c[j - 1]));
            let (mh, _) = mpy_32_16_ss(gn, c[j + 1]);
            r[j + 1] = l_add(r[j + 1], mh);
            j += 2;
        }

        c[j] = mult_r(c[j - 1], xi);
        c[j] = add(c[j], sub(c[j], c[j - 2]));
        let (mh, _) = mpy_32_16_ss(gp, c[j]);
        r[j] = l_add(r[j], mh);
    }

    // Add the endpoints x = cos(0) = 1 and x = cos(pi) = -1 as well as the lower limit x = cos(pi/2)
    let gp = l_shr(l_add(g[0], g[n - 1]), 1);
    let gn = l_shr(l_sub(g[0], g[n - 1]), 1);

    // Adjust the autocorrelation coefficients
    r[0] = l_add(r[0], gp);
    let exp0 = norm_l(r[0]);
    (rh[0], rl[0]) = l_extract(l_shl(r[0], exp0));

    let mut j = 1;
    while j < m {
        (rh[j], rl[j]) = l_extract(l_shl(l_add(r[j], gn), exp0));
        (rh[j + 1], rl[j + 1]) = l_extract(l_shl(l_add(r[j + 1], gp), exp0));
        j += 2;
    }
}

/// `zeros2poly_fx`: the sum and difference polynomials `R`, `S` (Q27, in the cosine domain) whose
/// roots are the even and odd LSPs of `x[0..M]`.
pub fn zeros2poly(x: &[i16], r: &mut [i32], s: &mut [i32]) {
    r[0] = (1 << 27) - 1;
    s[0] = (1 << 27) - 1;
    r[1] = l_msu(0, x[0], 1 << 11);
    s[1] = l_msu(0, x[1], 1 << 11);

    for i in 2..=NC {
        let xr = negate(x[2 * i - 2]);
        let xs = negate(x[2 * i - 1]);
        (r[i], _) = mpy_32_16_ss(r[i - 1], xr);
        (s[i], _) = mpy_32_16_ss(s[i - 1], xs);

        for j in (1..i).rev() {
            let (mh, _) = mpy_32_16_ss(r[j - 1], xr);
            r[j] = l_add(r[j], mh);
            let (mh, _) = mpy_32_16_ss(s[j - 1], xs);
            s[j] = l_add(s[j], mh);
        }
    }
}

/// `polydecomp_fx`: the sum and difference polynomials `R`, `S` (Q27 in the cosine domain) of the
/// AMR-WB IO LP filter `a[0..=M]` (ISP form: `A(z) = (P(z) + Q(z)) / 2`).
pub fn polydecomp(a: &[i16], r: &mut [i32], s: &mut [i32]) {
    let scale = shl(1 << 5, norm_s(a[0]));
    let m = M as usize;

    r[0] = (1 << 20) - 1;
    s[0] = (1 << 20) - 1;

    for i in 0..NC {
        let ltmp1 = l_mult(a[i + 1], scale);
        let ltmp2 = l_msu(ltmp1, a[m - i], scale);
        let ltmp1 = l_mac(ltmp1, a[m - i], scale);
        r[i + 1] = l_sub(ltmp1, r[i]);
        s[i + 1] = l_add(ltmp2, s[i]);
    }

    cheb2poly(r);
    cheb2poly(s);
}

/// `cheb2poly_fx`: converts the Chebyshev series `L_P[0..=M/2]` (Q22) of `polydecomp_fx` in place
/// into polynomial coefficients in the cosine domain.
fn cheb2poly(l_p: &mut [i32]) {
    let mut l_c = [0i32; NC + 1];
    l_c[1..=NC].copy_from_slice(&l_p[1..=NC]);

    l_p[0] = (1 << 27) - 1;

    l_p[1] = l_shl(l_c[1], 6);
    l_p[8] = l_shl(l_c[1], 3);

    l_p[5] = l_sub(l_p[1], l_p[8]);

    l_p[2] = l_shl(l_c[3], 2);
    let l_tmp = l_add(l_c[3], l_p[2]);
    l_p[7] = l_sub(l_tmp, l_sub(l_p[8], l_c[1]));

    l_p[8] = l_shl(l_c[3], 4);
    l_p[3] = l_sub(l_p[8], l_shl(l_p[5], 1));

    l_p[5] = l_sub(l_p[5], l_add(l_p[8], l_p[2]));

    l_p[2] = l_shl(l_c[5], 2);
    l_p[5] = l_add(l_p[5], l_p[2]);

    let l_tmp = l_sub(l_p[7], l_sub(l_p[2], l_c[5]));
    l_p[7] = l_add(l_tmp, l_c[7]);

    l_p[6] = l_shl(l_c[2], 4);
    let l_tmp = l_sub(160 << 20, l_p[6]);
    l_p[4] = l_sub(l_tmp, l_shl(l_c[2], 5));

    let l_tmp = l_add(l_p[6], l_shl(l_c[2], 1));
    l_p[6] = l_sub(l_tmp, 32 << 20);

    l_p[8] = l_shl(l_c[4], 3);
    l_p[4] = l_add(l_p[4], l_p[8]);

    let l_tmp = l_sub(l_p[6], l_p[8]);
    l_p[6] = l_add(l_tmp, l_shl(l_c[6], 1));

    let l_tmp = l_shl(l_c[2], 5);
    l_p[2] = l_sub(l_tmp, 256 << 20);

    let l_tmp = l_add((1 << 21) + 1, l_c[8]);
    let l_tmp = l_shr(l_tmp, 1);
    let l_tmp = l_sub(l_tmp, l_c[2]);
    let l_tmp = l_add(l_tmp, l_c[4]);
    l_p[8] = l_sub(l_tmp, l_c[6]);
}
