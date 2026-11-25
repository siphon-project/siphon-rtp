//! Autocorrelation, Levinson-Durbin and Schur recursions and the LPC / LSP helpers of the TCX
//! path (TS 26.442 `lib_com/lpc_tools_fx.c`). Ported: `autocorr_fx`, `E_LPC_lev_dur` /
//! `E_LPC_lev_dur_stab`, `E_LPC_schur`, `E_LPC_a_add_tilt`, `E_LPC_int_lpc_tcx`,
//! `E_LPC_lsp_unweight` and what they need.

use crate::evs::basop::{l_extract_lc, mpy_32_16_1, mpy_32_32, msu_32_16};
use crate::evs::cnst::{GAMMA16K_INV, GAMMA1_INV, M};
use crate::evs::com::basop_util::{divide3232, get_scale_factor32};
use crate::evs::com::lsf_tools::{e_lpc_f_lsp_a_conversion, xsf_to_xsp, xsp_to_xsf};
use crate::evs::com::tools::scale_sig32;
use crate::evs::rom::{P16_GAMMA0_92TO1, P16_GAMMA0_94TO1};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu, l_mult,
    l_negate, l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, round_word, shl, shr, shr_r, sub,
};
use crate::itu::oper_32b::{l_comp, l_extract, mpy_32};
use crate::itu::oper_32b::{mac_32, sqr_32};
use crate::itu::stl2009::{l_mac0, l_mult0, lshr};

/// `MAX_LEN_LP`: the longest LP analysis window, in samples.
const MAX_LEN_LP: usize = 960;

/// `autocorr_fx`: the autocorrelations `r[0..=m]` (DPF `r_h`/`r_l`, normalised; `q_r` the
/// normalisation shift) of `x[0..len]` windowed by `wind` (`rev_flag` 1: read backwards;
/// `sym_flag` 1: a symmetric window given by its first half; otherwise asymmetric).
pub fn autocorr(
    x: &[i16],
    m: i16,
    r_h: &mut [i16],
    r_l: &mut [i16],
    q_r: &mut i16,
    len: i16,
    wind: &[i16],
    rev_flag: i16,
    sym_flag: i16,
) {
    // one sample of slack: the energy loop below reads y[len] when len is odd (no caller passes an
    // odd length; the reference reads an uninitialised stack word there)
    let mut y = [0i16; MAX_LEN_LP + 1];
    let len = usize::try_from(len).unwrap_or(0).min(MAX_LEN_LP);
    if rev_flag == 1 {
        for i in 0..len {
            y[i] = mult_r(x[i], wind[len - i - 1]);
        }
    } else if sym_flag == 1 {
        // symmetric window of even length
        for i in 0..len / 2 {
            y[i] = mult_r(x[i], wind[i]);
        }
        for i in len / 2..len {
            y[i] = mult_r(x[i], wind[len - i - 1]);
        }
    } else {
        for i in 0..len {
            y[i] = mult_r(x[i], wind[i]);
        }
    }

    // energy of the signal
    let mut l_sum = l_deposit_h(16); // sqrt(256), avoid overflow after rounding
    let mut i = 0;
    while i < len {
        let mut l_tmp = l_mult0(y[i], y[i]);
        l_tmp &= !(128 - 1);
        l_tmp = l_mac0(l_tmp, y[i + 1], y[i + 1]);
        l_tmp = l_shr(l_tmp, 7);
        l_sum = l_add(l_sum, l_tmp);
        i += 2;
    }

    // scale the signal to avoid overflow in the autocorrelation
    let mut norm = norm_l(l_sum);
    let mut shift = sub(4, shr(norm, 1));
    if shift > 0 {
        let fact = lshr(-32768, shift);
        for v in &mut y[..len] {
            *v = mult_r(*v, fact);
        }
    } else {
        shift = 0;
    }

    // r[0]
    let mut l_sum = l_mac(1, y[0], y[0]);
    for &v in &y[1..len.max(1)] {
        l_sum = l_mac(l_sum, v, v);
    }
    norm = norm_l(l_sum);
    l_sum = l_shl(l_sum, norm);
    (r_h[0], r_l[0]) = l_extract(l_sum);

    // r[1] to r[m]
    let m = usize::try_from(m).unwrap_or(0);
    for i in 1..=m {
        let mut l_sum = l_mult(y[0], y[i]);
        for j in 1..len.saturating_sub(i) {
            l_sum = l_mac(l_sum, y[j], y[j + i]);
        }
        l_sum = l_shl(l_sum, norm);
        (r_h[i], r_l[i]) = l_extract(l_sum);
    }

    *q_r = sub(norm, shl(shift, 1));
}

/// `TCXLTP_LTP_ORDER`: the highest order the reference sizes the recursion's arrays for.
const MAX_ORDER: usize = 24;

/// `Div_32_opt`: `L_num / (denom_hi, denom_lo)` by one Newton step from `1/denom_hi`.
fn div_32_opt(l_num: i32, denom_hi: i16, denom_lo: i16) -> i32 {
    // First approximation: 1 / L_denom = 1/denom_hi
    let approx = div_s(0x3fff, denom_hi);
    // 1/L_denom = approx * (2.0 - L_denom * approx)
    let mut l_32 = msu_32_16(0x7fff_ffff, denom_hi, denom_lo, approx);
    l_32 = mpy_32_16_1(l_32, approx);
    // L_num * (1/L_denom)
    l_32 = mpy_32_32(l_num, l_32);
    l_shl(l_32, 2)
}

/// `E_LPC_lev_dur`: [`e_lpc_lev_dur_stab`] with the stability bound 0.99945.
pub fn e_lpc_lev_dur(
    rh: &[i16],
    rl: &[i16],
    a: &mut [i16],
    eps_p: Option<&mut [i32]>,
    order: i16,
    mem: Option<&mut [i16]>,
) -> i16 {
    e_lpc_lev_dur_stab(rh, rl, a, eps_p, order, mem, 32750)
}

/// `E_LPC_lev_dur_stab`: Levinson-Durbin recursion from the autocorrelations `(rh, rl)` (DPF) to
/// the LP filter `a[0..=order]` (adaptively scaled; `a[0]` gives the format), the prediction
/// errors in `eps_p`. With `mem`, an unstable or unreliable solution (|k| above `k_max`) is
/// replaced by `mem` and the return value is 1; a good one is saved into `mem`.
pub fn e_lpc_lev_dur_stab(
    rh: &[i16],
    rl: &[i16],
    a: &mut [i16],
    mut eps_p: Option<&mut [i32]>,
    order: i16,
    mem: Option<&mut [i16]>,
    k_max: i16,
) -> i16 {
    let mut ah = [0i16; MAX_ORDER + 1];
    let mut al = [0i16; MAX_ORDER + 1];
    let order = (order.max(1) as usize).min(MAX_ORDER);
    let check = mem.is_some();

    if let Some(eps) = eps_p.as_deref_mut() {
        eps[0] = l_comp(rh[0], rl[0]);
    }
    let mut flag: i16 = 0;

    // K = A[1] = -R[1] / R[0]
    let mut t1 = l_comp(rh[1], rl[1]); // R[1] in Q31
    let mut t2 = l_abs(t1); // abs R[1]
    let mut t0 = l_deposit_l(0);
    if rh[0] != 0 {
        t0 = div_32_opt(t2, rh[0], rl[0]); // R[1]/R[0] in Q31
    }
    if t1 > 0 {
        t0 = l_negate(t0); // -R[1]/R[0]
    }
    let (mut kh, mut kl) = l_extract_lc(t0); // K in DPF
    t0 = l_shr(t0, 4); // A[1] in Q27
    (ah[1], al[1]) = l_extract(t0); // A[1] in DPF

    // Alpha = R[0] * (1-K**2)
    t0 = sqr_32(kh, kl); // K*K in Q31
    t0 = l_abs(t0); // Some case <0 !!
    t0 = l_sub(0x7fff_ffff, t0); // 1 - K*K in Q31
    let (hi, lo) = l_extract_lc(t0); // DPF format
    t0 = mpy_32(rh[0], rl[0], hi, lo); // Alpha in Q31
    if let Some(eps) = eps_p.as_deref_mut() {
        eps[1] = t0;
    }

    // Normalize Alpha
    let mut alp_exp = norm_l(t0);
    t0 = l_shl(t0, alp_exp);
    let (mut alp_h, mut alp_l) = l_extract_lc(t0);

    // ITERATIONS I=2 to m
    for i in 2..=order {
        // t0 = SUM(R[j]*A[i-j], j=1, i-1) + R[i]
        t0 = l_deposit_l(0);
        for j in 1..i {
            t0 = mac_32(t0, rh[j], rl[j], ah[i - j], al[i - j]);
        }
        t0 = l_shl(t0, 4); // result in Q27 -> convert to Q31
                           // Compose and add R[i] in Q3
        t0 = l_mac(t0, rl[i], 1);
        t0 = l_msu(t0, rh[i], -32768);

        // K = -t0 / Alpha
        t1 = l_abs(t0);
        t2 = l_deposit_l(0);
        if alp_h != 0 {
            t2 = div_32_opt(t1, alp_h, alp_l); // abs(t0)/Alpha
        }
        if t0 > 0 {
            t2 = l_negate(t2); // K = -t0/Alpha
        }
        t2 = l_shl(t2, alp_exp); // denormalize; compare to Alpha
        if check && sub(abs_s(extract_h(t2)), k_max) > 0 {
            flag = 1; // Test for unstable filter. If unstable keep old A(z)
        }
        if check && l_sub(l_abs(t2), 5) < 0 {
            flag = 1; // R matrix not reliable (R saturated for many coeff), keep old A(z)
        }
        (kh, kl) = l_extract_lc(t2); // K in DPF

        // An[j] = A[j] + K*A[i-j], j=1 to i-1; An[i] = K
        let k = mult_r(i as i16, 16384) as usize;
        let mut j = 1usize;
        while j < k {
            // Do two iterations together to allow direct update of Ah & Al
            let t0 = mac_32(l_comp(ah[j], al[j]), kh, kl, ah[i - j], al[i - j]);
            let t1 = mac_32(l_comp(ah[i - j], al[i - j]), kh, kl, ah[j], al[j]);
            (ah[j], al[j]) = l_extract(t0);
            (ah[i - j], al[i - j]) = l_extract(t1);
            j += 1;
        }
        if i & 1 == 0 {
            let t0 = mac_32(l_comp(ah[j], al[j]), kh, kl, ah[i - j], al[i - j]);
            (ah[j], al[j]) = l_extract(t0);
        }
        t2 = l_shr(t2, 4); // t2 = K in Q31 -> convert to Q27
        (ah[i], al[i]) = l_extract(t2); // An[i] in Q27

        // Alpha = Alpha * (1-K**2)
        t1 = l_mult(kh, kh); // K*K in Q31
        t0 = l_mac(t1, mult(kh, kl), 2);
        t0 = l_abs(t0); // Some case <0 !!
        t0 = l_sub(0x7fff_ffff, t0); // 1 - K*K in Q31
        let (hi, lo) = l_extract_lc(t0); // DPF format
        t0 = mpy_32(alp_h, alp_l, hi, lo); // Alpha in Q31

        // store denormalized alpha in epsP
        t1 = l_shr(t0, alp_exp);
        if let Some(eps) = eps_p.as_deref_mut() {
            eps[i] = t1;
        }

        // Normalize Alpha
        let jn = norm_l(t0);
        t0 = l_shl(t0, jn);
        (alp_h, alp_l) = l_extract_lc(t0); // DPF format
        alp_exp = add(alp_exp, jn); // Add normalization to alp_exp
    }

    // Adaptive scaling
    t1 = l_deposit_l(0);
    for i in 1..=order {
        t0 = l_comp(ah[i], al[i]);
        t1 = t1.max(l_abs(t0));
    }
    let k = norm_l(t1).min(3);
    a[0] = shl(2048, k);
    for i in 1..=order {
        t0 = l_comp(ah[i], al[i]);
        a[i] = round_word(l_shl(t0, k));
    }

    if let Some(mem) = mem {
        // Enforce stable LPC filter
        if flag != 0 {
            a[..=order].copy_from_slice(&mem[..=order]);
        } else {
            // If stable LPC filter, store into memories
            mem[..=order].copy_from_slice(&a[..=order]);
        }
    }
    flag
}

/// `E_LPC_a_add_tilt`: `Ap(z) = A(z) · (1 - gamma · z^-1)`, the LP filter `a[0..=m]` (Q12) with a
/// first-order pre-emphasis added, normalised to the headroom of its largest coefficient into
/// `ap[0..=m + 1]`.
pub fn e_lpc_a_add_tilt(a: &[i16], ap: &mut [i16], gamma: i16, m: i16) {
    let m = m as usize;
    let mut atmp = [0i32; M as usize + 2];

    let mut a_max = l_mult(16384, a[0]);
    for i in 1..=m {
        atmp[i] = l_sub(l_mult(16384, a[i]), l_mult0(gamma, a[i - 1]));
        a_max = a_max.max(l_abs(atmp[i]));
    }
    atmp[m + 1] = l_negate(l_mult0(gamma, a[m]));
    a_max = a_max.max(l_abs(atmp[m + 1]));
    let shift = norm_l(a_max);
    ap[0] = shl(a[0], sub(shift, 1));
    for i in 1..=m {
        ap[i] = round_word(l_shl(atmp[i], shift));
    }
    ap[m + 1] = round_word(l_shl(atmp[m + 1], shift));
}

/// `E_LPC_int_lpc_tcx`: the LP coefficients `a` (Q12) of a TCX frame from the LSPs of the past
/// frame (weight 1/8) and the present frame (weight 7/8).
pub fn e_lpc_int_lpc_tcx(lsp_old: &[i16], lsp_new: &[i16], a: &mut [i16]) {
    let mut lsp = [0i16; M as usize];

    for i in 0..M as usize {
        // lsp[i] = lsp_old[i]*0.125f + lsp_new[i]*0.875f;
        lsp[i] = round_word(l_mac(l_mult(lsp_old[i], 4096), lsp_new[i], 28672));
    }
    e_lpc_f_lsp_a_conversion(&lsp, a, M);
}

/// `lsp_reorder`: enforce an ascending LSP order with a minimum distance `min_dist` (Q13 · 1.2732)
/// in the `acos()` domain, forwards and then, where the last one is too high, backwards.
fn lsp_reorder(lsp: &mut [i16], min_dist: i16, lpcorder: i16) {
    // Verify the LSF ordering and minimum GAP
    let mut lsp_min = min_dist;
    for value in &mut lsp[..lpcorder as usize] {
        *value = (*value).max(lsp_min);
        lsp_min = add(*value, min_dist);
    }

    // Reverify the LSF ordering and minimum GAP in the reverse order (security)
    let mut lsp_max = sub(32767, min_dist);

    // If danger of unstable filter in case of resonance in HF
    let last = sub(lpcorder, 1);
    if sub(lsp[last as usize], lsp_max) > 0 {
        // Reverify the minimum LSF gap in the reverse sense
        for i in (0..=last as usize).rev() {
            lsp[i] = lsp[i].min(lsp_max);
            lsp_max = sub(lsp[i], min_dist);
        }
    }
}

/// `E_LPC_lsp_unweight`: approximate removal of the perceptual weighting `inv_gamma` (Q14, one of
/// `GAMMA1_INV`, `GAMMA16k_INV`) from the weighted LSPs `lsp_w` (Q15) by a 3-tap FIR on their
/// `acos()` (mean removed); returns the unweighted LSPs `lsp_uw` (Q15) and LSFs `lsf_uw`
/// (Q1 · 1.28). The reference supports `lpcorder == 16` only (asserted); an `inv_gamma` other than
/// the two weightings leaves the outputs untouched (the reference dereferences `NULL`).
pub fn e_lpc_lsp_unweight(
    lsp_w: &[i16],
    lsp_uw: &mut [i16],
    lsf_uw: &mut [i16],
    inv_gamma: i16,
    lpcorder: i16,
) -> i16 {
    let mut lsp_w_orig = [0i16; M as usize];
    let mut lsp_w_diff = [0i16; M as usize];

    // Table selection
    let unw_coeffs: &[[i16; 3]; 16] = if sub(inv_gamma, GAMMA16K_INV) == 0 {
        &P16_GAMMA0_94TO1
    } else if sub(inv_gamma, GAMMA1_INV) == 0 {
        &P16_GAMMA0_92TO1
    } else {
        return 0;
    };
    let order = lpcorder as usize;

    // step = M_PI/(float)(lpcorder+1);
    let step: i16 = 1927;
    let mut mean: i16 = 0;

    // Apply acos() and get mean removed version
    for i in 0..order {
        mean = add(mean, step);
        lsp_w_orig[i] = shl(xsp_to_xsf(lsp_w[i]), 1);
        lsp_w_diff[i] = sub(lsp_w_orig[i], mean);
    }

    // Approximate unweighting by 3-tap FIR
    lsp_uw[0] = add(
        lsp_w_orig[0],
        round_word(l_shl(
            l_mac0(
                l_mult0(unw_coeffs[0][1], lsp_w_diff[0]),
                unw_coeffs[0][2],
                lsp_w_diff[1],
            ),
            2,
        )),
    );
    for i in 1..order - 1 {
        lsp_uw[i] = add(
            lsp_w_orig[i],
            round_word(l_shl(
                l_mac0(
                    l_mac0(
                        l_mult0(unw_coeffs[i][0], lsp_w_diff[i - 1]),
                        unw_coeffs[i][1],
                        lsp_w_diff[i],
                    ),
                    unw_coeffs[i][2],
                    lsp_w_diff[i + 1],
                ),
                2,
            )),
        );
    }
    let i = order - 1;
    lsp_uw[i] = add(
        lsp_w_orig[i],
        round_word(l_shl(
            l_mac0(
                l_mult0(unw_coeffs[i][0], lsp_w_diff[i - 1]),
                unw_coeffs[i][1],
                lsp_w_diff[i],
            ),
            2,
        )),
    );

    // Reorder
    lsp_reorder(lsp_uw, 256, lpcorder);

    // Convert to LSF, apply cos()
    for i in 0..order {
        lsf_uw[i] = shr_r(lsp_uw[i], 1);
        lsp_uw[i] = xsf_to_xsp(lsf_uw[i]);
    }

    0
}

/// `E_LPC_schur`: the Schur recursion on the autocorrelations `r[0..=m]` (scaled in place to full
/// range): the reflection coefficients `refl_coeff[0..m]` (Q15) and the prediction errors
/// `eps_p[0..=m]`. Returns the final `g1[0]` (the zero-lag energy after the recursion).
pub fn e_lpc_schur(r: &mut [i32], refl_coeff: &mut [i16], eps_p: &mut [i32], m: i16) -> i32 {
    let min_eps_p: i32 = 1; // > 0.01f*2^27/2^30
    let mut g0 = [0i32; M as usize];
    let order = m as usize;

    let m_m1 = sub(m, 1);

    let s = get_scale_factor32(r, add(m, 1));
    if s != 0 {
        scale_sig32(r, add(m, 1), s); // scale in-place
    }

    // g1 is r
    g0[..order].copy_from_slice(&r[1..=order]);

    // compute g0[0]/g1[0], where g0[0] < g1[0]
    let mut temp16 = negate(divide3232(g0[0], r[0]));
    refl_coeff[0] = temp16;
    eps_p[0] = r[0];

    let mut i = 0usize;
    while (i as i16) < m_m1 {
        // g1[0] = g0[0]*temp16 + g1[0];
        let tmp32 = mpy_32_16_1(g0[0], temp16);
        r[0] = l_add(r[0], tmp32);

        let m_mi = sub(m, i as i16) as usize;
        for j in 1..m_mi {
            // g0[j-1] = g0[j]        + g1[j]*temp16;
            // g1[j]   = g0[j]*temp16 + g1[j];
            g0[j - 1] = l_add(g0[j], mpy_32_16_1(r[j], temp16));
            r[j] = l_add(r[j], mpy_32_16_1(g0[j], temp16));
        }
        temp16 = negate(divide3232(g0[0], r[0]));
        refl_coeff[i + 1] = temp16;

        // Prediction errors
        let mut tmp_eps_p = l_shr(r[0], s);
        if tmp_eps_p <= 0 {
            tmp_eps_p = l_add(0, min_eps_p);
        }
        eps_p[i + 1] = tmp_eps_p;
        i += 1;
    }

    // epsP[i+1] = g0[0]*temp16 + g1[0];
    let mut tmp_eps_p = l_add(r[0], mpy_32_16_1(g0[0], temp16));
    tmp_eps_p = l_shr(tmp_eps_p, s);
    if tmp_eps_p <= 0 {
        tmp_eps_p = l_add(min_eps_p, 0);
    }
    eps_p[i + 1] = tmp_eps_p;

    // prediction gain = divide3232(L_shr(epsP[0], PRED_GAIN_E), g1[0]);
    r[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tilt_filter_of_a_unit_filter_is_one_minus_gamma() {
        let mut a = [0i16; 17];
        a[0] = 4096;
        let mut ap = [0i16; 18];
        e_lpc_a_add_tilt(&a, &mut ap, 16384, 16);
        // (1 - 0.5 z^-1) normalised by the headroom of the largest coefficient (a gain of 4)
        assert_eq!(ap[0], 16384);
        assert_eq!(ap[1], -8192);
    }

    #[test]
    fn the_schur_recursion_of_white_noise_has_no_reflection() {
        let mut r = [0i32; 17];
        r[0] = 1 << 28;
        let mut refl = [1i16; 16];
        let mut eps = [0i32; 17];
        e_lpc_schur(&mut r, &mut refl, &mut eps, 16);
        assert!(refl.iter().all(|&k| k == 0));
    }
}
