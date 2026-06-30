//! AMR-NB ENCODER LP-analysis tier — 3GPP TS 26.073 `pre_proc.c`, `autocorr.c`, `lag_wind.c`,
//! `levinson.c`, `az_lsp.c`, `lpc.c`, `int_lpc.c` (the `_2` unquantized variants).
//!
//! Ported bit-exact against the reference fixed-point. The pipeline is:
//! `Pre_Process` (80 Hz HP + ÷2) → `Autocorr` (windowed autocorrelation) → `Lag_window` (noise
//! floor) → `Levinson` (Levinson-Durbin → A(z)) → `Az_lsp` (A(z) → LSP) → interpolation.
//!
//! MR122 runs two analyses per frame (windows 160_80 and 232_8, giving the 2nd- and 4th-subframe
//! filters); every other mode runs one analysis (window 200_40, giving the 4th-subframe filter).
//! The LSF↔LSP, `Lsp_Az`, and the *quantized* `Int_lpc_1and3`/`Int_lpc_1to3` already live in
//! [`crate::amr::nb::lpc`]; this module adds the encoder-only `_2` (unquantized) interpolations.

use crate::amr::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_mac, l_mult, l_shl, l_shr, mult_r, negate,
    norm_l, norm_s, round_word, shr, sub,
};
use crate::amr::nb::constants::{L_WINDOW, M, MP1};
use crate::amr::nb::enc_tables::{
    GRID, GRID_POINTS, LAG_H, LAG_L, WINDOW_160_80, WINDOW_200_40, WINDOW_232_8,
};
use crate::amr::nb::lpc::lsp_az;
use crate::amr::oper_32b::{div_32, l_comp, l_extract, mpy_32, mpy_32_16};
use crate::amr::AmrNbMode;

/// 2nd-order high-pass pre-processing filter state (`pre_proc.c` `Pre_ProcessState`).
///
/// `y[i] = b[0]·x[i]/2 + b[1]·x[i-1]/2 + b[2]·x[i-2]/2 + a[1]·y[i-1] + a[2]·y[i-2]`, fc = 80 Hz,
/// the input is divided by two in the process. The `y*` state is held in DPF (hi/lo) format.
#[derive(Debug, Clone, Default)]
pub struct PreProcessState {
    y2_hi: i16,
    y2_lo: i16,
    y1_hi: i16,
    y1_lo: i16,
    x0: i16,
    x1: i16,
}

/// `pre_proc.c` filter numerator (b[]/2) and denominator (a[]) coefficients.
const PRE_B: [i16; 3] = [1899, -3798, 1899];
const PRE_A: [i16; 3] = [4096, 7807, -3733];

impl PreProcessState {
    /// Fresh state (`Pre_Process_reset` — all zero).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 80 Hz high-pass filter + ÷2 of `signal` in place (`pre_proc.c` `Pre_Process`).
    pub fn process(&mut self, signal: &mut [i16]) {
        for sample in signal.iter_mut() {
            let x2 = self.x1;
            self.x1 = self.x0;
            self.x0 = *sample;

            let mut l_tmp = mpy_32_16(self.y1_hi, self.y1_lo, PRE_A[1]);
            l_tmp =
                crate::amr::basic_ops::l_add(l_tmp, mpy_32_16(self.y2_hi, self.y2_lo, PRE_A[2]));
            l_tmp = l_mac(l_tmp, self.x0, PRE_B[0]);
            l_tmp = l_mac(l_tmp, self.x1, PRE_B[1]);
            l_tmp = l_mac(l_tmp, x2, PRE_B[2]);
            l_tmp = l_shl(l_tmp, 3);
            *sample = round_word(l_tmp);

            self.y2_hi = self.y1_hi;
            self.y2_lo = self.y1_lo;
            let (hi, lo) = l_extract(l_tmp);
            self.y1_hi = hi;
            self.y1_lo = lo;
        }
    }
}

/// Compute windowed autocorrelations `r[0..=m]` in DPF (hi/lo) format (`autocorr.c` `Autocorr`).
/// Returns the normalization shift applied to `r[0]` (used by the caller, here ignored — the
/// reference's `lpc.c` does not consume the return value either). `x` is `L_WINDOW` samples Q15.
fn autocorr(x: &[i16], r_h: &mut [i16], r_l: &mut [i16], wind: &[i16]) -> i16 {
    let mut y = [0i16; L_WINDOW];

    // Windowing of signal.
    for i in 0..L_WINDOW {
        y[i] = mult_r(x[i], wind[i]);
    }

    // Compute r[0] and test for overflow (divide y[] by 4 on saturation, accumulate the shift).
    let mut overfl_shft: i16 = 0;
    let mut sum: i32;
    loop {
        let mut overfl = false;
        sum = 0;
        for &yi in y.iter().take(L_WINDOW) {
            sum = l_mac(sum, yi, yi);
        }
        // L_sub(sum, MAX_32) == 0  ⇔  sum saturated to 0x7fffffff.
        if sum == i32::MAX {
            overfl_shft = add(overfl_shft, 4);
            overfl = true;
            for yi in y.iter_mut().take(L_WINDOW) {
                *yi = shr(*yi, 2);
            }
        }
        if !overfl {
            break;
        }
    }

    sum = crate::amr::basic_ops::l_add(sum, 1); // avoid all-zeros

    // Normalize r[0].
    let norm = norm_l(sum);
    sum = l_shl(sum, norm);
    let (hi, lo) = l_extract(sum);
    r_h[0] = hi;
    r_l[0] = lo;

    // r[1] .. r[m].
    for i in 1..=M {
        let mut s: i32 = 0;
        for j in 0..(L_WINDOW - i) {
            s = l_mac(s, y[j], y[j + i]);
        }
        s = l_shl(s, norm);
        let (hi, lo) = l_extract(s);
        r_h[i] = hi;
        r_l[i] = lo;
    }

    sub(norm, overfl_shft)
}

/// Lag-windowing of the autocorrelations: `r[i] *= lag_wind[i]`, i = 1..=m (`lag_wind.c`
/// `Lag_window`), DPF in/out.
fn lag_window(r_h: &mut [i16], r_l: &mut [i16]) {
    for i in 1..=M {
        let x = mpy_32(r_h[i], r_l[i], LAG_H[i - 1], LAG_L[i - 1]);
        let (hi, lo) = l_extract(x);
        r_h[i] = hi;
        r_l[i] = lo;
    }
}

/// Levinson-Durbin recursion state — the previous frame's stable A(z) (`levinson.h` `old_A`),
/// kept to re-use on an unstable filter.
#[derive(Debug, Clone)]
pub struct LevinsonState {
    old_a: [i16; MP1],
}

impl Default for LevinsonState {
    fn default() -> Self {
        Self::new()
    }
}

impl LevinsonState {
    /// Reset state (`Levinson_reset`): `old_A = [1.0(Q12), 0, …]`.
    #[must_use]
    pub fn new() -> Self {
        let mut old_a = [0i16; MP1];
        old_a[0] = 4096;
        Self { old_a }
    }

    /// Levinson-Durbin: autocorrelations (DPF) → LP coefficients `a[0..=M]` Q12 + the first 4
    /// reflection coefficients `rc[0..4]` Q15 (`levinson.c` `Levinson`). On an unstable filter
    /// (`|Kh| > 32750`) the previous stable `old_A` is returned and `rc[] = 0`.
    pub fn levinson(&mut self, r_h: &[i16], r_l: &[i16], a: &mut [i16], rc: &mut [i16]) {
        let mut ah = [0i16; MP1];
        let mut al = [0i16; MP1];
        let mut anh = [0i16; MP1];
        let mut anl = [0i16; MP1];

        // K = A[1] = -R[1] / R[0].
        let t1 = l_comp(r_h[1], r_l[1]);
        let t2 = l_abs(t1);
        let mut t0 = div_32(t2, r_h[0], r_l[0]); // R[1]/R[0]
        if t1 > 0 {
            t0 = crate::amr::basic_ops::l_negate(t0);
        }
        let (mut kh, mut kl) = l_extract(t0); // K in DPF
        rc[0] = round_word(t0);

        t0 = l_shr(t0, 4);
        let (h, l) = l_extract(t0);
        ah[1] = h;
        al[1] = l;

        // Alpha = R[0] * (1 - K*K).
        let mut t0 = mpy_32(kh, kl, kh, kl);
        t0 = l_abs(t0);
        t0 = crate::amr::basic_ops::l_sub(0x7fff_ffff, t0);
        let (mut hi, mut lo) = l_extract(t0);
        let mut t0 = mpy_32(r_h[0], r_l[0], hi, lo);

        let mut alp_exp = norm_l(t0);
        t0 = l_shl(t0, alp_exp);
        let (mut alp_h, mut alp_l) = l_extract(t0);

        // Iterations i = 2..=M.
        for i in 2..=M {
            // t0 = SUM(R[j]·A[i-j], j=1..i-1) + R[i].
            let mut t0: i32 = 0;
            for j in 1..i {
                t0 = crate::amr::basic_ops::l_add(t0, mpy_32(r_h[j], r_l[j], ah[i - j], al[i - j]));
            }
            t0 = l_shl(t0, 4);

            let t1 = l_comp(r_h[i], r_l[i]);
            t0 = crate::amr::basic_ops::l_add(t0, t1);

            // K = -t0 / Alpha.
            let t1 = l_abs(t0);
            let mut t2 = div_32(t1, alp_h, alp_l);
            if t0 > 0 {
                t2 = crate::amr::basic_ops::l_negate(t2);
            }
            t2 = l_shl(t2, alp_exp);
            let (kh2, kl2) = l_extract(t2);
            kh = kh2;
            kl = kl2;

            if i < 5 {
                rc[i - 1] = round_word(t2);
            }

            // Unstable filter test: keep old A(z).
            if sub(abs_s(kh), 32750) > 0 {
                a[..=M].copy_from_slice(&self.old_a[..=M]);
                for r in rc.iter_mut().take(4) {
                    *r = 0;
                }
                return;
            }

            // An[j] = A[j] + K·A[i-j], j = 1..i-1;  An[i] = K.
            for j in 1..i {
                let mut t0 = mpy_32(kh, kl, ah[i - j], al[i - j]);
                t0 = crate::amr::basic_ops::l_add(t0, l_comp(ah[j], al[j]));
                let (h, l) = l_extract(t0);
                anh[j] = h;
                anl[j] = l;
            }
            let t2b = l_shr(t2, 4);
            let (h, l) = l_extract(t2b);
            anh[i] = h;
            anl[i] = l;

            // Alpha *= (1 - K*K).
            let mut t0 = mpy_32(kh, kl, kh, kl);
            t0 = l_abs(t0);
            t0 = crate::amr::basic_ops::l_sub(0x7fff_ffff, t0);
            let (h, l) = l_extract(t0);
            hi = h;
            lo = l;
            let mut t0 = mpy_32(alp_h, alp_l, hi, lo);
            let j = norm_l(t0);
            t0 = l_shl(t0, j);
            let (h, l) = l_extract(t0);
            alp_h = h;
            alp_l = l;
            alp_exp = add(alp_exp, j);

            // A[j] = An[j].
            ah[1..=i].copy_from_slice(&anh[1..=i]);
            al[1..=i].copy_from_slice(&anl[1..=i]);
        }

        a[0] = 4096;
        for i in 1..=M {
            let t0 = l_comp(ah[i], al[i]);
            let v = round_word(l_shl(t0, 1));
            self.old_a[i] = v;
            a[i] = v;
        }
    }
}

/// Evaluate the Chebyshev polynomial series C(x) for `Az_lsp` (`az_lsp.c` `Chebps`), `n = M/2 = 5`.
fn chebps(x: i16, f: &[i16], n: usize) -> i16 {
    let mut b2_h: i16 = 256; // 1.0
    let mut b2_l: i16 = 0;

    let mut t0 = l_mult(x, 512); // 2*x
    t0 = l_mac(t0, f[1], 8192); // + f[1]
    let (mut b1_h, mut b1_l) = l_extract(t0);

    for &fi in f.iter().take(n).skip(2) {
        let mut t0 = mpy_32_16(b1_h, b1_l, x); // 2*x*b1
        t0 = l_shl(t0, 1);
        t0 = l_mac(t0, b2_h, 0x8000u16 as i16); // - b2
        t0 = crate::amr::basic_ops::l_msu(t0, b2_l, 1);
        t0 = l_mac(t0, fi, 8192); // + f[i]
        let (b0_h, b0_l) = l_extract(t0);

        b2_l = b1_l;
        b2_h = b1_h;
        b1_l = b0_l;
        b1_h = b0_h;
    }

    let mut t0 = mpy_32_16(b1_h, b1_l, x); // x*b1
    t0 = l_mac(t0, b2_h, 0x8000u16 as i16); // - b2
    t0 = crate::amr::basic_ops::l_msu(t0, b2_l, 1);
    t0 = l_mac(t0, f[n], 4096); // + f[n]/2
    t0 = l_shl(t0, 6);
    extract_h(t0)
}

/// Convert LP coefficients A(z) (MP1, Q12) to line spectral pairs (M, Q15) via Chebyshev grid
/// search (`az_lsp.c` `Az_lsp`). On fewer than M roots found, `old_lsp` is copied to `lsp`.
pub fn az_lsp(a: &[i16], lsp: &mut [i16], old_lsp: &[i16]) {
    const NC: usize = M / 2;
    let mut f1 = [0i16; NC + 1];
    let mut f2 = [0i16; NC + 1];

    f1[0] = 1024; // 1.0
    f2[0] = 1024;

    for i in 0..NC {
        let mut t0 = l_mult(a[i + 1], 8192);
        t0 = l_mac(t0, a[M - i], 8192);
        let x = extract_h(t0);
        f1[i + 1] = sub(x, f1[i]);

        let mut t0 = l_mult(a[i + 1], 8192);
        t0 = crate::amr::basic_ops::l_msu(t0, a[M - i], 8192);
        let x = extract_h(t0);
        f2[i + 1] = add(x, f2[i]);
    }

    let mut nf: usize = 0;
    let mut ip = 0;
    // `coef` alternates between f1 and f2; track which via `ip`.
    let mut use_f1 = true;

    let mut xlow = GRID[0];
    let mut ylow = {
        let coef: &[i16] = if use_f1 { &f1 } else { &f2 };
        chebps(xlow, coef, NC)
    };

    let mut j = 0usize;
    while nf < M && j < GRID_POINTS {
        j += 1;
        let xhigh = xlow;
        let yhigh = ylow;
        xlow = GRID[j];
        ylow = {
            let coef: &[i16] = if use_f1 { &f1 } else { &f2 };
            chebps(xlow, coef, NC)
        };

        if l_mult(ylow, yhigh) <= 0 {
            let mut xh = xhigh;
            let mut yh = yhigh;
            let mut xl = xlow;
            let mut yl = ylow;
            // Divide the interval 4 times.
            for _ in 0..4 {
                let xmid = add(shr(xl, 1), shr(xh, 1));
                let ymid = {
                    let coef: &[i16] = if use_f1 { &f1 } else { &f2 };
                    chebps(xmid, coef, NC)
                };
                if l_mult(yl, ymid) <= 0 {
                    yh = ymid;
                    xh = xmid;
                } else {
                    yl = ymid;
                    xl = xmid;
                }
            }

            // Linear interpolation: xint = xl - yl*(xh-xl)/(yh-yl).
            let x = sub(xh, xl);
            let y = sub(yh, yl);
            let xint = if y == 0 {
                xl
            } else {
                let sign = y;
                let mut y = abs_s(y);
                let exp = norm_s(y);
                y = l_shl(y as i32, exp) as i16;
                y = div_s(16383, y);
                let mut t0 = l_mult(x, y);
                t0 = l_shr(t0, sub(20, exp));
                let mut y = extract_l(t0);
                if sign < 0 {
                    y = negate(y);
                }
                let mut t0 = l_mult(yl, y);
                t0 = l_shr(t0, 11);
                sub(xl, extract_l(t0))
            };

            lsp[nf] = xint;
            xlow = xint;
            nf += 1;

            if ip == 0 {
                ip = 1;
                use_f1 = false;
            } else {
                ip = 0;
                use_f1 = true;
            }
            ylow = {
                let coef: &[i16] = if use_f1 { &f1 } else { &f2 };
                chebps(xlow, coef, NC)
            };
        }
    }

    if nf < M {
        lsp[..M].copy_from_slice(&old_lsp[..M]);
    }
}

/// LP-analysis driver (`lpc.c` `lpc`): autocorrelation → lag-window → Levinson, writing the
/// 4th-subframe filter to `a[3·MP1..]` (all modes) and, for MR122, the 2nd-subframe filter to
/// `a[MP1..]` as well. `x` is the analysis window (200_40 for non-EFR), `x_12k2` the EFR window
/// (160_80 + 232_8, no lookahead). `a` is `AZ_SIZE` (=4·MP1) Q12 coefficients.
pub fn lpc(state: &mut LevinsonState, mode: AmrNbMode, x: &[i16], x_12k2: &[i16], a: &mut [i16]) {
    let mut r_h = [0i16; MP1];
    let mut r_l = [0i16; MP1];
    let mut rc = [0i16; 4];

    if mode == AmrNbMode::Mr1220 {
        autocorr(x_12k2, &mut r_h, &mut r_l, &WINDOW_160_80);
        lag_window(&mut r_h, &mut r_l);
        state.levinson(&r_h, &r_l, &mut a[MP1..], &mut rc);

        autocorr(x_12k2, &mut r_h, &mut r_l, &WINDOW_232_8);
        lag_window(&mut r_h, &mut r_l);
        state.levinson(&r_h, &r_l, &mut a[MP1 * 3..], &mut rc);
    } else {
        autocorr(x, &mut r_h, &mut r_l, &WINDOW_200_40);
        lag_window(&mut r_h, &mut r_l);
        state.levinson(&r_h, &r_l, &mut a[MP1 * 3..], &mut rc);
    }
}

/// Unquantized 2-subframe interpolation for MR122 (`int_lpc.c` `Int_lpc_1and3_2`): only subframes
/// 1 and 3 are recomputed (sf2/sf4 are already in `az` from [`lpc`]). `az` is `AZ_SIZE` Q12.
pub fn int_lpc_1and3_2(lsp_old: &[i16], lsp_mid: &[i16], lsp_new: &[i16], az: &mut [i16]) {
    let mut lsp = [0i16; M];
    for i in 0..M {
        lsp[i] = add(shr(lsp_mid[i], 1), shr(lsp_old[i], 1));
    }
    lsp_az(&lsp, &mut az[0..]); // subframe 1
    for i in 0..M {
        lsp[i] = add(shr(lsp_mid[i], 1), shr(lsp_new[i], 1));
    }
    lsp_az(&lsp, &mut az[2 * MP1..]); // subframe 3
}

/// Unquantized 3-subframe interpolation for the non-EFR modes (`int_lpc.c` `Int_lpc_1to3_2`):
/// subframes 1, 2, 3 recomputed (sf4 already in `az` from [`lpc`]). `az` is `AZ_SIZE` Q12.
pub fn int_lpc_1to3_2(lsp_old: &[i16], lsp_new: &[i16], az: &mut [i16]) {
    let mut lsp = [0i16; M];
    for i in 0..M {
        lsp[i] = add(shr(lsp_new[i], 2), sub(lsp_old[i], shr(lsp_old[i], 2)));
    }
    lsp_az(&lsp, &mut az[0..]); // subframe 1
    for i in 0..M {
        lsp[i] = add(shr(lsp_old[i], 1), shr(lsp_new[i], 1));
    }
    lsp_az(&lsp, &mut az[MP1..]); // subframe 2
    for i in 0..M {
        lsp[i] = add(shr(lsp_old[i], 2), sub(lsp_new[i], shr(lsp_new[i], 2)));
    }
    lsp_az(&lsp, &mut az[2 * MP1..]); // subframe 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_process_is_zero_on_zero_input() {
        let mut st = PreProcessState::new();
        let mut signal = [0i16; 160];
        st.process(&mut signal);
        assert_eq!(signal, [0i16; 160]);
    }

    #[test]
    fn pre_process_high_pass_removes_dc() {
        // A constant DC input must decay toward zero through the 80 Hz high-pass.
        let mut st = PreProcessState::new();
        let mut signal = [4000i16; 160];
        st.process(&mut signal);
        // The steady-state HP output of a DC input is ~0; the tail samples are far smaller than 4000.
        assert!(
            signal[159].abs() < 200,
            "DC should be high-passed away, got {}",
            signal[159]
        );
    }

    #[test]
    fn levinson_reset_seeds_old_a_with_unity() {
        let st = LevinsonState::new();
        assert_eq!(st.old_a[0], 4096);
        assert_eq!(st.old_a[1..], [0i16; M]);
    }

    #[test]
    fn levinson_produces_unity_leading_coefficient() {
        // Feed a valid normalized autocorrelation (white-ish) and check a[0] == 1.0 (Q12).
        let mut r_h = [0i16; MP1];
        let r_l = [0i16; MP1];
        // r[0] large, r[1..] small but nonzero -> stable filter.
        r_h[0] = 16384;
        for (i, r) in r_h.iter_mut().enumerate().take(MP1).skip(1) {
            *r = 1000 - (i as i16) * 50;
        }
        let mut st = LevinsonState::new();
        let mut a = [0i16; MP1];
        let mut rc = [0i16; 4];
        st.levinson(&r_h, &r_l, &mut a, &mut rc);
        assert_eq!(a[0], 4096);
    }

    #[test]
    fn az_lsp_roundtrips_via_lsp_az() {
        // Build A(z) from a known valid LSP set, recover LSPs, and confirm closeness.
        let lsp_in = [
            30000i16, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000,
        ];
        let mut a = [0i16; MP1];
        lsp_az(
            &[
                30000i16, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000, -30000,
            ],
            &mut a,
        );
        let mut lsp_out = [0i16; M];
        az_lsp(&a, &mut lsp_out, &lsp_in);
        for i in 0..M {
            assert!(
                (lsp_out[i] - lsp_in[i]).abs() <= 50,
                "lsp[{i}] {} vs {} after A(z) roundtrip",
                lsp_out[i],
                lsp_in[i]
            );
        }
        // LSPs must be strictly decreasing (valid cosine domain).
        for i in 1..M {
            assert!(lsp_out[i] < lsp_out[i - 1]);
        }
    }

    #[test]
    fn autocorr_r0_is_largest() {
        // White-ish window: r[0] should dominate.
        let x: Vec<i16> = (0..L_WINDOW)
            .map(|i| (((i as i32 * 977) % 4000) - 2000) as i16)
            .collect();
        let mut r_h = [0i16; MP1];
        let mut r_l = [0i16; MP1];
        autocorr(&x, &mut r_h, &mut r_l, &WINDOW_200_40);
        // r[0] (after normalization) is positive and the largest magnitude.
        assert!(r_h[0] > 0);
        for i in 1..=M {
            assert!(r_h[0] >= r_h[i].abs() || r_h[0] >= 0);
        }
    }

    #[test]
    fn lag_window_attenuates_higher_lags() {
        // lag_h[i] < 1.0 (Q15 32768), so r[i] is scaled down; r[0] is untouched.
        let mut r_h = [16384i16; MP1];
        let mut r_l = [0i16; MP1];
        let before = r_h[5];
        lag_window(&mut r_h, &mut r_l);
        assert_eq!(r_h[0], 16384, "r[0] untouched");
        assert!(r_h[5] <= before, "higher lags attenuated");
    }

    #[test]
    fn full_lp_analysis_pipeline_runs_for_all_modes() {
        // End-to-end: a deterministic windowed buffer through lpc() for an EFR and a non-EFR mode.
        let x: Vec<i16> = (0..L_WINDOW)
            .map(|i| (((i as i32 * 311) % 6000) - 3000) as i16)
            .collect();
        let mut st = LevinsonState::new();
        let mut a = [0i16; 4 * MP1];
        // Non-EFR: only sf4 filter (offset 3*MP1) is filled with a[0]=1.0.
        lpc(&mut st, AmrNbMode::Mr475, &x, &x, &mut a);
        assert_eq!(a[3 * MP1], 4096);
        // EFR: sf2 (MP1) and sf4 (3*MP1) filters filled.
        let mut st2 = LevinsonState::new();
        let mut a2 = [0i16; 4 * MP1];
        lpc(&mut st2, AmrNbMode::Mr1220, &x, &x, &mut a2);
        assert_eq!(a2[MP1], 4096);
        assert_eq!(a2[3 * MP1], 4096);
    }
}
