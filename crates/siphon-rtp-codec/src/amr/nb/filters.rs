//! AMR-NB synthesis / post-filter primitives — 3GPP TS 26.073 `syn_filt.c`, `residu.c`,
//! `weight_a.c`, `preemph.c`, `agc.c`, `post_pro.c`. Ported bit-exact.

use crate::amr::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_l, l_mac, l_msu, l_mult, l_shl, l_shr, mult,
    norm_l, round_word, sub,
};
use crate::amr::nb::constants::M;
use crate::amr::nb::math_nb::inv_sqrt;
use crate::amr::oper_32b::{l_extract, mpy_32_16};

/// Synthesis (all-pole) filter `1/A(z)` (`syn_filt.c` `Syn_filt`). Filters `x[0..lg]` into `y[0..lg]`
/// using LPC `a[0..M]` (Q12) and the `M`-word `mem`. If `update`, `mem` is refreshed with the last
/// `M` outputs. The internal `L_shl(s, 3)` + `round` saturate — bit-exact with the reference (this is
/// what trips the decoder's overflow re-scale).
pub fn syn_filt(a: &[i16], x: &[i16], y: &mut [i16], lg: usize, mem: &mut [i16], update: bool) {
    let mut overflow = false;
    syn_filt_overflow(a, x, y, lg, mem, update, &mut overflow);
}

/// As [`syn_filt`], but reports whether the saturating `L_shl(s, 3)` overflowed on any sample
/// (`overflow` is set, never cleared). The decoder reads this to trigger its excitation re-scale
/// (`dec_amr.c`: `Overflow = 0; Syn_filt(...); if (Overflow) ...`). Bit-exact: the reference's global
/// `Overflow` is set inside `L_shl` when the 32-bit value cannot be shifted left by 3 without
/// saturating; `round`'s `L_add` cannot overflow here because the input is already 16-bit-range
/// after the (possibly saturated) `L_shl`.
pub fn syn_filt_overflow(
    a: &[i16],
    x: &[i16],
    y: &mut [i16],
    lg: usize,
    mem: &mut [i16],
    update: bool,
    overflow: &mut bool,
) {
    // tmp holds M memory words followed by the lg outputs (max lg = L_SUBFR = 40).
    let mut tmp = [0i16; M + 40];
    tmp[..M].copy_from_slice(&mem[..M]);

    for i in 0..lg {
        let mut s = l_mult(x[i], a[0]);
        for j in 1..=M {
            // yy[-j] where yy currently points at tmp[M+i]
            s = l_msu(s, a[j], tmp[M + i - j]);
        }
        // L_shl(s, 3) sets Overflow if the value saturates.
        let shifted = l_shl(s, 3);
        if (s > 0 && shifted == i32::MAX && s != i32::MAX)
            || (s < 0 && shifted == i32::MIN && s != i32::MIN)
        {
            *overflow = true;
        }
        s = shifted;
        tmp[M + i] = round_word(s);
    }

    y[..lg].copy_from_slice(&tmp[M..M + lg]);

    if update {
        mem[..M].copy_from_slice(&y[lg - M..lg]);
    }
}

/// LP residual filter `A(z)` (`residu.c` `Residu`). `x` must carry `M` history samples before
/// `x[0]` (i.e. `x` is a slice whose index 0 is the current sample and negative offsets are valid);
/// here we pass `x` as a slice with `base` pointing at the current sample so `x[base - j]` is read.
pub fn residu(a: &[i16], x: &[i16], base: usize, y: &mut [i16], lg: usize) {
    for i in 0..lg {
        let mut s = l_mult(x[base + i], a[0]);
        for j in 1..=M {
            s = l_mac(s, a[j], x[base + i - j]);
        }
        s = l_shl(s, 3);
        y[i] = round_word(s);
    }
}

/// Spectral expansion of the LPC by a per-coefficient factor (`weight_a.c` `Weight_Ai`).
/// `a_exp[i] = round(a[i] * fac[i-1])` for `i = 1..=M`, `a_exp[0] = a[0]`.
pub fn weight_ai(a: &[i16], fac: &[i16], a_exp: &mut [i16]) {
    a_exp[0] = a[0];
    for i in 1..=M {
        a_exp[i] = round_word(l_mult(a[i], fac[i - 1]));
    }
}

/// Pre-emphasis filter `1 - g·z^-1` applied back-to-front (`preemph.c` `preemphasis`).
/// `mem_pre` carries the previous block's last input sample.
pub fn preemphasis(mem_pre: &mut i16, signal: &mut [i16], g: i16, l: usize) {
    let temp = signal[l - 1];
    // *p1 = signal[i] - g*signal[i-1] for i = l-1 down to 1
    for i in (1..l).rev() {
        signal[i] = sub(signal[i], mult(g, signal[i - 1]));
    }
    signal[0] = sub(signal[0], mult(g, *mem_pre));
    *mem_pre = temp;
}

/// Energy of `in` with a ÷4 pre-scale to avoid overflow (`agc.c` `energy_old`).
fn energy_old(sig: &[i16], l: usize) -> i32 {
    let temp = extract_l(l_shr(l_deposit_l(sig[0]), 2));
    let mut s = l_mult(temp, temp);
    for &v in sig.iter().take(l).skip(1) {
        let temp = extract_l(l_shr(l_deposit_l(v), 2));
        s = l_mac(s, temp, temp);
    }
    s
}

/// Overflow-aware energy of `in` (`agc.c` `energy_new`). Falls back to [`energy_old`] when the
/// saturating sum reaches `MAX_32` — bit-exact with the reference, which checks the final sum only
/// (`L_sub(s, MAX_32) == 0`) using its global `Overflow` flag, equivalent to `s == MAX_32` here
/// because `L_mac` saturates exactly to `MAX_32`.
fn energy_new(sig: &[i16], l: usize) -> i32 {
    let mut s = l_mult(sig[0], sig[0]);
    for &v in sig.iter().take(l).skip(1) {
        s = l_mac(s, v, v);
    }
    if s == i32::MAX {
        energy_old(sig, l)
    } else {
        l_shr(s, 4)
    }
}

/// Adaptive gain control state (`agc.c` `agcState`).
#[derive(Debug, Clone)]
pub struct AgcState {
    /// Smoothed gain, Q12 (`past_gain`).
    pub past_gain: i16,
}

impl Default for AgcState {
    fn default() -> Self {
        Self::new()
    }
}

impl AgcState {
    /// Reset: `past_gain = 4096` (1.0 in Q12) (`agc_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self { past_gain: 4096 }
    }
}

/// Scale `sig_out` to match `sig_in`'s energy, smoothed by `agc_fac` (`agc.c` `agc`).
pub fn agc(st: &mut AgcState, sig_in: &[i16], sig_out: &mut [i16], agc_fac: i16, l_trm: usize) {
    let s = energy_new(sig_out, l_trm);
    if s == 0 {
        st.past_gain = 0;
        return;
    }
    let mut exp = sub(norm_l(s), 1);
    let gain_out = round_word(l_shl(s, exp));

    let s = energy_new(sig_in, l_trm);
    let g0 = if s == 0 {
        0
    } else {
        let i = norm_l(s);
        let gain_in = round_word(l_shl(s, i));
        exp = sub(exp, i);
        let mut s = l_deposit_l(div_s(gain_out, gain_in));
        s = l_shl(s, 7);
        s = l_shr(s, exp);
        let s = inv_sqrt(s);
        let i = round_word(l_shl(s, 9));
        mult(i, sub(32767, agc_fac))
    };

    let mut gain = st.past_gain;
    for v in sig_out.iter_mut().take(l_trm) {
        gain = mult(gain, agc_fac);
        gain = add(gain, g0);
        *v = extract_h(l_shl(l_mult(*v, gain), 3));
    }
    st.past_gain = gain;
}

/// Stateless gain control matching `sig_in` energy exactly (`agc.c` `agc2`).
pub fn agc2(sig_in: &[i16], sig_out: &mut [i16], l_trm: usize) {
    let s = energy_new(sig_out, l_trm);
    if s == 0 {
        return;
    }
    let mut exp = sub(norm_l(s), 1);
    let gain_out = round_word(l_shl(s, exp));

    let s = energy_new(sig_in, l_trm);
    let g0 = if s == 0 {
        0
    } else {
        let i = norm_l(s);
        let gain_in = round_word(l_shl(s, i));
        exp = sub(exp, i);
        let mut s = l_deposit_l(div_s(gain_out, gain_in));
        s = l_shl(s, 7);
        s = l_shr(s, exp);
        let s = inv_sqrt(s);
        round_word(l_shl(s, 9))
    };

    for v in sig_out.iter_mut().take(l_trm) {
        *v = extract_h(l_shl(l_mult(*v, g0), 3));
    }
}

/// Output high-pass (60 Hz) + 15→16 bit upscale state (`post_pro.c` `Post_ProcessState`).
#[derive(Debug, Clone, Default)]
pub struct PostProcessState {
    y2_hi: i16,
    y2_lo: i16,
    y1_hi: i16,
    y1_lo: i16,
    x0: i16,
    x1: i16,
}

impl PostProcessState {
    /// Reset: all state to zero (`Post_Process_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// 60 Hz high-pass filter + ×2 (`post_pro.c` `Post_Process`). Filters `signal[0..lg]` in place.
pub fn post_process(st: &mut PostProcessState, signal: &mut [i16], lg: usize) {
    // b[3]={7699,-15398,7699}, a[3]={8192,15836,-7667}
    const B: [i16; 3] = [7699, -15398, 7699];
    const A: [i16; 3] = [8192, 15836, -7667];
    for s in signal.iter_mut().take(lg) {
        let x2 = st.x1;
        st.x1 = st.x0;
        st.x0 = *s;
        let mut l_tmp = mpy_32_16(st.y1_hi, st.y1_lo, A[1]);
        l_tmp = l_add(l_tmp, mpy_32_16(st.y2_hi, st.y2_lo, A[2]));
        l_tmp = l_mac(l_tmp, st.x0, B[0]);
        l_tmp = l_mac(l_tmp, st.x1, B[1]);
        l_tmp = l_mac(l_tmp, x2, B[2]);
        l_tmp = l_shl(l_tmp, 2);
        *s = round_word(l_shl(l_tmp, 1)); // ×2 output
        st.y2_hi = st.y1_hi;
        st.y2_lo = st.y1_lo;
        let (hi, lo) = l_extract(l_tmp);
        st.y1_hi = hi;
        st.y1_lo = lo;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_filt_identity_filter_passes_input() {
        // A(z) = [4096,0,..0] is gain 1.0 in Q12; 1/A(z) = identity (with the L_shl(.,3) scaling).
        let mut a = [0i16; M + 1];
        a[0] = 4096;
        let x = [100i16, -50, 25, 0, 10, 0, 0, 0, 0, 0];
        let mut y = [0i16; 10];
        let mut mem = [0i16; M];
        syn_filt(&a, &x, &mut y, 10, &mut mem, true);
        // With identity LPC, y == x (round of L_shl(L_mult(x,4096),3) = x).
        assert_eq!(&y[..], &x[..]);
        // mem updated with last M outputs.
        assert_eq!(&mem[..], &y[0..M]);
    }

    #[test]
    fn residu_then_syn_filt_roundtrips_identity() {
        let mut a = [0i16; M + 1];
        a[0] = 4096;
        // x with M leading history zeros, then a signal.
        let mut x = [0i16; M + 10];
        for (i, v) in x.iter_mut().enumerate().skip(M) {
            *v = ((i as i16) - M as i16) * 7;
        }
        let mut res = [0i16; 10];
        residu(&a, &x, M, &mut res, 10);
        // identity A(z): residual == input signal
        assert_eq!(&res[..], &x[M..M + 10]);
    }

    #[test]
    fn weight_ai_scales_coefficients() {
        let a = [4096i16, 2000, 1000, 500, 250, 125, 60, 30, 15, 7, 3];
        let fac = [16384i16; M]; // 0.5 in Q15
        let mut out = [0i16; M + 1];
        weight_ai(&a, &fac, &mut out);
        assert_eq!(out[0], 4096);
        // a_exp[1] = round(2000 * 16384) = round(2000<<14 ...) = 1000
        assert_eq!(out[1], 1000);
    }

    #[test]
    fn preemphasis_first_order_difference() {
        let mut mem = 0i16;
        let mut sig = [1000i16, 1000, 1000, 1000];
        preemphasis(&mut mem, &mut sig, 16384, 4); // g = 0.5
                                                   // sig[i] -= 0.5*sig[i-1]; back-to-front. sig[3]=1000-500=500, etc. sig[0]=1000-0.5*mem(0).
        assert_eq!(sig[0], 1000);
        assert_eq!(sig[1], 500);
        assert_eq!(sig[2], 500);
        assert_eq!(sig[3], 500);
        assert_eq!(mem, 1000); // last input saved
    }

    #[test]
    fn agc_scales_toward_input_energy() {
        let mut st = AgcState::new();
        let sig_in = [1000i16; 40];
        let mut sig_out = [200i16; 40];
        agc(&mut st, &sig_in, &mut sig_out, 29491, 40);
        // Output should be amplified toward the higher-energy input (monotone increase here).
        assert!(sig_out.iter().any(|&v| v.abs() > 200));
    }

    #[test]
    fn post_process_doubles_and_filters_without_panic() {
        let mut st = PostProcessState::new();
        let original = [100i16, -100, 200, -200, 0, 50, -50, 0];
        let mut sig = original;
        post_process(&mut st, &mut sig, 8);
        // The HP filter + ×2 changes the signal and leaves filter state non-trivial.
        assert_ne!(sig, original);
        assert!(st.y1_hi != 0 || st.y1_lo != 0);
    }
}
