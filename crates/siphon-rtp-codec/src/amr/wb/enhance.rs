//! AMR-WB decoder enhancers and the high-frequency (HF) synthesis path (3GPP TS 26.173), ported
//! bit-exact. This tier groups the post-processing that shapes the excitation and rebuilds the
//! 6–7 kHz band that the 12.8 kHz ACELP core cannot carry:
//!
//! - [`voice_factor`] (`voicefac.c`) — the voicing measure that steers tilt / noise enhancement.
//! - [`phase_dispersion`] (`ph_disp.c`) — circular-convolution dispersion of the fixed code.
//! - [`isf_extrapolation`] (`isfextrp.c`) — 16th-order 12.8 kHz ISF → 20th-order 16 kHz ISF.
//! - [`weight_a`] (`weight_a.c`), [`syn_filt`] (`syn_filt.c`), [`hp400_12k8`] (`hp400.c`),
//!   [`filt_6k_7k`] / [`filt_7k`] (`hp6k.c` / `hp7k.c`), [`agc2`] (`agc2.c`) — the HF synth chain.
//! - small vector helpers [`preemph`], [`scale_sig`].

use super::constants::{L_SUBFR, L_SUBFR16K, M, M16K};
use super::lpc::isf_isp;
use super::tables::{FIR_6K_7K, FIR_7K, PH_IMP_LOW, PH_IMP_MID};
use crate::amr::basic_ops::{
    add, div_s, extract_h, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, mult, mult_r, negate,
    norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::amr::math_op::{dot_product12, isqrt};
use crate::amr::oper_32b::{l_extract, mpy_32};

/// 0.9 in Q14 (`pitch_0_9`).
const PITCH_0_9: i16 = 14746;
/// 0.6 in Q14 (`pitch_0_6`).
const PITCH_0_6: i16 = 9830;

/// Voicing factor (−1 = unvoiced … +1 = voiced) in Q15 (`voice_factor`).
///
/// `exc` is the pitch excitation in `Q_exc`, `gain_pit` is Q14, `code` the Q9 fixed code, and
/// `gain_code` is Q0.
pub fn voice_factor(
    exc: &[i16],
    q_exc: i16,
    gain_pit: i16,
    code: &[i16],
    gain_code: i16,
    l_subfr: usize,
) -> i16 {
    let (l_e1, exp1_dot) = dot_product12(exc, exc, l_subfr);
    let mut ener1 = extract_h(l_e1);
    let mut exp1 = sub(exp1_dot, add(q_exc, q_exc));
    let l_tmp = l_mult(gain_pit, gain_pit);
    let exp = norm_l(l_tmp);
    let mut tmp = extract_h(l_shl(l_tmp, exp));
    ener1 = mult(ener1, tmp);
    exp1 = sub(sub(exp1, exp), 10); // 10 -> gain_pit Q14 to Q9

    let (l_e2, exp2_dot) = dot_product12(code, code, l_subfr);
    let mut ener2 = extract_h(l_e2);
    let exp = norm_s(gain_code);
    tmp = shl(gain_code, exp);
    tmp = mult(tmp, tmp);
    ener2 = mult(ener2, tmp);
    let exp2 = sub(exp2_dot, add(exp, exp));

    let i = sub(exp1, exp2);
    if i >= 0 {
        ener1 = shr(ener1, 1);
        ener2 = shr(ener2, add(i, 1));
    } else {
        ener1 = shr(ener1, sub(1, i));
        ener2 = shr(ener2, 1);
    }

    tmp = sub(ener1, ener2);
    ener1 = add(add(ener1, ener2), 1);

    if tmp >= 0 {
        div_s(tmp, ener1)
    } else {
        negate(div_s(negate(tmp), ener1))
    }
}

/// Initialize the 8-word phase-dispersion memory (`Init_Phase_dispersion`).
pub fn init_phase_dispersion(disp_mem: &mut [i16; 8]) {
    disp_mem.fill(0);
}

/// Phase dispersion of the fixed-codebook vector (`Phase_dispersion`). `mode` selects the impulse
/// response level: 0 = high dispersion, 1 = low, 2 = off. `disp_mem[8]` is
/// `[prev_state, prev_gain_code, prev_gain_pit[0..6]]` — note the C reads `prev_gain_pit[i]` for
/// `i` up to 5, overlapping the 8-word buffer exactly as the reference does.
pub fn phase_dispersion(
    gain_code: i16,
    gain_pit: i16,
    code: &mut [i16],
    mode: i16,
    disp_mem: &mut [i16; 8],
) {
    let mut code2 = [0i16; 2 * L_SUBFR];

    // disp_mem layout: [0]=prev_state, [1]=prev_gain_code, [2..8]=prev_gain_pit[0..6].
    let mut state = if sub(gain_pit, PITCH_0_6) < 0 {
        0
    } else if sub(gain_pit, PITCH_0_9) < 0 {
        1
    } else {
        2
    };

    // Shift prev_gain_pit[5..0] (indices 2+5 .. 2+0 in disp_mem).
    for i in (1..=5).rev() {
        disp_mem[2 + i] = disp_mem[2 + i - 1];
    }
    disp_mem[2] = gain_pit;

    if sub(sub(gain_code, disp_mem[1]), shl(disp_mem[1], 1)) > 0 {
        // onset
        if sub(state, 2) < 0 {
            state = add(state, 1);
        }
    } else {
        let mut j = 0i16;
        for i in 0..6 {
            if sub(disp_mem[2 + i], PITCH_0_6) < 0 {
                j = add(j, 1);
            }
        }
        if sub(j, 2) > 0 {
            state = 0;
        }
        if sub(sub(state, disp_mem[0]), 1) > 0 {
            state = sub(state, 1);
        }
    }

    disp_mem[1] = gain_code;
    disp_mem[0] = state;

    // Circular convolution at the selected dispersion level.
    state = add(state, mode);

    if state == 0 {
        for i in 0..L_SUBFR {
            if code[i] != 0 {
                for j in 0..L_SUBFR {
                    code2[i + j] = add(code2[i + j], mult_r(code[i], PH_IMP_LOW[j]));
                }
            }
        }
    } else if sub(state, 1) == 0 {
        for i in 0..L_SUBFR {
            if code[i] != 0 {
                for j in 0..L_SUBFR {
                    code2[i + j] = add(code2[i + j], mult_r(code[i], PH_IMP_MID[j]));
                }
            }
        }
    }
    if sub(state, 2) < 0 {
        for i in 0..L_SUBFR {
            code[i] = add(code2[i], code2[i + L_SUBFR]);
        }
    }
}

/// Pre-emphasis through `1 - mu·z⁻¹` (`Preemph`). `mem` is `x[-1]`, updated to the last input.
pub fn preemph(x: &mut [i16], mu: i16, lg: usize, mem: &mut i16) {
    let temp = x[lg - 1];
    for i in (1..lg).rev() {
        let l_tmp = l_msu(l_deposit_h(x[i]), x[i - 1], mu);
        x[i] = round_word(l_tmp);
    }
    let l_tmp = l_msu(l_deposit_h(x[0]), *mem, mu);
    x[0] = round_word(l_tmp);
    *mem = temp;
}

/// Scale a signal by `2^exp` with rounding and saturation, in place (`Scale_sig`).
pub fn scale_sig(x: &mut [i16], exp: i16) {
    for value in x.iter_mut() {
        let l_tmp = l_shl(l_deposit_h(*value), exp);
        *value = round_word(l_tmp);
    }
}

/// Spectral-expansion weighting `ap[i] = a[i]·gamma^i` (`Weight_a`). `a`/`ap` are `a[0..=m]` (Q12).
pub fn weight_a(a: &[i16], ap: &mut [i16], gamma: i16, m: usize) {
    ap[0] = a[0];
    let mut fac = gamma;
    for i in 1..m {
        ap[i] = round_word(l_mult(a[i], fac));
        fac = round_word(l_mult(fac, gamma));
    }
    ap[m] = round_word(l_mult(a[m], fac));
}

/// Order-`m` LPC synthesis `1/A(z)` in single precision (`Syn_filt`).
///
/// `a` is `a[0..=m]` (Q12), `x` the input (`lg`), `y` the output (`lg`), and `mem[m]` the carried
/// filter state. When `update` is set, the last `m` outputs are written back into `mem`.
pub fn syn_filt(a: &[i16], m: usize, x: &[i16], y: &mut [i16], lg: usize, mem: &mut [i16], update: bool) {
    // y_buf = [mem (m)] ++ [outputs (lg)] on the stack (HF path is one subframe, lg <= L_SUBFR16k).
    let mut y_buf = [0i16; L_SUBFR16K + M16K];
    y_buf[..m].copy_from_slice(&mem[..m]);

    let s = sub(norm_s(a[0]), 2);
    let a0 = shr(a[0], 1); // input / 2

    for i in 0..lg {
        let mut l_tmp = l_mult(x[i], a0);
        for j in 1..=m {
            l_tmp = l_msu(l_tmp, a[j], y_buf[m + i - j]);
        }
        l_tmp = l_shl(l_tmp, add(3, s));
        let out = round_word(l_tmp);
        y_buf[m + i] = out;
        y[i] = out;
    }

    if update {
        mem[..m].copy_from_slice(&y_buf[lg..lg + m]);
    }
}

/// 400 Hz 2nd-order high-pass at 12.8 kHz (`HP400_12k8`); output is divided by 16. `mem[6]` carries
/// `[y2_hi, y2_lo, y1_hi, y1_lo, x0, x1]`.
pub fn hp400_12k8(signal: &mut [i16], lg: usize, mem: &mut [i16; 6]) {
    const B: [i16; 3] = [915, -1830, 915]; // Q12 (/4)
    const A: [i16; 3] = [16384, 29280, -14160]; // Q12 (x4)

    let mut y2_hi = mem[0];
    let mut y2_lo = mem[1];
    let mut y1_hi = mem[2];
    let mut y1_lo = mem[3];
    let mut x0 = mem[4];
    let mut x1 = mem[5];

    for sample in signal.iter_mut().take(lg) {
        let x2 = x1;
        x1 = x0;
        x0 = *sample;

        let mut l_tmp = 16384i32;
        l_tmp = l_mac(l_tmp, y1_lo, A[1]);
        l_tmp = l_mac(l_tmp, y2_lo, A[2]);
        l_tmp = l_shr(l_tmp, 15);
        l_tmp = l_mac(l_tmp, y1_hi, A[1]);
        l_tmp = l_mac(l_tmp, y2_hi, A[2]);
        l_tmp = l_mac(l_tmp, x0, B[0]);
        l_tmp = l_mac(l_tmp, x1, B[1]);
        l_tmp = l_mac(l_tmp, x2, B[2]);
        l_tmp = l_shl(l_tmp, 1); // Q12 -> Q13

        y2_hi = y1_hi;
        y2_lo = y1_lo;
        (y1_hi, y1_lo) = l_extract(l_tmp);

        *sample = round_word(l_tmp);
    }

    *mem = [y2_hi, y2_lo, y1_hi, y1_lo, x0, x1];
}

/// 6–7 kHz band-pass FIR with built-in 1/4 input gain (`Filt_6k_7k`). `mem[30]` carries the tail.
pub fn filt_6k_7k(signal: &mut [i16], lg: usize, mem: &mut [i16; 30]) {
    const L_FIR: usize = 31;
    let mut x = [0i16; L_SUBFR16K + (L_FIR - 1)];
    x[..L_FIR - 1].copy_from_slice(mem);
    for i in 0..lg {
        x[i + L_FIR - 1] = shr(signal[i], 2); // gain of filter = 4
    }
    for i in 0..lg {
        let mut l_tmp = 0i32;
        for j in 0..L_FIR {
            l_tmp = l_mac(l_tmp, x[i + j], FIR_6K_7K[j]);
        }
        signal[i] = round_word(l_tmp);
    }
    mem.copy_from_slice(&x[lg..lg + L_FIR - 1]);
}

/// 7 kHz low-pass FIR (`Filt_7k`). `mem[30]` carries the tail. (nb_bits ≥ 23.85k only.)
pub fn filt_7k(signal: &mut [i16], lg: usize, mem: &mut [i16; 30]) {
    const L_FIR: usize = 31;
    let mut x = [0i16; L_SUBFR16K + (L_FIR - 1)];
    x[..L_FIR - 1].copy_from_slice(mem);
    for i in 0..lg {
        x[i + L_FIR - 1] = signal[i];
    }
    for i in 0..lg {
        let mut l_tmp = 0i32;
        for j in 0..L_FIR {
            l_tmp = l_mac(l_tmp, x[i + j], FIR_7K[j]);
        }
        signal[i] = round_word(l_tmp);
    }
    mem.copy_from_slice(&x[lg..lg + L_FIR - 1]);
}

/// Adaptive gain control matching `sig_out` energy to `sig_in` (`agc2`). nb_bits ≤ 9k strong-pitch
/// path only.
pub fn agc2(sig_in: &[i16], sig_out: &mut [i16], l_trm: usize) {
    let temp = shr(sig_out[0], 2);
    let mut s = l_mult(temp, temp);
    for &v in &sig_out[1..l_trm] {
        let temp = shr(v, 2);
        s = l_mac(s, temp, temp);
    }
    if s == 0 {
        return;
    }
    let mut exp = sub(norm_l(s), 1);
    let gain_out = round_word(l_shl(s, exp));

    let temp = shr(sig_in[0], 2);
    s = l_mult(temp, temp);
    for &v in &sig_in[1..l_trm] {
        let temp = shr(v, 2);
        s = l_mac(s, temp, temp);
    }
    let g0 = if s == 0 {
        0
    } else {
        let i = norm_l(s);
        let gain_in = round_word(l_shl(s, i));
        exp = sub(exp, i);
        let mut s2 = crate::amr::basic_ops::l_deposit_l(div_s(gain_out, gain_in));
        s2 = l_shl(s2, 7);
        s2 = l_shr(s2, exp);
        s2 = isqrt(s2);
        round_word(l_shl(s2, 9))
    };
    for value in sig_out.iter_mut().take(l_trm) {
        *value = extract_h(l_shl(l_mult(*value, g0), 2));
    }
}

/// Convert a 16th-order 12.8 kHz ISF vector into a 20th-order 16 kHz ISP vector, in place
/// (`Isf_Extrapolation`). `hf_isf` is length `M16K`; on return it holds the extrapolated ISPs.
pub fn isf_extrapolation(hf_isf: &mut [i16]) {
    const INV_LENGTH: i16 = 2731; // 1/12
    let mut isf_diff = [0i16; M - 2];
    let mut isf_corr = [0i32; 3];

    hf_isf[M16K - 1] = hf_isf[M - 1];

    for i in 1..(M - 1) {
        isf_diff[i - 1] = sub(hf_isf[i], hf_isf[i - 1]);
    }

    let mut l_tmp = 0i32;
    for i in 3..(M - 1) {
        l_tmp = l_mac(l_tmp, isf_diff[i - 1], INV_LENGTH);
    }
    let mut mean = round_word(l_tmp);

    let mut tmp = 0i16;
    for &d in &isf_diff {
        if sub(d, tmp) > 0 {
            tmp = d;
        }
    }
    let exp = norm_s(tmp);
    for value in isf_diff.iter_mut() {
        *value = shl(*value, exp);
    }
    mean = shl(mean, exp);

    for i in 7..(M - 2) {
        let tmp2 = sub(isf_diff[i], mean);
        let tmp3 = sub(isf_diff[i - 2], mean);
        let l_p = l_mult(tmp2, tmp3);
        let (hi, lo) = l_extract(l_p);
        isf_corr[0] = crate::amr::basic_ops::l_add(isf_corr[0], mpy_32(hi, lo, hi, lo));
    }
    for i in 7..(M - 2) {
        let tmp2 = sub(isf_diff[i], mean);
        let tmp3 = sub(isf_diff[i - 3], mean);
        let l_p = l_mult(tmp2, tmp3);
        let (hi, lo) = l_extract(l_p);
        isf_corr[1] = crate::amr::basic_ops::l_add(isf_corr[1], mpy_32(hi, lo, hi, lo));
    }
    for i in 7..(M - 2) {
        let tmp2 = sub(isf_diff[i], mean);
        let tmp3 = sub(isf_diff[i - 4], mean);
        let l_p = l_mult(tmp2, tmp3);
        let (hi, lo) = l_extract(l_p);
        isf_corr[2] = crate::amr::basic_ops::l_add(isf_corr[2], mpy_32(hi, lo, hi, lo));
    }

    let mut max_corr = if crate::amr::basic_ops::l_sub(isf_corr[0], isf_corr[1]) > 0 {
        0usize
    } else {
        1
    };
    if crate::amr::basic_ops::l_sub(isf_corr[2], isf_corr[max_corr]) > 0 {
        max_corr = 2;
    }
    let max_corr = max_corr + 1; // index step of the strongest correlation

    for i in (M - 1)..(M16K - 1) {
        let tmp = sub(hf_isf[i - 1 - max_corr], hf_isf[i - 2 - max_corr]);
        hf_isf[i] = add(hf_isf[i - 1], tmp);
    }

    // tmp = 7965 + (HfIsf[2] - HfIsf[3] - HfIsf[4]) / 6.
    let mut tmp = add(hf_isf[4], hf_isf[3]);
    tmp = sub(hf_isf[2], tmp);
    tmp = mult(tmp, 5461);
    tmp = add(tmp, 20390);
    if sub(tmp, 19456) > 0 {
        tmp = 19456; // ISF max at 7600 Hz
    }
    tmp = sub(tmp, hf_isf[M - 2]);
    let mut tmp2 = sub(hf_isf[M16K - 2], hf_isf[M - 2]);

    let exp2 = norm_s(tmp2);
    let mut exp = norm_s(tmp);
    exp = sub(exp, 1);
    tmp = shl(tmp, exp);
    tmp2 = shl(tmp2, exp2);
    let coeff = div_s(tmp, tmp2);
    let exp = sub(exp2, exp);

    for i in (M - 1)..(M16K - 1) {
        let tmp = mult(sub(hf_isf[i], hf_isf[i - 1]), coeff);
        isf_diff[i - (M - 1)] = shl(tmp, exp);
    }

    for i in M..(M16K - 1) {
        // ISF(n) - ISF(n-2) >= 500 Hz.
        let tmp = sub(add(isf_diff[i - (M - 1)], isf_diff[i - M]), 1280);
        if tmp < 0 {
            if sub(isf_diff[i - (M - 1)], isf_diff[i - M]) > 0 {
                isf_diff[i - M] = sub(1280, isf_diff[i - (M - 1)]);
            } else {
                isf_diff[i - (M - 1)] = sub(1280, isf_diff[i - M]);
            }
        }
    }

    for i in (M - 1)..(M16K - 1) {
        hf_isf[i] = add(hf_isf[i - 1], isf_diff[i - (M - 1)]);
    }

    for value in hf_isf.iter_mut().take(M16K - 1) {
        *value = mult(*value, 26214); // scale for 16 kHz
    }

    // Convert to ISP, in place (the C aliases input and output of Isf_isp).
    let mut input = [0i16; M16K];
    input.copy_from_slice(&hf_isf[..M16K]);
    isf_isp(&input, hf_isf, M16K);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_factor_extremes() {
        // Pure pitch energy, no code energy → strongly voiced (≈ +1.0 Q15).
        let exc = [1000i16; L_SUBFR];
        let code = [0i16; L_SUBFR];
        let v = voice_factor(&exc, 0, 16384, &code, 0, L_SUBFR);
        assert!(v > 30000, "voiced excitation → near +1.0, got {v}");

        // Pure code energy, no pitch → strongly unvoiced (≈ −1.0).
        let exc0 = [0i16; L_SUBFR];
        let code1 = [400i16; L_SUBFR];
        let u = voice_factor(&exc0, 0, 0, &code1, 4000, L_SUBFR);
        assert!(u < -30000, "unvoiced → near −1.0, got {u}");
    }

    #[test]
    fn phase_dispersion_off_mode_is_identity() {
        // mode 2 (off): high gain_pit forces state 2, state + mode >= 2 → code unchanged.
        let mut code = [0i16; L_SUBFR];
        code[5] = 300;
        code[40] = -200;
        let expected = code;
        let mut mem = [0i16; 8];
        init_phase_dispersion(&mut mem);
        phase_dispersion(100, 16384, &mut code, 2, &mut mem);
        assert_eq!(code, expected, "off mode leaves the code untouched");
    }

    #[test]
    fn weight_a_scales_by_gamma_powers() {
        // a = [4096, 4096, 4096], gamma = 0.5 (Q15) → ap = [4096, 2048, 512].
        let a = [4096i16, 4096, 4096];
        let mut ap = [0i16; 3];
        weight_a(&a, &mut ap, 16384, 2);
        assert_eq!(ap[0], 4096);
        assert_eq!(ap[1], round_word(l_mult(4096, 16384)));
    }

    #[test]
    fn syn_filt_unity_halves_the_input() {
        // a = [1.0, 0, 0]: with a[0]=4096 the filter applies the reference's `input/2` scaling
        // (a0 = a[0]>>1), so a no-prediction filter outputs x/2. Memory carries the last outputs.
        let a = [4096i16, 0, 0];
        let x = [1000i16, -500, 250, 0];
        let mut y = [0i16; 4];
        let mut mem = [0i16; 2];
        syn_filt(&a, 2, &x, &mut y, 4, &mut mem, true);
        assert_eq!(y, [500, -250, 125, 0]);
        assert_eq!(&mem[..], &y[2..4]);
    }

    #[test]
    fn scale_sig_is_a_rounded_shift() {
        let mut x = [100i16, -100, 0];
        scale_sig(&mut x, 1);
        assert_eq!(x, [200, -200, 0]);
        scale_sig(&mut x, -1);
        assert_eq!(x, [100, -100, 0]);
    }

    #[test]
    fn preemph_first_order_difference() {
        // mu = 1.0 (Q15 ~ 32767), x = [a, b] → x'[1] = b - a (approx), mem updated to b.
        let mut x = [16384i16, 8192];
        let mut mem = 0;
        preemph(&mut x, 32767, 2, &mut mem);
        assert_eq!(mem, 8192, "mem holds last input");
    }

    #[test]
    fn hp400_silent_on_zero() {
        let mut sig = [0i16; L_SUBFR];
        let mut mem = [0i16; 6];
        hp400_12k8(&mut sig, L_SUBFR, &mut mem);
        assert!(sig.iter().all(|&v| v == 0));
    }
}
