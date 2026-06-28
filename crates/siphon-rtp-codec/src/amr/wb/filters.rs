//! AMR-WB de-emphasis filters (3GPP TS 26.173 `deemph.c`), ported bit-exact on [`crate::amr::basic_ops`].
//!
//! De-emphasis is the 1-pole inverse of the encoder's pre-emphasis: `y[n] = x[n] + mu·y[n-1]`. The
//! synthesis path uses [`deemph_32`], which consumes the synthesis filter's split hi/lo signal;
//! [`deemph`] / [`deemph2`] are the single-precision variants used elsewhere. Each carries `mem`
//! (`y[-1]`) across calls.

use crate::amr::basic_ops::{
    add, extract_h, extract_l, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, mult, norm_s,
    round_word, shl, shr, sub,
};
use crate::amr::oper_32b::l_extract;
use crate::amr::wb::constants::L_SUBFR;

/// 50 Hz high-pass biquad numerator (Q12) — `HP50.C`.
const HP50_B: [i16; 3] = [4053, -8106, 4053];
/// 50 Hz high-pass biquad denominator (Q12, ×2) — `HP50.C`.
const HP50_A: [i16; 3] = [8192, 16211, -8021];

/// Up-sampling filter half-length (`NB_COEF_UP`).
const NB_COEF_UP: usize = 12;
/// 1/5 in Q15 (`INV_FAC5`).
const INV_FAC5: i16 = 6554;
/// Up-sampling phase resolution (`FAC5`) and step (`FAC4`).
const FAC5: i16 = 5;
const FAC4: i16 = 4;
/// 5/4 in Q14 (`UP_FAC`).
const UP_FAC: i16 = 20480;

/// 1/5-resolution 12.8 → 16 kHz interpolation filter, Q14 (`decim54.c` `fir_up`).
#[rustfmt::skip]
static FIR_UP: [i16; 120] = [
    -1, -4, -7, -6, 0,            12, 24, 30, 23, 0,
    -33, -62, -73, -52, 0,        68, 124, 139, 96, 0,
    -119, -213, -235, -160, 0,    191, 338, 368, 247, 0,
    -291, -510, -552, -369, 0,    430, 752, 812, 542, 0,
    -634, -1111, -1204, -809, 0,  963, 1708, 1881, 1288, 0,
    -1616, -2974, -3432, -2496, 0, 3792, 8219, 12368, 15317, 16384,
    15317, 12368, 8219, 3792, 0,  -2496, -3432, -2974, -1616, 0,
    1288, 1881, 1708, 963, 0,     -809, -1204, -1111, -634, 0,
    542, 812, 752, 430, 0,        -369, -552, -510, -291, 0,
    247, 368, 338, 191, 0,        -160, -235, -213, -119, 0,
    96, 139, 124, 68, 0,          -52, -73, -62, -33, 0,
    23, 30, 24, 12, 0,            -6, -7, -4, -1, 0,
];

/// De-emphasis on a Q15-deposited signal: `y[n] = x[n] + mu·y[n-1]`, in place. `mem` is `y[-1]`.
pub fn deemph(x: &mut [i16], mu: i16, mem: &mut i16) {
    if x.is_empty() {
        return;
    }
    let mut l_tmp = l_deposit_h(x[0]);
    l_tmp = l_mac(l_tmp, *mem, mu);
    x[0] = round_word(l_tmp);
    for i in 1..x.len() {
        l_tmp = l_deposit_h(x[i]);
        l_tmp = l_mac(l_tmp, x[i - 1], mu);
        x[i] = round_word(l_tmp);
    }
    *mem = x[x.len() - 1];
}

/// As [`deemph`] but with the input scaled by 0.5 (Q14 deposit) — the `Deemph2` variant.
pub fn deemph2(x: &mut [i16], mu: i16, mem: &mut i16) {
    if x.is_empty() {
        return;
    }
    let mut l_tmp = l_mult(x[0], 16384);
    l_tmp = l_mac(l_tmp, *mem, mu);
    x[0] = round_word(l_tmp);
    for i in 1..x.len() {
        l_tmp = l_mult(x[i], 16384);
        l_tmp = l_mac(l_tmp, x[i - 1], mu);
        x[i] = round_word(l_tmp);
    }
    *mem = x[x.len() - 1];
}

/// De-emphasis on the synthesis filter's split signal (`x_hi` bits 31..16, `x_lo` bits 15..4),
/// writing the 16-bit output to `y`. `mem` is `y[-1]`.
pub fn deemph_32(x_hi: &[i16], x_lo: &[i16], y: &mut [i16], mu: i16, mem: &mut i16) {
    let len = y.len();
    if len == 0 {
        return;
    }
    let fac = shr(mu, 1); // Q15 → Q14

    let mut l_tmp = l_deposit_h(x_hi[0]);
    l_tmp = l_mac(l_tmp, x_lo[0], 8); // hi<<16 + lo<<4
    l_tmp = l_shl(l_tmp, 3);
    l_tmp = l_mac(l_tmp, *mem, fac);
    l_tmp = l_shl(l_tmp, 1); // saturation can occur here
    y[0] = round_word(l_tmp);
    for i in 1..len {
        l_tmp = l_deposit_h(x_hi[i]);
        l_tmp = l_mac(l_tmp, x_lo[i], 8);
        l_tmp = l_shl(l_tmp, 3);
        l_tmp = l_mac(l_tmp, y[i - 1], fac);
        l_tmp = l_shl(l_tmp, 1);
        y[i] = round_word(l_tmp);
    }
    *mem = y[len - 1];
}

/// Order-`m` LPC synthesis at the 12.8 kHz core (TS 26.173 `Syn_filt_32`): `1/A(z)` driven by the
/// `Qnew`-scaled excitation, producing the synthesis as a split `(sig_hi, sig_lo)` 32-bit signal for
/// extra precision in the recursion.
///
/// `a` is `a[0..=m]` (Q12). `sig_hi`/`sig_lo` are length `m + lg`: indices `[0..m)` are the carried
/// filter memory (the previous frame's last `m` synthesis samples), and `[m..m+lg)` receive this
/// block's output. `exc` is length `lg`.
pub fn syn_filt_32(
    a: &[i16],
    m: usize,
    exc: &[i16],
    q_new: i16,
    sig_hi: &mut [i16],
    sig_lo: &mut [i16],
    lg: usize,
) {
    let s = sub(norm_s(a[0]), 2);
    let a0 = shr(a[0], add(4, q_new)); // input / 16 and >> Qnew

    for i in 0..lg {
        // Low-part feedback: -sum(sig_lo[i-j]·a[j]).
        let mut l_tmp = 0i32;
        for j in 1..=m {
            l_tmp = l_msu(l_tmp, sig_lo[m + i - j], a[j]);
        }
        l_tmp = l_shr(l_tmp, 16 - 4); // sig_lo carried << 4
        l_tmp = l_mac(l_tmp, exc[i], a0);
        // High-part feedback: -sum(sig_hi[i-j]·a[j]).
        for j in 1..=m {
            l_tmp = l_msu(l_tmp, sig_hi[m + i - j], a[j]);
        }
        l_tmp = l_shl(l_tmp, add(3, s)); // a in Q12

        let hi = extract_h(l_tmp); // bits 16..31
        sig_hi[m + i] = hi;
        l_tmp = l_shr(l_tmp, 4);
        sig_lo[m + i] = extract_l(l_msu(l_tmp, hi, 2048)); // bits 4..15
    }
}

/// 50 Hz high-pass biquad at 12.8 kHz (TS 26.173 `HP50_12k8`), removing the DC/sub-band rumble from
/// the synthesis. `mem[6]` carries `[y2_hi, y2_lo, y1_hi, y1_lo, x0, x1]` across blocks.
pub fn hp50_12k8(signal: &mut [i16], mem: &mut [i16; 6]) {
    let mut y2_hi = mem[0];
    let mut y2_lo = mem[1];
    let mut y1_hi = mem[2];
    let mut y1_lo = mem[3];
    let mut x0 = mem[4];
    let mut x1 = mem[5];

    for sample in signal.iter_mut() {
        let x2 = x1;
        x1 = x0;
        x0 = *sample;

        let mut l_tmp = 16384i32; // rounding to maximise precision
        l_tmp = l_mac(l_tmp, y1_lo, HP50_A[1]);
        l_tmp = l_mac(l_tmp, y2_lo, HP50_A[2]);
        l_tmp = l_shr(l_tmp, 15);
        l_tmp = l_mac(l_tmp, y1_hi, HP50_A[1]);
        l_tmp = l_mac(l_tmp, y2_hi, HP50_A[2]);
        l_tmp = l_mac(l_tmp, x0, HP50_B[0]);
        l_tmp = l_mac(l_tmp, x1, HP50_B[1]);
        l_tmp = l_mac(l_tmp, x2, HP50_B[2]);
        l_tmp = l_shl(l_tmp, 2); // Q12 → Q14

        y2_hi = y1_hi;
        y2_lo = y1_lo;
        (y1_hi, y1_lo) = l_extract(l_tmp);

        l_tmp = l_shl(l_tmp, 1); // Q14 → Q15 with saturation
        *sample = round_word(l_tmp);
    }

    *mem = [y2_hi, y2_lo, y1_hi, y1_lo, x0, x1];
}

/// Up-sample the 12.8 kHz synthesis to 16 kHz (TS 26.173 `Oversamp_16k`), a 5/4 polyphase
/// interpolation. `mem[2*NB_COEF_UP]` carries the filter's input history. `sig16k` receives
/// `lg·5/4` samples. `lg` must be ≤ `L_SUBFR` (the codec always oversamples one subframe at a time).
pub fn oversamp_16k(
    sig12k8: &[i16],
    lg: usize,
    sig16k: &mut [i16],
    mem: &mut [i16; 2 * NB_COEF_UP],
) {
    debug_assert!(lg <= L_SUBFR, "oversamp processes at most one subframe");
    // signal = [mem (2·NB_COEF_UP)] ++ [sig12k8 (lg)], on the stack (no per-frame heap alloc).
    let mut signal = [0i16; L_SUBFR + 2 * NB_COEF_UP];
    signal[..2 * NB_COEF_UP].copy_from_slice(mem);
    signal[2 * NB_COEF_UP..2 * NB_COEF_UP + lg].copy_from_slice(&sig12k8[..lg]);

    let lg_up = shl(mult(lg as i16, UP_FAC), 1) as usize; // lg · 5/4

    // Up_samp over signal[NB_COEF_UP..]; Interpol(&sig_d[i]) reads signal[i+1 .. i+1+2·NB_COEF_UP].
    let mut pos = 0i16;
    for out in sig16k.iter_mut().take(lg_up) {
        let i = mult(pos, INV_FAC5); // pos/5
        let frac = sub(pos, add(shl(i, 2), i)); // pos − (pos/5)·5
        let base = i as usize + 1;

        let mut l_sum = 0i32;
        let mut k = sub(sub(FAC5, 1), frac);
        for t in 0..(2 * NB_COEF_UP) {
            l_sum = l_mac(l_sum, signal[base + t], FIR_UP[k as usize]);
            k += FAC5;
        }
        l_sum = l_shl(l_sum, 1); // saturation can occur here
        *out = round_word(l_sum);

        pos = add(pos, FAC4); // + 4/5
    }

    mem.copy_from_slice(&signal[lg..lg + 2 * NB_COEF_UP]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amr::wb::constants::PREEMPH_FAC;

    #[test]
    fn deemph_with_zero_mu_is_identity() {
        let mut x = [100, 200, -300];
        let mut mem = 0;
        deemph(&mut x, 0, &mut mem);
        assert_eq!(x, [100, 200, -300]);
        assert_eq!(mem, -300, "memory carries the last output");
    }

    #[test]
    fn deemph_decays_the_memory_by_mu() {
        // Zero input with a non-zero memory yields mu·mem ≈ 0.68·16384 = 11141.
        let mut x = [0];
        let mut mem = 16384;
        deemph(&mut x, PREEMPH_FAC, &mut mem);
        assert_eq!(x[0], 11141);
        assert_eq!(mem, 11141);
    }

    #[test]
    fn deemph_32_scales_the_split_signal() {
        // hi=1000, lo=0, mem=0 → (1000<<16)<<3<<1 rounded = 1000·16 = 16000 (no saturation).
        let mut y = [0i16];
        let mut mem = 0;
        deemph_32(&[1000], &[0], &mut y, PREEMPH_FAC, &mut mem);
        assert_eq!(y[0], 16000);
        assert_eq!(mem, 16000);
    }

    #[test]
    fn empty_input_is_a_no_op() {
        let mut mem = 42;
        deemph(&mut [], PREEMPH_FAC, &mut mem);
        deemph_32(&[], &[], &mut [], PREEMPH_FAC, &mut mem);
        assert_eq!(mem, 42);
    }

    #[test]
    fn syn_filt_zero_excitation_is_silent() {
        // 1/A(z) of zero excitation with zero memory → zero synthesis.
        let a = [4096i16, -2048, 0, 0]; // a[0]=1.0 Q12, m=3
        let mut sig_hi = vec![0i16; 3 + 4];
        let mut sig_lo = vec![0i16; 3 + 4];
        syn_filt_32(&a, 3, &[0; 4], 0, &mut sig_hi, &mut sig_lo, 4);
        assert!(sig_hi.iter().all(|&v| v == 0));
        assert!(sig_lo.iter().all(|&v| v == 0));
    }

    #[test]
    fn hp50_passes_an_impulse_first_sample() {
        // First sample with zero memory: round(8 · b0 0.9895) = 8.
        let mut signal = [8i16];
        let mut mem = [0i16; 6];
        hp50_12k8(&mut signal, &mut mem);
        assert_eq!(signal[0], 8);
        // Memory advanced (x0 stored).
        assert_eq!(mem[4], 8);
    }

    #[test]
    fn hp50_is_silent_on_zero() {
        let mut signal = [0i16; 16];
        let mut mem = [0i16; 6];
        hp50_12k8(&mut signal, &mut mem);
        assert!(signal.iter().all(|&v| v == 0));
    }

    #[test]
    fn oversamp_produces_five_quarters_length() {
        let mut out = [0i16; 80];
        let mut mem = [0i16; 2 * NB_COEF_UP];
        oversamp_16k(&[0; 64], 64, &mut out, &mut mem);
        assert!(out.iter().all(|&v| v == 0), "zero in → zero out");
    }

    #[test]
    fn oversamp_preserves_dc() {
        // Constant 4096 in steady state (memory primed) → constant 4096 out (passband gain 1).
        let mut out = [0i16; 80];
        let mut mem = [4096i16; 2 * NB_COEF_UP];
        oversamp_16k(&[4096; 64], 64, &mut out, &mut mem);
        for &v in &out {
            assert!((v - 4096).abs() <= 4, "DC gain ~1, got {v}");
        }
    }

    #[test]
    fn syn_filt_unity_gain_passes_excitation() {
        // a = [1.0, 0] (m=1, no prediction) → the synthesis is the scaled excitation. exc=16, Qnew=0:
        // 16·a0(256)·2 (L_mac) ·8 (<<3) = 65536 = hi(1)<<16, lo=0.
        let a = [4096i16, 0];
        let mut sig_hi = vec![0i16; 1 + 1];
        let mut sig_lo = vec![0i16; 1 + 1];
        syn_filt_32(&a, 1, &[16], 0, &mut sig_hi, &mut sig_lo, 1);
        assert_eq!(sig_hi[1], 1);
        assert_eq!(sig_lo[1], 0);
    }
}
