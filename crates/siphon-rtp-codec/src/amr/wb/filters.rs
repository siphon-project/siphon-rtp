//! AMR-WB de-emphasis filters (3GPP TS 26.173 `deemph.c`), ported bit-exact on [`crate::amr::basic_ops`].
//!
//! De-emphasis is the 1-pole inverse of the encoder's pre-emphasis: `y[n] = x[n] + mu·y[n-1]`. The
//! synthesis path uses [`deemph_32`], which consumes the synthesis filter's split hi/lo signal;
//! [`deemph`] / [`deemph2`] are the single-precision variants used elsewhere. Each carries `mem`
//! (`y[-1]`) across calls.

use crate::amr::basic_ops::{l_deposit_h, l_mac, l_mult, l_shl, round_word, shr};

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
}
