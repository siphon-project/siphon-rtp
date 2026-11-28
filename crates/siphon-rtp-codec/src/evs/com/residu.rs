//! LP analysis (residual) filtering `A(z)` (TS 26.442 `lib_com/residu_fx.c`).
//!
//! The reference reads the input history through negative indices (`x[i - 16]`), so the input is
//! the whole buffer plus the index the C pointer points at (`x_at`).

use crate::itu::basic_ops::{add, l_mac, l_mult, l_shl, norm_s, round_word, shl};

/// `Residu3_fx`: order-16 residual `y[i] = sum_{k=0..=16} a[k]·x[i - k]` over `lg` samples, the
/// input history `x[x_at - 16..x_at]` included. `shift` raises the output Q (0 or 1 in practice).
pub fn residu3(a: &[i16], x: &[i16], x_at: usize, y: &mut [i16], lg: i16, shift: i16) {
    let mut q = add(norm_s(a[0]), 1);
    if shift != 0 {
        q = add(q, shift);
    }
    for (i, out) in y.iter_mut().enumerate().take(lg.max(0) as usize) {
        let at = x_at + i;
        let mut s = l_mult(x[at], a[0]);
        for k in 1..=16 {
            s = l_mac(s, x[at - k], a[k]);
        }
        *out = round_word(l_shl(s, q));
    }
}

/// `Residu3_lc_fx`: order-`m` residual of `x` from a zero history (only `x[i - j]` with `j <= i` is
/// read); the first output is `x[0]` shifted by `shift`.
pub fn residu3_lc(a: &[i16], m: i16, x: &[i16], y: &mut [i16], lg: i16, shift: i16) {
    let order = m.max(0) as usize;
    let lg = lg.max(0) as usize;
    let mut q = add(norm_s(a[0]), 1);
    if shift > 0 {
        q = add(q, shift);
    }
    if lg == 0 {
        return;
    }
    y[0] = shl(x[0], shift);
    for i in 1..lg {
        let mut s = l_mult(x[i], a[0]);
        for j in 1..=i.min(order) {
            s = l_mac(s, x[i - j], a[j]);
        }
        y[i] = round_word(l_shl(s, q));
    }
}
