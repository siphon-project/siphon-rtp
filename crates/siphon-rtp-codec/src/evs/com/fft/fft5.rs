//! `fft5`: the 5-point complex FFT kernel of TS 26.442 `lib_com/fft.c`, translated statement for
//! statement from the preprocessed reference (the `WORD322WORD16` constants folded).

use super::ComplexBuffer;
use crate::evs::basop::mpy_32_16_1;
use crate::itu::basic_ops::{l_add, l_shl, l_shr, l_sub};

/// `fft5`: in-place 5-point FFT of `c` at stride `s`.
pub(crate) fn fft5<C: ComplexBuffer + ?Sized>(c: &mut C, s: usize) {
    let mut x0 = l_shr(c.re(0), 4);
    let mut x1 = l_shr(c.re(s), 4);
    let mut x2 = l_shr(c.re(s * 2), 4);
    let mut x3 = l_shr(c.re(s * 3), 4);
    let mut x4 = l_shr(c.re(s * 4), 4);
    let mut r1 = l_add(x1, x4);
    let mut r4 = l_sub(x1, x4);
    let mut r3 = l_add(x2, x3);
    let mut r2 = l_sub(x2, x3);
    let mut t = mpy_32_16_1(l_sub(r1, r3), 18318);
    r1 = l_add(r1, r3);
    c.set_re(0, l_add(x0, r1));
    r1 = l_add(c.re(0), l_shl(mpy_32_16_1(r1, -20480), 1));
    r3 = l_sub(r1, t);
    r1 = l_add(r1, t);
    t = mpy_32_16_1(l_add(r4, r2), 31164);
    r4 = l_add(t, l_shl(mpy_32_16_1(r4, -25212), 1));
    r2 = l_add(t, mpy_32_16_1(r2, -11904));
    x0 = l_shr(c.im(0), 4);
    x1 = l_shr(c.im(s), 4);
    x2 = l_shr(c.im(s * 2), 4);
    x3 = l_shr(c.im(s * 3), 4);
    x4 = l_shr(c.im(s * 4), 4);
    let mut s1 = l_add(x1, x4);
    let mut s4 = l_sub(x1, x4);
    let mut s3 = l_add(x2, x3);
    let mut s2 = l_sub(x2, x3);
    t = mpy_32_16_1(l_sub(s1, s3), 18318);
    s1 = l_add(s1, s3);
    c.set_im(0, l_add(x0, s1));
    s1 = l_add(c.im(0), l_shl(mpy_32_16_1(s1, -20480), 1));
    s3 = l_sub(s1, t);
    s1 = l_add(s1, t);
    t = mpy_32_16_1(l_add(s4, s2), 31164);
    s4 = l_add(t, l_shl(mpy_32_16_1(s4, -25212), 1));
    s2 = l_add(t, mpy_32_16_1(s2, -11904));
    c.set_re(s, l_add(r1, s2));
    c.set_re(s * 4, l_sub(r1, s2));
    c.set_re(s * 2, l_sub(r3, s4));
    c.set_re(s * 3, l_add(r3, s4));
    c.set_im(s, l_sub(s1, r2));
    c.set_im(s * 4, l_add(s1, r2));
    c.set_im(s * 2, l_add(s3, r4));
    c.set_im(s * 3, l_sub(s3, r4));
}
