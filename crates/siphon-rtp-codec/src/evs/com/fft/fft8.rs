//! `fft8`: the 8-point complex FFT kernel of TS 26.442 `lib_com/fft.c`, translated statement for
//! statement from the preprocessed reference (the `WORD322WORD16` constants folded).

use super::ComplexBuffer;
use crate::evs::basop::mpy_32_16_1;
use crate::itu::basic_ops::{l_add, l_shr, l_sub};

/// `fft8`: in-place 8-point FFT of `c` at stride `s`.
pub(crate) fn fft8<C: ComplexBuffer + ?Sized>(c: &mut C, s: usize) {
    let x00 = l_shr(c.re(0), 4);
    let x01 = l_shr(c.im(0), 4);
    let x02 = l_shr(c.re(s), 4);
    let x03 = l_shr(c.im(s), 4);
    let x04 = l_shr(c.re(s * 2), 4);
    let x05 = l_shr(c.im(s * 2), 4);
    let x06 = l_shr(c.re(s * 3), 4);
    let x07 = l_shr(c.im(s * 3), 4);
    let x08 = l_shr(c.re(s * 4), 4);
    let x09 = l_shr(c.im(s * 4), 4);
    let x10 = l_shr(c.re(s * 5), 4);
    let x11 = l_shr(c.im(s * 5), 4);
    let x12 = l_shr(c.re(s * 6), 4);
    let x13 = l_shr(c.im(s * 6), 4);
    let x14 = l_shr(c.re(s * 7), 4);
    let x15 = l_shr(c.im(s * 7), 4);
    let mut t00 = l_add(x00, x08);
    let mut t02 = l_sub(x00, x08);
    let mut t01 = l_add(x01, x09);
    let mut t03 = l_sub(x01, x09);
    let t04 = l_add(x02, x10);
    let t06 = l_sub(x02, x10);
    let t05 = l_add(x03, x11);
    let t07 = l_sub(x03, x11);
    let t08 = l_add(x04, x12);
    let t10 = l_sub(x04, x12);
    let t09 = l_add(x05, x13);
    let t11 = l_sub(x05, x13);
    let t12 = l_add(x06, x14);
    let t14 = l_sub(x06, x14);
    let t13 = l_add(x07, x15);
    let t15 = l_sub(x07, x15);
    let s00 = l_add(t00, t08);
    let s04 = l_sub(t00, t08);
    let s01 = l_add(t01, t09);
    let s05 = l_sub(t01, t09);
    let s08 = l_sub(t02, t11);
    let s10 = l_add(t02, t11);
    let s09 = l_add(t03, t10);
    let s11 = l_sub(t03, t10);
    let s02 = l_add(t04, t12);
    let s07 = l_sub(t04, t12);
    let s03 = l_add(t05, t13);
    let s06 = l_sub(t13, t05);
    t01 = l_add(t06, t14);
    t02 = l_sub(t06, t14);
    t00 = l_add(t07, t15);
    t03 = l_sub(t07, t15);
    let s12 = mpy_32_16_1(l_add(t00, t02), 23170);
    let s14 = mpy_32_16_1(l_sub(t00, t02), 23170);
    let s13 = mpy_32_16_1(l_sub(t03, t01), 23170);
    let s15 = mpy_32_16_1(l_add(t01, t03), -23170);
    c.set_re(0, l_add(s00, s02));
    c.set_re(s * 4, l_sub(s00, s02));
    c.set_im(0, l_add(s01, s03));
    c.set_im(s * 4, l_sub(s01, s03));
    c.set_re(s * 2, l_sub(s04, s06));
    c.set_re(s * 6, l_add(s04, s06));
    c.set_im(s * 2, l_sub(s05, s07));
    c.set_im(s * 6, l_add(s05, s07));
    c.set_re(s * 3, l_add(s08, s14));
    c.set_re(s * 7, l_sub(s08, s14));
    c.set_im(s * 3, l_add(s09, s15));
    c.set_im(s * 7, l_sub(s09, s15));
    c.set_re(s, l_add(s10, s12));
    c.set_re(s * 5, l_sub(s10, s12));
    c.set_im(s, l_add(s11, s13));
    c.set_im(s * 5, l_sub(s11, s13));
}
