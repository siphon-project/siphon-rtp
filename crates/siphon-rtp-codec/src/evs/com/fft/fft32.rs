//! `fft32`: the 32-point complex FFT kernel of TS 26.442 `lib_com/fft.c`, translated statement for
//! statement from the preprocessed reference (the `WORD322WORD16` constants folded).

use super::ComplexBuffer;
use crate::evs::basop::mpy_32_16_1;
use crate::evs::rom::ROTVECTOR_32;
use crate::itu::basic_ops::{l_add, l_shr, l_sub};

/// The first radix-8 stage of [`fft32`] on input columns 0 and 1, into `y`.
fn fft32_first_stage_columns_0_1<C: ComplexBuffer + ?Sized>(
    c: &mut C,
    s: usize,
    y: &mut [i32; 64],
) {
    let mut x00 = l_shr(c.re(0), 5);
    let mut x01 = l_shr(c.im(0), 5);
    let mut x02 = l_shr(c.re(s * 4), 5);
    let mut x03 = l_shr(c.im(s * 4), 5);
    let mut x04 = l_shr(c.re(s * 8), 5);
    let mut x05 = l_shr(c.im(s * 8), 5);
    let mut x06 = l_shr(c.re(s * 12), 5);
    let mut x07 = l_shr(c.im(s * 12), 5);
    let mut x08 = l_shr(c.re(s * 16), 5);
    let mut x09 = l_shr(c.im(s * 16), 5);
    let mut x10 = l_shr(c.re(s * 20), 5);
    let mut x11 = l_shr(c.im(s * 20), 5);
    let mut x12 = l_shr(c.re(s * 24), 5);
    let mut x13 = l_shr(c.im(s * 24), 5);
    let mut x14 = l_shr(c.re(s * 28), 5);
    let mut x15 = l_shr(c.im(s * 28), 5);
    let mut t00 = l_add(x00, x08);
    let mut t02 = l_sub(x00, x08);
    let mut t01 = l_add(x01, x09);
    let mut t03 = l_sub(x01, x09);
    let mut t04 = l_add(x02, x10);
    let mut t06 = l_sub(x02, x10);
    let mut t05 = l_add(x03, x11);
    let mut t07 = l_sub(x03, x11);
    let mut t08 = l_add(x04, x12);
    let mut t10 = l_sub(x04, x12);
    let mut t09 = l_add(x05, x13);
    let mut t11 = l_sub(x05, x13);
    let mut t12 = l_add(x06, x14);
    let mut t14 = l_sub(x06, x14);
    let mut t13 = l_add(x07, x15);
    let mut t15 = l_sub(x07, x15);
    let mut s00 = l_add(t00, t08);
    let mut s04 = l_sub(t00, t08);
    let mut s01 = l_add(t01, t09);
    let mut s05 = l_sub(t01, t09);
    let mut s08 = l_sub(t02, t11);
    let mut s10 = l_add(t02, t11);
    let mut s09 = l_add(t03, t10);
    let mut s11 = l_sub(t03, t10);
    let mut s02 = l_add(t04, t12);
    let mut s07 = l_sub(t04, t12);
    let mut s03 = l_add(t05, t13);
    let mut s06 = l_sub(t13, t05);
    t01 = l_add(t06, t14);
    t02 = l_sub(t06, t14);
    t00 = l_add(t07, t15);
    t03 = l_sub(t07, t15);
    let mut s12 = mpy_32_16_1(l_add(t00, t02), 23170);
    let mut s14 = mpy_32_16_1(l_sub(t00, t02), 23170);
    let mut s13 = mpy_32_16_1(l_sub(t03, t01), 23170);
    let mut s15 = mpy_32_16_1(l_add(t01, t03), -23170);
    y[0] = l_add(s00, s02);
    y[8] = l_sub(s00, s02);
    y[1] = l_add(s01, s03);
    y[9] = l_sub(s01, s03);
    y[4] = l_sub(s04, s06);
    y[12] = l_add(s04, s06);
    y[5] = l_sub(s05, s07);
    y[13] = l_add(s05, s07);
    y[6] = l_add(s08, s14);
    y[14] = l_sub(s08, s14);
    y[7] = l_add(s09, s15);
    y[15] = l_sub(s09, s15);
    y[2] = l_add(s10, s12);
    y[10] = l_sub(s10, s12);
    y[3] = l_add(s11, s13);
    y[11] = l_sub(s11, s13);
    x00 = l_shr(c.re(s), 5);
    x01 = l_shr(c.im(s), 5);
    x02 = l_shr(c.re(s * 5), 5);
    x03 = l_shr(c.im(s * 5), 5);
    x04 = l_shr(c.re(s * 9), 5);
    x05 = l_shr(c.im(s * 9), 5);
    x06 = l_shr(c.re(s * 13), 5);
    x07 = l_shr(c.im(s * 13), 5);
    x08 = l_shr(c.re(s * 17), 5);
    x09 = l_shr(c.im(s * 17), 5);
    x10 = l_shr(c.re(s * 21), 5);
    x11 = l_shr(c.im(s * 21), 5);
    x12 = l_shr(c.re(s * 25), 5);
    x13 = l_shr(c.im(s * 25), 5);
    x14 = l_shr(c.re(s * 29), 5);
    x15 = l_shr(c.im(s * 29), 5);
    t00 = l_add(x00, x08);
    t02 = l_sub(x00, x08);
    t01 = l_add(x01, x09);
    t03 = l_sub(x01, x09);
    t04 = l_add(x02, x10);
    t06 = l_sub(x02, x10);
    t05 = l_add(x03, x11);
    t07 = l_sub(x03, x11);
    t08 = l_add(x04, x12);
    t10 = l_sub(x04, x12);
    t09 = l_add(x05, x13);
    t11 = l_sub(x05, x13);
    t12 = l_add(x06, x14);
    t14 = l_sub(x06, x14);
    t13 = l_add(x07, x15);
    t15 = l_sub(x07, x15);
    s00 = l_add(t00, t08);
    s04 = l_sub(t00, t08);
    s01 = l_add(t01, t09);
    s05 = l_sub(t01, t09);
    s08 = l_sub(t02, t11);
    s10 = l_add(t02, t11);
    s09 = l_add(t03, t10);
    s11 = l_sub(t03, t10);
    s02 = l_add(t04, t12);
    s07 = l_sub(t04, t12);
    s03 = l_add(t05, t13);
    s06 = l_sub(t13, t05);
    t01 = l_add(t06, t14);
    t02 = l_sub(t06, t14);
    t00 = l_add(t07, t15);
    t03 = l_sub(t07, t15);
    s12 = mpy_32_16_1(l_add(t00, t02), 23170);
    s14 = mpy_32_16_1(l_sub(t00, t02), 23170);
    s13 = mpy_32_16_1(l_sub(t03, t01), 23170);
    s15 = mpy_32_16_1(l_add(t01, t03), -23170);
    y[16] = l_add(s00, s02);
    y[24] = l_sub(s00, s02);
    y[17] = l_add(s01, s03);
    y[25] = l_sub(s01, s03);
    y[20] = l_sub(s04, s06);
    y[28] = l_add(s04, s06);
    y[21] = l_sub(s05, s07);
    y[29] = l_add(s05, s07);
    y[22] = l_add(s08, s14);
    y[30] = l_sub(s08, s14);
    y[23] = l_add(s09, s15);
    y[31] = l_sub(s09, s15);
    y[18] = l_add(s10, s12);
    y[26] = l_sub(s10, s12);
    y[19] = l_add(s11, s13);
    y[27] = l_sub(s11, s13);
}

/// The first radix-8 stage of [`fft32`] on input columns 2 and 3, into `y`.
fn fft32_first_stage_columns_2_3<C: ComplexBuffer + ?Sized>(
    c: &mut C,
    s: usize,
    y: &mut [i32; 64],
) {
    let mut x00 = l_shr(c.re(s * 2), 5);
    let mut x01 = l_shr(c.im(s * 2), 5);
    let mut x02 = l_shr(c.re(s * 6), 5);
    let mut x03 = l_shr(c.im(s * 6), 5);
    let mut x04 = l_shr(c.re(s * 10), 5);
    let mut x05 = l_shr(c.im(s * 10), 5);
    let mut x06 = l_shr(c.re(s * 14), 5);
    let mut x07 = l_shr(c.im(s * 14), 5);
    let mut x08 = l_shr(c.re(s * 18), 5);
    let mut x09 = l_shr(c.im(s * 18), 5);
    let mut x10 = l_shr(c.re(s * 22), 5);
    let mut x11 = l_shr(c.im(s * 22), 5);
    let mut x12 = l_shr(c.re(s * 26), 5);
    let mut x13 = l_shr(c.im(s * 26), 5);
    let mut x14 = l_shr(c.re(s * 30), 5);
    let mut x15 = l_shr(c.im(s * 30), 5);
    let mut t00 = l_add(x00, x08);
    let mut t02 = l_sub(x00, x08);
    let mut t01 = l_add(x01, x09);
    let mut t03 = l_sub(x01, x09);
    let mut t04 = l_add(x02, x10);
    let mut t06 = l_sub(x02, x10);
    let mut t05 = l_add(x03, x11);
    let mut t07 = l_sub(x03, x11);
    let mut t08 = l_add(x04, x12);
    let mut t10 = l_sub(x04, x12);
    let mut t09 = l_add(x05, x13);
    let mut t11 = l_sub(x05, x13);
    let mut t12 = l_add(x06, x14);
    let mut t14 = l_sub(x06, x14);
    let mut t13 = l_add(x07, x15);
    let mut t15 = l_sub(x07, x15);
    let mut s00 = l_add(t00, t08);
    let mut s04 = l_sub(t00, t08);
    let mut s01 = l_add(t01, t09);
    let mut s05 = l_sub(t01, t09);
    let mut s08 = l_sub(t02, t11);
    let mut s10 = l_add(t02, t11);
    let mut s09 = l_add(t03, t10);
    let mut s11 = l_sub(t03, t10);
    let mut s02 = l_add(t04, t12);
    let mut s07 = l_sub(t04, t12);
    let mut s03 = l_add(t05, t13);
    let mut s06 = l_sub(t13, t05);
    t01 = l_add(t06, t14);
    t02 = l_sub(t06, t14);
    t00 = l_add(t07, t15);
    t03 = l_sub(t07, t15);
    let mut s12 = mpy_32_16_1(l_add(t00, t02), 23170);
    let mut s14 = mpy_32_16_1(l_sub(t00, t02), 23170);
    let mut s13 = mpy_32_16_1(l_sub(t03, t01), 23170);
    let mut s15 = mpy_32_16_1(l_add(t01, t03), -23170);
    y[32] = l_add(s00, s02);
    y[40] = l_sub(s00, s02);
    y[33] = l_add(s01, s03);
    y[41] = l_sub(s01, s03);
    y[36] = l_sub(s04, s06);
    y[44] = l_add(s04, s06);
    y[37] = l_sub(s05, s07);
    y[45] = l_add(s05, s07);
    y[38] = l_add(s08, s14);
    y[46] = l_sub(s08, s14);
    y[39] = l_add(s09, s15);
    y[47] = l_sub(s09, s15);
    y[34] = l_add(s10, s12);
    y[42] = l_sub(s10, s12);
    y[35] = l_add(s11, s13);
    y[43] = l_sub(s11, s13);
    x00 = l_shr(c.re(s * 3), 5);
    x01 = l_shr(c.im(s * 3), 5);
    x02 = l_shr(c.re(s * 7), 5);
    x03 = l_shr(c.im(s * 7), 5);
    x04 = l_shr(c.re(s * 11), 5);
    x05 = l_shr(c.im(s * 11), 5);
    x06 = l_shr(c.re(s * 15), 5);
    x07 = l_shr(c.im(s * 15), 5);
    x08 = l_shr(c.re(s * 19), 5);
    x09 = l_shr(c.im(s * 19), 5);
    x10 = l_shr(c.re(s * 23), 5);
    x11 = l_shr(c.im(s * 23), 5);
    x12 = l_shr(c.re(s * 27), 5);
    x13 = l_shr(c.im(s * 27), 5);
    x14 = l_shr(c.re(s * 31), 5);
    x15 = l_shr(c.im(s * 31), 5);
    t00 = l_add(x00, x08);
    t02 = l_sub(x00, x08);
    t01 = l_add(x01, x09);
    t03 = l_sub(x01, x09);
    t04 = l_add(x02, x10);
    t06 = l_sub(x02, x10);
    t05 = l_add(x03, x11);
    t07 = l_sub(x03, x11);
    t08 = l_add(x04, x12);
    t10 = l_sub(x04, x12);
    t09 = l_add(x05, x13);
    t11 = l_sub(x05, x13);
    t12 = l_add(x06, x14);
    t14 = l_sub(x06, x14);
    t13 = l_add(x07, x15);
    t15 = l_sub(x07, x15);
    s00 = l_add(t00, t08);
    s04 = l_sub(t00, t08);
    s01 = l_add(t01, t09);
    s05 = l_sub(t01, t09);
    s08 = l_sub(t02, t11);
    s10 = l_add(t02, t11);
    s09 = l_add(t03, t10);
    s11 = l_sub(t03, t10);
    s02 = l_add(t04, t12);
    s07 = l_sub(t04, t12);
    s03 = l_add(t05, t13);
    s06 = l_sub(t13, t05);
    t01 = l_add(t06, t14);
    t02 = l_sub(t06, t14);
    t00 = l_add(t07, t15);
    t03 = l_sub(t07, t15);
    s12 = mpy_32_16_1(l_add(t00, t02), 23170);
    s14 = mpy_32_16_1(l_sub(t00, t02), 23170);
    s13 = mpy_32_16_1(l_sub(t03, t01), 23170);
    s15 = mpy_32_16_1(l_add(t01, t03), -23170);
    y[48] = l_add(s00, s02);
    y[56] = l_sub(s00, s02);
    y[49] = l_add(s01, s03);
    y[57] = l_sub(s01, s03);
    y[52] = l_sub(s04, s06);
    y[60] = l_add(s04, s06);
    y[53] = l_sub(s05, s07);
    y[61] = l_add(s05, s07);
    y[54] = l_add(s08, s14);
    y[62] = l_sub(s08, s14);
    y[55] = l_add(s09, s15);
    y[63] = l_sub(s09, s15);
    y[50] = l_add(s10, s12);
    y[58] = l_sub(s10, s12);
    y[51] = l_add(s11, s13);
    y[59] = l_sub(s11, s13);
}

/// [`fft32`]'s scaling and twiddle rotation of the first stage's output in `y`.
fn fft32_twiddle(y: &mut [i32; 64]) {
    y[0] = l_shr(y[0], 1);
    y[1] = l_shr(y[1], 1);
    y[2] = l_shr(y[2], 1);
    y[3] = l_shr(y[3], 1);
    y[4] = l_shr(y[4], 1);
    y[5] = l_shr(y[5], 1);
    y[6] = l_shr(y[6], 1);
    y[7] = l_shr(y[7], 1);
    y[8] = l_shr(y[8], 1);
    y[9] = l_shr(y[9], 1);
    y[10] = l_shr(y[10], 1);
    y[11] = l_shr(y[11], 1);
    y[12] = l_shr(y[12], 1);
    y[13] = l_shr(y[13], 1);
    y[14] = l_shr(y[14], 1);
    y[15] = l_shr(y[15], 1);
    y[16] = l_shr(y[16], 1);
    y[17] = l_shr(y[17], 1);
    y[32] = l_shr(y[32], 1);
    y[33] = l_shr(y[33], 1);
    y[48] = l_shr(y[48], 1);
    y[49] = l_shr(y[49], 1);
    y[40] = l_shr(y[40], 1);
    y[41] = l_shr(y[41], 1);
    let mut a_s = l_shr(y[18], 1);
    let mut b_s = l_shr(y[19], 1);
    y[18] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[0]),
        mpy_32_16_1(b_s, ROTVECTOR_32[1]),
    );
    y[19] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[1]),
        mpy_32_16_1(b_s, ROTVECTOR_32[0]),
    );
    a_s = l_shr(y[20], 1);
    b_s = l_shr(y[21], 1);
    y[20] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[2]),
        mpy_32_16_1(b_s, ROTVECTOR_32[3]),
    );
    y[21] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[3]),
        mpy_32_16_1(b_s, ROTVECTOR_32[2]),
    );
    a_s = l_shr(y[22], 1);
    b_s = l_shr(y[23], 1);
    y[22] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[4]),
        mpy_32_16_1(b_s, ROTVECTOR_32[5]),
    );
    y[23] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[5]),
        mpy_32_16_1(b_s, ROTVECTOR_32[4]),
    );
    a_s = l_shr(y[24], 1);
    b_s = l_shr(y[25], 1);
    y[24] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[6]),
        mpy_32_16_1(b_s, ROTVECTOR_32[7]),
    );
    y[25] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[7]),
        mpy_32_16_1(b_s, ROTVECTOR_32[6]),
    );
    a_s = l_shr(y[26], 1);
    b_s = l_shr(y[27], 1);
    y[26] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[8]),
        mpy_32_16_1(b_s, ROTVECTOR_32[9]),
    );
    y[27] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[9]),
        mpy_32_16_1(b_s, ROTVECTOR_32[8]),
    );
    a_s = l_shr(y[28], 1);
    b_s = l_shr(y[29], 1);
    y[28] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[10]),
        mpy_32_16_1(b_s, ROTVECTOR_32[11]),
    );
    y[29] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[11]),
        mpy_32_16_1(b_s, ROTVECTOR_32[10]),
    );
    a_s = l_shr(y[30], 1);
    b_s = l_shr(y[31], 1);
    y[30] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[12]),
        mpy_32_16_1(b_s, ROTVECTOR_32[13]),
    );
    y[31] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[13]),
        mpy_32_16_1(b_s, ROTVECTOR_32[12]),
    );
    a_s = l_shr(y[34], 1);
    b_s = l_shr(y[35], 1);
    y[34] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[14]),
        mpy_32_16_1(b_s, ROTVECTOR_32[15]),
    );
    y[35] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[15]),
        mpy_32_16_1(b_s, ROTVECTOR_32[14]),
    );
    a_s = l_shr(y[36], 1);
    b_s = l_shr(y[37], 1);
    y[36] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[16]),
        mpy_32_16_1(b_s, ROTVECTOR_32[17]),
    );
    y[37] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[17]),
        mpy_32_16_1(b_s, ROTVECTOR_32[16]),
    );
    a_s = l_shr(y[38], 1);
    b_s = l_shr(y[39], 1);
    y[38] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[18]),
        mpy_32_16_1(b_s, ROTVECTOR_32[19]),
    );
    y[39] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[19]),
        mpy_32_16_1(b_s, ROTVECTOR_32[18]),
    );
    a_s = l_shr(y[42], 1);
    b_s = l_shr(y[43], 1);
    y[42] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[20]),
        mpy_32_16_1(b_s, ROTVECTOR_32[21]),
    );
    y[43] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[21]),
        mpy_32_16_1(b_s, ROTVECTOR_32[20]),
    );
    a_s = l_shr(y[44], 1);
    b_s = l_shr(y[45], 1);
    y[44] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[22]),
        mpy_32_16_1(b_s, ROTVECTOR_32[23]),
    );
    y[45] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[23]),
        mpy_32_16_1(b_s, ROTVECTOR_32[22]),
    );
    a_s = l_shr(y[46], 1);
    b_s = l_shr(y[47], 1);
    y[46] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[24]),
        mpy_32_16_1(b_s, ROTVECTOR_32[25]),
    );
    y[47] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[25]),
        mpy_32_16_1(b_s, ROTVECTOR_32[24]),
    );
    a_s = l_shr(y[50], 1);
    b_s = l_shr(y[51], 1);
    y[50] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[26]),
        mpy_32_16_1(b_s, ROTVECTOR_32[27]),
    );
    y[51] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[27]),
        mpy_32_16_1(b_s, ROTVECTOR_32[26]),
    );
    a_s = l_shr(y[52], 1);
    b_s = l_shr(y[53], 1);
    y[52] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[28]),
        mpy_32_16_1(b_s, ROTVECTOR_32[29]),
    );
    y[53] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[29]),
        mpy_32_16_1(b_s, ROTVECTOR_32[28]),
    );
    a_s = l_shr(y[54], 1);
    b_s = l_shr(y[55], 1);
    y[54] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[30]),
        mpy_32_16_1(b_s, ROTVECTOR_32[31]),
    );
    y[55] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[31]),
        mpy_32_16_1(b_s, ROTVECTOR_32[30]),
    );
    a_s = l_shr(y[56], 1);
    b_s = l_shr(y[57], 1);
    y[56] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[32]),
        mpy_32_16_1(b_s, ROTVECTOR_32[33]),
    );
    y[57] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[33]),
        mpy_32_16_1(b_s, ROTVECTOR_32[32]),
    );
    a_s = l_shr(y[58], 1);
    b_s = l_shr(y[59], 1);
    y[58] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[34]),
        mpy_32_16_1(b_s, ROTVECTOR_32[35]),
    );
    y[59] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[35]),
        mpy_32_16_1(b_s, ROTVECTOR_32[34]),
    );
    a_s = l_shr(y[60], 1);
    b_s = l_shr(y[61], 1);
    y[60] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[36]),
        mpy_32_16_1(b_s, ROTVECTOR_32[37]),
    );
    y[61] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[37]),
        mpy_32_16_1(b_s, ROTVECTOR_32[36]),
    );
    a_s = l_shr(y[62], 1);
    b_s = l_shr(y[63], 1);
    y[62] = l_sub(
        mpy_32_16_1(a_s, ROTVECTOR_32[38]),
        mpy_32_16_1(b_s, ROTVECTOR_32[39]),
    );
    y[63] = l_add(
        mpy_32_16_1(a_s, ROTVECTOR_32[39]),
        mpy_32_16_1(b_s, ROTVECTOR_32[38]),
    );
}

/// `fft32`: in-place 32-point FFT of `c` at stride `s`.
pub(crate) fn fft32<C: ComplexBuffer + ?Sized>(c: &mut C, s: usize) {
    let mut y = [0i32; 64];
    fft32_first_stage_columns_0_1(c, s, &mut y);
    fft32_first_stage_columns_2_3(c, s, &mut y);
    fft32_twiddle(&mut y);
    let mut t00 = l_add(y[0], y[32]);
    let mut t02 = l_sub(y[0], y[32]);
    let mut t01 = l_add(y[1], y[33]);
    let mut t03 = l_sub(y[1], y[33]);
    let mut t04 = l_add(y[16], y[48]);
    let mut t07 = l_sub(y[16], y[48]);
    let mut t05 = l_add(y[49], y[17]);
    let mut t06 = l_sub(y[49], y[17]);
    c.set_re(0, l_add(t00, t04));
    c.set_im(0, l_add(t01, t05));
    c.set_re(s * 8, l_sub(t02, t06));
    c.set_im(s * 8, l_sub(t03, t07));
    c.set_re(s * 16, l_sub(t00, t04));
    c.set_im(s * 16, l_sub(t01, t05));
    c.set_re(s * 24, l_add(t02, t06));
    c.set_im(s * 24, l_add(t03, t07));
    t00 = l_add(y[2], y[34]);
    t02 = l_sub(y[2], y[34]);
    t01 = l_add(y[3], y[35]);
    t03 = l_sub(y[3], y[35]);
    t04 = l_add(y[18], y[50]);
    t07 = l_sub(y[18], y[50]);
    t05 = l_add(y[51], y[19]);
    t06 = l_sub(y[51], y[19]);
    c.set_re(s, l_add(t00, t04));
    c.set_im(s, l_add(t01, t05));
    c.set_re(s * 9, l_sub(t02, t06));
    c.set_im(s * 9, l_sub(t03, t07));
    c.set_re(s * 17, l_sub(t00, t04));
    c.set_im(s * 17, l_sub(t01, t05));
    c.set_re(s * 25, l_add(t02, t06));
    c.set_im(s * 25, l_add(t03, t07));
    t00 = l_add(y[4], y[36]);
    t02 = l_sub(y[4], y[36]);
    t01 = l_add(y[5], y[37]);
    t03 = l_sub(y[5], y[37]);
    t04 = l_add(y[20], y[52]);
    t07 = l_sub(y[20], y[52]);
    t05 = l_add(y[53], y[21]);
    t06 = l_sub(y[53], y[21]);
    c.set_re(s * 2, l_add(t00, t04));
    c.set_im(s * 2, l_add(t01, t05));
    c.set_re(s * 10, l_sub(t02, t06));
    c.set_im(s * 10, l_sub(t03, t07));
    c.set_re(s * 18, l_sub(t00, t04));
    c.set_im(s * 18, l_sub(t01, t05));
    c.set_re(s * 26, l_add(t02, t06));
    c.set_im(s * 26, l_add(t03, t07));
    t00 = l_add(y[6], y[38]);
    t02 = l_sub(y[6], y[38]);
    t01 = l_add(y[7], y[39]);
    t03 = l_sub(y[7], y[39]);
    t04 = l_add(y[22], y[54]);
    t07 = l_sub(y[22], y[54]);
    t05 = l_add(y[55], y[23]);
    t06 = l_sub(y[55], y[23]);
    c.set_re(s * 3, l_add(t00, t04));
    c.set_im(s * 3, l_add(t01, t05));
    c.set_re(s * 11, l_sub(t02, t06));
    c.set_im(s * 11, l_sub(t03, t07));
    c.set_re(s * 19, l_sub(t00, t04));
    c.set_im(s * 19, l_sub(t01, t05));
    c.set_re(s * 27, l_add(t02, t06));
    c.set_im(s * 27, l_add(t03, t07));
    t00 = l_add(y[8], y[41]);
    t02 = l_sub(y[8], y[41]);
    t01 = l_sub(y[9], y[40]);
    t03 = l_add(y[9], y[40]);
    t04 = l_add(y[24], y[56]);
    t07 = l_sub(y[24], y[56]);
    t05 = l_add(y[57], y[25]);
    t06 = l_sub(y[57], y[25]);
    c.set_re(s * 4, l_add(t00, t04));
    c.set_im(s * 4, l_add(t01, t05));
    c.set_re(s * 12, l_sub(t02, t06));
    c.set_im(s * 12, l_sub(t03, t07));
    c.set_re(s * 20, l_sub(t00, t04));
    c.set_im(s * 20, l_sub(t01, t05));
    c.set_re(s * 28, l_add(t02, t06));
    c.set_im(s * 28, l_add(t03, t07));
    t00 = l_add(y[10], y[42]);
    t02 = l_sub(y[10], y[42]);
    t01 = l_add(y[11], y[43]);
    t03 = l_sub(y[11], y[43]);
    t04 = l_add(y[26], y[58]);
    t07 = l_sub(y[26], y[58]);
    t05 = l_add(y[59], y[27]);
    t06 = l_sub(y[59], y[27]);
    c.set_re(s * 5, l_add(t00, t04));
    c.set_im(s * 5, l_add(t01, t05));
    c.set_re(s * 13, l_sub(t02, t06));
    c.set_im(s * 13, l_sub(t03, t07));
    c.set_re(s * 21, l_sub(t00, t04));
    c.set_im(s * 21, l_sub(t01, t05));
    c.set_re(s * 29, l_add(t02, t06));
    c.set_im(s * 29, l_add(t03, t07));
    t00 = l_add(y[12], y[44]);
    t02 = l_sub(y[12], y[44]);
    t01 = l_add(y[13], y[45]);
    t03 = l_sub(y[13], y[45]);
    t04 = l_add(y[28], y[60]);
    t07 = l_sub(y[28], y[60]);
    t05 = l_add(y[61], y[29]);
    t06 = l_sub(y[61], y[29]);
    c.set_re(s * 6, l_add(t00, t04));
    c.set_im(s * 6, l_add(t01, t05));
    c.set_re(s * 14, l_sub(t02, t06));
    c.set_im(s * 14, l_sub(t03, t07));
    c.set_re(s * 22, l_sub(t00, t04));
    c.set_im(s * 22, l_sub(t01, t05));
    c.set_re(s * 30, l_add(t02, t06));
    c.set_im(s * 30, l_add(t03, t07));
    t00 = l_add(y[14], y[46]);
    t02 = l_sub(y[14], y[46]);
    t01 = l_add(y[15], y[47]);
    t03 = l_sub(y[15], y[47]);
    t04 = l_add(y[30], y[62]);
    t07 = l_sub(y[30], y[62]);
    t05 = l_add(y[63], y[31]);
    t06 = l_sub(y[63], y[31]);
    c.set_re(s * 7, l_add(t00, t04));
    c.set_im(s * 7, l_add(t01, t05));
    c.set_re(s * 15, l_sub(t02, t06));
    c.set_im(s * 15, l_sub(t03, t07));
    c.set_re(s * 23, l_sub(t00, t04));
    c.set_im(s * 23, l_sub(t01, t05));
    c.set_re(s * 31, l_add(t02, t06));
    c.set_im(s * 31, l_add(t03, t07));
}
