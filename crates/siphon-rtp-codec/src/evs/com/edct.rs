//! The DCT-IV of the TCX, HQ and GSC paths, computed through a complex FFT of half the length
//! (TS 26.442 `lib_com/edct_fx.c`; TS 26.445 §5.3.2.2 and §6.2.4).
//!
//! The reference calls both `edct_fx` and `edct_16fx` in place (`edct_fx(y, y, ...)` in
//! `tcx_mdct.c`, `edct_16fx(x, x, ...)` in `gs_dec_fx.c`). Both read their whole input before
//! writing any output, so the `_in_place` variants here are the same arithmetic on one buffer.

use crate::evs::basop::{madd_32_16, mpy_32_16_1, msub_32_16};
use crate::evs::com::fft::{basop_cfft, Split, BASOP_CFFT_WORK_LENGTH};
use crate::evs::com::fft_fx::{do_rtft128_16fx, do_rtft160_16fx, do_rtft320_16fx};
use crate::evs::rom::{
    EDCT_TABLE_100_FX, EDCT_TABLE_120_FX, EDCT_TABLE_128_16FX, EDCT_TABLE_128_FX,
    EDCT_TABLE_160_16FX, EDCT_TABLE_160_FX, EDCT_TABLE_200_FX, EDCT_TABLE_20_FX, EDCT_TABLE_240_FX,
    EDCT_TABLE_256_FX, EDCT_TABLE_320_16FX, EDCT_TABLE_320_FX, EDCT_TABLE_400_FX, EDCT_TABLE_40_FX,
    EDCT_TABLE_480_FX, EDCT_TABLE_600_FX, EDCT_TABLE_64_FX, EDCT_TABLE_80_FX,
};
use crate::itu::basic_ops::{
    add, div_s, l_add, l_mac, l_msu, l_mult, l_negate, l_shl, l_shr, l_sub, mult_r, norm_l,
    round_word, shr, sub,
};

/// `L_FRAME48k/2+240`, the reference's `re2` / `im2` size in `edct_fx`.
const EDCT_HALF_MAX: usize = 960 / 2 + 240;
/// `L_FRAME48k/2`, the scratch size of `edct_16fx`.
const EDCT_16_HALF_MAX: usize = 960 / 2;
/// `MAX_SEGMENT_LENGTH`.
const MAX_SEGMENT_LENGTH: usize = 480;

/// `Mult_32_16` (`basic_math/math_32.c`): built with `ALLOW_40bits`, it is the high word of
/// `Mpy_32_16_ss`, i.e. exactly `Mpy_32_16_1`.
#[inline]
fn mult_32_16(a: i32, b: i16) -> i32 {
    mpy_32_16_1(a, b)
}

/// `get_edct_table`: the Q16 twiddle table of an `length`-point `edct_fx`, adding 2 to `*q` for
/// the two lengths whose table is pre-scaled. `None` for a length without a table (the reference
/// returns `NULL` and its caller then dereferences it).
pub fn get_edct_table(length: i16, q: &mut i16) -> Option<&'static [i16]> {
    let table: &'static [i16] = match length {
        1200 => {
            *q = add(*q, 2);
            &EDCT_TABLE_600_FX
        }
        960 => &EDCT_TABLE_480_FX,
        640 => &EDCT_TABLE_320_FX,
        320 => &EDCT_TABLE_160_FX,
        256 => &EDCT_TABLE_128_FX,
        240 => &EDCT_TABLE_120_FX,
        200 => &EDCT_TABLE_100_FX,
        160 => &EDCT_TABLE_80_FX,
        40 => &EDCT_TABLE_20_FX,
        800 => {
            *q = add(*q, 2);
            &EDCT_TABLE_400_FX
        }
        512 => &EDCT_TABLE_256_FX,
        480 => &EDCT_TABLE_240_FX,
        400 => &EDCT_TABLE_200_FX,
        128 => &EDCT_TABLE_64_FX,
        80 => &EDCT_TABLE_40_FX,
        _ => return None,
    };
    Some(table)
}

/// The twiddle and pre-rotation of `edct_fx`: `x` into `re2` / `im2`, `Q(q+1)`.
fn edct_pre_rotate(
    x: &[i32],
    edct_table: &[i16],
    length: usize,
    re2: &mut [i32; EDCT_HALF_MAX],
    im2: &mut [i32; EDCT_HALF_MAX],
) {
    let len1 = length / 2;
    for i in 0..len1 {
        let l_tmp = mult_32_16(x[2 * i], edct_table[i]);
        re2[i] = madd_32_16(l_tmp, x[length - 1 - 2 * i], edct_table[len1 - 1 - i]);

        let l_tmp = mult_32_16(x[length - 1 - 2 * i], edct_table[i]);
        im2[i] = msub_32_16(l_tmp, x[2 * i], edct_table[len1 - 1 - i]);
    }
}

/// The FFT and post-rotation of `edct_fx`, writing `y`.
fn edct_transform(
    y: &mut [i32],
    edct_table: &[i16],
    length: i16,
    q: &mut i16,
    re2: &mut [i32; EDCT_HALF_MAX],
    im2: &mut [i32; EDCT_HALF_MAX],
) {
    let len1 = shr(length, 1);
    // The reference lends the FFT the output `y` as its work buffer; nothing in it is read back.
    let mut work = [0i32; BASOP_CFFT_WORK_LENGTH];

    *q = sub(15, *q);
    basop_cfft(&mut Split { re: re2, im: im2 }, len1, 1, q, &mut work);

    let mut tmp = div_s(1, length); // Q15
    tmp = round_word(l_shl(l_mult(tmp, 19302), 2)); // Q15
    let (len1, length) = (len1 as usize, length as usize);
    for i in 0..len1 {
        let re = msub_32_16(re2[i], im2[i], tmp);
        let im = madd_32_16(im2[i], re2[i], tmp);
        y[2 * i] = l_add(
            mult_32_16(re, edct_table[i]),
            mult_32_16(im, edct_table[len1 - 1 - i]),
        );
        y[length - 1 - 2 * i] = l_sub(
            mult_32_16(re, edct_table[len1 - 1 - i]),
            mult_32_16(im, edct_table[i]),
        );
    } // Q(q-2)

    *q = sub(15 + 2, *q);
}

/// `edct_fx`: the `length`-point DCT-IV of `x` (Q`*q`) into `y`, updating `*q` to the output's Q.
/// A length without a table leaves `y` untouched (the reference would dereference `NULL`).
pub fn edct(x: &[i32], y: &mut [i32], length: i16, q: &mut i16) {
    let Some(edct_table) = get_edct_table(length, q) else {
        return;
    };
    let mut re2 = [0i32; EDCT_HALF_MAX];
    let mut im2 = [0i32; EDCT_HALF_MAX];
    edct_pre_rotate(x, edct_table, length as usize, &mut re2, &mut im2);
    edct_transform(y, edct_table, length, q, &mut re2, &mut im2);
}

/// [`edct`] with `x` and `y` the same buffer (`edct_fx(y, y, ...)`).
pub fn edct_in_place(xy: &mut [i32], length: i16, q: &mut i16) {
    let Some(edct_table) = get_edct_table(length, q) else {
        return;
    };
    let mut re2 = [0i32; EDCT_HALF_MAX];
    let mut im2 = [0i32; EDCT_HALF_MAX];
    edct_pre_rotate(xy, edct_table, length as usize, &mut re2, &mut im2);
    edct_transform(xy, edct_table, length, q, &mut re2, &mut im2);
}

/// The table of an `edct_16fx` length: `L_FRAME32k`, `L_FRAME` or `L_FRAME16k`. Any other length
/// has none (the reference would dereference `NULL`) and leaves the output untouched.
fn edct_16fx_table(length: i16) -> Option<&'static [i16]> {
    match length {
        640 => Some(&EDCT_TABLE_320_16FX),
        256 => Some(&EDCT_TABLE_128_16FX),
        320 => Some(&EDCT_TABLE_160_16FX),
        _ => None,
    }
}

/// The twiddle, pre-rotation and block scaling of `edct_16fx`: `x` into `re2` / `im2` at
/// `Q(Qx + Q_edct)`, returning `Q_edct`.
fn edct_16fx_pre_rotate(
    x: &[i16],
    edct_table: &[i16],
    length: usize,
    bh: i16,
    re2: &mut [i16; EDCT_16_HALF_MAX],
    im2: &mut [i16; EDCT_16_HALF_MAX],
) -> i16 {
    let len2 = length / 2;
    let mut l_max: i32 = 0;
    for i in 0..len2 {
        let (px, pt) = (length - 1 - 2 * i, len2 - 1 - i);
        let l_tmp = l_mult(x[2 * i], edct_table[i]);
        let l_acc = l_mac(l_tmp, x[px], edct_table[pt]);
        l_max = l_max.max(l_acc);

        let l_tmp = l_mult(x[px], edct_table[i]);
        let l_acc = l_msu(l_tmp, x[2 * i], edct_table[pt]);
        l_max = l_max.max(l_acc);
    }

    let mut tmp = 31;
    if l_max != 0 {
        tmp = norm_l(l_max);
    }
    let q_edct = sub(tmp, bh); // creating a bit-headroom

    for i in 0..len2 {
        let (px, pt) = (length - 1 - 2 * i, len2 - 1 - i);
        let l_tmp = l_mult(x[2 * i], edct_table[i]);
        let l_acc = l_mac(l_tmp, x[px], edct_table[pt]);
        re2[i] = round_word(l_shl(l_acc, q_edct));

        let l_tmp = l_mult(x[px], edct_table[i]);
        let l_acc = l_msu(l_tmp, x[2 * i], edct_table[pt]);
        im2[i] = round_word(l_shl(l_acc, q_edct));
    }
    q_edct
}

/// The FFT, rotation and post-rotation of `edct_16fx`, writing `y`.
fn edct_16fx_transform(
    y: &mut [i16],
    edct_table: &[i16],
    length: i16,
    q_edct: i16,
    re2: &mut [i16; EDCT_16_HALF_MAX],
    im2: &mut [i16; EDCT_16_HALF_MAX],
) {
    match length {
        640 => do_rtft320_16fx(re2, im2),
        256 => do_rtft128_16fx(re2, im2),
        320 => do_rtft160_16fx(re2, im2),
        _ => return,
    }
    let tmp = div_s(1, length); // Q15
    let l_tmp = l_mult(tmp, 19302); // Q29, (3*PI/4) in Q13
    let fact = round_word(l_shl(l_tmp, 2)); // Q15

    let length = length as usize;
    let len2 = length / 2;
    let mut re = [0i16; EDCT_16_HALF_MAX];
    let mut im = [0i16; EDCT_16_HALF_MAX];
    for i in 0..len2 {
        let tmp = mult_r(im2[i], fact);
        re[i] = sub(re2[i], tmp);
        let tmp = mult_r(re2[i], fact);
        im[i] = add(im2[i], tmp);
    }

    // Post-rotate and obtain the output data
    for i in 0..len2 {
        let (py, pt) = (length - 1 - 2 * i, len2 - 1 - i);
        let l_tmp = l_mult(re[i], edct_table[i]);
        let l_acc = l_mac(l_tmp, im[i], edct_table[pt]);
        y[2 * i] = round_word(l_shr(l_acc, q_edct));

        let l_tmp = l_mult(re[i], edct_table[len2 - 1 - i]);
        let l_acc = l_msu(l_tmp, im[i], edct_table[i]);
        y[py] = round_word(l_shr(l_acc, q_edct));
    }
}

/// `edct_16fx`: the `length`-point 16-bit DCT-IV of `x` into `y` (same Q), keeping `bh` bits of
/// headroom in the transform. Lengths 640, 256 and 320.
pub fn edct_16fx(x: &[i16], y: &mut [i16], length: i16, bh: i16) {
    let Some(edct_table) = edct_16fx_table(length) else {
        return;
    };
    let mut re2 = [0i16; EDCT_16_HALF_MAX];
    let mut im2 = [0i16; EDCT_16_HALF_MAX];
    let q_edct = edct_16fx_pre_rotate(x, edct_table, length as usize, bh, &mut re2, &mut im2);
    edct_16fx_transform(y, edct_table, length, q_edct, &mut re2, &mut im2);
}

/// [`edct_16fx`] with `x` and `y` the same buffer (`edct_16fx(x, x, ...)`).
pub fn edct_16fx_in_place(xy: &mut [i16], length: i16, bh: i16) {
    let Some(edct_table) = edct_16fx_table(length) else {
        return;
    };
    let mut re2 = [0i16; EDCT_16_HALF_MAX];
    let mut im2 = [0i16; EDCT_16_HALF_MAX];
    let q_edct = edct_16fx_pre_rotate(xy, edct_table, length as usize, bh, &mut re2, &mut im2);
    edct_16fx_transform(xy, edct_table, length, q_edct, &mut re2, &mut im2);
}

/// `iedct_short_fx`: the inverse EDCT of a short (transient) segment: an [`edct`] of
/// `segment_length / 2` points unfolded into `segment_length` outputs. `*q` keeps its input value
/// when the transform is all zero.
pub fn iedct_short(input: &[i32], q: &mut i16, out: &mut [i32], segment_length: i16) {
    let mut alias = [0i32; MAX_SEGMENT_LENGTH];

    let qtmp = *q;
    let mut tmp = 0;
    let seg_len_div2 = shr(segment_length, 1);
    let seg_len_div4 = shr(segment_length, 2);
    let seg_len_3mul_div4 = add(seg_len_div2, seg_len_div4);

    edct(input, &mut alias, seg_len_div2, q);
    if alias[..seg_len_div2.max(0) as usize]
        .iter()
        .any(|&v| v != 0)
    {
        tmp = 1;
    }
    if tmp == 0 {
        *q = qtmp;
    }
    let (div2, div4, mul3_div4) = (
        seg_len_div2 as usize,
        seg_len_div4.max(0) as usize,
        seg_len_3mul_div4 as usize,
    );
    for i in 0..div4 {
        out[i] = alias[div4 + i];
        out[div4 + i] = l_negate(alias[div2 - 1 - i]);
        out[div2 + i] = l_negate(alias[div4 - 1 - i]);
        out[mul3_div4 + i] = l_negate(alias[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edct_table_raises_q_for_the_prescaled_lengths() {
        let mut q = 3;
        assert!(get_edct_table(1200, &mut q).is_some());
        assert_eq!(q, 5);
        assert!(get_edct_table(800, &mut q).is_some());
        assert_eq!(q, 7);
        assert_eq!(get_edct_table(256, &mut q).map(<[i16]>::len), Some(128));
        assert_eq!(q, 7);
        assert!(get_edct_table(100, &mut q).is_none());
    }

    #[test]
    fn unsupported_lengths_leave_the_output_untouched() {
        let x = [1i32; 64];
        let mut y = [5i32; 64];
        let mut q = 0;
        edct(&x, &mut y, 64, &mut q);
        assert_eq!(y, [5; 64]);
        assert_eq!(q, 0);
        let x16 = [1i16; 200];
        let mut y16 = [5i16; 200];
        edct_16fx(&x16, &mut y16, 200, 6);
        assert_eq!(y16, [5; 200]);
    }

    #[test]
    fn in_place_matches_out_of_place() {
        let x: Vec<i32> = (0..256).map(|i| (i * 7919 % 2001 - 1000) << 12).collect();
        let mut y = vec![0i32; 256];
        let (mut q1, mut q2) = (10, 10);
        edct(&x, &mut y, 256, &mut q1);
        let mut xy = x.clone();
        edct_in_place(&mut xy, 256, &mut q2);
        assert_eq!(y, xy);
        assert_eq!(q1, q2);

        let x16: Vec<i16> = (0..256).map(|i| (i * 7919 % 2001 - 1000) as i16).collect();
        let mut y16 = vec![0i16; 256];
        edct_16fx(&x16, &mut y16, 256, 6);
        let mut xy16 = x16.clone();
        edct_16fx_in_place(&mut xy16, 256, 6);
        assert_eq!(y16, xy16);
    }
}
