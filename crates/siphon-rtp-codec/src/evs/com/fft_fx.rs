//! The 16-bit complex FFTs of the EDCT/EMDCT path (TS 26.442 `lib_com/fft_fx.c`, the `*_16fx`
//! half): the 128-point split-radix FFT and the 160-point (32x5) and 320-point (64x5)
//! prime-factor FFTs.
//!
//! The module keeps the reference's `_fx` because `lib_com/fft.c` ports to `fft.rs`. Only the
//! functions the decoder executes are ported. `a` is an interleaved complex array (re, im, ...).
//! The 32-bit half (`edct2_fx` and its `Word32` split-radix kernels) follows at the end.
//!
//! `Mult_32_16` and `Mult_32_32` (`basic_math/math_32.c`) are compiled with `ALLOW_40bits`, where
//! they are the high word of `Mpy_32_16_ss` / `Mpy_32_32_ss`, i.e. exactly
//! [`mpy_32_16_1`] / [`mpy_32_32`].

mod fft3;

pub use fft3::{fft3, ifft3};

use crate::evs::basop::{madd_32_16, mpy_32_16_1, mpy_32_32, msub_32_16, mult_32_16};
use crate::evs::cnst::{KP559016994_16FX, KP587785252_16FX, KP951056516_16FX};
use crate::evs::com::tools::exp16_array;
use crate::evs::rom::{
    IDX_DORTFT160, IDX_DORTFT320_16FX, IP_FFT128_16FX, IP_FFT128_FX, IP_FFT16_FX, IP_FFT256_FX,
    IP_FFT32_16FX, IP_FFT32_FX, IP_FFT512_FX, IP_FFT64_16FX, IP_FFT64_FX, ODX_FFT32_5,
    ODX_FFT64_16FX, W_FFT128_16FX, W_FFT128_FX, W_FFT16_FX, W_FFT256_FX, W_FFT32_16FX, W_FFT32_FX,
    W_FFT512_FX, W_FFT64_16FX, W_FFT64_FX,
};
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_deposit_l, l_mult, l_negate, l_shl, l_shr, l_sub, negate, round_word,
    shl, shr, sub,
};
use crate::itu::stl2009::l_msu0;

/// `round_fx(L_shl(Mult_32_16(w, t), 1))`.
#[inline]
fn scale1(w: i32, t: i16) -> i16 {
    round_word(l_shl(mpy_32_16_1(w, t), 1))
}

/// `round_fx(L_shl(Msub_32_16(Mult_32_16(wr, xr), wi, xi), 1))`.
#[inline]
fn rotate_sub(wr: i32, xr: i16, wi: i32, xi: i16) -> i16 {
    round_word(l_shl(msub_32_16(mpy_32_16_1(wr, xr), wi, xi), 1))
}

/// `round_fx(L_shl(Madd_32_16(Mult_32_16(wr, xr), wi, xi), 1))`.
#[inline]
fn rotate_add(wr: i32, xr: i16, wi: i32, xi: i16) -> i16 {
    round_word(l_shl(madd_32_16(mpy_32_16_1(wr, xr), wi, xi), 1))
}

/// `wk3 = (wk1r - 2·2·wk2·wk1i, 2·2·wk2·wk1r - wk1i)`, the third twiddle from the first two.
#[inline]
fn third_twiddle(wk2: i32, wk1r: i32, wk1i: i32) -> (i32, i32) {
    let l_tmp = l_shl(mpy_32_32(wk2, wk1i), 1); // Q29
    let wk3r = l_sub(wk1r, l_shl(l_tmp, 1)); // Q30
    let l_tmp = l_shl(mpy_32_32(wk2, wk1r), 1); // Q29
    let wk3i = l_sub(l_shl(l_tmp, 1), wk1i); // Q30
    (wk3r, wk3i)
}

/// The radix-4 butterfly's sums and differences of `a[j..]`, `a[j1..]`, `a[j2..]`, `a[j3..]`:
/// `(x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i)`.
#[inline]
fn butterfly(a: &[i16], j: usize, j1: usize, j2: usize, j3: usize) -> [i16; 8] {
    [
        add(a[j], a[j1]),
        add(a[j + 1], a[j1 + 1]),
        sub(a[j], a[j1]),
        sub(a[j + 1], a[j1 + 1]),
        add(a[j2], a[j3]),
        add(a[j2 + 1], a[j3 + 1]),
        sub(a[j2], a[j3]),
        sub(a[j2 + 1], a[j3 + 1]),
    ]
}

/// The untwiddled radix-4 butterfly over `a[j]`, `a[j1]`, `a[j2]`, `a[j3]`, written back in place.
#[inline]
fn butterfly_plain(a: &mut [i16], j: usize, j1: usize, j2: usize, j3: usize) {
    let [x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i] = butterfly(a, j, j1, j2, j3);
    a[j] = add(x0r, x2r);
    a[j + 1] = add(x0i, x2i);
    a[j2] = sub(x0r, x2r);
    a[j2 + 1] = sub(x0i, x2i);
    a[j1] = sub(x1r, x3i);
    a[j1 + 1] = add(x1i, x3r);
    a[j3] = add(x1r, x3i);
    a[j3 + 1] = sub(x1i, x3r);
}

/// The radix-4 butterfly with the fixed pi/4 twiddle `wk1r = w[2]` (the second block of
/// `cft1st` and `cftmdl`).
#[inline]
fn butterfly_eighth(a: &mut [i16], j: usize, j1: usize, j2: usize, j3: usize, wk1r: i32) {
    let [x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i] = butterfly(a, j, j1, j2, j3);
    a[j] = add(x0r, x2r);
    a[j + 1] = add(x0i, x2i);
    a[j2] = sub(x2i, x0i);
    a[j2 + 1] = sub(x0r, x2r);

    let x0r = sub(x1r, x3i);
    let x0i = add(x1i, x3r);
    a[j1] = scale1(wk1r, sub(x0r, x0i));
    a[j1 + 1] = scale1(wk1r, add(x0r, x0i));

    let x0r = add(x3i, x1r);
    let x0i = sub(x3r, x1i);
    a[j3] = scale1(wk1r, sub(x0i, x0r));
    a[j3 + 1] = scale1(wk1r, add(x0i, x0r));
}

/// `fft5_shift4_16fx`: a 5-point FFT with a 4-point circular output shift, in place on
/// `z_re` / `z_im` at the positions `idx[0]`, `idx[n1]`, ..., `idx[4·n1]`.
pub fn fft5_shift4_16fx(n1: i16, z_re: &mut [i16], z_im: &mut [i16], idx: &[i16]) {
    let n1 = n1 as usize;
    let i0 = idx[0] as usize;
    let i1 = idx[n1] as usize;
    let i2 = idx[n1 * 2] as usize;
    let i3 = idx[n1 * 3] as usize;
    let i4 = idx[n1 * 4] as usize;

    let t1 = z_re[i0];
    let to = z_im[i0];

    let t2 = z_re[i1];
    let t3 = z_re[i4];
    let t4 = add(t2, t3);
    let t5 = z_re[i2];
    let t6 = z_re[i3];
    let t7 = add(t5, t6);
    let t8 = add(t4, t7);
    let tt = sub(t5, t6);
    // T9 = KP559016994 * (T4 - T7)
    let t9 = round_word(mpy_32_16_1(KP559016994_16FX, sub(t4, t7)));
    let ts = sub(t2, t3);

    let t2 = z_im[i1];
    let t3 = z_im[i4];
    let t4 = add(t2, t3);
    let t5 = z_im[i2];
    let t6 = z_im[i3];
    let t7 = add(t5, t6);
    let te = sub(t2, t3);
    let tp = add(t4, t7);
    let th = sub(t5, t6);
    // Tn = KP559016994 * (T4 - T7)
    let tn = round_word(mpy_32_16_1(KP559016994_16FX, sub(t4, t7)));

    z_re[i0] = add(t1, t8);
    z_im[i0] = add(to, tp);

    // T2 = KP951056516*Te + KP587785252*Th
    let t2 = round_word(madd_32_16(
        mpy_32_16_1(KP951056516_16FX, te),
        KP587785252_16FX,
        th,
    ));
    // T3 = KP951056516*Th - KP587785252*Te
    let t3 = round_word(msub_32_16(
        mpy_32_16_1(KP951056516_16FX, th),
        KP587785252_16FX,
        te,
    ));

    let t6 = sub(t1, shr(t8, 2));
    let t4 = add(t9, t6);
    let t5 = sub(t6, t9);
    z_re[i1] = sub(t4, t2);
    z_re[i2] = add(t5, t3);
    z_re[i4] = add(t4, t2);
    z_re[i3] = sub(t5, t3);

    // T2 = KP951056516 * Ts + KP587785252 * Tt
    let t2 = round_word(madd_32_16(
        mpy_32_16_1(KP951056516_16FX, ts),
        KP587785252_16FX,
        tt,
    ));
    // T3 = KP951056516 * Tt - KP587785252 * Ts
    let t3 = round_word(msub_32_16(
        mpy_32_16_1(KP951056516_16FX, tt),
        KP587785252_16FX,
        ts,
    ));

    let t6 = sub(to, shr(tp, 2));
    let t4 = add(tn, t6);
    let t5 = sub(t6, tn);
    z_im[i4] = sub(t4, t2);
    z_im[i2] = sub(t5, t3);
    z_im[i1] = add(t2, t4);
    z_im[i3] = add(t3, t5);
}

/// `fft5_32_16fx`: the 5-point FFT of the 160-point transform, in place on `z_re` / `z_im` at the
/// positions `idx[0]`, `idx[32]`, ..., `idx[128]`. The arithmetic is [`fft5_shift4_16fx`]'s; only
/// the output permutation differs.
pub fn fft5_32_16fx(z_re: &mut [i16], z_im: &mut [i16], idx: &[i16]) {
    let i0 = idx[0] as usize;
    let i1 = idx[32] as usize;
    let i2 = idx[64] as usize;
    let i3 = idx[96] as usize;
    let i4 = idx[128] as usize;

    let t1 = z_re[i0];
    let to = z_im[i0];

    let t2 = z_re[i1];
    let t3 = z_re[i4];
    let t4 = add(t2, t3);
    let t5 = z_re[i2];
    let t6 = z_re[i3];
    let t7 = add(t5, t6);
    let t8 = add(t4, t7);
    let tt = sub(t5, t6);
    // T9 = KP559016994 * (T4 - T7)
    let t9 = round_word(mpy_32_16_1(KP559016994_16FX, sub(t4, t7)));
    let ts = sub(t2, t3);

    let t2 = z_im[i1];
    let t3 = z_im[i4];
    let t4 = add(t2, t3);
    let t5 = z_im[i2];
    let t6 = z_im[i3];
    let t7 = add(t5, t6);
    let te = sub(t2, t3);
    let tp = add(t4, t7);
    let th = sub(t5, t6);
    let tn = round_word(mpy_32_16_1(KP559016994_16FX, sub(t4, t7)));

    z_re[i0] = add(t1, t8);
    z_im[i0] = add(to, tp);

    // T2 = KP951056516*Te + KP587785252*Th
    let t2 = round_word(madd_32_16(
        mpy_32_16_1(KP951056516_16FX, te),
        KP587785252_16FX,
        th,
    ));
    // T3 = KP951056516*Th - KP587785252*Te
    let t3 = round_word(msub_32_16(
        mpy_32_16_1(KP951056516_16FX, th),
        KP587785252_16FX,
        te,
    ));

    let t6 = sub(t1, shr(t8, 2));
    let t4 = add(t9, t6);
    let t5 = sub(t6, t9);
    z_re[i3] = sub(t4, t2);
    z_re[i1] = add(t5, t3);
    z_re[i2] = add(t4, t2);
    z_re[i4] = sub(t5, t3);

    // T2 = KP951056516 * Ts + KP587785252 * Tt
    let t2 = round_word(madd_32_16(
        mpy_32_16_1(KP951056516_16FX, ts),
        KP587785252_16FX,
        tt,
    ));
    // T3 = KP951056516 * Tt - KP587785252 * Ts
    let t3 = round_word(msub_32_16(
        mpy_32_16_1(KP951056516_16FX, tt),
        KP587785252_16FX,
        ts,
    ));

    let t6 = sub(to, shr(tp, 2));
    let t4 = add(tn, t6);
    let t5 = sub(t6, tn);
    z_im[i2] = sub(t4, t2);
    z_im[i1] = sub(t5, t3);
    z_im[i3] = add(t2, t4);
    z_im[i4] = add(t3, t5);
}

/// `fft32_5_16fx`: a 32-point FFT in place on `x` / `y` at the positions `idx[0..32]`.
pub fn fft32_5_16fx(x: &mut [i16], y: &mut [i16], idx: &[i16]) {
    let mut z = [0i16; 64];
    for i in 0..32 {
        let id = idx[i] as usize;
        z[2 * i] = x[id];
        z[2 * i + 1] = y[id];
    }

    cdft_forw_16fx(64, &mut z, &IP_FFT32_16FX, &W_FFT32_16FX);

    for i in 0..32 {
        let jd = ODX_FFT32_5[i] as usize;
        let id = idx[jd] as usize;
        x[id] = z[2 * i];
        y[id] = z[2 * i + 1];
    }
}

/// `DoRTFT160_16fx`: a low complexity 2-dimensional DFT of 160 points (32 x 5), in place.
pub fn do_rtft160_16fx(x: &mut [i16], y: &mut [i16]) {
    // Applying 32-point FFT for 5 times based on the address table Idx_dortft160
    for j in 0..5 {
        fft32_5_16fx(x, y, &IDX_DORTFT160[32 * j..]);
    }
    // Applying 5-point FFT for 32 times based on the address table Idx_dortft160
    for j in 0..32 {
        fft5_32_16fx(x, y, &IDX_DORTFT160[j..]);
    }
}

/// `fft64_16fx`: a 64-point FFT in place on `x` / `y` at the positions `idx[0..64]`.
pub fn fft64_16fx(x: &mut [i16], y: &mut [i16], idx: &[i16]) {
    let mut z = [0i16; 128];
    for i in 0..64 {
        let id = idx[i] as usize;
        z[2 * i] = x[id];
        z[2 * i + 1] = y[id];
    }

    cdft_forw_16fx(128, &mut z, &IP_FFT64_16FX, &W_FFT64_16FX);

    for i in 0..64 {
        let jd = ODX_FFT64_16FX[i] as usize;
        let id = idx[jd] as usize;
        x[id] = z[2 * i];
        y[id] = z[2 * i + 1];
    }
}

/// `DoRTFT320_16fx`: a low complexity 2-dimensional DFT of 320 points (64 x 5), in place.
pub fn do_rtft320_16fx(x: &mut [i16], y: &mut [i16]) {
    // Applying 64-point FFT for 5 times based on the address table Idx_dortft320
    for j in 0..5 {
        fft64_16fx(x, y, &IDX_DORTFT320_16FX[64 * j..]);
    }
    // Applying 5-point FFT for 64 times based on the address table Idx_dortft320
    for j in 0..64 {
        fft5_shift4_16fx(64, x, y, &IDX_DORTFT320_16FX[j..]);
    }
}

/// `DoRTFT128_16fx`: a 128-point complex FFT in place; the output bins are in reverse order
/// after bin 0.
pub fn do_rtft128_16fx(x: &mut [i16], y: &mut [i16]) {
    let mut z = [0i16; 256];
    for i in 0..128 {
        z[2 * i] = x[i];
        z[2 * i + 1] = y[i];
    }

    cdft_forw_16fx(256, &mut z, &IP_FFT128_16FX, &W_FFT128_16FX);

    x[0] = z[0];
    y[0] = z[1];
    for i in 1..128 {
        x[128 - i] = z[2 * i];
        y[128 - i] = z[2 * i + 1];
    }
}

/// `cdftForw_16fx`: the forward complex DFT of `n / 2` interleaved points, in place. `ip` is the
/// bit-reversal work table (its first two entries are skipped), `w` the Q30 cos/sin table.
pub fn cdft_forw_16fx(n: i16, a: &mut [i16], ip: &[i16], w: &[i32]) {
    // bit reversal
    bitrv2_sr_16fx(n, &ip[2..], a);
    // Do FFT
    cftfsub_16fx(n, a, w);
}

/// Swap the complex values at `a[j1..j1 + 2]` and `a[k1..k1 + 2]`.
#[inline]
fn swap_complex(a: &mut [i16], j1: i16, k1: i16) {
    let (j1, k1) = (j1 as usize, k1 as usize);
    let (xr, xi) = (a[j1], a[j1 + 1]);
    let (yr, yi) = (a[k1], a[k1 + 1]);
    a[j1] = yr;
    a[j1 + 1] = yi;
    a[k1] = xr;
    a[k1 + 1] = xi;
}

/// `bitrv2_SR_16fx`: the split-radix bit reversal of `n / 2` interleaved complex points.
pub fn bitrv2_sr_16fx(n: i16, ip: &[i16], a: &mut [i16]) {
    let mut l = n;
    let mut m: i16 = 1;
    while sub(shl(m, 3), l) < 0 {
        l = shr(l, 1);
        m = shl(m, 1);
    }

    let m2 = shl(m, 1);
    if sub(shl(m, 3), l) == 0 {
        for k in 0..m {
            for j in 0..k {
                let mut j1 = add(shl(j, 1), ip[k as usize]);
                let mut k1 = add(shl(k, 1), ip[j as usize]);
                swap_complex(a, j1, k1);
                j1 = add(j1, m2);
                k1 = add(k1, shl(m2, 1));
                swap_complex(a, j1, k1);
                j1 = add(j1, m2);
                k1 = sub(k1, m2);
                swap_complex(a, j1, k1);
                j1 = add(j1, m2);
                k1 = add(k1, shl(m2, 1));
                swap_complex(a, j1, k1);
            }
            let j1 = add(add(shl(k, 1), m2), ip[k as usize]);
            let k1 = add(j1, m2);
            swap_complex(a, j1, k1);
        }
    } else {
        for k in 1..m {
            for j in 0..k {
                let mut j1 = add(shl(j, 1), ip[k as usize]);
                let mut k1 = add(shl(k, 1), ip[j as usize]);
                swap_complex(a, j1, k1);
                j1 = add(j1, m2);
                k1 = add(k1, m2);
                swap_complex(a, j1, k1);
            }
        }
    }
}

/// `cftfsub_16fx`: the split-radix butterflies of the forward complex DFT, in place.
pub fn cftfsub_16fx(n: i16, a: &mut [i16], w: &[i32]) {
    let mut l: i16 = 2;
    if sub(n, 8) > 0 {
        cft1st_16fx(n, a, w);
        l = 8;
        while sub(shl(l, 2), n) < 0 {
            cftmdl_16fx(n, l, a, w);
            l = shl(l, 2);
        }
    }

    let lu = l as usize;
    if sub(shl(l, 2), n) == 0 {
        for j in (0..lu).step_by(2) {
            let j1 = j + lu;
            let j2 = j1 + lu;
            let j3 = j2 + lu;
            butterfly_plain(a, j, j1, j2, j3);
        }
    } else {
        for j in (0..lu).step_by(2) {
            let j1 = j + lu;
            let x0r = sub(a[j], a[j1]);
            let x0i = sub(a[j + 1], a[j1 + 1]);
            a[j] = add(a[j], a[j1]);
            a[j + 1] = add(a[j + 1], a[j1 + 1]);
            a[j1] = x0r;
            a[j1 + 1] = x0i;
        }
    }
}

/// The twiddled radix-4 butterfly of `cft1st` / `cftmdl` (first half of a twiddle group):
/// outputs to `j`, `j1`, `j2`, `j3` with twiddles `wk1`, `wk2`, `wk3`.
#[inline]
fn butterfly_twiddled(
    a: &mut [i16],
    [j, j1, j2, j3]: [usize; 4],
    (wk1r, wk1i): (i32, i32),
    (wk2r, wk2i): (i32, i32),
    (wk3r, wk3i): (i32, i32),
) {
    let [x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i] = butterfly(a, j, j1, j2, j3);
    a[j] = add(x0r, x2r);
    a[j + 1] = add(x0i, x2i);

    let x0r = sub(x0r, x2r);
    let x0i = sub(x0i, x2i);
    a[j2] = rotate_sub(wk2r, x0r, wk2i, x0i);
    a[j2 + 1] = rotate_add(wk2r, x0i, wk2i, x0r);

    let x0r = sub(x1r, x3i);
    let x0i = add(x1i, x3r);
    a[j1] = rotate_sub(wk1r, x0r, wk1i, x0i);
    a[j1 + 1] = rotate_add(wk1r, x0i, wk1i, x0r);

    wk3_tail(a, j3, (wk3r, wk3i), [x1r, x1i, x3r, x3i]);
}

/// The last product pair of a twiddled butterfly: `x0 = x1 - j·x3` (saturating) rotated by
/// `wk3` into `a[j3..j3 + 2]`.
#[inline]
fn wk3_tail(a: &mut [i16], j3: usize, (wk3r, wk3i): (i32, i32), [x1r, x1i, x3r, x3i]: [i16; 4]) {
    let x0r = add(x1r, x3i);
    let x0i = sub(x1i, x3r);
    a[j3] = rotate_sub(wk3r, x0r, wk3i, x0i);
    a[j3 + 1] = rotate_add(wk3r, x0i, wk3i, x0r);
}

/// As [`butterfly_twiddled`] but with the `wk3` input formed as `extract_l(L_add(x1r, x3i))`, as
/// `cftmdl`'s first twiddle group does: a 32-bit sum truncated to 16 bits, which wraps where
/// `cft1st`'s `add` saturates.
#[inline]
fn butterfly_twiddled_wrapping(
    a: &mut [i16],
    [j, j1, j2, j3]: [usize; 4],
    (wk1r, wk1i): (i32, i32),
    (wk2r, wk2i): (i32, i32),
    (wk3r, wk3i): (i32, i32),
) {
    let [x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i] = butterfly(a, j, j1, j2, j3);
    a[j] = add(x0r, x2r);
    a[j + 1] = add(x0i, x2i);

    let x0r = sub(x0r, x2r);
    let x0i = sub(x0i, x2i);
    a[j2] = rotate_sub(wk2r, x0r, wk2i, x0i);
    a[j2 + 1] = rotate_add(wk2r, x0i, wk2i, x0r);

    let x0r = sub(x1r, x3i);
    let x0i = add(x1i, x3r);
    a[j1] = rotate_sub(wk1r, x0r, wk1i, x0i);
    a[j1 + 1] = rotate_add(wk1r, x0i, wk1i, x0r);

    let l_x0r = l_add(i32::from(x1r), i32::from(x3i));
    let l_x0i = l_sub(i32::from(x1i), i32::from(x3r));
    let x0r = extract_l(l_x0r);
    let x0i = extract_l(l_x0i);
    a[j3] = rotate_sub(wk3r, x0r, wk3i, x0i);
    a[j3 + 1] = rotate_add(wk3r, x0i, wk3i, x0r);
}

/// The twiddled radix-4 butterfly of the second half of a twiddle group, where the `wk2`
/// rotation is by `-j·wk2` (`tmp = negate(x0r)` ...).
#[inline]
fn butterfly_twiddled_quarter(
    a: &mut [i16],
    [j, j1, j2, j3]: [usize; 4],
    (wk1r, wk1i): (i32, i32),
    (wk2r, wk2i): (i32, i32),
    (wk3r, wk3i): (i32, i32),
) {
    let [x0r, x0i, x1r, x1i, x2r, x2i, x3r, x3i] = butterfly(a, j, j1, j2, j3);
    a[j] = add(x0r, x2r);
    a[j + 1] = add(x0i, x2i);

    let x0r = sub(x0r, x2r);
    let x0i = sub(x0i, x2i);
    a[j2] = rotate_sub(wk2i, negate(x0r), wk2r, x0i);
    a[j2 + 1] = rotate_add(wk2i, negate(x0i), wk2r, x0r);

    let x0r = sub(x1r, x3i);
    let x0i = add(x1i, x3r);
    a[j1] = rotate_sub(wk1r, x0r, wk1i, x0i);
    a[j1 + 1] = rotate_add(wk1r, x0i, wk1i, x0r);

    wk3_tail(a, j3, (wk3r, wk3i), [x1r, x1i, x3r, x3i]);
}

/// `cft1st_16fx`: the first radix-4 stage over blocks of 8 complex points.
pub fn cft1st_16fx(n: i16, a: &mut [i16], w: &[i32]) {
    butterfly_plain(a, 0, 2, 4, 6);
    butterfly_eighth(a, 8, 10, 12, 14, w[2]);

    let mut k1: usize = 0;
    for j in (16..n.max(0) as usize).step_by(16) {
        k1 += 2;
        let k2 = 2 * k1;
        let wk2 = (w[k1], w[k1 + 1]);
        let wk1 = (w[k2], w[k2 + 1]);
        let wk3 = third_twiddle(wk2.1, wk1.0, wk1.1);
        butterfly_twiddled(a, [j, j + 2, j + 4, j + 6], wk1, wk2, wk3);

        let wk1 = (w[k2 + 2], w[k2 + 3]);
        let wk3 = third_twiddle(wk2.0, wk1.0, wk1.1);
        butterfly_twiddled_quarter(a, [j + 8, j + 10, j + 12, j + 14], wk1, wk2, wk3);
    }
}

/// `cftmdl_16fx`: a middle radix-4 stage with butterfly span `l`.
pub fn cftmdl_16fx(n: i16, l: i16, a: &mut [i16], w: &[i32]) {
    let m = shl(l, 2);
    let (lu, mu) = (l as usize, m as usize);
    for j in (0..lu).step_by(2) {
        butterfly_plain(a, j, j + lu, j + 2 * lu, j + 3 * lu);
    }

    let wk1r = w[2];
    for j in (mu..lu + mu).step_by(2) {
        butterfly_eighth(a, j, j + lu, j + 2 * lu, j + 3 * lu, wk1r);
    }

    let mut k1: usize = 0;
    let m2 = 2 * mu;
    for k in (m2..n.max(0) as usize).step_by(m2.max(1)) {
        k1 += 2;
        let k2 = 2 * k1;
        let wk2 = (w[k1], w[k1 + 1]);
        let wk1 = (w[k2], w[k2 + 1]);
        let wk3 = third_twiddle(wk2.1, wk1.0, wk1.1);
        for j in (k..lu + k).step_by(2) {
            butterfly_twiddled_wrapping(a, [j, j + lu, j + 2 * lu, j + 3 * lu], wk1, wk2, wk3);
        }

        let wk1 = (w[k2 + 2], w[k2 + 3]);
        let wk3 = third_twiddle(wk2.0, wk1.0, wk1.1);
        for j in (k + mu..lu + k + mu).step_by(2) {
            butterfly_twiddled_quarter(a, [j, j + lu, j + 2 * lu, j + 3 * lu], wk1, wk2, wk3);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The 32-bit split-radix kernels behind `edct2_fx` (Ooura's DCT, `Word32` data, Q14 `Word16`
// twiddles). `Mult_32_16` is `basic_math/math_32.c`'s, the same high word as `mpy_32_16_1`.
// ---------------------------------------------------------------------------------------------

/// `Mult_32_16(L_shl(x, 1), w)`, the rotation product every 32-bit butterfly uses.
#[inline]
fn mul2(x: i32, w: i16) -> i32 {
    mult_32_16(l_shl(x, 1), w)
}

/// Swap the complex values at `a[j1..j1 + 2]` and `a[k1..k1 + 2]`.
#[inline]
fn swap_complex32(a: &mut [i32], j1: i16, k1: i16) {
    let (j1, k1) = (j1 as usize, k1 as usize);
    let (xr, xi) = (a[j1], a[j1 + 1]);
    let (yr, yi) = (a[k1], a[k1 + 1]);
    a[j1] = yr;
    a[j1 + 1] = yi;
    a[k1] = xr;
    a[k1 + 1] = xi;
}

/// `wk3 = (wk1r - 2·wk2·wk1i, 2·wk2·wk1r - wk1i)` in Q14, the third twiddle from the first two.
#[inline]
fn third_twiddle32(wk2: i16, wk1r: i16, wk1i: i16) -> (i16, i16) {
    let wk3r = extract_l(l_sub(l_deposit_l(wk1r), l_shr(l_mult(wk2, wk1i), 14)));
    let wk3i = extract_l(l_msu0(l_shr(l_mult(wk2, wk1r), 14), wk1i, 1));
    (wk3r, wk3i)
}

/// `bitrv2_SR_fx`: the split-radix bit reversal of `n / 2` interleaved complex 32-bit points.
pub fn bitrv2_sr(n: i16, ip: &[i16], a: &mut [i32]) {
    let mut l = n;
    let mut m: i16 = 1;
    while shl(m, 3) < l {
        l = shr(l, 1);
        m = shl(m, 1);
    }
    let m2 = shl(m, 1);
    if shl(m, 3) == l {
        for k in 0..m {
            for j in 0..k {
                let mut j1 = add(shl(j, 1), ip[k as usize]);
                let mut k1 = add(shl(k, 1), ip[j as usize]);
                swap_complex32(a, j1, k1);
                j1 = add(j1, m2);
                k1 = add(k1, shl(m2, 1));
                swap_complex32(a, j1, k1);
                j1 = add(j1, m2);
                k1 = sub(k1, m2);
                swap_complex32(a, j1, k1);
                j1 = add(j1, m2);
                k1 = add(k1, shl(m2, 1));
                swap_complex32(a, j1, k1);
            }
            let j1 = add(add(shl(k, 1), m2), ip[k as usize]);
            let k1 = add(j1, m2);
            swap_complex32(a, j1, k1);
        }
    } else {
        for k in 1..m {
            for j in 0..k {
                let mut j1 = add(shl(j, 1), ip[k as usize]);
                let mut k1 = add(shl(k, 1), ip[j as usize]);
                swap_complex32(a, j1, k1);
                j1 = add(j1, m2);
                k1 = add(k1, m2);
                swap_complex32(a, j1, k1);
            }
        }
    }
}

/// The radix-4 butterfly shared by `cftfsub_fx` / `cftmdl_fx`'s first loop on `a[j]`,
/// `a[j + l]`, `a[j + 2l]`, `a[j + 3l]`, untwiddled.
#[inline]
fn radix4_plain(a: &mut [i32], j: usize, l: usize) {
    let (j1, j2, j3) = (j + l, j + 2 * l, j + 3 * l);
    let x0r = l_add(a[j], a[j1]);
    let x0i = l_add(a[j + 1], a[j1 + 1]);
    let x1r = l_sub(a[j], a[j1]);
    let x1i = l_sub(a[j + 1], a[j1 + 1]);
    let x2r = l_add(a[j2], a[j3]);
    let x2i = l_add(a[j2 + 1], a[j3 + 1]);
    let x3r = l_sub(a[j2], a[j3]);
    let x3i = l_sub(a[j2 + 1], a[j3 + 1]);
    a[j] = l_add(x0r, x2r);
    a[j2] = l_sub(x0r, x2r);
    a[j + 1] = l_add(x0i, x2i);
    a[j2 + 1] = l_sub(x0i, x2i);
    a[j1] = l_sub(x1r, x3i);
    a[j1 + 1] = l_add(x1i, x3r);
    a[j3] = l_add(x1r, x3i);
    a[j3 + 1] = l_sub(x1i, x3r);
}

/// `cftfsub_fx`: the split-radix butterflies of the forward complex DFT, in place.
pub fn cftfsub(n: i16, a: &mut [i32], w: &[i16]) {
    let mut l: i16 = 2;
    if n > 8 {
        cft1st(n, a, w);
        l = 8;
        while shl(l, 2) < n {
            cftmdl(n, l, a, w);
            l = shl(l, 2);
        }
    }
    let lu = l.max(0) as usize;
    if shl(l, 2) == n {
        for j in (0..lu).step_by(2) {
            radix4_plain(a, j, lu);
        }
    } else {
        for j in (0..lu).step_by(2) {
            let j1 = j + lu;
            let x0r = l_sub(a[j], a[j1]);
            let x0i = l_sub(a[j + 1], a[j1 + 1]);
            a[j] = l_add(a[j], a[j1]);
            a[j + 1] = l_add(a[j + 1], a[j1 + 1]);
            a[j1] = x0r;
            a[j1 + 1] = x0i;
        }
    }
}

/// The twiddled radix-4 butterfly of `cft1st_fx` / `cftmdl_fx` on `a[j]`, `a[j + l]`,
/// `a[j + 2l]`, `a[j + 3l]`; `second` selects the `(wk2i, wk2r)` rotation of the second half.
#[inline]
fn radix4_twiddled(
    a: &mut [i32],
    j: usize,
    l: usize,
    (wk1r, wk1i): (i16, i16),
    (wk2r, wk2i): (i16, i16),
    (wk3r, wk3i): (i16, i16),
    second: bool,
) {
    let (j1, j2, j3) = (j + l, j + 2 * l, j + 3 * l);
    let mut x0r = l_add(a[j], a[j1]);
    let mut x0i = l_add(a[j + 1], a[j1 + 1]);
    let x1r = l_sub(a[j], a[j1]);
    let x1i = l_sub(a[j + 1], a[j1 + 1]);
    let x2r = l_add(a[j2], a[j3]);
    let x2i = l_add(a[j2 + 1], a[j3 + 1]);
    let x3r = l_sub(a[j2], a[j3]);
    let x3i = l_sub(a[j2 + 1], a[j3 + 1]);
    a[j] = l_add(x0r, x2r);
    a[j + 1] = l_add(x0i, x2i);
    x0r = l_sub(x0r, x2r);
    x0i = l_sub(x0i, x2i);
    if second {
        a[j2] = l_negate(l_add(mul2(x0r, wk2i), mul2(x0i, wk2r)));
        a[j2 + 1] = l_sub(mul2(x0r, wk2r), mul2(x0i, wk2i));
    } else {
        a[j2] = l_sub(mul2(x0r, wk2r), mul2(x0i, wk2i));
        a[j2 + 1] = l_add(mul2(x0i, wk2r), mul2(x0r, wk2i));
    }
    x0r = l_sub(x1r, x3i);
    x0i = l_add(x1i, x3r);
    a[j1] = l_sub(mul2(x0r, wk1r), mul2(x0i, wk1i));
    a[j1 + 1] = l_add(mul2(x0i, wk1r), mul2(x0r, wk1i));
    x0r = l_add(x1r, x3i);
    x0i = l_sub(x1i, x3r);
    a[j3] = l_sub(mul2(x0r, wk3r), mul2(x0i, wk3i));
    a[j3 + 1] = l_add(mul2(x0i, wk3r), mul2(x0r, wk3i));
}

/// The `wk1r`-only butterfly of `cft1st_fx` (at 8) / `cftmdl_fx` (at `m`), the `pi/4` rotation.
#[inline]
fn radix4_eighth(a: &mut [i32], j: usize, l: usize, wk1r: i16) {
    let (j1, j2, j3) = (j + l, j + 2 * l, j + 3 * l);
    let mut x0r = l_add(a[j], a[j1]);
    let mut x0i = l_add(a[j + 1], a[j1 + 1]);
    let x1r = l_sub(a[j], a[j1]);
    let x1i = l_sub(a[j + 1], a[j1 + 1]);
    let x2r = l_add(a[j2], a[j3]);
    let x2i = l_add(a[j2 + 1], a[j3 + 1]);
    let x3r = l_sub(a[j2], a[j3]);
    let x3i = l_sub(a[j2 + 1], a[j3 + 1]);
    a[j] = l_add(x0r, x2r);
    a[j + 1] = l_add(x0i, x2i);
    a[j2] = l_sub(x2i, x0i);
    a[j2 + 1] = l_sub(x0r, x2r);
    x0r = l_sub(x1r, x3i);
    x0i = l_add(x1i, x3r);
    a[j1] = mul2(l_sub(x0r, x0i), wk1r);
    a[j1 + 1] = mul2(l_add(x0r, x0i), wk1r);
    x0r = l_add(x3i, x1r);
    x0i = l_sub(x3r, x1i);
    a[j3] = mul2(l_sub(x0i, x0r), wk1r);
    a[j3 + 1] = mul2(l_add(x0i, x0r), wk1r);
}

/// `cft1st_fx`: the first radix-4 stage of the split-radix FFT, in place.
pub fn cft1st(n: i16, a: &mut [i32], w: &[i16]) {
    radix4_plain(a, 0, 2);
    radix4_eighth(a, 8, 2, w[2]);
    let mut k1: i16 = 0;
    let mut j: i16 = 16;
    while j < n {
        k1 = add(k1, 2);
        let k2 = shl(k1, 1);
        let wk2r = w[k1 as usize];
        let wk2i = w[k1 as usize + 1];
        let mut wk1r = w[k2 as usize];
        let mut wk1i = w[k2 as usize + 1];
        let wk3 = third_twiddle32(wk2i, wk1r, wk1i);
        let ju = j as usize;
        radix4_twiddled(a, ju, 2, (wk1r, wk1i), (wk2r, wk2i), wk3, false);
        wk1r = w[k2 as usize + 2];
        wk1i = w[k2 as usize + 3];
        let wk3 = third_twiddle32(wk2r, wk1r, wk1i);
        radix4_twiddled(a, ju + 8, 2, (wk1r, wk1i), (wk2r, wk2i), wk3, true);
        j += 16;
    }
}

/// `cftmdl_fx`: a middle radix-4 stage of span `l` of the split-radix FFT, in place.
pub fn cftmdl(n: i16, l: i16, a: &mut [i32], w: &[i16]) {
    let m = shl(l, 2);
    let lu = l.max(0) as usize;
    for j in (0..lu).step_by(2) {
        radix4_plain(a, j, lu);
    }
    let wk1r = w[2];
    let mut j = m;
    let tmp = add(l, m);
    while j < tmp {
        radix4_eighth(a, j as usize, lu, wk1r);
        j += 2;
    }
    let mut k1: i16 = 0;
    let m2 = shl(m, 1);
    let mut k = m2;
    while k < n {
        k1 = add(k1, 2);
        let k2 = shl(k1, 1);
        let wk2r = w[k1 as usize];
        let wk2i = w[k1 as usize + 1];
        let mut wk1r = w[k2 as usize];
        let mut wk1i = w[k2 as usize + 1];
        let wk3 = third_twiddle32(wk2i, wk1r, wk1i);
        let mut j = k;
        let tmp = add(l, k);
        while j < tmp {
            radix4_twiddled(a, j as usize, lu, (wk1r, wk1i), (wk2r, wk2i), wk3, false);
            j += 2;
        }
        wk1r = w[k2 as usize + 2];
        wk1i = w[k2 as usize + 3];
        let wk3 = third_twiddle32(wk2r, wk1r, wk1i);
        let mut j = add(k, m);
        let tmp = add(l, add(k, m));
        while j < tmp {
            radix4_twiddled(a, j as usize, lu, (wk1r, wk1i), (wk2r, wk2i), wk3, true);
            j += 2;
        }
        k += m2;
    }
}

/// `cftbsub_fx`: the split-radix butterflies of the backward (conjugate) complex DFT, in place.
pub fn cftbsub(n: i16, a: &mut [i32], w: &[i16]) {
    let mut l: i16 = 2;
    if n > 8 {
        cft1st(n, a, w);
        l = 8;
        while sub(shl(l, 2), n) < 0 {
            cftmdl(n, l, a, w);
            l = shl(l, 2);
        }
    }
    let lu = l.max(0) as usize;
    if sub(shl(l, 2), n) == 0 {
        for j in (0..lu).step_by(2) {
            let (j1, j2, j3) = (j + lu, j + 2 * lu, j + 3 * lu);
            let x0r = l_add(a[j], a[j1]);
            let x0i = l_negate(l_add(a[j + 1], a[j1 + 1]));
            let x1r = l_sub(a[j], a[j1]);
            let x1i = l_sub(a[j1 + 1], a[j + 1]);
            let x2r = l_add(a[j2], a[j3]);
            let x2i = l_add(a[j2 + 1], a[j3 + 1]);
            let x3r = l_sub(a[j2], a[j3]);
            let x3i = l_sub(a[j2 + 1], a[j3 + 1]);
            a[j] = l_add(x0r, x2r);
            a[j + 1] = l_sub(x0i, x2i);
            a[j2] = l_sub(x0r, x2r);
            a[j2 + 1] = l_add(x0i, x2i);
            a[j1] = l_sub(x1r, x3i);
            a[j1 + 1] = l_sub(x1i, x3r);
            a[j3] = l_add(x1r, x3i);
            a[j3 + 1] = l_add(x1i, x3r);
        }
    } else {
        for j in (0..lu).step_by(2) {
            let j1 = j + lu;
            let x0r = l_sub(a[j], a[j1]);
            let x0i = l_sub(a[j1 + 1], a[j + 1]);
            a[j] = l_add(a[j], a[j1]);
            a[j + 1] = l_negate(l_add(a[j + 1], a[j1 + 1]));
            a[j1] = x0r;
            a[j1 + 1] = x0i;
        }
    }
}

/// The `ks` step of `rftfsub_fx` / `rftbsub_fx`: how many times `m` fits into `2·nc`.
#[inline]
fn twiddle_step(mut tmp: i16, m: i16) -> i16 {
    let mut ks: i16 = 0;
    while sub(tmp, m) >= 0 {
        ks = add(ks, 1);
        tmp = sub(tmp, m);
    }
    ks
}

/// `rftfsub_fx`: the real-to-complex post-processing of the forward real DFT, in place.
pub fn rftfsub(n: i16, a: &mut [i32], nc: i16, c: &[i16]) {
    let m = shr(n, 1);
    let ks = twiddle_step(shl(nc, 1), m);
    let mut kk: i16 = 0;
    let mut j: i16 = 2;
    while j < m {
        let k = sub(n, j) as usize;
        kk = add(kk, ks);
        let wkr = sub(8192, c[(nc - kk) as usize]);
        let wki = c[kk as usize];
        let ju = j as usize;
        let xr = l_sub(a[ju], a[k]);
        let xi = l_add(a[ju + 1], a[k + 1]);
        let yr = l_sub(mul2(xr, wkr), mul2(xi, wki));
        let yi = l_add(mul2(xi, wkr), mul2(xr, wki));
        a[ju] = l_sub(a[ju], yr);
        a[ju + 1] = l_sub(a[ju + 1], yi);
        a[k] = l_add(a[k], yr);
        a[k + 1] = l_sub(a[k + 1], yi);
        j += 2;
    }
}

/// `rftbsub_fx`: the complex-to-real pre-processing of the backward real DFT, in place.
pub fn rftbsub(n: i16, a: &mut [i32], nc: i16, c: &[i16]) {
    a[1] = l_negate(a[1]);
    let m = shr(n, 1);
    let ks = twiddle_step(shl(nc, 1), m);
    let mut kk: i16 = 0;
    let mut j: i16 = 2;
    while j < m {
        let k = sub(n, j) as usize;
        kk = add(kk, ks);
        let wkr = sub(8192, c[(nc - kk) as usize]);
        let wki = c[kk as usize];
        let ju = j as usize;
        let xr = l_sub(a[ju], a[k]);
        let xi = l_add(a[ju + 1], a[k + 1]);
        let yr = l_add(mul2(xr, wkr), mul2(xi, wki));
        let yi = l_sub(mul2(xi, wkr), mul2(xr, wki));
        a[ju] = l_sub(a[ju], yr);
        a[ju + 1] = l_sub(yi, a[ju + 1]);
        a[k] = l_add(a[k], yr);
        a[k + 1] = l_sub(yi, a[k + 1]);
        j += 2;
    }
    a[m as usize + 1] = l_negate(a[m as usize + 1]);
}

/// `dctsub_fx`: the DCT pre/post rotation of `edct2_fx`, in place.
pub fn dctsub(n: i16, a: &mut [i32], nc: i16, c: &[i16]) {
    let m = shr(n, 1);
    let ks = twiddle_step(nc, n);
    let mut kk: i16 = 0;
    for j in 1..m.max(1) as usize {
        let k = sub(n, j as i16) as usize;
        kk = add(kk, ks);
        let wkr = sub(c[kk as usize], c[(nc - kk) as usize]);
        let wki = add(c[kk as usize], c[(nc - kk) as usize]);
        let xr = l_sub(mul2(a[j], wki), mul2(a[k], wkr));
        a[j] = l_add(mul2(a[j], wkr), mul2(a[k], wki));
        a[k] = xr;
    }
    a[m as usize] = mul2(a[m as usize], c[0]);
}

/// `edct2_fx`: Ooura's DCT-II (`isgn >= 0`) or DCT-III (`isgn < 0`) of `n` 16-bit samples into
/// the 32-bit `a`, with the input normalised first; `q` receives the normalisation shift. `ip`
/// is the bit-reversal work table, `w` the Q14 cos/sin table followed by the DCT rotations.
pub fn edct2(n: i16, isgn: i16, input: &[i16], a: &mut [i32], q: &mut i16, ip: &[i16], w: &[i16]) {
    *q = exp16_array(n, input);
    *q = add(*q, 6);
    let nu = n.max(0) as usize;
    for j in 0..nu {
        a[j] = l_shl(i32::from(input[j]), *q);
    }

    let mut nw = ip[0];
    if sub(n, shl(nw, 2)) > 0 {
        nw = shr(n, 2);
    }
    let mut nc = ip[1];
    if n > nc {
        nc = n;
    }
    let c = &w[nw.max(0) as usize..];

    if isgn < 0 {
        let xr = a[nu - 1];
        let mut j = nu as isize - 2;
        while j >= 2 {
            let ju = j as usize;
            a[ju + 1] = l_sub(a[ju], a[ju - 1]);
            a[ju] = l_add(a[ju], a[ju - 1]);
            j -= 2;
        }
        a[1] = l_sub(a[0], xr);
        a[0] = l_add(a[0], xr);
        if n > 4 {
            rftbsub(n, a, nc, c);
            bitrv2_sr(n, &ip[2..], a);
            cftbsub(n, a, w);
        } else if n == 4 {
            cftfsub(n, a, w);
        }
    }

    if isgn >= 0 {
        a[0] = l_shr(a[0], 1);
    }

    dctsub(n, a, nc, c);

    if isgn >= 0 {
        if n > 4 {
            bitrv2_sr(n, &ip[2..], a);
            cftfsub(n, a, w);
            rftfsub(n, a, nc, c);
        } else if n == 4 {
            cftfsub(n, a, w);
        }
        let xr = l_sub(a[0], a[1]);
        a[0] = l_add(a[0], a[1]);
        let mut j = 2;
        while j < nu {
            a[j - 1] = l_sub(a[j], a[j + 1]);
            a[j] = l_add(a[j], a[j + 1]);
            j += 2;
        }
        a[nu - 1] = xr;
        for value in a.iter_mut().take(nu) {
            *value = l_shr(*value, 5);
        }
    }
}

/// `DoRTFTn_fx`: complex forward FFT of `n` (16 .. 512, a power of two) 32-bit points, real parts
/// in `x`, imaginary parts in `y`, in place; the output bins `1..n` come back in reverse order,
/// as in the reference. Any other `n` (the reference `assert`s) leaves both unchanged.
pub fn do_rtftn(x: &mut [i32], y: &mut [i32], n: i16) {
    let (ip, w): (&[i16], &[i16]) = match n {
        16 => (&IP_FFT16_FX, &W_FFT16_FX),
        32 => (&IP_FFT32_FX, &W_FFT32_FX),
        64 => (&IP_FFT64_FX, &W_FFT64_FX),
        128 => (&IP_FFT128_FX, &W_FFT128_FX),
        256 => (&IP_FFT256_FX, &W_FFT256_FX),
        512 => (&IP_FFT512_FX, &W_FFT512_FX),
        _ => return,
    };
    let nu = n as usize;
    let mut z = [0i32; 2048];
    for i in 0..nu {
        z[2 * i] = x[i];
        z[2 * i + 1] = y[i];
    }
    cdft_forw(2 * n, &mut z, ip, w);
    x[0] = z[0];
    y[0] = z[1];
    let mut at = 2;
    for i in (1..nu).rev() {
        x[i] = z[at];
        y[i] = z[at + 1];
        at += 2;
    }
}

/// `cdftForw_fx`: bit reversal then the split-radix forward butterflies of `n / 2` interleaved
/// complex 32-bit points.
fn cdft_forw(n: i16, a: &mut [i32], ip: &[i16], w: &[i16]) {
    // bit reversal
    bitrv2_sr(n, &ip[2..], a);
    // Do FFT
    cftfsub(n, a, w);
}
