//! Mixed-radix complex FFT and the real FFT built on it, on 32-bit data (TS 26.442
//! `lib_com/fft.c`): the CLDFB's DCT-IV, the FD-CNG and phase-dispersion real transforms, the TCX
//! FDNS and the eDCT all go through [`basop_cfft`].
//!
//! The reference passes the real and imaginary parts as two `Word32 *` that are as often two
//! interleaved views of one buffer (`&x[0]`, `&x[1]`, stride 2) as two separate arrays, so the
//! kernels here are generic over [`ComplexBuffer`]: [`Interleaved`] for the first, [`Split`] for the
//! second. Both are monomorphised, so the indexing costs what the C's does.
//!
//! The unrolled kernels (`fft5` .. `fft32`) live in `fft/`, one file each, translated statement for
//! statement from the preprocessed reference; the `WORD322WORD16(...)` constants are folded to the
//! `Word16` the macro yields.

mod fft10;
mod fft15;
mod fft16;
mod fft20;
mod fft30;
mod fft32;
mod fft5;
mod fft8;

use fft10::fft10;
use fft15::fft15;
pub use fft16::fft16;
use fft20::fft20;
use fft30::fft30;
use fft32::fft32;
use fft5::fft5;
use fft8::fft8;

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::BASOP_CFFT_MAX_LENGTH;
use crate::evs::com::rom_basop_util::basop_get_tables;
use crate::evs::rom::{ROTVECTOR_256, ROTVECTOR_320, ROTVECTOR_400, ROTVECTOR_480, ROTVECTOR_600};
use crate::itu::basic_ops::{add, l_add, l_negate, l_shr, l_sub, shr};

/// The work buffer [`basop_cfft`] needs (`Word32 x[2*BASOP_CFFT_MAX_LENGTH]`).
pub const BASOP_CFFT_WORK_LENGTH: usize = 2 * BASOP_CFFT_MAX_LENGTH as usize;

/// A complex vector the FFT kernels read and write in place: element `index` of the real and the
/// imaginary part, as the reference's `re[index]` / `im[index]`.
pub trait ComplexBuffer {
    /// `re[index]`.
    fn re(&self, index: usize) -> i32;
    /// `im[index]`.
    fn im(&self, index: usize) -> i32;
    /// `re[index] = value`.
    fn set_re(&mut self, index: usize, value: i32);
    /// `im[index] = value`.
    fn set_im(&mut self, index: usize, value: i32);
}

/// `re = &data[at]`, `im = &data[at + 1]`: the interleaved layout the reference calls with a
/// stride of 2 (`BASOP_cfft(&x[0], &x[1], n, 2, ...)`).
#[derive(Debug)]
pub struct Interleaved<'a> {
    pub data: &'a mut [i32],
    pub at: usize,
}

impl ComplexBuffer for Interleaved<'_> {
    #[inline]
    fn re(&self, index: usize) -> i32 {
        self.data[self.at + index]
    }
    #[inline]
    fn im(&self, index: usize) -> i32 {
        self.data[self.at + 1 + index]
    }
    #[inline]
    fn set_re(&mut self, index: usize, value: i32) {
        self.data[self.at + index] = value;
    }
    #[inline]
    fn set_im(&mut self, index: usize, value: i32) {
        self.data[self.at + 1 + index] = value;
    }
}

/// Separate real and imaginary arrays (`BASOP_cfft(re, im, n, 1, ...)`).
#[derive(Debug)]
pub struct Split<'a> {
    pub re: &'a mut [i32],
    pub im: &'a mut [i32],
}

impl ComplexBuffer for Split<'_> {
    #[inline]
    fn re(&self, index: usize) -> i32 {
        self.re[index]
    }
    #[inline]
    fn im(&self, index: usize) -> i32 {
        self.im[index]
    }
    #[inline]
    fn set_re(&mut self, index: usize, value: i32) {
        self.re[index] = value;
    }
    #[inline]
    fn set_im(&mut self, index: usize, value: i32) {
        self.im[index] = value;
    }
}

/// `WORD322WORD16(0x5a82799a)`, cos(pi/4) in Q15.
const C81: i16 = 23170;
/// `WORD322WORD16(0xa57d8666)`, -cos(pi/4) in Q15.
const C82: i16 = -23170;
/// `SCALEFACTORN2` (3) less one: the per-stage shift of the radix-8 second pass.
const N2_SHIFT_8: i16 = 3 - 1;
/// `SCALEFACTOR16` (5): the input shift of the radix-16 second pass.
const N2_SHIFT_16: i16 = 5;
/// `SCALEFACTOR16 - SCALEFACTOR20` (5 - 6): the radix-20 second pass after a 30-point first pass
/// shifts *left* by one, through `L_shr` with a negative count (saturating).
const N2_SHIFT_20_30: i16 = 5 - 6;

/// The rotation `x · W` of `fftN2`'s `CPLX_MPY`: `(xr·wr - xi·wi, xr·wi + xi·wr)`.
#[inline]
fn cplx_mpy(x_re: i32, x_im: i32, w_re: i16, w_im: i16) -> (i32, i32) {
    (
        l_sub(mpy_32_16_1(x_re, w_re), mpy_32_16_1(x_im, w_im)),
        l_add(mpy_32_16_1(x_re, w_im), mpy_32_16_1(x_im, w_re)),
    )
}

/// The geometry of one `fftN2` call: `len = dim1 · dim2`, input stride `sx`, twiddle stride `sc`
/// into `w`, which starts `woff` entries into the full rotation table.
#[derive(Debug, Clone, Copy)]
struct FftN2 {
    w: &'static [i16],
    len: usize,
    dim1: usize,
    dim2: usize,
    sx: usize,
    sc: usize,
    woff: usize,
}

impl FftN2 {
    /// `W[sc*i + sc*j*dim1 - Woff]` and the next entry: the twiddle of the radix-8/10 passes.
    #[inline]
    fn twiddle(&self, i: usize, j: usize) -> (i16, i16) {
        let k = self.sc * i + self.sc * j * self.dim1 - self.woff;
        (self.w[k], self.w[k + 1])
    }

    /// The twiddle of the radix-16/20 passes, which index even `j` as `W[sc*i + j*dim1 - Woff]`
    /// and odd `j` from the second half, `W[len + sc*i + (j-1)*dim1 - Woff]`.
    #[inline]
    fn twiddle_split(&self, i: usize, j: usize) -> (i16, i16) {
        let k = if j.is_multiple_of(2) {
            self.sc * i + j * self.dim1 - self.woff
        } else {
            self.len + self.sc * i + (j - 1) * self.dim1 - self.woff
        };
        (self.w[k], self.w[k + 1])
    }
}

/// `fftN2`: a `dim1 x dim2` two-pass FFT through the work buffer `x` (`2 * len` words).
fn fft_n2<C: ComplexBuffer + ?Sized>(c: &mut C, geometry: FftN2, x: &mut [i32]) {
    let FftN2 { dim1, dim2, sx, .. } = geometry;
    for i in 0..dim2 {
        for j in 0..dim1 {
            x[2 * i * dim1 + 2 * j] = c.re(sx * i + sx * j * dim2);
            x[2 * i * dim1 + 2 * j + 1] = c.im(sx * i + sx * j * dim2);
        }
    }
    for i in 0..dim2 {
        let mut row = Interleaved {
            data: &mut *x,
            at: i * 2 * dim1,
        };
        match dim1 {
            5 => fft5(&mut row, 2),
            8 => fft8(&mut row, 2),
            10 => fft10(&mut row, 2),
            15 => fft15(&mut row, 2),
            16 => fft16(&mut row, 2, 1),
            20 => fft20(&mut row, 2),
            30 => fft30(&mut row, 2),
            32 => fft32(&mut row, 2),
            _ => {}
        }
    }
    match dim2 {
        8 => fft_n2_dim2_8(c, geometry, x),
        10 => fft_n2_dim2_10(c, geometry, x),
        16 => fft_n2_dim2_16(c, geometry, x),
        20 => fft_n2_dim2_20(c, geometry, x),
        _ => {}
    }
}

/// `fftN2`'s second pass for `dim2 == 8`: a radix-8 butterfly per column, inline.
fn fft_n2_dim2_8<C: ComplexBuffer + ?Sized>(c: &mut C, geometry: FftN2, x: &[i32]) {
    let FftN2 { dim1, sx, .. } = geometry;
    for i in 0..dim1 {
        let mut v = [0i32; 16];
        v[0] = l_shr(x[2 * i], 1);
        v[1] = l_shr(x[2 * i + 1], 1);
        for k in 1..8 {
            let (xr, xi) = (x[2 * i + 2 * k * dim1], x[2 * i + 2 * k * dim1 + 1]);
            if i == 0 {
                v[2 * k] = l_shr(xr, 1);
                v[2 * k + 1] = l_shr(xi, 1);
            } else {
                let (w_re, w_im) = geometry.twiddle(i, k);
                v[2 * k] = l_shr(l_sub(mpy_32_16_1(xr, w_re), mpy_32_16_1(xi, w_im)), 1);
                v[2 * k + 1] = l_shr(l_add(mpy_32_16_1(xr, w_im), mpy_32_16_1(xi, w_re)), 1);
            }
        }
        let [x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15] = v;
        let t00 = l_shr(l_add(x00, x08), N2_SHIFT_8);
        let t02 = l_shr(l_sub(x00, x08), N2_SHIFT_8);
        let t01 = l_shr(l_add(x01, x09), N2_SHIFT_8);
        let t03 = l_shr(l_sub(x01, x09), N2_SHIFT_8);
        let t04 = l_shr(l_add(x02, x10), N2_SHIFT_8);
        let t06 = l_sub(x02, x10);
        let t05 = l_shr(l_add(x03, x11), N2_SHIFT_8);
        let t07 = l_sub(x03, x11);
        let t08 = l_shr(l_add(x04, x12), N2_SHIFT_8);
        let t10 = l_shr(l_sub(x04, x12), N2_SHIFT_8);
        let t09 = l_shr(l_add(x05, x13), N2_SHIFT_8);
        let t11 = l_shr(l_sub(x05, x13), N2_SHIFT_8);
        let t12 = l_shr(l_add(x06, x14), N2_SHIFT_8);
        let t14 = l_sub(x06, x14);
        let t13 = l_shr(l_add(x07, x15), N2_SHIFT_8);
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
        let t01 = l_shr(l_add(t06, t14), N2_SHIFT_8);
        let t02 = l_shr(l_sub(t06, t14), N2_SHIFT_8);
        let t00 = l_shr(l_add(t07, t15), N2_SHIFT_8);
        let t03 = l_shr(l_sub(t07, t15), N2_SHIFT_8);
        let s12 = mpy_32_16_1(l_add(t00, t02), C81);
        let s14 = mpy_32_16_1(l_sub(t00, t02), C81);
        let s13 = mpy_32_16_1(l_sub(t03, t01), C81);
        let s15 = mpy_32_16_1(l_add(t01, t03), C82);
        let out = |k: usize| sx * i + sx * k * dim1;
        c.set_re(out(0), l_add(s00, s02));
        c.set_im(out(0), l_add(s01, s03));
        c.set_re(out(1), l_add(s10, s12));
        c.set_im(out(1), l_add(s11, s13));
        c.set_re(out(2), l_sub(s04, s06));
        c.set_im(out(2), l_sub(s05, s07));
        c.set_re(out(3), l_add(s08, s14));
        c.set_im(out(3), l_add(s09, s15));
        c.set_re(out(4), l_sub(s00, s02));
        c.set_im(out(4), l_sub(s01, s03));
        c.set_re(out(5), l_sub(s10, s12));
        c.set_im(out(5), l_sub(s11, s13));
        c.set_re(out(6), l_add(s04, s06));
        c.set_im(out(6), l_add(s05, s07));
        c.set_re(out(7), l_sub(s08, s14));
        c.set_im(out(7), l_sub(s09, s15));
    }
}

/// Write the `dim2`-point column transform in `y` back to column `i` of the output.
fn fft_n2_store<C: ComplexBuffer + ?Sized>(c: &mut C, geometry: FftN2, i: usize, y: &[i32]) {
    let FftN2 { dim1, dim2, sx, .. } = geometry;
    for j in 0..dim2 {
        c.set_re(sx * i + sx * j * dim1, y[2 * j]);
        c.set_im(sx * i + sx * j * dim1, y[2 * j + 1]);
    }
}

/// `fftN2`'s second pass for `dim2 == 10` (`dim1` 10 or 20): rotate, then a 10-point kernel.
fn fft_n2_dim2_10<C: ComplexBuffer + ?Sized>(c: &mut C, geometry: FftN2, x: &[i32]) {
    let FftN2 { dim1, dim2, .. } = geometry;
    let mut y = [0i32; 2 * 20];
    for i in 0..dim1 {
        y[0] = x[2 * i];
        y[1] = x[2 * i + 1];
        for j in 1..dim2 {
            let (xr, xi) = (x[2 * i + 2 * j * dim1], x[2 * i + 2 * j * dim1 + 1]);
            if i == 0 {
                y[2 * j] = xr;
                y[2 * j + 1] = xi;
            } else {
                let (w_re, w_im) = geometry.twiddle(i, j);
                (y[2 * j], y[2 * j + 1]) = cplx_mpy(xr, xi, w_re, w_im);
            }
        }
        fft10(
            &mut Interleaved {
                data: &mut y,
                at: 0,
            },
            2,
        );
        fft_n2_store(c, geometry, i, &y);
    }
}

/// Fill `y` with column `i` of the first pass, rotated (column 0 is not) and shifted right by
/// `shift` (which the `30 x 20` case makes negative: a saturating left shift).
fn fft_n2_gather_split(geometry: FftN2, x: &[i32], i: usize, shift: i16, y: &mut [i32]) {
    let FftN2 { dim1, dim2, .. } = geometry;
    y[0] = l_shr(x[2 * i], shift);
    y[1] = l_shr(x[2 * i + 1], shift);
    for j in 1..dim2 {
        let (xr, xi) = (x[2 * i + 2 * j * dim1], x[2 * i + 2 * j * dim1 + 1]);
        if i == 0 {
            y[2 * j] = l_shr(xr, shift);
            y[2 * j + 1] = l_shr(xi, shift);
        } else {
            let (w_re, w_im) = geometry.twiddle_split(i, j);
            let (re, im) = cplx_mpy(xr, xi, w_re, w_im);
            y[2 * j] = l_shr(re, shift);
            y[2 * j + 1] = l_shr(im, shift);
        }
    }
}

/// `fftN2`'s second pass for `dim2 == 16`: rotate and scale down by `SCALEFACTOR16`, then an
/// unscaled 16-point kernel.
fn fft_n2_dim2_16<C: ComplexBuffer + ?Sized>(c: &mut C, geometry: FftN2, x: &[i32]) {
    let mut y = [0i32; 2 * 20];
    for i in 0..geometry.dim1 {
        fft_n2_gather_split(geometry, x, i, N2_SHIFT_16, &mut y);
        fft16(
            &mut Interleaved {
                data: &mut y,
                at: 0,
            },
            2,
            0,
        );
        fft_n2_store(c, geometry, i, &y);
    }
}

/// `fftN2`'s second pass for `dim2 == 20` (`dim1` 20 or 30): rotate, then a 20-point kernel. The
/// `dim1 == 20` branch does not scale; the `dim1 == 30` branch shifts by `SCALEFACTOR16 -
/// SCALEFACTOR20`.
fn fft_n2_dim2_20<C: ComplexBuffer + ?Sized>(c: &mut C, geometry: FftN2, x: &[i32]) {
    let shift = if geometry.dim1 == 20 {
        0
    } else {
        N2_SHIFT_20_30
    };
    let mut y = [0i32; 2 * 20];
    for i in 0..geometry.dim1 {
        // The C's `dim1 == 20` branch copies without `L_shr`; `L_shr(v, 0)` is the identity, so
        // one gather serves both branches exactly.
        fft_n2_gather_split(geometry, x, i, shift, &mut y);
        fft20(
            &mut Interleaved {
                data: &mut y,
                at: 0,
            },
            2,
        );
        fft_n2_store(c, geometry, i, &y);
    }
}

/// `(len, rotation table, Woff, dim1, dim2, sc, scale)` for every composite length `BASOP_cfft`
/// takes through `fftN2`.
fn fft_n2_geometry(size_of_fft: i16, sx: usize) -> Option<(FftN2, i16)> {
    let (w, dim1, dim2, sc, woff, scale): (&'static [i16], usize, usize, usize, usize, i16) =
        match size_of_fft {
            40 => (&ROTVECTOR_320, 5, 8, 8, 40, 7),
            64 => (&ROTVECTOR_256, 8, 8, 8, 64, 7),
            80 => (&ROTVECTOR_320, 10, 8, 4, 40, 8),
            100 => (&ROTVECTOR_400, 10, 10, 4, 40, 10),
            120 => (&ROTVECTOR_480, 15, 8, 4, 60, 8),
            128 => (&ROTVECTOR_256, 16, 8, 4, 64, 8),
            160 => (&ROTVECTOR_320, 20, 8, 2, 40, 8),
            200 => (&ROTVECTOR_400, 20, 10, 2, 40, 10),
            240 => (&ROTVECTOR_480, 30, 8, 2, 60, 9),
            256 => (&ROTVECTOR_256, 32, 8, 2, 64, 9),
            320 => (&ROTVECTOR_320, 20, 16, 2, 40, 10),
            400 => (&ROTVECTOR_400, 20, 20, 2, 40, 10),
            480 => (&ROTVECTOR_480, 30, 16, 2, 60, 11),
            600 => (&ROTVECTOR_600, 30, 20, 2, 60, 10),
            _ => return None,
        };
    let geometry = FftN2 {
        w,
        len: dim1 * dim2,
        dim1,
        dim2,
        sx,
        sc,
        woff,
    };
    Some((geometry, scale))
}

/// `BASOP_cfft`: in-place complex FFT of `size_of_fft` points at stride `s`, adding the transform's
/// scaling shift to `*scale`. `x` is the composite lengths' work buffer.
///
/// The reference asserts on a length it does not implement; here such a call leaves the data and
/// `scale` untouched. Every call site passes a constant length from the table below.
pub fn basop_cfft<C: ComplexBuffer + ?Sized>(
    c: &mut C,
    size_of_fft: i16,
    s: i16,
    scale: &mut i16,
    x: &mut [i32; BASOP_CFFT_WORK_LENGTH],
) {
    let stride = s as usize;
    let shift = match size_of_fft {
        5 => {
            fft5(c, stride);
            4
        }
        8 => {
            fft8(c, stride);
            4
        }
        10 => {
            fft10(c, stride);
            5
        }
        16 => {
            fft16(c, stride, 1);
            5
        }
        20 => {
            fft20(c, stride);
            5
        }
        30 => {
            fft30(c, stride);
            6
        }
        32 => {
            fft32(c, stride);
            6
        }
        _ => {
            let Some((geometry, shift)) = fft_n2_geometry(size_of_fft, stride) else {
                return;
            };
            fft_n2(c, geometry, x);
            shift
        }
    };
    *scale = add(*scale, shift);
}

/// One `BASOP_rfft` split/merge step on the bins `i` and `size - i` (the reference's
/// `RFFTN_POSTPROCESSING` / `RFFTN_PREPROCESSING` macro), returning `(t1, t2, t3, t4)`.
/// `forward` selects which of the two macros' twiddle combinations is used; `(w_a, w_b)` are the
/// sine-table entry's components in the order that macro reads them.
#[inline]
fn rfft_butterfly(x: &[i32], size: usize, i: usize, forward: bool, w_a: i16, w_b: i16) -> [i32; 4] {
    let xb0 = l_shr(x[2 * i], 2);
    let xb1 = l_shr(x[2 * i + 1], 2);
    let xt0 = l_shr(x[size - 2 * i], 2);
    let xt1 = l_shr(x[size - 2 * i + 1], 2);
    let t1 = l_sub(xb0, xt0);
    let t2 = l_add(xb1, xt1);
    let (t3, t4) = if forward {
        (
            l_sub(mpy_32_16_1(t1, w_a), mpy_32_16_1(t2, w_b)),
            l_add(mpy_32_16_1(t1, w_b), mpy_32_16_1(t2, w_a)),
        )
    } else {
        (
            l_add(mpy_32_16_1(t1, w_a), mpy_32_16_1(t2, w_b)),
            l_sub(mpy_32_16_1(t2, w_a), mpy_32_16_1(t1, w_b)),
        )
    };
    [l_add(xb0, xt0), l_sub(xb1, xt1), t3, t4]
}

/// `BASOP_rfft`: real FFT of `size_of_fft` samples in place, forward (`isign == -1`, packed result
/// with `x[1]` holding the Nyquist bin) or inverse (`isign == +1`), through a half-length
/// [`basop_cfft`]. `*scale` accumulates the exponent.
///
/// The reference asserts on lengths it does not support (the inverse scale table knows only 64,
/// 512 and 640); such a call returns without touching `x` or `scale` here.
pub fn basop_rfft(x: &mut [i32], size_of_fft: i16, scale: &mut i16, isign: i16) {
    let size_of_fft2 = shr(size_of_fft, 1);
    let size_of_fft4 = shr(size_of_fft, 2);
    let size_of_fft8 = shr(size_of_fft, 3);
    let tables = basop_get_tables(size_of_fft2);
    let (w1, wstride) = (tables.sin_twiddle, tables.sin_step as usize);
    let inverse_shift = match size_of_fft {
        64 => 2 - 6,
        512 | 640 => 2 - 9,
        _ => 0,
    };
    let supported = fft_n2_geometry(size_of_fft2, 2).is_some()
        || matches!(size_of_fft2, 5 | 8 | 10 | 16 | 20 | 30 | 32);
    if !supported
        || w1.is_empty()
        || x.len() < size_of_fft as usize
        || !(isign == -1 || (isign == 1 && inverse_shift != 0))
    {
        return;
    }
    let size = size_of_fft as usize;
    let (n4, n8) = (size_of_fft4 as usize, size_of_fft8 as usize);
    let mut work_buffer = [0i32; BASOP_CFFT_WORK_LENGTH];
    // The C's loop index after both loops: the second loop starts at sizeOfFft8.
    let last = n8.max(n4);
    if isign == -1 {
        basop_cfft(
            &mut Interleaved {
                data: &mut *x,
                at: 0,
            },
            size_of_fft2,
            2,
            scale,
            &mut work_buffer,
        );
        let xb0 = l_shr(x[0], 1);
        let xb1 = l_shr(x[1], 1);
        x[0] = l_add(xb0, xb1);
        x[1] = l_sub(xb0, xb1);
        for i in 1..n8 {
            let w = w1[i * wstride].v;
            let [t1, t2, t3, t4] = rfft_butterfly(x, size, i, true, w.im, w.re);
            rfft_store_forward(x, size, i, [t1, t2, t3, t4]);
        }
        for i in n8..n4 {
            let w = w1[(n4 - i) * wstride].v;
            let [t1, t2, t3, t4] = rfft_butterfly(x, size, i, true, w.re, w.im);
            rfft_store_forward(x, size, i, [t1, t2, t3, t4]);
        }
        x[size - 2 * last] = l_shr(x[2 * last], 1);
        x[size - 2 * last + 1] = l_negate(l_shr(x[2 * last + 1], 1));
        *scale = add(*scale, 1);
    } else {
        let xb0 = l_shr(x[0], 2);
        let xb1 = l_shr(x[1], 2);
        x[0] = l_add(xb0, xb1);
        x[1] = l_sub(xb1, xb0);
        for i in 1..n8 {
            let w = w1[i * wstride].v;
            let t = rfft_butterfly(x, size, i, false, w.im, w.re);
            rfft_store_inverse(x, size, i, t);
        }
        for i in n8..n4 {
            let w = w1[(n4 - i) * wstride].v;
            let t = rfft_butterfly(x, size, i, false, w.re, w.im);
            rfft_store_inverse(x, size, i, t);
        }
        x[size - 2 * last] = l_shr(x[2 * last], 1);
        x[size - 2 * last + 1] = l_shr(x[2 * last + 1], 1);
        basop_cfft(
            &mut Interleaved {
                data: &mut *x,
                at: 0,
            },
            size_of_fft2,
            2,
            scale,
            &mut work_buffer,
        );
        rfft_inverse_finish(x, size_of_fft, size_of_fft2 as usize);
        *scale = add(*scale, inverse_shift);
    }
}

#[inline]
fn rfft_store_forward(x: &mut [i32], size: usize, i: usize, [t1, t2, t3, t4]: [i32; 4]) {
    x[2 * i] = l_sub(t1, t3);
    x[2 * i + 1] = l_sub(t2, t4);
    x[size - 2 * i] = l_add(t1, t3);
    x[size - 2 * i + 1] = l_negate(l_add(t2, t4));
}

#[inline]
fn rfft_store_inverse(x: &mut [i32], size: usize, i: usize, [t1, t2, t3, t4]: [i32; 4]) {
    x[2 * i] = l_sub(t1, t3);
    x[2 * i + 1] = l_sub(t4, t2);
    x[size - 2 * i] = l_add(t1, t3);
    x[size - 2 * i + 1] = l_add(t2, t4);
}

/// The inverse's final scaling (the 640 raster) or conjugation (radix 2).
fn rfft_inverse_finish(x: &mut [i32], size_of_fft: i16, half: usize) {
    /// `WORD322WORD16(0x66666680)` and `WORD322WORD16(0x99999980)`: ±0.8 in Q15.
    const C1: i16 = 26214;
    const C2: i16 = -26214;
    match size_of_fft {
        40 | 80 | 320 | 640 => {
            for i in 0..half {
                x[2 * i] = mpy_32_16_1(x[2 * i], C1);
                x[2 * i + 1] = mpy_32_16_1(x[2 * i + 1], C2);
            }
        }
        _ => {
            for i in 0..half {
                x[2 * i + 1] = l_negate(x[2 * i + 1]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_and_split_buffers_transform_identically() {
        let re: Vec<i32> = (0..20).map(|i| (i * 7919 % 4001 - 2000) << 12).collect();
        let im: Vec<i32> = (0..20).map(|i| (i * 104_729 % 3001 - 1500) << 12).collect();
        let mut work = [0i32; BASOP_CFFT_WORK_LENGTH];
        let (mut re_split, mut im_split) = (re.clone(), im.clone());
        let mut scale_split = 0;
        basop_cfft(
            &mut Split {
                re: &mut re_split,
                im: &mut im_split,
            },
            20,
            1,
            &mut scale_split,
            &mut work,
        );
        let mut interleaved: Vec<i32> = re.iter().zip(&im).flat_map(|(&r, &i)| [r, i]).collect();
        let mut scale_interleaved = 0;
        basop_cfft(
            &mut Interleaved {
                data: &mut interleaved,
                at: 0,
            },
            20,
            2,
            &mut scale_interleaved,
            &mut work,
        );
        assert_eq!(scale_split, 5);
        assert_eq!(scale_split, scale_interleaved);
        for k in 0..20 {
            assert_eq!(re_split[k], interleaved[2 * k]);
            assert_eq!(im_split[k], interleaved[2 * k + 1]);
        }
    }

    #[test]
    fn unsupported_lengths_leave_data_and_scale_untouched() {
        let mut work = [0i32; BASOP_CFFT_WORK_LENGTH];
        let mut data = [5i32; 64];
        let mut scale = 3;
        basop_cfft(
            &mut Interleaved {
                data: &mut data,
                at: 0,
            },
            24,
            2,
            &mut scale,
            &mut work,
        );
        assert_eq!((data, scale), ([5; 64], 3));
        basop_rfft(&mut data, 256, &mut scale, 1);
        assert_eq!((data, scale), ([5; 64], 3));
    }
}
