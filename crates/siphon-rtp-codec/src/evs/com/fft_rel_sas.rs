//! Split-radix real FFT and its inverse, in place, in 16-bit fixed point (TS 26.442
//! `lib_com/fft_rel_sas_fx.c`; Sorensen, Jones, Heideman, Burrus, "Real-valued fast Fourier
//! transform algorithms", IEEE Trans. ASSP 35(6), 1987).
//!
//! Spectra are laid out as the reference has them: `re[0], re[1], ..., re[n/2], im[n/2-1], ...,
//! im[1]`. The twiddles come from `sincos_t_fx` (a sine quarter-wave of `N_MAX_SAS = 256` points
//! per turn, the cosine 64 entries on), which bounds `n` to 256; the decoder uses 4, 8 and 256.
//!
//! The reference walks the buffer with several pointers moving in opposite directions; the port
//! keeps each as an index with the same name, and the inverse keeps the reference's 1-based
//! `x = &io[-1]` view through `at`.

use crate::evs::com::math_op::i_mult2;
use crate::evs::rom::SINCOS_T_FX;
use crate::itu::basic_ops::{add, div_s, mult_r, negate, shl, sub};

/// `1/sqrt(2)` in Q15.
const INV_SQR2_FX: i16 = 23170;
/// Twiddle-table resolution: points per full turn.
const N_MAX_SAS: i16 = 256;

/// `fft_rel_fx`: forward real FFT of `x[0..n]` in place, `n = 2^m`.
pub fn fft_rel(x: &mut [i16], n: i16, m: i16) {
    let size = n.max(0) as usize;

    // Digit reverse counter.
    let mut j: usize = 0;
    for i in 0..size.saturating_sub(1) {
        if i < j {
            x.swap(i, j);
        }
        let mut k = size >> 1;
        while k <= j && k != 0 {
            j -= k;
            k >>= 1;
        }
        j += k;
    }

    // Length-two butterflies.
    for i in 0..size / 2 {
        let xt = x[2 * i];
        x[2 * i] = add(xt, x[2 * i + 1]);
        x[2 * i + 1] = sub(xt, x[2 * i + 1]);
    }

    // Other butterflies, twiddles by table lookup.
    let mut n2: usize = 1;
    for _ in 2..=m {
        let n4 = n2;
        n2 = n4 << 1;
        let n1 = n2 << 1;
        let step = N_MAX_SAS as usize / n1;
        let mut i = 0;
        while i < size {
            let (x0, x1, x2) = (i, i + n2, i + n2 + n4);
            let xt = x[x0];
            x[x0] = add(xt, x[x1]);
            x[x1] = sub(xt, x[x1]);
            x[x2] = negate(x[x2]);

            // The reference's pointers start at xi1 = i + 1, xi3 = xi1 + n2, xi2 = xi3 - 2,
            // xi4 = xi1 + n1 - 2, s = step, c = s + 64; xi1 / xi3 / s / c step up and xi2 / xi4
            // down once per tap, so each is a function of the tap number.
            for tap in 1..n4 {
                let (xi1, xi3) = (i + tap, i + n2 + tap);
                let (xi2, xi4) = (i + n2 - tap, i + n1 - tap);
                let (sv, cv) = (SINCOS_T_FX[step * tap], SINCOS_T_FX[64 + step * tap]);
                let t1 = add(mult_r(x[xi3], cv), mult_r(x[xi4], sv));
                let t2 = sub(mult_r(x[xi3], sv), mult_r(x[xi4], cv));
                x[xi4] = sub(x[xi2], t2);
                x[xi3] = negate(add(x[xi2], t2));
                x[xi2] = sub(x[xi1], t1);
                x[xi1] = add(x[xi1], t1);
            }
            i += n1;
        }
    }
}

/// The reference's `x = &io[-1]`: element `p` of the 1-based view.
#[inline]
fn at(p: i32) -> usize {
    (p - 1) as usize
}

/// The first (radix-4 L-shaped) butterfly pass of one [`ifft_rel`] stage.
fn ifft_rel_l_butterflies(io: &mut [i16], n: i32, n2: i32, n4: i32, n8: i32) {
    let mut is: i32 = 0;
    let mut id: i32 = n2 << 1;
    while is < n - 1 {
        let mut xi1 = is + 1;
        let mut xi2 = xi1 + n4;
        let mut xi3 = xi2 + n4;
        let mut xi4 = xi3 + n4;
        let mut i = is;
        while i < n {
            let t1 = sub(io[at(xi1)], io[at(xi3)]);
            io[at(xi1)] = add(io[at(xi1)], io[at(xi3)]);
            io[at(xi2)] = shl(io[at(xi2)], 1);
            io[at(xi3)] = sub(t1, shl(io[at(xi4)], 1));
            io[at(xi4)] = add(t1, shl(io[at(xi4)], 1));
            if n4 != 1 {
                let t1 = mult_r(sub(io[at(xi2 + n8)], io[at(xi1 + n8)]), INV_SQR2_FX);
                let t2 = mult_r(add(io[at(xi4 + n8)], io[at(xi3 + n8)]), INV_SQR2_FX);
                io[at(xi1 + n8)] = add(io[at(xi1 + n8)], io[at(xi2 + n8)]);
                io[at(xi2 + n8)] = sub(io[at(xi4 + n8)], io[at(xi3 + n8)]);
                io[at(xi3 + n8)] = negate(shl(add(t2, t1), 1));
                io[at(xi4 + n8)] = shl(sub(t1, t2), 1);
            }
            xi1 += id;
            xi2 += id;
            xi3 += id;
            xi4 += id;
            i += id;
        }
        is = (id << 1) - n2;
        id <<= 2;
    }
}

/// The twiddled butterfly pass of one [`ifft_rel`] stage.
fn ifft_rel_twiddled_butterflies(io: &mut [i16], n: i32, n2: i32, n4: i32, n8: i32) {
    let step = i32::from(N_MAX_SAS) / n2;
    let mut s = step;
    let mut c = s + 64;
    let mut s3 = i32::from(i_mult2(step as i16, 3));
    let mut c3 = s3 + 64;
    for j in 2..=n8 {
        let cc1 = SINCOS_T_FX[c as usize];
        let ss1 = SINCOS_T_FX[s as usize];
        let cc3 = SINCOS_T_FX[c3 as usize];
        let ss3 = SINCOS_T_FX[s3 as usize];
        let mut is: i32 = 0;
        let mut id: i32 = n2 << 1;
        c += step;
        s += step;
        c3 += 3 * step;
        s3 += 3 * step;
        while is < n - 1 {
            let mut xup1 = j + is;
            let mut xup3 = xup1 + (n4 << 1);
            let mut xdn6 = xup3 - (j << 1) + 2;
            let mut xdn8 = xdn6 + (n4 << 1);
            let mut i = is;
            while i < n {
                let mut t1 = sub(io[at(xup1)], io[at(xdn6)]);
                io[at(xup1)] = add(io[at(xup1)], io[at(xdn6)]);
                xup1 += n4;
                xdn6 -= n4;

                let mut t2 = sub(io[at(xdn6)], io[at(xup1)]);
                io[at(xdn6)] = add(io[at(xup1)], io[at(xdn6)]);

                xdn6 += n4;
                let t3 = add(io[at(xdn8)], io[at(xup3)]);
                io[at(xdn6)] = sub(io[at(xdn8)], io[at(xup3)]);

                xup3 += n4;
                xdn8 -= n4;

                let mut t4 = add(io[at(xup3)], io[at(xdn8)]);
                io[at(xup1)] = sub(io[at(xup3)], io[at(xdn8)]);

                let t5 = sub(t1, t4);
                t1 = add(t1, t4);
                t4 = sub(t2, t3);
                t2 = add(t2, t3);
                io[at(xup3)] = sub(mult_r(t1, cc3), mult_r(t2, ss3));
                xup3 -= n4;
                io[at(xup3)] = add(mult_r(t5, cc1), mult_r(t4, ss1));
                io[at(xdn8)] = sub(mult_r(t5, ss1), mult_r(t4, cc1));

                xdn8 += n4;
                io[at(xdn8)] = add(mult_r(t2, cc3), mult_r(t1, ss3));

                xup1 -= n4;
                xup1 += id;
                xup3 += id;
                xdn6 += id;
                xdn8 += id;
                i += id;
            }
            is = (id << 1) - n2;
            id <<= 2;
        }
    }
}

/// `ifft_rel_fx`: inverse real FFT of `io[0..n]` in place, `n = 2^m`, scaled by `1/n`.
pub fn ifft_rel(io: &mut [i16], n: i16, m: i16) {
    let n = i32::from(n);
    let mut n2 = n << 1;
    for _ in 1..m {
        n2 >>= 1;
        let n4 = n2 >> 2;
        let n8 = n4 >> 1;
        ifft_rel_l_butterflies(io, n, n2, n4, n8);
        ifft_rel_twiddled_butterflies(io, n, n2, n4, n8);
    }

    // Length-two butterflies.
    let mut is: i32 = 1;
    let mut id: i32 = 4;
    while is < n {
        let mut i0 = is;
        while i0 <= n {
            let r1 = io[at(i0)];
            io[at(i0)] = add(r1, io[at(i0 + 1)]);
            io[at(i0 + 1)] = sub(r1, io[at(i0 + 1)]);
            i0 += id;
        }
        is = (id << 1) - 1;
        id <<= 2;
    }

    // Digit reverse counter.
    let mut j: i32 = 1;
    for i in 1..n {
        if i < j {
            io.swap(at(i), at(j));
        }
        let mut k = n >> 1;
        while k < j {
            j -= k;
            k >>= 1;
        }
        j += k;
    }

    // Normalisation.
    let tmp = div_s(1, n as i16); // Q15
    for value in io.iter_mut().take(n as usize) {
        *value = mult_r(*value, tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_impulse_transforms_to_a_flat_spectrum() {
        let mut x = [0_i16; 16];
        x[0] = 1000;
        fft_rel(&mut x, 16, 4);
        assert_eq!(&x[..9], &[1000; 9]);
        assert_eq!(&x[9..], &[0; 7]);
    }
}
