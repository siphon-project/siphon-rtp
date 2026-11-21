//! The radix-2 FFT of the waveform interpolator (TS 26.442 `lib_com/wi_fx.c`: `c_fft_wi_fx`,
//! `r_fft_4_fx`), split out of `wi.rs` to keep that file under the production-line gate.

use crate::evs::rom::COS_TABLE;
use crate::itu::basic_ops::{
    add, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_negate, l_shr, l_sub, negate, round_word, shl,
    shr, sub,
};

/// The `cos_table` entry at `index` (masked to the table), the butterflies' twiddle.
#[inline]
fn cos_at(index: i32) -> i16 {
    COS_TABLE[(index & 511) as usize]
}

/// `c_fft_wi_fx`: the decimation-in-time complex FFT (`isign == 1`, halving each stage) or IFFT
/// of `size / 2` interleaved points, in place.
fn c_fft_wi(farray: &mut [i16], size: i16, stage: i16, isign: i16) {
    let mut ii_table = [0_i16; 8];
    let mut big_k: i16 = 0;
    let mut k: i16 = 256;
    while k > 0 && size > 0 {
        big_k = add(big_k, 1); // K=512/size
        k -= size;
    }
    let n_2 = shr(size, 1);
    for i in 1..=stage.clamp(0, 8) {
        ii_table[i as usize - 1] = shr(size, i);
    }
    let size_u = (size.max(0) as usize).min(farray.len());

    // Rearrange the input array in bit reversed order
    let mut j: i16 = 0;
    let mut i: i16 = 0;
    while i32::from(i) < i32::from(size) - 2 {
        if sub(j, i) > 0 && (j as usize) + 1 < size_u {
            farray.swap(i as usize, j as usize);
            farray.swap(i as usize + 1, j as usize + 1);
        }
        let mut k = n_2;
        while j >= k && k > 0 {
            j = sub(j, k);
            k = shr(k, 1);
        }
        j += k;
        i += 2;
    }

    // The FFT part
    for i in 0..stage.clamp(0, 8) {
        let jj = shl(2, i); // FFT size
        let kk = shl(jj, 1); // 2 * FFT size
        let ii = ii_table[i as usize]; // 2 * number of FFT's
        let mut j: i16 = 0;
        while j < jj {
            let ji = i32::from(j) * i32::from(ii); // ji is phase table index
            let cos_k = cos_at(ji * i32::from(big_k));
            let sin_k = cos_at(ji * i32::from(big_k) + 384);
            let mut k = j;
            while k < size {
                let kj = add(k, jj); // kj is butterfly bottom
                let (k_u, kj_u) = (k as usize, kj as usize);
                if kj_u + 1 >= size_u {
                    break;
                }
                if isign == 1 {
                    let ftmp_real = l_msu(l_mult(farray[kj_u], cos_k), farray[kj_u + 1], sin_k);
                    let ftmp_imag = l_mac(l_mult(farray[kj_u + 1], cos_k), farray[kj_u], sin_k);
                    let tmp1 = round_word(ftmp_real);
                    let tmp2 = round_word(ftmp_imag);
                    farray[kj_u] = shr(sub(farray[k_u], tmp1), 1);
                    farray[kj_u + 1] = shr(sub(farray[k_u + 1], tmp2), 1);
                    farray[k_u] = shr(add(farray[k_u], tmp1), 1);
                    farray[k_u + 1] = shr(add(farray[k_u + 1], tmp2), 1);
                } else {
                    let ftmp_real = l_mac(l_mult(farray[kj_u], cos_k), farray[kj_u + 1], sin_k);
                    let ftmp_imag = l_msu(l_mult(farray[kj_u + 1], cos_k), farray[kj_u], sin_k);
                    let tmp1 = round_word(ftmp_real);
                    let tmp2 = round_word(ftmp_imag);
                    farray[kj_u] = sub(farray[k_u], tmp1);
                    farray[kj_u + 1] = sub(farray[k_u + 1], tmp2);
                    farray[k_u] = add(farray[k_u], tmp1);
                    farray[k_u + 1] = add(farray[k_u + 1], tmp2);
                }
                k = k.wrapping_add(kk);
                if kk <= 0 {
                    break;
                }
            }
            j += 2;
        }
    }
}

/// `r_fft_4_fx`: the real FFT (`isign == 1`) or IFFT of `size` samples through a `size / 2`-point
/// complex transform, in place.
pub fn r_fft_4(farray: &mut [i16], size: i16, stage: i16, isign: i16) {
    let n_2 = shr(size, 1);
    let mut big_k: i16 = 0;
    let mut k: i16 = 256;
    while k > 0 && size > 0 {
        big_k = add(big_k, 1); // K=512/size
        k -= size;
    }
    let bk = i32::from(big_k);
    let size_u = size.max(0) as usize;
    if size_u < 2 || farray.len() < size_u {
        return;
    }

    if isign == 1 {
        // Perform the complex FFT
        c_fft_wi(farray, size, stage, isign);

        // First, handle the DC and foldover frequencies
        let ftmp1_real = farray[0];
        let ftmp2_real = farray[1];
        farray[0] = add(ftmp1_real, ftmp2_real);
        farray[1] = sub(ftmp1_real, ftmp2_real);

        // Now, handle the remaining positive frequencies
        let mut j = size_u - 2;
        let mut i: usize = 2;
        while i as i16 <= n_2 {
            let ftmp1_real = add(farray[i], farray[j]);
            let ftmp1_imag = sub(farray[i + 1], farray[j + 1]);
            let ftmp2_real = add(farray[i + 1], farray[j + 1]);
            let ftmp2_imag = sub(farray[j], farray[i]);

            let lftmp1_real = l_deposit_h(ftmp1_real);
            let lftmp1_imag = l_deposit_h(ftmp1_imag);
            let cos_i = cos_at(i as i32 * bk);
            let sin_i = cos_at(i as i32 * bk + 384);
            let cos_j = cos_at(j as i32 * bk);

            let ltmp1 = l_msu(l_mult(ftmp2_real, cos_i), ftmp2_imag, sin_i);
            farray[i] = round_word(l_shr(l_add(lftmp1_real, ltmp1), 1));

            let ltmp1 = l_mac(l_mult(ftmp2_imag, cos_i), ftmp2_real, sin_i);
            farray[i + 1] = round_word(l_shr(l_add(lftmp1_imag, ltmp1), 1));

            let ltmp1 = l_mac(l_mult(ftmp2_real, cos_j), ftmp2_imag, sin_i);
            farray[j] = round_word(l_shr(l_add(lftmp1_real, ltmp1), 1));

            let ltmp1 = l_msu(l_mult(ftmp2_real, sin_i), ftmp2_imag, cos_j);
            let ltmp2 = l_sub(ltmp1, lftmp1_imag);
            farray[j + 1] = round_word(l_shr(ltmp2, 1));
            j = size_u - i;
            i += 2;
        }
    } else {
        // First, handle the DC and foldover frequencies
        let ftmp1_real = farray[0];
        let ftmp2_real = farray[1];
        farray[0] = shr(add(ftmp1_real, ftmp2_real), 1);
        farray[1] = shr(sub(ftmp1_real, ftmp2_real), 1);

        // Now, handle the remaining positive frequencies
        let mut i: usize = 2;
        while i as i16 <= n_2 {
            let j = size_u - i;

            let ftmp1_real = add(farray[i], farray[j]);
            let ftmp1_imag = sub(farray[i + 1], farray[j + 1]);
            let ftmp2_real = negate(add(farray[j + 1], farray[i + 1]));
            let ftmp2_imag = negate(sub(farray[j], farray[i]));

            let lftmp1_real = l_deposit_h(ftmp1_real);
            let lftmp1_imag = l_deposit_h(ftmp1_imag);
            let cos_i = cos_at(i as i32 * bk);
            let sin_i = cos_at(i as i32 * bk + 384);
            let cos_j = cos_at(j as i32 * bk);

            let ltmp1 = l_mac(l_mult(ftmp2_real, cos_i), ftmp2_imag, sin_i);
            farray[i] = round_word(l_shr(l_add(lftmp1_real, ltmp1), 1));

            let ltmp1 = l_msu(l_mult(ftmp2_imag, cos_i), ftmp2_real, sin_i);
            farray[i + 1] = round_word(l_shr(l_add(lftmp1_imag, ltmp1), 1));

            let ltmp1 = l_msu(l_mult(ftmp2_real, cos_j), ftmp2_imag, sin_i);
            farray[j] = round_word(l_shr(l_add(lftmp1_real, ltmp1), 1));

            let ltmp1 = l_negate(l_mac(l_mult(ftmp2_imag, cos_j), ftmp2_real, sin_i));
            let ltmp2 = l_sub(ltmp1, lftmp1_imag);
            farray[j + 1] = round_word(l_shr(ltmp2, 1));
            i += 2;
        }

        // Perform the complex IFFT
        c_fft_wi(farray, size, stage, isign);
    }
}
