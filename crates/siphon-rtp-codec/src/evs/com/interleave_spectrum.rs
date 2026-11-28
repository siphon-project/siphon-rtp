//! Interleaving of the transient HQ spectrum (TS 26.442 `lib_com/interleave_spectrum_fx.c`;
//! TS 26.445 §6.2.2.3.5).

use crate::evs::cnst::{L_FRAME32K, L_FRAME48K, N_INTL_GRP_16, N_INTL_GRP_32, N_INTL_GRP_48};
use crate::evs::rom::{INTL_BW_16, INTL_BW_32, INTL_BW_48, INTL_CNT_16, INTL_CNT_32, INTL_CNT_48};
use crate::itu::basic_ops::sub;

/// Largest spectrum: `L_FRAME48k`.
const L_FRAME48K_LEN: usize = L_FRAME48K as usize;

/// Group layout of a frame length: block widths, repeat counts, group count (`intl_bw_*`,
/// `intl_cnt_*`, `N_INTL_GRP_*`).
fn layout(length: i16) -> (&'static [i16], &'static [i16], usize) {
    if sub(length, L_FRAME48K) == 0 {
        (&INTL_BW_48, &INTL_CNT_48, N_INTL_GRP_48 as usize)
    } else if sub(length, L_FRAME32K) == 0 {
        (&INTL_BW_32, &INTL_CNT_32, N_INTL_GRP_32 as usize)
    } else {
        // length == L_FRAME16k
        (&INTL_BW_16, &INTL_CNT_16, N_INTL_GRP_16 as usize)
    }
}

/// `interleave_spectrum_fx`: interleave the four quarters of `coefs` (240 / 160 / 80 coefficients
/// each for 48 / 32 / 16 kHz frames) block by block. The 48 kHz layout covers 800 coefficients
/// and leaves the rest of `coefs` untouched.
pub fn interleave_spectrum(coefs: &mut [i32], length: i16) {
    let mut coefs_out = [0i32; L_FRAME48K_LEN];
    let sublen: usize = if sub(length, L_FRAME48K) == 0 {
        240
    } else if sub(length, L_FRAME32K) == 0 {
        160
    } else {
        80
    };
    let (bw, cnt, grps) = layout(length);
    let mut quarter = [0usize, sublen, 2 * sublen, 3 * sublen];
    let mut p_out = 0usize;
    for i in 0..grps {
        let width = bw[i] as usize;
        for _ in 0..cnt[i] {
            for pointer in &mut quarter {
                for _ in 0..width {
                    coefs_out[p_out] = coefs[*pointer];
                    p_out += 1;
                    *pointer += 1;
                }
            }
        }
    }
    // For FB the interleaved spectrum is 800 samples
    coefs[..p_out].copy_from_slice(&coefs_out[..p_out]);
}

/// `de_interleave_spectrum_fx`: the inverse of [`interleave_spectrum`] over `length` coefficients;
/// the bins past the interleaved region come out zero.
pub fn de_interleave_spectrum(coefs: &mut [i32], length: i16) {
    let mut coefs_out = [0i32; L_FRAME48K_LEN];
    // quarter starts: length/4, 2*length/4 and 3*length/4 (240/480/720, 160/320/480, 80/160/240)
    let quarter_len: usize = if sub(length, L_FRAME48K) == 0 {
        240
    } else if sub(length, L_FRAME32K) == 0 {
        160
    } else {
        80
    };
    let (bw, cnt, grps) = layout(length);
    let mut quarter = [0usize, quarter_len, 2 * quarter_len, 3 * quarter_len];
    let mut p_in = 0usize;
    for i in 0..grps {
        let width = bw[i] as usize;
        for _ in 0..cnt[i] {
            for pointer in &mut quarter {
                for _ in 0..width {
                    coefs_out[*pointer] = coefs[p_in];
                    p_in += 1;
                    *pointer += 1;
                }
            }
        }
    }
    let length = (length.max(0) as usize).min(L_FRAME48K_LEN);
    coefs[..length].copy_from_slice(&coefs_out[..length]);
}
