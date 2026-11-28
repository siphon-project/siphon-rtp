//! The TCX MDCT windows (TS 26.442 `lib_com/tcx_mdct_window.c`; TS 26.445 §5.3.2.2): the sine
//! overlap slopes, and the asymmetric low-delay (ALDO) window decimated from its 48 kHz / 25.6 kHz
//! master tables.

use crate::evs::com::basop_util::imult1616;
use crate::evs::com::rom_basop_util::get_sine_window_table;
use crate::evs::rom::types::PWord16;
use crate::evs::rom::{WINDOW_256KHZ, WINDOW_48KHZ_FX, WINDOW_8_16_32KHZ_FX};
use crate::itu::basic_ops::{shr, sub};

/// `mdct_window_sine`: point `window` at the sine slope of length `n`. A length without one
/// leaves it empty, the state's encoding of the reference's `NULL`.
pub fn mdct_window_sine(window: &mut &'static [PWord16], n: i16) {
    *window = get_sine_window_table(n).unwrap_or(&[]);
}

/// `mdct_window_aldo`: decimate the ALDO window for a frame of `n` (half the TCX frame length:
/// 160, 256, 320, 512, 640 or 960) into its three parts: the leading `n * 9 / 32` samples of the
/// long slope into `window1`, the rest of the long slope folded into `window1_trunc` (`n * 7 / 32`
/// pairs) and the short slope folded into `window2` (`n * 7 / 32` pairs). Any other `n` writes
/// nothing (the reference asserts).
pub fn mdct_window_aldo(
    window1: &mut [i16],
    window1_trunc: &mut [PWord16],
    window2: &mut [PWord16],
    n: i16,
) {
    // set table pointers and decimation factor
    let (table, mut p1, mut p2, d): (&[i16], usize, usize, usize) = match n {
        160 => (&WINDOW_48KHZ_FX, 2, 1110 - 3, 6),
        256 => (&WINDOW_256KHZ, 0, 592 - 1, 2),
        320 => (&WINDOW_48KHZ_FX, 1, 1110 - 2, 3),
        512 => (&WINDOW_256KHZ, 0, 592 - 1, 1),
        640 => (&WINDOW_48KHZ_FX, 1, 1110 - 2, 3),
        960 => (&WINDOW_48KHZ_FX, 0, 1110 - 1, 1),
        _ => return,
    };

    // set lengths
    let n0 = shr(imult1616(n, 9), 5);
    let n1 = shr(imult1616(n, 23), 5); // left slope length
    let n2 = shr(imult1616(n, 14), 5); // right slope length
    let half = shr(n, 1);
    let interleaved = sub(n, 1280 / 2) == 0;
    let odd_offset = n == 512 / 2 || n == 320 / 2;

    // first part (long slope)
    let mut w1 = 0usize;
    let mut trunc = 0usize;
    if !interleaved {
        let mut i = 0;
        while i < n0 {
            window1[w1] = table[p1];
            w1 += 1;
            p1 += d;
            i += 1;
        }
        while i < half {
            window1_trunc[trunc].v.im = table[p1];
            trunc += 1;
            p1 += d;
            i += 1;
        }
        if odd_offset {
            p1 += 1;
        }
        while i < n1 {
            trunc -= 1;
            window1_trunc[trunc].v.re = table[p1];
            p1 += d;
            i += 1;
        }
    } else {
        let mut pi = 0usize;
        let mut i = 0;
        while i < n0 {
            window1[w1] = table[p1];
            w1 += 1;
            p1 += d;
            window1[w1] = WINDOW_8_16_32KHZ_FX[pi];
            w1 += 1;
            pi += 1;
            i += 2;
        }
        while i < half {
            window1_trunc[trunc].v.im = table[p1];
            trunc += 1;
            p1 += d;
            window1_trunc[trunc].v.im = WINDOW_8_16_32KHZ_FX[pi];
            trunc += 1;
            pi += 1;
            i += 2;
        }
        while i < n1 {
            trunc -= 1;
            window1_trunc[trunc].v.re = WINDOW_8_16_32KHZ_FX[pi];
            pi += 1;
            trunc -= 1;
            window1_trunc[trunc].v.re = table[p1];
            p1 += d;
            i += 2;
        }
    }

    // second part (short slope)
    let mut w2 = 0usize;
    let half2 = shr(n2, 1);
    if !interleaved {
        let mut i = 0;
        while i < half2 {
            window2[w2].v.im = table[p2];
            w2 += 1;
            p2 = p2.wrapping_sub(d);
            i += 1;
        }
        if odd_offset {
            p2 -= 1;
        }
        while i < n2 {
            w2 -= 1;
            window2[w2].v.re = table[p2];
            // The last step leaves p2 one decimation step before the table on the 160 setup;
            // the reference forms that pointer without reading it.
            p2 = p2.wrapping_sub(d);
            i += 1;
        }
    } else {
        let mut pi = 370 - 1;
        let mut i = 0;
        while i < half2 {
            window2[w2].v.im = table[p2];
            w2 += 1;
            p2 = p2.wrapping_sub(d);
            window2[w2].v.im = WINDOW_8_16_32KHZ_FX[pi];
            w2 += 1;
            pi = pi.wrapping_sub(1);
            i += 2;
        }
        while i < n2 {
            w2 -= 1;
            window2[w2].v.re = WINDOW_8_16_32KHZ_FX[pi];
            pi = pi.wrapping_sub(1);
            w2 -= 1;
            window2[w2].v.re = table[p2];
            p2 = p2.wrapping_sub(d);
            i += 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sine_window_follows_the_rom_table() {
        let mut window: &'static [PWord16] = &[];
        mdct_window_sine(&mut window, 140);
        assert_eq!(window.len(), 70);
        mdct_window_sine(&mut window, 11);
        assert!(window.is_empty());
    }

    #[test]
    fn unknown_aldo_length_writes_nothing() {
        let mut w1 = [7i16; 4];
        let mut trunc = vec![PWord16::zeroed(); 4];
        let mut w2 = vec![PWord16::zeroed(); 4];
        mdct_window_aldo(&mut w1, &mut trunc, &mut w2, 100);
        assert_eq!(w1, [7; 4]);
    }
}
