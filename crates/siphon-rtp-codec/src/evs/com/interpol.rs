//! Polyphase interpolation for the resampler (TS 26.442 `lib_com/interpol_fx.c`).
//!
//! Only `Interpol_lc_fx`, the kernel of `modify_Fs_fx`, is ported here.

use crate::itu::basic_ops::l_shl;
use crate::itu::stl2009::{l_mac0, l_mult0};

/// `Interpol_lc_fx`: one output sample of the polyphase filter `win` (Q14) at phase `frac` of
/// `up_samp`, `nb_coef` taps either side of `x[x_at]` (Qx), returned in Qx+16.
///
/// The taps read `win[frac + i·up_samp]` and `win[up_samp - frac + i·up_samp]`; a zero tap is
/// skipped exactly as the reference skips it. A tap past the end of `win` (no resampling
/// configuration reaches one) is read as zero.
#[must_use]
pub fn interpol_lc(
    x: &[i16],
    x_at: usize,
    win: &[i16],
    frac: i16,
    up_samp: i16,
    nb_coef: i16,
) -> i32 {
    let tap = |index: i32| -> i16 {
        usize::try_from(index)
            .ok()
            .and_then(|i| win.get(i))
            .copied()
            .unwrap_or(0)
    };
    let mut x1 = x_at as isize;
    let mut x2 = x_at + 1;
    let mut c1 = i32::from(frac);
    let mut c2 = i32::from(up_samp) - i32::from(frac);
    let sample = |at: isize| -> i16 {
        usize::try_from(at)
            .ok()
            .and_then(|i| x.get(i))
            .copied()
            .unwrap_or(0)
    };
    let mut l_sum = l_mult0(sample(x1), tap(c1));
    x1 -= 1;
    l_sum = l_mac0(l_sum, sample(x2 as isize), tap(c2));
    x2 += 1;
    for _ in 1..nb_coef {
        c2 += i32::from(up_samp);
        c1 += i32::from(up_samp);
        // L_mac0 limits the risk of saturation inside the loop; it may still saturate after it
        let t1 = tap(c1);
        if t1 != 0 {
            l_sum = l_mac0(l_sum, sample(x1), t1);
        }
        x1 -= 1;
        let t2 = tap(c2);
        if t2 != 0 {
            l_sum = l_mac0(l_sum, sample(x2 as isize), t2);
        }
        x2 += 1;
    }
    l_shl(l_sum, 1)
}
