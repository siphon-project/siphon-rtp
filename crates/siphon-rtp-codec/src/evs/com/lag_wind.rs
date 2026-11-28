//! Lag windowing of autocorrelations (TS 26.442 `lib_com/lag_wind.c`; TS 26.445 §5.1.9.2).
//!
//! Only `lag_wind` is ported (`adapt_lag_wind` is encoder-only).

use crate::evs::rom::{
    LAG_WINDOW_12K8, LAG_WINDOW_16K, LAG_WINDOW_25K6, LAG_WINDOW_32K, LAG_WINDOW_48K, LAG_WINDOW_8K,
};
use crate::itu::oper_32b::{l_extract, mpy_32};

/// `LAGW_WEAK` (the reference's lag-window strength enum, `lib_com/cnst_fx.h`).
pub const LAGW_WEAK: i16 = 0;
/// `LAGW_MEDIUM`.
pub const LAGW_MEDIUM: i16 = 1;
/// `LAGW_STRONG`.
pub const LAGW_STRONG: i16 = 2;

/// `lag_wind`: multiply the autocorrelations `r[1..=m]` (DPF `r_h`/`r_l`) by the lag window of
/// sampling rate `sr` and `strength`. A rate the reference has no window for (it asserts) leaves
/// `r` untouched, as the reference's release build returns there.
pub fn lag_wind(r_h: &mut [i16], r_l: &mut [i16], m: i16, sr: i32, strength: i16) {
    let s = usize::try_from(strength).unwrap_or(0).min(2);
    let (wnd_h, wnd_l): (&[i16; 16], &[i16; 16]) = match sr {
        8000 => (&LAG_WINDOW_8K[0], &LAG_WINDOW_8K[1]),
        12800 => (&LAG_WINDOW_12K8[s][0], &LAG_WINDOW_12K8[s][1]),
        16000 => (&LAG_WINDOW_16K[s][0], &LAG_WINDOW_16K[s][1]),
        24000 | 25600 => (&LAG_WINDOW_25K6[s][0], &LAG_WINDOW_25K6[s][1]),
        32000 => (&LAG_WINDOW_32K[s][0], &LAG_WINDOW_32K[s][1]),
        48000 => (&LAG_WINDOW_48K[0], &LAG_WINDOW_48K[1]),
        _ => return,
    };
    // every window has 16 lags (the reference asserts m <= 16)
    let m = usize::try_from(m).unwrap_or(0).min(16);
    for i in 1..=m {
        let tmp = mpy_32(r_h[i], r_l[i], wnd_h[i - 1], wnd_l[i - 1]);
        (r_h[i], r_l[i]) = l_extract(tmp);
    }
}
