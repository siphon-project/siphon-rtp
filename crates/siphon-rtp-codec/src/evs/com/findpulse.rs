//! Position of the dominant pitch pulse of a residual (TS 26.442 `lib_com/findpulse_fx.c`;
//! TS 26.445 §5.4.2.3 and §6.5.3 for the decoder-side concealment use).

use crate::evs::cnst::{DEC, L_FRAME16K};
use crate::itu::basic_ops::{add, l_mac, l_mult, negate, shr, sub};
use crate::itu::stl2009::{l_msu0, l_mult0, mac_r};

/// `findpulse_fx`: the position of the "biggest" pulse of the last pitch section of `res`. With
/// `enc` other than `DEC` (encoder side) the residual is first low-pass filtered by
/// `[0.25 0.5 0.25]` and the pulse is the largest magnitude among the last `t0` filtered samples
/// counted from the end, `sign` receiving its sign; on the decoder side the pulse is the
/// largest (`*sign == 0`) or smallest value among the first `t0` samples of `res`, and the result
/// is one past its position (0 when there is none). `res` holds at least `l_frame` samples on the
/// encoder side and `t0` on the decoder side.
pub fn findpulse(l_frame: i16, res: &[i16], t0: i16, enc: i16, sign: &mut i16) -> i16 {
    let mut maxi: i16 = 0;

    if sub(enc, DEC) != 0 {
        // 1. very simple LP filter
        let mut resf = [0i16; L_FRAME16K as usize];
        let frame = l_frame.max(0) as usize;
        if frame < 2 || frame > resf.len() || res.len() < frame {
            // the reference only runs on whole frames; nothing to filter otherwise
            return 0;
        }
        // resf[0] = 0.50 * res[0] + 0.25 * res[1]
        resf[0] = mac_r(l_mult(res[0], 16384), res[1], 8192);
        for i in 1..frame - 1 {
            // resf[i] = 0.25 * res[i-1] + 0.5 * res[i] + 0.25 * res[i+1]
            let l_tmp = l_mult(8192, res[i - 1]);
            let l_tmp = l_mac(l_tmp, 16384, res[i]);
            resf[i] = mac_r(l_tmp, 8192, res[i + 1]);
        }
        // resf[L_frame-1] = 0.25 * res[L_frame-2] + 0.50 * res[L_frame-1]
        resf[frame - 1] = mac_r(l_mult(res[frame - 2], 8192), 16384, res[frame - 1]);

        // 2. find the "biggest" pitch pulse
        let ptr = frame - 1;
        for i in 1..t0.max(0) as usize {
            if i > ptr {
                break;
            }
            let at_max = resf[ptr - maxi as usize];
            let l_tmp = l_mult0(at_max, at_max);
            if l_msu0(l_tmp, resf[ptr - i], resf[ptr - i]) < 0 {
                maxi = i as i16;
            }
        }
        *sign = negate(shr(resf[ptr - maxi as usize], 15));
    } else {
        // 2. find the "biggest" pulse in the last pitch section according to the sign
        let mut maxval: i16 = 0;
        let count = t0.max(0) as usize;
        if *sign == 0 {
            for (i, &value) in res.iter().enumerate().take(count) {
                if sub(value, maxval) >= 0 {
                    maxi = add(i as i16, 1);
                }
                maxval = maxval.max(value);
            }
        } else {
            for (i, &value) in res.iter().enumerate().take(count) {
                if sub(value, maxval) <= 0 {
                    maxi = add(i as i16, 1);
                }
                maxval = maxval.min(value);
            }
        }
    }
    maxi
}
