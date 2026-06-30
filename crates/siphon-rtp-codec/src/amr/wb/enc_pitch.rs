// AMR-WB encoder — WORK IN PROGRESS: not yet wired into the codec factory or validated
// bit-exact. Ported from the 3GPP fixed-point C reference (index loops / manual slice
// copies mirror the C, plus not-yet-used WIP code); these style + dead-code lints are
// quieted module-wide until the encoder is complete and validated, then revisited.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_memcpy,
    clippy::explicit_counter_loop,
    clippy::manual_div_ceil,
    clippy::unnecessary_to_owned,
    dead_code,
    unused
)]

//! AMR-WB encoder open-loop pitch tier (3GPP TS 26.173 `p_med_ol.c` + `hp_wsp.c`), ported bit-exact.
//!
//! [`pitch_med_ol`] finds the open-loop pitch lag of the (decimated) weighted speech via a weighted
//! correlation maximum, then a normalized correlation gain on the 180 Hz high-passed weighted speech
//! ([`hp_wsp`]). [`med_olag`]/[`median5`] track the median of the last open-loop lags.

use crate::amr::basic_ops::{
    add, l_add, l_deposit_h, l_mac, l_shl, norm_l, round_word, shl, shr, sub,
};
use crate::amr::math_op::isqrt_n;
use crate::amr::oper_32b::{l_comp, l_extract, mpy_32_16};

/// `corrweight` table for the open-loop correlation weighting (`p_med_ol.tab`), 199 entries.
#[rustfmt::skip]
static CORRWEIGHT: [i16; 199] = [
    10772, 10794, 10816, 10839, 10862, 10885, 10908, 10932, 10955, 10980,
    11004, 11029, 11054, 11079, 11105, 11131, 11157, 11183, 11210, 11238,
    11265, 11293, 11322, 11350, 11379, 11409, 11439, 11469, 11500, 11531,
    11563, 11595, 11628, 11661, 11694, 11728, 11763, 11798, 11834, 11870,
    11907, 11945, 11983, 12022, 12061, 12101, 12142, 12184, 12226, 12270,
    12314, 12358, 12404, 12451, 12498, 12547, 12596, 12647, 12699, 12751,
    12805, 12861, 12917, 12975, 13034, 13095, 13157, 13221, 13286, 13353,
    13422, 13493, 13566, 13641, 13719, 13798, 13880, 13965, 14053, 14143,
    14237, 14334, 14435, 14539, 14648, 14761, 14879, 15002, 15130, 15265,
    15406, 15554, 15710, 15874, 16056, 16384, 16384, 16384, 16384, 16384,
    16384, 16384, 16056, 15874, 15710, 15554, 15406, 15265, 15130, 15002,
    14879, 14761, 14648, 14539, 14435, 14334, 14237, 14143, 14053, 13965,
    13880, 13798, 13719, 13641, 13566, 13493, 13422, 13353, 13286, 13221,
    13157, 13095, 13034, 12975, 12917, 12861, 12805, 12751, 12699, 12647,
    12596, 12547, 12498, 12451, 12404, 12358, 12314, 12270, 12226, 12184,
    12142, 12101, 12061, 12022, 11983, 11945, 11907, 11870, 11834, 11798,
    11763, 11728, 11694, 11661, 11628, 11595, 11563, 11531, 11500, 11469,
    11439, 11409, 11379, 11350, 11322, 11293, 11265, 11238, 11210, 11183,
    11157, 11131, 11105, 11079, 11054, 11029, 11004, 10980, 10955, 10932,
    10908, 10885, 10862, 10839, 10816, 10794, 10772, 10750, 10728,
];

/// 180 Hz HP filter coefficients (Q12) for `hp_wsp.c`.
const HPWSP_A: [i16; 4] = [8192, 21663, -19258, 5734];
const HPWSP_B: [i16; 4] = [-3432, 10280, -10280, 3432];

/// 3rd-order 180 Hz high-pass filter (`hp_wsp.c` `Hp_wsp`). `wsp[0..lg]` → `hp_wsp[0..lg]`; `mem[9]`
/// holds `[y3_hi,y3_lo,y2_hi,y2_lo,y1_hi,y1_lo,x0,x1,x2]`.
pub fn hp_wsp(
    wsp: &[i16],
    wsp_off: usize,
    hp_wsp_out: &mut [i16],
    hp_off: usize,
    lg: usize,
    mem: &mut [i16; 9],
) {
    let mut y3_hi = mem[0];
    let mut y3_lo = mem[1];
    let mut y2_hi = mem[2];
    let mut y2_lo = mem[3];
    let mut y1_hi = mem[4];
    let mut y1_lo = mem[5];
    let mut x0 = mem[6];
    let mut x1 = mem[7];
    let mut x2 = mem[8];

    for i in 0..lg {
        let x3 = x2;
        x2 = x1;
        x1 = x0;
        x0 = wsp[wsp_off + i];

        let mut l_tmp = 16384i32;
        l_tmp = l_mac(l_tmp, y1_lo, HPWSP_A[1]);
        l_tmp = l_mac(l_tmp, y2_lo, HPWSP_A[2]);
        l_tmp = l_mac(l_tmp, y3_lo, HPWSP_A[3]);
        l_tmp = crate::amr::basic_ops::l_shr(l_tmp, 15);
        l_tmp = l_mac(l_tmp, y1_hi, HPWSP_A[1]);
        l_tmp = l_mac(l_tmp, y2_hi, HPWSP_A[2]);
        l_tmp = l_mac(l_tmp, y3_hi, HPWSP_A[3]);
        l_tmp = l_mac(l_tmp, x0, HPWSP_B[0]);
        l_tmp = l_mac(l_tmp, x1, HPWSP_B[1]);
        l_tmp = l_mac(l_tmp, x2, HPWSP_B[2]);
        l_tmp = l_mac(l_tmp, x3, HPWSP_B[3]);

        l_tmp = l_shl(l_tmp, 2);

        y3_hi = y2_hi;
        y3_lo = y2_lo;
        y2_hi = y1_hi;
        y2_lo = y1_lo;
        (y1_hi, y1_lo) = l_extract(l_tmp);

        l_tmp = l_shl(l_tmp, 1);
        hp_wsp_out[hp_off + i] = round_word(l_tmp);
    }

    *mem = [y3_hi, y3_lo, y2_hi, y2_lo, y1_hi, y1_lo, x0, x1, x2];
}

/// Scale the `hp_wsp` filter memory by `exp` (`hp_wsp.c` `scale_mem_Hp_wsp`).
pub fn scale_mem_hp_wsp(mem: &mut [i16; 9], exp: i16) {
    let mut i = 0;
    while i < 6 {
        let mut l_tmp = l_comp(mem[i], mem[i + 1]);
        l_tmp = l_shl(l_tmp, exp);
        (mem[i], mem[i + 1]) = l_extract(l_tmp);
        i += 2;
    }
    for v in mem.iter_mut().take(9).skip(6) {
        let mut l_tmp = l_deposit_h(*v);
        l_tmp = l_shl(l_tmp, exp);
        *v = round_word(l_tmp);
    }
}

/// Open-loop pitch lag with weighted correlation + normalized gain (`p_med_ol.c` `Pitch_med_ol`).
///
/// `wsp` is the decimated weighted speech with `wsp[wsp_off-pit_max .. wsp_off-1]` valid history.
/// `old_hp_wsp` holds `l_max + l_frame/2 + pit_max/decim` samples of past high-passed wsp and is
/// updated. Returns `(lag, gain)`; the gain is written too.
#[allow(clippy::too_many_arguments)]
pub fn pitch_med_ol(
    wsp: &[i16],
    wsp_off: usize,
    l_min: i16,
    l_max: i16,
    l_frame: i16,
    l_0: i16,
    gain: &mut i16,
    hp_wsp_mem: &mut [i16; 9],
    old_hp_wsp: &mut [i16],
    wght_flg: i16,
) -> i16 {
    // ww = &corrweight[198]; we = &corrweight[98 + L_max - L_0]
    let mut ww = 198i32;
    let mut we = 98i32 + l_max as i32 - l_0 as i32;

    let mut max = i32::MIN;
    let mut tm = 0i16;
    let mut i = l_max;
    while i > l_min {
        let mut r0 = 0i32;
        for j in 0..l_frame as usize {
            r0 = l_mac(
                r0,
                wsp[wsp_off + j],
                wsp[(wsp_off as isize + j as isize - i as isize) as usize],
            );
        }
        let (hi, lo) = l_extract(r0);
        r0 = mpy_32_16(hi, lo, CORRWEIGHT[ww as usize]);
        ww -= 1;

        if l_0 > 0 && wght_flg > 0 {
            let (hi2, lo2) = l_extract(r0);
            r0 = mpy_32_16(hi2, lo2, CORRWEIGHT[we as usize]);
            we -= 1;
        }
        if l_add(r0, 0) >= max {
            // L_sub(R0, max) >= 0
            max = r0;
            tm = i;
        }
        i -= 1;
    }

    // hp_wsp = old_hp_wsp + L_max
    let hp_base = l_max as usize;
    hp_wsp(
        wsp,
        wsp_off,
        old_hp_wsp,
        hp_base,
        l_frame as usize,
        hp_wsp_mem,
    );

    let mut r0 = 0i32;
    let mut r1 = 1i32;
    let mut r2 = 1i32;
    for j in 0..l_frame as usize {
        let cur = old_hp_wsp[hp_base + j];
        let lag = old_hp_wsp[(hp_base as isize + j as isize - tm as isize) as usize];
        r0 = l_mac(r0, cur, lag);
        r1 = l_mac(r1, lag, lag);
        r2 = l_mac(r2, cur, cur);
    }

    let exp_r0 = norm_l(r0);
    r0 = l_shl(r0, exp_r0);
    let exp_r1 = norm_l(r1);
    r1 = l_shl(r1, exp_r1);
    let exp_r2 = norm_l(r2);
    r2 = l_shl(r2, exp_r2);

    r1 = crate::amr::basic_ops::l_mult(round_word(r1), round_word(r2));
    let inorm = norm_l(r1);
    r1 = l_shl(r1, inorm);

    let mut exp_r1b = add(exp_r1, exp_r2);
    exp_r1b = add(exp_r1b, inorm);
    exp_r1b = sub(62, exp_r1b);

    isqrt_n(&mut r1, &mut exp_r1b);

    r0 = crate::amr::basic_ops::l_mult(round_word(r0), round_word(r1));
    let mut exp_r0b = sub(31, exp_r0);
    exp_r0b = add(exp_r0b, exp_r1b);

    *gain = round_word(l_shl(r0, exp_r0b));

    // Shift hp_wsp[] for next frame.
    for k in 0..l_max as usize {
        old_hp_wsp[k] = old_hp_wsp[k + l_frame as usize];
    }

    tm
}

/// Median of `{x[-2], x[-1], x[0], x[1], x[2]}` (`p_med_ol.c` `median5`); `center` indexes `x[0]`.
pub fn median5(x: &[i16], center: usize) -> i16 {
    let mut x1 = x[center - 2];
    let mut x2 = x[center - 1];
    let mut x3 = x[center];
    let mut x4 = x[center + 1];
    let mut x5 = x[center + 2];

    if sub(x2, x1) < 0 {
        core::mem::swap(&mut x1, &mut x2);
    }
    if sub(x3, x1) < 0 {
        core::mem::swap(&mut x1, &mut x3);
    }
    if sub(x4, x1) < 0 {
        core::mem::swap(&mut x1, &mut x4);
    }
    if sub(x5, x1) < 0 {
        x5 = x1;
    }
    if sub(x3, x2) < 0 {
        core::mem::swap(&mut x2, &mut x3);
    }
    if sub(x4, x2) < 0 {
        core::mem::swap(&mut x2, &mut x4);
    }
    if sub(x5, x2) < 0 {
        x5 = x2;
    }
    if sub(x4, x3) < 0 {
        x3 = x4;
    }
    if sub(x5, x3) < 0 {
        x3 = x5;
    }
    x3
}

/// Median of the 5 previous open-loop lags (`p_med_ol.c` `Med_olag`). `old_ol_lag[5]` is updated.
pub fn med_olag(prev_ol_lag: i16, old_ol_lag: &mut [i16; 5]) -> i16 {
    for i in (1..5).rev() {
        old_ol_lag[i] = old_ol_lag[i - 1];
    }
    old_ol_lag[0] = prev_ol_lag;
    // median5(&old_ol_lag[2]) -> window old_ol_lag[0..5], center index 2.
    median5(old_ol_lag, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median5_picks_the_middle() {
        let x = [0i16, 0, 1, 5, 2, 8, 3];
        assert_eq!(median5(&x, 4), 3);
    }

    #[test]
    fn med_olag_shifts_and_medians() {
        let mut buf = [40i16; 5];
        let m = med_olag(60, &mut buf);
        assert_eq!(buf[0], 60);
        assert_eq!(m, 40); // median of {60,40,40,40,40}
    }

    #[test]
    fn hp_wsp_silent_on_zero() {
        let wsp = [0i16; 64];
        let mut out = [0i16; 64];
        let mut mem = [0i16; 9];
        hp_wsp(&wsp, 0, &mut out, 0, 64, &mut mem);
        assert!(out.iter().all(|&v| v == 0));
    }
}
