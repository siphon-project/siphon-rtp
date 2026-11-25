//! Pitch prediction for a lost frame by a weighted linear fit over the past subframe lags (TS
//! 26.442 `lib_dec/pitch_extr.c`; TS 26.447 §5.4.2.2), and the per-subframe lags between two
//! pitch values (`get_subframe_pitch`, MODE2).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{NB_SUBFR, NB_SUBFR16K, ONSET, UNVOICED_TRANSITION};
use crate::evs::com::basop_util::{basop_util_add_mant32_exp, basop_util_divide3216_scale};
use crate::itu::basic_ops::{
    add, extract_h, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_negate, l_shl, l_sub,
    mult, mult_r, norm_l, round_word, shr, sub,
};
use crate::itu::stl2009::{l_mult0, l_shl_r, mac_r};

/// The weights of the five most recent subframes in the fit (Q14).
const TIME_WEIGHT: [i16; 5] = [20480, 18432, 16384, 14336, 12288];

/// `pitch_pred_linear_fit`: the pitch lag `t0_out` (Q16) predicted for the end of a lost frame
/// of `nb_subfr` subframes from the past lags `old_pitch_buf` (Q16, `2·nb_subfr + 2` of them,
/// oldest first) weighted by the squared past pitch gains `mem_pitch_gain` (Q14, newest first),
/// limited to `[pit_min, pit_max]`. Only the first lost frame after a voiced one is
/// extrapolated; otherwise, or when the lags vary too much, `extrapolation_failed` is set and
/// `t0_out` is the last lag `old_fpitch` (or 0).
///
/// When `old_fpitch` is above `pit_max`, the reference writes `pit_max` into the Q16 output
/// unconverted (a Q0 value), and so does this port.
pub fn pitch_pred_linear_fit(
    bfi_cnt: i16,
    last_good: i16,
    old_pitch_buf: &[i32],
    old_fpitch: i32,
    t0_out: &mut i32,
    pit_min: i16,
    pit_max: i16,
    mem_pitch_gain: &[i16],
    limitation: i16,
    plc_use_future_lag: i8,
    extrapolation_failed: &mut i16,
    nb_subfr: i16,
) {
    let mut mem_lag = [0i32; 2 * NB_SUBFR16K as usize + 2];

    // Inverse the order the pitch lag memory
    let lags = if sub(nb_subfr, 4) == 0 {
        2 * NB_SUBFR as usize + 2
    } else {
        // L_frame == L_FRAME16k
        2 * NB_SUBFR16K as usize + 2
    };
    for i in 0..lags {
        mem_lag[i] = old_pitch_buf[lags - 1 - i];
    }

    if 0 > sub(pit_max, extract_h(old_fpitch)) {
        *extrapolation_failed = 1;
        *t0_out = i32::from(pit_max);
        return;
    }

    let t0: i32;
    if sub(bfi_cnt, 1) == 0 && sub(last_good, UNVOICED_TRANSITION) >= 0 && sub(last_good, ONSET) < 0
    {
        let no_subfr_pred: i16 = if plc_use_future_lag != 0 { 2 } else { 4 };

        // copy to local buffers, depending on availability of info about future subframes
        let from = (no_subfr_pred - 2) as usize;
        let mut pg = [0i16; 8];
        let mut ml = [0i32; 8];
        pg.copy_from_slice(&mem_pitch_gain[from..from + 8]);
        ml.copy_from_slice(&mem_lag[from..from + 8]);

        t0 = pitch_pred_linear_fit_extrapolate(
            &mut pg,
            &ml,
            old_fpitch,
            pit_min,
            pit_max,
            limitation,
            no_subfr_pred,
            nb_subfr,
            extrapolation_failed,
        );
    } else {
        t0 = l_add(old_fpitch, 0);
        *extrapolation_failed = 1;
    }
    *t0_out = t0;
}

/// The fit itself, on the local copies of the gains `pg` and lags `ml` (newest first): 0 with
/// `extrapolation_failed` set when the largest lag step is too large or the weights vanish.
fn pitch_pred_linear_fit_extrapolate(
    pg: &mut [i16; 8],
    ml: &[i32; 8],
    old_fpitch: i32,
    pit_min: i16,
    pit_max: i16,
    limitation: i16,
    no_subfr_pred: i16,
    nb_subfr: i16,
    extrapolation_failed: &mut i16,
) -> i32 {
    const LCOR: usize = 5;
    let mut dy = [0i32; 5];
    let mut mdy = l_deposit_l(0);

    for i in (0..LCOR).rev() {
        dy[i] = l_sub(ml[i], ml[i + 1]);
        mdy = l_add(mdy, dy[i]);
    }

    // remove maximum variation
    let mut imax = 0usize;
    let mut pita = l_abs(dy[0]);
    for (i, &step) in dy.iter().enumerate().skip(1) {
        if l_sub(pita, l_abs(step)) < 0 {
            pita = l_abs(step);
            imax = i;
        }
    }
    if !(l_sub(l_abs(dy[imax]), mpy_32_16_1(old_fpitch, 4915)) < 0
        && (sub(limitation, 1) == 0 || l_sub(l_abs(dy[imax]), l_abs(mdy)) < 0))
    {
        *extrapolation_failed = 1;
        return l_deposit_l(0);
    }

    for i in 0..LCOR {
        // Q12 'til pg[lcor-1], Q14 'til pg[8]
        pg[i] = mult(mult(pg[i], pg[i]), TIME_WEIGHT[i]);
    }

    // Linear prediction (estimation) of pitch
    let (mut sum0, mut sum0_q) = pitch_pred_linear_fit_sum0(pg);
    if sum0 == 0 {
        *extrapolation_failed = 1;
        return l_deposit_l(0);
    }

    // Shift to the right, changing Q as long as no precision is lost
    while sum0 & 1 == 0 {
        sum0 = shr(sum0, 1);
        sum0_q = sub(sum0_q, 1);
    }

    let (a1, tmpa, a_e) = pitch_pred_linear_fit_a(pg, ml, sum0);
    let (b1, tmpb, b_e) = pitch_pred_linear_fit_b(pg, ml, sum0);

    // pit = a + b * ((float)no_subfr_pred + (float)nb_subfr);
    let pita = l_shl(
        l_deposit_l(a1),
        add(add(sum0_q, 16 - 10 + 1), sub(tmpa, a_e)),
    ); // Q16
    let pitb = l_shl_r(
        l_mult(b1, add(no_subfr_pred, nb_subfr)),
        add(add(sum0_q, 16 - 12), sub(tmpb, b_e)),
    );
    let pit = l_add(pita, pitb); // Q16

    let mut t0 = l_add(pit, 0);

    // limit pitch to allowed range
    t0 = l_deposit_h(pit_max).min(t0);
    t0 = l_deposit_h(pit_min).max(t0);

    *extrapolation_failed = 0;
    t0
}

/// The denominator of the fit, `(pg1+4pg2+9pg3+16pg4)pg0 + (pg2+4pg3+9pg4)pg1 + (pg3+4pg4)pg2 +
/// pg4·pg3`, as a Q`sum0_q` 16-bit value.
fn pitch_pred_linear_fit_sum0(pg: &[i16; 8]) -> (i16, i16) {
    let dl = |x: i16| l_deposit_l(x);
    let t1 = l_mult0(pg[4], pg[3]); // Q24, t1 = pg[4]*pg[3]
    let e1: i16 = 7;
    let mut t2 = l_add(dl(pg[3]), l_shl(dl(pg[4]), 2)); // Q12
    let mut e2 = norm_l(t2);
    t2 = l_shl(t2, e2); // Q12,-e2
    t2 = mpy_32_16_1(t2, pg[2]); // Q9,-e2, t2 = (pg[3]+4*pg[4])*pg[2]
    e2 = sub(22, e2);
    let mut t3 = l_add(
        dl(pg[2]),
        l_add(l_shl(dl(pg[3]), 2), l_add(l_shl(dl(pg[4]), 3), dl(pg[4]))),
    ); // Q12
    let mut e3 = norm_l(t3);
    t3 = l_shl(t3, e3); // Q12,-e3
    t3 = mpy_32_16_1(t3, pg[1]); // Q9,-e3, t3 = (pg[2]+4*pg[3]+9*pg[4])*pg[1]
    e3 = sub(22, e3);
    let mut t4 = l_add(
        i32::from(pg[1]),
        l_add(
            l_shl(dl(pg[2]), 2),
            l_add(l_add(l_shl(dl(pg[3]), 3), dl(pg[3])), l_shl(dl(pg[4]), 4)),
        ),
    ); // Q12
    let mut e4 = norm_l(t4);
    t4 = l_shl(t4, e4); // Q12,-e4
    t4 = mpy_32_16_1(t4, pg[0]); // Q9,-e4, t4 = (pg[1]+4*pg[2]+9*pg[3]+16*pg[4])*pg[0]
    e4 = sub(22, e4);
    let (mut e5, mut e6, mut e7) = (0i16, 0i16, 0i16);
    let t5 = basop_util_add_mant32_exp(t1, e1, t2, e2, &mut e5);
    let t6 = basop_util_add_mant32_exp(t3, e3, t4, e4, &mut e6);
    let t7 = basop_util_add_mant32_exp(t5, e5, t6, e6, &mut e7); // Q31,e7
    let mut sum0_q = norm_l(t7);
    let sum0 = round_word(l_shl(t7, sum0_q)); // Q15,e7-sum0_q
    sum0_q = add(15, sub(sum0_q, e7)); // sum0 is now Qsum0_q
    (sum0, sum0_q)
}

/// `round_fx(L_shl(ml[i], 4))`: a lag in Q4.
fn lag_q4(ml: &[i32; 8], i: usize) -> i16 {
    round_word(l_shl(ml[i], 4))
}

/// The intercept `a` of the fit divided by `sum0`: the quotient, its scale and the numerator's
/// normalisation shift.
fn pitch_pred_linear_fit_a(pg: &[i16; 8], ml: &[i32; 8], sum0: i16) -> (i16, i16, i16) {
    // magic numbers: Q11 if not DIRECTLY marked otherwise
    let a5 = mac_r(
        l_mac(
            l_mac(
                l_mult(mult_r(-32768, pg[0]), pg[4]),
                mult_r(-9 * 2048, pg[1]),
                pg[4],
            ),
            mult_r(-4 * 2048, pg[2]),
            pg[4],
        ),
        mult_r(pg[4], -4096),
        mult_r(pg[3], 16384),
    ); // Q5
    let a4 = mac_r(
        l_mac(
            l_mult(mult_r(-12 * 2048, pg[0]), pg[3]),
            mult_r(-6 * 2048, pg[1]),
            pg[3],
        ),
        mult_r(-2 * 2048, pg[2]),
        pg[3],
    ); // Q5
    let a3 = mac_r(
        l_mac(
            l_mult(mult_r(-8 * 2048, pg[0]), pg[2]),
            mult_r(-3 * 2048, pg[1]),
            pg[2],
        ),
        mult_r(pg[2], 4096),
        mult_r(pg[3], 16384),
    ); // Q5
    let a2 = mac_r(
        l_mac(
            l_mult(mult_r(2 * 2048, pg[1]), pg[2]),
            mult_r(2 * 2048, pg[1]),
            pg[3],
        ),
        mult_r(-4 * 2048, pg[0]),
        pg[1],
    ); // Q5
    let a1 = mac_r(
        l_mac(
            l_mult(mult_r(3 * 2048, pg[0]), pg[1]),
            mult_r(4 * 2048, pg[0]),
            pg[2],
        ),
        mult_r(3 * 2048, pg[0]),
        pg[3],
    ); // Q5

    let mut a = l_mac(
        l_mac(
            l_mac(
                l_mac(l_mult(a1, lag_q4(ml, 0)), lag_q4(ml, 1), a2),
                lag_q4(ml, 2),
                a3,
            ),
            lag_q4(ml, 3),
            a4,
        ),
        lag_q4(ml, 4),
        a5,
    ); // Q-6+16 = Q10

    let a_e = norm_l(a);
    a = l_shl(a, a_e);

    let mut tmpa = 0i16;
    let quotient = basop_util_divide3216_scale(l_negate(a), sum0, &mut tmpa);
    (quotient, tmpa, a_e)
}

/// The slope `b` of the fit divided by `sum0`: the quotient, its scale and the numerator's
/// normalisation shift.
fn pitch_pred_linear_fit_b(pg: &[i16; 8], ml: &[i32; 8], sum0: i16) -> (i16, i16, i16) {
    // magic numbers in Q13 if not DIRECTLY marked otherwise
    let b1 = mac_r(
        l_mac(
            l_mac(
                l_mult(mult_r(pg[1], pg[0]), 8192),
                mult_r(2 * 8192, pg[0]),
                pg[2],
            ),
            mult_r(3 * 8192, pg[0]),
            pg[3],
        ),
        pg[0],
        pg[4],
    ); // Q7
    let b2 = mac_r(
        l_mac(
            l_mac(
                l_mult(mult_r(pg[2], pg[1]), 8192),
                mult_r(2 * 8192, pg[1]),
                pg[3],
            ),
            mult_r(3 * 8192, pg[1]),
            pg[4],
        ),
        mult_r(pg[1], -16384),
        mult_r(pg[0], 16384),
    ); // Q7
    let b3 = mac_r(
        l_mac(
            l_mac(
                l_mult(mult_r(-2 * 8192, pg[0]), pg[2]),
                mult_r(pg[2], -16384),
                mult_r(pg[1], 16384),
            ),
            mult_r(pg[3], 16384),
            mult_r(pg[2], 16384),
        ),
        mult_r(2 * 8192, pg[2]),
        pg[4],
    ); // Q7
    let b4 = mac_r(
        l_mac(
            l_mac(
                l_mult(mult_r(-3 * 8192, pg[0]), pg[3]),
                mult_r(-2 * 8192, pg[1]),
                pg[3],
            ),
            mult_r(-16384, pg[3]),
            mult_r(16384, pg[2]),
        ),
        mult_r(16384, pg[4]),
        mult_r(16384, pg[3]),
    ); // Q7
    let b5 = mac_r(
        l_mac(
            l_mac(
                l_mult(mult_r(-32768, pg[0]), pg[4]),
                mult_r(-3 * 8192, pg[1]),
                pg[4],
            ),
            mult_r(-2 * 8192, pg[2]),
            pg[4],
        ),
        mult_r(-16384, pg[4]),
        mult_r(16384, pg[3]),
    ); // Q7

    let mut b = l_mac(
        l_mac(
            l_mac(
                l_mac(l_mult(b1, lag_q4(ml, 0)), lag_q4(ml, 1), b2),
                lag_q4(ml, 2),
                b3,
            ),
            lag_q4(ml, 3),
            b4,
        ),
        lag_q4(ml, 4),
        b5,
    ); // Q-4+16 = Q12

    // predict pitch for 4th future subframe
    let b_e = norm_l(b);
    b = l_shl(b, b_e);

    let mut tmpb = 0i16;
    let quotient = basop_util_divide3216_scale(b, sum0, &mut tmpb);
    (quotient, tmpb, b_e)
}

/// `get_subframe_pitch`: the pitch lag (15Q16) of each of the `n_subframes` subframes of a
/// concealed frame, interpolated linearly from `pitch_start` (subframe -1) to `pitch_end`
/// (subframe `n_subframes - 1`). The reference asserts `n_subframes > 0`, `pitch_start >= 0` and
/// `pitch_end > 0`.
pub fn get_subframe_pitch(
    n_subframes: i16,
    pitch_start: i32,
    pitch_end: i32,
    pitch_buf: &mut [i32],
) {
    let mut s: i16 = 0;
    // pitchDelta = (pitchEnd - pitchStart)/nSubframes
    let pitch_delta = l_deposit_l(basop_util_divide3216_scale(
        l_sub(pitch_end, pitch_start),
        n_subframes,
        &mut s,
    )); // Q15
    let pitch_delta = l_shl(pitch_delta, add(s, 1)); // Q16
    pitch_buf[0] = l_add(pitch_start, pitch_delta);
    for i in 1..n_subframes.max(1) as usize {
        pitch_buf[i] = l_add(pitch_buf[i - 1], pitch_delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_subframe_pitch_interpolates_linearly() {
        let mut buf = [0i32; 4];
        get_subframe_pitch(4, 100 << 16, 108 << 16, &mut buf);
        assert_eq!(buf, [102 << 16, 104 << 16, 106 << 16, 108 << 16]);
    }

    #[test]
    fn get_subframe_pitch_keeps_a_constant_pitch() {
        let mut buf = [0i32; 5];
        get_subframe_pitch(5, 77 << 16, 77 << 16, &mut buf);
        assert_eq!(buf, [77 << 16; 5]);
    }
}
