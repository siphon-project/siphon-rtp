//! Long-term (adaptive codebook) prediction with fractional interpolation (TS 26.442
//! `lib_com/pred_lt4_fx.c`; TS 26.445 §6.1.1.2.1).
//!
//! Both functions read the excitation *before* the current subframe, so they take the whole
//! excitation buffer plus the index the reference's `exc` pointer points at (`exc_at`).

use crate::evs::cnst::{L_IMPULSE2, L_INTERPOL2, L_SUBFR, PIT_SHARP_FX, UP_SAMP};
use crate::itu::basic_ops::{add, l_mac, l_mult, l_shl, mult_r, negate, round_word, sub};
use crate::itu::stl2009::l_mac0;

/// `pred_lt4`: interpolate the past excitation at lag `t0 + frac/up_sample` into
/// `exc[exc_at..exc_at + l_subfr]`, with `nb_coef` taps per side of the window `win`.
///
/// Every reference call site passes the same buffer as `excI` and `excO`, so this is the in-place
/// form: output sample `j` is written before sample `j + 1` is computed, and a lag shorter than
/// the subframe reads back samples this call already wrote, exactly as the aliased C does.
/// Returns without writing if the lag reaches before the start of `exc` (a lag the reference's
/// pitch limits never produce).
pub fn pred_lt4(
    exc: &mut [i16],
    exc_at: usize,
    t0: i16,
    frac: i16,
    l_subfr: i16,
    win: &[i16],
    nb_coef: i16,
    up_sample: i16,
) {
    let mut x0 = exc_at as isize - t0 as isize;
    let mut frac = negate(frac);
    if frac < 0 {
        frac = add(frac, up_sample);
        x0 -= 1;
    }
    let nb_coef = nb_coef.max(0) as isize;
    let l_subfr = l_subfr.max(0) as isize;
    // bounds: x1 reaches back nb_coef - 1 samples, x2 forward nb_coef samples
    if x0 - (nb_coef - 1) < 0
        || x0 + l_subfr + nb_coef > exc.len() as isize
        || exc_at as isize + l_subfr > exc.len() as isize
    {
        return;
    }
    let up = up_sample as usize;
    let frac = frac as usize;
    for j in 0..l_subfr {
        let x1 = (x0 + j) as usize;
        let x2 = x1 + 1;
        let mut s = 0i32;
        for i in 0..nb_coef as usize {
            s = l_mac0(s, exc[x1 - i], win[frac + i * up]);
            s = l_mac0(s, exc[x2 + i], win[up - frac + i * up]);
        }
        // INTERP_EXP is 0
        s = l_shl(s, 1);
        exc[exc_at + j as usize] = round_word(s);
    }
}

/// `pred_lt4_tc_fx`: in a transition-coded subframe at `i_subfr`, add the pitch-sharpened
/// prediction of a second glottal impulse (lag `t0`, fraction `frac`, window `win`) to
/// `exc[exc_at + i_subfr + t0 ..]`. `exc_at` is the index of the reference's `exc[0]`, which has
/// at least `L_SUBFR` samples of history before `i_subfr`.
pub fn pred_lt4_tc(
    exc: &mut [i16],
    exc_at: usize,
    t0: i16,
    frac: i16,
    win: &[i16],
    imp_pos: i16,
    i_subfr: i16,
) {
    const SUBFR: usize = L_SUBFR as usize;
    let mut exc_o = [0i16; SUBFR + 1];
    let mut exc_i = [0i16; 2 * SUBFR];
    let start = exc_at as isize + sub(i_subfr, L_SUBFR) as isize;
    if start < 0 || start as usize + 2 * SUBFR > exc.len() {
        return;
    }
    let start = start as usize;
    exc_i.copy_from_slice(&exc[start..start + 2 * SUBFR]);

    if sub(add(t0, sub(imp_pos, L_IMPULSE2)), L_SUBFR) < 0 && sub(t0, L_SUBFR) < 0 {
        // The interpolation reads 2·L_INTERPOL2 samples from x0 for every output from t0 to
        // L_SUBFR, which stays inside excI only for t0 > L_INTERPOL2; the TC lag is never below
        // PIT_MIN, so a shorter one (only a hostile frame) is dropped instead of read past the end.
        if t0 <= L_INTERPOL2 {
            return;
        }
        let t0u = t0 as usize;
        exc_i[SUBFR - t0u..SUBFR].fill(0);
        let mut x0 = SUBFR - (L_INTERPOL2 as usize - 1);
        let mut frac = frac;
        if frac > 0 {
            frac = sub(frac, UP_SAMP);
            x0 -= 1;
        }
        let l = add(UP_SAMP - 1, frac) as usize;
        for out in &mut exc_o[t0u..=SUBFR] {
            let mut k = l;
            let mut l_sum = l_mult(exc_i[x0], win[k]);
            for i in 1..2 * L_INTERPOL2 as usize {
                k += UP_SAMP as usize;
                l_sum = l_mac(l_sum, exc_i[x0 + i], win[k]); // Q1
            }
            l_sum = l_shl(l_sum, 1); // Q0h
            *out = round_word(l_sum);
            x0 += 1;
        }
        let base = (exc_at as isize + i_subfr as isize) as usize;
        for i in t0u..SUBFR {
            exc[base + i] = add(exc[base + i], mult_r(PIT_SHARP_FX, exc_o[i]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::rom::PITCH_INTER4_2;

    #[test]
    fn a_lag_past_the_buffer_start_writes_nothing() {
        let mut exc = [7i16; 100];
        pred_lt4(&mut exc, 20, 50, 0, 64, &PITCH_INTER4_2, 16, 4);
        assert!(exc.iter().all(|&s| s == 7));
    }
}
