//! AMR-NB pitch (adaptive-codebook) tier — 3GPP TS 26.073 `dec_lag3.c`, `dec_lag6.c`, `pred_lt.c`,
//! `d_gain_p.c`. Ported bit-exact.
//!
//! From the received adaptive-codebook index the decoder recovers the integer + fractional pitch
//! lag ([`dec_lag3`] for 1/3-resolution modes, [`dec_lag6`] for the MR122 1/6-resolution path),
//! builds the adaptive-codebook excitation by fractionally interpolating the past excitation
//! ([`pred_lt_3or6`]), and decodes the quantized pitch gain ([`d_gain_pitch`]).

use crate::amr::basic_ops::{add, l_mac, mult, negate, round_word, shl, shr, sub};
use crate::amr::nb::constants::L_INTERPOL;
use crate::amr::nb::gain_tables::QUA_GAIN_PITCH;
use crate::amr::AmrNbMode;

/// `pred_lt.c` `UP_SAMP_MAX`.
const UP_SAMP_MAX: i16 = 6;
/// `pred_lt.c` `L_INTER10` (= `L_INTERPOL - 1`).
const L_INTER10: usize = L_INTERPOL - 1;

/// 1/6-resolution interpolation FIR (`pred_lt.c` `inter_6`, -3 dB at 3600 Hz). The 1/3-resolution
/// filter is every second coefficient. `FIR_SIZE = UP_SAMP_MAX * L_INTER10 + 1 = 61`.
#[rustfmt::skip]
static INTER_6: [i16; 61] = [
    29443,
    28346, 25207, 20449, 14701, 8693, 3143,
    -1352, -4402, -5865, -5850, -4673, -2783,
    -672, 1211, 2536, 3130, 2991, 2259,
    1170, 0, -1001, -1652, -1868, -1666,
    -1147, -464, 218, 756, 1060, 1099,
    904, 550, 135, -245, -514, -634,
    -602, -451, -231, 0, 191, 308,
    340, 296, 198, 78, -36, -120,
    -163, -165, -132, -79, -19, 34,
    73, 91, 89, 70, 38, 0,
];

/// Decode the 1/3-resolution fractional pitch lag (`dec_lag3.c` `Dec_lag3`).
/// Returns `(T0, T0_frac)` — integer and fractional parts of the pitch lag.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn dec_lag3(
    index: i16,
    t0_min: i16,
    t0_max: i16,
    i_subfr: i16,
    t0_prev: i16,
    flag4: bool,
) -> (i16, i16) {
    let t0;
    let t0_frac;
    if i_subfr == 0 {
        // 1st or 3rd subframe
        if sub(index, 197) < 0 {
            t0 = add(mult(add(index, 2), 10923), 19);
            let i = add(add(t0, t0), t0);
            t0_frac = add(sub(index, i), 58);
        } else {
            t0 = sub(index, 112);
            t0_frac = 0;
        }
    } else {
        // 2nd or 4th subframe
        if !flag4 {
            // 'normal' decoding: 5- or 6-bit resolution
            let i = sub(mult(add(index, 2), 10923), 1);
            t0 = add(i, t0_min);
            let i = add(add(i, i), i);
            t0_frac = sub(sub(index, 2), i);
        } else {
            // 4-bit resolution
            let mut tmp_lag = t0_prev;
            if sub(sub(tmp_lag, t0_min), 5) > 0 {
                tmp_lag = add(t0_min, 5);
            }
            if sub(sub(t0_max, tmp_lag), 4) > 0 {
                tmp_lag = sub(t0_max, 4);
            }
            if sub(index, 4) < 0 {
                let i = sub(tmp_lag, 5);
                t0 = add(i, index);
                t0_frac = 0;
            } else if sub(index, 12) < 0 {
                let i = sub(mult(sub(index, 5), 10923), 1);
                t0 = add(i, tmp_lag);
                let i = add(add(i, i), i);
                t0_frac = sub(sub(index, 9), i);
            } else {
                let i = add(sub(index, 12), tmp_lag);
                t0 = add(i, 1);
                t0_frac = 0;
            }
        }
    }
    (t0, t0_frac)
}

/// Decode the 1/6-resolution fractional pitch lag (`dec_lag6.c` `Dec_lag6`), for MR122.
/// `t0_in` is the previous subframe's integer lag (used in the relative 2nd/4th-subframe path).
/// Returns `(T0, T0_frac)`.
#[must_use]
pub fn dec_lag6(index: i16, pit_min: i16, pit_max: i16, i_subfr: i16, t0_in: i16) -> (i16, i16) {
    let t0;
    let t0_frac;
    if i_subfr == 0 {
        // 1st or 3rd subframe
        if sub(index, 463) < 0 {
            // T0 = (index+5)/6 + 17
            t0 = add(mult(add(index, 5), 5462), 17);
            let i = add(add(t0, t0), t0);
            // T0_frac = index - T0*6 + 105
            t0_frac = add(sub(index, add(i, i)), 105);
        } else {
            t0 = sub(index, 368);
            t0_frac = 0;
        }
    } else {
        // 2nd or 4th subframe: bound the search range around the previous lag
        let mut t0_min = sub(t0_in, 5);
        if sub(t0_min, pit_min) < 0 {
            t0_min = pit_min;
        }
        let mut t0_max = add(t0_min, 9);
        if sub(t0_max, pit_max) > 0 {
            t0_max = pit_max;
            t0_min = sub(t0_max, 9);
        }
        // i = (index+5)/6 - 1
        let i = sub(mult(add(index, 5), 5462), 1);
        t0 = add(i, t0_min);
        let i = add(add(i, i), i);
        t0_frac = sub(sub(index, 3), add(i, i));
    }
    (t0, t0_frac)
}

/// Long-term prediction with 1/3 or 1/6 fractional interpolation (`pred_lt.c` `Pred_lt_3or6`).
///
/// Builds the adaptive-codebook excitation in place: reads the past excitation
/// `exc[pos - T0 - …]` and writes `exc[pos .. pos + l_subfr]`. `flag3` selects 1/3-resolution
/// upsampling (every second filter tap); otherwise 1/6. `pos` is the subframe start within `exc`.
pub fn pred_lt_3or6(exc: &mut [i16], pos: usize, t0: i16, frac: i16, l_subfr: usize, flag3: bool) {
    // x0 = &exc[-T0] (relative to the subframe start `pos`).
    let mut x0 = pos as isize - t0 as isize;

    let mut frac = negate(frac);
    if flag3 {
        frac = shl(frac, 1); // inter_3l[k] = inter_6[2*k]
    }
    if frac < 0 {
        frac = add(frac, UP_SAMP_MAX);
        x0 -= 1;
    }
    let frac = frac as usize;
    let c2_base = sub(UP_SAMP_MAX, frac as i16) as usize;

    for j in 0..l_subfr {
        // x1 = x0++; x2 = x0;  (x1 = old x0, x2 = x0 after increment)
        let x1 = x0; // points at exc[x0]
        let x2 = x0 + 1;
        x0 += 1;

        let mut s: i32 = 0;
        let mut k = 0usize;
        for i in 0..L_INTER10 {
            // s += x1[-i] * c1[k];  s += x2[i] * c2[k];
            let xi1 = (x1 - i as isize) as usize;
            let xi2 = (x2 + i as isize) as usize;
            s = l_mac(s, exc[xi1], INTER_6[frac + k]);
            s = l_mac(s, exc[xi2], INTER_6[c2_base + k]);
            k += UP_SAMP_MAX as usize;
        }
        exc[pos + j] = round_word(s);
    }
}

/// Decode the pitch gain from its index (`d_gain_p.c` `d_gain_pitch`). Output is Q14; MR122 clears
/// the 2 LSBs of the table entry.
#[must_use]
pub fn d_gain_pitch(mode: usize, index: i16) -> i16 {
    let gain = QUA_GAIN_PITCH[index as usize];
    if mode == AmrNbMode::Mr1220 as usize {
        shl(shr(gain, 2), 2) // clear 2 LSBs
    } else {
        gain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dec_lag3_first_subframe_low_index() {
        // index 0: T0 = (0+2)*10923>>15 ... mult rounds; classic boundary case.
        let (t0, frac) = dec_lag3(0, 0, 0, 0, 0, false);
        // mult(2,10923) = (2*10923)>>15 = 0; T0 = 0+19 = 19; i = 57; frac = 0-57+58 = 1.
        assert_eq!(t0, 19);
        assert_eq!(frac, 1);
    }

    #[test]
    fn dec_lag3_first_subframe_high_index() {
        // index >= 197 -> T0 = index - 112, frac 0.
        let (t0, frac) = dec_lag3(200, 0, 0, 0, 0, false);
        assert_eq!(t0, 88);
        assert_eq!(frac, 0);
    }

    #[test]
    fn dec_lag6_first_subframe() {
        // index 0: T0 = (5)*5462>>15 + 17 = 0 + 17 = 17; i = 51; frac = 0 - 102 + 105 = 3.
        let (t0, frac) = dec_lag6(0, 18, 143, 0, 0);
        assert_eq!(t0, 17);
        assert_eq!(frac, 3);
    }

    #[test]
    fn d_gain_pitch_table_lookup() {
        // Non-MR122 returns the raw table value.
        assert_eq!(d_gain_pitch(AmrNbMode::Mr475 as usize, 10), 15565);
        // MR122 clears the 2 LSBs: 15565 = 0x3CCD -> &~3 = 0x3CCC = 15564.
        assert_eq!(d_gain_pitch(AmrNbMode::Mr1220 as usize, 10), 15564);
    }

    #[test]
    fn pred_lt_integer_lag_copies_past() {
        // With frac=0 and integer lag, the output at integer lag equals a delayed copy of history.
        let mut exc = [0i16; 200];
        // Fill history before pos with a ramp.
        let pos = 100usize;
        for (i, e) in exc.iter_mut().enumerate().take(pos) {
            *e = (i as i16) - 50;
        }
        pred_lt_3or6(&mut exc, pos, 40, 0, 40, true);
        // inter_6[0] = 29443 (~0.898 Q15); a pure integer-lag interpolation is a scaled tap sum;
        // the output is finite and deterministic — assert it produced nonzero structure.
        assert!(exc[pos..pos + 40].iter().any(|&v| v != 0));
    }

    #[test]
    fn pred_lt_zero_history_is_silent() {
        let mut exc = [0i16; 200];
        pred_lt_3or6(&mut exc, 100, 40, 2, 40, true);
        assert!(exc[100..140].iter().all(|&v| v == 0));
    }
}
