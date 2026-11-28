//! Shaping of the algebraic codebook vector: pre-emphasis, pitch sharpening, phase scrambling and
//! formant sharpening (TS 26.442 `lib_com/cb_shape_fx.c`; TS 26.445 §6.1.1.2.x).

use crate::evs::cnst::{L_SUBFR, M};
use crate::evs::com::get_gain::get_gain;
use crate::evs::com::preemph::preemph_copy_in_place;
use crate::evs::com::residu::residu3_lc;
use crate::evs::com::syn_filt::{e_util_synthesis_in_place, syn_filt_s_lc_in_place};
use crate::evs::com::weight_a::weight_a;
use crate::itu::basic_ops::{add, extract_l, l_mult, l_shr, mult_r, shr, sub};
use crate::itu::stl2009::{mac_r, StlFlags};

const SUBFR: usize = L_SUBFR as usize;
const ORDER: usize = M as usize;

/// `E_GAIN_f_pitch_sharpening`: `x[i] += 0.85·x[i - pit_lag]` for `i` in `pit_lag..L_subfr`,
/// running forwards, so a lag below the subframe length feeds sharpened samples back in.
pub fn e_gain_f_pitch_sharpening(x: &mut [i16], pit_lag: i16, l_subfr: i16) {
    if pit_lag < 0 {
        // The reference would read before x; the lag is a decoded pitch, never negative.
        return;
    }
    let pit_lag = pit_lag as usize;
    let l_subfr = l_subfr.max(0) as usize;
    for i in pit_lag..l_subfr {
        let tmp = mult_r(x[i - pit_lag], 27853 /* F_PIT_SHARP Q15 */);
        x[i] = add(x[i], tmp);
    }
}

/// `cb_shape_fx`: shapes the `L_SUBFR`-sample algebraic code vector `code` in place.
///
/// `p_aq` is the subframe's quantised LP filter (order `M`). `shift` is the Q shift the residual
/// / synthesis pair of the formant sharpening runs at. `flags` carries the STL `Carry` the
/// formant-tilt branch's `get_gain` accumulates through.
pub fn cb_shape(
    preemph_flag: i16,
    pitch_flag: i16,
    scrambling_flag: i16,
    sharp_flag: i16,
    formant_tilt_flag: i16,
    g1: i16,
    g2: i16,
    p_aq: &[i16],
    code: &mut [i16],
    tilt_code: i16,
    pt_pitch: i16,
    shift: i16,
    flags: &mut StlFlags,
) {
    let mut buff = [0i16; SUBFR + ORDER];
    let mut a_num = [0i16; ORDER + 1];
    let mut a_den = [0i16; ORDER + 1];

    let mut tmp: i16 = 0;
    // Pre-emphasis
    if preemph_flag != 0 {
        preemph_copy_in_place(code, tilt_code, L_SUBFR, &mut tmp);
    }
    // Pitch sharpening
    if pitch_flag != 0 {
        e_gain_f_pitch_sharpening(code, pt_pitch, L_SUBFR);
    }
    // Phase scrambling filter
    if scrambling_flag != 0 {
        buff[0] = code[0];
        for i in 1..SUBFR {
            buff[i] = code[i];
            let l_tmp = l_mult(22938, buff[i]);
            tmp = mac_r(l_tmp, -22938, code[i - 1]);
            code[i] = add(tmp, buff[i - 1]);
        }
    }
    // Formant sharpening
    if sharp_flag != 0 || formant_tilt_flag != 0 {
        weight_a(p_aq, &mut a_num, g1, M);
        weight_a(p_aq, &mut a_den, g2, M);
        buff.fill(0);
        if formant_tilt_flag != 0 {
            // Impulse response of A(z/g1)/A(z/g2), its tilt, and a first-order tilt filter
            buff[ORDER..=2 * ORDER].copy_from_slice(&a_num);
            let (mem, h) = buff.split_at_mut(ORDER);
            e_util_synthesis_in_place(1, &a_den, h, L_SUBFR, mem, 0, M);
            let tilt = extract_l(l_shr(
                get_gain(&buff[ORDER + 1..], &buff[ORDER..], L_SUBFR - 1, flags),
                1,
            ));
            tmp = 0;
            let mu = sub(shr(tilt_code, 1), shr(tilt, 2));
            preemph_copy_in_place(code, mu, L_SUBFR, &mut tmp);
        } else {
            buff[..SUBFR].copy_from_slice(&code[..SUBFR]);
            // The reference clears Overflow here; nothing after reads it.
            residu3_lc(&a_num, M, &buff, code, L_SUBFR, shift);
            syn_filt_s_lc_in_place(shift, &a_den, code, L_SUBFR);
        }
    }
}
