//! Phase dispersion of the fixed-codebook vector (TS 26.442 `lib_com/phase_dispersion.c`; the
//! MODE2 ACELP counterpart of `phase_dispersion_fx`, which `enhancer.rs` carries for MODE1).

use crate::evs::cnst::L_SUBFR;
use crate::evs::com::basop_util::get_scale_factor32;
use crate::evs::com::fft::basop_rfft;
use crate::evs::rom::{LOW_H, LOW_H16K, MID_H, MID_H16K};
use crate::itu::basic_ops::{
    add, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_sub, round_word, sub,
};

/// `2 * L_SUBFR`: the reference's `x32` scratch length.
const X32_LEN: usize = 2 * L_SUBFR as usize;

/// `phase_dispersion`: post-processing that spreads the energy of the sparse code vector `code`
/// (exponent `code_exp`) by a circular convolution, in the frequency domain, with a low- or
/// mid-dispersion impulse response chosen from the pitch-gain history `prev_gain_pit` (6 values),
/// the code-gain jump against `prev_gain_code` and the bit-rate dependent `mode`
/// (0 high, 1 low, 2 off). `prev_gain_code`, `prev_gain_pit` and `prev_state` are the static
/// memory carried between subframes.
///
/// The impulse responses and the transform are ported for subframes of 64 samples (and the
/// shorter `L_subfr <= 64` tables); a subframe length the reference's `BASOP_rfft` does not
/// support leaves the transform, and so the code vector, as it was.
pub fn phase_dispersion(
    gain_code: i32,
    gain_pit: i16,
    code: &mut [i16],
    code_exp: &mut i16,
    mode: i16,
    prev_gain_code: &mut i32,
    prev_gain_pit: &mut [i16],
    prev_state: &mut i16,
    l_subfr: i16,
) {
    let mut x32 = [0i32; X32_LEN];

    let mut state: i16 = 2;

    if sub(gain_pit, 14746) < 0 {
        // 0.9f Q14
        state = 1;
    }
    if sub(gain_pit, 9830) < 0 {
        // 0.6f Q14
        state = 0;
    }

    for i in (1..=5).rev() {
        prev_gain_pit[i] = prev_gain_pit[i - 1];
    }
    prev_gain_pit[0] = gain_pit;

    if crate::itu::basic_ops::l_sub(gain_code, l_add(*prev_gain_code, l_shl(*prev_gain_code, 1)))
        > 0
    {
        if sub(state, 2) < 0 {
            state = add(state, 1);
        }
    } else {
        let mut j: i16 = 0;
        for &previous in prev_gain_pit.iter().take(6) {
            if l_sub(i32::from(previous), 9830) < 0 {
                j = add(j, 1);
            }
        }

        if sub(j, 2) > 0 {
            state = 0;
        }

        if sub(sub(state, *prev_state), 1) > 0 {
            state = sub(state, 1);
        }
    }

    *prev_gain_code = gain_code;
    *prev_state = state;

    // circular convolution
    state = add(state, mode); // level of dispersion
    let mut j = *code_exp;
    if sub(state, 2) < 0 {
        let n = l_subfr.max(0) as usize;
        for i in 0..n {
            x32[i] = l_deposit_h(code[i]);
        }

        basop_rfft(&mut x32, l_subfr, &mut j, -1);

        // Normalize output data.
        let mut scale2 = get_scale_factor32(&x32, l_subfr);
        let half = n / 2;
        for i in 0..half - 1 {
            code[i] = round_word(l_shl(x32[2 * i], scale2));
            code[n - 1 - i] = round_word(l_shl(x32[2 * i + 3], scale2));
        }

        code[half - 1] = round_word(l_shl(x32[n - 2], scale2));
        code[half] = round_word(l_shl(x32[1], scale2));

        j = sub(j, scale2);

        let h: &[i16] = if sub(l_subfr, 64) <= 0 {
            if sub(state, 1) == 0 {
                &MID_H
            } else {
                &LOW_H
            }
        } else if sub(state, 1) == 0 {
            &MID_H16K
        } else {
            &LOW_H16K
        };

        let mut code_real = 0usize;
        let mut code_imag = n - 1;
        let mut h_real = 0usize;
        let mut h_imag = n - 1;

        x32[0] = l_mult(code[code_real], h[h_real]);
        code_real += 1;
        h_real += 1;
        for i in 1..half {
            x32[2 * i] = l_msu(
                l_mult(code[code_real], h[h_real]),
                code[code_imag],
                h[h_imag],
            );
            x32[2 * i + 1] = l_mac(
                l_mult(code[code_real], h[h_imag]),
                code[code_imag],
                h[h_real],
            );
            code_real += 1;
            h_imag = h_imag.saturating_sub(1);
            code_imag = code_imag.saturating_sub(1);
            h_real += 1;
        }
        x32[1] = l_mult(code[code_real], h[h_real]);

        // low_H and mid_H are in Q14 format, thus account that here.
        j = add(j, 1);

        basop_rfft(&mut x32, l_subfr, &mut j, 1);
        scale2 = get_scale_factor32(&x32, l_subfr);
        for i in 0..n {
            code[i] = round_word(l_shl(x32[i], scale2));
        }
        j = sub(j, scale2);
    }

    // Store exponent of code
    *code_exp = j;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_off_leaves_the_code_and_updates_the_memory() {
        let mut code = [0i16; 64];
        code[3] = 1000;
        let expected = code;
        let mut code_exp = 6;
        let mut prev_gain_code = 0;
        let mut prev_gain_pit = [0i16; 6];
        let mut prev_state = 0;
        // gain_pit above 0.9 makes the state 2, and mode 2 switches the dispersion off.
        phase_dispersion(
            1 << 16,
            16000,
            &mut code,
            &mut code_exp,
            2,
            &mut prev_gain_code,
            &mut prev_gain_pit,
            &mut prev_state,
            64,
        );
        assert_eq!(code, expected);
        assert_eq!(code_exp, 6);
        assert_eq!(prev_gain_code, 1 << 16);
        assert_eq!(prev_gain_pit[0], 16000);
        assert_eq!(prev_state, 2);
    }
}
