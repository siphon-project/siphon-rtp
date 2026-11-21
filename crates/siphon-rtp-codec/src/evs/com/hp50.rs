//! Second-order 20 Hz high-pass on the output synthesis (TS 26.442 `lib_com/hp50.c`).
//!
//! The filter runs in 32-bit state with a per-frame prescale kept in `mem[4]`; the
//! `BASOP_SATURATE_*` markers in the reference are debugging no-ops in the release build.

use crate::evs::basop::{mpy_32_16_1, mpy_32_32};
use crate::evs::com::basop_util::get_scale_factor16;
use crate::itu::basic_ops::{
    extract_l, l_add, l_deposit_h, l_deposit_l, l_shl, l_shr, l_sub, norm_l, round_word, shr, sub,
};

/// `HP20_COEFF_SCALE`: the coefficients are Q29, so each output is shifted left by 2.
const HP20_COEFF_SCALE: i16 = 2;

/// `HP50_Mode2_Mpy_32_16_fix`: [`mpy_32_16_1`] with a negative result moved one step towards
/// zero.
#[must_use]
pub fn hp50_mode2_mpy_32_16_fix(a: i32, b: i16) -> i32 {
    let result = mpy_32_16_1(a, b);
    // perform rounding towards lower value for negative results
    if result < 0 {
        l_add(result, 1)
    } else {
        result
    }
}

/// `HP50_Mpy_32_32_fix`: [`mpy_32_32`] with a negative result moved one step towards zero.
#[must_use]
pub fn hp50_mpy_32_32_fix(a: i32, b: i32) -> i32 {
    let result = mpy_32_32(a, b);
    if result < 0 {
        l_add(result, 1)
    } else {
        result
    }
}

/// `filter_2nd_order`: the biquad `y[i] = b2·x[i-2] + b1·x[i-1] + b2·x[i] + a2·y[i-2] +
/// a1·y[i-1]` over `signal[0], signal[stride], ...` (`lg` samples, `lg` even and `>= 2`), with
/// the input scaled down by `prescale` and the state in `mem[0..4]`.
pub fn filter_2nd_order(
    signal: &mut [i16],
    stride: i16,
    prescale: i16,
    lg: i16,
    mem: &mut [i32],
    a1: i32,
    a2: i32,
    b1: i32,
    b2: i32,
) {
    let stride = stride as usize;

    // Execute first 2 iterations with 32-bit x anx y memory values
    let mut l_sum = hp50_mpy_32_32_fix(b2, mem[2]); // b2*x2
    l_sum = l_add(l_sum, hp50_mpy_32_32_fix(b1, mem[3])); // b1*x1
    let mut x2 = shr(signal[0], prescale);
    l_sum = l_add(l_sum, hp50_mode2_mpy_32_16_fix(b2, x2)); // b2*x0
    l_sum = l_add(l_sum, hp50_mpy_32_32_fix(mem[0], a2)); // y2*a2
    l_sum = l_add(l_sum, hp50_mpy_32_32_fix(mem[1], a1)); // y1*a1
    let mut l_y2 = l_shl(l_sum, HP20_COEFF_SCALE);
    signal[0] = round_word(l_shl(l_y2, prescale));

    l_sum = hp50_mpy_32_32_fix(b2, mem[3]); // b2*x2
    l_sum = l_add(l_sum, hp50_mode2_mpy_32_16_fix(b1, x2)); // b1*x1
    let mut x1 = shr(signal[stride], prescale);
    l_sum = l_add(l_sum, hp50_mode2_mpy_32_16_fix(b2, x1)); // b2*x0
    l_sum = l_add(l_sum, hp50_mpy_32_32_fix(mem[1], a2)); // y2*a2
    l_sum = l_add(l_sum, hp50_mpy_32_32_fix(l_y2, a1)); // y1*a1
    let mut l_y1 = l_shl(l_sum, HP20_COEFF_SCALE);
    signal[stride] = round_word(l_shl(l_y1, prescale));

    // toggle x1/x2 and L_y1/L_y2, unrolling the loop by 2
    let mut i = 2usize;
    while i < lg.max(0) as usize {
        // y[i+0] = b2*x[i-2] + b1*x[i-1] + b2*x[i-0] + a2*y[i-2] + a1*y[i-1]
        l_sum = hp50_mode2_mpy_32_16_fix(b2, x2);
        l_sum = l_add(l_sum, hp50_mode2_mpy_32_16_fix(b1, x1));
        x2 = shr(signal[i * stride], prescale);
        l_sum = l_add(l_sum, hp50_mode2_mpy_32_16_fix(b2, x2));
        l_sum = l_add(l_sum, hp50_mpy_32_32_fix(l_y2, a2));
        l_sum = l_add(l_sum, hp50_mpy_32_32_fix(l_y1, a1));
        l_y2 = l_shl(l_sum, HP20_COEFF_SCALE);
        signal[i * stride] = round_word(l_shl(l_y2, prescale));

        // y[i+1] = b2*x[i-1] + b1*x[i-0] + b2*x[i+1] + a2*y[i-1] + a1*y[i+0]
        l_sum = hp50_mode2_mpy_32_16_fix(b2, x1);
        l_sum = l_add(l_sum, hp50_mode2_mpy_32_16_fix(b1, x2));
        x1 = shr(signal[(i + 1) * stride], prescale);
        l_sum = l_add(l_sum, hp50_mode2_mpy_32_16_fix(b2, x1));
        l_sum = l_add(l_sum, hp50_mpy_32_32_fix(l_y1, a2));
        l_sum = l_add(l_sum, hp50_mpy_32_32_fix(l_y2, a1));
        l_y1 = l_shl(l_sum, HP20_COEFF_SCALE);
        signal[(i + 1) * stride] = round_word(l_shl(l_y1, prescale));
        i += 2;
    }
    // update static filter memory from variables
    mem[0] = l_y2;
    mem[1] = l_y1;
    mem[2] = l_deposit_h(x2);
    mem[3] = l_deposit_h(x1);
}

/// `hp20`: 2nd order high pass filter with nominal cut off frequency at 20 Hz over `lg` samples of
/// `signal` taken `stride` apart, at input rate `s_freq` (8, 16, 32 or 48 kHz).
///
/// `mem` layout: `mem[0]` y\[-2\], `mem[1]` y\[-1\] (32-bit), `mem[2]` x\[-2\] << 16,
/// `mem[3]` x\[-1\] << 16, `mem[4]` the scale of those states.
pub fn hp20(signal: &mut [i16], stride: i16, lg: i16, mem: &mut [i32], s_freq: i32) {
    // The reference scans `lg` contiguous samples whatever the stride; every caller passes 1.
    let mut prescale = get_scale_factor16(signal, lg);
    let prescale_old = extract_l(mem[4]);
    let mut diff = norm_l(l_shl(mem[2], prescale_old));
    if mem[2] != 0 {
        prescale = prescale.min(diff);
    }
    diff = norm_l(l_shl(mem[3], prescale_old));
    if mem[3] != 0 {
        prescale = prescale.min(diff);
    }
    // Take into account the left shift performed into the loop + 1 bit headroom
    prescale = (-12i16).max(sub(1 + HP20_COEFF_SCALE, prescale));
    if prescale != prescale_old {
        diff = sub(prescale, prescale_old);
        mem[0] = l_shr(mem[0], diff);
        mem[1] = l_shr(mem[1], diff);
        mem[2] = l_shr(mem[2], diff);
        mem[3] = l_shr(mem[3], diff);
        mem[4] = l_deposit_l(prescale);
    }

    // [b,a] = butter(2, 20.0/(fs/2), 'high'), Q29
    let (a1, a2, b1, b2) = if l_sub(s_freq, 8000) == 0 {
        (1_061_816_033, -525_076_131, -1_061_881_538, 530_940_769)
    } else if l_sub(s_freq, 16000) == 0 {
        (1_067_778_748, -530_940_770, -1_067_795_215, 533_897_608)
    } else if l_sub(s_freq, 32000) == 0 {
        (1_070_760_263, -533_897_608, -1_070_764_392, 535_382_196)
    } else {
        // the reference asserts 48000 here
        (1_071_754_114, -534_886_875, -1_071_755_951, 535_877_975)
    };

    filter_2nd_order(signal, stride, prescale, lg, mem, a1, a2, b1, b2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_products_round_towards_zero() {
        // -1.5 floors to -2 in the multiply, then moves one step towards zero
        assert_eq!(hp50_mpy_32_32_fix(-3, 1 << 30), -1);
        assert_eq!(hp50_mode2_mpy_32_16_fix(-3, 16384), -1);
        assert_eq!(hp50_mpy_32_32_fix(1 << 30, 1 << 30), 1 << 29);
    }

    #[test]
    fn silence_stays_silent() {
        let mut signal = [0i16; 320];
        let mut mem = [0i32; 5];
        hp20(&mut signal, 1, 320, &mut mem, 16000);
        assert!(signal.iter().all(|&s| s == 0));
    }
}
