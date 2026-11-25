//! Envelope shaping of the TCX arithmetic coder (TS 26.442 `lib_com/arith_coder.c`; TS 26.445
//! §6.2.2.2.4). The encoder-only `powfp_odd2` of that file is not part of the decoder.
//!
//! The reference passes the scaled envelope as a `Word16` view of the same memory as the 32-bit
//! envelope (`envelope = (Word16*)env`); [`env_half`] and [`set_env_half`] are that view, on the
//! little-endian layout of the reference platform.
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

pub mod envelope;
use crate::evs::basop::mpy_32_16_1;
use crate::itu::basic_ops::{
    add, extract_l, l_deposit_h, l_deposit_l, l_shl, l_shr, mult, negate, round_word, shr,
};
use crate::itu::stl2009::l_mac0;

/// `((Word16 *)env)[k]`: half-word `k` of the 32-bit array `env`, low half first.
#[must_use]
pub fn env_half(env: &[i32], k: usize) -> i16 {
    (env[k / 2] >> (16 * (k % 2))) as i16
}

/// `((Word16 *)env)[k] = value`: store half-word `k` of the 32-bit array `env`.
pub fn set_env_half(env: &mut [i32], k: usize, value: i16) {
    let shift = 16 * (k % 2);
    let word = &mut env[k / 2];
    *word = (*word & !(0xFFFF_i32 << shift)) | (i32::from(value as u16) << shift);
}

/// `expfp`: `exp(-x)` in Q31 for `x = x_mantissa * 2^(-x_e)` (a positive `x`, fixed point).
#[must_use]
pub fn expfp(x: i16, x_e: i16) -> i32 {
    // The reference asserts x > 0.
    let l_tmp = l_shl(l_deposit_h(x), x_e);

    // split into integer and fractional parts
    let xi = round_word(l_tmp);
    let xf = negate(extract_l(l_tmp));

    // Fractional part
    // y = 65536 + xf + ((xf*xf) / (2*65536)) + ...
    let mut y = l_mac0(65536, xf, 1);
    let mut tmp = shr(mult(xf, xf), 2);
    y = l_mac0(y, tmp, 1);
    tmp = shr(mult(shr(mult(tmp, xf), 1), (65536 / 3) as i16), 1);
    y = l_mac0(y, tmp, 1);
    tmp = shr(mult(tmp, xf), 3);
    y = l_mac0(y, tmp, 1);

    // Integer part
    let b0 = xi & 1;
    let b1 = xi & 2;
    let b2 = xi & 4;
    let b3 = xi & 8;

    if b0 != 0 {
        y = mpy_32_16_1(y, 24109); // exp(-1) in -1Q16
    }
    if b1 != 0 {
        y = mpy_32_16_1(y, 17739); // exp(-2) in -2Q17
    }
    if b2 != 0 {
        y = mpy_32_16_1(y, 19205); // exp(-4) in -5Q20
    }
    if b3 != 0 {
        y = mpy_32_16_1(y, 22513); // exp(-8) in -11Q26
    }

    // scaling: -1*b0 - 2*b1 -5*b2 -11*b3
    y = l_shr(y, add(add(xi, shr(xi, 2)), shr(b3, 3)));

    // zero for xi >= 16
    if shr(xi, 4) > 0 {
        y = l_deposit_l(0);
    }

    l_shl(y, 15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_halves_alias_the_32_bit_words() {
        let mut env = [0x1234_5678_i32, -1, 0];
        assert_eq!(env_half(&env, 0), 0x5678);
        assert_eq!(env_half(&env, 1), 0x1234);
        set_env_half(&mut env, 1, -2);
        set_env_half(&mut env, 4, 0x7ABC);
        assert_eq!(env[0], 0xFFFE_5678_u32 as i32);
        assert_eq!(env[2], 0x7ABC);
        assert_eq!(env[1], -1);
    }

    #[test]
    fn expfp_of_a_small_argument_is_just_under_one() {
        // x = 4 / 65536: exp(-x) = 1 - x to the first order, y = 65536 - 4 (Q16), shifted to Q31.
        assert_eq!(expfp(1, -14), 65532 << 15);
    }

    #[test]
    fn expfp_vanishes_for_large_arguments() {
        // x = 16.0 (Q0 mantissa 16, exponent 0): exp(-16) is below Q31 resolution after scaling.
        assert_eq!(expfp(16, 0), 0);
    }
}
