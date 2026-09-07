//! 3GPP / ITU-T fixed-point basic operators (the `basicop2` set).
//!
//! AMR-NB and AMR-WB are specified in fixed-point integer arithmetic with exact saturation and
//! rounding semantics. Bit-exactness against the 3GPP reference is won or lost entirely in these
//! primitives, so they are ported faithfully and tested before any codec DSP is built on top.
//!
//! `Word16` = [`i16`], `Word32` = [`i32`]. All operators saturate rather than wrap.

/// Saturate a 32-bit value to the 16-bit range.
#[inline]
#[must_use]
pub const fn saturate(value: i32) -> i16 {
    if value > i16::MAX as i32 {
        i16::MAX
    } else if value < i16::MIN as i32 {
        i16::MIN
    } else {
        value as i16
    }
}

/// 16-bit saturating addition.
#[inline]
#[must_use]
pub fn add(var1: i16, var2: i16) -> i16 {
    saturate(var1 as i32 + var2 as i32)
}

/// 16-bit saturating subtraction.
#[inline]
#[must_use]
pub fn sub(var1: i16, var2: i16) -> i16 {
    saturate(var1 as i32 - var2 as i32)
}

/// Saturating absolute value (`abs(MIN) == MAX`).
#[inline]
#[must_use]
pub fn abs_s(var1: i16) -> i16 {
    if var1 == i16::MIN {
        i16::MAX
    } else {
        var1.abs()
    }
}

/// Saturating negation (`-MIN == MAX`).
#[inline]
#[must_use]
pub fn negate(var1: i16) -> i16 {
    if var1 == i16::MIN {
        i16::MAX
    } else {
        -var1
    }
}

/// Extract the high 16 bits of a 32-bit value.
#[inline]
#[must_use]
pub const fn extract_h(l_var1: i32) -> i16 {
    (l_var1 >> 16) as i16
}

/// Extract the low 16 bits of a 32-bit value.
#[inline]
#[must_use]
pub const fn extract_l(l_var1: i32) -> i16 {
    l_var1 as i16
}

/// Deposit a 16-bit value into the high half of a 32-bit value.
#[inline]
#[must_use]
pub const fn l_deposit_h(var1: i16) -> i32 {
    (var1 as i32) << 16
}

/// Deposit a 16-bit value into the low half (sign-extended) of a 32-bit value.
#[inline]
#[must_use]
pub const fn l_deposit_l(var1: i16) -> i32 {
    var1 as i32
}

/// 16x16 → 16 multiply with `>> 15` (`mult(MIN, MIN) == MAX`).
#[inline]
#[must_use]
pub fn mult(var1: i16, var2: i16) -> i16 {
    saturate((var1 as i32 * var2 as i32) >> 15)
}

/// Rounded 16x16 → 16 multiply (`(a*b + 0x4000) >> 15`).
#[inline]
#[must_use]
pub fn mult_r(var1: i16, var2: i16) -> i16 {
    saturate((var1 as i32 * var2 as i32 + 0x4000) >> 15)
}

/// 16x16 → 32 multiply, left-shifted by 1, saturating (`L_mult(MIN, MIN) == MAX_32`).
#[inline]
#[must_use]
pub fn l_mult(var1: i16, var2: i16) -> i32 {
    let product = var1 as i32 * var2 as i32;
    if product == 0x4000_0000 {
        i32::MAX
    } else {
        product << 1
    }
}

/// 32-bit saturating addition.
#[inline]
#[must_use]
pub fn l_add(l_var1: i32, l_var2: i32) -> i32 {
    l_var1.saturating_add(l_var2)
}

/// 32-bit saturating subtraction.
#[inline]
#[must_use]
pub fn l_sub(l_var1: i32, l_var2: i32) -> i32 {
    l_var1.saturating_sub(l_var2)
}

/// Multiply-accumulate: `l_add(l_var3, l_mult(var1, var2))`.
#[inline]
#[must_use]
pub fn l_mac(l_var3: i32, var1: i16, var2: i16) -> i32 {
    l_add(l_var3, l_mult(var1, var2))
}

/// Multiply-subtract: `l_sub(l_var3, l_mult(var1, var2))`.
#[inline]
#[must_use]
pub fn l_msu(l_var3: i32, var1: i16, var2: i16) -> i32 {
    l_sub(l_var3, l_mult(var1, var2))
}

/// 32-bit saturating negation (`-MIN_32 == MAX_32`).
#[inline]
#[must_use]
pub fn l_negate(l_var1: i32) -> i32 {
    if l_var1 == i32::MIN {
        i32::MAX
    } else {
        -l_var1
    }
}

/// Round a 32-bit accumulator to 16 bits: `extract_h(l_add(l, 0x8000))`.
#[inline]
#[must_use]
pub fn round_word(l_var1: i32) -> i16 {
    extract_h(l_add(l_var1, 0x0000_8000))
}

/// Arithmetic right shift of a 16-bit value (negative count shifts left).
#[inline]
#[must_use]
pub fn shr(var1: i16, var2: i16) -> i16 {
    if var2 < 0 {
        let count = if var2 < -16 { 16 } else { -var2 };
        return shl(var1, count);
    }
    if var2 >= 15 {
        return if var1 < 0 { -1 } else { 0 };
    }
    var1 >> var2
}

/// Saturating left shift of a 16-bit value (negative count shifts right).
#[inline]
#[must_use]
pub fn shl(var1: i16, var2: i16) -> i16 {
    if var2 < 0 {
        let count = if var2 < -16 { 16 } else { -var2 };
        return shr(var1, count);
    }
    if var2 >= 15 {
        return if var1 == 0 {
            0
        } else if var1 > 0 {
            i16::MAX
        } else {
            i16::MIN
        };
    }
    saturate((var1 as i32) << var2)
}

/// Arithmetic right shift of a 32-bit value (negative count shifts left).
#[inline]
#[must_use]
pub fn l_shr(l_var1: i32, var2: i16) -> i32 {
    if var2 < 0 {
        let count = if var2 < -32 { 32 } else { -var2 };
        return l_shl(l_var1, count);
    }
    if var2 >= 31 {
        return if l_var1 < 0 { -1 } else { 0 };
    }
    l_var1 >> var2
}

/// 32-bit arithmetic right shift with rounding: `L_shr` then add the bit shifted past the LSB
/// (ITU-T `L_shr_r`). For `var2 > 31` the result is 0; for `var2 <= 0` it is a plain shift.
#[inline]
#[must_use]
pub fn l_shr_r(l_var1: i32, var2: i16) -> i32 {
    if var2 > 31 {
        return 0;
    }
    let l_var_out = l_shr(l_var1, var2);
    if var2 > 0 && (l_var1 & (1i32 << (var2 - 1))) != 0 {
        l_var_out + 1
    } else {
        l_var_out
    }
}

/// 16-bit arithmetic right shift with rounding (ITU-T `shr_r`): `shr` then add the bit shifted past
/// the LSB. For `var2 > 15` the result is 0.
#[inline]
#[must_use]
pub fn shr_r(var1: i16, var2: i16) -> i16 {
    if var2 > 15 {
        return 0;
    }
    let var_out = shr(var1, var2);
    if var2 > 0 && (var1 & (1i16 << (var2 - 1))) != 0 {
        var_out + 1 // var2 > 0 ⇒ var_out ≤ 0x3FFF, so +1 cannot overflow
    } else {
        var_out
    }
}

/// Absolute value of a 32-bit integer (ITU-T `L_abs`); `MIN` saturates to `MAX`.
#[inline]
#[must_use]
pub fn l_abs(l_var1: i32) -> i32 {
    if l_var1 == i32::MIN {
        i32::MAX
    } else {
        l_var1.abs()
    }
}

/// Saturating left shift of a 32-bit value (negative count shifts right).
#[inline]
#[must_use]
pub fn l_shl(l_var1: i32, var2: i16) -> i32 {
    if var2 <= 0 {
        let count = if var2 < -32 { 32 } else { -var2 };
        return l_shr(l_var1, count);
    }
    let mut value = l_var1;
    let mut remaining = var2;
    while remaining > 0 {
        if value > 0x3FFF_FFFF {
            return i32::MAX;
        }
        if value < -0x4000_0000 {
            return i32::MIN;
        }
        value *= 2;
        remaining -= 1;
    }
    value
}

/// Number of left shifts to normalize a non-zero 16-bit value (0 for 0).
#[inline]
#[must_use]
pub fn norm_s(var1: i16) -> i16 {
    if var1 == 0 {
        return 0;
    }
    if var1 == -1 {
        return 15;
    }
    let mut value = if var1 < 0 { !var1 } else { var1 };
    let mut count = 0i16;
    while value < 0x4000 {
        value <<= 1;
        count += 1;
    }
    count
}

/// Number of left shifts to normalize a non-zero 32-bit value (0 for 0).
#[inline]
#[must_use]
pub fn norm_l(l_var1: i32) -> i16 {
    if l_var1 == 0 {
        return 0;
    }
    if l_var1 == -1 {
        return 31;
    }
    let mut value = if l_var1 < 0 { !l_var1 } else { l_var1 };
    let mut count = 0i16;
    while value < 0x4000_0000 {
        value <<= 1;
        count += 1;
    }
    count
}

/// Fractional division `var1 / var2` in Q15. Requires `0 <= var1 <= var2` and `var2 != 0`.
#[inline]
#[must_use]
pub fn div_s(var1: i16, var2: i16) -> i16 {
    if var1 == 0 {
        return 0;
    }
    if var1 < 0 || var2 <= 0 || var1 > var2 {
        // Precondition violated; saturate rather than panic.
        return i16::MAX;
    }
    if var1 == var2 {
        return i16::MAX;
    }
    let mut numerator = var1 as i32;
    let denominator = var2 as i32;
    let mut result = 0i16;
    for _ in 0..15 {
        result <<= 1;
        numerator <<= 1;
        if numerator >= denominator {
            numerator -= denominator;
            result += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturate_clamps() {
        assert_eq!(saturate(40000), i16::MAX);
        assert_eq!(saturate(-40000), i16::MIN);
        assert_eq!(saturate(123), 123);
    }

    #[test]
    fn l_shr_r_rounds_on_the_dropped_bit() {
        // No rounding when the bit shifted past the LSB is 0.
        assert_eq!(l_shr_r(0b100, 1), 0b10);
        // Round up when it is 1: 0b110 >> 1 = 0b11, dropped bit (bit0) = 0 → 0b11.
        assert_eq!(l_shr_r(0b110, 1), 0b11);
        // 0b111 >> 1 = 0b11, dropped bit0 = 1 → 0b11 + 1 = 0b100.
        assert_eq!(l_shr_r(0b111, 1), 0b100);
        // var2 > 31 → 0; var2 <= 0 behaves as a plain (left) shift, no rounding.
        assert_eq!(l_shr_r(0x7FFF_FFFF, 32), 0);
        assert_eq!(l_shr_r(0x4000_0000, 30), 1);
    }

    #[test]
    fn shr_r_rounds_16bit() {
        assert_eq!(shr_r(0b100, 1), 0b10); // dropped bit 0 → no round
        assert_eq!(shr_r(0b111, 1), 0b100); // dropped bit 1 → round up
        assert_eq!(shr_r(100, 0), 100); // no shift, no round
        assert_eq!(shr_r(1, 16), 0); // var2 > 15 → 0
    }

    #[test]
    fn l_abs_saturates_min() {
        assert_eq!(l_abs(-5), 5);
        assert_eq!(l_abs(5), 5);
        assert_eq!(l_abs(i32::MIN), i32::MAX);
    }

    #[test]
    fn add_sub_saturate() {
        assert_eq!(add(i16::MAX, 1), i16::MAX);
        assert_eq!(add(i16::MIN, -1), i16::MIN);
        assert_eq!(add(100, 200), 300);
        assert_eq!(sub(i16::MIN, 1), i16::MIN);
        assert_eq!(sub(i16::MAX, -1), i16::MAX);
        assert_eq!(sub(300, 100), 200);
    }

    #[test]
    fn abs_and_negate_handle_min() {
        assert_eq!(abs_s(i16::MIN), i16::MAX);
        assert_eq!(abs_s(-5), 5);
        assert_eq!(negate(i16::MIN), i16::MAX);
        assert_eq!(negate(5), -5);
    }

    #[test]
    fn mult_min_min_is_max() {
        assert_eq!(mult(i16::MIN, i16::MIN), i16::MAX);
        // 0.5 * 0.5 in Q15: 16384 * 16384 >> 15 = 8192.
        assert_eq!(mult(16384, 16384), 8192);
        assert_eq!(mult(0, 12345), 0);
    }

    #[test]
    fn l_mult_min_min_saturates() {
        assert_eq!(l_mult(i16::MIN, i16::MIN), i32::MAX);
        assert_eq!(l_mult(16384, 16384), 0x2000_0000);
        assert_eq!(l_mult(0, 1), 0);
    }

    #[test]
    fn mac_and_msu() {
        // 0 + (16384*16384)<<1 = 0x20000000.
        assert_eq!(l_mac(0, 16384, 16384), 0x2000_0000);
        assert_eq!(l_msu(0x2000_0000, 16384, 16384), 0);
        // Saturation on accumulate.
        assert_eq!(l_mac(i32::MAX, i16::MAX, i16::MAX), i32::MAX);
    }

    #[test]
    fn deposit_and_extract_roundtrip() {
        let composed = l_add(l_deposit_h(0x1234), l_deposit_l(0x5678));
        assert_eq!(composed, 0x1234_5678);
        assert_eq!(extract_h(composed), 0x1234);
        assert_eq!(extract_l(composed), 0x5678);
        // Sign extension in deposit_l.
        assert_eq!(l_deposit_l(-1), -1);
        assert_eq!(extract_h(l_deposit_h(-1)), -1);
    }

    #[test]
    fn round_word_rounds_half_up() {
        assert_eq!(round_word(0x0001_8000), 2);
        assert_eq!(round_word(0x0001_7FFF), 1);
        assert_eq!(round_word(i32::MAX), i16::MAX);
    }

    #[test]
    fn shifts_saturate_and_invert() {
        assert_eq!(shl(0x4000, 2), i16::MAX); // overflow saturates positive
        assert_eq!(shl(-0x4000, 2), i16::MIN); // overflow saturates negative
        assert_eq!(shl(100, 3), 800);
        assert_eq!(shr(800, 3), 100);
        // Negative count inverts direction.
        assert_eq!(shl(100, -3), shr(100, 3));
        assert_eq!(shr(100, -3), shl(100, 3));
        assert_eq!(shr(-1, 15), -1);
        assert_eq!(shr(1, 15), 0);
    }

    #[test]
    fn long_shifts_saturate_and_invert() {
        assert_eq!(l_shl(0x4000_0000, 1), i32::MAX);
        assert_eq!(l_shl(-0x4000_0001, 1), i32::MIN);
        assert_eq!(l_shl(0x0000_1000, 4), 0x0001_0000);
        assert_eq!(l_shr(0x0001_0000, 4), 0x0000_1000);
        assert_eq!(l_shl(123, -4), l_shr(123, 4));
        assert_eq!(l_shr(-1, 31), -1);
        assert_eq!(l_shr(1, 31), 0);
    }

    #[test]
    fn norm_counts_leading_sign_bits() {
        assert_eq!(norm_s(0), 0);
        assert_eq!(norm_s(-1), 15);
        assert_eq!(norm_s(0x4000), 0);
        assert_eq!(norm_s(0x2000), 1);
        assert_eq!(norm_s(1), 14);

        assert_eq!(norm_l(0), 0);
        assert_eq!(norm_l(-1), 31);
        assert_eq!(norm_l(0x4000_0000), 0);
        assert_eq!(norm_l(0x2000_0000), 1);
        assert_eq!(norm_l(1), 30);
    }

    #[test]
    fn div_s_known_values() {
        assert_eq!(div_s(0, 100), 0);
        assert_eq!(div_s(100, 100), i16::MAX);
        assert_eq!(div_s(1, 2), 16384); // 0.5 in Q15
        assert_eq!(div_s(1, 4), 8192); // 0.25 in Q15
        assert_eq!(div_s(3, 4), 24576); // 0.75 in Q15
    }
}
