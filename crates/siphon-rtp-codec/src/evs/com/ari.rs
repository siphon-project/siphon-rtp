//! Arithmetic-coder multiplies shared by encoder and decoder (TS 26.442 `lib_com/ari.c`).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::STAT_BITSNEW;
use crate::itu::basic_ops::l_shl;
use crate::itu::stl2009::{l_mac0, l_mult0};

/// `L_multi31x16_X2`: the 31x16 bit product `x * y`, with `x = xh * 2^15 + xl` (`xh` is bits
/// 30..15 of `x`, `xl` its 15 LSBs).
#[must_use]
pub fn l_multi31x16_x2(xh: i16, xl: i16, y: i16) -> i32 {
    let z = l_shl(l_mult0(xh, y), 15);
    l_mac0(z, xl, y)
}

/// `mul_sbc_14bits`: `(r * c) >> stat_bitsnew`, as `Mpy_32_16_1(r << (15 - stat_bitsnew), c)`.
#[must_use]
pub fn mul_sbc_14bits(r: i32, c: i16) -> i32 {
    // The reference asserts stat_bitsnew == 14.
    mpy_32_16_1(l_shl(r, 15 - STAT_BITSNEW), c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi31x16_splits_the_first_operand() {
        // x = 3 * 2^15 + 5, y = 7: (3 * 7) << 15 plus 5 * 7.
        assert_eq!(l_multi31x16_x2(3, 5, 7), (21 << 15) + 35);
        assert_eq!(l_multi31x16_x2(0, 0, -32768), 0);
    }

    #[test]
    fn mul_sbc_scales_by_two_to_the_fourteen() {
        // (65536 * 8192) >> 14 = 32768, (16384 * 16384) >> 14 = 16384.
        assert_eq!(mul_sbc_14bits(65536, 8192), 32768);
        assert_eq!(mul_sbc_14bits(16384, 16384), 16384);
    }
}
