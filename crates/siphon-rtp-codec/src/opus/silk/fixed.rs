//! SILK fixed-point primitives (libopus `silk/macros.h`, `silk/SigProc_FIX.h`).
//!
//! RFC 6716 §4.2.7.5 says an implementation SHOULD reproduce the reference fixed-point arithmetic
//! exactly, and it means the *arithmetic*, not just the algorithm: several of these macros truncate,
//! and the truncation is observable in the decoded output. Porting them as named functions rather than
//! open-coding `(a as i64 * b as i64) >> 16` at each site keeps the rounding in one audited place.
//!
//! All of them wrap on 32-bit overflow, exactly as the C's `opus_int32` arithmetic does. The domains
//! SILK actually feeds them never overflow — the tests below pin that down where it matters — but a
//! hostile bitstream must not be able to make a debug build panic on an arithmetic overflow, so the
//! wrapping is explicit rather than incidental.

/// `silk_SMULWB(a32, b32)` — `(a32 * (int16)b32) >> 16` (`macros.h:41-46`).
///
/// **The truncation is load-bearing.** `b32` is narrowed to 16 bits *before* multiplying, and the
/// 48-bit product is shifted right arithmetically, so the result is a floor, not a round. libopus
/// carries two implementations (a 64-bit one and a split 32×16 one for platforms without a fast
/// 64-bit multiply); they agree for every input in SILK's domain, which
/// `smulwb_split_and_wide_forms_agree` proves.
#[inline]
#[must_use]
pub fn smulwb(a32: i32, b32: i32) -> i32 {
    // (i16) narrowing of b32 first, matching the C cast.
    let b16 = b32 as i16;
    ((i64::from(a32) * i64::from(b16)) >> 16) as i32
}

/// `silk_SMLAWB(a32, b32, c32)` — `a32 + ((b32 * (int16)c32) >> 16)` (`macros.h:48-53`), i.e.
/// [`smulwb`] accumulated onto `a32`.
#[inline]
#[must_use]
pub fn smlawb(a32: i32, b32: i32, c32: i32) -> i32 {
    a32.wrapping_add(smulwb(b32, c32))
}

/// `silk_SMULBB(a32, b32)` — `(int32)(int16)a32 * (int32)(int16)b32` (`macros.h:70`). Both operands
/// are narrowed to 16 bits first; the 32-bit product is exact for any pair of `i16`s.
#[inline]
#[must_use]
pub fn smulbb(a32: i32, b32: i32) -> i32 {
    i32::from(a32 as i16).wrapping_mul(i32::from(b32 as i16))
}

/// `silk_SMLABB(a32, b32, c32)` — `a32 + (int16)b32 * (int16)c32` (`macros.h:73`).
#[inline]
#[must_use]
pub fn smlabb(a32: i32, b32: i32, c32: i32) -> i32 {
    a32.wrapping_add(smulbb(b32, c32))
}

/// `silk_LIMIT_int(a, lower, upper)` (`SigProc_FIX.h`) — clamp.
///
/// The C macro evaluates `lower > upper ? (a < lower ? lower : a > upper ? upper : a) : ...`, which
/// for SILK's always-ordered bounds is a plain clamp. Callers pass literal ordered bounds, so this
/// asserts the ordering in debug builds instead of silently reproducing the degenerate branch.
#[inline]
#[must_use]
pub fn limit_int(value: i32, lower: i32, upper: i32) -> i32 {
    debug_assert!(lower <= upper, "silk: limit bounds must be ordered");
    value.clamp(lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// libopus' non-`OPUS_FAST_INT64` `silk_SMULWB`: `((a >> 16) * b) + (((a & 0xFFFF) * b) >> 16)`.
    /// Kept here as the second, independently written reference for the same macro.
    fn smulwb_split(a32: i32, b32: i32) -> i32 {
        let b = i32::from(b32 as i16);
        (a32 >> 16)
            .wrapping_mul(b)
            .wrapping_add(((a32 & 0x0000_FFFF).wrapping_mul(b)) >> 16)
    }

    #[test]
    fn smulwb_known_values() {
        assert_eq!(smulwb(65536, 1), 1);
        assert_eq!(smulwb(65536, 2), 2);
        assert_eq!(smulwb(1, 1), 0, "floors toward negative infinity");
        assert_eq!(smulwb(-65536, 3), -3);
        // Narrowing of the second operand: 0x1_0001 becomes 1, not 65537.
        assert_eq!(smulwb(65536, 0x1_0001), 1);
        // Negative narrowing: 0xFFFF as i16 is -1.
        assert_eq!(smulwb(65536, 0xFFFF), -1);
        // Arithmetic (not logical) shift, so a negative product floors away from zero.
        assert_eq!(smulwb(-65537, 1), -2, "floor(-65537/65536) = -2");
        assert_eq!(smulwb(-1, 1), -1, "floor(-1/65536) = -1, not 0");
    }

    /// The exact case that decides every SILK subframe gain: `INV_SCALE_Q16 * 63`. A plain
    /// `1907825 * 63 / 65536` in real arithmetic is 1834.35, so a rounding implementation would
    /// return 1834 and every maximum-gain subframe in the codec would come out one step too loud.
    /// The floor is 1833, and RFC 6716 §4.2.7.4's stated maximum gain of 1686110208 only comes out
    /// right with 1833.
    #[test]
    fn smulwb_gain_scale_floors_to_1833() {
        assert_eq!(smulwb(1_907_825, 63), 1833);
        assert_eq!(smulwb_split(1_907_825, 63), 1833);
        assert_eq!(1_907_825_i64 * 63 / 65536, 1833);
    }

    #[test]
    fn smlawb_accumulates_smulwb() {
        assert_eq!(smlawb(100, 65536, 5), 105);
        assert_eq!(smlawb(-7, 65536, 3), -4);
        // The §4.2.7.4 log2lin parabola term: f + ((f*(128-f) * -174) >> 16) for f = 83.
        assert_eq!(smlawb(83, 83 * (128 - 83), -174), 73);
        // ...and for f = 42, the minimum-gain case.
        assert_eq!(smlawb(42, 42 * (128 - 42), -174), 32);
    }

    #[test]
    fn smulbb_and_smlabb_narrow_both_operands() {
        assert_eq!(smulbb(3, 4), 12);
        assert_eq!(smulbb(-3, 4), -12);
        assert_eq!(smulbb(0x1_0003, 4), 12, "0x10003 narrows to 3");
        assert_eq!(smulbb(32767, 32767), 1_073_676_289);
        assert_eq!(smlabb(1000, 3, 4), 1012);
        assert_eq!(smlabb(-1000, -3, 4), -1012);
        // The §4.2.7.1 stereo interpolation: low_Q13 + step_Q13 * (2*i + 1).
        assert_eq!(smlabb(-13732, 368, 9), -13732 + 3312);
    }

    #[test]
    fn limit_int_clamps() {
        assert_eq!(limit_int(-5, 0, 63), 0);
        assert_eq!(limit_int(70, 0, 63), 63);
        assert_eq!(limit_int(31, 0, 63), 31);
        assert_eq!(limit_int(0, 0, 0), 0);
    }

    proptest! {
        /// libopus' two `silk_SMULWB` spellings must agree over SILK's operand domain. The split form
        /// can overflow `i32` for extreme `a32`, which is why the range is bounded: SILK only ever
        /// feeds it Q13/Q16 quantities well inside this window (the widest real use is
        /// `INV_SCALE_Q16 * log_gain`, i.e. ~1.9e6 by 63).
        #[test]
        fn smulwb_split_and_wide_forms_agree(
            a in -(1i32 << 28)..(1i32 << 28),
            b in i16::MIN..=i16::MAX,
        ) {
            prop_assert_eq!(smulwb(a, i32::from(b)), smulwb_split(a, i32::from(b)));
        }

        /// [`smulwb`] is exactly a floored division by 2^16 of the narrowed product.
        #[test]
        fn smulwb_is_a_floored_shift(a: i32, b in i16::MIN..=i16::MAX) {
            let product = i64::from(a) * i64::from(b);
            prop_assert_eq!(i64::from(smulwb(a, i32::from(b))), product >> 16);
        }

        /// Nothing panics on arbitrary input, including `i32::MIN` operands.
        #[test]
        fn primitives_never_panic(a: i32, b: i32, c: i32) {
            let _ = smulwb(a, b);
            let _ = smlawb(a, b, c);
            let _ = smulbb(a, b);
            let _ = smlabb(a, b, c);
        }
    }
}
