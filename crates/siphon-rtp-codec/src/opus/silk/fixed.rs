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

/// `silk_log2lin(inLog_Q7)` (`log2lin.c:36-58`) — an approximation of `2^(inLog_Q7 / 128)`, the
/// inverse of `silk_lin2log`. Used to turn a quantized log-gain into a linear Q16 scale factor
/// (RFC 6716 §4.2.7.4).
///
/// The integer part `i = inLog_Q7 >> 7` gives `1 << i`; the fractional part `f = inLog_Q7 & 127` is
/// applied through a parabolic correction `f + ((-174 * f * (128 - f)) >> 16)`. RFC 6716 §4.2.7.4
/// prints only the `inLog_Q7 >= 2048` form,
/// `(1<<i) + ((-174*f*(128-f)>>16)+f)*((1<<i)>>7)` — which is the only branch the gain path can reach,
/// since the smallest log-gain maps to 2090. libopus keeps a second branch for smaller inputs that
/// multiplies before shifting, preserving precision when `1 << i` is small; both are ported.
///
/// The two guards are the C's: a negative input is 0, and 3967 (31.0 in Q7) or above saturates.
#[inline]
#[must_use]
pub fn log2lin(in_log_q7: i32) -> i32 {
    if in_log_q7 < 0 {
        return 0;
    }
    if in_log_q7 >= 3967 {
        return i32::MAX;
    }
    let out = 1i32 << (in_log_q7 >> 7);
    let frac_q7 = in_log_q7 & 0x7F;
    // silk_SMLAWB( frac_Q7, silk_SMULBB( frac_Q7, 128 - frac_Q7 ), -174 )
    let correction = smlawb(frac_q7, smulbb(frac_q7, 128 - frac_q7), -174);
    if in_log_q7 < 2048 {
        // silk_ADD_RSHIFT32( out, silk_MUL( out, correction ), 7 )
        out.wrapping_add(out.wrapping_mul(correction) >> 7)
    } else {
        // silk_MLA( out, silk_RSHIFT( out, 7 ), correction )
        out.wrapping_add((out >> 7).wrapping_mul(correction))
    }
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

/// `silk_SMULWW(a32, b32)` — `(a32 * b32) >> 16` (`macros.h:86`). Unlike [`smulwb`] neither operand
/// is narrowed, so the full 64-bit product is shifted; the result is a floor.
#[inline]
#[must_use]
pub fn smulww(a32: i32, b32: i32) -> i32 {
    ((i64::from(a32) * i64::from(b32)) >> 16) as i32
}

/// `silk_SMMUL(a32, b32)` — `(a32 * b32) >> 32` (`SigProc_FIX.h:610`), i.e. the signed high word of
/// the product.
#[inline]
#[must_use]
pub fn smmul(a32: i32, b32: i32) -> i32 {
    ((i64::from(a32) * i64::from(b32)) >> 32) as i32
}

/// `silk_RSHIFT_ROUND(a, shift)` (`SigProc_FIX.h:531`) — right shift with round-half-up.
///
/// The C spells it `((a) >> ((shift) - 1)) + 1) >> 1`, which rounds ties **towards +infinity**, not
/// away from zero. That asymmetry is observable in the Q12 LPC coefficients, so it is reproduced
/// exactly rather than replaced with a "nicer" rounding. `shift` must be >= 1, as the macro says.
#[inline]
#[must_use]
pub fn rshift_round(a: i32, shift: u32) -> i32 {
    debug_assert!(shift >= 1, "silk: RSHIFT_ROUND needs shift >= 1");
    if shift == 1 {
        (a >> 1) + (a & 1)
    } else {
        ((a >> (shift - 1)) + 1) >> 1
    }
}

/// `silk_RSHIFT_ROUND64(a, shift)` (`SigProc_FIX.h:532`) — [`rshift_round`] on a 64-bit value.
#[inline]
#[must_use]
pub fn rshift_round64(a: i64, shift: u32) -> i64 {
    debug_assert!(shift >= 1, "silk: RSHIFT_ROUND64 needs shift >= 1");
    if shift == 1 {
        (a >> 1) + (a & 1)
    } else {
        ((a >> (shift - 1)) + 1) >> 1
    }
}

/// `silk_SAT16(a)` (`SigProc_FIX.h:474`) — saturate to `i16`.
#[inline]
#[must_use]
pub fn sat16(a: i32) -> i16 {
    a.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

/// `silk_ADD_SAT16(a, b)` (`SigProc_FIX.h:483`) — add in 32 bits, then saturate to `i16`.
#[inline]
#[must_use]
pub fn add_sat16(a: i16, b: i16) -> i16 {
    sat16(i32::from(a) + i32::from(b))
}

/// `silk_LSHIFT_SAT32(a, shift)` (`SigProc_FIX.h:514`) — clamp so the left shift cannot overflow,
/// **then** shift. Note the C clamps against `int32_MIN >> shift` / `int32_MAX >> shift`, so this is
/// not the same as shifting and saturating afterwards.
#[inline]
#[must_use]
pub fn lshift_sat32(a: i32, shift: u32) -> i32 {
    let lower = i32::MIN >> shift;
    let upper = i32::MAX >> shift;
    a.clamp(lower, upper) << shift
}

/// `silk_SUB_SAT32(a, b)` (`macros.h:103`) — subtract, saturating at the `i32` bounds.
#[inline]
#[must_use]
pub fn sub_sat32(a: i32, b: i32) -> i32 {
    a.saturating_sub(b)
}

/// `silk_abs(a)` (`SigProc_FIX.h:588`) — magnitude, wrapping at `i32::MIN` exactly as the C macro
/// does. The C carries its own warning about that case; the callers here bound their input first.
#[inline]
#[must_use]
pub fn abs_wrapping(a: i32) -> i32 {
    if a > 0 {
        a
    } else {
        a.wrapping_neg()
    }
}

/// `silk_INVERSE32_varQ(b32, Qres)` (`Inlines.h:143-182`) — `(1 << Qres) / b32` to about 30 bits of
/// precision, without a divide in the inner loop.
///
/// Only ever called with a strictly positive `b32` on the decode path (`LPC_inv_pred_gain.c:76`
/// passes `rc_mult1_Q30`, which the C asserts is in `(1<<15, 1<<30]`), so a zero denominator returns
/// 0 rather than reproducing the C's `silk_assert`.
#[inline]
#[must_use]
pub fn inverse32_var_q(b32: i32, q_result: i32) -> i32 {
    if b32 == 0 {
        return 0;
    }
    // silk_CLZ32( silk_abs(b32) ) - 1.
    let head_room = (b32.unsigned_abs().leading_zeros() as i32) - 1;
    let b32_normalized = ((b32 as u32) << head_room) as i32;
    // Inverse of b32 with 14 bits of precision.
    let b32_inverse = (i32::MAX >> 2) / (b32_normalized >> 16);
    let mut result = ((b32_inverse as u32) << 16) as i32;
    // One Newton refinement: err = 1 - b32_nrm * b32_inv, in Q32.
    let error_q32 = ((1i32 << 29).wrapping_sub(smulwb(b32_normalized, b32_inverse)) as u32) << 3;
    let error_q32 = error_q32 as i32;
    // silk_SMLAWW( result, err_Q32, b32_inv ) = result + ((err * inv) >> 16).
    result = result.wrapping_add(smulww(error_q32, b32_inverse));

    let left_shift = 61 - head_room - q_result;
    if left_shift <= 0 {
        lshift_sat32(result, (-left_shift) as u32)
    } else if left_shift < 32 {
        result >> left_shift
    } else {
        // "Avoid undefined result" (Inlines.h:178-180).
        0
    }
}

/// `silk_DIV32_varQ(a32, b32, Qres)` (`Inlines.h:97-140`) — `(a32 << Qres) / b32` to about 30 bits
/// of precision, by the same normalise-invert-refine shape as [`inverse32_var_q`].
///
/// A zero denominator returns 0 instead of reproducing the C's `silk_assert`; the decode path only
/// ever divides by a subframe gain, which RFC 6716 §4.2.7.4 bounds below by 81920.
#[inline]
#[must_use]
pub fn div32_var_q(a32: i32, b32: i32, q_result: i32) -> i32 {
    if b32 == 0 {
        return 0;
    }
    // silk_CLZ32( silk_abs(a32) ) - 1 — `abs` of 0 is 0, whose CLZ is 32, so the head room is 31.
    let a_head_room = (a32.unsigned_abs().leading_zeros() as i32) - 1;
    let mut a32_normalized = ((a32 as u32) << a_head_room) as i32;
    let b_head_room = (b32.unsigned_abs().leading_zeros() as i32) - 1;
    let b32_normalized = ((b32 as u32) << b_head_room) as i32;

    // Inverse of b32 with 14 bits of precision.
    let b32_inverse = (i32::MAX >> 2) / (b32_normalized >> 16);
    let mut result = smulwb(a32_normalized, b32_inverse);
    // "It's OK to overflow because the final value of a32_nrm should always be small."
    a32_normalized =
        a32_normalized.wrapping_sub(((smmul(b32_normalized, result) as u32) << 3) as i32);
    result = smlawb(result, a32_normalized, b32_inverse);

    let left_shift = 29 + a_head_room - b_head_room - q_result;
    if left_shift < 0 {
        lshift_sat32(result, (-left_shift) as u32)
    } else if left_shift < 32 {
        result >> left_shift
    } else {
        // "Avoid undefined result" (Inlines.h:135-137).
        0
    }
}

/// `silk_SMULTT(a32, b32)` — `(a32 >> 16) * (b32 >> 16)` (`macros.h:80`), the product of the two
/// *high* halves. Used by the CNG gain estimate on values too large for [`smulww`].
#[inline]
#[must_use]
pub fn smultt(a32: i32, b32: i32) -> i32 {
    (a32 >> 16).wrapping_mul(b32 >> 16)
}

/// `silk_SQRT_APPROX(x)` (`Inlines.h:71-94`) — square root to within ±10 % for outputs above 15 and
/// ±2.5 % above 120. Exactly this approximation, not a real `sqrt`: the CNG gain it produces is
/// audible state, so the error is part of the bitstream-defined behaviour.
#[inline]
#[must_use]
pub fn sqrt_approx(x: i32) -> i32 {
    if x <= 0 {
        return 0;
    }
    // silk_CLZ_FRAC: leading zeros, plus the 7 bits immediately right of the leading one. The C's
    // `silk_ROR32(in, 24 - lzeros)` is a rotate *right* whose count goes negative for small inputs;
    // rotation is cyclic mod 32, so masking the two's-complement count reproduces both branches.
    let leading_zeros = x.leading_zeros() as i32;
    let fraction_q7 = x.rotate_right(((24 - leading_zeros) as u32) & 31) & 0x7F;

    // sqrt(2) * 32768 = 46214 when the leading one sits at an even bit position.
    let mut y = if leading_zeros & 1 != 0 { 32768 } else { 46214 };
    y >>= leading_zeros >> 1;
    smlawb(y, y, smulbb(213, fraction_q7))
}

/// `silk_ADD_LSHIFT32(a, b, shift)` (`SigProc_FIX.h:521`) — `a + (b << shift)`, wrapping.
#[inline]
#[must_use]
pub fn add_lshift32(a: i32, b: i32, shift: u32) -> i32 {
    a.wrapping_add(((b as u32) << shift) as i32)
}

/// `silk_SUB_LSHIFT32(a, b, shift)` (`SigProc_FIX.h:524`) — `a - (b << shift)`, wrapping.
#[inline]
#[must_use]
pub fn sub_lshift32(a: i32, b: i32, shift: u32) -> i32 {
    a.wrapping_sub(((b as u32) << shift) as i32)
}

/// `silk_sum_sqr_shift(energy, shift, x, len)` (`sum_sqr_shift.c:36-82`) — the sum of squares of an
/// `i16` vector, right-shifted by however much it takes to fit an `i32` with two bits of head room.
///
/// Returns `(energy, shift)`. The two-pass shape is the C's: a first pass with the maximum shift
/// `31 - CLZ(len)` establishes the magnitude, then a second pass redoes the sum with the tightest
/// shift that keeps it in range. Two energies are only comparable after normalising to a common
/// shift, which is what `silk_PLC_conceal` and `silk_PLC_glue_frames` do with the pair.
#[must_use]
pub fn sum_sqr_shift(x: &[i16]) -> (i32, i32) {
    let len = x.len() as i32;
    if len == 0 {
        return (0, 0);
    }
    /// One pass of the C's pairwise accumulate: `nrg += (unsigned)(x[i]^2 + x[i+1]^2) >> shift`.
    fn accumulate(x: &[i16], seed: i32, shift: i32) -> i32 {
        let mut energy = seed;
        let mut index = 0usize;
        while index + 1 < x.len() {
            let pair = smlabb(
                smulbb(i32::from(x[index]), i32::from(x[index])),
                i32::from(x[index + 1]),
                i32::from(x[index + 1]),
            );
            energy = energy.wrapping_add(((pair as u32) >> shift) as i32);
            index += 2;
        }
        if index < x.len() {
            let single = smulbb(i32::from(x[index]), i32::from(x[index]));
            energy = energy.wrapping_add(((single as u32) >> shift) as i32);
        }
        energy
    }

    let mut shift = 31 - (len.leading_zeros() as i32);
    // "Let's be conservative with rounding and start with nrg=len."
    let energy = accumulate(x, len, shift);
    // "Make sure the result will fit in a 32-bit signed integer with two bits of headroom."
    // `energy` is non-negative, so its leading-zero count is at least 1 and the second shift can
    // exceed the first by at most 2. SILK only ever calls this with at most `MAX_FRAME_LENGTH`
    // samples, where the first shift is at most 8, so the clamp is unreachable — it is there so a
    // caller cannot turn an over-long slice into a shift-overflow panic.
    shift = (shift + 3 - (energy.leading_zeros() as i32)).clamp(0, 31);
    (accumulate(x, 0, shift), shift)
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
    fn log2lin_guard_rails() {
        assert_eq!(log2lin(-1), 0);
        assert_eq!(log2lin(-100_000), 0);
        assert_eq!(log2lin(3967), i32::MAX);
        assert_eq!(log2lin(i32::MAX), i32::MAX);
    }

    /// Exact powers of two: `f = 0` makes the correction 0, so the result is exactly `1 << i`.
    #[test]
    fn log2lin_is_exact_at_powers_of_two() {
        for i in 0..31i32 {
            assert_eq!(log2lin(i << 7), 1i32 << i, "2^{i}");
        }
    }

    /// RFC 6716 §4.2.7.4's own worked bounds: the SILK gain path spans exactly 81920..=1686110208 in
    /// Q16 (scale factors 1.25 to 25728). Both endpoints have to come out on the nose — they are the
    /// tightest published check on `log2lin`, `smulwb` and the gain offset all at once.
    #[test]
    fn log2lin_hits_the_rfc_gain_bounds() {
        // log_gain = 0  -> inLog_Q7 = smulwb(1907825, 0)  + 2090 = 2090.
        assert_eq!(log2lin(2090), 81_920);
        // log_gain = 63 -> inLog_Q7 = smulwb(1907825, 63) + 2090 = 3923.
        assert_eq!(smulwb(1_907_825, 63) + 2090, 3923);
        assert_eq!(log2lin(3923), 1_686_110_208);
    }

    /// The RFC prints only the `inLog_Q7 >= 2048` formula. Reproduce it independently and require the
    /// implementation to agree across that whole range — which is the entire gain path.
    #[test]
    fn log2lin_matches_the_rfc_formula_above_2048() {
        for in_log_q7 in 2048..3967i32 {
            let i = in_log_q7 >> 7;
            let f = in_log_q7 & 127;
            let expected = (1i32 << i) + (((-174 * f * (128 - f)) >> 16) + f) * ((1i32 << i) >> 7);
            assert_eq!(log2lin(in_log_q7), expected, "inLog_Q7 = {in_log_q7}");
        }
    }

    /// Monotonic over the whole legal domain: a larger log-gain must never decode to a smaller linear
    /// gain, or the gain ladder would fold back on itself.
    #[test]
    fn log2lin_is_monotonic() {
        let mut previous = log2lin(0);
        for in_log_q7 in 1..3967i32 {
            let current = log2lin(in_log_q7);
            assert!(
                current >= previous,
                "log2lin({in_log_q7}) = {current} < {previous}"
            );
            previous = current;
        }
    }

    #[test]
    fn limit_int_clamps() {
        assert_eq!(limit_int(-5, 0, 63), 0);
        assert_eq!(limit_int(70, 0, 63), 63);
        assert_eq!(limit_int(31, 0, 63), 31);
        assert_eq!(limit_int(0, 0, 0), 0);
    }

    #[test]
    fn smulww_shifts_the_full_product() {
        assert_eq!(smulww(65536, 65536), 65536);
        assert_eq!(smulww(1, 1), 0, "floors");
        assert_eq!(smulww(-1, 1), -1, "floor(-1/65536) = -1");
        // Neither operand is narrowed, unlike smulwb: 0x1_0001 stays 65537 here.
        assert_eq!(smulww(65536, 0x1_0001), 0x1_0001);
        assert_eq!(smulwb(65536, 0x1_0001), 1);
        // The bwexpander chirp update: chirp_Q16 * ar in Q16.
        assert_eq!(smulww(65_470, 1 << 20), 1_047_520);
    }

    #[test]
    fn smmul_is_the_signed_high_word() {
        assert_eq!(smmul(1 << 16, 1 << 16), 1);
        assert_eq!(smmul(i32::MAX, i32::MAX), 1_073_741_823);
        assert_eq!(smmul(1, 1), 0);
        assert_eq!(smmul(-(1 << 16), 1 << 16), -1);
    }

    /// The C rounds ties **up**, not away from zero: `-3 >> 1` with rounding is -1, not -2.
    #[test]
    fn rshift_round_rounds_ties_upward() {
        assert_eq!(rshift_round(4, 1), 2);
        assert_eq!(rshift_round(3, 1), 2);
        assert_eq!(rshift_round(-3, 1), -1, "ties round towards +infinity");
        assert_eq!(rshift_round(-4, 1), -2);
        assert_eq!(rshift_round(5, 2), 1);
        assert_eq!(rshift_round(6, 2), 2, "6/4 = 1.5 rounds to 2");
        assert_eq!(rshift_round(-6, 2), -1, "-1.5 rounds to -1, not -2");
        assert_eq!(rshift_round(0, 5), 0);
    }

    /// The 64-bit form must agree with the 32-bit one everywhere the 32-bit one is defined.
    #[test]
    fn rshift_round64_matches_the_32_bit_form() {
        for value in [
            -1000i32,
            -7,
            -4,
            -3,
            -1,
            0,
            1,
            3,
            4,
            7,
            1000,
            i32::MAX,
            i32::MIN,
        ] {
            for shift in 1..=16u32 {
                assert_eq!(
                    i64::from(rshift_round(value, shift)),
                    rshift_round64(i64::from(value), shift),
                    "value {value}, shift {shift}"
                );
            }
        }
    }

    #[test]
    fn saturation_helpers_clamp_at_the_int16_bounds() {
        assert_eq!(sat16(32_767), 32_767);
        assert_eq!(sat16(32_768), 32_767);
        assert_eq!(sat16(-32_768), -32_768);
        assert_eq!(sat16(-32_769), -32_768);
        assert_eq!(sat16(i32::MAX), 32_767);
        assert_eq!(
            add_sat16(32_000, 1_000),
            32_767,
            "adds in 32 bits, then saturates"
        );
        assert_eq!(add_sat16(-32_000, -1_000), -32_768);
        assert_eq!(add_sat16(100, 200), 300);
    }

    /// `silk_LSHIFT_SAT32` clamps *before* shifting, which is not the same as shifting then
    /// saturating — the difference is exactly what stops the shift from overflowing.
    #[test]
    fn lshift_sat32_clamps_before_shifting() {
        assert_eq!(lshift_sat32(1, 4), 16);
        assert_eq!(lshift_sat32(i32::MAX, 1), (i32::MAX >> 1) << 1);
        assert_eq!(lshift_sat32(i32::MIN, 1), (i32::MIN >> 1) << 1);
        assert_eq!(lshift_sat32(-3, 2), -12);
        assert_eq!(lshift_sat32(7, 0), 7);
    }

    /// `silk_INVERSE32_varQ` against exact division. libopus documents ~14 bits refined to ~30, so
    /// require a relative error well inside 2^-20 over the domain the LPC stability check uses
    /// (`rc_mult1_Q30` in (2^15, 2^30]).
    #[test]
    fn inverse32_var_q_approximates_the_reciprocal() {
        for denominator in [
            1i32 << 16,
            (1 << 20) + 12_345,
            1 << 25,
            (1 << 29) + 7,
            1 << 30,
        ] {
            for q_result in [40i32, 45, 50, 55] {
                let approximation = f64::from(inverse32_var_q(denominator, q_result));
                let exact = 2f64.powi(q_result) / f64::from(denominator);
                if exact > f64::from(i32::MAX) {
                    continue; // Saturates; the exact value is not representable.
                }
                assert!(
                    (approximation - exact).abs() <= exact / 1_000_000.0 + 1.0,
                    "1/{denominator} in Q{q_result}: {approximation} vs {exact}"
                );
            }
        }
    }

    #[test]
    fn inverse32_var_q_guard_rails() {
        assert_eq!(inverse32_var_q(0, 30), 0, "no divide by zero");
        // 61 - head_room - Qres >= 32 means the result would underflow to nothing.
        assert_eq!(inverse32_var_q(1 << 30, 1), 0);
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
            let _ = log2lin(a);
            let _ = smultt(a, b);
            let _ = sqrt_approx(a);
            let _ = add_lshift32(a, b, 3);
            let _ = sub_lshift32(a, b, 3);
        }

        /// `silk_DIV32_varQ` claims "a good approximation"; over the domain the decoder actually
        /// uses — a ratio of two subframe gains, in Q16 — it must be within a few LSBs of the exact
        /// quotient. This is what keeps the gain adjustment from drifting the filter state.
        #[test]
        fn div32_var_q_approximates_the_real_quotient(
            numerator in 81_920i32..1_686_110_208,
            denominator in 81_920i32..1_686_110_208,
        ) {
            let exact = ((i64::from(numerator) << 16) / i64::from(denominator)) as f64;
            let approximate = f64::from(div32_var_q(numerator, denominator, 16));
            // A 30-bit-precision reciprocal followed by one refinement: the relative error is well
            // under 2^-24, and the absolute error never matters below one LSB.
            prop_assert!(
                (approximate - exact).abs() <= 1.0 + exact * 1e-6,
                "div32_var_q({numerator}, {denominator}, 16) = {approximate}, exact {exact}"
            );
        }

        /// `silk_SQRT_APPROX` is documented as accurate to ±10 % above 15 and ±2.5 % above 120.
        #[test]
        fn sqrt_approx_holds_its_documented_accuracy(x in 1i32..=i32::MAX) {
            let exact = f64::from(x).sqrt();
            let approximate = f64::from(sqrt_approx(x));
            if approximate > 120.0 {
                prop_assert!((approximate - exact).abs() <= 0.025 * exact + 1.0);
            } else if approximate > 15.0 {
                prop_assert!((approximate - exact).abs() <= 0.10 * exact + 1.0);
            }
        }

        /// The energy `sum_sqr_shift` reports, scaled back by its shift, must be the real sum of
        /// squares to within the rounding the shift itself introduces.
        #[test]
        fn sum_sqr_shift_reconstructs_the_energy(
            samples in proptest::collection::vec(i16::MIN..=i16::MAX, 1..=320),
        ) {
            let (energy, shift) = sum_sqr_shift(&samples);
            prop_assert!(energy >= 0, "energy must be non-negative");
            prop_assert!((0..=31).contains(&shift));
            let exact: i64 = samples.iter().map(|&x| i64::from(x) * i64::from(x)).sum();
            let reported = i64::from(energy) << shift;
            // Every pair is truncated once by the shift, so the deficit is bounded by the number of
            // accumulation steps times the shift's granularity.
            let slack = ((samples.len() as i64 / 2) + 1) << shift;
            prop_assert!(
                reported <= exact + slack && reported + slack >= exact,
                "sum_sqr_shift = {reported} (energy {energy} << {shift}), exact {exact}"
            );
        }
    }

    /// Q16 identities that pin the scaling: 1.0/x, x/x, and x/1.0.
    #[test]
    fn div32_var_q_known_values() {
        // Not exactly 65536: the reciprocal is a 14-bit estimate plus one Newton step, so the
        // identity lands one LSB low. That inexactness is the specified behaviour — reproducing it
        // is the point, since the decoder feeds the result straight into its filter state.
        assert_eq!(div32_var_q(1 << 16, 1 << 16, 16), 65_535, "x / x ~ 1.0");
        // 1.0 / 2.0 = 0.5 in Q16, to within the approximation's precision.
        let half = div32_var_q(1 << 16, 2 << 16, 16);
        assert!((half - (1 << 15)).abs() <= 1, "got {half}");
        // A zero denominator cannot happen on the decode path; it must not panic or divide by zero.
        assert_eq!(div32_var_q(12345, 0, 16), 0);
    }

    #[test]
    fn sqrt_approx_known_values() {
        assert_eq!(sqrt_approx(0), 0);
        assert_eq!(sqrt_approx(-1), 0);
        assert_eq!(sqrt_approx(1), 1);
        // Exact powers of four are where the approximation is at its best.
        for root in [16i32, 64, 256, 1024, 4096, 16384] {
            let approximate = sqrt_approx(root * root);
            assert!(
                (approximate - root).abs() <= root / 40 + 1,
                "sqrt_approx({}) = {approximate}, want ~{root}",
                root * root
            );
        }
    }

    #[test]
    fn smultt_multiplies_the_high_halves() {
        assert_eq!(smultt(1 << 16, 1 << 16), 1);
        assert_eq!(smultt(3 << 16, 5 << 16), 15);
        // The low halves are discarded, not rounded.
        assert_eq!(smultt(0x0001_FFFF, 0x0001_FFFF), 1);
        assert_eq!(smultt(-1 << 16, 1 << 16), -1);
    }

    #[test]
    fn shift_helpers_wrap_like_the_c_macros() {
        assert_eq!(add_lshift32(10, 3, 2), 22);
        assert_eq!(sub_lshift32(10, 3, 2), -2);
        // `silk_LSHIFT` is a plain shift: overflow wraps rather than saturating.
        assert_eq!(add_lshift32(0, i32::MAX, 1), -2);
    }

    /// All-zero input, and a single known vector computed by hand.
    #[test]
    fn sum_sqr_shift_known_values() {
        let (energy, shift) = sum_sqr_shift(&[0i16; 16]);
        assert_eq!((energy, shift), (0, 0));
        // Four samples of 100: 4 * 10_000 = 40_000, small enough that no shift is needed.
        let (energy, shift) = sum_sqr_shift(&[100i16; 4]);
        assert_eq!(shift, 0);
        assert_eq!(energy, 40_000);
        // Full-scale samples force a shift so the sum still fits with two bits of head room.
        let (energy, shift) = sum_sqr_shift(&[i16::MIN; 320]);
        assert!(shift > 0, "full-scale energy must be shifted down");
        assert!(energy >= 0);
        assert_eq!(i64::from(energy) << shift, 320 * (1i64 << 30));
    }

    #[test]
    fn sum_sqr_shift_of_an_empty_slice_is_zero() {
        assert_eq!(sum_sqr_shift(&[]), (0, 0));
    }

    /// Known answers taken from libopus itself (`silk/Inlines.h`, `silk/sum_sqr_shift.c`, built and
    /// run over these exact inputs). These are approximations whose *error* is part of the decoded
    /// signal, so "close enough" is not a passing grade — every value below is bit-exact.
    #[test]
    fn div32_var_q_matches_libopus() {
        for (numerator, denominator, q_result, expected) in [
            (65_536i32, 65_536i32, 16i32, 65_535i32),
            (65_536, 131_072, 16, 32_767),
            (81_920, 1_686_110_208, 16, 3),
            (1_686_110_208, 81_920, 16, 1_348_888_166),
            (100_000, 3, 16, 2_147_483_644),
            (-100_000, 7, 16, -936_228_572),
            (123_456_789, 987_654, 16, 8_192_002),
            (1, 1_686_110_208, 16, 0),
        ] {
            assert_eq!(
                div32_var_q(numerator, denominator, q_result),
                expected,
                "DIV32_varQ({numerator}, {denominator}, {q_result})"
            );
        }
    }

    #[test]
    fn sqrt_approx_matches_libopus() {
        for (input, expected) in [
            (0i32, 0i32),
            (1, 1),
            (2, 1),
            (3, 1),
            (15, 2),
            (16, 4),
            (100, 9),
            (255, 15),
            (256, 16),
            (1_000, 30),
            (65_535, 254),
            (65_536, 256),
            (1_000_000, 994),
            (16_777_216, 4_096),
            (1_073_741_824, 32_768),
            (2_147_483_647, 46_293),
            (12_345_678, 3_451),
        ] {
            assert_eq!(sqrt_approx(input), expected, "SQRT_APPROX({input})");
        }
    }

    #[test]
    fn inverse32_var_q_matches_libopus_at_the_gain_scaling_q() {
        // Q47 is what `silk_decode_core` asks for when it inverts a subframe gain.
        for (input, expected) in [
            (65_536i32, 2_147_483_646i32),
            (81_920, 1_717_986_918),
            (1_686_110_208, 83_468),
            (1_000, 2_147_483_520),
            (7, 2_147_467_264),
        ] {
            assert_eq!(
                inverse32_var_q(input, 47),
                expected,
                "INVERSE32_varQ({input})"
            );
        }
    }

    #[test]
    fn sum_sqr_shift_matches_libopus() {
        // The same deterministic LCG vector the C probe used.
        let mut seed: u32 = 12_345;
        let samples: Vec<i16> = (0..320)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (seed >> 16) as i16
            })
            .collect();
        for (length, energy, shift) in [
            (1usize, 127_690_000i32, 0i32),
            (2, 323_309_200, 1),
            (4, 386_149_102, 1),
            (8, 469_159_388, 2),
            (16, 380_730_900, 4),
            (32, 390_917_774, 5),
            (64, 388_155_464, 6),
            (128, 373_117_878, 7),
            (256, 364_014_984, 8),
        ] {
            assert_eq!(
                sum_sqr_shift(&samples[..length]),
                (energy, shift),
                "sum_sqr_shift over {length} samples"
            );
        }
        assert_eq!(sum_sqr_shift(&[i16::MIN; 320]), (335_544_320, 10));
    }
}
