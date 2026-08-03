//! Fixed-point primitives the SILK **encoder** needs and the decoder does not
//! (libopus `silk/SigProc_FIX.h`, `silk/Inlines.h`, `silk/lin2log.c`).
//!
//! The decoder's [`crate::opus::silk::fixed`] carries every macro its own path uses; this module is
//! its encoder-side complement and deliberately does not duplicate any of them — `smulwb`,
//! `smulbb`, `smlabb`, `smulww`, `smmul`, `log2lin`, `rshift_round`, `sat16`, `limit_int` and
//! `lshift_sat32` are imported from there.
//!
//! Everything here wraps on 32-bit overflow exactly as the C's `opus_int32` arithmetic does. The
//! encoder feeds these from *analysis* results rather than from a bitstream, so the domains are
//! bounded by the signal rather than by an attacker — but the wrapping is still explicit, because a
//! debug build must not panic on an arithmetic overflow no matter what audio arrives.

use crate::opus::silk::fixed::{lshift_sat32, smlawb, smmul, smulwb};

/// `silk_MLA(a32, b32, c32)` — `a32 + b32 * c32` (`SigProc_FIX.h:433`), wrapping.
#[inline]
#[must_use]
pub fn mla(a32: i32, b32: i32, c32: i32) -> i32 {
    a32.wrapping_add(b32.wrapping_mul(c32))
}

/// `silk_SMLAWW(a32, b32, c32)` — `a32 + ((b32 * c32) >> 16)` (`macros.h:93`), i.e. the full
/// 64-bit product shifted down, accumulated. Unlike `silk_SMLAWB` neither operand is narrowed.
#[inline]
#[must_use]
pub fn smlaww(a32: i32, b32: i32, c32: i32) -> i32 {
    a32.wrapping_add(((i64::from(b32) * i64::from(c32)) >> 16) as i32)
}

/// `silk_SMULWT(a32, b32)` — `(a32 * (b32 >> 16)) >> 16` (`macros.h:56-61`).
///
/// The **top** half of `b32` is the multiplier, which is what lets the noise-shaping quantiser pack
/// the two low-frequency shaping coefficients into one `LF_shp_Q14` word: `silk_SMULWB` reads
/// `LF_MA_shp` out of the low half and this reads `LF_AR_shp` out of the high half
/// (`NSQ.c:255-256`).
#[inline]
#[must_use]
pub fn smulwt(a32: i32, b32: i32) -> i32 {
    ((i64::from(a32) * i64::from(b32 >> 16)) >> 16) as i32
}

/// `silk_SMLAWT(a32, b32, c32)` — `a32 + ((b32 * (c32 >> 16)) >> 16)` (`macros.h:63-68`), i.e.
/// [`smulwt`] accumulated.
#[inline]
#[must_use]
pub fn smlawt(a32: i32, b32: i32, c32: i32) -> i32 {
    a32.wrapping_add(smulwt(b32, c32))
}

/// `silk_ADD_POS_SAT32(a, b)` (`SigProc_FIX.h:499`) — add, returning `i32::MAX` whenever the sum's
/// sign bit comes out set.
///
/// The name says "POS", and the macro is written for non-negative operands: it detects overflow by
/// testing the sign bit of the *unsigned* sum. But `silk_quant_LTP_gains` calls it with a value
/// that is routinely **negative** — `rate_dist_Q7_subfr` is
/// `subfr_len * (lin2log(residual energy) - 15<<7)`, which goes below zero for any tap set whose
/// weighted residual energy is under 1.0, i.e. for every good one (`quant_LTP_gains.c:101`,
/// `VQ_WMat_EC.c:117`).
///
/// So this is *not* a saturating add in practice: a running rate-distortion total that dips below
/// zero collapses to `i32::MAX` and that codebook loses. That is libopus' actual behaviour and it
/// decides which LTP codebook a voiced frame uses, so it is reproduced literally — clamping the
/// operands non-negative "to be safe" changes the chosen codebook on roughly a quarter of voiced
/// frames.
#[inline]
#[must_use]
pub fn add_pos_sat32(a: i32, b: i32) -> i32 {
    if (a as u32).wrapping_add(b as u32) & 0x8000_0000 != 0 {
        i32::MAX
    } else {
        a.wrapping_add(b)
    }
}

/// `silk_CLZ32(in32)` (`macros.h`) — count leading zeros, 32 for an input of zero.
#[inline]
#[must_use]
pub fn clz32(value: i32) -> i32 {
    (value as u32).leading_zeros() as i32
}

/// `silk_ROR32(a32, rot)` (`SigProc_FIX.h:398-410`) — rotate right, with a negative `rot` meaning
/// rotate left. Written on `u32` because the C casts to unsigned before shifting.
#[inline]
#[must_use]
fn ror32(value: i32, rotate: i32) -> i32 {
    let bits = value as u32;
    if rotate == 0 {
        value
    } else if rotate < 0 {
        bits.rotate_left(rotate.unsigned_abs() % 32) as i32
    } else {
        bits.rotate_right(rotate as u32 % 32) as i32
    }
}

/// `silk_lin2log(inLin)` (`lin2log.c:35-45`) — an approximation of `128 * log2(inLin)`, the very
/// close inverse of [`crate::opus::silk::fixed::log2lin`].
///
/// Used all over the encoder's rate-distortion arithmetic: the gain quantiser's log ladder
/// (`gain_quant.c:51`), the NLSF first-stage bit cost (`NLSF_encode.c:108`), and the LTP codebook
/// search's "6 dB is one bit per sample" conversion (`VQ_WMat_EC.c:117`).
///
/// A zero or negative input has `lz == 32` and `frac_Q7 == 0`, which the C evaluates to
/// `(31 - 32) << 7 = -128`; that is reproduced rather than special-cased, because
/// `silk_lin2log(0)` really does appear (an all-silent subframe's residual energy).
#[inline]
#[must_use]
pub fn lin2log(in_lin: i32) -> i32 {
    let leading_zeros = clz32(in_lin);
    let frac_q7 = ror32(in_lin, 24 - leading_zeros) & 0x7F;
    // silk_ADD_LSHIFT32( silk_SMLAWB( frac_Q7, silk_MUL( frac_Q7, 128 - frac_Q7 ), 179 ), 31 - lz, 7 )
    smlawb(frac_q7, frac_q7.wrapping_mul(128 - frac_q7), 179)
        .wrapping_add((31 - leading_zeros).wrapping_shl(7))
}

/// `silk_DIV32_varQ(a32, b32, Qres)` (`Inlines.h:97-140`) — `(a32 << Qres) / b32` to about 30 bits
/// of precision, without a divide in the refinement step.
///
/// Returns 0 for `b32 == 0` rather than reproducing the C's `silk_assert`; the one call site
/// (`NLSF_encode.c:91`) divides by `W_tmp_Q9 * W_tmp_Q9`, and the codebook weights are all strictly
/// positive, so the guard is unreachable in practice and exists only so a future table edit cannot
/// panic.
#[must_use]
pub fn div32_var_q(a32: i32, b32: i32, q_result: i32) -> i32 {
    if b32 == 0 {
        return 0;
    }
    let a_head_room = clz32(a32.wrapping_abs()) - 1;
    let a32_normalized = ((a32 as u32) << a_head_room) as i32;
    let b_head_room = clz32(b32.wrapping_abs()) - 1;
    let b32_normalized = ((b32 as u32) << b_head_room) as i32;

    // Inverse of b32 with 14 bits of precision.
    let b32_inverse = (i32::MAX >> 2) / (b32_normalized >> 16);

    // First approximation, then one Newton refinement against the residual.
    let mut result = smulwb(a32_normalized, b32_inverse);
    let a32_normalized =
        (a32_normalized as u32).wrapping_sub((smmul(b32_normalized, result) as u32) << 3) as i32;
    result = smlawb(result, a32_normalized, b32_inverse);

    let left_shift = 29 + a_head_room - b_head_room - q_result;
    if left_shift < 0 {
        lshift_sat32(result, (-left_shift) as u32)
    } else if left_shift < 32 {
        result >> left_shift
    } else {
        // "Avoid undefined result" (Inlines.h:136-138).
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::fixed::log2lin;
    use proptest::prelude::*;

    #[test]
    fn mla_and_smlaww_accumulate() {
        assert_eq!(mla(10, 3, 4), 22);
        assert_eq!(mla(-10, 3, -4), -22);
        // Wraps rather than panicking in debug.
        assert_eq!(mla(0, i32::MAX, 2), i32::MAX.wrapping_mul(2));
        assert_eq!(smlaww(100, 65_536, 5), 105);
        // Neither operand is narrowed: 0x1_0001 stays 65537.
        assert_eq!(smlaww(0, 65_536, 0x1_0001), 0x1_0001);
    }

    #[test]
    fn add_pos_sat32_saturates_at_the_top() {
        assert_eq!(add_pos_sat32(1, 2), 3);
        assert_eq!(add_pos_sat32(i32::MAX, 1), i32::MAX);
        assert_eq!(add_pos_sat32(i32::MAX, i32::MAX), i32::MAX);
        assert_eq!(add_pos_sat32(0, 0), 0);
    }

    #[test]
    fn clz32_counts_leading_zeros_including_zero() {
        assert_eq!(clz32(0), 32);
        assert_eq!(clz32(1), 31);
        assert_eq!(clz32(i32::MAX), 1);
        assert_eq!(clz32(-1), 0);
    }

    #[test]
    fn ror32_rotates_in_both_directions() {
        assert_eq!(ror32(0x1234_5678, 0), 0x1234_5678);
        assert_eq!(ror32(1, 1) as u32, 0x8000_0000);
        assert_eq!(ror32(0x8000_0000u32 as i32, -1), 1);
        assert_eq!(ror32(0x0000_00FF, 4) as u32, 0xF000_000F);
    }

    /// `silk_lin2log` is documented as "a very close inverse of `silk_log2lin()`". Require the
    /// round trip to hold across the whole gain ladder (2090..=3923 in Q7, i.e. gain indices 0..=63
    /// — see the decoder's `log2lin_hits_the_rfc_gain_bounds`), which is the domain the gain
    /// quantiser actually uses.
    ///
    /// The bound is 3 Q7 units (0.023 dB), which is the measured worst case over that range: the
    /// two functions use *different* parabolic corrections (-174 going one way, +179 coming back),
    /// so they are close inverses, not exact ones. Outside the ladder the error grows to 127 at the
    /// very bottom, where `log2lin` takes its low branch; the gain path never goes there.
    #[test]
    fn lin2log_inverts_log2lin_across_the_gain_ladder() {
        let mut worst = 0i32;
        for in_log_q7 in 2090..3924i32 {
            let linear = log2lin(in_log_q7);
            let back = lin2log(linear);
            worst = worst.max((back - in_log_q7).abs());
            assert!(
                (back - in_log_q7).abs() <= 3,
                "inLog_Q7 {in_log_q7} -> {linear} -> {back}"
            );
        }
        assert_eq!(worst, 3, "the measured worst case must not drift silently");
    }

    /// Exact powers of two have a zero fractional part, so the approximation is exact there.
    #[test]
    fn lin2log_is_exact_at_powers_of_two() {
        for exponent in 0..31i32 {
            assert_eq!(lin2log(1 << exponent), exponent << 7, "2^{exponent}");
        }
    }

    /// The degenerate input the C does not guard: an all-silent subframe's energy.
    #[test]
    fn lin2log_of_zero_is_minus_128() {
        assert_eq!(lin2log(0), -128);
    }

    #[test]
    fn lin2log_is_monotonic() {
        let mut previous = lin2log(1);
        for value in 2..20_000i32 {
            let current = lin2log(value);
            assert!(
                current >= previous,
                "lin2log({value}) = {current} < {previous}"
            );
            previous = current;
        }
    }

    /// `silk_DIV32_varQ` against exact division over the domain `silk_NLSF_encode` uses: a Q2
    /// weight over the square of a Q9 codebook weight, asked for a Q21 result.
    #[test]
    fn div32_var_q_approximates_the_quotient() {
        for numerator in [1i32, 7, 255, 4096, 100_000] {
            for denominator in [1i32 << 10, (1 << 14) + 3, 1 << 18, 5_000_000] {
                for q_result in [10i32, 16, 21] {
                    let approximation = f64::from(div32_var_q(numerator, denominator, q_result));
                    let exact = f64::from(numerator) * 2f64.powi(q_result) / f64::from(denominator);
                    if exact > f64::from(i32::MAX) {
                        continue;
                    }
                    assert!(
                        (approximation - exact).abs() <= exact / 100_000.0 + 1.0,
                        "{numerator}/{denominator} in Q{q_result}: {approximation} vs {exact}"
                    );
                }
            }
        }
    }

    #[test]
    fn div32_var_q_guard_rails() {
        assert_eq!(div32_var_q(1, 0, 16), 0, "no divide by zero");
        // 29 + a_headrm - b_headrm - Qres >= 32 underflows to nothing.
        assert_eq!(div32_var_q(1, 1 << 30, 0), 0);
    }

    proptest! {
        /// Nothing here may panic, on any input, in a debug build.
        #[test]
        fn primitives_never_panic(a: i32, b: i32, c in 0i32..=30) {
            let _ = mla(a, b, a);
            let _ = smlaww(a, b, a);
            let _ = clz32(a);
            let _ = ror32(a, b % 64);
            let _ = lin2log(a);
            let _ = div32_var_q(a, b, c);
        }

        /// `lin2log` is non-decreasing over the whole positive range.
        #[test]
        fn lin2log_is_monotonic_over_all_positive_inputs(a in 1i32..=i32::MAX, b in 1i32..=i32::MAX) {
            let (low, high) = if a <= b { (a, b) } else { (b, a) };
            prop_assert!(lin2log(low) <= lin2log(high));
        }
    }
}
