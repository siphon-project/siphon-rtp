//! Stereo prediction weights (RFC 6716 §4.2.7.1) and the mid-only flag (§4.2.7.2) — libopus
//! `silk/stereo_decode_pred.c`.
//!
//! A stereo SILK frame is coded as mid/side with *prediction*: the side channel is predicted from the
//! mid channel (and from a one-sample-delayed mid) with two weights, so plain mid/side coupling is the
//! special case where both weights are zero. Weights are coded on the **mid** channel's frame only,
//! and only for a stereo Opus frame; §4.2.8 then interpolates linearly from the previous frame's
//! weights over the first 8 ms, which is why [`super::decoder::StereoState::pred_prev_q13`] has to
//! survive across frames.
//!
//! The mid-only flag follows the weights and says the side channel has no frame at all for this
//! interval. It is present **only** when the side channel would otherwise be silent anyway — a
//! regular frame whose side VAD flag is clear, or an LBRR frame whose side LBRR flag is clear
//! (§4.2.7.2). When the side channel is active the flag is redundant and omitted, and reading it
//! anyway costs one symbol and desynchronises everything after it.

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::fixed::{smlabb, smulwb};
use crate::opus::silk::tables::{
    STEREO_ONLY_CODE_MID_ICDF, STEREO_PRED_JOINT_ICDF, STEREO_PRED_QUANT_Q13, UNIFORM3_ICDF,
    UNIFORM5_ICDF,
};
/// `ftb` for every SILK ICDF symbol: total frequency 256.
const ICDF_FTB: u32 = 8;

/// Interpolation step scale — `SILK_FIX_CONST(0.5 / STEREO_QUANT_SUB_STEPS, 16)`
/// (`stereo_decode_pred.c:57`), i.e. 0.1 in Q16. RFC 6716 §4.2.7.1 spells the same constant as the
/// literal 6554.
const STEREO_STEP_SCALE_Q16: i32 = 6554;

/// The two decoded stereo prediction weights in Q13 (libopus `MS_pred_Q13[2]`, `dec_API.c:152`).
///
/// Note the asymmetry the C bakes in and RFC 6716 §4.2.7.1 states explicitly: `w0_Q13` is stored with
/// `w1_Q13` **already subtracted**, because that is the form stereo unmixing wants. So a caller
/// reconstructing the two "raw" table weights has to add them back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StereoWeights {
    /// `pred_Q13[0]` — the first prediction weight, minus the second.
    pub w0_q13: i32,
    /// `pred_Q13[1]` — the second prediction weight.
    pub w1_q13: i32,
}

/// Decode the pair of stereo prediction weights (RFC 6716 §4.2.7.1; libopus
/// `silk_stereo_decode_pred`, `stereo_decode_pred.c:35-63`).
///
/// Five symbols in this exact order: one joint stage-1 index, then (stage-2, stage-3) for weight 0,
/// then (stage-2, stage-3) for weight 1. The stage-1 index supplies the *high* part of both table
/// indices at once — `n / 5` for the first weight and `n % 5` for the second — which is why a single
/// 25-entry PDF covers both.
pub fn decode_stereo_weights(decoder: &mut RangeDecoder<'_>) -> StereoWeights {
    // Stage 1: one symbol carrying the coarse index of both weights.
    let joint = decoder.dec_icdf(&STEREO_PRED_JOINT_ICDF, ICDF_FTB) as i32;
    let coarse = [joint / 5, joint % 5];

    // Stages 2 and 3, weight 0 first then weight 1 (stereo_decode_pred.c:47-50).
    let mut fine = [0i32; 2];
    let mut sub_step = [0i32; 2];
    for index in 0..2 {
        fine[index] = decoder.dec_icdf(&UNIFORM3_ICDF, ICDF_FTB) as i32;
        sub_step[index] = decoder.dec_icdf(&UNIFORM5_ICDF, ICDF_FTB) as i32;
    }

    // Dequantize: pick the codebook entry, then step `2*i + 1` half-sub-steps toward the next one.
    let mut weights = [0i32; 2];
    for index in 0..2 {
        // `wi = i0 + 3*(n/5)` / `i2 + 3*(n%5)`, in 0..=14 (RFC 6716 §4.2.7.1).
        let table_index = (fine[index] + 3 * coarse[index]) as usize;
        // 3 * 4 + 3 * 4 = 24 is impossible: `fine` is 0..=2 and `coarse` is 0..=4, so `table_index`
        // is at most 2 + 12 = 14 and `table_index + 1` at most 15 — the last codebook entry, which
        // exists solely so this interpolation is always in bounds.
        let low_q13 = i32::from(STEREO_PRED_QUANT_Q13[table_index]);
        let next_q13 = i32::from(STEREO_PRED_QUANT_Q13[table_index + 1]);
        let step_q13 = smulwb(next_q13 - low_q13, STEREO_STEP_SCALE_Q16);
        weights[index] = smlabb(low_q13, step_q13, 2 * sub_step[index] + 1);
    }

    // "Subtract second from first predictor (helps when actually applying these)"
    // (stereo_decode_pred.c:61-62). RFC 6716 §4.2.7.1 folds the same subtraction into w0_Q13.
    StereoWeights {
        w0_q13: weights[0] - weights[1],
        w1_q13: weights[1],
    }
}

/// Decode the mid-only flag (RFC 6716 §4.2.7.2; libopus `silk_stereo_decode_mid_only`,
/// `stereo_decode_pred.c:66-73`). `true` means no side-channel frame follows for this interval.
///
/// The caller decides whether this symbol is present at all — see [`mid_only_flag_is_coded`].
pub fn decode_mid_only(decoder: &mut RangeDecoder<'_>) -> bool {
    decoder.dec_icdf(&STEREO_ONLY_CODE_MID_ICDF, ICDF_FTB) == 1
}

/// Whether a mid-only flag is present for this SILK frame (RFC 6716 §4.2.7.2; libopus
/// `dec_API.c:262-264` for LBRR and `dec_API.c:288-294` for regular frames).
///
/// It is coded exactly when the corresponding side-channel frame is *not* going to be coded for its
/// own reasons: for a regular frame, the side VAD flag is clear; for an LBRR frame, the side LBRR flag
/// is clear. When the side channel is active the flag would be redundant, so it is omitted — and when
/// it is omitted, mid-only is implicitly false.
#[must_use]
pub fn mid_only_flag_is_coded(side_channel_coded: bool) -> bool {
    !side_channel_coded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;
    use crate::opus::silk::types::STEREO_QUANT_SUB_STEPS;

    /// The stage-3 PDF has exactly `STEREO_QUANT_SUB_STEPS` symbols — that is what makes
    /// `SILK_FIX_CONST(0.5 / STEREO_QUANT_SUB_STEPS, 16)` the right step scale.
    #[test]
    fn stage_three_covers_every_sub_step() {
        assert_eq!(UNIFORM5_ICDF.len(), STEREO_QUANT_SUB_STEPS as usize);
    }

    /// Encode the five stereo weight symbols the way libopus' `silk_stereo_encode_pred` does, so the
    /// decoder is driven with a legal stream.
    fn encode_weights(joint: usize, fine: [usize; 2], sub_step: [usize; 2], buffer: &mut [u8]) {
        let mut encoder = RangeEncoder::new(buffer);
        encoder.enc_icdf(joint, &STEREO_PRED_JOINT_ICDF, ICDF_FTB);
        for index in 0..2 {
            encoder.enc_icdf(fine[index], &UNIFORM3_ICDF, ICDF_FTB);
            encoder.enc_icdf(sub_step[index], &UNIFORM5_ICDF, ICDF_FTB);
        }
        encoder.done();
        assert!(!encoder.error());
    }

    /// The RFC's own formula, written out independently of the implementation:
    /// `w = w_Q13[wi] + (((w_Q13[wi+1] - w_Q13[wi]) * 6554) >> 16) * (2*i + 1)`.
    fn reference_weight(table_index: usize, sub_step: i32) -> i32 {
        let low = i32::from(STEREO_PRED_QUANT_Q13[table_index]);
        let next = i32::from(STEREO_PRED_QUANT_Q13[table_index + 1]);
        low + (((next - low) * 6554) >> 16) * (2 * sub_step + 1)
    }

    #[test]
    fn zero_weights_are_reachable_and_mean_plain_mid_side() {
        // Table entries 7 and 8 straddle zero (-820, 820); the RFC says "zeros indicate normal
        // mid-side coupling", so a near-zero weight pair must be codeable. joint = 12 puts both
        // coarse indices at 2 (12/5 = 2, 12%5 = 2), and fine = 1 gives table index 1 + 6 = 7.
        let mut buffer = [0u8; 64];
        encode_weights(12, [1, 1], [4, 4], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let weights = decode_stereo_weights(&mut decoder);
        // Entry 7 = -820, step = ((820 - -820) * 6554) >> 16 = 164, 9 steps -> -820 + 1476 = 656.
        assert_eq!(weights.w1_q13, reference_weight(7, 4));
        assert_eq!(weights.w0_q13, 0, "identical indices cancel in w0 - w1");
    }

    /// Every legal symbol combination must match the RFC formula exactly, including the `w0 -= w1`
    /// fold. 25 * 3 * 5 * 3 * 5 = 5625 combinations, so this is exhaustive over the whole parameter
    /// space rather than a spot check.
    #[test]
    fn all_symbol_combinations_match_the_rfc_formula() {
        let mut buffer = [0u8; 64];
        for joint in 0..25usize {
            for fine0 in 0..3usize {
                for sub0 in 0..5usize {
                    for fine1 in 0..3usize {
                        for sub1 in 0..5usize {
                            buffer.fill(0);
                            encode_weights(joint, [fine0, fine1], [sub0, sub1], &mut buffer);
                            let mut decoder = RangeDecoder::new(&buffer);
                            let weights = decode_stereo_weights(&mut decoder);

                            let wi0 = fine0 + 3 * (joint / 5);
                            let wi1 = fine1 + 3 * (joint % 5);
                            assert!(wi0 <= 14 && wi1 <= 14, "index range (RFC 6716 §4.2.7.1)");
                            let expected_w1 = reference_weight(wi1, sub1 as i32);
                            let expected_w0 = reference_weight(wi0, sub0 as i32) - expected_w1;
                            assert_eq!(
                                (weights.w0_q13, weights.w1_q13),
                                (expected_w0, expected_w1),
                                "joint={joint} fine={fine0},{fine1} sub={sub0},{sub1}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The step scale really is 0.1 in Q16 and `smulwb` floors it, so a rounding implementation would
    /// drift. Widest codebook gap is 3682 (entries 0→1 and 14→15).
    #[test]
    fn interpolation_step_is_a_floored_tenth() {
        assert_eq!(STEREO_STEP_SCALE_Q16, 6554);
        let widest = i32::from(STEREO_PRED_QUANT_Q13[1]) - i32::from(STEREO_PRED_QUANT_Q13[0]);
        assert_eq!(widest, 3682);
        assert_eq!(smulwb(widest, STEREO_STEP_SCALE_Q16), 368);
        // 3682 * 0.1 = 368.2, so the floor drops the .2 — five sub-steps stay inside the gap.
        assert!(368 * 9 < widest * 2);
    }

    /// The decoded weights stay inside the range Q13 and the C's `opus_int16 pred_prev_Q13` can hold,
    /// checked over the whole symbol space (the widest possible `w0 - w1` spread).
    #[test]
    fn weights_fit_the_int16_storage_the_c_uses() {
        let mut extreme_low = i32::MAX;
        let mut extreme_high = i32::MIN;
        for table_index in 0..15usize {
            for sub_step in 0..5i32 {
                let weight = reference_weight(table_index, sub_step);
                extreme_low = extreme_low.min(weight);
                extreme_high = extreme_high.max(weight);
            }
        }
        // w1 on its own, and the widest possible w0 - w1.
        for value in [
            extreme_low,
            extreme_high,
            extreme_high - extreme_low,
            extreme_low - extreme_high,
        ] {
            assert!(
                i32::from(i16::MIN) <= value && value <= i32::from(i16::MAX),
                "{value} must fit stereo_dec_state.pred_prev_Q13 (opus_int16)"
            );
        }
    }

    #[test]
    fn mid_only_flag_decodes_both_symbols() {
        for (symbol, expected) in [(0usize, false), (1, true)] {
            let mut buffer = [0u8; 32];
            let mut encoder = RangeEncoder::new(&mut buffer);
            encoder.enc_icdf(symbol, &STEREO_ONLY_CODE_MID_ICDF, ICDF_FTB);
            encoder.done();
            let mut decoder = RangeDecoder::new(&buffer);
            assert_eq!(decode_mid_only(&mut decoder), expected, "symbol {symbol}");
        }
    }

    #[test]
    fn mid_only_flag_presence_rule() {
        // Side channel not coded (VAD or LBRR flag clear): the flag is present.
        assert!(mid_only_flag_is_coded(false));
        // Side channel coded: redundant, so omitted.
        assert!(!mid_only_flag_is_coded(true));
    }

    /// Weights then the mid-only flag, in that order (RFC 6716 Table 5) — a swap would misread both.
    #[test]
    fn weights_precede_the_mid_only_flag() {
        let mut buffer = [0u8; 64];
        {
            let mut encoder = RangeEncoder::new(&mut buffer);
            encoder.enc_icdf(20, &STEREO_PRED_JOINT_ICDF, ICDF_FTB);
            for _ in 0..2 {
                encoder.enc_icdf(2, &UNIFORM3_ICDF, ICDF_FTB);
                encoder.enc_icdf(3, &UNIFORM5_ICDF, ICDF_FTB);
            }
            encoder.enc_icdf(1, &STEREO_ONLY_CODE_MID_ICDF, ICDF_FTB);
            encoder.done();
        }
        let mut decoder = RangeDecoder::new(&buffer);
        let weights = decode_stereo_weights(&mut decoder);
        // joint = 20 -> coarse (4, 0); fine 2 -> indices 14 and 2.
        let expected_w1 = reference_weight(2, 3);
        assert_eq!(weights.w1_q13, expected_w1);
        assert_eq!(weights.w0_q13, reference_weight(14, 3) - expected_w1);
        assert!(decode_mid_only(&mut decoder), "mid-only flag follows");
    }

    #[test]
    fn arbitrary_payloads_never_panic_or_index_out_of_bounds() {
        for seed in 0u32..4000 {
            let length = (seed % 7) as usize;
            let payload: Vec<u8> = (0..length)
                .map(|k| (seed.wrapping_mul(2_246_822_519).wrapping_add(k as u32) >> 9) as u8)
                .collect();
            let mut decoder = RangeDecoder::new(&payload);
            let weights = decode_stereo_weights(&mut decoder);
            // Whatever symbols came out, the result stays inside the codebook-derived range.
            assert!(weights.w1_q13.abs() <= 16_384);
            assert!(weights.w0_q13.abs() <= 32_768);
            let _ = decode_mid_only(&mut decoder);
        }
    }
}
