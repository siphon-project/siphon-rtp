//! Stereo mid/side conversion and its coded predictors (libopus `silk/stereo_LR_to_MS.c`,
//! `silk/stereo_find_predictor.c`, `silk/stereo_quant_pred.c`, `silk/stereo_encode_pred.c`).
//!
//! SILK does not code left and right. It codes a **mid** channel and, when the stereo image is
//! worth the bits, a **side** channel that has already had a two-tap prediction from the mid
//! removed from it. What crosses the wire is the two predictor indices plus whatever is left of the
//! side signal — which for a nearly-mono input is almost nothing.
//!
//! # The three decisions this makes, and none of them is cosmetic
//!
//! 1. **The predictors.** Two least-squares gains, one from a low-passed mid to a low-passed side
//!    and one from the high-passed pair, each quantised on a 16-level table with 5 sub-steps
//!    (`stereo_quant_pred.c:35-73`). Splitting low from high is what lets a signal that is panned
//!    at low frequencies but decorrelated at high ones still predict well.
//! 2. **The mid/side rate split.** Mid gets `8 / (13 + 3 * frac)` of the packet, where `frac` is
//!    the residual-to-mid norm ratio — so a wide stereo image buys the side channel more bits, and
//!    a narrow one starves it. If that leaves mid below `2000 + 600 * fs_kHz` bps, the stereo
//!    *width* is reduced instead, because a starved mid sounds worse than a narrow image.
//! 3. **`mid_only`.** Below the width or rate floor the side channel is dropped entirely and the
//!    frame is coded as panned mono. The taper matters: the width is interpolated to zero over the
//!    first `STEREO_INTERP_LEN_MS` and the flag is held off until the tapered output has actually
//!    been transmitted (`stereo_LR_to_MS.c:180-192`), so the image collapses smoothly instead of
//!    clicking.
//!
//! # Where this sits
//!
//! Above the per-channel analysis and below the packet driver: [`left_right_to_mid_side`] rewrites
//! its two input buffers in place, and each resulting channel is then analysed, quantised and
//! written independently. The decoder's inverse is [`crate::opus::silk::stereo_unmix`], and the
//! **one-sample delay** both sides carry is the same one: the mid is filtered with a three-tap
//! window centred on `n + 1`, so the side output at index `n - 1` is what lines up.

use crate::opus::range_coder::RangeEncoder;
use crate::opus::silk::fixed::{
    div32_var_q, limit_int, rshift_round, sat16, smlabb, smlawb, smulbb, smulwb, sqrt_approx,
    sub_lshift32, sum_sqr_shift,
};
use crate::opus::silk::tables::{
    STEREO_ONLY_CODE_MID_ICDF, STEREO_PRED_JOINT_ICDF, STEREO_PRED_QUANT_Q13, UNIFORM3_ICDF,
    UNIFORM5_ICDF,
};
use crate::opus::silk::types::{MAX_FRAME_LENGTH, STEREO_QUANT_SUB_STEPS, STEREO_QUANT_TAB_SIZE};

/// `ftb` for every SILK ICDF symbol.
const ICDF_FTB: u32 = 8;

/// `STEREO_INTERP_LEN_MS` (`define.h:82`) — how long the width and predictors take to reach their
/// new values. Must be even.
const INTERP_LEN_MS: usize = 8;

/// `STEREO_RATIO_SMOOTH_COEF` (`define.h:83`) in Q16 — `SILK_FIX_CONST(0.01, 16)`.
const RATIO_SMOOTH_COEF_Q16: i32 = 655;
/// The same halved, for a 10 ms frame.
const RATIO_SMOOTH_COEF_HALF_Q16: i32 = 328;

/// `LA_SHAPE_MS` (`define.h:112`) — repeated here because the mid-only taper is measured in it.
const LA_SHAPE_MS: usize = 5;

/// The stereo encoder's cross-frame state (libopus `stereo_enc_state`, `structs.h:198-208`),
/// minus the per-packet index arrays the packet driver owns.
#[derive(Debug, Clone, Copy)]
pub struct StereoEncoderState {
    /// `pred_prev_Q13` — the previous frame's predictors, which this frame interpolates away from.
    pub previous_predictors_q13: [i16; 2],
    /// `sMid` / `sSide` — the two-sample overlap each filter needs before the frame.
    pub mid_history: [i16; 2],
    /// See [`StereoEncoderState::mid_history`].
    pub side_history: [i16; 2],
    /// `mid_side_amp_Q0` — the smoothed mid and residual norms, one pair per filter band.
    pub smoothed_norms: [i32; 4],
    /// `smth_width_Q14` — the smoothed stereo width.
    pub smoothed_width_q14: i16,
    /// `width_prev_Q14` — the width the previous frame ended on.
    pub previous_width_q14: i16,
    /// `silent_side_len` — how long the side channel has been tapered to silence, so the mid-only
    /// flag is not raised until the taper has actually been transmitted.
    pub silent_side_length: i16,
}

impl Default for StereoEncoderState {
    /// `silk_Encode`'s mono-to-stereo init (`enc_API.c:184-191`): everything cleared except the
    /// alternating norm seeds and a full-width smoother.
    fn default() -> Self {
        Self {
            previous_predictors_q13: [0; 2],
            mid_history: [0; 2],
            side_history: [0; 2],
            smoothed_norms: [0, 1, 0, 1],
            smoothed_width_q14: 1 << 14,
            previous_width_q14: 0,
            silent_side_length: 0,
        }
    }
}

/// The coded stereo side info for one SILK frame (libopus `predIx[frame][2][3]` plus
/// `mid_only_flags[frame]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StereoIndices {
    /// `ix[2][3]` — per predictor: the table index within its group, the sub-step, and the group.
    pub indices: [[i8; 3]; 2],
    /// `mid_only_flag` — the side channel is not coded at all.
    pub mid_only: bool,
}

/// What [`left_right_to_mid_side`] decided about the rate split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MidSideRates {
    /// `mid_side_rates_bps[0]`.
    pub mid_bps: i32,
    /// `mid_side_rates_bps[1]` — zero when the side channel is dropped.
    pub side_bps: i32,
}

/// `silk_stereo_quant_pred` (`stereo_quant_pred.c:35-73`) — quantise both predictors on the
/// 16-level table with 5 linear sub-steps between neighbours.
///
/// The search breaks out of the level loop as soon as the error starts increasing, which is why it
/// is exact rather than approximate: the levels are monotonic, so the first minimum is the global
/// one. The final subtraction (`pred[0] -= pred[1]`) is not a normalisation — the *decoder*
/// reconstructs the pair the same way, so it is part of the coded representation.
pub fn quantize_predictors(predictors_q13: &mut [i32; 2], indices: &mut [[i8; 3]; 2]) {
    for predictor in 0..2 {
        let mut smallest_error = i32::MAX;
        let mut quantized = 0i32;
        'levels: for level in 0..STEREO_QUANT_TAB_SIZE - 1 {
            let low_q13 = i32::from(STEREO_PRED_QUANT_Q13[level]);
            // SILK_FIX_CONST( 0.5 / STEREO_QUANT_SUB_STEPS, 16 ) = 6554.
            let step_q13 = smulwb(i32::from(STEREO_PRED_QUANT_Q13[level + 1]) - low_q13, 6554);
            for sub_step in 0..STEREO_QUANT_SUB_STEPS {
                let candidate = smlabb(low_q13, step_q13, 2 * sub_step + 1);
                let error = (predictors_q13[predictor] - candidate).abs();
                if error < smallest_error {
                    smallest_error = error;
                    quantized = candidate;
                    indices[predictor][0] = level as i8;
                    indices[predictor][1] = sub_step as i8;
                } else {
                    // The levels are monotonic, so the first minimum is the global one.
                    break 'levels;
                }
            }
        }
        indices[predictor][2] = indices[predictor][0] / 3;
        indices[predictor][0] -= indices[predictor][2] * 3;
        predictors_q13[predictor] = quantized;
    }

    // Code the first predictor relative to the second; the decoder undoes exactly this.
    predictors_q13[0] -= predictors_q13[1];
}

/// `silk_inner_prod_aligned_scale` (`inner_prod_aligned.c:34-48`) — the correlation, accumulated
/// with a per-term right shift so it cannot overflow whatever the input level is.
fn scaled_inner_product(first: &[i16], second: &[i16], scale: i32) -> i32 {
    let mut sum = 0i32;
    for (&a, &b) in first.iter().zip(second.iter()) {
        sum = sum.wrapping_add(smulbb(i32::from(a), i32::from(b)) >> scale);
    }
    sum
}

/// `silk_stereo_find_predictor` (`stereo_find_predictor.c:35-79`) — the least-squares gain from
/// `basis` to `target`, plus the smoothed residual-to-basis norm ratio the rate split reads.
///
/// `norms` is the two-entry smoothed-norm state for this filter band and is updated in place. The
/// smoothing coefficient is raised to `|pred^2|` whenever the prediction is strong, so a strongly
/// panned signal tracks quickly instead of lagging behind its own image.
fn find_predictor(
    basis: &[i16],
    target: &[i16],
    norms: &mut [i32],
    mut smooth_coef_q16: i32,
) -> (i32, i32) {
    let (mut basis_energy, basis_scale) = sum_sqr_shift(basis);
    let (mut target_energy, target_scale) = sum_sqr_shift(target);
    let mut scale = basis_scale.max(target_scale);
    scale += scale & 1; // make even, so the square root below halves it exactly
    target_energy >>= scale - target_scale;
    basis_energy >>= scale - basis_scale;
    basis_energy = basis_energy.max(1);

    let correlation = scaled_inner_product(basis, target, scale);
    let mut predictor_q13 = div32_var_q(correlation, basis_energy, 13);
    predictor_q13 = limit_int(predictor_q13, -(1 << 14), 1 << 14);
    let predictor_squared_q10 = smulwb(predictor_q13, predictor_q13);

    // Faster update for signals with large prediction parameters.
    smooth_coef_q16 = smooth_coef_q16.max(predictor_squared_q10.abs());

    let half_scale = (scale >> 1) as u32;
    norms[0] = smlawb(
        norms[0],
        (sqrt_approx(basis_energy) << half_scale) - norms[0],
        smooth_coef_q16,
    );
    // Residual energy = target - 2 * pred * corr + pred^2 * basis.
    target_energy = sub_lshift32(target_energy, smulwb(correlation, predictor_q13), 4);
    target_energy = target_energy.wrapping_add(smulwb(basis_energy, predictor_squared_q10) << 6);
    norms[1] = smlawb(
        norms[1],
        (sqrt_approx(target_energy) << half_scale) - norms[1],
        smooth_coef_q16,
    );

    let ratio_q14 = limit_int(div32_var_q(norms[1], norms[0].max(1), 14), 0, 32767);
    (predictor_q13, ratio_q14)
}

/// Convert one frame of left/right into mid/side in place (`silk_stereo_LR_to_MS`,
/// `stereo_LR_to_MS.c:36-229`).
///
/// `left` and `right` are `frame_length + 2` samples: the first two are the previous frame's
/// overlap (this function refreshes them from [`StereoEncoderState`] and saves the new ones), and
/// the frame proper starts at index 2. On return `left[..frame_length + 2]` holds the mid channel
/// and `right[1..frame_length + 1]` the prediction residual of the side channel — the same
/// one-sample offset the decoder's unmixer expects.
///
/// `to_mono` forces the width to collapse for one frame, which is what a stereo-to-mono transition
/// uses so the image tapers instead of cutting.
#[allow(clippy::too_many_arguments)]
pub fn left_right_to_mid_side(
    state: &mut StereoEncoderState,
    left: &mut [i16],
    right: &mut [i16],
    total_rate_bps: i32,
    previous_speech_activity_q8: i32,
    to_mono: bool,
    rate_khz: usize,
    frame_length: usize,
) -> (StereoIndices, MidSideRates) {
    debug_assert!(left.len() >= frame_length + 2 && right.len() >= frame_length + 2);
    let mut side = [0i16; MAX_FRAME_LENGTH + 2];

    // ── Basic mid/side, then re-seed the two-sample overlap from the previous frame ────────────
    for index in 0..frame_length + 2 {
        let sum = i32::from(left[index]) + i32::from(right[index]);
        let difference = i32::from(left[index]) - i32::from(right[index]);
        left[index] = rshift_round(sum, 1) as i16;
        side[index] = sat16(rshift_round(difference, 1));
    }
    left[..2].copy_from_slice(&state.mid_history);
    side[..2].copy_from_slice(&state.side_history);
    state
        .mid_history
        .copy_from_slice(&left[frame_length..frame_length + 2]);
    state
        .side_history
        .copy_from_slice(&side[frame_length..frame_length + 2]);

    // ── Split both channels into a low- and a high-passed half ─────────────────────────────────
    let mut low_mid = [0i16; MAX_FRAME_LENGTH];
    let mut high_mid = [0i16; MAX_FRAME_LENGTH];
    let mut low_side = [0i16; MAX_FRAME_LENGTH];
    let mut high_side = [0i16; MAX_FRAME_LENGTH];
    for index in 0..frame_length {
        let sum = rshift_round(
            i32::from(left[index]) + i32::from(left[index + 2]) + (i32::from(left[index + 1]) << 1),
            2,
        );
        low_mid[index] = sum as i16;
        high_mid[index] = left[index + 1].wrapping_sub(sum as i16);

        let sum = rshift_round(
            i32::from(side[index]) + i32::from(side[index + 2]) + (i32::from(side[index + 1]) << 1),
            2,
        );
        low_side[index] = sum as i16;
        high_side[index] = side[index + 1].wrapping_sub(sum as i16);
    }

    // ── Predictors, and the residual-to-mid ratio the rate split reads ─────────────────────────
    let is_ten_ms = frame_length == 10 * rate_khz;
    let base_smooth_q16 = if is_ten_ms {
        RATIO_SMOOTH_COEF_HALF_Q16
    } else {
        RATIO_SMOOTH_COEF_Q16
    };
    // Squaring the previous frame's activity means a silent stretch barely moves the smoother.
    let smooth_coef_q16 = smulwb(
        smulbb(previous_speech_activity_q8, previous_speech_activity_q8),
        base_smooth_q16,
    );

    let mut predictors_q13 = [0i32; 2];
    let (predictor, low_ratio_q14) = find_predictor(
        &low_mid[..frame_length],
        &low_side[..frame_length],
        &mut state.smoothed_norms[0..2],
        smooth_coef_q16,
    );
    predictors_q13[0] = predictor;
    let (predictor, high_ratio_q14) = find_predictor(
        &high_mid[..frame_length],
        &high_side[..frame_length],
        &mut state.smoothed_norms[2..4],
        smooth_coef_q16,
    );
    predictors_q13[1] = predictor;

    // The low band counts three times: it carries most of the perceptual stereo image.
    let fraction_q16 = smlabb(high_ratio_q14, low_ratio_q14, 3).min(1 << 16);

    // ── Rate split, and the width reduction that protects the mid ──────────────────────────────
    let mut total_rate_bps = total_rate_bps - if is_ten_ms { 1200 } else { 600 };
    total_rate_bps = total_rate_bps.max(1);
    let minimum_mid_bps = smlabb(2000, rate_khz as i32, 600);
    let fraction_times_three_q16 = 3 * fraction_q16;

    // mid_rate = ( 8 / ( 13 + 3 * frac ) ) * total_rate
    let mut mid_bps = div32_var_q(
        total_rate_bps,
        (13 << 16) + fraction_times_three_q16,
        16 + 3,
    );
    let mut side_bps;
    let mut width_q14;
    if mid_bps < minimum_mid_bps {
        mid_bps = minimum_mid_bps;
        side_bps = total_rate_bps - mid_bps;
        // width = 4 * ( 2 * side_rate - min_rate ) / ( ( 1 + 3 * frac ) * min_rate )
        width_q14 = div32_var_q(
            (side_bps << 1) - minimum_mid_bps,
            smulwb((1 << 16) + fraction_times_three_q16, minimum_mid_bps),
            14 + 2,
        );
        width_q14 = limit_int(width_q14, 0, 1 << 14);
    } else {
        side_bps = total_rate_bps - mid_bps;
        width_q14 = 1 << 14;
    }

    state.smoothed_width_q14 = smlawb(
        i32::from(state.smoothed_width_q14),
        width_q14 - i32::from(state.smoothed_width_q14),
        smooth_coef_q16,
    ) as i16;

    // ── The mid-only decision ──────────────────────────────────────────────────────────────────
    let mut indices = StereoIndices::default();
    let smoothed_width = i32::from(state.smoothed_width_q14);
    // SILK_FIX_CONST( 0.05, 14 ) = 819, SILK_FIX_CONST( 0.02, 14 ) = 328.
    let narrow_now =
        8 * total_rate_bps < 13 * minimum_mid_bps || smulwb(fraction_q16, smoothed_width) < 819;
    let narrow_still =
        8 * total_rate_bps < 11 * minimum_mid_bps || smulwb(fraction_q16, smoothed_width) < 328;

    if to_mono {
        // Last frame before a stereo-to-mono transition: collapse the width outright.
        width_q14 = 0;
        predictors_q13 = [0, 0];
        quantize_predictors(&mut predictors_q13, &mut indices.indices);
    } else if state.previous_width_q14 == 0 && narrow_now {
        // Already at zero width and still narrow: code as panned mono.
        predictors_q13[0] = smulbb(smoothed_width, predictors_q13[0]) >> 14;
        predictors_q13[1] = smulbb(smoothed_width, predictors_q13[1]) >> 14;
        quantize_predictors(&mut predictors_q13, &mut indices.indices);
        width_q14 = 0;
        predictors_q13 = [0, 0];
        mid_bps = total_rate_bps;
        side_bps = 0;
        indices.mid_only = true;
    } else if state.previous_width_q14 != 0 && narrow_still {
        // Transition to zero width: taper this frame, decide next frame.
        predictors_q13[0] = smulbb(smoothed_width, predictors_q13[0]) >> 14;
        predictors_q13[1] = smulbb(smoothed_width, predictors_q13[1]) >> 14;
        quantize_predictors(&mut predictors_q13, &mut indices.indices);
        width_q14 = 0;
        predictors_q13 = [0, 0];
    } else if smoothed_width > 15565 {
        // SILK_FIX_CONST( 0.95, 14 ): full-width stereo.
        quantize_predictors(&mut predictors_q13, &mut indices.indices);
        width_q14 = 1 << 14;
    } else {
        predictors_q13[0] = smulbb(smoothed_width, predictors_q13[0]) >> 14;
        predictors_q13[1] = smulbb(smoothed_width, predictors_q13[1]) >> 14;
        quantize_predictors(&mut predictors_q13, &mut indices.indices);
        width_q14 = smoothed_width;
    }

    // Hold the flag off until the taper has actually been transmitted, or the side channel cuts
    // mid-taper and clicks.
    if indices.mid_only {
        state.silent_side_length +=
            (frame_length - INTERP_LEN_MS * rate_khz).min(i16::MAX as usize) as i16;
        if i32::from(state.silent_side_length) < (LA_SHAPE_MS * rate_khz) as i32 {
            indices.mid_only = false;
        } else {
            state.silent_side_length = 10_000;
        }
    } else {
        state.silent_side_length = 0;
    }

    if !indices.mid_only && side_bps < 1 {
        side_bps = 1;
        mid_bps = (total_rate_bps - side_bps).max(1);
    }

    // ── Interpolate the predictors and the width across the transition, then subtract ──────────
    let interpolation_length = INTERP_LEN_MS * rate_khz;
    let mut predictor0_q13 = -i32::from(state.previous_predictors_q13[0]);
    let mut predictor1_q13 = -i32::from(state.previous_predictors_q13[1]);
    let mut width_q24 = i32::from(state.previous_width_q14) << 10;
    let denominator_q16 = (1i32 << 16) / interpolation_length as i32;
    let delta0_q13 = -rshift_round(
        smulbb(
            predictors_q13[0] - i32::from(state.previous_predictors_q13[0]),
            denominator_q16,
        ),
        16,
    );
    let delta1_q13 = -rshift_round(
        smulbb(
            predictors_q13[1] - i32::from(state.previous_predictors_q13[1]),
            denominator_q16,
        ),
        16,
    );
    let width_delta_q24 = smulwb(
        width_q14 - i32::from(state.previous_width_q14),
        denominator_q16,
    ) << 10;

    for (index, slot) in right.iter_mut().enumerate().take(interpolation_length) {
        predictor0_q13 += delta0_q13;
        predictor1_q13 += delta1_q13;
        width_q24 += width_delta_q24;
        *slot = predict_side(
            left,
            &side,
            index,
            width_q24,
            predictor0_q13,
            predictor1_q13,
        );
    }
    let predictor0_q13 = -predictors_q13[0];
    let predictor1_q13 = -predictors_q13[1];
    let width_q24 = width_q14 << 10;
    for (index, slot) in right
        .iter_mut()
        .enumerate()
        .take(frame_length)
        .skip(interpolation_length)
    {
        *slot = predict_side(
            left,
            &side,
            index,
            width_q24,
            predictor0_q13,
            predictor1_q13,
        );
    }

    state.previous_predictors_q13 = [predictors_q13[0] as i16, predictors_q13[1] as i16];
    state.previous_width_q14 = width_q14 as i16;

    (indices, MidSideRates { mid_bps, side_bps })
}

/// One sample of the side channel's prediction residual (`stereo_LR_to_MS.c:203-208`).
///
/// The C writes it to `x2[n - 1]`, i.e. one sample earlier than the mid it was predicted from;
/// that offset is the delay the decoder's unmixer compensates.
#[inline]
fn predict_side(
    mid: &[i16],
    side: &[i16],
    index: usize,
    width_q24: i32,
    predictor0_q13: i32,
    predictor1_q13: i32,
) -> i16 {
    let filtered =
        (i32::from(mid[index]) + i32::from(mid[index + 2]) + (i32::from(mid[index + 1]) << 1)) << 9; // Q11
    let mut sum = smlawb(
        smulwb(width_q24, i32::from(side[index + 1])),
        filtered,
        predictor0_q13,
    ); // Q8
    sum = smlawb(sum, i32::from(mid[index + 1]) << 11, predictor1_q13); // Q8
    sat16(rshift_round(sum, 8))
}

/// `silk_stereo_encode_pred` (`stereo_encode_pred.c:35-52`) — the two predictor index triples.
///
/// The two *group* indices are coded jointly as `5 * ix[0][2] + ix[1][2]`, which is why the joint
/// table has 25 entries; the within-group index and the sub-step are then uniform.
pub fn encode_predictors(encoder: &mut RangeEncoder<'_>, indices: &[[i8; 3]; 2]) {
    let joint = 5 * indices[0][2] as usize + indices[1][2] as usize;
    debug_assert!(joint < 25);
    encoder.enc_icdf(joint, &STEREO_PRED_JOINT_ICDF, ICDF_FTB);
    for predictor in indices {
        debug_assert!(predictor[0] < 3 && predictor[1] < STEREO_QUANT_SUB_STEPS as i8);
        encoder.enc_icdf(predictor[0] as usize, &UNIFORM3_ICDF, ICDF_FTB);
        encoder.enc_icdf(predictor[1] as usize, &UNIFORM5_ICDF, ICDF_FTB);
    }
}

/// `silk_stereo_encode_mid_only` (`stereo_encode_pred.c:55-62`).
pub fn encode_mid_only(encoder: &mut RangeEncoder<'_>, mid_only: bool) {
    encoder.enc_icdf(usize::from(mid_only), &STEREO_ONLY_CODE_MID_ICDF, ICDF_FTB);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeDecoder;
    use crate::opus::silk::stereo_pred::{decode_mid_only, decode_stereo_weights};

    /// A deterministic stereo pair with a controllable inter-channel gain.
    fn panned(frame_length: usize, right_gain: f32) -> (Vec<i16>, Vec<i16>) {
        let mut state = 4242u32;
        let mut left = vec![0i16; frame_length + 2];
        let mut right = vec![0i16; frame_length + 2];
        let mut history = [0.0f32; 2];
        for index in 0..frame_length + 2 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 20) as i32 - 2048) as f32 * 2.0;
            let pulse = if index % 80 == 0 { 5000.0 } else { 0.0 };
            let value = pulse + noise + 1.4 * history[0] - 0.8 * history[1];
            history[1] = history[0];
            history[0] = value;
            let sample = value.clamp(-24_000.0, 24_000.0);
            left[index] = sample as i16;
            right[index] = (sample * right_gain).clamp(-32_000.0, 32_000.0) as i16;
        }
        (left, right)
    }

    /// The predictor quantiser must land on a real table level, and the *decoder's* dequantiser
    /// must rebuild exactly the pair the encoder said it chose. That inverse is the check that
    /// matters: a wrong sub-step here is a wrong stereo image at the far end.
    #[test]
    fn quantised_predictors_round_trip_through_the_decoder() {
        for target in [-16384i32, -9000, -1000, 0, 700, 4096, 12000, 16384] {
            let mut predictors = [target, target / 2];
            let mut indices = [[0i8; 3]; 2];
            quantize_predictors(&mut predictors, &mut indices);

            let mut buffer = [0u8; 32];
            let mut encoder = RangeEncoder::new(&mut buffer);
            encode_predictors(&mut encoder, &indices);
            let used = (encoder.tell() as usize).div_ceil(8);
            encoder.done();

            let mut decoder = RangeDecoder::new(&buffer[..used.max(1)]);
            let weights = decode_stereo_weights(&mut decoder);
            // Both sides fold the same `pred[0] -= pred[1]` in, so the comparison is direct.
            assert_eq!(
                weights.w0_q13, predictors[0],
                "target {target}: first predictor"
            );
            assert_eq!(
                weights.w1_q13, predictors[1],
                "target {target}: second predictor"
            );
        }
    }

    /// The mid-only flag must round-trip, both ways.
    #[test]
    fn the_mid_only_flag_round_trips() {
        for mid_only in [false, true] {
            let mut buffer = [0u8; 16];
            let mut encoder = RangeEncoder::new(&mut buffer);
            encode_mid_only(&mut encoder, mid_only);
            let used = (encoder.tell() as usize).div_ceil(8);
            encoder.done();
            let mut decoder = RangeDecoder::new(&buffer[..used.max(1)]);
            assert_eq!(decode_mid_only(&mut decoder), mid_only);
        }
    }

    /// A hard-panned-to-mono input (both channels identical) must produce a side channel that is
    /// essentially empty — that is the entire economic case for mid/side.
    #[test]
    fn an_identical_pair_leaves_almost_no_side_signal() {
        let frame_length = 320;
        let (mut left, mut right) = panned(frame_length, 1.0);
        let mut state = StereoEncoderState::default();
        let (_, rates) = left_right_to_mid_side(
            &mut state,
            &mut left,
            &mut right,
            48_000,
            200,
            false,
            16,
            frame_length,
        );
        let side_energy: i64 = right[..frame_length]
            .iter()
            .map(|&s| i64::from(s) * i64::from(s))
            .sum();
        let mid_energy: i64 = left[2..frame_length]
            .iter()
            .map(|&s| i64::from(s) * i64::from(s))
            .sum();
        assert!(
            side_energy * 1000 < mid_energy,
            "side {side_energy} vs mid {mid_energy}"
        );
        assert!(rates.mid_bps > rates.side_bps);
    }

    /// A genuinely wide image must *not* collapse to mid-only, and must buy the side channel a
    /// real share of the rate.
    #[test]
    fn a_wide_image_keeps_a_side_channel() {
        let frame_length = 320;
        let mut state = StereoEncoderState::default();
        let mut last = StereoIndices::default();
        let mut rates = MidSideRates {
            mid_bps: 0,
            side_bps: 0,
        };
        for _ in 0..10 {
            // Anti-correlated channels: the widest image there is.
            let (mut left, mut right) = panned(frame_length, -1.0);
            let result = left_right_to_mid_side(
                &mut state,
                &mut left,
                &mut right,
                64_000,
                220,
                false,
                16,
                frame_length,
            );
            last = result.0;
            rates = result.1;
        }
        assert!(
            !last.mid_only,
            "a fully decorrelated pair collapsed to mono"
        );
        assert!(
            rates.side_bps > 1000,
            "side got only {} bps",
            rates.side_bps
        );
    }

    /// At a rate too low to carry a side channel the encoder must fall back to panned mono, and a
    /// mid-only frame must not budget the side channel any bits at all.
    #[test]
    fn a_starved_rate_collapses_to_mid_only() {
        let frame_length = 320;
        let mut state = StereoEncoderState::default();
        let mut flags = Vec::new();
        for _ in 0..12 {
            let (mut left, mut right) = panned(frame_length, 0.98);
            let (indices, rates) = left_right_to_mid_side(
                &mut state,
                &mut left,
                &mut right,
                6_000,
                200,
                false,
                16,
                frame_length,
            );
            if indices.mid_only {
                assert_eq!(rates.side_bps, 0, "a mid-only frame must not budget a side");
                assert_eq!(rates.mid_bps, 6_000 - 600);
            }
            flags.push(indices.mid_only);
        }
        assert!(flags.iter().all(|&flag| flag), "never collapsed: {flags:?}");
    }

    /// The mid-only flag is held off until the width taper has actually been transmitted. It only
    /// bites where a frame is short relative to `STEREO_INTERP_LEN_MS`: at 8 kHz and 10 ms the
    /// frame is 80 samples and the taper is 64, so it takes three frames to accumulate the
    /// `LA_SHAPE_MS` worth of tapered output the flag waits for (`stereo_LR_to_MS.c:180-192`).
    #[test]
    fn the_mid_only_flag_waits_for_the_taper_to_be_transmitted() {
        let frame_length = 80;
        let mut state = StereoEncoderState::default();
        let mut flags = Vec::new();
        for _ in 0..5 {
            let (mut left, mut right) = panned(frame_length, 0.99);
            let (indices, _) = left_right_to_mid_side(
                &mut state,
                &mut left,
                &mut right,
                5_000,
                200,
                false,
                8,
                frame_length,
            );
            flags.push(indices.mid_only);
        }
        assert_eq!(
            flags,
            vec![false, false, true, true, true],
            "the taper hold-off did not fire"
        );
    }

    /// `to_mono` must collapse the width immediately, whatever the image was.
    #[test]
    fn to_mono_collapses_the_width_at_once() {
        let frame_length = 320;
        let (mut left, mut right) = panned(frame_length, -1.0);
        let mut state = StereoEncoderState::default();
        left_right_to_mid_side(
            &mut state,
            &mut left,
            &mut right,
            64_000,
            220,
            true,
            16,
            frame_length,
        );
        assert_eq!(state.previous_width_q14, 0);
        assert_eq!(state.previous_predictors_q13, [0, 0]);
    }

    /// Every rate and duration must run without reading out of bounds.
    #[test]
    fn every_rate_and_duration_converts() {
        for rate_khz in [8usize, 12, 16] {
            for duration_ms in [10usize, 20] {
                let frame_length = duration_ms * rate_khz;
                let (mut left, mut right) = panned(frame_length, 0.6);
                let mut state = StereoEncoderState::default();
                let (indices, rates) = left_right_to_mid_side(
                    &mut state,
                    &mut left,
                    &mut right,
                    32_000,
                    200,
                    false,
                    rate_khz,
                    frame_length,
                );
                for predictor in indices.indices {
                    assert!((0..3).contains(&predictor[0]));
                    assert!((0..5).contains(&predictor[1]));
                    assert!((0..5).contains(&predictor[2]));
                }
                assert!(rates.mid_bps > 0);
                assert!(rates.side_bps >= 0);
            }
        }
    }
}
