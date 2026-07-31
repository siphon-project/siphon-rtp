//! Mid/side to left/right unmixing (RFC 6716 §4.2.8; libopus `silk/stereo_MS_to_LR.c`).
//!
//! SILK codes a stereo signal as a **mid** channel plus a *residual* side channel: the encoder
//! already predicted the side from the mid and only coded what was left over, so the decoder has to
//! put the prediction back before it can separate left from right.
//!
//! Two details make this more than an add/subtract, and both are load-bearing:
//!
//! * **The prediction runs one sample behind.** The first predictor is applied to a 3-tap
//!   low-passed mid (`x1[n] + 2*x1[n+1] + x1[n+2]`), which needs one sample of look-ahead, so the
//!   whole output is delayed by one sample. That is why the mid and side buffers carry **two extra
//!   leading samples** from the previous frame ([`StereoState::mid_history`] /
//!   [`StereoState::side_history`]) and why the caller reads the result from index 1, not 0.
//! * **The weights are interpolated over the first 8 ms** of every frame (`STEREO_INTERP_LEN_MS`),
//!   from the previous frame's pair to this frame's, so a weight change never steps. A frame shorter
//!   than 8 ms — a 10 ms Opus frame is 10 ms of *audio*, so this never bites in practice — would
//!   simply spend its whole length interpolating.
//!
//! The weights themselves are decoded upstream, in [`super::stereo_pred`].

use crate::opus::silk::decoder::StereoState;
use crate::opus::silk::fixed::{add_lshift32, rshift_round, sat16, smlawb, smulbb};
use crate::opus::silk::types::InternalRate;
use crate::CodecError;

/// `STEREO_INTERP_LEN_MS` (`define.h:82`) — the weights are interpolated over the first 8 ms of a
/// frame. "must be even", says the C.
pub const STEREO_INTERP_LEN_MS: usize = 8;

/// How many leading samples of previous-frame history the unmixing buffers carry.
pub const STEREO_HISTORY: usize = 2;

/// Convert one frame of mid/side to left/right in place (libopus `silk_stereo_MS_to_LR`,
/// `stereo_MS_to_LR.c:35-85`).
///
/// `mid` and `side` must each hold `frame_length + 2` samples: the two leading slots are overwritten
/// with the state's history and the decoded frame occupies `[2, frame_length + 2)`. On return the
/// **left** channel is in `mid[1..=frame_length]` and the **right** in `side[1..=frame_length]` —
/// shifted by one, per the one-sample prediction delay described in the module docs.
///
/// `weights_q13` is the pair decoded for this frame ([`super::stereo_pred::StereoWeights`]); the
/// state's previous pair is the interpolation anchor and is replaced with it.
pub fn mid_side_to_left_right(
    state: &mut StereoState,
    mid: &mut [i16],
    side: &mut [i16],
    weights_q13: [i32; 2],
    rate: InternalRate,
    frame_length: usize,
) -> Result<(), CodecError> {
    if mid.len() < frame_length + STEREO_HISTORY || side.len() < frame_length + STEREO_HISTORY {
        return Err(CodecError::Unsupported(
            "silk: stereo unmixing buffers need frame_length + 2 samples",
        ));
    }

    // Buffering: bring in the previous frame's tail, and stash this frame's for the next one
    // (stereo_MS_to_LR.c:47-51). Both happen *before* anything is overwritten.
    mid[..STEREO_HISTORY].copy_from_slice(&state.mid_history);
    side[..STEREO_HISTORY].copy_from_slice(&state.side_history);
    state
        .mid_history
        .copy_from_slice(&mid[frame_length..frame_length + STEREO_HISTORY]);
    state
        .side_history
        .copy_from_slice(&side[frame_length..frame_length + STEREO_HISTORY]);

    // Interpolate the predictors and add the prediction back to the side channel.
    let mut prediction0_q13 = i32::from(state.pred_prev_q13[0]);
    let mut prediction1_q13 = i32::from(state.pred_prev_q13[1]);
    // The C ramps for exactly `STEREO_INTERP_LEN_MS * fs_kHz` samples with no bound on the frame.
    // It never overruns because the shortest SILK frame is 10 ms of audio and the ramp is 8 ms; the
    // clamp is here so a caller cannot turn a short frame into an out-of-bounds write.
    let interpolation_length = (STEREO_INTERP_LEN_MS * rate.khz()).min(frame_length);
    // silk_DIV32_16( 1 << 16, STEREO_INTERP_LEN_MS * fs_kHz ) — an exact integer divide (512 at
    // 16 kHz, 682 at 12, 1024 at 8), so the ramp lands on the new weight at the end of the window.
    let denominator_q16 = (1i32 << 16) / (STEREO_INTERP_LEN_MS * rate.khz()) as i32;
    let delta0_q13 = rshift_round(
        smulbb(
            weights_q13[0] - i32::from(state.pred_prev_q13[0]),
            denominator_q16,
        ),
        16,
    );
    let delta1_q13 = rshift_round(
        smulbb(
            weights_q13[1] - i32::from(state.pred_prev_q13[1]),
            denominator_q16,
        ),
        16,
    );

    for index in 0..interpolation_length {
        prediction0_q13 += delta0_q13;
        prediction1_q13 += delta1_q13;
        predict_side(mid, side, index, prediction0_q13, prediction1_q13);
    }
    for index in interpolation_length..frame_length {
        predict_side(mid, side, index, weights_q13[0], weights_q13[1]);
    }

    // The C stores the *coded* weights, not the ramp's endpoint — they differ by the rounding in
    // `delta*_Q13` (stereo_MS_to_LR.c:75-76).
    state.pred_prev_q13 = [weights_q13[0] as i16, weights_q13[1] as i16];

    // Mid/side to left/right. Both saturate: an out-of-range side prediction must clip, not wrap.
    for index in 0..frame_length {
        let mid_sample = i32::from(mid[index + 1]);
        let side_sample = i32::from(side[index + 1]);
        mid[index + 1] = sat16(mid_sample + side_sample);
        side[index + 1] = sat16(mid_sample - side_sample);
    }
    Ok(())
}

/// One sample of the §4.2.8 side-channel prediction (`stereo_MS_to_LR.c:62-65`).
///
/// The first weight is applied to a 3-tap low-passed mid (`x1[n] + 2*x1[n+1] + x1[n+2]`, hence the
/// one-sample delay), the second directly to the delayed mid.
#[inline]
fn predict_side(
    mid: &[i16],
    side: &mut [i16],
    index: usize,
    prediction0_q13: i32,
    prediction1_q13: i32,
) {
    // (x1[n] + x1[n+2] + 2*x1[n+1]) << 9, i.e. Q11.
    let low_passed_q11 = ((add_lshift32(
        i32::from(mid[index]) + i32::from(mid[index + 2]),
        i32::from(mid[index + 1]),
        1,
    ) as u32)
        << 9) as i32;
    // Q8 accumulator: the side residual, plus each weight's contribution.
    let mut sum_q8 = smlawb(
        ((i32::from(side[index + 1]) as u32) << 8) as i32,
        low_passed_q11,
        prediction0_q13,
    );
    sum_q8 = smlawb(
        sum_q8,
        ((i32::from(mid[index + 1]) as u32) << 11) as i32,
        prediction1_q13,
    );
    side[index + 1] = sat16(rshift_round(sum_q8, 8));
}

/// The mono counterpart of the buffering half of [`mid_side_to_left_right`]
/// (`dec_API.c:378-381`).
///
/// A mono stream (or a stereo stream decoded to a mono API) never unmixes, but it still pays the
/// one-sample delay, because the resampler is fed from index 1 either way. Keeping the delay
/// identical is what makes a mid-stream mono/stereo switch click-free.
pub fn buffer_mono(
    state: &mut StereoState,
    mid: &mut [i16],
    frame_length: usize,
) -> Result<(), CodecError> {
    if mid.len() < frame_length + STEREO_HISTORY {
        return Err(CodecError::Unsupported(
            "silk: mono buffering needs frame_length + 2 samples",
        ));
    }
    mid[..STEREO_HISTORY].copy_from_slice(&state.mid_history);
    state
        .mid_history
        .copy_from_slice(&mid[frame_length..frame_length + STEREO_HISTORY]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the mid/side pair the decoder hands in: two junk leading slots (overwritten from state)
    /// followed by the frame.
    fn buffers(mid_frame: &[i16], side_frame: &[i16]) -> (Vec<i16>, Vec<i16>) {
        let mut mid = vec![i16::MIN; STEREO_HISTORY];
        mid.extend_from_slice(mid_frame);
        let mut side = vec![i16::MIN; STEREO_HISTORY];
        side.extend_from_slice(side_frame);
        (mid, side)
    }

    /// With both weights zero the side channel is its own residual, so unmixing is exactly the
    /// textbook `L = M + S`, `R = M - S` — on the *delayed* sample pair.
    #[test]
    fn zero_weights_are_a_plain_sum_and_difference() {
        let mid_frame: Vec<i16> = (0..80).map(|n| (n as i16) * 100 - 4000).collect();
        let side_frame: Vec<i16> = (0..80).map(|n| 1000 - (n as i16) * 25).collect();
        let (mut mid, mut side) = buffers(&mid_frame, &side_frame);
        let mut state = StereoState::new();
        state.mid_history = [7, -9];
        state.side_history = [-3, 11];

        mid_side_to_left_right(
            &mut state,
            &mut mid,
            &mut side,
            [0, 0],
            InternalRate::Wide16k,
            80,
        )
        .expect("unmix");

        // Sample 0 of the output is the *previous* frame's last sample — the one-sample delay.
        assert_eq!(mid[1], -9 + 11);
        assert_eq!(side[1], -9 - 11);
        for index in 1..80 {
            let mid_sample = i32::from(mid_frame[index - 1]);
            let side_sample = i32::from(side_frame[index - 1]);
            assert_eq!(
                mid[index + 1],
                sat16(mid_sample + side_sample),
                "L[{index}]"
            );
            assert_eq!(
                side[index + 1],
                sat16(mid_sample - side_sample),
                "R[{index}]"
            );
        }
        // The state now holds this frame's last two samples, captured before anything was rewritten.
        assert_eq!(state.mid_history, [mid_frame[78], mid_frame[79]]);
        assert_eq!(state.side_history, [side_frame[78], side_frame[79]]);
        assert_eq!(state.pred_prev_q13, [0, 0]);
    }

    /// A constant mid with a zero side residual and a steady first weight: after the 8 ms ramp the
    /// predicted side settles at `w0 * mid`, so left and right separate by a known amount. This pins
    /// the Q13/Q11/Q8 scaling chain, which no amount of structural testing would catch.
    #[test]
    fn first_weight_predicts_the_side_from_the_low_passed_mid() {
        let frame_length = 320usize;
        let mid_frame = vec![1000i16; frame_length];
        let side_frame = vec![0i16; frame_length];
        let (mut mid, mut side) = buffers(&mid_frame, &side_frame);
        let mut state = StereoState::new();
        state.mid_history = [1000, 1000];
        // 0.5 in Q13.
        let weight = 4096i32;

        mid_side_to_left_right(
            &mut state,
            &mut mid,
            &mut side,
            [weight, 0],
            InternalRate::Wide16k,
            frame_length,
        )
        .expect("unmix");

        // Past the 8 ms ramp (128 samples at 16 kHz) the weight is fully applied. The low-pass
        // (1 + 2 + 1)/4 has unit DC gain, so side = 0.5 * 1000 = 500 and L/R = 1500/500.
        for index in 200..frame_length {
            assert_eq!(mid[index + 1], 1500, "L[{index}]");
            assert_eq!(side[index + 1], 500, "R[{index}]");
        }
        assert_eq!(state.pred_prev_q13, [4096, 0]);
    }

    /// The ramp must start at the previous frame's weight and reach the new one, monotonically —
    /// that is the whole point of interpolating, and a sign error would show as an overshoot.
    #[test]
    fn the_weight_ramp_is_monotone_across_the_interpolation_window() {
        let frame_length = 320usize;
        let mid_frame = vec![2000i16; frame_length];
        let side_frame = vec![0i16; frame_length];
        let (mut mid, mut side) = buffers(&mid_frame, &side_frame);
        let mut state = StereoState::new();
        state.mid_history = [2000, 2000];
        state.pred_prev_q13 = [0, 0];

        mid_side_to_left_right(
            &mut state,
            &mut mid,
            &mut side,
            [8192, 0],
            InternalRate::Wide16k,
            frame_length,
        )
        .expect("unmix");

        // R = mid - side, so a rising prediction makes R fall, sample by sample, until the ramp ends.
        let interpolation_length = STEREO_INTERP_LEN_MS * 16;
        for index in 1..interpolation_length {
            assert!(
                side[index + 1] <= side[index],
                "R must fall monotonically through the ramp, broke at {index}"
            );
        }
        assert_eq!(side[interpolation_length], 0, "R = mid - 1.0*mid = 0");
        assert_eq!(mid[interpolation_length], 4000, "L = mid + 1.0*mid");
    }

    #[test]
    fn the_interpolation_window_is_eight_milliseconds_at_every_internal_rate() {
        for (rate, samples) in [
            (InternalRate::Narrow8k, 64usize),
            (InternalRate::Medium12k, 96),
            (InternalRate::Wide16k, 128),
        ] {
            assert_eq!(STEREO_INTERP_LEN_MS * rate.khz(), samples, "{rate:?}");
        }
    }

    #[test]
    fn mono_buffering_applies_the_same_one_sample_delay() {
        let frame: Vec<i16> = (0..160).map(|n| n as i16).collect();
        let mut mid = vec![i16::MIN; STEREO_HISTORY];
        mid.extend_from_slice(&frame);
        let mut state = StereoState::new();
        state.mid_history = [111, 222];

        buffer_mono(&mut state, &mut mid, 160).expect("buffering");
        assert_eq!(mid[0], 111);
        assert_eq!(mid[1], 222, "the resampler reads from index 1");
        assert_eq!(mid[2], frame[0]);
        assert_eq!(state.mid_history, [frame[158], frame[159]]);
        // The side history is untouched by the mono path (dec_API.c:378-381 only moves sMid).
        assert_eq!(state.side_history, [0, 0]);
    }

    #[test]
    fn rejects_buffers_without_room_for_the_history() {
        let mut state = StereoState::new();
        let mut mid = [0i16; 80];
        let mut side = [0i16; 82];
        assert!(mid_side_to_left_right(
            &mut state,
            &mut mid,
            &mut side,
            [0, 0],
            InternalRate::Wide16k,
            80,
        )
        .is_err());
        assert!(buffer_mono(&mut state, &mut mid, 80).is_err());
    }

    /// Saturation, not wrapping, at both extremes.
    #[test]
    fn extreme_mid_and_side_saturate() {
        let frame_length = 80usize;
        let mid_frame = vec![i16::MAX; frame_length];
        let side_frame = vec![i16::MAX; frame_length];
        let (mut mid, mut side) = buffers(&mid_frame, &side_frame);
        let mut state = StereoState::new();
        state.mid_history = [i16::MAX; 2];
        state.side_history = [i16::MAX; 2];
        mid_side_to_left_right(
            &mut state,
            &mut mid,
            &mut side,
            [0, 0],
            InternalRate::Narrow8k,
            frame_length,
        )
        .expect("unmix");
        for index in 0..frame_length {
            assert_eq!(mid[index + 1], i16::MAX, "L[{index}] must clip, not wrap");
            assert_eq!(side[index + 1], 0, "R[{index}]");
        }
    }
}
