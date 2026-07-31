//! LTP + LPC synthesis — the inverse noise-shaping quantiser (RFC 6716 §4.2.7.9; libopus
//! `silk/decode_core.c`).
//!
//! This is where a SILK frame stops being side info and becomes audio. Everything upstream produced
//! numbers; this module runs them through the two synthesis filters, in the fixed-point arithmetic
//! RFC 6716 §4.2.7.9 specifies:
//!
//! ```text
//!   excitation (Q14)  ──► long-term (pitch) predictor ──► short-term (LPC) predictor ──► gain ──► PCM
//!                          voiced frames only, per                 order 10 (NB/MB)     Q10
//!                          5 ms subframe, 5 taps                   or 16 (WB)
//! ```
//!
//! Three things about it are easy to get wrong and are called out at the point they are enforced
//! below: the **re-whitening** of the LTP history (the filter memory has to be re-derived with the
//! *current* frame's LPC coefficients whenever they change, §4.2.7.9.1), the **gain adjustment**
//! that rescales both filter memories when the subframe gain moves, and the fact that the LTP
//! history lives in the *unscaled* Q15 domain while the LPC state lives in Q14.
//!
//! The excitation itself is **not** rebuilt here. `silk_decode_core` opens by re-running the
//! §4.2.7.8.6 reconstruction from the pulse signal; in this port that already happened in
//! [`super::excitation::reconstruct`], which wrote `channel.excitation_q14`, so this module starts
//! at the subframe loop with the same values.

use crate::opus::silk::decoder::ChannelState;
use crate::opus::silk::fixed::{
    add_lshift32, div32_var_q, inverse32_var_q, lshift_sat32, rshift_round, sat16, smlabb, smlawb,
    smulbb, smulwb, smulww,
};
use crate::opus::silk::types::{
    InternalRate, SignalType, LTP_MEM_LENGTH_MS, LTP_ORDER, MAX_FRAME_LENGTH, MAX_FS_KHZ,
    MAX_LPC_ORDER, MAX_NB_SUBFR, MAX_SUB_FRAME_LENGTH,
};
use crate::CodecError;

/// Longest LTP memory — `LTP_MEM_LENGTH_MS * MAX_FS_KHZ` (`decoder_set_fs.c:73`), i.e. 20 ms at
/// 16 kHz.
pub const MAX_LTP_MEM_LENGTH: usize = LTP_MEM_LENGTH_MS * MAX_FS_KHZ;

/// The per-frame decoder control block (libopus `silk_decoder_control`, `structs.h:342-350`).
///
/// It is the aggregate `silk_decode_parameters` fills and `silk_decode_core` / `silk_PLC` / `silk_CNG`
/// consume: everything about *this* frame that is not entropy state and not sample history. The
/// synthesis, PLC and CNG stages all read it, and two of them write back to it — `silk_decode_core`
/// overwrites the LTP taps and pitch lag on the voiced-PLC-to-unvoiced transition
/// (`decode_core.c:126-134`) and `silk_PLC_conceal` overwrites every pitch lag
/// (`PLC.c:426-428`) — which is why it is passed by mutable reference rather than by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderControl {
    /// `pitchL[MAX_NB_SUBFR]` — per-subframe pitch lag in samples at the internal rate. Zero for an
    /// unvoiced frame.
    pub pitch_lags: [i32; MAX_NB_SUBFR],
    /// `Gains_Q16[MAX_NB_SUBFR]` — per-subframe linear gain in Q16 (§4.2.7.4).
    pub gains_q16: [i32; MAX_NB_SUBFR],
    /// `PredCoef_Q12[2][MAX_LPC_ORDER]` — the short-term filter for the first half of the frame
    /// (index 0, possibly interpolated) and for the second half (index 1) (§4.2.7.5.5).
    pub pred_coef_q12: [[i16; MAX_LPC_ORDER]; 2],
    /// `LTPCoef_Q14[LTP_ORDER * MAX_NB_SUBFR]` — five long-term taps per subframe, subframe-major.
    pub ltp_coef_q14: [i16; LTP_ORDER * MAX_NB_SUBFR],
    /// `LTP_scale_Q14` — the §4.2.7.6.3 re-whitening scale. Zero for an unvoiced frame.
    pub ltp_scale_q14: i32,
}

impl DecoderControl {
    /// The all-zero control block `silk_decode_frame` starts each frame from
    /// (`decode_frame.c:64-65` allocates it and clears `LTP_scale_Q14`; every other field is written
    /// before it is read, on both the decode and the concealment path).
    #[must_use]
    pub fn new() -> Self {
        Self {
            pitch_lags: [0; MAX_NB_SUBFR],
            gains_q16: [0; MAX_NB_SUBFR],
            pred_coef_q12: [[0; MAX_LPC_ORDER]; 2],
            ltp_coef_q14: [0; LTP_ORDER * MAX_NB_SUBFR],
            ltp_scale_q14: 0,
        }
    }

    /// The five Q14 long-term taps of one subframe.
    #[must_use]
    pub fn ltp_taps_q14(&self, subframe: usize) -> &[i16] {
        let start = subframe * LTP_ORDER;
        &self.ltp_coef_q14[start..start + LTP_ORDER]
    }
}

impl Default for DecoderControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Scratch buffers for one [`decode_core`] call — the C's four `VARDECL`s, hoisted to a caller-owned
/// struct so the synthesis path makes no heap allocation per frame.
///
/// Deliberately **not** cleared between frames. The C leaves these uninitialised on the stack and
/// every read is preceded by a write in the same call (the re-whitening fills the LTP history a
/// subframe before the predictor reads it); zeroing would cost a memset per frame and hide nothing.
#[derive(Debug, Clone)]
pub struct CoreScratch {
    /// `sLTP[ltp_mem_length]` — the re-whitened output history, still in Q0.
    ltp_history: [i16; MAX_LTP_MEM_LENGTH],
    /// `sLTP_Q15[ltp_mem_length + frame_length]` — the same history plus this frame, gain-normalised
    /// to Q15. The long-term predictor reads back into it by the pitch lag.
    ltp_q15: [i32; MAX_LTP_MEM_LENGTH + MAX_FRAME_LENGTH],
    /// `res_Q14[subfr_length]` — one subframe of LPC excitation (excitation + long-term prediction).
    residual_q14: [i32; MAX_SUB_FRAME_LENGTH],
    /// `sLPC_Q14[subfr_length + MAX_LPC_ORDER]` — the short-term filter memory followed by one
    /// subframe of its output, in Q14.
    lpc_q14: [i32; MAX_SUB_FRAME_LENGTH + MAX_LPC_ORDER],
}

impl CoreScratch {
    /// A zeroed scratch block.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ltp_history: [0; MAX_LTP_MEM_LENGTH],
            ltp_q15: [0; MAX_LTP_MEM_LENGTH + MAX_FRAME_LENGTH],
            residual_q14: [0; MAX_SUB_FRAME_LENGTH],
            lpc_q14: [0; MAX_SUB_FRAME_LENGTH + MAX_LPC_ORDER],
        }
    }
}

impl Default for CoreScratch {
    fn default() -> Self {
        Self::new()
    }
}

/// `silk_LPC_analysis_filter` (`LPC_analysis_filter.c:49-111`) — run the *inverse* of the short-term
/// synthesis filter over `input`, leaving the prediction residual in `out`.
///
/// The first `order` output samples are zeroed, as the C does: the filter starts from zero state, so
/// they carry no information. Every accumulation wraps rather than saturating — the C says so
/// explicitly ("Allowing wrap around so that two wraps can cancel each other"), and a hostile stream
/// is the only thing that can reach the wrapping case.
///
/// `out` and `input` must be the same length, and that length at least `order`.
pub fn lpc_analysis_filter(
    out: &mut [i16],
    input: &[i16],
    coefficients_q12: &[i16],
) -> Result<(), CodecError> {
    let order = coefficients_q12.len();
    if out.len() != input.len() || input.len() < order || order < 6 || !order.is_multiple_of(2) {
        return Err(CodecError::Unsupported(
            "silk: LPC analysis filter geometry",
        ));
    }
    for index in order..input.len() {
        // in_ptr = &in[ix - 1]; taps run backwards from there.
        let mut prediction_q12 =
            smulbb(i32::from(input[index - 1]), i32::from(coefficients_q12[0]));
        for (tap, &coefficient) in coefficients_q12.iter().enumerate().skip(1) {
            prediction_q12 = smlabb(
                prediction_q12,
                i32::from(input[index - 1 - tap]),
                i32::from(coefficient),
            );
        }
        // Subtract the prediction from the sample itself, in Q12, then round back to Q0.
        let residual_q12 =
            ((i32::from(input[index]) as u32) << 12).wrapping_sub(prediction_q12 as u32) as i32;
        out[index] = sat16(rshift_round(residual_q12, 12));
    }
    out[..order].fill(0);
    Ok(())
}

/// Run the LTP and LPC synthesis filters over one SILK frame (RFC 6716 §4.2.7.9; libopus
/// `silk_decode_core`, `decode_core.c:38-237`).
///
/// Reads `channel.excitation_q14[..frame_length]` (already reconstructed by
/// [`super::excitation::decode`]) plus the channel's `lpc_state_q14`, `out_buf` and `prev_gain_q16`,
/// and writes `frame_length` samples of PCM into `xq`. All three pieces of channel state are
/// updated, so consecutive frames filter continuously.
///
/// `interpolated_nlsf` is the C's `NLSF_interpolation_flag` — true when the frame's *effective*
/// interpolation factor is below 4, which is what makes subframe 2 re-whiten with the second-half
/// filter (`decode_core.c:65-69, 141`). Take it from
/// [`super::nlsf::LpcCoefficients::interpolation_factor_q2`], which already applies the
/// first-frame-after-reset override.
///
/// `signal_type` is the frame's type. It is passed separately from `control` because the
/// voiced-PLC-to-unvoiced transition (`decode_core.c:126-134`) overrides it per subframe.
pub fn decode_core(
    channel: &mut ChannelState,
    control: &mut DecoderControl,
    signal_type: SignalType,
    interpolated_nlsf: bool,
    xq: &mut [i16],
    scratch: &mut CoreScratch,
) -> Result<(), CodecError> {
    let rate = channel.internal_rate()?;
    let order = rate.lpc_order();
    let subframe_length = rate.subframe_length();
    let ltp_memory_length = rate.ltp_memory_length();
    let subframe_count = channel.subframe_count();
    let frame_length = subframe_count * subframe_length;
    if xq.len() < frame_length {
        return Err(CodecError::Unsupported(
            "silk: synthesis output buffer shorter than the frame",
        ));
    }
    // `silk_assert( psDec->prev_gain_Q16 != 0 )` (decode_core.c:56) — a zero previous gain would make
    // the gain-adjustment divide meaningless. It is seeded to 1.0 and only ever written from a
    // dequantized gain, which RFC 6716 §4.2.7.4 bounds below by 81920.
    if channel.prev_gain_q16 == 0 {
        return Err(CodecError::Malformed("silk: zero previous subframe gain"));
    }

    // Copy the short-term filter state in; it is written back at the end.
    scratch.lpc_q14[..MAX_LPC_ORDER].copy_from_slice(&channel.lpc_state_q14);

    let mut lag = 0i32;
    let mut ltp_buffer_index = ltp_memory_length;

    for subframe in 0..subframe_count {
        // Subframes 0..1 use the (possibly interpolated) first-half filter, 2..3 the second half.
        let coefficients_q12 = control.pred_coef_q12[subframe >> 1];
        let gain_q16 = control.gains_q16[subframe];
        let gain_q10 = gain_q16 >> 6;
        let mut inverse_gain_q31 = inverse32_var_q(gain_q16, 47);

        // Gain adjustment: rescale both filter memories so the state carried in from the previous
        // subframe is expressed in this subframe's gain (decode_core.c:109-119).
        let gain_adjust_q16 = if gain_q16 != channel.prev_gain_q16 {
            let adjust = div32_var_q(channel.prev_gain_q16, gain_q16, 16);
            for slot in scratch.lpc_q14[..MAX_LPC_ORDER].iter_mut() {
                *slot = smulww(adjust, *slot);
            }
            adjust
        } else {
            1 << 16
        };
        channel.prev_gain_q16 = gain_q16;

        // "Avoid abrupt transition from voiced PLC to unvoiced normal decoding" — the first half of
        // the frame keeps predicting at the concealed pitch, with a single 0.25 tap
        // (decode_core.c:125-134). This *writes back* into the control block, which is what the PLC
        // state update then picks up.
        let mut subframe_signal_type = signal_type;
        if channel.loss_count != 0
            && channel.prev_signal_type == SignalType::Voiced
            && signal_type != SignalType::Voiced
            && subframe < MAX_NB_SUBFR / 2
        {
            let taps = &mut control.ltp_coef_q14[subframe * LTP_ORDER..(subframe + 1) * LTP_ORDER];
            taps.fill(0);
            // SILK_FIX_CONST( 0.25, 14 ) = 4096.
            taps[LTP_ORDER / 2] = 4096;
            subframe_signal_type = SignalType::Voiced;
            control.pitch_lags[subframe] = channel.lag_prev;
        }

        if subframe_signal_type == SignalType::Voiced {
            lag = control.pitch_lags[subframe];

            // ── Re-whitening (§4.2.7.9.1) ─────────────────────────────────────────────────────
            // Only when the short-term filter changes: at the start of the frame, and again at
            // subframe 2 if the two halves differ (decode_core.c:141).
            if subframe == 0 || (subframe == 2 && interpolated_nlsf) {
                let start_index =
                    (ltp_memory_length as i32) - lag - (order as i32) - (LTP_ORDER as i32) / 2;
                if start_index <= 0 {
                    // `celt_assert( start_idx > 0 )` (decode_core.c:144). Unreachable: the pitch lag
                    // is clamped to at most 18 ms and the LTP memory is 20 ms, leaving
                    // 2*fs_kHz - order - 2 >= 4 samples of margin at every internal rate.
                    return Err(CodecError::Malformed(
                        "silk: pitch lag leaves no re-whitening history",
                    ));
                }
                let start_index = start_index as usize;
                if subframe == 2 {
                    // The first half of this frame is already decoded; fold it into the output
                    // history so the analysis filter can reach it (decode_core.c:146-148).
                    channel.out_buf[ltp_memory_length..ltp_memory_length + 2 * subframe_length]
                        .copy_from_slice(&xq[..2 * subframe_length]);
                }
                let window = start_index + subframe * subframe_length;
                lpc_analysis_filter(
                    &mut scratch.ltp_history[start_index..ltp_memory_length],
                    &channel.out_buf[window..window + (ltp_memory_length - start_index)],
                    &coefficients_q12[..order],
                )?;

                // "After rewhitening the LTP state is unscaled". Subframe 0 additionally applies the
                // §4.2.7.6.3 LTP scaling, which is what limits inter-packet dependency.
                if subframe == 0 {
                    inverse_gain_q31 =
                        ((smulwb(inverse_gain_q31, control.ltp_scale_q14) as u32) << 2) as i32;
                }
                for offset in 0..(lag as usize + LTP_ORDER / 2) {
                    scratch.ltp_q15[ltp_buffer_index - offset - 1] = smulwb(
                        inverse_gain_q31,
                        i32::from(scratch.ltp_history[ltp_memory_length - offset - 1]),
                    );
                }
            } else if gain_adjust_q16 != 1 << 16 {
                // No re-whitening this subframe, but the gain moved: rescale the LTP history the
                // predictor is about to read (decode_core.c:162-167).
                for offset in 0..(lag as usize + LTP_ORDER / 2) {
                    let slot = ltp_buffer_index - offset - 1;
                    scratch.ltp_q15[slot] = smulww(gain_adjust_q16, scratch.ltp_q15[slot]);
                }
            }
        }

        // ── Long-term (pitch) prediction ──────────────────────────────────────────────────────
        let residual_source_offset = if subframe_signal_type == SignalType::Voiced {
            let base = ltp_buffer_index - lag as usize + LTP_ORDER / 2;
            let taps = &control.ltp_coef_q14[subframe * LTP_ORDER..(subframe + 1) * LTP_ORDER];
            for sample in 0..subframe_length {
                // The `2` seed avoids a bias: silk_SMLAWB always rounds towards -infinity.
                let mut prediction_q13 = 2i32;
                for (tap_index, &tap) in taps.iter().enumerate() {
                    prediction_q13 = smlawb(
                        prediction_q13,
                        scratch.ltp_q15[base + sample - tap_index],
                        i32::from(tap),
                    );
                }
                let excitation = channel.excitation_q14[subframe * subframe_length + sample];
                let residual = add_lshift32(excitation, prediction_q13, 1);
                scratch.residual_q14[sample] = residual;
                scratch.ltp_q15[ltp_buffer_index] = ((residual as u32) << 1) as i32;
                ltp_buffer_index += 1;
            }
            None
        } else {
            // Unvoiced: the LPC excitation *is* the excitation (decode_core.c:193-195).
            Some(subframe * subframe_length)
        };

        // ── Short-term (LPC) prediction and gain scaling ───────────────────────────────────────
        for sample in 0..subframe_length {
            // The `order >> 1` seed is the same anti-bias trick as above.
            let mut prediction_q10 = (order >> 1) as i32;
            for (tap, &coefficient) in coefficients_q12[..order].iter().enumerate() {
                prediction_q10 = smlawb(
                    prediction_q10,
                    scratch.lpc_q14[MAX_LPC_ORDER + sample - 1 - tap],
                    i32::from(coefficient),
                );
            }
            let residual = match residual_source_offset {
                Some(offset) => channel.excitation_q14[offset + sample],
                None => scratch.residual_q14[sample],
            };
            let synthesized = residual.saturating_add(lshift_sat32(prediction_q10, 4));
            scratch.lpc_q14[MAX_LPC_ORDER + sample] = synthesized;
            xq[subframe * subframe_length + sample] =
                sat16(rshift_round(smulww(synthesized, gain_q10), 8));
        }

        // Slide the short-term filter memory forward one subframe.
        scratch
            .lpc_q14
            .copy_within(subframe_length..subframe_length + MAX_LPC_ORDER, 0);
    }

    channel
        .lpc_state_q14
        .copy_from_slice(&scratch.lpc_q14[..MAX_LPC_ORDER]);
    Ok(())
}

/// Slide `frame_length` freshly decoded samples into the channel's output history
/// (`decode_frame.c:104-107`), so the next frame's long-term predictor can reach them.
///
/// `out_buf` holds exactly `ltp_mem_length` samples of history; this drops the oldest
/// `frame_length` of them and appends the new frame. It is shared by the good-frame and the
/// concealed-frame path, which is why it is a free function rather than part of [`decode_core`].
pub fn update_output_history(channel: &mut ChannelState, frame: &[i16]) -> Result<(), CodecError> {
    let ltp_memory_length = channel.internal_rate()?.ltp_memory_length();
    let frame_length = frame.len();
    if frame_length > ltp_memory_length {
        return Err(CodecError::Unsupported(
            "silk: frame longer than the LTP memory",
        ));
    }
    let keep = ltp_memory_length - frame_length;
    channel
        .out_buf
        .copy_within(frame_length..ltp_memory_length, 0);
    channel.out_buf[keep..ltp_memory_length].copy_from_slice(frame);
    Ok(())
}

/// The internal rate a channel is configured for, as the PLC and CNG stages need it too.
#[must_use]
pub fn frame_length_of(rate: InternalRate, subframe_count: usize) -> usize {
    subframe_count * rate.subframe_length()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::types::SubframeLayout;

    /// A straightforward transcription of `LPC_analysis_filter.c:82-106`, written from the C rather
    /// than from the implementation above, as the second opinion on the rounding and the wrap.
    fn reference_analysis_filter(input: &[i16], coefficients_q12: &[i16]) -> Vec<i16> {
        let order = coefficients_q12.len();
        let mut out = vec![0i16; input.len()];
        for index in order..input.len() {
            let mut accumulator: i32 = 0;
            for (tap, &coefficient) in coefficients_q12.iter().enumerate() {
                accumulator = accumulator.wrapping_add(
                    i32::from(input[index - 1 - tap]).wrapping_mul(i32::from(coefficient)),
                );
            }
            let residual = (i32::from(input[index]) << 12).wrapping_sub(accumulator);
            out[index] = (((residual >> 11) + 1) >> 1).clamp(-32768, 32767) as i16;
        }
        out
    }

    #[test]
    fn analysis_filter_matches_the_reference_transcription() {
        let coefficients: [i16; 10] = [4096, -1024, 512, -256, 128, -64, 32, -16, 8, -4];
        let input: Vec<i16> = (0..80)
            .map(|n| (((n * 977) % 4001) as i16) - 2000)
            .collect();
        let mut out = vec![0i16; input.len()];
        lpc_analysis_filter(&mut out, &input, &coefficients).expect("geometry");
        assert_eq!(out, reference_analysis_filter(&input, &coefficients));
        assert!(
            out[..10].iter().all(|&value| value == 0),
            "the first `order` samples are zeroed (LPC_analysis_filter.c:109)"
        );
    }

    /// An all-zero predictor makes the filter the identity, which pins the Q12 scaling and the
    /// rounding independently of any coefficient.
    #[test]
    fn analysis_filter_with_zero_coefficients_is_the_identity() {
        let coefficients = [0i16; 16];
        let input: Vec<i16> = (0..64).map(|n| (n as i16) * 37 - 1000).collect();
        let mut out = vec![0i16; input.len()];
        lpc_analysis_filter(&mut out, &input, &coefficients).expect("geometry");
        for index in 16..input.len() {
            assert_eq!(out[index], input[index], "sample {index}");
        }
    }

    #[test]
    fn analysis_filter_rejects_bad_geometry() {
        let mut out = [0i16; 8];
        // Mismatched lengths.
        assert!(lpc_analysis_filter(&mut out[..4], &[0i16; 8], &[0i16; 6]).is_err());
        // Order below 6 / odd order: the C asserts both.
        assert!(lpc_analysis_filter(&mut out, &[0i16; 8], &[0i16; 4]).is_err());
        assert!(lpc_analysis_filter(&mut out, &[0i16; 8], &[0i16; 7]).is_err());
        // Shorter than the order.
        let mut short = [0i16; 4];
        assert!(lpc_analysis_filter(&mut short, &[0i16; 4], &[0i16; 6]).is_err());
    }

    fn configured_channel(rate: InternalRate, duration_ms: usize) -> ChannelState {
        let mut channel = ChannelState::new();
        let layout = SubframeLayout::from_duration_ms(duration_ms).expect("layout");
        channel.set_internal_rate(rate, layout);
        channel
    }

    /// A unit-gain, zero-prediction frame: the synthesis filter degenerates to `excitation >> 4`
    /// (Q14 to Q10, then `SMULWW` by `gain_Q10 = 1024` and a rounding shift by 8), which is the one
    /// case the whole chain can be checked against by hand.
    #[test]
    fn unvoiced_frame_with_unit_gain_and_no_prediction_is_a_plain_rescale() {
        let mut channel = configured_channel(InternalRate::Wide16k, 20);
        let mut control = DecoderControl::new();
        control.gains_q16 = [1 << 16; MAX_NB_SUBFR];
        let mut scratch = CoreScratch::new();

        for (index, slot) in channel.excitation_q14.iter_mut().enumerate() {
            *slot = ((index as i32) - 160) << 8;
        }
        let excitation = channel.excitation_q14;

        let mut xq = [0i16; MAX_FRAME_LENGTH];
        decode_core(
            &mut channel,
            &mut control,
            SignalType::Unvoiced,
            false,
            &mut xq,
            &mut scratch,
        )
        .expect("synthesis");

        for (index, &sample) in xq.iter().enumerate() {
            let expected = sat16(rshift_round(smulww(excitation[index], 1024), 8));
            assert_eq!(sample, expected, "sample {index}");
        }
        assert_eq!(channel.prev_gain_q16, 1 << 16);
    }

    /// Zero excitation and zero LPC state must decode to digital silence at any gain — a synthesis
    /// filter that leaked its own seed constants would show up here as a DC offset.
    #[test]
    fn silence_in_is_silence_out() {
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            let mut channel = configured_channel(rate, 20);
            let mut control = DecoderControl::new();
            control.gains_q16 = [1 << 20; MAX_NB_SUBFR];
            control.pred_coef_q12[0][0] = 2048;
            control.pred_coef_q12[1][0] = 2048;
            let mut scratch = CoreScratch::new();
            let mut xq = [0i16; MAX_FRAME_LENGTH];
            decode_core(
                &mut channel,
                &mut control,
                SignalType::Unvoiced,
                false,
                &mut xq,
                &mut scratch,
            )
            .expect("synthesis");
            let frame_length = 4 * rate.subframe_length();
            assert!(
                xq[..frame_length].iter().all(|&value| value == 0),
                "{rate:?}: silence must stay silent"
            );
            // The filter *state* is not zero: `LPC_pred_Q10` is seeded with `LPC_order >> 1`
            // (decode_core.c:201) to keep `silk_SMLAWB`'s round-towards-negative-infinity from
            // biasing the output downwards. That seed survives into `sLPC_Q14` and is well below the
            // one-LSB output threshold, which is exactly what the silent output above proves.
            assert!(
                channel
                    .lpc_state_q14
                    .iter()
                    .all(|&value| value.abs() < (1 << 14)),
                "{rate:?}: the anti-bias seed must stay far below one output LSB"
            );
        }
    }

    /// A voiced frame reads its own freshly written LTP history back at the pitch lag, so a periodic
    /// excitation must come out periodic. This is the cheap structural check that the predictor is
    /// wired to the right buffer; bit-exactness is the conformance harness' job.
    #[test]
    fn voiced_frame_predicts_from_the_pitch_lagged_history() {
        let mut channel = configured_channel(InternalRate::Wide16k, 20);
        let mut control = DecoderControl::new();
        control.gains_q16 = [1 << 16; MAX_NB_SUBFR];
        control.pitch_lags = [80; MAX_NB_SUBFR];
        control.ltp_scale_q14 = 15565;
        // One unit tap in the middle: the predictor copies the sample exactly one lag back.
        for subframe in 0..MAX_NB_SUBFR {
            control.ltp_coef_q14[subframe * LTP_ORDER + LTP_ORDER / 2] = 1 << 14;
        }
        let mut scratch = CoreScratch::new();
        // A single impulse in the first subframe.
        channel.excitation_q14[0] = 1 << 20;
        let mut xq = [0i16; MAX_FRAME_LENGTH];
        decode_core(
            &mut channel,
            &mut control,
            SignalType::Voiced,
            false,
            &mut xq,
            &mut scratch,
        )
        .expect("synthesis");
        assert_ne!(xq[0], 0, "the impulse itself");
        assert_ne!(xq[80], 0, "and its echo one pitch period later");
        assert_ne!(xq[160], 0, "and the next");
    }

    #[test]
    fn output_history_slides_by_the_frame_length() {
        let mut channel = configured_channel(InternalRate::Narrow8k, 20);
        // 8 kHz: ltp_mem_length == frame_length == 160, so the whole history is replaced.
        for (index, slot) in channel.out_buf[..160].iter_mut().enumerate() {
            *slot = index as i16;
        }
        let frame: Vec<i16> = (1000..1160).collect();
        update_output_history(&mut channel, &frame).expect("history");
        assert_eq!(&channel.out_buf[..160], &frame[..]);

        // 10 ms at 8 kHz: 80 new samples, so half the history survives, shifted down.
        let mut channel = configured_channel(InternalRate::Narrow8k, 10);
        for (index, slot) in channel.out_buf[..160].iter_mut().enumerate() {
            *slot = index as i16;
        }
        let frame: Vec<i16> = (1000..1080).collect();
        update_output_history(&mut channel, &frame).expect("history");
        for index in 0..80 {
            assert_eq!(channel.out_buf[index], (index + 80) as i16);
        }
        assert_eq!(&channel.out_buf[80..160], &frame[..]);
    }

    #[test]
    fn decode_core_rejects_a_short_output_buffer() {
        let mut channel = configured_channel(InternalRate::Wide16k, 20);
        let mut control = DecoderControl::new();
        control.gains_q16 = [1 << 16; MAX_NB_SUBFR];
        let mut scratch = CoreScratch::new();
        let mut xq = [0i16; 16];
        assert!(decode_core(
            &mut channel,
            &mut control,
            SignalType::Unvoiced,
            false,
            &mut xq,
            &mut scratch,
        )
        .is_err());
    }

    #[test]
    fn decoder_control_taps_are_subframe_major() {
        let mut control = DecoderControl::new();
        for subframe in 0..MAX_NB_SUBFR {
            for tap in 0..LTP_ORDER {
                control.ltp_coef_q14[subframe * LTP_ORDER + tap] = (subframe * 10 + tap) as i16;
            }
        }
        for subframe in 0..MAX_NB_SUBFR {
            let taps = control.ltp_taps_q14(subframe);
            assert_eq!(taps.len(), LTP_ORDER);
            for (tap, &value) in taps.iter().enumerate() {
                assert_eq!(value, (subframe * 10 + tap) as i16);
            }
        }
    }
}
