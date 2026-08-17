//! Gain processing — the limiter, the quantiser, and the rate-distortion lambda (libopus
//! `silk/float/process_gains_FLP.c`, `silk/gain_quant.c`).
//!
//! The noise-shaping analysis produces an *initial* gain per subframe: the residual level the
//! shaping filter implies. This stage turns that into the gain the bitstream actually carries.
//!
//! Three things happen, and each is a real decision rather than a scaling:
//!
//! 1. **Gain reduction on a strongly predicted frame** — a high LTP prediction gain means the
//!    quantiser has less work to do, so the gain is pulled down by up to half through a sigmoid on
//!    `LTPredCodGain - 12` dB.
//! 2. **A soft ceiling on residual-energy-to-gain** — `sqrt(g^2 + ResNrg * k)` with `k` derived from
//!    the target SNR. This is what keeps a subframe whose LPC filter predicted badly from being
//!    coded with a gain so small that the excitation clips.
//! 3. **Scalar quantisation with hysteresis** ([`gains_quant`]), on a uniform log scale, delta-coded
//!    against the previous subframe. It has to invert [`crate::opus::silk::gains::dequantize_gains`]
//!    exactly, and it does so by construction: both end at
//!    [`crate::opus::silk::gains::log_gain_to_q16`].
//!
//! [`process_gains`] also computes `Lambda`, the rate-distortion weight the noise-shaping quantiser
//! runs on. It is produced here rather than in [`super::noise_shape`] because two of its six terms
//! (the quantisation offset, and the coding quality) are only settled once the gains are.
//!
//! # Seam for the rate control
//!
//! `silk_encode_frame_FLP`'s bitrate loop re-enters the encoder **at this function**, not at the
//! pitch analysis: it scales `GainsUnq_Q16` by a trial multiplier, re-quantises, and re-runs the
//! NSQ until the frame fits. [`ProcessedGains::unquantized_q16`] and
//! [`ProcessedGains::previous_index_before`] exist for exactly that loop — they are what it needs to
//! restart from a clean state on the next iteration. Neither is used here, and neither is
//! speculative: `process_gains_FLP.c:71-72` stores both for the same reason.

use crate::opus::silk::enc::fixed::lin2log;
use crate::opus::silk::enc::float::sigmoid;
use crate::opus::silk::fixed::{limit_int, smulwb};
use crate::opus::silk::gains::log_gain_to_q16;
use crate::opus::silk::types::{
    QuantOffsetType, SignalType, MAX_DELTA_GAIN_QUANT, MAX_NB_SUBFR, MAX_QGAIN_DB,
    MIN_DELTA_GAIN_QUANT, MIN_QGAIN_DB, N_LEVELS_QGAIN,
};

/// `OFFSET` (`gain_quant.c:34`) — `(MIN_QGAIN_DB * 128) / 6 + 16 * 128`, i.e. 2090 in Q7.
const GAIN_OFFSET_Q7: i32 = (MIN_QGAIN_DB * 128) / 6 + 16 * 128;

/// `SCALE_Q16` (`gain_quant.c:35`) — the forward map from Q7 log-gain to index, the reciprocal of
/// the decoder's `INV_SCALE_Q16`. The inner `/ 6` truncates before the multiply, exactly as in the C.
const SCALE_Q16: i32 = (65536 * (N_LEVELS_QGAIN - 1)) / (((MAX_QGAIN_DB - MIN_QGAIN_DB) * 128) / 6);

/// `LAMBDA_OFFSET` (`tuning_parameters.h:138`).
const LAMBDA_OFFSET: f32 = 1.2;
/// `LAMBDA_SPEECH_ACT` (`tuning_parameters.h:139`).
const LAMBDA_SPEECH_ACT: f32 = -0.2;
/// `LAMBDA_DELAYED_DECISIONS` (`tuning_parameters.h:140`).
const LAMBDA_DELAYED_DECISIONS: f32 = -0.05;
/// `LAMBDA_INPUT_QUALITY` (`tuning_parameters.h:141`).
const LAMBDA_INPUT_QUALITY: f32 = -0.1;
/// `LAMBDA_CODING_QUALITY` (`tuning_parameters.h:142`).
const LAMBDA_CODING_QUALITY: f32 = -0.2;
/// `LAMBDA_QUANT_OFFSET` (`tuning_parameters.h:143`).
const LAMBDA_QUANT_OFFSET: f32 = 0.8;

/// `silk_gains_quant(ind, gain_Q16, prev_ind, conditional, nb_subfr)` (`gain_quant.c:39-91`).
///
/// Quantises `gains_q16` in place — on return each entry is the value a decoder will reconstruct —
/// and writes the coded indices. `previous_index` is the running log-gain index and crosses both
/// subframes and frames, so it is `&mut`.
///
/// Two details that are easy to lose and both observable on the wire:
///
/// * **Hysteresis.** After the floor to an index, a value *below* the previous index is bumped back
///   up by one (`gain_quant.c:53-55`). That makes a gain that is drifting downward stick to the
///   previous level for one more step, which costs fewer bits than alternating.
/// * **The doubled step.** Above `2 * MAX_DELTA_GAIN_QUANT - N_LEVELS_QGAIN + prev`, the delta's
///   step size doubles so the top of the 64-level range is reachable at all from a low starting
///   point (`gain_quant.c:68-72`), and the accumulation on the way back out has to double it again
///   (`:77-79`). The decoder does the same in `silk_gains_dequant`.
pub fn gains_quant(
    indices: &mut [i8; MAX_NB_SUBFR],
    gains_q16: &mut [i32; MAX_NB_SUBFR],
    previous_index: &mut i8,
    conditional: bool,
    subframe_count: usize,
) {
    for subframe in 0..subframe_count {
        // Convert to log scale, scale, floor.
        let mut index = smulwb(SCALE_Q16, lin2log(gains_q16[subframe]) - GAIN_OFFSET_Q7);

        // Round towards the previous quantized gain (hysteresis).
        if index < i32::from(*previous_index) {
            index += 1;
        }
        index = limit_int(index, 0, N_LEVELS_QGAIN - 1);

        if subframe == 0 && !conditional {
            // Absolute index, floored so the decoder's own 16-step limiter cannot disagree.
            index = limit_int(
                index,
                i32::from(*previous_index) + MIN_DELTA_GAIN_QUANT,
                N_LEVELS_QGAIN - 1,
            );
            *previous_index = index as i8;
            indices[subframe] = index as i8;
        } else {
            let mut delta = index - i32::from(*previous_index);
            let threshold = 2 * MAX_DELTA_GAIN_QUANT - N_LEVELS_QGAIN + i32::from(*previous_index);
            if delta > threshold {
                delta = threshold + ((delta - threshold + 1) >> 1);
            }
            delta = limit_int(delta, MIN_DELTA_GAIN_QUANT, MAX_DELTA_GAIN_QUANT);

            let mut running = i32::from(*previous_index);
            if delta > threshold {
                running += (delta << 1) - threshold;
                running = running.min(N_LEVELS_QGAIN - 1);
            } else {
                running += delta;
            }
            *previous_index = running as i8;

            // Shift to make the coded symbol non-negative.
            indices[subframe] = (delta - MIN_DELTA_GAIN_QUANT) as i8;
        }

        // Scale and convert back to a linear gain — the decoder's own map.
        gains_q16[subframe] = log_gain_to_q16(i32::from(*previous_index));
    }
}

/// Inputs [`process_gains`] takes from stages outside this module.
#[derive(Debug, Clone, Copy)]
pub struct GainProcessingInputs {
    /// `psEncC->SNR_dB_Q7` — the target coding SNR. Owned by the rate control.
    pub snr_db_q7: i32,
    /// `psEncC->subfr_length`.
    pub subframe_length: usize,
    /// `psEncC->nb_subfr`.
    pub subframe_count: usize,
    /// `psEncC->speech_activity_Q8`.
    pub speech_activity_q8: i32,
    /// `psEncC->input_tilt_Q15`.
    pub input_tilt_q15: i32,
    /// `psEncC->nStatesDelayedDecision` — 1..=4 by complexity. The lambda term is genuinely wired:
    /// a deeper NSQ search can afford a lower rate weight.
    pub delayed_decision_states: i32,
    /// `psEncCtrl->input_quality` and `psEncCtrl->coding_quality`, both from
    /// [`super::noise_shape::noise_shape_analysis`].
    pub input_quality: f32,
    /// See [`GainProcessingInputs::input_quality`].
    pub coding_quality: f32,
    /// `psEncCtrl->LTPredCodGain` — from [`super::pred_coefs::find_pred_coefs`].
    pub ltp_prediction_gain_db: f32,
    /// Whether the first subframe's gain is delta-coded (`condCoding == CODE_CONDITIONALLY`).
    pub conditional: bool,
}

/// The output of [`process_gains`].
#[derive(Debug, Clone, Copy)]
pub struct ProcessedGains {
    /// `psEncCtrl->Gains` — the quantised gains as floats, what the NSQ scales the excitation by.
    pub gains: [f32; MAX_NB_SUBFR],
    /// `psEncCtrl->Gains` in Q16, the form `silk_NSQ_wrapper_FLP` converts to.
    pub gains_q16: [i32; MAX_NB_SUBFR],
    /// `psEncC->indices.GainsIndices` — the coded symbols.
    pub indices: [i8; MAX_NB_SUBFR],
    /// `psEncCtrl->GainsUnq_Q16` — the gains *before* quantisation. Kept for the rate-control loop,
    /// which rescales these and re-quantises rather than compounding rounding.
    pub unquantized_q16: [i32; MAX_NB_SUBFR],
    /// `psEncCtrl->lastGainIndexPrev` — the running index as it stood before this frame, so the
    /// rate-control loop can restart the quantiser cleanly.
    pub previous_index_before: i8,
    /// `psEncC->indices.quantOffsetType` — decided here for a voiced frame, and left as the
    /// noise-shaping analysis set it otherwise.
    pub quant_offset_type: QuantOffsetType,
    /// `psEncCtrl->Lambda` — the rate-distortion weight the NSQ runs on.
    pub lambda: f32,
}

/// `silk_process_gains_FLP(psEnc, psEncCtrl, condCoding)` (`process_gains_FLP.c:36-103`).
///
/// `gains` are the initial gains from the noise-shaping analysis and `residual_energy` the
/// per-subframe residual energies from [`super::pred_coefs::find_pred_coefs`].
/// `previous_gain_index` is the running log-gain index and is updated in place.
///
/// `quant_offset_type` comes in as the noise-shaping analysis' sparseness verdict and is
/// **overruled here for a voiced frame** (`process_gains_FLP.c:84-90`): a voiced frame with a low
/// LTP gain or a strongly low-passed input gets the larger offset. The C's own comment at
/// `noise_shape_analysis_FLP.c:197` says "may be overruled in process_gains", which is why it is
/// threaded through rather than decided twice.
#[must_use]
pub fn process_gains(
    gains: &[f32; MAX_NB_SUBFR],
    residual_energy: &[f32; MAX_NB_SUBFR],
    signal_type: SignalType,
    quant_offset_type: QuantOffsetType,
    previous_gain_index: &mut i8,
    inputs: &GainProcessingInputs,
) -> ProcessedGains {
    let mut working = *gains;

    // Gain reduction when the LTP coding gain is high.
    if signal_type == SignalType::Voiced {
        let scale = 1.0 - 0.5 * sigmoid(0.25 * (inputs.ltp_prediction_gain_db - 12.0));
        for gain in working.iter_mut().take(inputs.subframe_count) {
            *gain *= scale;
        }
    }

    // Soft limit on the ratio of residual energy to squared gain.
    let inverse_max_square = (2.0f64.powf(f64::from(
        0.33f32 * (21.0 - inputs.snr_db_q7 as f32 * (1.0 / 128.0)),
    )) / inputs.subframe_length as f64) as f32;
    for subframe in 0..inputs.subframe_count {
        let gain = working[subframe];
        let limited = (gain * gain + residual_energy[subframe] * inverse_max_square).sqrt();
        working[subframe] = limited.min(32_767.0);
    }

    // The C uses a plain cast here, i.e. truncation toward zero — not `lrintf`.
    let mut gains_q16 = [0i32; MAX_NB_SUBFR];
    for subframe in 0..inputs.subframe_count {
        gains_q16[subframe] = (working[subframe] * 65_536.0) as i32;
    }

    let unquantized_q16 = gains_q16;
    let previous_index_before = *previous_gain_index;

    let mut indices = [0i8; MAX_NB_SUBFR];
    gains_quant(
        &mut indices,
        &mut gains_q16,
        previous_gain_index,
        inputs.conditional,
        inputs.subframe_count,
    );

    for subframe in 0..inputs.subframe_count {
        working[subframe] = gains_q16[subframe] as f32 / 65_536.0;
    }

    // Quantizer offset for voiced signals: a larger offset when the LTP coding gain is low or the
    // input is strongly tilted (low-pass).
    let quant_offset_type = if signal_type == SignalType::Voiced {
        if inputs.ltp_prediction_gain_db + inputs.input_tilt_q15 as f32 * (1.0 / 32768.0) > 1.0 {
            QuantOffsetType::Low
        } else {
            QuantOffsetType::High
        }
    } else {
        quant_offset_type
    };

    let offset = f32::from(quant_offset_type.offset_q10(signal_type)) / 1024.0;
    let lambda = LAMBDA_OFFSET
        + LAMBDA_DELAYED_DECISIONS * inputs.delayed_decision_states as f32
        + LAMBDA_SPEECH_ACT * inputs.speech_activity_q8 as f32 * (1.0 / 256.0)
        + LAMBDA_INPUT_QUALITY * inputs.input_quality
        + LAMBDA_CODING_QUALITY * inputs.coding_quality
        + LAMBDA_QUANT_OFFSET * offset;
    debug_assert!(
        lambda > 0.0 && lambda < 2.0,
        "silk enc: lambda out of range"
    );

    ProcessedGains {
        gains: working,
        gains_q16,
        indices,
        unquantized_q16,
        previous_index_before,
        quant_offset_type,
        lambda,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::gains::{dequantize_gains, GainIndices};
    use proptest::prelude::*;

    fn default_inputs() -> GainProcessingInputs {
        GainProcessingInputs {
            snr_db_q7: 2600,
            subframe_length: 80,
            subframe_count: 4,
            speech_activity_q8: 200,
            input_tilt_q15: 0,
            delayed_decision_states: 2,
            input_quality: 0.7,
            coding_quality: 0.5,
            ltp_prediction_gain_db: 0.0,
            conditional: false,
        }
    }

    /// The inverse check that matters most here: whatever [`gains_quant`] writes must dequantise,
    /// through the **decoder's** `silk_gains_dequant`, to exactly the gains it reported. Both the
    /// gains and the running index have to agree, because the next frame's first delta is measured
    /// against that index.
    #[test]
    fn quantised_gain_indices_dequantise_to_the_same_gains() {
        for conditional in [false, true] {
            for source in [
                [100_000i32, 200_000, 400_000, 800_000],
                [1_686_110_208, 81_920, 81_920, 1_686_110_208],
                [5_000_000; 4],
            ] {
                let mut encoder_index = 20i8;
                let mut gains = source;
                let mut indices = [0i8; MAX_NB_SUBFR];
                gains_quant(&mut indices, &mut gains, &mut encoder_index, conditional, 4);

                let mut decoder_index = 20i8;
                let decoded = dequantize_gains(
                    &GainIndices {
                        indices,
                        count: 4,
                        conditional,
                    },
                    &mut decoder_index,
                );
                assert_eq!(decoded.gains_q16, gains, "conditional {conditional}");
                assert_eq!(
                    decoder_index, encoder_index,
                    "running index diverged, conditional {conditional}"
                );
            }
        }
    }

    /// Every coded symbol has to be inside the alphabet the decoder's entropy tables can express:
    /// 0..=63 for an absolute first index, 0..=40 for every delta.
    #[test]
    fn coded_gain_symbols_are_inside_the_decoder_s_alphabets() {
        let mut index = 0i8;
        let mut gains = [81_920i32, 1_686_110_208, 81_920, 500_000];
        let mut indices = [0i8; MAX_NB_SUBFR];
        gains_quant(&mut indices, &mut gains, &mut index, false, 4);
        assert!(
            (0..64).contains(&i32::from(indices[0])),
            "absolute index {} out of range",
            indices[0]
        );
        for &delta in &indices[1..4] {
            let span = MAX_DELTA_GAIN_QUANT - MIN_DELTA_GAIN_QUANT;
            assert!(
                (0..=span).contains(&i32::from(delta)),
                "delta symbol {delta} out of 0..={span}"
            );
        }
    }

    /// The hysteresis is what makes a slowly falling gain hold its level for one extra step. Pin it
    /// directly: a gain just under the previous level's boundary must not drop an index.
    #[test]
    fn the_hysteresis_holds_a_falling_gain_for_one_step() {
        // Quantise a gain, then quantise something marginally smaller from the same index.
        let mut index = 30i8;
        let mut gains = [log_gain_to_q16(30); MAX_NB_SUBFR];
        let mut indices = [0i8; MAX_NB_SUBFR];
        gains_quant(&mut indices, &mut gains, &mut index, false, 1);
        assert_eq!(index, 30, "an exact level must round to itself");

        let mut index = 30i8;
        let mut gains = [log_gain_to_q16(30) - 1; MAX_NB_SUBFR];
        gains_quant(&mut indices, &mut gains, &mut index, false, 1);
        assert_eq!(
            index, 30,
            "a gain a hair below the level must stay on it, not drop"
        );
    }

    /// The step-size doubling is what makes the top of the range reachable. From index 0, a single
    /// delta must be able to climb past `MAX_DELTA_GAIN_QUANT` levels.
    #[test]
    fn the_doubled_step_reaches_the_top_of_the_range() {
        let mut index = 0i8;
        let mut gains = [log_gain_to_q16(63); MAX_NB_SUBFR];
        let mut indices = [0i8; MAX_NB_SUBFR];
        // Conditional, so the first subframe is delta-coded too.
        gains_quant(&mut indices, &mut gains, &mut index, true, 1);
        assert!(
            i32::from(index) > MAX_DELTA_GAIN_QUANT,
            "a single delta only reached index {index}"
        );

        // ...and the decoder follows it there.
        let mut decoder_index = 0i8;
        let decoded = dequantize_gains(
            &GainIndices {
                indices,
                count: 1,
                conditional: true,
            },
            &mut decoder_index,
        );
        assert_eq!(decoder_index, index);
        assert_eq!(decoded.gains_q16[0], gains[0]);
    }

    /// An independently coded first gain is not allowed to drop more than four steps below the
    /// previous index (`MIN_DELTA_GAIN_QUANT`), so a sudden silence still costs a few frames to
    /// reach the floor.
    #[test]
    fn an_absolute_gain_cannot_drop_more_than_the_minimum_delta() {
        let mut index = 40i8;
        let mut gains = [log_gain_to_q16(0); MAX_NB_SUBFR];
        let mut indices = [0i8; MAX_NB_SUBFR];
        gains_quant(&mut indices, &mut gains, &mut index, false, 1);
        assert_eq!(i32::from(index), 40 + MIN_DELTA_GAIN_QUANT);
    }

    /// A high LTP prediction gain must pull the gains down — up to a factor of two — because the
    /// long-term predictor has already removed most of the energy.
    #[test]
    fn a_high_ltp_gain_reduces_the_subframe_gains() {
        let mut index = 20i8;
        let low = process_gains(
            &[1000.0; MAX_NB_SUBFR],
            &[0.0; MAX_NB_SUBFR],
            SignalType::Voiced,
            QuantOffsetType::Low,
            &mut index,
            &GainProcessingInputs {
                ltp_prediction_gain_db: 0.0,
                ..default_inputs()
            },
        );
        let mut index = 20i8;
        let high = process_gains(
            &[1000.0; MAX_NB_SUBFR],
            &[0.0; MAX_NB_SUBFR],
            SignalType::Voiced,
            QuantOffsetType::Low,
            &mut index,
            &GainProcessingInputs {
                ltp_prediction_gain_db: 40.0,
                ..default_inputs()
            },
        );
        assert!(
            high.gains[0] < low.gains[0],
            "a high LTP gain did not reduce the gain: {} vs {}",
            high.gains[0],
            low.gains[0]
        );
        // The sigmoid bottoms out at half.
        assert!(high.gains[0] > low.gains[0] * 0.4);
    }

    /// An unvoiced frame is not touched by the LTP reduction and keeps the noise-shaping
    /// analysis' quantisation-offset verdict.
    #[test]
    fn an_unvoiced_frame_keeps_the_shaping_analysis_offset() {
        for offset in [QuantOffsetType::Low, QuantOffsetType::High] {
            let mut index = 20i8;
            let result = process_gains(
                &[1000.0; MAX_NB_SUBFR],
                &[0.0; MAX_NB_SUBFR],
                SignalType::Unvoiced,
                offset,
                &mut index,
                &GainProcessingInputs {
                    ltp_prediction_gain_db: 40.0,
                    ..default_inputs()
                },
            );
            assert_eq!(result.quant_offset_type, offset);
        }
    }

    /// A voiced frame with a low LTP gain and no tilt takes the *high* offset; the same frame with
    /// a high LTP gain takes the low one. Both branches of `process_gains_FLP.c:85-89`.
    #[test]
    fn a_voiced_frame_picks_its_own_quantisation_offset() {
        let mut index = 20i8;
        let weak = process_gains(
            &[1000.0; MAX_NB_SUBFR],
            &[0.0; MAX_NB_SUBFR],
            SignalType::Voiced,
            QuantOffsetType::Low,
            &mut index,
            &GainProcessingInputs {
                ltp_prediction_gain_db: 0.0,
                ..default_inputs()
            },
        );
        assert_eq!(weak.quant_offset_type, QuantOffsetType::High);

        let mut index = 20i8;
        let strong = process_gains(
            &[1000.0; MAX_NB_SUBFR],
            &[0.0; MAX_NB_SUBFR],
            SignalType::Voiced,
            QuantOffsetType::High,
            &mut index,
            &GainProcessingInputs {
                ltp_prediction_gain_db: 20.0,
                ..default_inputs()
            },
        );
        assert_eq!(strong.quant_offset_type, QuantOffsetType::Low);
    }

    /// The residual-energy soft limit must raise the gain when the LPC filter predicted badly —
    /// that is the whole point of `sqrt(g^2 + ResNrg * k)`.
    #[test]
    fn a_large_residual_energy_raises_the_gain() {
        let mut index = 20i8;
        let clean = process_gains(
            &[100.0; MAX_NB_SUBFR],
            &[0.0; MAX_NB_SUBFR],
            SignalType::Unvoiced,
            QuantOffsetType::Low,
            &mut index,
            &default_inputs(),
        );
        let mut index = 20i8;
        let noisy = process_gains(
            &[100.0; MAX_NB_SUBFR],
            &[1e9; MAX_NB_SUBFR],
            SignalType::Unvoiced,
            QuantOffsetType::Low,
            &mut index,
            &default_inputs(),
        );
        assert!(
            noisy.gains[0] > clean.gains[0],
            "residual energy did not raise the gain: {} vs {}",
            noisy.gains[0],
            clean.gains[0]
        );
    }

    /// Lambda must move with every input the C feeds it, and stay inside the range the C asserts.
    #[test]
    fn lambda_responds_to_each_of_its_terms() {
        let base_inputs = default_inputs();
        let evaluate = |inputs: GainProcessingInputs, offset: QuantOffsetType| -> f32 {
            let mut index = 20i8;
            process_gains(
                &[1000.0; MAX_NB_SUBFR],
                &[0.0; MAX_NB_SUBFR],
                SignalType::Unvoiced,
                offset,
                &mut index,
                &inputs,
            )
            .lambda
        };

        let base = evaluate(base_inputs, QuantOffsetType::Low);
        assert!(base > 0.0 && base < 2.0, "lambda {base}");

        // More speech activity lowers it (LAMBDA_SPEECH_ACT is negative).
        assert!(
            evaluate(
                GainProcessingInputs {
                    speech_activity_q8: 256,
                    ..base_inputs
                },
                QuantOffsetType::Low
            ) < base
        );
        // More delayed-decision states lower it.
        assert!(
            evaluate(
                GainProcessingInputs {
                    delayed_decision_states: 4,
                    ..base_inputs
                },
                QuantOffsetType::Low
            ) < base
        );
        // Better input quality lowers it.
        assert!(
            evaluate(
                GainProcessingInputs {
                    input_quality: 1.0,
                    ..base_inputs
                },
                QuantOffsetType::Low
            ) < base
        );
        // Better coding quality lowers it.
        assert!(
            evaluate(
                GainProcessingInputs {
                    coding_quality: 1.0,
                    ..base_inputs
                },
                QuantOffsetType::Low
            ) < base
        );
        // A larger quantisation offset raises it.
        assert!(evaluate(base_inputs, QuantOffsetType::High) > base);
    }

    proptest! {
        /// The encoder and decoder must agree on both the gains and the running index for *any*
        /// input gains and any starting index — this is the invariant a desynchronised gain ladder
        /// would break, and it would corrupt every subsequent frame, not just this one.
        #[test]
        fn gain_quantisation_always_inverts(
            raw in prop::collection::vec(81_920i32..1_686_110_208, 4..=4),
            start in 0i8..=63,
            conditional: bool,
        ) {
            let mut gains = [raw[0], raw[1], raw[2], raw[3]];
            let mut encoder_index = start;
            let mut indices = [0i8; MAX_NB_SUBFR];
            gains_quant(&mut indices, &mut gains, &mut encoder_index, conditional, 4);

            prop_assert!((0..64).contains(&i32::from(indices[0])) || conditional);
            for &symbol in &indices[usize::from(!conditional)..4] {
                let span = MAX_DELTA_GAIN_QUANT - MIN_DELTA_GAIN_QUANT;
                prop_assert!((0..=span).contains(&i32::from(symbol)), "symbol {}", symbol);
            }

            let mut decoder_index = start;
            let decoded = dequantize_gains(
                &GainIndices { indices, count: 4, conditional },
                &mut decoder_index,
            );
            prop_assert_eq!(decoded.gains_q16, gains);
            prop_assert_eq!(decoder_index, encoder_index);
            prop_assert!((0..64).contains(&i32::from(encoder_index)));
        }
    }
}
