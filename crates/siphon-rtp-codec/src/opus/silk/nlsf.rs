//! Normalized line spectral frequencies (RFC 6716 §4.2.7.5) — the SILK frame's short-term spectral
//! envelope, from two entropy-coded stages to the Q12 LPC coefficients the synthesis filter runs.
//!
//! The stage sequence, and where each piece lives:
//!
//! ```text
//!   §4.2.7.5.1  stage-1 codebook index           decode_indices.c:80        decode_indices()
//!   §4.2.7.5.2  stage-2 residual, per coefficient decode_indices.c:83-91    decode_indices()
//!   §4.2.7.5.3  backward prediction + rescale     NLSF_decode.c:35-89       decode()
//!   §4.2.7.5.4  stabilisation (minimum spacing)   NLSF_stabilize.c:47-142   stabilize()
//!   §4.2.7.5.5  interpolation with the previous   decode_parameters.c:63-76 interpolate()
//!   §4.2.7.5.8  NLSF -> LPC, Q12                  NLSF2A.c:66-140           super::lpc
//! ```
//!
//! Three properties of this stage are worth stating up front, because they are the ones that make it
//! subtle rather than merely long:
//!
//! * **Stage 2 is backward-predicted.** [`residual_dequant`] walks the coefficients from the *highest*
//!   index down, and each one's dequantized value feeds the prediction of the one below it. A single
//!   wrong residual therefore shifts every lower coefficient too, so a mismatch localises poorly —
//!   which is why the conformance harness diffs the raw residual vector, not just the final NLSFs.
//! * **The entropy table and prediction weight for each coefficient are chosen by the *stage-1*
//!   index.** [`unpack`] reads a packed byte per coefficient pair (`NLSF_unpack.c:46-53`); getting
//!   that wrong reads the right number of symbols with the wrong distributions, which desynchronises
//!   the range decoder some symbols later rather than immediately.
//! * **Stabilisation is not a safety net, it is part of the format.** RFC 6716 §4.2.7.5.4 requires
//!   the decoder to enforce a minimum spacing between coefficients; the reconstructed vector is
//!   routinely *not* sorted, and the encoder relies on the decoder fixing it the same way. So
//!   [`stabilize`] reproduces `silk_NLSF_stabilize` exactly, including its 20-iteration budget and
//!   the sort-based fallback that runs when the budget is exhausted.

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::decoder::SilkDecoder;
use crate::opus::silk::fixed::{add_sat16, rshift_round, smlawb, smulbb};
use crate::opus::silk::lpc::{bwexpander_q12, nlsf_to_lpc_q12, BWE_AFTER_LOSS_Q16};
use crate::opus::silk::nlsf_tables::{
    NlsfCodebook, NLSF_EXT_ICDF, NLSF_INTERPOLATION_FACTOR_ICDF, NLSF_QUANT_MAX_AMPLITUDE,
};
use crate::opus::silk::types::{InternalRate, SignalType, MAX_LPC_ORDER, MAX_NB_SUBFR};
use crate::CodecError;

/// `ftb` for every SILK ICDF symbol: total frequency 256.
const ICDF_FTB: u32 = 8;

/// Coded indices per NLSF vector: the stage-1 index plus one stage-2 residual per coefficient
/// (`SideInfoIndices.NLSFIndices[MAX_LPC_ORDER + 1]`, `structs.h:359`).
pub const MAX_NLSF_INDICES: usize = MAX_LPC_ORDER + 1;

/// `SILK_FIX_CONST(NLSF_QUANT_LEVEL_ADJ, 10)` — 0.1 in Q10 (`define.h:210`), the dead-zone
/// correction pulled out of every non-zero stage-2 residual (`NLSF_decode.c:50-53`).
const QUANT_LEVEL_ADJUST_Q10: i32 = 102;

/// The interpolation factor of a frame that is **not** interpolated: full weight on the current
/// vector (`decode_indices.c:97`, `decode_parameters.c:60`).
pub const NO_INTERPOLATION_Q2: i8 = 4;

/// `MAX_LOOPS` (`NLSF_stabilize.c:44`) — stabilisation attempts before the sorting fallback.
const MAX_STABILIZE_LOOPS: usize = 20;

/// The coded NLSF indices of one SILK frame (libopus `SideInfoIndices.NLSFIndices` plus
/// `NLSFInterpCoef_Q2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlsfIndices {
    /// `NLSFIndices[0]` is the stage-1 codebook index (0..=31); `NLSFIndices[1..=order]` are the
    /// stage-2 residuals, each in `-10..=10`. Entries past `order` are 0.
    pub indices: [i8; MAX_NLSF_INDICES],
    /// LPC order — 10 (NB/MB) or 16 (WB); also the number of stage-2 residuals.
    pub order: usize,
    /// `NLSFInterpCoef_Q2` — weight on the current frame's vector when interpolating the first
    /// half of the frame, 0..=4. Always [`NO_INTERPOLATION_Q2`] for a two-subframe (10 ms) frame,
    /// where the symbol is not coded at all.
    pub interpolation_factor_q2: i8,
}

impl NlsfIndices {
    /// The stage-1 codebook index (`NLSFIndices[0]`).
    #[must_use]
    pub fn stage1_index(&self) -> usize {
        // The stage-1 symbol comes from a 32-entry ICDF, so it is always 0..=31.
        self.indices[0].max(0) as usize
    }

    /// The stage-2 residual indices, `order` of them.
    #[must_use]
    pub fn stage2_residuals(&self) -> &[i8] {
        &self.indices[1..=self.order]
    }
}

/// Both Q12 LPC coefficient sets of one SILK frame (libopus `silk_decoder_control.PredCoef_Q12`,
/// `structs.h:344`).
///
/// SILK runs **two** short-term filters per 20 ms frame: subframes 0..1 use
/// [`LpcCoefficients::first_half_q12`] and subframes 2..3 use
/// [`LpcCoefficients::second_half_q12`] (`decode_core.c`). They are equal whenever the frame is not
/// interpolated — a 10 ms frame, the first frame after a reset, or a coded factor of 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpcCoefficients {
    /// `PredCoef_Q12[0]` — the filter for the first half of the frame.
    pub first_half_q12: [i16; MAX_LPC_ORDER],
    /// `PredCoef_Q12[1]` — the filter for the second half, from the current frame's own NLSFs.
    pub second_half_q12: [i16; MAX_LPC_ORDER],
    /// The stabilised NLSFs the second half was built from, in Q15. This is what the *next* frame
    /// interpolates against, so it is returned rather than hidden.
    pub nlsf_q15: [i16; MAX_LPC_ORDER],
    /// LPC order — only `..order` of the arrays above is meaningful.
    pub order: usize,
    /// The interpolation factor actually applied, after the first-frame-after-reset override
    /// (`decode_parameters.c:59-61`). [`NO_INTERPOLATION_Q2`] means the two halves are identical.
    pub interpolation_factor_q2: i8,
}

/// The per-coefficient entropy table and prediction weight a stage-1 index selects
/// (libopus `silk_NLSF_unpack`, `NLSF_unpack.c:35-54`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unpacked {
    /// Which of the eight stage-2 residual PDFs codes each coefficient. The C stores this as a byte
    /// *offset* into the flat `ec_iCDF` table (`ec_ix[i] = pdf_index * 9`); the index is kept here
    /// instead, since [`NlsfCodebook::stage2_icdf`] does the multiply.
    pub pdf_index: [usize; MAX_LPC_ORDER],
    /// The backward prediction weight in Q8 for each coefficient.
    pub prediction_q8: [u8; MAX_LPC_ORDER],
}

/// Unpack the stage-2 entropy tables and prediction weights for a stage-1 index (libopus
/// `silk_NLSF_unpack`, `NLSF_unpack.c:35-54`).
///
/// One packed byte covers a coefficient *pair*: bits 1..3 and 5..7 are the two PDF indices, bits 0
/// and 4 pick prediction weight set 0 or 1. Note the asymmetry in the C's weight lookup — the even
/// coefficient reads `pred_Q8[i + set * (order - 1)]` and the odd one
/// `pred_Q8[i + set * (order - 1) + 1]`, so the two halves of `pred_Q8` overlap by one entry rather
/// than being two independent vectors.
#[must_use]
pub fn unpack(codebook: &NlsfCodebook, stage1_index: usize) -> Unpacked {
    let order = codebook.order;
    let mut pdf_index = [0usize; MAX_LPC_ORDER];
    let mut prediction_q8 = [0u8; MAX_LPC_ORDER];
    // The stage-1 index comes from a `vector_count`-entry ICDF, so this cannot run off the table;
    // clamping keeps a caller-constructed `NlsfIndices` from indexing out of bounds.
    let stage1_index = stage1_index.min(codebook.vector_count - 1);
    let select = &codebook.ec_select[stage1_index * order / 2..][..order / 2];

    for (pair, &entry) in select.iter().enumerate() {
        let low = 2 * pair;
        pdf_index[low] = usize::from((entry >> 1) & 7);
        prediction_q8[low] = codebook.prediction_q8[low + usize::from(entry & 1) * (order - 1)];
        pdf_index[low + 1] = usize::from((entry >> 5) & 7);
        prediction_q8[low + 1] =
            codebook.prediction_q8[low + usize::from((entry >> 4) & 1) * (order - 1) + 1];
    }
    Unpacked {
        pdf_index,
        prediction_q8,
    }
}

/// Decode one frame's NLSF indices (RFC 6716 §4.2.7.5.1-2, §4.2.7.5.5; libopus
/// `decode_indices.c:77-98`).
///
/// `signal_type` selects the stage-1 PDF row (inactive and unvoiced share one; voiced has its own).
/// `subframe_count` is `nb_subfr`: the interpolation factor is only coded for a four-subframe frame,
/// and is [`NO_INTERPOLATION_Q2`] otherwise — reading it "just in case" would consume bits that are
/// not there and desynchronise everything after it.
pub fn decode_indices(
    decoder: &mut RangeDecoder<'_>,
    rate: InternalRate,
    signal_type: SignalType,
    subframe_count: usize,
) -> Result<NlsfIndices, CodecError> {
    if subframe_count == 0 || subframe_count > MAX_NB_SUBFR {
        return Err(CodecError::Unsupported(
            "silk: subframe count must be 1..=4",
        ));
    }
    let codebook = NlsfCodebook::for_rate(rate);
    let order = codebook.order;
    let mut indices = [0i8; MAX_NLSF_INDICES];

    // Stage 1: one index into the 32-entry codebook (decode_indices.c:80).
    let stage1_index = decoder.dec_icdf(codebook.stage1_icdf(signal_type.index()), ICDF_FTB);
    // 0..=31 always fits i8.
    indices[0] = stage1_index as i8;

    // Stage 2: one residual per coefficient, from the PDF the stage-1 index selects.
    let unpacked = unpack(codebook, stage1_index);
    for coefficient in 0..order {
        let mut value = decoder.dec_icdf(
            codebook.stage2_icdf(unpacked.pdf_index[coefficient]),
            ICDF_FTB,
        ) as i32;
        // An index that saturates at either end of the 9-symbol alphabet carries an extension
        // symbol (decode_indices.c:85-89), which is how the ±4 range reaches ±10.
        if value == 0 {
            value -= decoder.dec_icdf(&NLSF_EXT_ICDF, ICDF_FTB) as i32;
        } else if value == 2 * NLSF_QUANT_MAX_AMPLITUDE {
            value += decoder.dec_icdf(&NLSF_EXT_ICDF, ICDF_FTB) as i32;
        }
        // -10..=10 always fits i8.
        indices[coefficient + 1] = (value - NLSF_QUANT_MAX_AMPLITUDE) as i8;
    }

    // The interpolation weight, for four-subframe frames only (decode_indices.c:94-98).
    let interpolation_factor_q2 = if subframe_count == MAX_NB_SUBFR {
        decoder.dec_icdf(&NLSF_INTERPOLATION_FACTOR_ICDF, ICDF_FTB) as i8
    } else {
        NO_INTERPOLATION_Q2
    };

    Ok(NlsfIndices {
        indices,
        order,
        interpolation_factor_q2,
    })
}

/// Dequantize the stage-2 residuals with backward prediction (RFC 6716 §4.2.7.5.3; libopus
/// `silk_NLSF_residual_dequant`, `NLSF_decode.c:35-57`).
///
/// Runs from the **highest** coefficient down: each dequantized value predicts the next lower one
/// through that coefficient's Q8 weight. Every non-zero index also gives back 0.1 quantizer steps
/// (`NLSF_QUANT_LEVEL_ADJ`, 0.1 in Q10) — the dead zone the encoder's quantizer left around zero.
///
/// Writes `order` values in Q10 into `residual_q10`.
pub fn residual_dequant(
    residual_q10: &mut [i16],
    residual_indices: &[i8],
    prediction_q8: &[u8],
    quant_step_size_q16: i32,
) {
    let order = residual_q10.len();
    let mut previous_q10: i32 = 0;
    for coefficient in (0..order).rev() {
        let predicted_q10 = smulbb(previous_q10, i32::from(prediction_q8[coefficient])) >> 8;
        let mut value_q10 = i32::from(residual_indices[coefficient]) << 10;
        if value_q10 > 0 {
            value_q10 -= QUANT_LEVEL_ADJUST_Q10;
        } else if value_q10 < 0 {
            value_q10 += QUANT_LEVEL_ADJUST_Q10;
        }
        previous_q10 = smlawb(predicted_q10, value_q10, quant_step_size_q16);
        // The C stores into an `opus_int16` array while the recursion keeps the full `opus_int`
        // value, so the narrowing is on the *output* only (NLSF_decode.c:55).
        residual_q10[coefficient] = previous_q10 as i16;
    }
}

/// Reconstruct the normalized LSFs from the stage-1 codebook vector and the dequantized stage-2
/// residual (RFC 6716 §4.2.7.5.3; libopus `NLSF_decode.c:83-89`), **before** stabilisation.
///
/// The residual is scaled by the reciprocal of the per-coefficient weight the codebook stores —
/// RFC 6716 derives those weights from the codebook vector itself; libopus precomputes them, and
/// [`super::nlsf_tables`] proves the two agree.
fn reconstruct(
    nlsf_q15: &mut [i16],
    codebook: &NlsfCodebook,
    stage1_index: usize,
    residual_q10: &[i16],
) {
    let stage1_index = stage1_index.min(codebook.vector_count - 1);
    let vector_q8 = codebook.cb1_vector_q8(stage1_index);
    let weights_q9 = codebook.cb1_weights_q9(stage1_index);
    for coefficient in 0..codebook.order {
        // silk_ADD_LSHIFT32( silk_DIV32_16( silk_LSHIFT( res_Q10[i], 14 ), wght_Q9[i] ), cb_Q8[i], 7 )
        // The weights are all strictly positive (proved in the table tests), so this cannot divide
        // by zero; the `max(1)` is belt-and-braces against a future table edit, not a deviation.
        let scaled = (i32::from(residual_q10[coefficient]) << 14)
            / i32::from(weights_q9[coefficient].max(1));
        let value = scaled.wrapping_add(i32::from(vector_q8[coefficient]) << 7);
        nlsf_q15[coefficient] = value.clamp(0, 32_767) as i16;
    }
}

/// Enforce the minimum spacing between normalized LSFs (RFC 6716 §4.2.7.5.4; libopus
/// `silk_NLSF_stabilize`, `NLSF_stabilize.c:47-142`).
///
/// The reconstructed vector is regularly out of order or too tightly packed, and an LPC filter built
/// from such a vector is unstable, so this is part of decoding rather than a guard. The algorithm
/// repeatedly finds the *worst* violated spacing and repairs it, keeping the offending pair's centre
/// frequency where it was, for at most `MAX_LOOPS` (20) passes; if that budget runs out it
/// falls back to a sort plus a forward and a backward clamp, which always terminates.
///
/// `delta_min_q15` has `order + 1` entries: `[0]` is the floor below the first coefficient and
/// `[order]` the headroom above the last.
pub fn stabilize(nlsf_q15: &mut [i16], delta_min_q15: &[i16]) {
    let order = nlsf_q15.len();
    if order == 0 || delta_min_q15.len() < order + 1 {
        return;
    }

    for _ in 0..MAX_STABILIZE_LOOPS {
        // Smallest spacing, scanning the lower bound, every gap, then the upper bound.
        let mut smallest = i32::from(nlsf_q15[0]) - i32::from(delta_min_q15[0]);
        let mut position = 0usize;
        for index in 1..order {
            let spacing = i32::from(nlsf_q15[index])
                - (i32::from(nlsf_q15[index - 1]) + i32::from(delta_min_q15[index]));
            if spacing < smallest {
                smallest = spacing;
                position = index;
            }
        }
        let headroom =
            (1 << 15) - (i32::from(nlsf_q15[order - 1]) + i32::from(delta_min_q15[order]));
        if headroom < smallest {
            smallest = headroom;
            position = order;
        }

        if smallest >= 0 {
            return;
        }

        if position == 0 {
            // Push the first coefficient off the lower limit.
            nlsf_q15[0] = delta_min_q15[0];
        } else if position == order {
            // Push the last coefficient off the upper limit.
            nlsf_q15[order - 1] = ((1 << 15) - i32::from(delta_min_q15[order])) as i16;
        } else {
            // Move the offending pair apart around the centre frequency it already had, clamped so
            // the coefficients on either side still have room (NLSF_stabilize.c:98-116).
            let mut lowest_centre: i32 = 0;
            for &delta in &delta_min_q15[..position] {
                lowest_centre += i32::from(delta);
            }
            lowest_centre += i32::from(delta_min_q15[position]) >> 1;

            let mut highest_centre: i32 = 1 << 15;
            for &delta in &delta_min_q15[position + 1..=order] {
                highest_centre -= i32::from(delta);
            }
            highest_centre -= i32::from(delta_min_q15[position]) >> 1;

            // The codebook minimum spacings sum to well under 1.0 in Q15 (a table test proves it),
            // so `lowest_centre <= highest_centre` always holds and this is a plain clamp.
            let centre = rshift_round(
                i32::from(nlsf_q15[position - 1]) + i32::from(nlsf_q15[position]),
                1,
            )
            .clamp(
                lowest_centre.min(highest_centre),
                highest_centre.max(lowest_centre),
            );
            nlsf_q15[position - 1] = (centre - (i32::from(delta_min_q15[position]) >> 1)) as i16;
            nlsf_q15[position] =
                (i32::from(nlsf_q15[position - 1]) + i32::from(delta_min_q15[position])) as i16;
        }
    }

    // Budget exhausted: the "safe and simple fall back" (NLSF_stabilize.c:120-141).
    insertion_sort_increasing(nlsf_q15);
    nlsf_q15[0] = nlsf_q15[0].max(delta_min_q15[0]);
    for index in 1..order {
        nlsf_q15[index] = nlsf_q15[index].max(add_sat16(nlsf_q15[index - 1], delta_min_q15[index]));
    }
    nlsf_q15[order - 1] =
        nlsf_q15[order - 1].min(((1 << 15) - i32::from(delta_min_q15[order])) as i16);
    for index in (0..order - 1).rev() {
        nlsf_q15[index] = nlsf_q15[index]
            .min((i32::from(nlsf_q15[index + 1]) - i32::from(delta_min_q15[index + 1])) as i16);
    }
}

/// `silk_insertion_sort_increasing_all_values_int16` (`sort.c:135-154`).
fn insertion_sort_increasing(values: &mut [i16]) {
    for index in 1..values.len() {
        let value = values[index];
        let mut position = index;
        while position > 0 && value < values[position - 1] {
            values[position] = values[position - 1];
            position -= 1;
        }
        values[position] = value;
    }
}

/// Decode a complete normalized LSF vector: reconstruct, then stabilise (libopus `silk_NLSF_decode`,
/// `NLSF_decode.c:63-93`). Writes `codebook.order` values in Q15 into `nlsf_q15`.
pub fn decode(nlsf_q15: &mut [i16], codebook: &NlsfCodebook, indices: &NlsfIndices) {
    let order = codebook.order;
    let unpacked = unpack(codebook, indices.stage1_index());
    let mut residual_q10 = [0i16; MAX_LPC_ORDER];
    residual_dequant(
        &mut residual_q10[..order],
        &indices.indices[1..=order],
        &unpacked.prediction_q8[..order],
        codebook.quant_step_size_q16,
    );
    reconstruct(
        &mut nlsf_q15[..order],
        codebook,
        indices.stage1_index(),
        &residual_q10[..order],
    );
    stabilize(&mut nlsf_q15[..order], codebook.delta_min_q15);
}

/// Interpolate the first half of the frame's NLSFs between the previous frame's vector and this
/// one's (RFC 6716 §4.2.7.5.5; libopus `decode_parameters.c:63-69`).
///
/// `factor_q2` is the weight on `current`, 0..=4: 0 reuses the previous frame's envelope unchanged
/// and 4 is no interpolation at all. The shift is arithmetic, so a negative difference floors —
/// matching the C, and *not* the same as truncating toward zero.
pub fn interpolate(out_q15: &mut [i16], previous_q15: &[i16], current_q15: &[i16], factor_q2: i8) {
    let factor = i32::from(factor_q2);
    for (index, slot) in out_q15.iter_mut().enumerate() {
        let previous = i32::from(previous_q15[index]);
        let difference = i32::from(current_q15[index]) - previous;
        *slot = previous.wrapping_add((factor.wrapping_mul(difference)) >> 2) as i16;
    }
}

impl SilkDecoder {
    /// Decode one SILK frame's NLSFs and convert them to both halves' Q12 LPC coefficients — the
    /// NLSF half of `silk_decode_indices` + `silk_decode_parameters` (`decode_parameters.c:49-84`),
    /// wired to the channel state it reads and updates.
    ///
    /// Reads [`super::decoder::ChannelState::prev_nlsf_q15`] as the interpolation anchor,
    /// [`super::decoder::ChannelState::first_frame_after_reset`] to suppress interpolation for one
    /// frame after a reset, and [`super::decoder::ChannelState::loss_count`] to bandwidth-expand
    /// after concealment; it writes back `prev_nlsf_q15` for the next frame.
    ///
    /// It deliberately does **not** clear `first_frame_after_reset`: the C clears that at the end of
    /// a successfully decoded *frame* (`decode_frame.c:130`), after synthesis, so that is the
    /// synthesis phase's call to make.
    pub fn decode_nlsf(
        &mut self,
        decoder: &mut RangeDecoder<'_>,
        channel_index: usize,
        signal_type: SignalType,
    ) -> Result<LpcCoefficients, CodecError> {
        let (rate, subframe_count) = {
            let channel = self.channel(channel_index)?;
            (channel.internal_rate()?, channel.subframe_count())
        };
        let indices = decode_indices(decoder, rate, signal_type, subframe_count)?;
        let channel = self.channel_mut(channel_index)?;
        Ok(nlsf_indices_to_lpc(
            &indices,
            rate,
            &mut channel.prev_nlsf_q15,
            channel.first_frame_after_reset,
            channel.loss_count != 0,
        ))
    }
}

/// Turn decoded NLSF indices into both halves' Q12 LPC coefficients (libopus
/// `silk_decode_parameters`, `decode_parameters.c:49-84`), updating the interpolation anchor.
///
/// Split out from [`SilkDecoder::decode_nlsf`] so it can be driven directly from a reference
/// decoder's index dump, with no bitstream and no decoder state.
pub fn nlsf_indices_to_lpc(
    indices: &NlsfIndices,
    rate: InternalRate,
    previous_nlsf_q15: &mut [i16; MAX_LPC_ORDER],
    first_frame_after_reset: bool,
    after_loss: bool,
) -> LpcCoefficients {
    let codebook = NlsfCodebook::for_rate(rate);
    let order = codebook.order;

    let mut nlsf_q15 = [0i16; MAX_LPC_ORDER];
    decode(&mut nlsf_q15, codebook, indices);

    let mut second_half_q12 = [0i16; MAX_LPC_ORDER];
    nlsf_to_lpc_q12(&mut second_half_q12, &nlsf_q15[..order]);

    // "If just reset, e.g., because internal Fs changed, do not allow interpolation" — it improves
    // the packet-loss case in the first frame after a switch (decode_parameters.c:57-61).
    let interpolation_factor_q2 = if first_frame_after_reset {
        NO_INTERPOLATION_Q2
    } else {
        indices.interpolation_factor_q2
    };

    let mut first_half_q12 = [0i16; MAX_LPC_ORDER];
    if interpolation_factor_q2 < NO_INTERPOLATION_Q2 {
        let mut interpolated_q15 = [0i16; MAX_LPC_ORDER];
        interpolate(
            &mut interpolated_q15[..order],
            &previous_nlsf_q15[..order],
            &nlsf_q15[..order],
            interpolation_factor_q2,
        );
        nlsf_to_lpc_q12(&mut first_half_q12, &interpolated_q15[..order]);
    } else {
        first_half_q12 = second_half_q12;
    }

    previous_nlsf_q15[..order].copy_from_slice(&nlsf_q15[..order]);

    // After a concealed frame, chirp both filters down (decode_parameters.c:80-84).
    if after_loss {
        bwexpander_q12(&mut first_half_q12[..order], BWE_AFTER_LOSS_Q16);
        bwexpander_q12(&mut second_half_q12[..order], BWE_AFTER_LOSS_Q16);
    }

    LpcCoefficients {
        first_half_q12,
        second_half_q12,
        nlsf_q15,
        order,
        interpolation_factor_q2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;
    use crate::opus::silk::lpc::inverse_prediction_gain_q12;
    use crate::opus::silk::nlsf_tables::{NB_MB, NLSF_STAGE2_PDF_COUNT, WB};
    use crate::opus::silk::types::SubframeLayout;
    use proptest::prelude::*;

    /// Round-trip helper: encode a symbol list with the same ICDFs the decoder reads.
    fn encode_symbols(symbols: &[(&[u8], usize)]) -> Vec<u8> {
        let mut buffer = vec![0u8; 512];
        let length = {
            let mut encoder = RangeEncoder::new(&mut buffer);
            for &(icdf, symbol) in symbols {
                encoder.enc_icdf(symbol, icdf, ICDF_FTB);
            }
            encoder.done()
        };
        buffer.truncate(length as usize);
        buffer
    }

    /// The stage-2 alphabet is `-4..=4` plus the extension symbol at each end.
    #[test]
    fn stage2_alphabet_bounds() {
        assert_eq!(NLSF_QUANT_MAX_AMPLITUDE, 4);
        // NLSF_QUANT_MAX_AMPLITUDE_EXT (define.h:209) is the widest an index can get.
        let widest = 2 * NLSF_QUANT_MAX_AMPLITUDE + (NLSF_EXT_ICDF.len() as i32 - 1)
            - NLSF_QUANT_MAX_AMPLITUDE;
        assert_eq!(widest, 10);
    }

    /// `silk_NLSF_unpack`: the packed byte splits into two PDF indices and two prediction-set bits,
    /// and the two halves of `pred_Q8` overlap by one entry.
    #[test]
    fn unpack_splits_the_select_byte() {
        // NB/MB stage-1 index 0's select bytes are { 16, 0, 0, 0, 0 } (tables_NLSF_CB_NB_MB.c:124).
        let unpacked = unpack(&NB_MB, 0);
        // Byte 16 = 0b0001_0000: low PDF (bits 1..3) = 0, low pred set (bit 0) = 0,
        // high PDF (bits 5..7) = 0, high pred set (bit 4) = 1.
        assert_eq!(unpacked.pdf_index[0], 0);
        assert_eq!(unpacked.pdf_index[1], 0);
        assert_eq!(unpacked.prediction_q8[0], NB_MB.prediction_q8[0]);
        // Set 1 for the odd coefficient: pred_Q8[ 0 + 1*(10-1) + 1 ] = pred_Q8[10].
        assert_eq!(unpacked.prediction_q8[1], NB_MB.prediction_q8[10]);
        // The remaining bytes are 0, so both coefficients of each pair take set 0.
        for coefficient in 2..NB_MB.order {
            assert_eq!(unpacked.pdf_index[coefficient], 0);
            assert_eq!(
                unpacked.prediction_q8[coefficient],
                NB_MB.prediction_q8[coefficient]
            );
        }
    }

    /// Whatever the stage-1 index, every unpacked PDF index addresses a real table and every
    /// prediction weight comes from inside the codebook's own vector.
    #[test]
    fn unpack_stays_in_range_for_every_stage1_index() {
        for codebook in [&NB_MB, &WB] {
            for index in 0..codebook.vector_count {
                let unpacked = unpack(codebook, index);
                for coefficient in 0..codebook.order {
                    assert!(unpacked.pdf_index[coefficient] < NLSF_STAGE2_PDF_COUNT);
                    assert!(
                        codebook
                            .prediction_q8
                            .contains(&unpacked.prediction_q8[coefficient]),
                        "prediction weight not from the codebook"
                    );
                }
            }
        }
    }

    /// An out-of-range stage-1 index (only reachable by constructing `NlsfIndices` by hand) must
    /// clamp rather than index out of bounds.
    #[test]
    fn unpack_clamps_an_impossible_stage1_index() {
        let unpacked = unpack(&NB_MB, 999);
        let last = unpack(&NB_MB, NB_MB.vector_count - 1);
        assert_eq!(unpacked, last);
    }

    /// An all-zero stage-2 residual dequantizes to all zeros — the dead-zone correction only
    /// applies to non-zero indices (`NLSF_decode.c:49-53`).
    #[test]
    fn residual_dequant_of_zero_is_zero() {
        let mut residual = [0i16; 10];
        residual_dequant(
            &mut residual,
            &[0i8; 10],
            &NB_MB.prediction_q8[..10],
            NB_MB.quant_step_size_q16,
        );
        assert_eq!(residual, [0i16; 10]);
    }

    /// The dead-zone correction and the step scaling, on a single isolated coefficient (the highest,
    /// which has no prediction feeding it): index 1 becomes `(1024 - 102) * step >> 16`.
    #[test]
    fn residual_dequant_applies_the_dead_zone_to_the_top_coefficient() {
        let mut residual = [0i16; 10];
        let mut indices = [0i8; 10];
        indices[9] = 1;
        residual_dequant(
            &mut residual,
            &indices,
            &NB_MB.prediction_q8[..10],
            NB_MB.quant_step_size_q16,
        );
        let expected = smlawb(0, 1024 - QUANT_LEVEL_ADJUST_Q10, NB_MB.quant_step_size_q16);
        assert_eq!(i32::from(residual[9]), expected);
        assert_eq!(expected, 165, "(1024 - 102) * 11796 >> 16");

        // Negative index: the correction is *added*, so the magnitude shrinks by the same 0.1 step —
        // but `silk_SMULWB` floors rather than truncating toward zero, so the negative side lands one
        // unit further from zero. That asymmetry is in the reference arithmetic, not a rounding bug,
        // and it is audible-free but bit-exact-relevant.
        indices[9] = -1;
        residual_dequant(
            &mut residual,
            &indices,
            &NB_MB.prediction_q8[..10],
            NB_MB.quant_step_size_q16,
        );
        assert_eq!(i32::from(residual[9]), -166);
        assert_eq!(
            i32::from(residual[9]),
            smlawb(
                0,
                -(1024 - QUANT_LEVEL_ADJUST_Q10),
                NB_MB.quant_step_size_q16
            )
        );
    }

    /// Backward prediction really is backward: a non-zero index at the top changes every lower
    /// coefficient, while a non-zero index at the bottom changes nothing above it.
    #[test]
    fn residual_dequant_predicts_downward_only() {
        let prediction = &NB_MB.prediction_q8[..10];
        let mut from_top = [0i16; 10];
        let mut indices = [0i8; 10];
        indices[9] = 4;
        residual_dequant(
            &mut from_top,
            &indices,
            prediction,
            NB_MB.quant_step_size_q16,
        );
        assert!(
            from_top[..9].iter().any(|&value| value != 0),
            "a top-coefficient residual must propagate downward"
        );

        let mut from_bottom = [0i16; 10];
        let mut indices = [0i8; 10];
        indices[0] = 4;
        residual_dequant(
            &mut from_bottom,
            &indices,
            prediction,
            NB_MB.quant_step_size_q16,
        );
        assert!(
            from_bottom[1..].iter().all(|&value| value == 0),
            "a bottom-coefficient residual must not reach upward"
        );
    }

    /// A zero residual reproduces the stage-1 codebook vector exactly (shifted Q8 → Q15), and the
    /// stabiliser leaves it alone because the codebook vectors are already legal.
    #[test]
    fn decode_of_a_zero_residual_is_the_codebook_vector() {
        for codebook in [&NB_MB, &WB] {
            for index in 0..codebook.vector_count {
                let mut nlsf = [0i16; MAX_LPC_ORDER];
                let mut indices = [0i8; MAX_NLSF_INDICES];
                indices[0] = index as i8;
                decode(
                    &mut nlsf,
                    codebook,
                    &NlsfIndices {
                        indices,
                        order: codebook.order,
                        interpolation_factor_q2: NO_INTERPOLATION_Q2,
                    },
                );
                let expected: Vec<i16> = codebook
                    .cb1_vector_q8(index)
                    .iter()
                    .map(|&entry| i16::from(entry) << 7)
                    .collect();
                assert_eq!(&nlsf[..codebook.order], expected.as_slice());
            }
        }
    }

    /// RFC 6716 §4.2.7.5.4's postcondition, stated directly: the output is sorted, at least
    /// `delta_min` apart everywhere, and inside `[delta_min[0], 1 - delta_min[order]]`.
    fn assert_minimum_spacing(nlsf_q15: &[i16], delta_min_q15: &[i16]) {
        let order = nlsf_q15.len();
        assert!(
            i32::from(nlsf_q15[0]) >= i32::from(delta_min_q15[0]),
            "first coefficient {} below the floor {}",
            nlsf_q15[0],
            delta_min_q15[0]
        );
        for index in 1..order {
            let spacing = i32::from(nlsf_q15[index]) - i32::from(nlsf_q15[index - 1]);
            assert!(
                spacing >= i32::from(delta_min_q15[index]),
                "coefficients {} and {index} are {spacing} apart, minimum {}",
                index - 1,
                delta_min_q15[index]
            );
        }
        let headroom = (1 << 15) - i32::from(nlsf_q15[order - 1]);
        assert!(
            headroom >= i32::from(delta_min_q15[order]),
            "last coefficient {} leaves only {headroom} headroom",
            nlsf_q15[order - 1]
        );
    }

    #[test]
    fn stabilize_leaves_an_already_legal_vector_untouched() {
        let mut nlsf: Vec<i16> = (0..10).map(|k| 1000 + 3000 * k as i16).collect();
        let original = nlsf.clone();
        stabilize(&mut nlsf, NB_MB.delta_min_q15);
        assert_eq!(nlsf, original);
    }

    #[test]
    fn stabilize_separates_coincident_coefficients() {
        let mut nlsf = [5000i16; 10];
        stabilize(&mut nlsf, NB_MB.delta_min_q15);
        assert_minimum_spacing(&nlsf, NB_MB.delta_min_q15);
    }

    #[test]
    fn stabilize_sorts_a_reversed_vector() {
        // Strictly decreasing: the worst case for the iterative pass, so this is what exercises the
        // sort-based fallback (NLSF_stabilize.c:120-141).
        let mut nlsf: Vec<i16> = (0..10).map(|k| 30000 - 3000 * k as i16).collect();
        stabilize(&mut nlsf, NB_MB.delta_min_q15);
        assert_minimum_spacing(&nlsf, NB_MB.delta_min_q15);
    }

    #[test]
    fn stabilize_pushes_off_both_limits() {
        let mut nlsf = [0i16; 10];
        stabilize(&mut nlsf, NB_MB.delta_min_q15);
        assert_minimum_spacing(&nlsf, NB_MB.delta_min_q15);

        let mut nlsf = [32767i16; 10];
        stabilize(&mut nlsf, NB_MB.delta_min_q15);
        assert_minimum_spacing(&nlsf, NB_MB.delta_min_q15);

        let mut nlsf = [32767i16; 16];
        stabilize(&mut nlsf, WB.delta_min_q15);
        assert_minimum_spacing(&nlsf, WB.delta_min_q15);
    }

    /// The iterative pass keeps the offending pair's centre frequency where it was — that is the
    /// "minimum Euclidean distance" property `NLSF_stabilize.c:36-37` claims, and it is what makes
    /// stabilisation a small correction rather than a re-quantisation.
    #[test]
    fn stabilize_preserves_the_centre_of_a_too_close_pair() {
        let mut nlsf: Vec<i16> = vec![
            1000, 4000, 7000, 10000, 13000, 16000, 19000, 22000, 25000, 28000,
        ];
        // Squeeze one pair together around 11500 (the gap needed is delta_min[4] = 3).
        nlsf[3] = 11500;
        nlsf[4] = 11500;
        stabilize(&mut nlsf, NB_MB.delta_min_q15);
        assert_minimum_spacing(&nlsf, NB_MB.delta_min_q15);
        let centre = (i32::from(nlsf[3]) + i32::from(nlsf[4])) / 2;
        assert!(
            (centre - 11500).abs() <= 2,
            "centre moved to {centre} from 11500"
        );
    }

    #[test]
    fn interpolation_endpoints_are_the_two_input_vectors() {
        let previous: Vec<i16> = (0..10).map(|k| 1000 + 1000 * k as i16).collect();
        let current: Vec<i16> = (0..10).map(|k| 2000 + 2500 * k as i16).collect();
        let mut out = [0i16; 10];

        interpolate(&mut out, &previous, &current, 0);
        assert_eq!(out.to_vec(), previous, "factor 0 keeps the previous vector");

        interpolate(&mut out, &previous, &current, 4);
        assert_eq!(out.to_vec(), current, "factor 4 is the current vector");
    }

    /// RFC 6716 §4.2.7.5.5's formula, written independently, over every factor and a spread of
    /// vectors — including negative differences, where the arithmetic shift floors.
    #[test]
    fn interpolation_matches_the_rfc_formula() {
        let previous: Vec<i16> = vec![
            100, 5000, 9000, 12000, 14000, 20000, 22000, 25000, 29000, 32000,
        ];
        let current: Vec<i16> = vec![
            300, 2000, 11000, 11500, 18000, 19000, 26000, 24000, 30000, 31000,
        ];
        for factor in 0..=4i8 {
            let mut out = [0i16; 10];
            interpolate(&mut out, &previous, &current, factor);
            for index in 0..10 {
                let expected = i32::from(previous[index])
                    + ((i32::from(factor)
                        * (i32::from(current[index]) - i32::from(previous[index])))
                        >> 2);
                assert_eq!(
                    i32::from(out[index]),
                    expected,
                    "factor {factor}, coefficient {index}"
                );
            }
        }
    }

    /// The interpolated vector is never outside the two it came from, so it cannot need
    /// re-stabilising — which is why `silk_decode_parameters` feeds it straight to `silk_NLSF2A`.
    #[test]
    fn interpolation_stays_between_the_two_vectors() {
        let previous: Vec<i16> = (0..16).map(|k| 500 + 1900 * k as i16).collect();
        let current: Vec<i16> = (0..16).map(|k| 900 + 1800 * k as i16).collect();
        for factor in 0..=4i8 {
            let mut out = [0i16; 16];
            interpolate(&mut out, &previous, &current, factor);
            for index in 0..16 {
                let (low, high) = if previous[index] <= current[index] {
                    (previous[index], current[index])
                } else {
                    (current[index], previous[index])
                };
                assert!((low..=high).contains(&out[index]));
            }
        }
    }

    /// A frame with no interpolation must produce two identical filters; one with a coded factor
    /// below 4 must not (given genuinely different previous NLSFs).
    #[test]
    fn interpolation_factor_decides_whether_the_halves_differ() {
        let mut indices = [0i8; MAX_NLSF_INDICES];
        indices[0] = 7;
        let mut previous = [0i16; MAX_LPC_ORDER];
        // A plausible previous frame: codebook vector 20.
        for (slot, &entry) in previous.iter_mut().zip(NB_MB.cb1_vector_q8(20)) {
            *slot = i16::from(entry) << 7;
        }

        let no_interpolation = nlsf_indices_to_lpc(
            &NlsfIndices {
                indices,
                order: 10,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            },
            InternalRate::Narrow8k,
            &mut previous.clone(),
            false,
            false,
        );
        assert_eq!(
            no_interpolation.first_half_q12,
            no_interpolation.second_half_q12
        );

        let interpolated = nlsf_indices_to_lpc(
            &NlsfIndices {
                indices,
                order: 10,
                interpolation_factor_q2: 1,
            },
            InternalRate::Narrow8k,
            &mut previous.clone(),
            false,
            false,
        );
        assert_ne!(interpolated.first_half_q12, interpolated.second_half_q12);
        assert_eq!(
            interpolated.second_half_q12, no_interpolation.second_half_q12,
            "the second half never depends on the interpolation factor"
        );
    }

    /// `decode_parameters.c:59-61`: the first frame after a reset ignores the coded factor, because
    /// the "previous" NLSFs are synthetic.
    #[test]
    fn first_frame_after_reset_suppresses_interpolation() {
        let mut indices = [0i8; MAX_NLSF_INDICES];
        indices[0] = 3;
        let mut previous = [0i16; MAX_LPC_ORDER];
        let coefficients = nlsf_indices_to_lpc(
            &NlsfIndices {
                indices,
                order: 10,
                interpolation_factor_q2: 0,
            },
            InternalRate::Narrow8k,
            &mut previous,
            true,
            false,
        );
        assert_eq!(coefficients.interpolation_factor_q2, NO_INTERPOLATION_Q2);
        assert_eq!(coefficients.first_half_q12, coefficients.second_half_q12);
    }

    /// The anchor really is updated, so the next frame interpolates against this frame's NLSFs.
    #[test]
    fn the_interpolation_anchor_is_written_back() {
        let mut indices = [0i8; MAX_NLSF_INDICES];
        indices[0] = 11;
        let mut previous = [0i16; MAX_LPC_ORDER];
        let coefficients = nlsf_indices_to_lpc(
            &NlsfIndices {
                indices,
                order: 10,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            },
            InternalRate::Narrow8k,
            &mut previous,
            false,
            false,
        );
        assert_eq!(previous[..10], coefficients.nlsf_q15[..10]);
        // Untouched past the order — a 10-order frame must not scribble on the WB tail.
        assert!(previous[10..].iter().all(|&value| value == 0));
    }

    /// After a concealed frame both filters are chirped down (`decode_parameters.c:80-84`).
    #[test]
    fn loss_bandwidth_expands_both_filters() {
        let mut indices = [0i8; MAX_NLSF_INDICES];
        indices[0] = 5;
        indices[1] = 2;
        let nlsf_indices = NlsfIndices {
            indices,
            order: 10,
            interpolation_factor_q2: NO_INTERPOLATION_Q2,
        };
        let clean = nlsf_indices_to_lpc(
            &nlsf_indices,
            InternalRate::Narrow8k,
            &mut [0i16; MAX_LPC_ORDER],
            false,
            false,
        );
        let after_loss = nlsf_indices_to_lpc(
            &nlsf_indices,
            InternalRate::Narrow8k,
            &mut [0i16; MAX_LPC_ORDER],
            false,
            true,
        );
        assert_ne!(clean.first_half_q12, after_loss.first_half_q12);
        assert_ne!(clean.second_half_q12, after_loss.second_half_q12);
        // Chirping can only shrink the tail of the filter.
        assert!(after_loss.second_half_q12[9].abs() <= clean.second_half_q12[9].abs());
    }

    /// Round-trip through the range coder: the exact symbol sequence RFC 6716 §4.2.7.5 specifies
    /// must decode back to the indices that were written, for both codebooks.
    #[test]
    fn index_decode_round_trips_through_the_range_coder() {
        for (rate, codebook) in [
            (InternalRate::Narrow8k, &NB_MB),
            (InternalRate::Wide16k, &WB),
        ] {
            let order = codebook.order;
            let stage1 = 19usize;
            let unpacked = unpack(codebook, stage1);
            // A residual per coefficient, cycling through the alphabet including both saturations.
            let residuals: Vec<usize> = (0..order).map(|k| k % 9).collect();

            let mut symbols: Vec<(&[u8], usize)> =
                vec![(codebook.stage1_icdf(SignalType::Voiced.index()), stage1)];
            for (coefficient, &value) in residuals.iter().enumerate() {
                symbols.push((codebook.stage2_icdf(unpacked.pdf_index[coefficient]), value));
                if value == 0 || value == 2 * NLSF_QUANT_MAX_AMPLITUDE as usize {
                    // The extension symbol, when the residual saturates.
                    symbols.push((&NLSF_EXT_ICDF, 3));
                }
            }
            symbols.push((&NLSF_INTERPOLATION_FACTOR_ICDF, 2));

            let bytes = encode_symbols(&symbols);
            let mut decoder = RangeDecoder::new(&bytes);
            let decoded = decode_indices(&mut decoder, rate, SignalType::Voiced, MAX_NB_SUBFR)
                .expect("decode");

            assert_eq!(decoded.order, order);
            assert_eq!(decoded.stage1_index(), stage1);
            assert_eq!(decoded.interpolation_factor_q2, 2);
            for (coefficient, &value) in residuals.iter().enumerate() {
                let saturated_high = 2 * NLSF_QUANT_MAX_AMPLITUDE as usize;
                let expected = match value {
                    0 => -NLSF_QUANT_MAX_AMPLITUDE - 3,
                    v if v == saturated_high => NLSF_QUANT_MAX_AMPLITUDE + 3,
                    v => v as i32 - NLSF_QUANT_MAX_AMPLITUDE,
                };
                assert_eq!(
                    i32::from(decoded.stage2_residuals()[coefficient]),
                    expected,
                    "coefficient {coefficient}"
                );
            }
        }
    }

    /// A two-subframe (10 ms) frame does not carry the interpolation symbol at all — reading it
    /// would eat bits belonging to the pitch lag.
    #[test]
    fn a_two_subframe_frame_codes_no_interpolation_factor() {
        let codebook = &NB_MB;
        let unpacked = unpack(codebook, 0);
        let mut symbols: Vec<(&[u8], usize)> =
            vec![(codebook.stage1_icdf(SignalType::Unvoiced.index()), 0)];
        for coefficient in 0..codebook.order {
            symbols.push((codebook.stage2_icdf(unpacked.pdf_index[coefficient]), 4));
        }
        // A sentinel the interpolation read would consume if it happened.
        symbols.push((&NLSF_INTERPOLATION_FACTOR_ICDF, 1));
        let bytes = encode_symbols(&symbols);

        let mut decoder = RangeDecoder::new(&bytes);
        let two_subframes = SubframeLayout::from_duration_ms(10)
            .expect("10 ms")
            .subframe_count;
        let decoded = decode_indices(
            &mut decoder,
            InternalRate::Narrow8k,
            SignalType::Unvoiced,
            two_subframes,
        )
        .expect("decode");
        assert_eq!(decoded.interpolation_factor_q2, NO_INTERPOLATION_Q2);
        // The sentinel is still there, i.e. nothing was consumed for the interpolation factor.
        assert_eq!(
            decoder.dec_icdf(&NLSF_INTERPOLATION_FACTOR_ICDF, ICDF_FTB),
            1
        );
    }

    #[test]
    fn decode_indices_rejects_an_impossible_subframe_count() {
        let bytes = [0u8; 16];
        let mut decoder = RangeDecoder::new(&bytes);
        assert!(
            decode_indices(&mut decoder, InternalRate::Narrow8k, SignalType::Voiced, 0).is_err()
        );
        let mut decoder = RangeDecoder::new(&bytes);
        assert!(
            decode_indices(&mut decoder, InternalRate::Narrow8k, SignalType::Voiced, 5).is_err()
        );
    }

    /// The decoder-state wiring: the channel's own rate and subframe count drive the decode, and the
    /// anchor lands on the channel rather than being thrown away.
    #[test]
    fn decoder_method_uses_and_updates_channel_state() {
        use crate::opus::silk::decoder::MID_CHANNEL;
        let mut silk = SilkDecoder::new(16_000, 1).expect("decoder");
        silk.configure(1, InternalRate::Wide16k, 20)
            .expect("configure");

        let codebook = &WB;
        let unpacked = unpack(codebook, 4);
        let mut symbols: Vec<(&[u8], usize)> =
            vec![(codebook.stage1_icdf(SignalType::Voiced.index()), 4)];
        for coefficient in 0..codebook.order {
            symbols.push((codebook.stage2_icdf(unpacked.pdf_index[coefficient]), 5));
        }
        symbols.push((&NLSF_INTERPOLATION_FACTOR_ICDF, 4));
        let bytes = encode_symbols(&symbols);

        let mut decoder = RangeDecoder::new(&bytes);
        let coefficients = silk
            .decode_nlsf(&mut decoder, MID_CHANNEL, SignalType::Voiced)
            .expect("nlsf");
        assert_eq!(coefficients.order, 16);
        assert_eq!(
            silk.channel(MID_CHANNEL).expect("mid").prev_nlsf_q15[..16],
            coefficients.nlsf_q15[..16]
        );
        assert!(inverse_prediction_gain_q12(&coefficients.second_half_q12[..16]) > 0);
    }

    #[test]
    fn decoder_method_rejects_an_unconfigured_channel() {
        use crate::opus::silk::decoder::MID_CHANNEL;
        let mut silk = SilkDecoder::new(16_000, 1).expect("decoder");
        let bytes = [0u8; 16];
        let mut decoder = RangeDecoder::new(&bytes);
        assert!(silk
            .decode_nlsf(&mut decoder, MID_CHANNEL, SignalType::Voiced)
            .is_err());
    }

    proptest! {
        /// RFC 6716 §4.2.7.5.4 as a property: whatever vector goes in — unsorted, coincident, at
        /// either limit — the stabilised output satisfies the minimum-spacing contract, for both
        /// codebooks.
        #[test]
        fn stabilize_always_establishes_the_minimum_spacing(
            raw in prop::collection::vec(0i16..=32767, MAX_LPC_ORDER),
        ) {
            let mut narrow: Vec<i16> = raw[..10].to_vec();
            stabilize(&mut narrow, NB_MB.delta_min_q15);
            assert_minimum_spacing(&narrow, NB_MB.delta_min_q15);

            let mut wide = raw.clone();
            stabilize(&mut wide, WB.delta_min_q15);
            assert_minimum_spacing(&wide, WB.delta_min_q15);
        }

        /// Stabilisation is idempotent: a stabilised vector is already legal, so a second pass is a
        /// no-op. If it were not, the decoder and encoder could disagree on the envelope.
        #[test]
        fn stabilize_is_idempotent(raw in prop::collection::vec(0i16..=32767, MAX_LPC_ORDER)) {
            let mut once = raw.clone();
            stabilize(&mut once, WB.delta_min_q15);
            let mut twice = once.clone();
            stabilize(&mut twice, WB.delta_min_q15);
            prop_assert_eq!(once, twice);
        }

        /// Any stage-1 index and any legal stage-2 residual vector decodes to a stabilised NLSF
        /// vector whose LPC filter is stable — the end-to-end invariant of this whole stage.
        #[test]
        fn any_index_vector_decodes_to_a_stable_filter(
            stage1 in 0usize..32,
            residuals in prop::collection::vec(-10i8..=10, MAX_LPC_ORDER),
            wideband: bool,
        ) {
            let codebook = if wideband { &WB } else { &NB_MB };
            let mut indices = [0i8; MAX_NLSF_INDICES];
            indices[0] = stage1 as i8;
            indices[1..=codebook.order].copy_from_slice(&residuals[..codebook.order]);
            let nlsf_indices = NlsfIndices {
                indices,
                order: codebook.order,
                interpolation_factor_q2: NO_INTERPOLATION_Q2,
            };
            let mut nlsf = [0i16; MAX_LPC_ORDER];
            decode(&mut nlsf, codebook, &nlsf_indices);
            assert_minimum_spacing(&nlsf[..codebook.order], codebook.delta_min_q15);

            let rate = if wideband { InternalRate::Wide16k } else { InternalRate::Narrow8k };
            let coefficients = nlsf_indices_to_lpc(
                &nlsf_indices,
                rate,
                &mut [0i16; MAX_LPC_ORDER],
                false,
                false,
            );
            prop_assert!(
                inverse_prediction_gain_q12(&coefficients.second_half_q12[..codebook.order]) > 0
            );
        }

        /// Arbitrary and truncated payloads must never panic or read out of bounds: this is the
        /// first NLSF symbol a hostile packet reaches.
        #[test]
        fn arbitrary_payloads_never_panic(
            payload in prop::collection::vec(any::<u8>(), 0..64),
            wideband: bool,
            subframes in 1usize..=4,
        ) {
            let rate = if wideband { InternalRate::Wide16k } else { InternalRate::Narrow8k };
            for signal_type in [SignalType::Inactive, SignalType::Unvoiced, SignalType::Voiced] {
                let mut decoder = RangeDecoder::new(&payload);
                if let Ok(indices) = decode_indices(&mut decoder, rate, signal_type, subframes) {
                    let mut nlsf = [0i16; MAX_LPC_ORDER];
                    decode(&mut nlsf, NlsfCodebook::for_rate(rate), &indices);
                    let _ = nlsf_indices_to_lpc(
                        &indices,
                        rate,
                        &mut [0i16; MAX_LPC_ORDER],
                        false,
                        true,
                    );
                }
            }
        }

        /// Interpolation over arbitrary vectors and factors never panics and always lands between
        /// its endpoints.
        #[test]
        fn interpolation_never_panics(
            previous in prop::collection::vec(0i16..=32767, MAX_LPC_ORDER),
            current in prop::collection::vec(0i16..=32767, MAX_LPC_ORDER),
            factor in 0i8..=4,
        ) {
            let mut out = [0i16; MAX_LPC_ORDER];
            interpolate(&mut out, &previous, &current, factor);
            for index in 0..MAX_LPC_ORDER {
                let low = previous[index].min(current[index]);
                let high = previous[index].max(current[index]);
                prop_assert!((low..=high).contains(&out[index]));
            }
        }
    }
}
