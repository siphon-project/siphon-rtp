//! Rate control — `silk_control_SNR` (`silk/control_SNR.c`) and the gain-multiplier loop that
//! wraps the quantiser and the writer (`silk/float/encode_frame_FLP.c:167-350`).
//!
//! SILK has no direct "spend N bits" knob. The only lever on frame size is the **subframe gain**:
//! a larger gain makes the excitation smaller in the quantiser's scaled domain, so fewer pulses are
//! spent and the frame shrinks. Rate control is therefore a search — encode the frame, measure it,
//! scale the unquantised gains, re-quantise, encode again — and it is why the writer has to be
//! cheap to re-run and the encoder state cheap to roll back.
//!
//! # Two stages, and they are not the same thing
//!
//! 1. **[`control_snr`]** maps a target bitrate to `SNR_dB_Q7`, the quality target the *analysis*
//!    runs under (it moves the shaping gain, the LTP scaling decision and the gain limiter). It is
//!    a table lookup, once per frame, before any encoding — the tables were measured by running
//!    libopus at each SNR and recording the bitrate it produced.
//! 2. **[`encode_frame`]**'s loop closes the remaining error against a hard **byte budget**. Stage 1
//!    gets the frame roughly the right size; stage 2 guarantees it fits.
//!
//! # The loop, and the three regimes
//!
//! `max_bits` is the budget and `use_cbr` says how tightly to hit it. The margin below it is
//! `5` bits for CBR and `max_bits / 4` for VBR (`encode_frame_FLP.c:113`), which is the whole
//! difference between the regimes at this layer:
//!
//! * **VBR** — one pass. If the first encode fits, it is kept, whatever it cost
//!   (`encode_frame_FLP.c:245-247`). The frame is as large as the signal wanted.
//! * **Constrained VBR** — the caller passes a `max_bits` derived from the *packet* cap rather than
//!   the target rate, so the loop only engages on a frame that would have busted it. Same code
//!   path; the constraint lives in the budget.
//! * **CBR** — `use_cbr` suppresses the early exit, so the loop always runs until the frame lands
//!   within 5 bits of the budget.
//!
//! The search itself is a bisection on a Q8 gain multiplier: pure exponential steps (×1.5 up,
//! ×0.8 down) until it has bracketed the budget, then interpolation clamped to the middle half of
//! the bracket so one bad measurement cannot make it jump to an end. Six iterations, then it takes
//! the best result that fitted.
//!
//! # Two failure paths that are not failures
//!
//! * **Per-subframe gain locking.** While no fitting result has been found, a subframe whose pulse
//!   count *stopped improving* has its multiplier frozen at its best value
//!   (`encode_frame_FLP.c:294-308`). Without it, one loud subframe drags every other subframe's
//!   gain up with it and the whole frame goes quiet.
//! * **Damage control.** If the last iteration still busts and nothing ever fitted, the frame is
//!   re-coded with the previous frame's gains and **no pulses at all** (`:218-243`). That is not a
//!   dropped frame: the side info is still coded, the decoder still runs its filters, and the
//!   result is one frame of shaped silence rather than a truncated packet.
//!
//! # What is rolled back, and what is not
//!
//! Each retried iteration restores the range encoder, the NSQ state, the seed and the writer's
//! entropy context (`encode_frame_FLP.c:176-193`). It does **not** restore the analysis state: the
//! pitch, shaping and NLSF stages ran once and their cross-frame state is already committed. That
//! is the reason [`super::gains::process_gains`] exposes `unquantized_q16` and
//! `previous_index_before` — the loop re-enters at the gain stage, not at the top.

use crate::opus::range_coder::RangeEncoder;
use crate::opus::silk::enc::bitstream::{encode_indices, encode_pulses, EntropyContext};
use crate::opus::silk::enc::float::float2int;
use crate::opus::silk::enc::frame::{
    analyze_frame, AnalysisConfig, AnalysisState, FrameAnalysis, SideIndices,
};
use crate::opus::silk::enc::gains::gains_quant;
use crate::opus::silk::enc::nsq::{gains_identifier, quantize, NsqConfig, NsqInput, NsqState};
use crate::opus::silk::enc::SignalMeasures;
use crate::opus::silk::fixed::{lshift_sat32, smulwb};
use crate::opus::silk::gains::dequantize_gains;
use crate::opus::silk::gains::GainIndices;
use crate::opus::silk::types::{
    CondCoding, InternalRate, SignalType, MAX_FRAME_LENGTH, MAX_NB_SUBFR, N_LEVELS_QGAIN,
};
use crate::CodecError;

/// `silk_TargetRate_NB_21` (`control_SNR.c:39`) — target SNR in dB divided by 21, at 400 bps steps
/// starting from 4 kb/s. Divided by 21 so it fits a byte, which is why the lookup multiplies back.
const NARROWBAND_SNR_OVER_21: [u8; 107] = [
    0, 15, 39, 52, 61, 68, 74, 79, 84, 88, 92, 95, 99, 102, 105, 108, 111, 114, 117, 119, 122, 124,
    126, 129, 131, 133, 135, 137, 139, 142, 143, 145, 147, 149, 151, 153, 155, 157, 158, 160, 162,
    163, 165, 167, 168, 170, 171, 173, 174, 176, 177, 179, 180, 182, 183, 185, 186, 187, 189, 190,
    192, 193, 194, 196, 197, 199, 200, 201, 203, 204, 205, 207, 208, 209, 211, 212, 213, 215, 216,
    217, 219, 220, 221, 223, 224, 225, 227, 228, 230, 231, 232, 234, 235, 236, 238, 239, 241, 242,
    243, 245, 246, 248, 249, 250, 252, 253, 255,
];

/// `silk_TargetRate_MB_21` (`control_SNR.c:60`).
const MEDIUMBAND_SNR_OVER_21: [u8; 155] = [
    0, 0, 28, 43, 52, 59, 65, 70, 74, 78, 81, 85, 87, 90, 93, 95, 98, 100, 102, 105, 107, 109, 111,
    113, 115, 116, 118, 120, 122, 123, 125, 127, 128, 130, 131, 133, 134, 136, 137, 138, 140, 141,
    143, 144, 145, 147, 148, 149, 151, 152, 153, 154, 156, 157, 158, 159, 160, 162, 163, 164, 165,
    166, 167, 168, 169, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185,
    186, 187, 188, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203,
    203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 214, 215, 216, 217, 218, 219, 220,
    221, 222, 223, 224, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 236, 237,
    238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
];

/// `silk_TargetRate_WB_21` (`control_SNR.c:76`).
const WIDEBAND_SNR_OVER_21: [u8; 191] = [
    0, 0, 0, 8, 29, 41, 49, 56, 62, 66, 70, 74, 77, 80, 83, 86, 88, 91, 93, 95, 97, 99, 101, 103,
    105, 107, 108, 110, 112, 113, 115, 116, 118, 119, 121, 122, 123, 125, 126, 127, 129, 130, 131,
    132, 134, 135, 136, 137, 138, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152,
    153, 154, 156, 157, 158, 159, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171,
    171, 172, 173, 174, 175, 176, 177, 177, 178, 179, 180, 181, 181, 182, 183, 184, 185, 185, 186,
    187, 188, 189, 189, 190, 191, 192, 192, 193, 194, 195, 195, 196, 197, 198, 198, 199, 200, 200,
    201, 202, 203, 203, 204, 205, 206, 206, 207, 208, 209, 209, 210, 211, 211, 212, 213, 214, 214,
    215, 216, 216, 217, 218, 219, 219, 220, 221, 221, 222, 223, 224, 224, 225, 226, 226, 227, 228,
    229, 229, 230, 231, 232, 232, 233, 234, 234, 235, 236, 237, 237, 238, 239, 240, 240, 241, 242,
    243, 243, 244, 245, 246, 246, 247, 248, 249, 249, 250, 251, 252, 253, 255,
];

/// The largest Opus packet, and therefore the largest byte range the loop ever has to snapshot
/// (`encode_frame_FLP.c:106`, `opus_uint8 ec_buf_copy[1275]`).
const MAX_PAYLOAD_BYTES: usize = 1275;

/// How many bisection steps the gain loop takes before it settles (`encode_frame_FLP.c:168`).
const MAX_ITERATIONS: i32 = 6;

/// Map a target bitrate to the coding SNR the analysis runs under (`silk_control_SNR`,
/// `control_SNR.c:85-112`).
///
/// A two-subframe (10 ms) frame pays a fixed overhead the tables do not model — the side info is
/// coded per frame regardless of length — so its target is reduced before the lookup
/// (`control_SNR.c:93-95`).
#[must_use]
pub fn control_snr(target_bitrate_bps: i32, rate: InternalRate, subframe_count: usize) -> i32 {
    let mut target = target_bitrate_bps;
    if subframe_count == 2 {
        target -= 2000 + rate.khz() as i32 / 16;
    }
    let table: &[u8] = match rate {
        InternalRate::Narrow8k => &NARROWBAND_SNR_OVER_21,
        InternalRate::Medium12k => &MEDIUMBAND_SNR_OVER_21,
        InternalRate::Wide16k => &WIDEBAND_SNR_OVER_21,
    };
    // The tables start at 4 kb/s (the first ten 400 bps slots are all zero and are omitted).
    let index = (target + 200) / 400 - 10;
    let index = index.min(table.len() as i32 - 1);
    if index <= 0 {
        0
    } else {
        i32::from(table[index as usize]) * 21
    }
}

/// A frame's LBRR slot: the side info and pulses a *redundant* copy of this frame would carry.
///
/// LBRR reuses every analysis decision and only re-runs the quantiser at a coarser gain, which is
/// what makes it cheap — see [`encode_frame`]'s `lbrr_gain_increase`.
#[derive(Debug, Clone, Copy)]
pub struct LbrrFrame {
    /// The side info, identical to the regular frame's except for `GainsIndices[0]`.
    pub indices: SideIndices,
    /// The seed the LBRR quantiser settled on, which may differ from the regular frame's.
    pub seed: u8,
    /// The redundant pulse signal.
    pub pulses: [i8; MAX_FRAME_LENGTH],
}

impl Default for LbrrFrame {
    fn default() -> Self {
        Self {
            indices: SideIndices::unvoiced(crate::opus::silk::types::MAX_LPC_ORDER),
            seed: 0,
            pulses: [0; MAX_FRAME_LENGTH],
        }
    }
}

/// The encoder state one channel carries from frame to frame, as far as this layer is concerned.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameEncoderState {
    /// The analysis front end's cross-frame state.
    pub analysis: AnalysisState,
    /// The noise-shaping quantiser's.
    pub nsq: NsqState,
    /// The writer's entropy context.
    pub entropy: EntropyContext,
    /// `psEnc->sCmn.frameCounter` — the source of the `Seed` symbol before the quantiser gets a
    /// say (`encode_frame_FLP.c:117`).
    pub frame_counter: i32,
    /// `psEnc->sCmn.LBRRprevLastGainIndex` — the LBRR path's own running gain index, which has to
    /// track what an LBRR *decoder* would reconstruct rather than what the regular path did.
    pub lbrr_previous_gain_index: i8,
}

/// What [`encode_frame`] needs beyond the encoder's own state.
#[derive(Debug, Clone, Copy)]
pub struct FrameEncodeRequest<'a> {
    /// The input buffer, with [`AnalysisConfig::required_history`] samples before `frame_start` and
    /// [`AnalysisConfig::required_lookahead`] after the frame.
    pub signal: &'a [f32],
    /// Index of the frame's first sample in `signal`.
    pub frame_start: usize,
    /// The VAD's verdict coming in — [`SignalType::Inactive`] or [`SignalType::Unvoiced`].
    pub signal_type: SignalType,
    /// Whether this frame may lean on the previous SILK frame of the same channel.
    pub cond_coding: CondCoding,
    /// The VAD's measures.
    pub measures: &'a SignalMeasures,
    /// The analysis configuration, including `snr_db_q7` from [`control_snr`].
    pub config: &'a AnalysisConfig,
    /// `maxBits` — the hard budget for this frame, in bits.
    pub max_bits: i32,
    /// `useCBR`.
    pub use_cbr: bool,
    /// `LBRR_GainIncreases` when this frame should also produce an LBRR copy, and `None` when it
    /// should not. `Some(0)` is a legal request meaning "code LBRR at the same gain".
    pub lbrr_gain_increase: Option<i32>,
    /// Whether the *previous* frame in this packet already carried LBRR — the LBRR gain increase is
    /// only applied on the first LBRR frame of a run (`encode_frame_FLP.c:405-412`).
    pub lbrr_continues: bool,
}

/// What one encoded frame produced.
#[derive(Debug, Clone, Copy)]
pub struct FrameEncodeResult {
    /// `*pnBytesOut` — the payload size so far, `(ec_tell + 7) >> 3` (`encode_frame_FLP.c:373`).
    pub payload_bytes: usize,
    /// The side info actually coded, after the loop's own overrides.
    pub indices: SideIndices,
    /// The `Seed` symbol coded.
    pub seed: u8,
    /// The LBRR copy, when one was requested.
    pub lbrr: Option<LbrrFrame>,
}

/// Encode one SILK frame into `encoder`, hitting `max_bits` (`silk_encode_frame_FLP`,
/// `encode_frame_FLP.c:84-376`).
///
/// `pulses` is caller-owned scratch of at least `MAX_FRAME_LENGTH` bytes and holds the frame's
/// quantised excitation on return.
pub fn encode_frame(
    state: &mut FrameEncoderState,
    encoder: &mut RangeEncoder<'_>,
    request: &FrameEncodeRequest<'_>,
    pulses: &mut [i8; MAX_FRAME_LENGTH],
) -> Result<FrameEncodeResult, CodecError> {
    let config = request.config;
    let subframe_count = config.layout.subframe_count;
    let frame_length = config.frame_length();

    let seed = (state.frame_counter & 3) as u8;
    state.frame_counter = state.frame_counter.wrapping_add(1);

    // ── The analysis runs exactly once ─────────────────────────────────────────────────────────
    let FrameAnalysis {
        mut indices,
        mut control,
    } = analyze_frame(
        &mut state.analysis,
        request.signal,
        request.frame_start,
        request.signal_type,
        request.cond_coding,
        request.measures,
        config,
    )?;

    let nsq_config = NsqConfig {
        subframe_length: config.subframe_length(),
        subframe_count,
        ltp_memory_length: config.ltp_memory_length(),
        predict_lpc_order: config.internal_rate.lpc_order(),
        shaping_lpc_order: config.settings.shaping_lpc_order,
        warping_q16: config.warping_q16(),
        delayed_decision_states: config.settings.delayed_decision_states.max(1) as usize,
    };

    // The NSQ works on the integer input, converted once (`wrappers_FLP.c:151-153`).
    let mut x16 = [0i16; MAX_FRAME_LENGTH];
    for (slot, &sample) in x16
        .iter_mut()
        .zip(request.signal[request.frame_start..].iter())
        .take(frame_length)
    {
        *slot = float2int(sample) as i16;
    }

    // ── LBRR, before the loop, on a copy of the quantiser state ────────────────────────────────
    let lbrr = request.lbrr_gain_increase.map(|increase| {
        encode_lbrr(
            state,
            &indices,
            &control,
            &x16[..frame_length],
            seed,
            increase,
            request.lbrr_continues,
            request.cond_coding,
            &nsq_config,
        )
    });

    // ── The gain-multiplier loop ───────────────────────────────────────────────────────────────
    let bits_margin = if request.use_cbr {
        5
    } else {
        request.max_bits / 4
    };
    let mut gain_multiplier_q8 = 256i32;
    let mut found_lower = false;
    let mut found_upper = false;
    let mut bits_lower = 0i32;
    let mut bits_upper = 0i32;
    let mut multiplier_lower = 0i32;
    let mut multiplier_upper = 0i32;
    let mut gains_id = gains_identifier(&indices.gains_indices, subframe_count);
    let mut gains_id_lower = -1i32;
    let mut gains_id_upper = -1i32;
    let mut gain_locked = [false; MAX_NB_SUBFR];
    let mut best_multiplier = [0i32; MAX_NB_SUBFR];
    let mut best_pulse_sum = [0i32; MAX_NB_SUBFR];
    let mut last_gain_index_saved = 0i8;

    // The rollback point: the coder, the quantiser and the entropy context as they stand now.
    let encoder_start = encoder.save_state();
    let nsq_start = state.nsq;
    let entropy_start = state.entropy;

    // The best fitting result seen so far, kept whole so it can be replayed.
    let mut saved_encoder = encoder_start;
    let mut saved_bytes = [0u8; MAX_PAYLOAD_BYTES];
    let mut saved_byte_count = 0usize;
    let mut saved_nsq = nsq_start;
    // The last-ditch snapshot taken just before the final iteration's symbols are written.
    let mut damage_control_encoder = encoder_start;

    let mut coded_seed = seed;
    // Set on the first pass through the loop body, before anything reads it: the only branch that
    // skips the encode is the `gainsID` cache hit, which cannot fire on iteration 0.
    let mut bits;

    let mut iteration = 0i32;
    loop {
        if gains_id == gains_id_lower {
            bits = bits_lower;
        } else if gains_id == gains_id_upper {
            bits = bits_upper;
        } else {
            if iteration > 0 {
                encoder.restore_state(&encoder_start);
                state.nsq = nsq_start;
                state.entropy = entropy_start;
            }

            let input = NsqInput::from_analysis(&control, &indices, seed, &nsq_config);
            coded_seed = quantize(&mut state.nsq, &input, &x16, &mut pulses[..], &nsq_config);

            if iteration == MAX_ITERATIONS && !found_lower {
                damage_control_encoder = encoder.save_state();
            }

            encode_indices(
                encoder,
                &indices,
                coded_seed,
                config.internal_rate,
                subframe_count,
                request.cond_coding,
                false,
                &mut state.entropy,
            );
            encode_pulses(
                encoder,
                indices.signal_type,
                indices.quant_offset_type,
                &mut pulses[..],
                frame_length,
            );
            bits = encoder.tell();

            // Damage control: nothing ever fitted and this is the last chance. Re-code with the
            // previous frame's gains and an empty excitation rather than busting the packet.
            if iteration == MAX_ITERATIONS && !found_lower && bits > request.max_bits {
                encoder.restore_state(&damage_control_encoder);

                state.analysis.shape.last_gain_index = control.previous_gain_index_before;
                indices.gains_indices = [4; MAX_NB_SUBFR];
                if request.cond_coding != CondCoding::Conditionally {
                    indices.gains_indices[0] = control.previous_gain_index_before;
                }
                state.entropy = entropy_start;
                pulses.fill(0);

                encode_indices(
                    encoder,
                    &indices,
                    coded_seed,
                    config.internal_rate,
                    subframe_count,
                    request.cond_coding,
                    false,
                    &mut state.entropy,
                );
                encode_pulses(
                    encoder,
                    indices.signal_type,
                    indices.quant_offset_type,
                    &mut pulses[..],
                    frame_length,
                );
                bits = encoder.tell();
            }

            // VBR's early exit: the first encode fitting the budget is the answer.
            if !request.use_cbr && iteration == 0 && bits <= request.max_bits {
                break;
            }
        }

        if iteration == MAX_ITERATIONS {
            if found_lower && (gains_id == gains_id_lower || bits > request.max_bits) {
                encoder.restore_state(&saved_encoder);
                encoder.buffer_mut()[..saved_byte_count]
                    .copy_from_slice(&saved_bytes[..saved_byte_count]);
                state.nsq = saved_nsq;
                state.analysis.shape.last_gain_index = last_gain_index_saved;
            }
            break;
        }

        if bits > request.max_bits {
            if !found_lower && iteration >= 2 {
                // Nothing has fitted in three tries: make the quantiser itself cheaper rather than
                // only turning the gain up, and discard the "upper" bracket the new lambda invalidates.
                control.lambda = (control.lambda * 1.5).max(1.5);
                indices.quant_offset_type = crate::opus::silk::types::QuantOffsetType::Low;
                found_upper = false;
                gains_id_upper = -1;
            } else {
                found_upper = true;
                bits_upper = bits;
                multiplier_upper = gain_multiplier_q8;
                gains_id_upper = gains_id;
            }
        } else if bits < request.max_bits - bits_margin {
            found_lower = true;
            bits_lower = bits;
            multiplier_lower = gain_multiplier_q8;
            if gains_id != gains_id_lower {
                gains_id_lower = gains_id;
                saved_encoder = encoder.save_state();
                saved_byte_count = (encoder.range_bytes() as usize).min(MAX_PAYLOAD_BYTES);
                saved_bytes[..saved_byte_count]
                    .copy_from_slice(&encoder.buffer()[..saved_byte_count]);
                saved_nsq = state.nsq;
                last_gain_index_saved = state.analysis.shape.last_gain_index;
            }
        } else {
            // Inside the margin: close enough.
            break;
        }

        if !found_lower && bits > request.max_bits {
            // Freeze a subframe whose pulse count stopped improving, so one loud subframe cannot
            // drag every other subframe's gain up with it.
            for subframe in 0..subframe_count {
                let sum: i32 = pulses[subframe * config.subframe_length()..]
                    [..config.subframe_length()]
                    .iter()
                    .map(|&pulse| i32::from(pulse).abs())
                    .sum();
                if iteration == 0 || (sum < best_pulse_sum[subframe] && !gain_locked[subframe]) {
                    best_pulse_sum[subframe] = sum;
                    best_multiplier[subframe] = gain_multiplier_q8;
                } else {
                    gain_locked[subframe] = true;
                }
            }
        }

        gain_multiplier_q8 = if !(found_lower && found_upper) {
            // No bracket yet: exponential steps along the high-rate rate/distortion curve.
            if bits > request.max_bits {
                (gain_multiplier_q8 * 3 / 2).min(1024)
            } else {
                (gain_multiplier_q8 * 4 / 5).max(64)
            }
        } else {
            // Bracketed: interpolate, then clamp to the middle half so one bad measurement cannot
            // send the next trial to an end of the bracket. Note `upper < lower`: a *larger*
            // multiplier means a larger gain and therefore *fewer* bits.
            let span = multiplier_upper - multiplier_lower;
            let interpolated = multiplier_lower
                + (span * (request.max_bits - bits_lower)) / (bits_upper - bits_lower).max(1);
            let high = multiplier_lower + (span >> 2);
            let low = multiplier_upper - (span >> 2);
            interpolated.min(high).max(low)
        };

        let mut trial_gains_q16 = [0i32; MAX_NB_SUBFR];
        for subframe in 0..subframe_count {
            let multiplier = if gain_locked[subframe] {
                best_multiplier[subframe]
            } else {
                gain_multiplier_q8
            };
            trial_gains_q16[subframe] = lshift_sat32(
                smulwb(control.unquantized_gains_q16[subframe], multiplier),
                8,
            );
        }

        // Re-quantise from the *unquantised* gains and the running index as it stood before this
        // frame, so rounding never compounds across iterations.
        state.analysis.shape.last_gain_index = control.previous_gain_index_before;
        gains_quant(
            &mut indices.gains_indices,
            &mut trial_gains_q16,
            &mut state.analysis.shape.last_gain_index,
            request.cond_coding == CondCoding::Conditionally,
            subframe_count,
        );
        gains_id = gains_identifier(&indices.gains_indices, subframe_count);

        for (subframe, &gain_q16) in trial_gains_q16.iter().enumerate().take(subframe_count) {
            control.gains[subframe] = gain_q16 as f32 / 65536.0;
            control.gains_q16[subframe] = gain_q16;
        }

        iteration += 1;
    }

    Ok(FrameEncodeResult {
        payload_bytes: (encoder.tell() as usize).div_ceil(8),
        indices,
        seed: coded_seed,
        lbrr,
    })
}

/// `silk_LBRR_encode_FLP` (`encode_frame_FLP.c:379-432`) — re-quantise the same frame at a coarser
/// gain, on a **copy** of the quantiser state.
///
/// The copy is the point: the LBRR pulses are a second, independent quantisation of the same
/// analysis, and running it must not disturb the state the regular frame will be quantised from.
/// The gain increase is applied to `GainsIndices[0]` only, and only at the start of an LBRR run —
/// once a run is going, the delta coding carries it forward on its own.
#[allow(clippy::too_many_arguments)]
fn encode_lbrr(
    state: &mut FrameEncoderState,
    indices: &SideIndices,
    control: &crate::opus::silk::enc::frame::AnalysisControl,
    x16: &[i16],
    seed: u8,
    gain_increase: i32,
    lbrr_continues: bool,
    cond_coding: CondCoding,
    nsq_config: &NsqConfig,
) -> LbrrFrame {
    let mut lbrr = LbrrFrame {
        indices: *indices,
        seed,
        pulses: [0; MAX_FRAME_LENGTH],
    };

    if !lbrr_continues {
        // First LBRR frame of a run: raise the gain so the redundant copy costs fewer bits.
        state.lbrr_previous_gain_index = state.analysis.shape.last_gain_index;
        lbrr.indices.gains_indices[0] = (i32::from(lbrr.indices.gains_indices[0]) + gain_increase)
            .min(N_LEVELS_QGAIN - 1) as i8;
    }

    // Dequantise through the *decoder's* own path, so the encoder's gains match what an LBRR
    // decoder will reconstruct (`encode_frame_FLP.c:414-421`).
    let decoded = dequantize_gains(
        &GainIndices {
            indices: lbrr.indices.gains_indices,
            count: nsq_config.subframe_count,
            conditional: cond_coding == CondCoding::Conditionally,
        },
        &mut state.lbrr_previous_gain_index,
    );

    let mut lbrr_control = *control;
    for subframe in 0..nsq_config.subframe_count {
        lbrr_control.gains_q16[subframe] = decoded.gains_q16[subframe];
        lbrr_control.gains[subframe] = decoded.gains_q16[subframe] as f32 / 65536.0;
    }

    let input = NsqInput::from_analysis(&lbrr_control, &lbrr.indices, seed, nsq_config);
    let mut nsq_copy = state.nsq;
    lbrr.seed = quantize(&mut nsq_copy, &input, x16, &mut lbrr.pulses[..], nsq_config);
    lbrr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::enc::frame::ComplexitySettings;
    use crate::opus::silk::types::SubframeLayout;

    fn config(rate: InternalRate, duration_ms: usize, snr_db_q7: i32) -> AnalysisConfig {
        AnalysisConfig {
            internal_rate: rate,
            layout: SubframeLayout::from_duration_ms(duration_ms).expect("legal duration"),
            settings: ComplexitySettings::for_complexity(5),
            snr_db_q7,
            use_cbr: false,
            packet_loss_percent: 0,
            frames_per_packet: 1,
            lbrr_enabled: false,
        }
    }

    fn measures() -> SignalMeasures {
        SignalMeasures {
            speech_activity_q8: 220,
            input_quality_bands_q15: [22_000; 4],
            input_tilt_q15: 1000,
            previous_signal_type: SignalType::Inactive,
        }
    }

    /// A deterministic voiced-like input: a pulse train through a two-formant filter.
    fn voiced_signal(length: usize, period: usize) -> Vec<f32> {
        let mut state = 24_680u32;
        let mut signal = vec![0.0f32; length];
        let mut history = [0.0f32; 2];
        for (index, slot) in signal.iter_mut().enumerate() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 20) as i32 - 2048) as f32 * 0.5;
            let pulse = if index % period == 0 { 4000.0 } else { 0.0 };
            let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
            history[1] = history[0];
            history[0] = value;
            *slot = value.clamp(-30_000.0, 30_000.0);
        }
        signal
    }

    /// The SNR table has to be monotonic in the target rate and clamp at both ends, or the search
    /// it seeds starts from the wrong place.
    #[test]
    fn control_snr_is_monotonic_and_clamped() {
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            let mut previous = -1;
            for bitrate in (4_000..80_000).step_by(400) {
                let snr = control_snr(bitrate, rate, 4);
                assert!(snr >= previous, "{rate:?} at {bitrate}: {snr} < {previous}");
                previous = snr;
            }
            assert_eq!(control_snr(0, rate, 4), 0);
            assert_eq!(control_snr(1_000_000, rate, 4), 255 * 21);
            // A 10 ms frame targets a lower SNR at the same rate, because its side info is
            // amortised over half as many samples.
            assert!(control_snr(20_000, rate, 2) < control_snr(20_000, rate, 4));
        }
    }

    /// The whole point of the loop: a frame must actually land inside its budget. Checked across a
    /// wide budget range so both the early exit and the bisection are exercised.
    #[test]
    fn every_budget_is_respected() {
        for max_bits in [400i32, 700, 1200, 2000, 4000] {
            for use_cbr in [false, true] {
                let configuration = config(InternalRate::Wide16k, 20, 2600);
                let history = configuration.required_history();
                let total =
                    history + configuration.frame_length() + configuration.required_lookahead();
                let signal = voiced_signal(total, 80);
                let mut state = FrameEncoderState {
                    analysis: AnalysisState {
                        first_frame_after_reset: false,
                        ..AnalysisState::default()
                    },
                    ..FrameEncoderState::default()
                };
                state.analysis.shape.last_gain_index = 10;
                let mut buffer = [0u8; 1275];
                let mut encoder = RangeEncoder::new(&mut buffer);
                let mut pulses = [0i8; MAX_FRAME_LENGTH];

                let result = encode_frame(
                    &mut state,
                    &mut encoder,
                    &FrameEncodeRequest {
                        signal: &signal,
                        frame_start: history,
                        signal_type: SignalType::Unvoiced,
                        cond_coding: CondCoding::Independently,
                        measures: &measures(),
                        config: &configuration,
                        max_bits,
                        use_cbr,
                        lbrr_gain_increase: None,
                        lbrr_continues: false,
                    },
                    &mut pulses,
                )
                .expect("encode");

                assert!(
                    result.payload_bytes * 8 <= max_bits as usize + 8,
                    "budget {max_bits} cbr {use_cbr}: produced {} bytes",
                    result.payload_bytes
                );
                assert!(!encoder.error());
                assert!(result.seed < 4);
            }
        }
    }

    /// CBR must fill the budget, not merely fit inside it: that is the entire difference between
    /// the two regimes at this layer.
    ///
    /// The two stages have to agree for this to mean anything. `control_snr` sets the analysis'
    /// quality target from the same bitrate the budget comes from, because the gain loop can only
    /// move the multiplier between 64 and 1024 in Q8 — a budget far away from what the analysis was
    /// aimed at is not reachable in six iterations, in libopus either.
    #[test]
    fn cbr_fills_the_budget_where_vbr_does_not() {
        let target_bitrate = 24_000;
        let max_bits = target_bitrate * 20 / 1000;
        let configuration = config(
            InternalRate::Wide16k,
            20,
            control_snr(target_bitrate, InternalRate::Wide16k, 4),
        );
        let history = configuration.required_history();
        let total = history + configuration.frame_length() + configuration.required_lookahead();
        let signal = voiced_signal(total, 80);

        let mut sizes = Vec::new();
        for use_cbr in [false, true] {
            let mut state = FrameEncoderState {
                analysis: AnalysisState {
                    first_frame_after_reset: false,
                    ..AnalysisState::default()
                },
                ..FrameEncoderState::default()
            };
            state.analysis.shape.last_gain_index = 10;
            let mut buffer = [0u8; 1275];
            let mut encoder = RangeEncoder::new(&mut buffer);
            let mut pulses = [0i8; MAX_FRAME_LENGTH];
            let result = encode_frame(
                &mut state,
                &mut encoder,
                &FrameEncodeRequest {
                    signal: &signal,
                    frame_start: history,
                    signal_type: SignalType::Unvoiced,
                    cond_coding: CondCoding::Independently,
                    measures: &measures(),
                    config: &configuration,
                    max_bits,
                    use_cbr,
                    lbrr_gain_increase: None,
                    lbrr_continues: false,
                },
                &mut pulses,
            )
            .expect("encode");
            sizes.push(result.payload_bytes);
        }
        assert!(
            sizes[1] >= sizes[0],
            "cbr {} must not be smaller than vbr {}",
            sizes[1],
            sizes[0]
        );
        assert!(
            sizes[1] * 8 >= max_bits as usize - 40,
            "cbr produced only {} bytes of a {max_bits}-bit budget",
            sizes[1]
        );
        assert!(
            sizes[1] * 8 <= max_bits as usize + 8,
            "cbr overshot: {} bytes",
            sizes[1]
        );
    }

    /// A tighter budget must produce a smaller frame — the loop's lever has to actually move.
    #[test]
    fn a_tighter_budget_produces_a_smaller_frame() {
        let configuration = config(InternalRate::Wide16k, 20, 2600);
        let history = configuration.required_history();
        let total = history + configuration.frame_length() + configuration.required_lookahead();
        let signal = voiced_signal(total, 80);

        let mut sizes = Vec::new();
        for max_bits in [500i32, 1000, 2500] {
            let mut state = FrameEncoderState {
                analysis: AnalysisState {
                    first_frame_after_reset: false,
                    ..AnalysisState::default()
                },
                ..FrameEncoderState::default()
            };
            state.analysis.shape.last_gain_index = 10;
            let mut buffer = [0u8; 1275];
            let mut encoder = RangeEncoder::new(&mut buffer);
            let mut pulses = [0i8; MAX_FRAME_LENGTH];
            let result = encode_frame(
                &mut state,
                &mut encoder,
                &FrameEncodeRequest {
                    signal: &signal,
                    frame_start: history,
                    signal_type: SignalType::Unvoiced,
                    cond_coding: CondCoding::Independently,
                    measures: &measures(),
                    config: &configuration,
                    max_bits,
                    use_cbr: true,
                    lbrr_gain_increase: None,
                    lbrr_continues: false,
                },
                &mut pulses,
            )
            .expect("encode");
            sizes.push(result.payload_bytes);
        }
        assert!(sizes[0] < sizes[1] && sizes[1] < sizes[2], "{sizes:?}");
    }

    /// An LBRR copy must be produced, must be a *different* quantisation of the same analysis, and
    /// must leave the regular path's quantiser state untouched.
    #[test]
    fn lbrr_is_a_second_quantisation_that_does_not_disturb_the_first() {
        let configuration = config(InternalRate::Wide16k, 20, 2600);
        let history = configuration.required_history();
        let total = history + configuration.frame_length() + configuration.required_lookahead();
        let signal = voiced_signal(total, 80);

        let mut without = FrameEncoderState {
            analysis: AnalysisState {
                first_frame_after_reset: false,
                ..AnalysisState::default()
            },
            ..FrameEncoderState::default()
        };
        without.analysis.shape.last_gain_index = 10;
        let mut with = without;

        let mut plain_buffer = [0u8; 1275];
        let mut plain = RangeEncoder::new(&mut plain_buffer);
        let mut plain_pulses = [0i8; MAX_FRAME_LENGTH];
        let plain_request = FrameEncodeRequest {
            signal: &signal,
            frame_start: history,
            signal_type: SignalType::Unvoiced,
            cond_coding: CondCoding::Independently,
            measures: &measures(),
            config: &configuration,
            max_bits: 2000,
            use_cbr: false,
            lbrr_gain_increase: None,
            lbrr_continues: false,
        };
        let plain_result =
            encode_frame(&mut without, &mut plain, &plain_request, &mut plain_pulses)
                .expect("encode");
        assert!(plain_result.lbrr.is_none());

        let mut lbrr_buffer = [0u8; 1275];
        let mut lbrr_encoder = RangeEncoder::new(&mut lbrr_buffer);
        let mut lbrr_pulses = [0i8; MAX_FRAME_LENGTH];
        let lbrr_result = encode_frame(
            &mut with,
            &mut lbrr_encoder,
            &FrameEncodeRequest {
                lbrr_gain_increase: Some(7),
                ..plain_request
            },
            &mut lbrr_pulses,
        )
        .expect("encode");

        let lbrr = lbrr_result.lbrr.expect("an LBRR copy was requested");
        // Same analysis: identical NLSFs and pitch, only the gain index moved.
        assert_eq!(lbrr.indices.nlsf.indices, plain_result.indices.nlsf.indices);
        assert_eq!(lbrr.indices.lag_index, plain_result.indices.lag_index);
        assert!(lbrr.indices.gains_indices[0] > plain_result.indices.gains_indices[0]);
        // A coarser gain must cost fewer pulses.
        let redundant: i64 = lbrr.pulses.iter().map(|&p| i64::from(p).abs()).sum();
        let regular: i64 = lbrr_pulses.iter().map(|&p| i64::from(p).abs()).sum();
        assert!(redundant < regular, "lbrr {redundant} vs regular {regular}");
        // And generating it must not have moved the regular path's quantiser.
        assert_eq!(plain_result.payload_bytes, lbrr_result.payload_bytes);
        assert_eq!(&plain_pulses[..], &lbrr_pulses[..]);
    }

    /// Every rate and duration must encode inside a plausible budget without erroring.
    #[test]
    fn every_rate_and_duration_encodes() {
        for rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            for duration_ms in [10usize, 20] {
                let bitrate = 8_000 + 1_000 * rate.khz() as i32;
                let snr = control_snr(
                    bitrate,
                    rate,
                    SubframeLayout::from_duration_ms(duration_ms)
                        .expect("duration")
                        .subframe_count,
                );
                let configuration = config(rate, duration_ms, snr);
                let history = configuration.required_history();
                let total =
                    history + configuration.frame_length() + configuration.required_lookahead();
                let signal = voiced_signal(total, 5 * rate.khz());
                let mut state = FrameEncoderState {
                    analysis: AnalysisState {
                        first_frame_after_reset: false,
                        ..AnalysisState::default()
                    },
                    ..FrameEncoderState::default()
                };
                state.analysis.shape.last_gain_index = 10;
                let mut buffer = [0u8; 1275];
                let mut encoder = RangeEncoder::new(&mut buffer);
                let mut pulses = [0i8; MAX_FRAME_LENGTH];
                let max_bits = bitrate * duration_ms as i32 / 1000;

                let result = encode_frame(
                    &mut state,
                    &mut encoder,
                    &FrameEncodeRequest {
                        signal: &signal,
                        frame_start: history,
                        signal_type: SignalType::Unvoiced,
                        cond_coding: CondCoding::Independently,
                        measures: &measures(),
                        config: &configuration,
                        max_bits,
                        use_cbr: false,
                        lbrr_gain_increase: None,
                        lbrr_continues: false,
                    },
                    &mut pulses,
                )
                .unwrap_or_else(|error| panic!("{rate:?} {duration_ms} ms: {error}"));

                assert!(result.payload_bytes > 0);
                assert!(!encoder.error());
            }
        }
    }
}
