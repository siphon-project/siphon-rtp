//! Packet-loss concealment (RFC 6716 §4.4; libopus `silk/PLC.c`).
//!
//! When a packet does not arrive, SILK does not go silent — it extrapolates. The concealer keeps the
//! last good frame's short-term filter, long-term taps and gain, and runs the same synthesis chain
//! [`super::synthesis::decode_core`] runs, but driven by a **randomly resampled slice of the last
//! excitation** instead of a decoded one. Each further lost frame attenuates the pitch prediction and
//! the noise, so a long outage fades out rather than buzzing.
//!
//! Three pieces of state have to survive between frames and are why this is a struct rather than a
//! function:
//!
//! * [`PlcState::rand_seed`] — the concealment LCG. RFC 6716 §4.4 is explicit that it carries across
//!   concealed frames; restarting it per frame would make consecutive lost frames identical, which is
//!   audible as a tone.
//! * [`PlcState::rand_scale_q14`] and [`PlcState::pitch_lag_q8`] — the running attenuation and the
//!   slowly drifting pitch, both updated per subframe *inside* the concealment loop.
//! * [`PlcState::conc_energy`] — the energy of the last concealed frame, used by
//!   [`glue_frames`] to fade the first good frame in rather than let it step.

use crate::opus::silk::decoder::ChannelState;
use crate::opus::silk::fixed::{
    inverse32_var_q, lshift_sat32, rshift_round, sat16, smlawb, smulbb, smulwb, smulww,
    sqrt_approx, sum_sqr_shift,
};
use crate::opus::silk::lpc::{bwexpander_q12, inverse_prediction_gain_q12};
use crate::opus::silk::synthesis::{lpc_analysis_filter, DecoderControl, MAX_LTP_MEM_LENGTH};
use crate::opus::silk::types::{
    InternalRate, SignalType, LTP_ORDER, MAX_FRAME_LENGTH, MAX_LPC_ORDER, MAX_NB_SUBFR,
};
use crate::CodecError;

/// `NB_ATT` (`PLC.c:40`) — attenuation table length; the second entry applies from the second
/// consecutive loss onward.
const ATTENUATION_STAGES: usize = 2;
/// `HARM_ATT_Q15` — 0.99 then 0.95, the per-subframe decay of the long-term taps.
const HARMONIC_ATTENUATION_Q15: [i16; ATTENUATION_STAGES] = [32_440, 31_130];
/// `PLC_RAND_ATTENUATE_V_Q15` — 0.95 then 0.8, for a voiced last frame.
const RANDOM_ATTENUATION_VOICED_Q15: [i16; ATTENUATION_STAGES] = [31_130, 26_214];
/// `PLC_RAND_ATTENUATE_UV_Q15` — 0.99 then 0.9, for an unvoiced one.
const RANDOM_ATTENUATION_UNVOICED_Q15: [i16; ATTENUATION_STAGES] = [32_440, 29_491];

/// `BWE_COEF` (`PLC.h:33`) — 0.99, as `SILK_FIX_CONST(0.99, 16)`. The concealed LPC filter is chirped
/// by this every lost frame so its poles walk inwards and the extrapolation cannot ring forever.
const BWE_COEF_Q16: i32 = 64_881;
/// `V_PITCH_GAIN_START_MIN_Q14` (`PLC.h:34`) — 0.7.
const PITCH_GAIN_START_MIN_Q14: i32 = 11_469;
/// `V_PITCH_GAIN_START_MAX_Q14` (`PLC.h:35`) — 0.95.
const PITCH_GAIN_START_MAX_Q14: i32 = 15_565;
/// `MAX_PITCH_LAG_MS` (`PLC.h:36`).
const MAX_PITCH_LAG_MS: i32 = 18;
/// `RAND_BUF_SIZE` (`PLC.h:37`) — how much of the last excitation the noise generator draws from.
const RAND_BUF_SIZE: usize = 128;
/// `RAND_BUF_MASK` (`PLC.h:38`).
const RAND_BUF_MASK: i32 = (RAND_BUF_SIZE - 1) as i32;
/// `LOG2_INV_LPC_GAIN_HIGH_THRES` (`PLC.h:39`) — 8 dB of LPC gain.
const LOG2_INV_LPC_GAIN_HIGH_THRES: u32 = 3;
/// `LOG2_INV_LPC_GAIN_LOW_THRES` (`PLC.h:40`) — 24 dB.
const LOG2_INV_LPC_GAIN_LOW_THRES: u32 = 8;
/// `PITCH_DRIFT_FAC_Q16` (`PLC.h:41`) — 0.01; the concealed pitch lengthens by 1 % per subframe so a
/// long outage does not sit on one exact period.
const PITCH_DRIFT_FAC_Q16: i32 = 655;

/// `silk_RAND(seed)` (`SigProc_FIX.h:600`) — the shared SILK LCG.
#[inline]
fn next_random(seed: i32) -> i32 {
    // RAND_INCREMENT + seed * RAND_MULTIPLIER, wrapping.
    907_633_515i32.wrapping_add(seed.wrapping_mul(196_314_165))
}

/// Concealment state (libopus `silk_PLC_struct`, `structs.h:253-268`).
#[derive(Debug, Clone)]
pub struct PlcState {
    /// `pitchL_Q8` — the lag the concealed voiced excitation is drawn at, drifting upwards per
    /// subframe.
    pub pitch_lag_q8: i32,
    /// `LTPCoef_Q14[LTP_ORDER]` — the long-term taps to conceal with, attenuated per subframe.
    pub ltp_coef_q14: [i16; LTP_ORDER],
    /// `prevLPC_Q12[MAX_LPC_ORDER]` — the last good frame's second-half short-term filter.
    pub prev_lpc_q12: [i16; MAX_LPC_ORDER],
    /// `last_frame_lost`.
    pub last_frame_lost: bool,
    /// `rand_seed` — the cross-frame concealment LCG seed (RFC 6716 §4.4).
    pub rand_seed: i32,
    /// `randScale_Q14` — the running amplitude of the random excitation component.
    pub rand_scale_q14: i16,
    /// `conc_energy` / `conc_energy_shift` — energy of the last concealed frame, for [`glue_frames`].
    pub concealed_energy: i32,
    /// Shift the energy above was scaled by.
    pub concealed_energy_shift: i32,
    /// `prevLTP_scale_Q14`.
    pub prev_ltp_scale_q14: i16,
    /// `prevGain_Q16[2]` — the last good frame's final two subframe gains.
    pub prev_gain_q16: [i32; 2],
    /// `fs_kHz` — the rate this state was built for; a change re-initialises it.
    pub rate_khz: usize,
    /// `nb_subfr` of the last good frame.
    pub subframe_count: usize,
    /// `subfr_length` of the last good frame.
    pub subframe_length: usize,
}

impl PlcState {
    /// A fresh state. The C reaches this through `silk_reset_decoder` → `silk_PLC_Reset` with
    /// `frame_length == 0`, so the seeded pitch lag is 0 until the first [`PlcState::reset_for_rate`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            pitch_lag_q8: 0,
            ltp_coef_q14: [0; LTP_ORDER],
            prev_lpc_q12: [0; MAX_LPC_ORDER],
            last_frame_lost: false,
            rand_seed: 0,
            rand_scale_q14: 0,
            concealed_energy: 0,
            concealed_energy_shift: 0,
            prev_ltp_scale_q14: 0,
            prev_gain_q16: [1 << 16; 2],
            rate_khz: 0,
            subframe_count: 2,
            subframe_length: 20,
        }
    }

    /// `silk_PLC_Reset` (`PLC.c:61-70`) — re-seed for a new internal rate and frame length.
    ///
    /// Note what it does *not* touch: `rand_seed` and `randScale_Q14` survive, because the C's reset
    /// only rewrites the four fields listed here.
    pub fn reset_for_rate(&mut self, frame_length: usize) {
        // silk_LSHIFT( frame_length, 8 - 1 ): half the frame, in Q8.
        self.pitch_lag_q8 = (frame_length as i32) << 7;
        self.prev_gain_q16 = [1 << 16; 2];
        self.subframe_length = 20;
        self.subframe_count = 2;
    }
}

impl Default for PlcState {
    fn default() -> Self {
        Self::new()
    }
}

/// Scratch for [`conceal`] — the C's two `VARDECL`s, caller-owned so concealment allocates nothing.
#[derive(Debug, Clone)]
pub struct PlcScratch {
    /// `sLTP[ltp_mem_length]` — the re-whitened output history.
    history: [i16; MAX_LTP_MEM_LENGTH],
    /// `sLTP_Q14[ltp_mem_length + frame_length]` — the same history in Q14, then the concealed frame.
    /// The LPC synthesis deliberately runs **in place** over its tail, exactly as the C aliases
    /// `sLPC_Q14_ptr` into this buffer (`PLC.c:368`).
    scaled_q14: [i32; MAX_LTP_MEM_LENGTH + MAX_FRAME_LENGTH],
}

impl PlcScratch {
    /// A zeroed scratch block.
    #[must_use]
    pub fn new() -> Self {
        Self {
            history: [0; MAX_LTP_MEM_LENGTH],
            scaled_q14: [0; MAX_LTP_MEM_LENGTH + MAX_FRAME_LENGTH],
        }
    }
}

impl Default for PlcScratch {
    fn default() -> Self {
        Self::new()
    }
}

/// `silk_PLC` (`PLC.c:72-114`) — the entry point both the good-frame and the lost-frame path go
/// through.
///
/// On a good frame it only *records* what a future loss would need; on a lost frame it synthesises
/// `frame` and bumps the channel's loss counter. A change of internal rate re-seeds the state first,
/// which is the C's lazy `fs_kHz` check rather than an explicit call from the rate setter.
pub fn run(
    channel: &mut ChannelState,
    control: &mut DecoderControl,
    signal_type: SignalType,
    lost: bool,
    frame: &mut [i16],
    scratch: &mut PlcScratch,
) -> Result<(), CodecError> {
    let rate = channel.internal_rate()?;
    let frame_length = channel.frame_length()?;
    if channel.plc.rate_khz != rate.khz() {
        channel.plc.reset_for_rate(frame_length);
        channel.plc.rate_khz = rate.khz();
    }
    if lost {
        conceal(channel, control, frame, scratch)?;
        channel.loss_count += 1;
    } else {
        update(channel, control, signal_type, rate);
    }
    Ok(())
}

/// `silk_PLC_update` (`PLC.c:119-190`) — remember what the next lost frame will extrapolate from.
///
/// For a voiced frame it picks the **last subframe that still contains a pitch pulse** and keeps its
/// summed long-term gain as a single centre tap, clamped into 0.7..=0.95 so concealment neither dies
/// immediately nor rings. An unvoiced frame keeps no taps and parks the lag at 18 ms.
fn update(
    channel: &mut ChannelState,
    control: &DecoderControl,
    signal_type: SignalType,
    rate: InternalRate,
) {
    let subframe_count = channel.subframe_count();
    let subframe_length = rate.subframe_length();
    let order = rate.lpc_order();
    channel.prev_signal_type = signal_type;
    let state = &mut channel.plc;

    let mut ltp_gain_q14 = 0i32;
    if signal_type == SignalType::Voiced {
        // Walk back from the last subframe while it is still inside one pitch period of the end.
        let mut back = 0usize;
        while (back * subframe_length) < control.pitch_lags[subframe_count - 1] as usize {
            if back == subframe_count {
                break;
            }
            let subframe = subframe_count - 1 - back;
            let candidate_q14: i32 = control
                .ltp_taps_q14(subframe)
                .iter()
                .map(|&tap| i32::from(tap))
                .sum();
            if candidate_q14 > ltp_gain_q14 {
                ltp_gain_q14 = candidate_q14;
                state
                    .ltp_coef_q14
                    .copy_from_slice(control.ltp_taps_q14(subframe));
                state.pitch_lag_q8 = control.pitch_lags[subframe] << 8;
            }
            back += 1;
        }

        // Collapse to a single centre tap carrying the whole gain (PLC.c:153-154).
        state.ltp_coef_q14 = [0; LTP_ORDER];
        state.ltp_coef_q14[LTP_ORDER / 2] = ltp_gain_q14 as i16;

        if ltp_gain_q14 < PITCH_GAIN_START_MIN_Q14 {
            let scale_q10 = (PITCH_GAIN_START_MIN_Q14 << 10) / ltp_gain_q14.max(1);
            for tap in state.ltp_coef_q14.iter_mut() {
                *tap = (smulbb(i32::from(*tap), scale_q10) >> 10) as i16;
            }
        } else if ltp_gain_q14 > PITCH_GAIN_START_MAX_Q14 {
            let scale_q14 = (PITCH_GAIN_START_MAX_Q14 << 14) / ltp_gain_q14.max(1);
            for tap in state.ltp_coef_q14.iter_mut() {
                *tap = (smulbb(i32::from(*tap), scale_q14) >> 14) as i16;
            }
        }
    } else {
        state.pitch_lag_q8 = smulbb(rate.khz() as i32, 18) << 8;
        state.ltp_coef_q14 = [0; LTP_ORDER];
    }

    state.prev_lpc_q12[..order].copy_from_slice(&control.pred_coef_q12[1][..order]);
    state.prev_ltp_scale_q14 = control.ltp_scale_q14 as i16;
    state.prev_gain_q16 = [
        control.gains_q16[subframe_count - 2],
        control.gains_q16[subframe_count - 1],
    ];
    state.subframe_length = subframe_length;
    state.subframe_count = subframe_count;
}

/// `silk_PLC_energy` (`PLC.c:192-214`) — the energy of each of the last two excitation subframes,
/// scaled back into the sample domain by the gain that produced them.
fn concealment_energies(
    excitation_q14: &[i32],
    previous_gain_q10: [i32; 2],
    subframe_length: usize,
    subframe_count: usize,
) -> ((i32, i32), (i32, i32)) {
    let mut buffer = [0i16; 2 * crate::opus::silk::types::MAX_SUB_FRAME_LENGTH];
    for half in 0..2 {
        let base = (half + subframe_count - 2) * subframe_length;
        for sample in 0..subframe_length {
            buffer[half * subframe_length + sample] =
                sat16(smulww(excitation_q14[base + sample], previous_gain_q10[half]) >> 8);
        }
    }
    (
        sum_sqr_shift(&buffer[..subframe_length]),
        sum_sqr_shift(&buffer[subframe_length..2 * subframe_length]),
    )
}

/// `silk_PLC_conceal` (`PLC.c:216-430`) — synthesise one concealed frame.
fn conceal(
    channel: &mut ChannelState,
    control: &mut DecoderControl,
    frame: &mut [i16],
    scratch: &mut PlcScratch,
) -> Result<(), CodecError> {
    let rate = channel.internal_rate()?;
    let order = rate.lpc_order();
    let subframe_length = rate.subframe_length();
    let ltp_memory_length = rate.ltp_memory_length();
    let subframe_count = channel.subframe_count();
    let frame_length = subframe_count * subframe_length;
    if frame.len() < frame_length {
        return Err(CodecError::Unsupported(
            "silk: concealment output buffer shorter than the frame",
        ));
    }
    // Split the channel into disjoint field borrows: the concealer reads the excitation and the
    // output history while it mutates the PLC state and the LPC filter memory.
    let ChannelState {
        plc: state,
        out_buf,
        excitation_q14,
        lpc_state_q14,
        first_frame_after_reset,
        prev_signal_type,
        loss_count,
        ..
    } = channel;
    let (first_frame_after_reset, prev_signal_type, loss_count) =
        (*first_frame_after_reset, *prev_signal_type, *loss_count);

    let previous_gain_q10 = [state.prev_gain_q16[0] >> 6, state.prev_gain_q16[1] >> 6];
    if first_frame_after_reset {
        state.prev_lpc_q12 = [0; MAX_LPC_ORDER];
    }

    // Draw the random excitation from whichever of the last two subframes was quieter — the quieter
    // one is more likely to be noise than a pitch pulse.
    let ((energy1, shift1), (energy2, shift2)) = concealment_energies(
        excitation_q14,
        previous_gain_q10,
        subframe_length,
        subframe_count,
    );
    let random_base = if (energy1 >> shift2) < (energy2 >> shift1) {
        ((state.subframe_count - 1) * state.subframe_length).saturating_sub(RAND_BUF_SIZE)
    } else {
        (state.subframe_count * state.subframe_length).saturating_sub(RAND_BUF_SIZE)
    };

    let attenuation_stage = (loss_count as usize).min(ATTENUATION_STAGES - 1);
    let harmonic_gain_q15 = i32::from(HARMONIC_ATTENUATION_Q15[attenuation_stage]);
    let mut random_gain_q15 = if prev_signal_type == SignalType::Voiced {
        i32::from(RANDOM_ATTENUATION_VOICED_Q15[attenuation_stage])
    } else {
        i32::from(RANDOM_ATTENUATION_UNVOICED_Q15[attenuation_stage])
    };

    // Chirp the concealed short-term filter inwards.
    bwexpander_q12(&mut state.prev_lpc_q12[..order], BWE_COEF_Q16);
    let coefficients_q12 = state.prev_lpc_q12;

    let mut random_scale_q14 = i32::from(state.rand_scale_q14);
    if loss_count == 0 {
        random_scale_q14 = 1 << 14;
        if prev_signal_type == SignalType::Voiced {
            // A strongly voiced last frame needs little noise: subtract the harmonic gain.
            for &tap in &state.ltp_coef_q14 {
                random_scale_q14 -= i32::from(tap);
            }
            random_scale_q14 = random_scale_q14.max(3277); // 0.2
            random_scale_q14 = smulbb(random_scale_q14, i32::from(state.prev_ltp_scale_q14)) >> 14;
        } else {
            // An unvoiced frame with a high LPC gain also needs less noise, or the synthesis filter
            // amplifies it (PLC.c:300-309).
            let mut down_scale_q30 = inverse_prediction_gain_q12(&coefficients_q12[..order])
                .min((1i32 << 30) >> LOG2_INV_LPC_GAIN_HIGH_THRES);
            down_scale_q30 = down_scale_q30.max((1i32 << 30) >> LOG2_INV_LPC_GAIN_LOW_THRES);
            down_scale_q30 = ((down_scale_q30 as u32) << LOG2_INV_LPC_GAIN_HIGH_THRES) as i32;
            random_gain_q15 = smulwb(down_scale_q30, random_gain_q15) >> 14;
        }
    }

    let mut random_seed = state.rand_seed;
    let mut lag = rshift_round(state.pitch_lag_q8, 8);
    let mut ltp_buffer_index = ltp_memory_length;

    // Re-whiten the output history with the concealed filter, then scale it by the inverse of the
    // last good gain so the long-term predictor works in the same domain the excitation does.
    let start_index = (ltp_memory_length as i32) - lag - (order as i32) - (LTP_ORDER as i32) / 2;
    if start_index <= 0 {
        return Err(CodecError::Malformed(
            "silk: concealed pitch lag leaves no history",
        ));
    }
    let start_index = start_index as usize;
    lpc_analysis_filter(
        &mut scratch.history[start_index..ltp_memory_length],
        &out_buf[start_index..ltp_memory_length],
        &coefficients_q12[..order],
    )?;
    let inverse_gain_q30 = inverse32_var_q(state.prev_gain_q16[1], 46).min(i32::MAX >> 1);
    for index in start_index + order..ltp_memory_length {
        scratch.scaled_q14[index] = smulwb(inverse_gain_q30, i32::from(scratch.history[index]));
    }

    // ── Long-term synthesis ───────────────────────────────────────────────────────────────────
    for _ in 0..subframe_count {
        let base = ltp_buffer_index - lag as usize + LTP_ORDER / 2;
        for sample in 0..subframe_length {
            let mut prediction_q12 = 2i32;
            for (tap_index, &tap) in state.ltp_coef_q14.iter().enumerate() {
                prediction_q12 = smlawb(
                    prediction_q12,
                    scratch.scaled_q14[base + sample - tap_index],
                    i32::from(tap),
                );
            }
            // The noise component is a random draw from the *last decoded excitation*, not from the
            // buffer being built (`PLC.c:346-348`).
            random_seed = next_random(random_seed);
            let index = ((random_seed >> 25) & RAND_BUF_MASK) as usize;
            scratch.scaled_q14[ltp_buffer_index] = ((smlawb(
                prediction_q12,
                excitation_q14[random_base + index],
                random_scale_q14,
            ) as u32)
                << 2) as i32;
            ltp_buffer_index += 1;
        }

        // Fade the pitch prediction and the noise, and let the pitch drift upwards.
        for tap in state.ltp_coef_q14.iter_mut() {
            *tap = (smulbb(harmonic_gain_q15, i32::from(*tap)) >> 15) as i16;
        }
        random_scale_q14 = smulbb(random_scale_q14, random_gain_q15) >> 15;
        state.pitch_lag_q8 = smlawb(state.pitch_lag_q8, state.pitch_lag_q8, PITCH_DRIFT_FAC_Q16);
        state.pitch_lag_q8 = state
            .pitch_lag_q8
            .min(smulbb(MAX_PITCH_LAG_MS, rate.khz() as i32) << 8);
        lag = rshift_round(state.pitch_lag_q8, 8);
    }

    // ── Short-term synthesis, in place over the long-term output ──────────────────────────────
    let lpc_base = ltp_memory_length - MAX_LPC_ORDER;
    scratch.scaled_q14[lpc_base..lpc_base + MAX_LPC_ORDER].copy_from_slice(lpc_state_q14);
    for (sample, output) in frame.iter_mut().enumerate().take(frame_length) {
        let mut prediction_q10 = (order >> 1) as i32;
        for (tap, &coefficient) in coefficients_q12[..order].iter().enumerate() {
            prediction_q10 = smlawb(
                prediction_q10,
                scratch.scaled_q14[lpc_base + MAX_LPC_ORDER + sample - 1 - tap],
                i32::from(coefficient),
            );
        }
        let slot = lpc_base + MAX_LPC_ORDER + sample;
        scratch.scaled_q14[slot] =
            scratch.scaled_q14[slot].saturating_add(lshift_sat32(prediction_q10, 4));
        *output = sat16(rshift_round(
            smulww(scratch.scaled_q14[slot], previous_gain_q10[1]),
            8,
        ));
    }

    lpc_state_q14.copy_from_slice(
        &scratch.scaled_q14[lpc_base + frame_length..lpc_base + frame_length + MAX_LPC_ORDER],
    );

    state.rand_seed = random_seed;
    state.rand_scale_q14 = random_scale_q14 as i16;
    control.pitch_lags = [lag; MAX_NB_SUBFR];
    Ok(())
}

/// `silk_PLC_glue_frames` (`PLC.c:433-493`) — fade the first good frame after an outage in.
///
/// Concealment usually undershoots the real signal's energy, so letting the next good frame in at
/// full level steps audibly. This ramps its gain from the concealed frame's energy up to unity over
/// (a quarter of) the frame. It also records the concealed frame's own energy on the way past, which
/// is what the next good frame measures against.
pub fn glue_frames(channel: &mut ChannelState, frame: &mut [i16]) {
    let loss_count = channel.loss_count;
    let state = &mut channel.plc;
    if loss_count != 0 {
        let (energy, shift) = sum_sqr_shift(frame);
        state.concealed_energy = energy;
        state.concealed_energy_shift = shift;
        state.last_frame_lost = true;
        return;
    }
    if state.last_frame_lost {
        let (mut energy, energy_shift) = sum_sqr_shift(frame);
        // Normalise the two energies to a common shift before comparing.
        let mut concealed = state.concealed_energy;
        if energy_shift > state.concealed_energy_shift {
            concealed >>= energy_shift - state.concealed_energy_shift;
        } else if energy_shift < state.concealed_energy_shift {
            energy >>= state.concealed_energy_shift - energy_shift;
        }
        if energy > concealed {
            let leading = (concealed.leading_zeros() as i32) - 1;
            let concealed = ((concealed as u32) << leading) as i32;
            let energy = energy >> (24 - leading).max(0) as u32;
            let fraction_q24 = concealed / energy.max(1);
            let mut gain_q16 = ((sqrt_approx(fraction_q24) as u32) << 4) as i32;
            // "Make slope 4x steeper to avoid missing onsets after DTX".
            let slope_q16 = (((1i32 << 16) - gain_q16) / frame.len() as i32) << 2;
            for sample in frame.iter_mut() {
                *sample = smulwb(gain_q16, i32::from(*sample)) as i16;
                gain_q16 += slope_q16;
                if gain_q16 > 1 << 16 {
                    break;
                }
            }
        }
    }
    state.last_frame_lost = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::types::SubframeLayout;

    fn configured_channel(rate: InternalRate, duration_ms: usize) -> ChannelState {
        let mut channel = ChannelState::new();
        let layout = SubframeLayout::from_duration_ms(duration_ms).expect("layout");
        channel.set_internal_rate(rate, layout);
        channel
    }

    fn voiced_control(rate: InternalRate) -> DecoderControl {
        let mut control = DecoderControl::new();
        control.gains_q16 = [1 << 18; MAX_NB_SUBFR];
        control.pitch_lags = [(6 * rate.khz()) as i32; MAX_NB_SUBFR];
        control.ltp_scale_q14 = 15_565;
        for subframe in 0..MAX_NB_SUBFR {
            control.ltp_coef_q14[subframe * LTP_ORDER + LTP_ORDER / 2] = 8_192;
        }
        control.pred_coef_q12[0][0] = 2_048;
        control.pred_coef_q12[1][0] = 2_048;
        control
    }

    /// Give a channel a plausible "last good frame": a periodic output history and a matching
    /// excitation, then run the good-frame PLC update over it.
    fn prime_with_a_good_frame(
        channel: &mut ChannelState,
        control: &mut DecoderControl,
        scratch: &mut PlcScratch,
        period: f64,
    ) {
        for (index, slot) in channel.out_buf.iter_mut().enumerate() {
            *slot = (7000.0 * ((index as f64) * period).sin()) as i16;
        }
        for (index, slot) in channel.excitation_q14.iter_mut().enumerate() {
            *slot = ((index as i32 % 37) - 18) << 10;
        }
        channel.first_frame_after_reset = false;
        run(
            channel,
            control,
            SignalType::Voiced,
            false,
            &mut [0i16; MAX_FRAME_LENGTH],
            scratch,
        )
        .expect("update");
    }

    #[test]
    fn reset_seeds_half_the_frame_as_the_pitch_lag_but_keeps_the_random_seed() {
        let mut state = PlcState::new();
        state.rand_seed = 424_242;
        state.rand_scale_q14 = 1234;
        state.reset_for_rate(320);
        assert_eq!(state.pitch_lag_q8, 320 << 7);
        assert_eq!(state.prev_gain_q16, [1 << 16; 2]);
        assert_eq!(state.subframe_length, 20);
        assert_eq!(state.subframe_count, 2);
        // RFC 6716 §4.4: the concealment PRNG carries across frames, so a reset must not touch it.
        assert_eq!(state.rand_seed, 424_242);
        assert_eq!(state.rand_scale_q14, 1234);
    }

    /// A voiced update collapses the five taps into a single centre tap and clamps the gain into
    /// 0.7..=0.95 — too little and concealment dies instantly, too much and it rings.
    #[test]
    fn voiced_update_clamps_the_concealment_gain() {
        let rate = InternalRate::Wide16k;
        let mut channel = configured_channel(rate, 20);
        channel.plc.rate_khz = rate.khz();

        // Sum of taps well below 0.7 in Q14: must be scaled up to 0.7.
        let mut control = voiced_control(rate);
        for subframe in 0..MAX_NB_SUBFR {
            control.ltp_coef_q14[subframe * LTP_ORDER + LTP_ORDER / 2] = 1_000;
        }
        update(&mut channel, &control, SignalType::Voiced, rate);
        let total: i32 = channel.plc.ltp_coef_q14.iter().map(|&t| i32::from(t)).sum();
        assert!(
            (total - PITCH_GAIN_START_MIN_Q14).abs() <= 2,
            "clamped up to 0.7, got {total}"
        );

        // Sum far above 0.95: scaled down.
        let mut control = voiced_control(rate);
        for subframe in 0..MAX_NB_SUBFR {
            control.ltp_coef_q14[subframe * LTP_ORDER + LTP_ORDER / 2] = 20_000;
        }
        update(&mut channel, &control, SignalType::Voiced, rate);
        let total: i32 = channel.plc.ltp_coef_q14.iter().map(|&t| i32::from(t)).sum();
        assert!(
            (total - PITCH_GAIN_START_MAX_Q14).abs() <= 2,
            "clamped down to 0.95, got {total}"
        );
        // Only the centre tap survives.
        for (index, &tap) in channel.plc.ltp_coef_q14.iter().enumerate() {
            if index != LTP_ORDER / 2 {
                assert_eq!(tap, 0, "tap {index} must be collapsed away");
            }
        }
    }

    #[test]
    fn unvoiced_update_parks_the_lag_at_eighteen_milliseconds_and_drops_the_taps() {
        let rate = InternalRate::Wide16k;
        let mut channel = configured_channel(rate, 20);
        channel.plc.rate_khz = rate.khz();
        let control = voiced_control(rate);
        update(&mut channel, &control, SignalType::Unvoiced, rate);
        assert_eq!(channel.plc.pitch_lag_q8, (18 * 16) << 8);
        assert_eq!(channel.plc.ltp_coef_q14, [0; LTP_ORDER]);
        assert_eq!(channel.prev_signal_type, SignalType::Unvoiced);
        // The last two gains and the second-half filter are what concealment will use.
        assert_eq!(channel.plc.prev_gain_q16, [1 << 18, 1 << 18]);
        assert_eq!(channel.plc.prev_lpc_q12[0], 2_048);
    }

    /// Concealment must produce a real signal from a real history, bump the loss counter, and leave
    /// the PRNG advanced — a concealer that returned silence would pass a "no panic" test and fail
    /// this one.
    #[test]
    fn concealment_extrapolates_rather_than_returning_silence() {
        let rate = InternalRate::Wide16k;
        let mut channel = configured_channel(rate, 20);
        let mut scratch = PlcScratch::new();
        let mut control = voiced_control(rate);
        prime_with_a_good_frame(&mut channel, &mut control, &mut scratch, 0.07);

        let seed_before = channel.plc.rand_seed;
        let mut frame = [0i16; MAX_FRAME_LENGTH];
        run(
            &mut channel,
            &mut control,
            SignalType::Voiced,
            true,
            &mut frame,
            &mut scratch,
        )
        .expect("conceal");

        assert_eq!(channel.loss_count, 1);
        assert_ne!(
            channel.plc.rand_seed, seed_before,
            "the concealment LCG must advance"
        );
        let energy: i64 = frame[..320]
            .iter()
            .map(|&s| i64::from(s) * i64::from(s))
            .sum();
        assert!(energy > 0, "concealment must not return silence");
        // Every concealed pitch lag is written back for the next frame's `lagPrev`.
        assert!(control.pitch_lags.iter().all(|&lag| lag > 0));
    }

    /// Consecutive losses must fade, not hold level — that is the whole point of the two-stage
    /// attenuation tables.
    #[test]
    fn consecutive_losses_attenuate() {
        let rate = InternalRate::Wide16k;
        let mut channel = configured_channel(rate, 20);
        let mut scratch = PlcScratch::new();
        let mut control = voiced_control(rate);
        prime_with_a_good_frame(&mut channel, &mut control, &mut scratch, 0.05);

        let mut energies = Vec::new();
        for _ in 0..6 {
            let mut frame = [0i16; MAX_FRAME_LENGTH];
            run(
                &mut channel,
                &mut control,
                SignalType::Voiced,
                true,
                &mut frame,
                &mut scratch,
            )
            .expect("conceal");
            energies.push(
                frame[..320]
                    .iter()
                    .map(|&s| i64::from(s) * i64::from(s))
                    .sum::<i64>(),
            );
        }
        assert!(
            energies[5] < energies[0],
            "a long outage must fade: {energies:?}"
        );
        assert_eq!(channel.loss_count, 6);
    }

    /// The glue only ever attenuates, and only after a loss. A good frame that follows a good frame
    /// must come through untouched.
    #[test]
    fn glue_leaves_an_uninterrupted_stream_alone() {
        let mut channel = configured_channel(InternalRate::Wide16k, 20);
        let original: Vec<i16> = (0..320).map(|n| ((n * 137) % 4001) as i16 - 2000).collect();
        let mut frame = original.clone();
        glue_frames(&mut channel, &mut frame);
        assert_eq!(frame, original);
        assert!(!channel.plc.last_frame_lost);

        // After a loss, the concealed frame's energy is recorded and the flag set.
        channel.loss_count = 1;
        let mut concealed = original.clone();
        glue_frames(&mut channel, &mut concealed);
        assert_eq!(
            concealed, original,
            "the concealed frame itself is not scaled"
        );
        assert!(channel.plc.last_frame_lost);
        assert!(channel.plc.concealed_energy > 0);
    }

    /// A loud frame arriving after a quiet concealed one must be faded in, not stepped in.
    #[test]
    fn glue_fades_a_loud_frame_in_after_a_quiet_concealment() {
        let mut channel = configured_channel(InternalRate::Wide16k, 20);
        // A very quiet concealed frame.
        channel.loss_count = 1;
        let mut quiet = vec![10i16; 320];
        glue_frames(&mut channel, &mut quiet);

        // Then a loud good frame.
        channel.loss_count = 0;
        let loud = vec![20_000i16; 320];
        let mut frame = loud.clone();
        glue_frames(&mut channel, &mut frame);
        assert!(
            frame[0].abs() < loud[0] / 2,
            "the first sample must be well below full level, got {}",
            frame[0]
        );
        assert!(
            frame[319] == loud[319],
            "and the ramp must have reached unity by the end"
        );
        assert!(!channel.plc.last_frame_lost);
    }
}
