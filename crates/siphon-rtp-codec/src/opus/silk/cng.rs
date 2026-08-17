//! Comfort-noise generation (RFC 6716 §4.4; libopus `silk/CNG.c`).
//!
//! CNG has two halves that run at different times, and conflating them is the usual way to get it
//! wrong:
//!
//! * **Estimation** happens on every *good, inactive* frame. The decoder keeps a slowly smoothed
//!   spectral envelope (the NLSFs), a smoothed gain, and a rolling buffer of the loudest recent
//!   excitation subframe. Nothing is added to the output.
//! * **Synthesis** happens on every *concealed* frame. The estimate above is turned back into a
//!   noise signal and **added** to whatever [`super::plc`] already extrapolated, so a long outage in
//!   speech decays into the background noise the talker was actually sitting in rather than into
//!   digital silence.
//!
//! [`CngState::rand_seed`] is the second of the two PRNG seeds that cross frames (the first is
//! [`super::plc::PlcState::rand_seed`]). It indexes into the excitation buffer, so restarting it per
//! frame would make consecutive concealed frames replay the same noise.

use crate::opus::silk::decoder::ChannelState;
use crate::opus::silk::fixed::{
    add_sat16, lshift_sat32, rshift_round, sat16, smlawb, smultt, smulwb, smulww, sqrt_approx,
    sub_lshift32,
};
use crate::opus::silk::lpc::nlsf_to_lpc_q12;
use crate::opus::silk::synthesis::DecoderControl;
use crate::opus::silk::types::{SignalType, MAX_FRAME_LENGTH, MAX_LPC_ORDER};
use crate::CodecError;

/// `CNG_BUF_MASK_MAX` (`define.h:226`) — `2^floor(log2(MAX_FRAME_LENGTH)) - 1`.
const BUF_MASK_MAX: i32 = 255;
/// `CNG_GAIN_SMTH_Q16` (`define.h:227`) — 0.25^(1/4).
const GAIN_SMOOTHING_Q16: i32 = 4_634;
/// `CNG_GAIN_SMTH_THRESHOLD_Q16` (`define.h:228`) — -3 dB.
const GAIN_SMOOTHING_THRESHOLD_Q16: i32 = 46_396;
/// `CNG_NLSF_SMTH_Q16` (`define.h:229`) — 0.25.
const NLSF_SMOOTHING_Q16: i32 = 16_348;
/// The seed `silk_CNG_Reset` installs (`CNG.c:75`).
const RESET_SEED: i32 = 3_176_576;

/// `silk_RAND(seed)` (`SigProc_FIX.h:600`).
#[inline]
fn next_random(seed: i32) -> i32 {
    907_633_515i32.wrapping_add(seed.wrapping_mul(196_314_165))
}

/// Comfort-noise state (libopus `silk_CNG_struct`, `structs.h:271-278`).
#[derive(Debug, Clone)]
pub struct CngState {
    /// `CNG_exc_buf_Q14[MAX_FRAME_LENGTH]` — the loudest recent excitation subframes, newest first.
    excitation_buffer_q14: [i32; MAX_FRAME_LENGTH],
    /// `CNG_smth_NLSF_Q15[MAX_LPC_ORDER]` — the smoothed spectral envelope.
    smoothed_nlsf_q15: [i16; MAX_LPC_ORDER],
    /// `CNG_synth_state[MAX_LPC_ORDER]` — the noise synthesis filter's memory.
    synthesis_state: [i32; MAX_LPC_ORDER],
    /// `CNG_smth_Gain_Q16`.
    smoothed_gain_q16: i32,
    /// `rand_seed` — the cross-frame noise-selection PRNG (RFC 6716 §4.4).
    pub rand_seed: i32,
    /// `fs_kHz` — a change re-initialises the estimate.
    rate_khz: usize,
}

impl CngState {
    /// A fresh state, before any rate is known.
    #[must_use]
    pub fn new() -> Self {
        Self {
            excitation_buffer_q14: [0; MAX_FRAME_LENGTH],
            smoothed_nlsf_q15: [0; MAX_LPC_ORDER],
            synthesis_state: [0; MAX_LPC_ORDER],
            smoothed_gain_q16: 0,
            rand_seed: RESET_SEED,
            rate_khz: 0,
        }
    }

    /// `silk_CNG_Reset` (`CNG.c:62-76`) — a flat spectral envelope, zero gain, and the fixed seed.
    ///
    /// The envelope is `order` equally spaced NLSFs, which is white noise: with no estimate yet, a
    /// flat spectrum is the only honest starting point.
    pub fn reset(&mut self, order: usize) {
        let step_q15 = i32::from(i16::MAX) / (order as i32 + 1);
        let mut accumulator_q15 = 0i32;
        for slot in self.smoothed_nlsf_q15.iter_mut().take(order) {
            accumulator_q15 += step_q15;
            *slot = accumulator_q15 as i16;
        }
        self.smoothed_gain_q16 = 0;
        self.rand_seed = RESET_SEED;
    }
}

impl Default for CngState {
    fn default() -> Self {
        Self::new()
    }
}

/// Scratch for [`run`] — the C's one `VARDECL`, caller-owned.
#[derive(Debug, Clone)]
pub struct CngScratch {
    /// `CNG_sig_Q14[length + MAX_LPC_ORDER]`.
    signal_q14: [i32; MAX_FRAME_LENGTH + MAX_LPC_ORDER],
}

impl CngScratch {
    /// A zeroed scratch block.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signal_q14: [0; MAX_FRAME_LENGTH + MAX_LPC_ORDER],
        }
    }
}

impl Default for CngScratch {
    fn default() -> Self {
        Self::new()
    }
}

/// `silk_CNG` (`CNG.c:79-188`) — update the estimate on a good inactive frame, add comfort noise on
/// a concealed one.
///
/// It reads the channel's `lossCnt` **after** [`super::plc::run`] has had its say, and its
/// `prevSignalType` — the signal type of the frame just decoded, which is what decides whether this
/// frame taught CNG anything. The concealment scale and the last good gain come from the channel's
/// [`super::plc::PlcState`]: the concealed frame's own level is what the comfort-noise gain is
/// measured against, so the two stages cannot be decoupled.
pub fn run(
    channel: &mut ChannelState,
    control: &DecoderControl,
    frame: &mut [i16],
    scratch: &mut CngScratch,
) -> Result<(), CodecError> {
    let rate = channel.internal_rate()?;
    let subframe_count = channel.subframe_count();
    let loss_count = channel.loss_count;
    let signal_type_is_inactive = channel.prev_signal_type == SignalType::Inactive;
    let plc_random_scale_q14 = channel.plc.rand_scale_q14;
    let plc_previous_gain_q16 = channel.plc.prev_gain_q16[1];
    // Disjoint field borrows: the estimate reads the interpolation anchor and the excitation while
    // it mutates the comfort-noise state.
    let ChannelState {
        cng: state,
        prev_nlsf_q15: previous_nlsf_q15,
        excitation_q14,
        ..
    } = channel;

    let order = rate.lpc_order();
    let subframe_length = rate.subframe_length();
    let length = frame.len().min(subframe_count * subframe_length);

    if state.rate_khz != rate.khz() {
        state.reset(order);
        state.rate_khz = rate.khz();
    }

    if loss_count == 0 && signal_type_is_inactive {
        // ── Estimation ────────────────────────────────────────────────────────────────────────
        for (smoothed, &target) in state
            .smoothed_nlsf_q15
            .iter_mut()
            .zip(previous_nlsf_q15.iter())
            .take(order)
        {
            let difference = i32::from(target) - i32::from(*smoothed);
            *smoothed = (i32::from(*smoothed) + smulwb(difference, NLSF_SMOOTHING_Q16)) as i16;
        }
        // Keep the loudest subframe's excitation — the quiet ones are more likely to be a gap than
        // the background the talker is actually in.
        let mut loudest = 0usize;
        let mut max_gain_q16 = 0i32;
        for subframe in 0..subframe_count {
            if control.gains_q16[subframe] > max_gain_q16 {
                max_gain_q16 = control.gains_q16[subframe];
                loudest = subframe;
            }
        }
        state
            .excitation_buffer_q14
            .copy_within(0..(subframe_count - 1) * subframe_length, subframe_length);
        state.excitation_buffer_q14[..subframe_length].copy_from_slice(
            &excitation_q14[loudest * subframe_length..(loudest + 1) * subframe_length],
        );

        for subframe in 0..subframe_count {
            state.smoothed_gain_q16 += smulwb(
                control.gains_q16[subframe] - state.smoothed_gain_q16,
                GAIN_SMOOTHING_Q16,
            );
            // "If the smoothed gain is 3 dB greater than this subframe's gain, use this subframe's
            // gain to adapt faster."
            if smulww(state.smoothed_gain_q16, GAIN_SMOOTHING_THRESHOLD_Q16)
                > control.gains_q16[subframe]
            {
                state.smoothed_gain_q16 = control.gains_q16[subframe];
            }
        }
    }

    if loss_count == 0 {
        state.synthesis_state[..order].fill(0);
        return Ok(());
    }

    // ── Synthesis ─────────────────────────────────────────────────────────────────────────────
    // The comfort-noise level is the smoothed background gain with the concealed frame's own
    // contribution subtracted, so the two together stay at the right level (`CNG.c:134-143`).
    let mut gain_q16 = smulww(i32::from(plc_random_scale_q14), plc_previous_gain_q16);
    if gain_q16 >= (1 << 21) || state.smoothed_gain_q16 > (1 << 23) {
        gain_q16 = smultt(gain_q16, gain_q16);
        gain_q16 = sub_lshift32(
            smultt(state.smoothed_gain_q16, state.smoothed_gain_q16),
            gain_q16,
            5,
        );
        gain_q16 = ((sqrt_approx(gain_q16) as u32) << 16) as i32;
    } else {
        gain_q16 = smulww(gain_q16, gain_q16);
        gain_q16 = sub_lshift32(
            smulww(state.smoothed_gain_q16, state.smoothed_gain_q16),
            gain_q16,
            5,
        );
        gain_q16 = ((sqrt_approx(gain_q16) as u32) << 8) as i32;
    }
    let gain_q10 = gain_q16 >> 6;

    // `silk_CNG_exc`: draw `length` samples at random from the stored excitation.
    let mut mask = BUF_MASK_MAX;
    while mask > length as i32 {
        mask >>= 1;
    }
    let mut seed = state.rand_seed;
    for sample in 0..length {
        seed = next_random(seed);
        let index = ((seed >> 24) & mask) as usize;
        scratch.signal_q14[MAX_LPC_ORDER + sample] = state.excitation_buffer_q14[index];
    }
    state.rand_seed = seed;

    // The smoothed NLSFs become a synthesis filter, and the noise is run through it.
    let mut coefficients_q12 = [0i16; MAX_LPC_ORDER];
    nlsf_to_lpc_q12(&mut coefficients_q12, &state.smoothed_nlsf_q15[..order]);
    scratch.signal_q14[..MAX_LPC_ORDER].copy_from_slice(&state.synthesis_state);

    for (sample, output) in frame.iter_mut().enumerate().take(length) {
        let mut prediction_q10 = (order >> 1) as i32;
        for (tap, &coefficient) in coefficients_q12[..order].iter().enumerate() {
            prediction_q10 = smlawb(
                prediction_q10,
                scratch.signal_q14[MAX_LPC_ORDER + sample - 1 - tap],
                i32::from(coefficient),
            );
        }
        let slot = MAX_LPC_ORDER + sample;
        scratch.signal_q14[slot] =
            scratch.signal_q14[slot].saturating_add(lshift_sat32(prediction_q10, 4));
        // Added to, not replacing, whatever concealment produced.
        *output = add_sat16(
            *output,
            sat16(rshift_round(smulww(scratch.signal_q14[slot], gain_q10), 8)),
        );
    }
    state
        .synthesis_state
        .copy_from_slice(&scratch.signal_q14[length..length + MAX_LPC_ORDER]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::types::{InternalRate, SubframeLayout, MAX_NB_SUBFR};

    fn control_with_gains(gains: [i32; MAX_NB_SUBFR]) -> DecoderControl {
        let mut control = DecoderControl::new();
        control.gains_q16 = gains;
        control
    }

    fn configured_channel(rate: InternalRate) -> ChannelState {
        let mut channel = ChannelState::new();
        let layout = SubframeLayout::from_duration_ms(20).expect("layout");
        channel.set_internal_rate(rate, layout);
        channel
    }

    #[test]
    fn reset_installs_a_flat_envelope_and_the_documented_seed() {
        let mut state = CngState::new();
        state.rand_seed = 1;
        state.smoothed_gain_q16 = 999;
        state.reset(16);
        assert_eq!(state.rand_seed, RESET_SEED);
        assert_eq!(state.smoothed_gain_q16, 0);
        // Equally spaced NLSFs: strictly increasing with a constant step.
        let step = i32::from(i16::MAX) / 17;
        for index in 0..16usize {
            assert_eq!(
                state.smoothed_nlsf_q15[index],
                (step * (index as i32 + 1)) as i16,
                "coefficient {index}"
            );
        }
    }

    /// On a good inactive frame CNG only *learns*: the output must come back untouched and the
    /// synthesis filter memory must be cleared.
    #[test]
    fn a_good_frame_updates_the_estimate_without_touching_the_output() {
        let mut channel = configured_channel(InternalRate::Wide16k);
        let mut scratch = CngScratch::new();
        let control = control_with_gains([1 << 18, 1 << 19, 1 << 17, 1 << 16]);
        for (index, slot) in channel.excitation_q14.iter_mut().enumerate() {
            *slot = ((index as i32 % 13) - 6) << 12;
        }
        let excitation = channel.excitation_q14;
        channel.prev_nlsf_q15 = [2_000i16; MAX_LPC_ORDER];
        channel.prev_signal_type = SignalType::Inactive;
        channel.cng.synthesis_state[0] = 12_345;
        let original: Vec<i16> = (0..320).map(|n| (n as i16) * 3 - 400).collect();
        let mut frame = original.clone();

        run(&mut channel, &control, &mut frame, &mut scratch).expect("cng");

        assert_eq!(frame, original, "estimation must not alter the signal");
        assert!(
            channel.cng.smoothed_gain_q16 > 0,
            "the gain estimate must move"
        );
        assert_eq!(
            channel.cng.synthesis_state[0], 0,
            "synthesis memory is cleared"
        );
        // The loudest subframe (index 1) is what was stored.
        assert_eq!(
            &channel.cng.excitation_buffer_q14[..80],
            &excitation[80..160],
            "the loudest subframe's excitation is kept"
        );
    }

    /// An *active* good frame teaches CNG nothing — comfort noise must model the background, not
    /// speech.
    #[test]
    fn an_active_frame_does_not_update_the_estimate() {
        let mut channel = configured_channel(InternalRate::Wide16k);
        let mut scratch = CngScratch::new();
        let control = control_with_gains([1 << 20; MAX_NB_SUBFR]);
        channel.prev_signal_type = SignalType::Voiced;
        let mut frame = [0i16; 320];
        run(&mut channel, &control, &mut frame, &mut scratch).expect("cng");
        assert_eq!(channel.cng.smoothed_gain_q16, 0);
    }

    /// Teach a channel a stationary background, so the synthesis path has something to work from.
    fn teach_background(channel: &mut ChannelState, scratch: &mut CngScratch, seed: usize) {
        let control = control_with_gains([1 << 20; MAX_NB_SUBFR]);
        for (index, slot) in channel.excitation_q14.iter_mut().enumerate() {
            *slot = ((((index * seed) % 4001) as i32) - 2000) << 8;
        }
        channel.prev_nlsf_q15 = [1_500i16; MAX_LPC_ORDER];
        channel.prev_signal_type = SignalType::Inactive;
        for _ in 0..40 {
            let mut quiet = [0i16; 320];
            run(channel, &control, &mut quiet, scratch).expect("cng");
        }
    }

    /// On a concealed frame the noise is *added* to what concealment produced, and the seed
    /// advances so the next concealed frame draws different samples.
    #[test]
    fn a_concealed_frame_adds_noise_and_advances_the_seed() {
        let mut channel = configured_channel(InternalRate::Wide16k);
        let mut scratch = CngScratch::new();
        teach_background(&mut channel, &mut scratch, 7919);
        assert!(channel.cng.smoothed_gain_q16 > 0);

        let seed_before = channel.cng.rand_seed;
        channel.loss_count = 1;
        channel.prev_signal_type = SignalType::Voiced;
        channel.plc.rand_scale_q14 = 1 << 14;
        channel.plc.prev_gain_q16 = [1 << 16; 2];
        let control = control_with_gains([1 << 20; MAX_NB_SUBFR]);
        let mut frame = [100i16; 320];
        run(&mut channel, &control, &mut frame, &mut scratch).expect("cng");

        assert_ne!(
            channel.cng.rand_seed, seed_before,
            "the CNG LCG must advance"
        );
        assert!(
            frame.iter().any(|&sample| sample != 100),
            "comfort noise must actually be added"
        );
    }

    /// Two consecutive concealed frames must not be identical — that is exactly what a per-frame
    /// seed reset would produce, and it sounds like a tone.
    #[test]
    fn consecutive_concealed_frames_draw_different_noise() {
        let mut channel = configured_channel(InternalRate::Wide16k);
        let mut scratch = CngScratch::new();
        teach_background(&mut channel, &mut scratch, 7919);
        let control = control_with_gains([1 << 21; MAX_NB_SUBFR]);
        channel.plc.rand_scale_q14 = 1 << 14;
        channel.plc.prev_gain_q16 = [1 << 16; 2];
        channel.prev_signal_type = SignalType::Voiced;

        channel.loss_count = 1;
        let mut first = [0i16; 320];
        run(&mut channel, &control, &mut first, &mut scratch).expect("cng");
        channel.loss_count = 2;
        let mut second = [0i16; 320];
        run(&mut channel, &control, &mut second, &mut scratch).expect("cng");
        assert_ne!(first, second);
    }

    /// A rate change re-initialises the estimate rather than reinterpreting an envelope built at a
    /// different bandwidth.
    #[test]
    fn a_rate_change_reinitialises_the_estimate() {
        let mut channel = configured_channel(InternalRate::Wide16k);
        let mut scratch = CngScratch::new();
        teach_background(&mut channel, &mut scratch, 4409);
        assert!(channel.cng.smoothed_gain_q16 > 0);

        let layout = SubframeLayout::from_duration_ms(20).expect("layout");
        channel.set_internal_rate(InternalRate::Narrow8k, layout);
        channel.prev_signal_type = SignalType::Voiced;
        let control = control_with_gains([1 << 20; MAX_NB_SUBFR]);
        let mut narrow = [0i16; 160];
        run(&mut channel, &control, &mut narrow, &mut scratch).expect("cng");
        assert_eq!(channel.cng.smoothed_gain_q16, 0, "reset on the rate change");
        assert_eq!(channel.cng.rate_khz, 8);
    }
}
