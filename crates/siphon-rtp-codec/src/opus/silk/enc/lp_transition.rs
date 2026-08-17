//! The bandwidth-transition low-pass (libopus `silk/LP_variable_cutoff.c`, `silk/biquad_alt.c`).
//!
//! # Why a filter exists between two internal rates at all
//!
//! SILK codes at 8, 12 or 16 kHz internally and the Opus layer may want to move between them
//! mid-call. Cutting from one rate to the next on a frame boundary steps the signal's bandwidth in
//! one sample, which is audible as a click. libopus instead *walks* the input bandwidth down towards
//! the target over a long ramp before the rate actually changes, so by the time the switch happens
//! the content above the new Nyquist is already gone and the seam carries no step.
//!
//! The ramp is a second-order elliptic low-pass whose cutoff is interpolated between five designed
//! points (`silk/tables_other.c:97-119`: 0.1 dB passband ripple, 80 dB stopband, normalised cutoffs
//! 0.95 / 0.80 / 0.65 / 0.50 / 0.35). [`TRANSITION_FRAMES`] SILK frames span the whole sweep, and
//! [`LowPassState::mode`] is the direction and speed it is walked at.
//!
//! # Where it sits in the chain
//!
//! Per SILK frame, `silk_encode_frame_FLP` (`encode_frame_FLP.c:129`) runs this over `inputBuf`
//! **after** the VAD and the stereo conversion have read it and immediately before the frame is
//! copied into the analysis buffer. So the VAD's activity measure is taken on the unfiltered signal
//! — which is what keeps the transition from suppressing its own trigger — while everything the
//! quantiser sees is band-limited.
//!
//! # The state machine that drives it
//!
//! [`LowPassState::mode`] is set by `silk_control_audio_bandwidth`
//! ([`super::encoder::SilkEncoder`]), not here: `+1` walks the cutoff up (a rate increase needs no
//! ramp, so this only unwinds a previous ramp), `-2` walks it down at double speed towards a rate
//! decrease, and `0` bypasses the filter entirely. This module only applies whatever mode it is
//! handed and advances [`LowPassState::transition_frame_no`] by it.

use crate::opus::silk::fixed::{limit_int, rshift_round, sat16, smlawb, smulwb};

/// `TRANSITION_TIME_MS` (`define.h:215`) — `64 * 20 * (TRANSITION_INT_NUM - 1)`.
const TRANSITION_TIME_MS: i32 = 5_120;

/// `MAX_FRAME_LENGTH_MS` (`define.h:184`) — the frame the transition counter is measured in.
const MAX_FRAME_LENGTH_MS: i32 = 20;

/// `TRANSITION_FRAMES` (`define.h:219`) — how many SILK frames the whole cutoff sweep spans, 256.
pub const TRANSITION_FRAMES: i32 = TRANSITION_TIME_MS / MAX_FRAME_LENGTH_MS;

/// `TRANSITION_INT_NUM` (`define.h:218`) — designed filters the sweep interpolates between.
const TRANSITION_INT_NUM: usize = 5;

/// `TRANSITION_INT_STEPS` (`define.h:220`) — frames per interpolation interval, 64.
const TRANSITION_INT_STEPS: i32 = TRANSITION_FRAMES / (TRANSITION_INT_NUM as i32 - 1);

/// `TRANSITION_NB` (`define.h:216`) — MA (numerator) taps.
const TRANSITION_NB: usize = 3;

/// `TRANSITION_NA` (`define.h:217`) — AR (denominator) taps.
const TRANSITION_NA: usize = 2;

/// `silk_Transition_LP_B_Q28` (`tables_other.c:102-109`) — the MA taps at the five design points.
const TRANSITION_LP_B_Q28: [[i32; TRANSITION_NB]; TRANSITION_INT_NUM] = [
    [250_767_114, 501_534_038, 250_767_114],
    [209_867_381, 419_732_057, 209_867_381],
    [170_987_846, 341_967_853, 170_987_846],
    [131_531_482, 263_046_905, 131_531_482],
    [89_306_658, 178_584_282, 89_306_658],
];

/// `silk_Transition_LP_A_Q28` (`tables_other.c:112-119`) — the AR taps at the five design points.
const TRANSITION_LP_A_Q28: [[i32; TRANSITION_NA]; TRANSITION_INT_NUM] = [
    [506_393_414, 239_854_379],
    [411_067_935, 169_683_996],
    [306_733_530, 116_694_253],
    [185_807_084, 77_959_395],
    [35_497_197, 57_401_098],
];

/// `silk_LP_state` (`structs.h:52-58`) — one channel's transition-filter state.
///
/// `saved_fs_kHz` is not the filter's; it is the sampling rate the bandwidth state machine has to
/// remember across the encoder reset a prefill performs, so that a prefill on the switching frame
/// still knows which rate it is switching *from* (`enc_API.c:214-218`,
/// `control_audio_bandwidth.c:46-49`). It rides here because this is the one struct that survives
/// that reset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LowPassState {
    /// `In_LP_State` — the biquad's two Q12 state words.
    pub state: [i32; 2],
    /// `transition_frame_no`, 0..=[`TRANSITION_FRAMES`]. 0 is the widest cutoff (the filter is at
    /// design point 4, the *narrowest* — see [`taps_for`]); [`TRANSITION_FRAMES`] is design point 0.
    pub transition_frame_no: i32,
    /// `mode` — 0 off, 1 walk up (one frame per frame), -2 walk down (two per frame).
    pub mode: i32,
    /// `saved_fs_kHz` — see the struct docs.
    pub saved_fs_khz: i32,
}

impl LowPassState {
    /// Clear the filter memory without touching the transition schedule
    /// (`control_audio_bandwidth.c:78`, `:110`).
    pub fn reset_memory(&mut self) {
        self.state = [0; 2];
    }
}

/// `silk_LP_interpolate_filter_taps` (`LP_variable_cutoff.c:41-94`) — the taps for one point on the
/// sweep.
///
/// `index` selects the lower design point and `fraction_q16` the position between it and the next.
/// The C splits the interpolation into a `fac_Q16 < 32768` and a `>= 32768` branch so the
/// `silk_SMLAWB` argument stays inside 16 bits; both reduce to the same linear interpolation, and
/// both are kept because the rounding of the two `SMLAWB`s is not identical.
fn taps_for(index: usize, fraction_q16: i32) -> ([i32; TRANSITION_NB], [i32; TRANSITION_NA]) {
    if index >= TRANSITION_INT_NUM - 1 {
        return (
            TRANSITION_LP_B_Q28[TRANSITION_INT_NUM - 1],
            TRANSITION_LP_A_Q28[TRANSITION_INT_NUM - 1],
        );
    }
    if fraction_q16 <= 0 {
        return (TRANSITION_LP_B_Q28[index], TRANSITION_LP_A_Q28[index]);
    }

    let mut numerator = [0i32; TRANSITION_NB];
    let mut denominator = [0i32; TRANSITION_NA];
    if fraction_q16 < 32_768 {
        // `fac_Q16` fits a 16-bit int, so interpolate forward from the lower point.
        for (tap, slot) in numerator.iter_mut().enumerate() {
            *slot = smlawb(
                TRANSITION_LP_B_Q28[index][tap],
                TRANSITION_LP_B_Q28[index + 1][tap] - TRANSITION_LP_B_Q28[index][tap],
                fraction_q16,
            );
        }
        for (tap, slot) in denominator.iter_mut().enumerate() {
            *slot = smlawb(
                TRANSITION_LP_A_Q28[index][tap],
                TRANSITION_LP_A_Q28[index + 1][tap] - TRANSITION_LP_A_Q28[index][tap],
                fraction_q16,
            );
        }
    } else {
        // `fac_Q16 - (1 << 16)` fits instead, so interpolate *backward* from the upper point.
        let fraction = fraction_q16 - (1 << 16);
        for (tap, slot) in numerator.iter_mut().enumerate() {
            *slot = smlawb(
                TRANSITION_LP_B_Q28[index + 1][tap],
                TRANSITION_LP_B_Q28[index + 1][tap] - TRANSITION_LP_B_Q28[index][tap],
                fraction,
            );
        }
        for (tap, slot) in denominator.iter_mut().enumerate() {
            *slot = smlawb(
                TRANSITION_LP_A_Q28[index + 1][tap],
                TRANSITION_LP_A_Q28[index + 1][tap] - TRANSITION_LP_A_Q28[index][tap],
                fraction,
            );
        }
    }
    (numerator, denominator)
}

/// `silk_biquad_alt_stride1` (`biquad_alt.c:41-76`) — a second-order ARMA section in transposed
/// direct form II, filtering `signal` in place.
///
/// The AR coefficients are negated and split into a 14-bit low and an upper part so the whole filter
/// runs on `silk_SMLAWB`'s 32×16 multiply. That split is not an optimisation to be simplified away:
/// the two halves round separately and the result differs from a single wide multiply in the last
/// bit, which is the difference between matching libopus' sample stream and not.
fn biquad(
    signal: &mut [i16],
    numerator_q28: &[i32; 3],
    denominator_q28: &[i32; 2],
    state: &mut [i32; 2],
) {
    let a0_low_q28 = (-denominator_q28[0]) & 0x0000_3FFF;
    let a0_high_q28 = (-denominator_q28[0]) >> 14;
    let a1_low_q28 = (-denominator_q28[1]) & 0x0000_3FFF;
    let a1_high_q28 = (-denominator_q28[1]) >> 14;

    for sample in signal.iter_mut() {
        let input = i32::from(*sample);
        let output_q14 = smlawb(state[0], numerator_q28[0], input) << 2;

        state[0] = state[1] + rshift_round(smulwb(output_q14, a0_low_q28), 14);
        state[0] = smlawb(state[0], output_q14, a0_high_q28);
        state[0] = smlawb(state[0], numerator_q28[1], input);

        state[1] = rshift_round(smulwb(output_q14, a1_low_q28), 14);
        state[1] = smlawb(state[1], output_q14, a1_high_q28);
        state[1] = smlawb(state[1], numerator_q28[2], input);

        *sample = sat16((output_q14 + (1 << 14) - 1) >> 14);
    }
}

/// `silk_LP_variable_cutoff` (`LP_variable_cutoff.c:100-135`) — filter one SILK frame in place and
/// advance the transition schedule by one frame.
///
/// A `mode` of 0 is the whole bypass: no taps are computed, the frame is untouched and the counter
/// does not move. That is the steady state — the filter only runs while a bandwidth transition is
/// actually in flight.
pub fn low_pass_variable_cutoff(state: &mut LowPassState, frame: &mut [i16]) {
    if state.mode == 0 {
        return;
    }
    debug_assert!((0..=TRANSITION_FRAMES).contains(&state.transition_frame_no));

    // `TRANSITION_INT_STEPS == 64`, so the division the C guards with an `#if` is a shift here too.
    debug_assert_eq!(TRANSITION_INT_STEPS, 64);
    let mut fraction_q16 = (TRANSITION_FRAMES - state.transition_frame_no) << (16 - 6);
    let index = (fraction_q16 >> 16) as usize;
    fraction_q16 -= (index as i32) << 16;

    let (numerator, denominator) = taps_for(index, fraction_q16);

    // The counter moves once per frame regardless of the frame's length, which is why it is defined
    // in 20 ms units: a 10 ms SILK frame walks the sweep at double the wall-clock speed, exactly as
    // the C does.
    state.transition_frame_no =
        limit_int(state.transition_frame_no + state.mode, 0, TRANSITION_FRAMES);

    let mut memory = state.state;
    biquad(frame, &numerator, &denominator, &mut memory);
    state.state = memory;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same deterministic input the C oracle was driven with (see the module's test docs): an
    /// LCG whose top bits are recentred on zero.
    struct Source(u32);

    impl Source {
        fn new() -> Self {
            Self(12_345)
        }

        fn fill(&mut self, frame: &mut [i16]) {
            for slot in frame.iter_mut() {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *slot = ((self.0 >> 18) as i32 - 8_192) as i16;
            }
        }
    }

    fn fnv1a(seed: u64, frame: &[i16]) -> u64 {
        let mut hash = seed;
        for &sample in frame {
            let bits = sample as u16;
            hash ^= u64::from(bits & 0xFF);
            hash = hash.wrapping_mul(1_099_511_628_211);
            hash ^= u64::from(bits >> 8);
            hash = hash.wrapping_mul(1_099_511_628_211);
        }
        hash
    }

    /// Run `frames` frames of 320 samples and return the digest plus the end state, the shape the
    /// C oracle prints.
    fn trajectory(mode: i32, transition_frame_no: i32, frames: usize) -> (u64, LowPassState) {
        let mut state = LowPassState {
            mode,
            transition_frame_no,
            ..LowPassState::default()
        };
        let mut source = Source::new();
        let mut frame = [0i16; 320];
        let mut hash = 14_695_981_039_346_656_037u64;
        for _ in 0..frames {
            source.fill(&mut frame);
            low_pass_variable_cutoff(&mut state, &mut frame);
            hash = fnv1a(hash, &frame);
        }
        (hash, state)
    }

    /// The five design points, value for value against `silk/tables_other.c`. A transposed or
    /// mistyped tap would still filter and still sound like a low-pass, so this is checked directly
    /// rather than inferred from the filtered output.
    #[test]
    fn the_transition_tables_match_libopus() {
        assert_eq!(
            TRANSITION_LP_B_Q28[0],
            [250_767_114, 501_534_038, 250_767_114]
        );
        assert_eq!(
            TRANSITION_LP_B_Q28[4],
            [89_306_658, 178_584_282, 89_306_658]
        );
        assert_eq!(TRANSITION_LP_A_Q28[0], [506_393_414, 239_854_379]);
        assert_eq!(TRANSITION_LP_A_Q28[4], [35_497_197, 57_401_098]);
        // Every numerator is symmetric — b0 == b2 — which is what a normalised elliptic low-pass
        // section looks like and what a transposed row of the table would break.
        for taps in TRANSITION_LP_B_Q28 {
            assert_eq!(taps[0], taps[2]);
        }
        assert_eq!(TRANSITION_FRAMES, 256);
        assert_eq!(TRANSITION_INT_STEPS, 64);
    }

    /// `mode == 0` is a true bypass: not a filter with a flat response, no filtering at all, and the
    /// counter does not move. Anything else would make the steady state pay for a transition that is
    /// not happening.
    #[test]
    fn mode_zero_leaves_the_frame_and_the_schedule_untouched() {
        let (digest, state) = trajectory(0, 0, 4);
        let mut source = Source::new();
        let mut frame = [0i16; 320];
        let mut expected = 14_695_981_039_346_656_037u64;
        for _ in 0..4 {
            source.fill(&mut frame);
            expected = fnv1a(expected, &frame);
        }
        assert_eq!(
            digest, expected,
            "mode 0 must pass the signal through untouched"
        );
        assert_eq!(
            digest, 0xd2ed_eed4_a921_4306,
            "libopus' digest for the same input"
        );
        assert_eq!(state.transition_frame_no, 0);
        assert_eq!(state.state, [0, 0]);
    }

    /// The first frame of an upward sweep, sample for sample against libopus. Eight samples pin the
    /// biquad's split-multiply rounding; the digest over the whole frame pins the rest.
    #[test]
    fn the_first_upward_frame_matches_libopus_sample_for_sample() {
        let mut state = LowPassState {
            mode: 1,
            ..LowPassState::default()
        };
        let mut source = Source::new();
        let mut frame = [0i16; 320];
        source.fill(&mut frame);
        assert_eq!(
            frame[..8],
            [-7858, -7921, 707, 2210, 6717, -6350, -68, 792],
            "the test source drifted from the one the oracle was run with"
        );
        low_pass_variable_cutoff(&mut state, &mut frame);
        assert_eq!(
            frame[..8],
            [-2614, -7517, -6095, 984, 5114, 2205, -3397, -1916]
        );
        assert_eq!(state.transition_frame_no, 1);
    }

    /// The first frame of a downward sweep, which starts at the *widest* cutoff and so barely
    /// changes the signal — the opposite end of the same table.
    #[test]
    fn the_first_downward_frame_matches_libopus_sample_for_sample() {
        let mut state = LowPassState {
            mode: -2,
            transition_frame_no: TRANSITION_FRAMES,
            ..LowPassState::default()
        };
        let mut source = Source::new();
        let mut frame = [0i16; 320];
        source.fill(&mut frame);
        low_pass_variable_cutoff(&mut state, &mut frame);
        assert_eq!(
            frame[..8],
            [-7340, -8233, 612, 2190, 6388, -5324, -1315, 1921]
        );
        assert_eq!(state.transition_frame_no, TRANSITION_FRAMES - 2);
    }

    /// Four-frame digests and end states for the three modes, against the C. Short runs catch a
    /// wrong starting tap; the full sweeps below catch a wrong step.
    #[test]
    fn short_sweeps_match_libopus() {
        let (digest, state) = trajectory(1, 0, 4);
        assert_eq!(digest, 0x006f_1d4d_453d_497c);
        assert_eq!(state.transition_frame_no, 4);
        assert_eq!(state.state, [10_733_202, 2_333_869]);

        let (digest, state) = trajectory(-2, TRANSITION_FRAMES, 4);
        assert_eq!(digest, 0x4fd3_4c89_a3da_9fc8);
        assert_eq!(state.transition_frame_no, 248);
        assert_eq!(state.state, [-2_951_569, -3_031_523]);

        // Starting mid-sweep exercises the `fac_Q16 >= 32768` interpolation branch, which the
        // endpoints do not reach.
        let (digest, state) = trajectory(1, 128, 4);
        assert_eq!(digest, 0xa51e_87fe_53c2_6020);
        assert_eq!(state.transition_frame_no, 132);
        assert_eq!(state.state, [2_244_522, -990_041]);
    }

    /// The complete sweeps in both directions — 256 frames up, 128 down — digested end to end. This
    /// is the check that every one of the 256 interpolation points, and the counter's clamp at both
    /// ends, agrees with libopus.
    #[test]
    fn full_sweeps_in_both_directions_match_libopus() {
        let (digest, state) = trajectory(1, 0, 256);
        assert_eq!(digest, 0x4455_b547_3d54_ea1c);
        assert_eq!(
            state.transition_frame_no, TRANSITION_FRAMES,
            "the upward sweep must saturate at the top rather than run past it"
        );
        assert_eq!(state.state, [1_237_457, 1_438_487]);

        let (digest, state) = trajectory(-2, TRANSITION_FRAMES, 128);
        assert_eq!(digest, 0xddf5_01bf_358e_4456);
        assert_eq!(
            state.transition_frame_no, 0,
            "128 frames at two per frame is exactly the whole downward sweep"
        );
        assert_eq!(state.state, [6_078_867, 6_141_994]);
    }

    /// The counter never leaves 0..=`TRANSITION_FRAMES`, whatever it is driven with — the filter
    /// indexes a five-entry table off it, so an unclamped counter would be an out-of-bounds read.
    #[test]
    fn the_transition_counter_stays_inside_the_table() {
        for mode in [-2, 1] {
            let mut state = LowPassState {
                mode,
                transition_frame_no: if mode < 0 { TRANSITION_FRAMES } else { 0 },
                ..LowPassState::default()
            };
            let mut frame = [0i16; 320];
            for _ in 0..1_000 {
                low_pass_variable_cutoff(&mut state, &mut frame);
                assert!((0..=TRANSITION_FRAMES).contains(&state.transition_frame_no));
            }
        }
    }

    /// A full-scale input must not wrap: the output saturates to `i16` like every other SILK filter.
    #[test]
    fn a_full_scale_input_saturates_rather_than_wrapping() {
        let mut state = LowPassState {
            mode: 1,
            ..LowPassState::default()
        };
        let mut frame = [i16::MIN; 320];
        low_pass_variable_cutoff(&mut state, &mut frame);
        assert!(frame.iter().all(|&sample| sample <= 0));
        let mut state = LowPassState {
            mode: 1,
            ..LowPassState::default()
        };
        let mut frame = [i16::MAX; 320];
        low_pass_variable_cutoff(&mut state, &mut frame);
        assert!(frame.iter().all(|&sample| sample >= 0));
    }

    /// `reset_memory` clears the filter's two state words and nothing else — the schedule has to
    /// survive it, because `silk_control_audio_bandwidth` resets the memory *while* setting up a new
    /// transition.
    #[test]
    fn resetting_the_memory_keeps_the_schedule() {
        let mut state = LowPassState {
            mode: -2,
            transition_frame_no: 200,
            saved_fs_khz: 16,
            state: [123, 456],
        };
        state.reset_memory();
        assert_eq!(state.state, [0, 0]);
        assert_eq!(state.transition_frame_no, 200);
        assert_eq!(state.mode, -2);
        assert_eq!(state.saved_fs_khz, 16);
    }
}
