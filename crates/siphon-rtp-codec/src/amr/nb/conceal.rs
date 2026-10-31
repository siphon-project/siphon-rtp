//! AMR-NB error concealment — 3GPP TS 26.091, as implemented by the TS 26.073 reference decoder:
//! `ec_gains.c` (`ec_gain_pitch*`, `ec_gain_code*`), `gmed_n.c`, `ex_ctrl.c` (`Ex_ctrl`),
//! `bgnscd.c` (`Bgn_scd`, the source-characteristic detector that decides whether a bad frame fell
//! into background noise) and `b_cn_cod.c` (`build_CN_param`, the parameters substituted for a frame
//! that never arrived). Ported bit-exact; the decoder-side state machine that drives them lives in
//! [`crate::amr::nb::dec_main`].
//!
//! Discontinuous transmission (SID frames, comfort noise, `dtx_dec.c`) is not part of this: a lost
//! frame is concealed as speech, which is what the reference does while its DTX state is `SPEECH`.

use crate::amr::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_mac, l_mult, l_shl, l_shr, mult, norm_s, shl, shr,
    sub,
};
use crate::amr::nb::bitstream::{BITNO, PRMNO};
use crate::amr::nb::constants::{L_FRAME, L_SUBFR};
use crate::amr::nb::enc_tables::WINDOW_200_40;
use crate::amr::nb::gains::{gc_pred_average_limited, gc_pred_update, GcPredState};

/// `gmed_n.c` `NMAX`: the largest median window.
const MEDIAN_MAX: usize = 9;

/// Median of `values` (`gmed_n.c` `gmed_n`): the reference sorts indices by descending value with
/// ties resolved to the last equal element, and returns the value at the middle rank. `values`
/// holds an odd count of at most `MEDIAN_MAX` (9) entries; anything longer is truncated and an
/// empty slice gives 0.
#[must_use]
pub fn gmed_n(values: &[i16]) -> i16 {
    let count = values.len().min(MEDIAN_MAX);
    let mut remaining = [0i16; MEDIAN_MAX];
    remaining[..count].copy_from_slice(&values[..count]);
    let mut by_rank = [0usize; MEDIAN_MAX];
    let mut index_of_max = 0usize;
    for rank in by_rank.iter_mut().take(count) {
        let mut max = -32767i16;
        for (j, &value) in remaining.iter().enumerate().take(count) {
            if value >= max {
                max = value;
                index_of_max = j;
            }
        }
        remaining[index_of_max] = -32768;
        *rank = index_of_max;
    }
    values.get(by_rank[count >> 1]).copied().unwrap_or(0)
}

/// Index into the 7-entry concealment tables for the BFH state (0..=6).
fn state_index(state: i16) -> usize {
    usize::try_from(state.clamp(0, 6)).unwrap_or(0)
}

/// Pitch-gain concealment (`ec_gains.c` `ec_gain_pitchState`).
#[derive(Debug, Clone)]
pub struct EcGainPitch {
    /// Last five (limited) pitch gains, Q14 (`pbuf`).
    pbuf: [i16; 5],
    /// Previous pitch gain, limited to 1.0 (`past_gain_pit`).
    past_gain_pit: i16,
    /// Last good pitch gain (`prev_gp`).
    prev_gp: i16,
}

impl Default for EcGainPitch {
    fn default() -> Self {
        Self::new()
    }
}

impl EcGainPitch {
    /// `ec_gain_pitch_reset`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pbuf: [1640; 5],
            past_gain_pit: 0,
            prev_gp: 16384,
        }
    }

    /// Conceal the pitch gain in a bad frame (`ec_gain_pitch`): the smaller of the median of the
    /// last five gains and the previous gain, attenuated by the BFH `state` (TS 26.091 §6.1).
    #[must_use]
    pub fn conceal(&self, state: i16) -> i16 {
        // ec_gains.c `pdown`
        const PDOWN: [i16; 7] = [32767, 32112, 32112, 26214, 9830, 6553, 6553];
        let mut median = gmed_n(&self.pbuf);
        if sub(median, self.past_gain_pit) > 0 {
            median = self.past_gain_pit;
        }
        mult(median, PDOWN[state_index(state)])
    }

    /// Update the concealment state after decoding or concealing a pitch gain
    /// (`ec_gain_pitch_update`); limits the gain of the first good frame after a bad one.
    pub fn update(&mut self, bad_frame: bool, previous_bad_frame: bool, gain_pitch: &mut i16) {
        if !bad_frame {
            if previous_bad_frame && sub(*gain_pitch, self.prev_gp) > 0 {
                *gain_pitch = self.prev_gp;
            }
            self.prev_gp = *gain_pitch;
        }
        self.past_gain_pit = *gain_pitch;
        if sub(self.past_gain_pit, 16384) > 0 {
            self.past_gain_pit = 16384;
        }
        self.pbuf.copy_within(1.., 0);
        self.pbuf[4] = self.past_gain_pit;
    }
}

/// Code-gain concealment (`ec_gains.c` `ec_gain_codeState`).
#[derive(Debug, Clone)]
pub struct EcGainCode {
    /// Last five code gains, Q1 (`gbuf`).
    gbuf: [i16; 5],
    /// Previous code gain (`past_gain_code`).
    past_gain_code: i16,
    /// Last good code gain (`prev_gc`).
    prev_gc: i16,
}

impl Default for EcGainCode {
    fn default() -> Self {
        Self::new()
    }
}

impl EcGainCode {
    /// `ec_gain_code_reset`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            gbuf: [1; 5],
            past_gain_code: 0,
            prev_gc: 1,
        }
    }

    /// Conceal the code gain in a bad frame (`ec_gain_code`): the smaller of the median and the
    /// previous gain, attenuated by `state`; the MA predictor is advanced with its own
    /// (floored) average so the gain after the loss starts from a plausible energy.
    #[must_use]
    pub fn conceal(&self, pred_state: &mut GcPredState, state: i16) -> i16 {
        // ec_gains.c `cdown`
        const CDOWN: [i16; 7] = [32767, 32112, 32112, 32112, 32112, 32112, 22937];
        let mut median = gmed_n(&self.gbuf);
        if sub(median, self.past_gain_code) > 0 {
            median = self.past_gain_code;
        }
        let gain_code = mult(median, CDOWN[state_index(state)]);
        let (average_mr122, average) = gc_pred_average_limited(pred_state);
        gc_pred_update(pred_state, average_mr122, average);
        gain_code
    }

    /// Update the concealment state after decoding or concealing a code gain
    /// (`ec_gain_code_update`); limits the gain of the first good frame after a bad one.
    pub fn update(&mut self, bad_frame: bool, previous_bad_frame: bool, gain_code: &mut i16) {
        if !bad_frame {
            if previous_bad_frame && sub(*gain_code, self.prev_gc) > 0 {
                *gain_code = self.prev_gc;
            }
            self.prev_gc = *gain_code;
        }
        self.past_gain_code = *gain_code;
        self.gbuf.copy_within(1.., 0);
        self.gbuf[4] = *gain_code;
    }
}

/// Excitation control (`ex_ctrl.c` `Ex_ctrl`): while concealing in background noise, scale the
/// subframe excitation up towards the median energy of the recent subframes so the noise does not
/// fade faster than the original. `energy_history` is `excEnergyHist` (9 entries, oldest first);
/// `excitation` is the `L_SUBFR` samples scaled in place.
pub fn ex_ctrl(
    excitation: &mut [i16],
    excitation_energy: i16,
    energy_history: &[i16; 9],
    voiced_hangover: i16,
    previous_bad_frame: bool,
    careful: bool,
) {
    let mut average_energy = gmed_n(energy_history);

    let mut previous_energy = shr(add(energy_history[7], energy_history[8]), 1);
    if sub(energy_history[8], previous_energy) < 0 {
        previous_energy = energy_history[8];
    }

    // upscale to avoid too rapid energy rises in some cases
    if sub(excitation_energy, average_energy) < 0 && sub(excitation_energy, 5) > 0 {
        let mut test_energy = shl(previous_energy, 2);
        if sub(voiced_hangover, 7) < 0 || previous_bad_frame {
            // testEnergy = 3 * prevEnergy
            test_energy = sub(test_energy, previous_energy);
        }
        if sub(average_energy, test_energy) > 0 {
            average_energy = test_energy;
        }

        // scaleFactor = avgEnergy / excEnergy (the constant 29 of the reference: Q10 result)
        let exponent = norm_s(excitation_energy);
        let normalised = shl(excitation_energy, exponent);
        let quotient = div_s(16383, normalised);
        let mut scaled = l_mult(average_energy, quotient);
        scaled = l_shr(scaled, sub(20, exponent));
        if scaled > 32767 {
            scaled = 32767;
        }
        let mut scale_factor = extract_l(scaled);

        // limit the dynamic when the previous frame is only potentially degraded
        if careful && sub(scale_factor, 3072) > 0 {
            scale_factor = 3072;
        }

        for sample in excitation.iter_mut().take(L_SUBFR) {
            *sample = extract_l(l_shr(l_mult(scale_factor, *sample), 11));
        }
    }
}

/// `bgnscd.h` `L_ENERGYHIST`: frames of energy history.
const L_ENERGYHIST: usize = 60;
/// `bgnscd.h` `FRAMEENERGYLIMIT` (150, Q-scaled).
const FRAME_ENERGY_LIMIT: i16 = 17578;
/// `bgnscd.h` `LOWERNOISELIMIT` (5).
const LOWER_NOISE_LIMIT: i16 = 20;
/// `bgnscd.h` `UPPERNOISELIMIT` (50).
const UPPER_NOISE_LIMIT: i16 = 1953;

/// Source-characteristic detector (`bgnscd.c` `Bgn_scd`): an energy detector floating on top of the
/// last 60 frames that flags background noise (valid for the next frame, should it be bad) and
/// counts the frames since the last voiced one.
#[derive(Debug, Clone)]
pub struct BackgroundNoiseDetector {
    /// Frame-energy history, oldest first (`frameEnergyHist`).
    frame_energy_history: [i16; L_ENERGYHIST],
    /// Frames of consecutive noise-like energy, capped at 30 (`bgHangover`).
    background_hangover: i16,
}

impl Default for BackgroundNoiseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BackgroundNoiseDetector {
    /// `Bgn_scd_reset`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            frame_energy_history: [0; L_ENERGYHIST],
            background_hangover: 0,
        }
    }

    /// Classify one decoded frame. `ltp_gain_history` holds the last nine pitch gains (Q14, oldest
    /// first), `speech` the `L_FRAME` synthesised samples (before the post-filter) and
    /// `voiced_hangover` is updated. Returns the background-noise decision: `1` for noise.
    pub fn detect(
        &mut self,
        ltp_gain_history: &[i16; 9],
        speech: &[i16],
        voiced_hangover: &mut i16,
    ) -> i16 {
        let mut energy = 0i32;
        for &sample in speech.iter().take(L_FRAME) {
            energy = l_mac(energy, sample, sample);
        }
        energy = l_shl(energy, 2);
        let current_energy = extract_h(energy);

        let mut frame_energy_min = 32767i16;
        for &entry in &self.frame_energy_history {
            if sub(entry, frame_energy_min) < 0 {
                frame_energy_min = entry;
            }
        }
        let noise_floor = shl(frame_energy_min, 4); // frame energy margin of 16

        let mut max_energy = self.frame_energy_history[0];
        for &entry in &self.frame_energy_history[1..L_ENERGYHIST - 4] {
            if sub(max_energy, entry) < 0 {
                max_energy = entry;
            }
        }

        let last_part = 2 * L_ENERGYHIST / 3;
        let mut max_energy_last_part = self.frame_energy_history[last_part];
        for &entry in &self.frame_energy_history[last_part + 1..] {
            if sub(max_energy_last_part, entry) < 0 {
                max_energy_last_part = entry;
            }
        }

        // Do not consider silence or continuous high volume as noise; mark as noise if under the
        // current noise limit or the maximum energy is below the upper limit.
        if sub(max_energy, LOWER_NOISE_LIMIT) > 0
            && sub(current_energy, FRAME_ENERGY_LIMIT) < 0
            && sub(current_energy, LOWER_NOISE_LIMIT) > 0
            && (sub(current_energy, noise_floor) < 0
                || sub(max_energy_last_part, UPPER_NOISE_LIMIT) < 0)
        {
            if sub(add(self.background_hangover, 1), 30) > 0 {
                self.background_hangover = 30;
            } else {
                self.background_hangover = add(self.background_hangover, 1);
            }
        } else {
            self.background_hangover = 0;
        }

        // final decision, taken somewhat cautiously
        let in_background_noise = i16::from(sub(self.background_hangover, 1) > 0);

        self.frame_energy_history.copy_within(1.., 0);
        self.frame_energy_history[L_ENERGYHIST - 1] = current_energy;

        // prepare the voicing decision; tighten the threshold after some time in noise
        let mut ltp_limit = 13926; // 0.85 in Q14
        if sub(self.background_hangover, 8) > 0 {
            ltp_limit = 15565; // 0.95
        }
        if sub(self.background_hangover, 15) > 0 {
            ltp_limit = 16383; // 1.00
        }

        // weak sort of voicing indication
        let mut previous_voiced = sub(gmed_n(&ltp_gain_history[4..]), ltp_limit) > 0;
        if sub(self.background_hangover, 20) > 0 {
            previous_voiced = sub(gmed_n(ltp_gain_history), ltp_limit) > 0;
        }

        if previous_voiced {
            *voiced_hangover = 0;
        } else {
            let incremented = add(*voiced_hangover, 1);
            *voiced_hangover = if sub(incremented, 10) > 0 {
                10
            } else {
                incremented
            };
        }

        in_background_noise
    }
}

/// Substitute parameters for a frame that never arrived (`b_cn_cod.c` `build_CN_param`): a seeded
/// pseudo-random slice of the analysis window, masked to each parameter's width. `seed` is the
/// decoder's `nodataSeed`; `parameters` receives `PRMNO[mode]` values.
pub fn build_cn_param(seed: &mut i16, mode: usize, parameters: &mut [i16]) {
    *seed = extract_l(l_add(l_shr(l_mult(*seed, 31821), 1), 13849));
    let start = usize::try_from(*seed & 0x7F).unwrap_or(0);
    let widths = BITNO[mode];
    for (index, parameter) in parameters.iter_mut().enumerate().take(PRMNO[mode]) {
        let mask = (1i32 << widths[index]) - 1;
        *parameter = WINDOW_200_40[start + index] & extract_l(mask);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amr::nb::bitstream::MAX_PRM_SIZE as MAX_PARAMETERS;

    // The expected values below were produced once by the unmodified TS 26.073 reference
    // functions (`gmed_n.c`, `ex_ctrl.c`, `ec_gains.c`, `bgnscd.c`, `b_cn_cod.c`) driven with the
    // same inputs outside the repository.

    #[test]
    fn median_matches_the_reference_ranking() {
        assert_eq!(gmed_n(&[5, -3, 100, 7, 7, 2, -32768, 32767, 0]), 5);
        assert_eq!(gmed_n(&[1640, 1640, 300, 32000, -5]), 1640);
        assert_eq!(gmed_n(&[9, 9, 9, 9, 9]), 9);
    }

    #[test]
    fn median_of_an_oversized_slice_never_panics() {
        assert_eq!(gmed_n(&[1; 12]), 1);
        assert_eq!(gmed_n(&[]), 0);
    }

    fn excitation_ramp() -> [i16; L_SUBFR] {
        let mut excitation = [0i16; L_SUBFR];
        for (index, sample) in excitation.iter_mut().enumerate() {
            *sample = ((index * 37) % 200) as i16 - 100;
        }
        excitation
    }

    #[test]
    fn ex_ctrl_saturating_scale_matches_the_reference() {
        let mut excitation = excitation_ramp();
        ex_ctrl(&mut excitation, 6, &[3000; 9], 8, false, false);
        assert_eq!(
            excitation[..12],
            [-3200, -2016, -832, 351, 1535, 2719, -2496, -1312, -128, 1055, 2239, -2976]
        );
        assert_eq!(excitation[39], -1824);
    }

    #[test]
    fn ex_ctrl_careful_flag_limits_the_scale_factor() {
        let mut excitation = excitation_ramp();
        ex_ctrl(&mut excitation, 6, &[3000; 9], 8, false, true);
        assert_eq!(
            excitation[..12],
            [-300, -189, -78, 33, 144, 255, -234, -123, -12, 99, 210, -279]
        );
        assert_eq!(excitation[39], -171);
    }

    #[test]
    fn ex_ctrl_after_a_bad_frame_uses_the_lower_target() {
        let mut excitation = excitation_ramp();
        let history = [100, 120, 90, 300, 200, 150, 400, 350, 500];
        ex_ctrl(&mut excitation, 80, &history, 3, true, false);
        assert_eq!(
            excitation[..12],
            [-250, -158, -65, 27, 119, 212, -195, -103, -10, 82, 174, -233]
        );
        assert_eq!(excitation[39], -143);
    }

    #[test]
    fn ex_ctrl_scales_a_quiet_subframe_up_to_the_median_energy() {
        let mut excitation = excitation_ramp();
        ex_ctrl(&mut excitation, 1000, &[2000; 9], 8, false, false);
        assert_eq!(
            excitation[..12],
            [-200, -126, -52, 21, 95, 169, -156, -82, -8, 65, 139, -186]
        );
        assert_eq!(excitation[39], -114);
    }

    #[test]
    fn ex_ctrl_leaves_a_loud_or_near_silent_subframe_alone() {
        let mut loud = excitation_ramp();
        ex_ctrl(&mut loud, 3000, &[2000; 9], 8, false, false);
        assert_eq!(loud, excitation_ramp());
        let mut silent = excitation_ramp();
        ex_ctrl(&mut silent, 5, &[2000; 9], 8, false, false);
        assert_eq!(silent, excitation_ramp());
    }

    #[test]
    fn pitch_gain_concealment_attenuates_with_the_state() {
        let mut concealment = EcGainPitch::new();
        for mut gain in [12000i16, 14000, 20000] {
            concealment.update(false, false, &mut gain);
        }
        let mut conceal_states = Vec::new();
        for state in 1..=6 {
            let mut gain = concealment.conceal(state);
            conceal_states.push(gain);
            concealment.update(true, false, &mut gain);
        }
        assert_eq!(conceal_states, [11759, 11523, 9218, 2765, 552, 110]);
    }

    #[test]
    fn pitch_gain_of_the_first_good_frame_after_a_loss_is_limited() {
        let mut concealment = EcGainPitch::new();
        let mut gain = 16000i16;
        concealment.update(false, true, &mut gain);
        // prev_gp starts at 1.0 (16384), so 16000 passes; a second, larger one is clamped to it
        let mut larger = 20000i16;
        concealment.update(false, true, &mut larger);
        assert_eq!(gain, 16000);
        assert_eq!(larger, 16000);
    }

    #[test]
    fn code_gain_concealment_attenuates_and_advances_the_predictor() {
        let mut concealment = EcGainCode::new();
        let mut predictor = GcPredState::new();
        for mut gain in [300i16, 500, 400] {
            concealment.update(false, false, &mut gain);
        }
        gc_pred_update(&mut predictor, -3000, -2000);
        gc_pred_update(&mut predictor, -3100, -2100);
        let mut gains = Vec::new();
        let mut histories = Vec::new();
        for state in 1..=6 {
            let mut gain = concealment.conceal(&mut predictor, state);
            gains.push(gain);
            histories.push((predictor.past_qua_en[0], predictor.past_qua_en_mr122[0]));
            concealment.update(true, false, &mut gain);
        }
        assert_eq!(gains, [293, 287, 281, 275, 269, 188]);
        assert_eq!(
            histories,
            [
                (-8192, -2381),
                (-6657, -2381),
                (-4738, -2381),
                (-5422, -2381),
                (-6253, -2381),
                (-5768, -2381)
            ]
        );
    }

    #[test]
    fn code_gain_of_the_first_good_frame_after_a_loss_is_limited_to_the_last_good_gain() {
        let mut concealment = EcGainCode::new();
        let mut gain = 400i16;
        concealment.update(false, false, &mut gain);
        let mut louder = 9000i16;
        concealment.update(false, true, &mut louder);
        assert_eq!(louder, 400);
    }

    #[test]
    fn substitute_parameters_follow_the_reference_seed_sequence() {
        let mut seed = 21845i16;
        let mut parameters = [0i16; MAX_PARAMETERS];
        build_cn_param(&mut seed, 0, &mut parameters);
        assert_eq!(seed, 3242);
        assert_eq!(
            parameters[..17],
            [168, 59, 81, 106, 6, 1, 70, 10, 17, 3, 7, 21, 2, 250, 0, 104, 3]
        );
        build_cn_param(&mut seed, 1, &mut parameters);
        assert_eq!(seed, 23867);
        assert_eq!(
            parameters[..19],
            [224, 159, 97, 36, 106, 2, 60, 7, 21, 0, 53, 8, 93, 3, 11, 4, 63, 3, 57]
        );
        for mode in 2..=7 {
            build_cn_param(&mut seed, mode, &mut parameters);
        }
        assert_eq!(seed, 19085);
        assert_eq!(parameters[..4], [120, 170, 480, 25]);
        assert_eq!(parameters[56], 21);
    }

    #[test]
    fn substitute_parameters_fit_their_bit_widths_for_every_seed() {
        for mode in 0..8 {
            let mut seed = i16::MIN;
            loop {
                let mut parameters = [0i16; MAX_PARAMETERS];
                let mut probe = seed;
                build_cn_param(&mut probe, mode, &mut parameters);
                for (index, &parameter) in parameters.iter().enumerate().take(PRMNO[mode]) {
                    assert!(parameter >= 0 && i32::from(parameter) < 1 << BITNO[mode][index]);
                }
                if seed == i16::MAX {
                    break;
                }
                seed += 257;
            }
        }
    }

    /// Frame of pseudo-noise with the given amplitude, as the reference KAT driver builds it.
    fn noise_frame(frame: usize, amplitude: i32) -> [i16; L_FRAME] {
        let mut speech = [0i16; L_FRAME];
        for (index, sample) in speech.iter_mut().enumerate() {
            let value = (index * 7919 + frame * 104_729) as i32 % (2 * amplitude + 1) - amplitude;
            *sample = value as i16;
        }
        speech
    }

    #[test]
    fn detector_follows_the_reference_through_noise_then_speech() {
        let mut detector = BackgroundNoiseDetector::new();
        let mut hangover = 0i16;
        let voiced = [16000i16; 9];
        let mut trace = Vec::new();
        for frame in 0..40 {
            let decision = detector.detect(&voiced, &noise_frame(frame, 300), &mut hangover);
            trace.push((decision, hangover, detector.background_hangover));
        }
        for frame in 0..5 {
            let decision = detector.detect(&voiced, &noise_frame(frame, 3000), &mut hangover);
            trace.push((decision, hangover, detector.background_hangover));
        }
        let expected: [(i16, i16, i16); 45] = [
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 1),
            (1, 0, 2),
            (1, 0, 3),
            (1, 0, 4),
            (1, 0, 5),
            (1, 0, 6),
            (1, 0, 7),
            (1, 0, 8),
            (1, 0, 9),
            (1, 0, 10),
            (1, 0, 11),
            (1, 0, 12),
            (1, 0, 13),
            (1, 0, 14),
            (1, 0, 15),
            (1, 1, 16),
            (1, 2, 17),
            (1, 3, 18),
            (1, 4, 19),
            (1, 5, 20),
            (1, 6, 21),
            (1, 7, 22),
            (1, 8, 23),
            (1, 9, 24),
            (1, 10, 25),
            (1, 10, 26),
            (1, 10, 27),
            (1, 10, 28),
            (1, 10, 29),
            (1, 10, 30),
            (1, 10, 30),
            (1, 10, 30),
            (1, 10, 30),
            (1, 10, 30),
            (1, 10, 30),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ];
        assert_eq!(trace, expected);
    }
}
