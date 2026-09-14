//! The Annex B voice-activity decision — ITU-T G.729 Annex B §3, reference `vad.c`.
//!
//! One bit per frame: speech, or not. Everything Annex B does downstream hangs off it — a frame the
//! decision calls noise is either not transmitted at all or sent as a 2-octet description of the
//! background, so a decision that is wrong in the "noise" direction clips a word off the front of a
//! sentence and one wrong in the "speech" direction spends the whole bit rate on silence.
//!
//! Four measurements per frame, each compared against a running estimate of what the background
//! sounds like: full-band energy, energy below 1 kHz, how far the line spectral frequencies have
//! moved from the background's, and the zero-crossing rate. The decision itself is a fixed set of
//! linear boundaries in the space of those four differences (`MakeDec`) — fourteen half-planes, any
//! one of which votes speech — rather than a single threshold, because none of the four separates
//! speech from noise on its own.
//!
//! Around that sit the parts that make it work on a real call: the background estimate only updates
//! on frames that already look like noise, so a long sentence cannot drag it up; a running minimum
//! over the last sixteen frames stops it drifting up during sustained noise; and a hangover keeps
//! the decision on speech for a few frames past the end of a word, because the tail of a voiced
//! sound is quiet and is exactly what the raw decision would cut off.

use super::analysis::VAD_ORDER;
use super::filter::ORDER;
use super::tables::{INITIAL_MEAN_FACTOR, INITIAL_MEAN_SHIFT, LOW_BAND_CORRELATION};
use crate::itu::basic_ops::{
    abs_s, add, extract_h, l_add, l_deposit_h, l_mac, l_mult, l_shl, l_shr, mult, shr, sub,
};
use crate::itu::oper_32b::{l_comp, mpy_32_16};

/// Frames of input the background estimate is initialised over (`INIT_FRAME`).
const INITIALISATION_FRAMES: i16 = 32;
/// Frames of noise after which the update coefficients stop tightening (`INIT_COUNT`).
const UPDATE_SETTLED: i16 = 20;
/// First and last sample of the window the zero-crossing rate is counted over.
const ZERO_CROSSING_START: usize = 120;
const ZERO_CROSSING_END: usize = 200;
/// Energy below which a frame is called noise outright, in the decision's own Q11 decibels.
const SILENCE_ENERGY: i16 = 3072;

/// The verdict for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// Background noise: the frame need not be transmitted as speech.
    Noise,
    /// Speech, or something close enough that losing it would be audible.
    Speech,
}

impl Activity {
    /// The reference's own encoding, which the frame loop compares and stores.
    #[must_use]
    pub fn is_speech(self) -> bool {
        matches!(self, Activity::Speech)
    }
}

/// The running background estimate the decision is made against.
#[derive(Debug, Clone)]
pub struct VoiceActivityDetector {
    /// Background line spectral frequencies.
    mean_lsf: [i16; ORDER],
    /// The last sixteen eight-frame energy minima, and the running minima over them.
    minima: [i16; 16],
    previous_minimum: i16,
    next_minimum: i16,
    minimum: i16,
    /// Background means: energy during initialisation, then full-band, low-band and zero-crossing.
    mean_energy: i16,
    mean_full_band: i16,
    mean_low_band: i16,
    mean_zero_crossings: i16,
    /// The previous frame's energy, which the hangover compares against.
    previous_energy: i16,
    /// Consecutive noise frames, frames the background estimate has been updated over, and how far
    /// the hangover has been extended.
    silent_frames: i16,
    updates: i16,
    extensions: i16,
    /// Whether the hangover may extend again, and whether this frame's decision came from it.
    hangover_armed: bool,
    hangover_used: bool,
    /// Frames skipped during initialisation because they were too quiet to be background.
    skipped: i16,
}

impl Default for VoiceActivityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoiceActivityDetector {
    /// A detector in its reset state (`vad_init`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            mean_lsf: [0; ORDER],
            minima: [0; 16],
            previous_minimum: 0,
            next_minimum: 0,
            minimum: i16::MAX,
            mean_energy: 0,
            mean_full_band: 0,
            mean_low_band: 0,
            mean_zero_crossings: 0,
            previous_energy: 0,
            silent_frames: 0,
            updates: 0,
            extensions: 0,
            hangover_armed: true,
            hangover_used: false,
            skipped: 0,
        }
    }

    /// Decide whether one frame carries speech (`vad`).
    ///
    /// `reflection` is the second reflection coefficient of the frame's LP fit, `lsf` its
    /// unquantised line spectral frequencies, `correlations` the lag-windowed autocorrelation with
    /// the exponent it was normalised by, and `window` the 30 ms analysis window of preprocessed
    /// speech. `frame` counts from one; `previous` and `before_previous` are the two preceding
    /// decisions, which the hangover consults.
    pub fn decide(
        &mut self,
        reflection: i16,
        lsf: &[i16; ORDER],
        correlations: &[(i16, i16); VAD_ORDER + 1],
        energy_exponent: i16,
        window: &[i16],
        frame: i16,
        previous: Activity,
        before_previous: Activity,
    ) -> Activity {
        let energy = decibels(
            l_comp(correlations[0].0, correlations[0].1),
            energy_exponent,
        );

        // The energy a 0–1 kHz filter would pass, obtained by correlating the autocorrelation with
        // that filter's own — no filtering of the samples needed.
        let mut low = 0_i32;
        for lag in 1..=VAD_ORDER {
            low = l_mac(low, correlations[lag].0, LOW_BAND_CORRELATION[lag]);
        }
        low = l_shl(low, 1);
        low = l_mac(low, correlations[0].0, LOW_BAND_CORRELATION[0]);
        let low_energy = decibels(low, energy_exponent);

        // How far the spectrum has moved from the background's, as a squared distance in Q15.
        let mut distortion = 0_i32;
        for (&current, &background) in lsf.iter().zip(self.mean_lsf.iter()) {
            let difference = sub(current, background);
            distortion = l_mac(distortion, difference, difference);
        }
        let spectral_distortion = extract_h(distortion);

        // Zero crossings over the middle of the window, 410 being 1/80 in Q15.
        let mut zero_crossings = 0_i16;
        for index in ZERO_CROSSING_START + 1..=ZERO_CROSSING_END {
            if mult(window[index - 1], window[index]) < 0 {
                zero_crossings = add(zero_crossings, 410);
            }
        }

        self.track_minimum(frame, energy);

        let mut marker = if sub(frame, INITIALISATION_FRAMES) <= 0 {
            self.initialise(energy, zero_crossings, lsf)
        } else {
            Activity::Speech
        };

        if sub(frame, INITIALISATION_FRAMES) >= 0 {
            if sub(frame, INITIALISATION_FRAMES) == 0 {
                self.close_initialisation();
            }
            marker = self.classify(
                energy,
                low_energy,
                spectral_distortion,
                zero_crossings,
                reflection,
                lsf,
                frame,
                previous,
                before_previous,
            );
        }

        self.previous_energy = energy;
        marker
    }

    /// Track the running minimum energy over the last sixteen groups of eight frames.
    ///
    /// A background estimate that only ever rises would follow a speaker up and never come back
    /// down; the minimum is what pulls it back, because the quietest frame in the last two seconds
    /// is background almost by definition.
    fn track_minimum(&mut self, frame: i16, energy: i16) {
        if sub(frame, 129) < 0 {
            if sub(energy, self.minimum) < 0 {
                self.minimum = energy;
                self.previous_minimum = energy;
            }
            if frame & 0x0007 == 0 {
                let slot = sub(shr(frame, 3), 1);
                if slot >= 0 {
                    self.minima[slot as usize] = self.minimum;
                }
                self.minimum = i16::MAX;
            }
        }

        if frame & 0x0007 == 0 {
            self.previous_minimum = self.minima[0];
            for &value in &self.minima[1..] {
                if sub(value, self.previous_minimum) < 0 {
                    self.previous_minimum = value;
                }
            }
        }

        if sub(frame, 129) >= 0 {
            if (frame & 0x0007) ^ 0x0001 == 0 {
                self.minimum = self.previous_minimum;
                self.next_minimum = i16::MAX;
            }
            if sub(energy, self.minimum) < 0 {
                self.minimum = energy;
            }
            if sub(energy, self.next_minimum) < 0 {
                self.next_minimum = energy;
            }
            if frame & 0x0007 == 0 {
                self.minima.copy_within(1.., 0);
                self.minima[15] = self.next_minimum;
                self.previous_minimum = self.minima[0];
                for &value in &self.minima[1..] {
                    if sub(value, self.previous_minimum) < 0 {
                        self.previous_minimum = value;
                    }
                }
            }
        }
    }

    /// Accumulate the background means over the first frames, skipping any too quiet to be
    /// background at all.
    fn initialise(&mut self, energy: i16, zero_crossings: i16, lsf: &[i16; ORDER]) -> Activity {
        if sub(energy, SILENCE_ENERGY) < 0 {
            self.skipped = add(self.skipped, 1);
            return Activity::Noise;
        }
        // 1024 is 1/32 in Q15: a running sum that becomes a mean once the window closes.
        self.mean_energy = extract_h(l_mac(l_deposit_h(self.mean_energy), energy, 1024));
        self.mean_zero_crossings = extract_h(l_mac(
            l_deposit_h(self.mean_zero_crossings),
            zero_crossings,
            1024,
        ));
        for (mean, &current) in self.mean_lsf.iter_mut().zip(lsf.iter()) {
            *mean = extract_h(l_mac(l_deposit_h(*mean), current, 1024));
        }
        Activity::Speech
    }

    /// Rescale the initial means by the number of frames that actually contributed, and seed the
    /// two energy backgrounds a little below the mean speech level.
    fn close_initialisation(&mut self) {
        let index = self.skipped.clamp(0, 32) as usize;
        let factor = INITIAL_MEAN_FACTOR[index];
        let shift = INITIAL_MEAN_SHIFT[index];

        self.mean_energy = extract_h(l_shl(l_mult(self.mean_energy, factor), shift));
        self.mean_zero_crossings =
            extract_h(l_shl(l_mult(self.mean_zero_crossings, factor), shift));
        for mean in self.mean_lsf.iter_mut() {
            *mean = extract_h(l_shl(l_mult(*mean, factor), shift));
        }

        // 2048 and 2458 in Q11 are 1 dB and 1.2 dB: the background sits just under the speech it
        // was measured from.
        self.mean_full_band = sub(self.mean_energy, 2048);
        self.mean_low_band = sub(self.mean_energy, 2458);
    }

    /// The steady-state decision, and the background update that follows it.
    #[allow(clippy::too_many_arguments)]
    fn classify(
        &mut self,
        energy: i16,
        low_energy: i16,
        spectral_distortion: i16,
        zero_crossings: i16,
        reflection: i16,
        lsf: &[i16; ORDER],
        frame: i16,
        previous: Activity,
        before_previous: Activity,
    ) -> Activity {
        let full_band_difference = sub(self.mean_full_band, energy);
        let low_band_difference = sub(self.mean_low_band, low_energy);
        let zero_crossing_difference = sub(self.mean_zero_crossings, zero_crossings);

        let mut marker = if sub(energy, SILENCE_ENERGY) < 0 {
            Activity::Noise
        } else {
            decide(
                low_band_difference,
                full_band_difference,
                spectral_distortion,
                zero_crossing_difference,
            )
        };

        // A frame that follows speech, is still above silence and is *louder* than the background
        // by more than the margin is the tail of a word, not the start of a gap.
        self.hangover_used = false;
        if previous.is_speech()
            && marker == Activity::Noise
            && add(full_band_difference, 410) < 0
            && sub(energy, SILENCE_ENERGY) > 0
        {
            marker = Activity::Speech;
            self.hangover_used = true;
        }

        // A longer hangover, for a steady level after two speech frames — but only four frames in a
        // row, or a constant tone would hold the channel open indefinitely.
        if self.hangover_armed {
            if before_previous.is_speech()
                && previous.is_speech()
                && marker == Activity::Noise
                && sub(abs_s(sub(self.previous_energy, energy)), 614) <= 0
            {
                self.extensions = add(self.extensions, 1);
                marker = Activity::Speech;
                self.hangover_used = true;
                if sub(self.extensions, 4) > 0 {
                    self.extensions = 0;
                    self.hangover_armed = false;
                }
            }
        } else {
            self.hangover_armed = true;
        }

        if marker == Activity::Noise {
            self.silent_frames = add(self.silent_frames, 1);
        }

        // Speech that arrives after a long silence without a rise in level is the noise floor
        // moving, not a talker.
        if marker == Activity::Speech
            && sub(self.silent_frames, 10) > 0
            && sub(sub(energy, self.previous_energy), 614) <= 0
        {
            marker = Activity::Noise;
            self.silent_frames = 0;
        }
        if marker == Activity::Speech {
            self.silent_frames = 0;
        }

        // Below the background by a margin, with a spectrum flat enough not to be voiced, is noise
        // whatever the boundaries said.
        if sub(sub(energy, 614), self.mean_full_band) < 0
            && sub(frame, 128) > 0
            && !self.hangover_used
            && sub(reflection, 19_661) < 0
        {
            marker = Activity::Noise;
        }

        self.update_background(
            energy,
            low_energy,
            spectral_distortion,
            zero_crossings,
            reflection,
            lsf,
        );

        // The background can never sit above the running minimum: if it has drifted there, the
        // minimum is the better estimate and the adaptation starts again.
        if sub(frame, 128) > 0
            && ((sub(self.mean_full_band, self.minimum) < 0 && sub(spectral_distortion, 83) < 0)
                || sub(self.mean_full_band, self.minimum) > 2048)
        {
            self.mean_full_band = self.minimum;
            self.updates = 0;
        }

        marker
    }

    /// Move the background estimate towards this frame, if this frame looks like background.
    ///
    /// The coefficients tighten as the estimate settles: an early noise frame moves it a quarter of
    /// the way, a late one a two-hundredth. That is what lets it lock on quickly at the start of a
    /// call and then stop chasing.
    fn update_background(
        &mut self,
        energy: i16,
        low_energy: i16,
        spectral_distortion: i16,
        zero_crossings: i16,
        reflection: i16,
        lsf: &[i16; ORDER],
    ) {
        if !(sub(sub(energy, 614), self.mean_full_band) < 0
            && sub(reflection, 24_576) < 0
            && sub(spectral_distortion, 83) < 0)
        {
            return;
        }
        self.updates = add(self.updates, 1);

        let (
            energy_coefficient,
            energy_complement,
            zero_coefficient,
            zero_complement,
            lsf_coefficient,
            lsf_complement,
        ) = if sub(self.updates, UPDATE_SETTLED) < 0 {
            (24_576, 8192, 26_214, 6554, 19_661, 13_017)
        } else if sub(self.updates, UPDATE_SETTLED + 10) < 0 {
            (31_130, 1638, 30_147, 2621, 21_299, 11_469)
        } else if sub(self.updates, UPDATE_SETTLED + 20) < 0 {
            (31_785, 983, 30_802, 1966, 22_938, 9830)
        } else if sub(self.updates, UPDATE_SETTLED + 30) < 0 {
            (32_440, 328, 31_457, 1311, 24_576, 8192)
        } else if sub(self.updates, UPDATE_SETTLED + 40) < 0 {
            (32_604, 164, 32_440, 328, 24_576, 8192)
        } else {
            (32_604, 164, 32_702, 66, 24_576, 8192)
        };

        self.mean_full_band = extract_h(l_mac(
            l_mult(energy_coefficient, self.mean_full_band),
            energy_complement,
            energy,
        ));
        self.mean_low_band = extract_h(l_mac(
            l_mult(energy_coefficient, self.mean_low_band),
            energy_complement,
            low_energy,
        ));
        self.mean_zero_crossings = extract_h(l_mac(
            l_mult(zero_coefficient, self.mean_zero_crossings),
            zero_complement,
            zero_crossings,
        ));
        for (mean, &current) in self.mean_lsf.iter_mut().zip(lsf.iter()) {
            *mean = extract_h(l_mac(
                l_mult(lsf_coefficient, *mean),
                lsf_complement,
                current,
            ));
        }
    }
}

/// `10·log10(energy)` in Q11 decibels, with the exponent folded back in and the mean speech level
/// subtracted, so the thresholds above are absolute rather than relative to the frame's scaling.
fn decibels(energy: i32, exponent: i16) -> i16 {
    let (whole, fraction) = super::dspfunc::log2(energy);
    // 9864 is 10·log10(2) in Q15.
    let mut accumulator = mpy_32_16(whole, fraction, 9864);
    accumulator = l_mac(accumulator, 9864, sub(sub(exponent, 1), 1));
    accumulator = l_shl(accumulator, 11);
    sub(extract_h(accumulator), 4875)
}

/// The decision boundary itself (`MakeDec`): fourteen half-planes over the four differences, any of
/// which votes speech.
///
/// The constants are the reference's, fitted rather than derived, and each pair of comments in the
/// source gives the Q format the product lands in — reproduced here as the shifts, because that is
/// where a transcription goes wrong.
fn decide(low_band: i16, full_band: i16, distortion: i16, zero_crossings: i16) -> Activity {
    let distortion_high = l_deposit_h(distortion);

    // Spectral distortion against zero-crossing rate.
    if l_add(
        l_shr(l_mac(l_mult(zero_crossings, -14_680), 8192, -28_521), 8),
        distortion_high,
    ) > 0
    {
        return Activity::Speech;
    }
    if l_add(
        l_shr(l_mac(l_mult(zero_crossings, 19_065), 8192, -19_446), 7),
        distortion_high,
    ) > 0
    {
        return Activity::Speech;
    }

    // Full-band energy against zero-crossing rate.
    let full_band_high = l_deposit_h(full_band);
    if l_add(
        l_shr(l_mac(l_mult(zero_crossings, 20_480), 8192, 16_384), 2),
        full_band_high,
    ) < 0
    {
        return Activity::Speech;
    }
    if l_add(
        l_shr(l_mac(l_mult(zero_crossings, -16_384), 8192, 19_660), 2),
        full_band_high,
    ) < 0
    {
        return Activity::Speech;
    }
    if l_mac(l_mult(full_band, 32_767), 1024, 30_802) < 0 {
        return Activity::Speech;
    }

    // Full-band energy against spectral distortion.
    if l_mac(
        l_mac(l_mult(distortion, -28_160), 64, 19_988),
        full_band,
        512,
    ) < 0
    {
        return Activity::Speech;
    }
    if l_mac(l_mult(distortion, 32_767), 32, -30_199) > 0 {
        return Activity::Speech;
    }

    // Low-band energy against zero-crossing rate. The reference compares these against the
    // *full*-band difference, not the low-band one, despite the comment above them — reproduced as
    // written, because the vectors were generated from this code and not from the comment.
    if l_add(
        l_shr(l_mac(l_mult(zero_crossings, -20_480), 8192, 22_938), 2),
        full_band_high,
    ) < 0
    {
        return Activity::Speech;
    }
    if l_add(
        l_shr(l_mac(l_mult(zero_crossings, 23_831), 4096, 31_576), 2),
        full_band_high,
    ) < 0
    {
        return Activity::Speech;
    }
    if l_mac(l_mult(full_band, 32_767), 2048, 17_367) < 0 {
        return Activity::Speech;
    }

    // Low-band energy against spectral distortion.
    if l_mac(
        l_mac(l_mult(distortion, -22_400), 32, 25_395),
        low_band,
        256,
    ) < 0
    {
        return Activity::Speech;
    }

    // Low-band against full-band energy.
    let low_band_high = l_deposit_h(low_band);
    if l_add(
        l_mac(l_mult(full_band, -30_427), 256, -29_959),
        low_band_high,
    ) > 0
    {
        return Activity::Speech;
    }
    if l_add(
        l_mac(l_mult(full_band, -23_406), 512, 28_087),
        low_band_high,
    ) < 0
    {
        return Activity::Speech;
    }
    if l_mac(
        l_mac(l_mult(full_band, 24_576), 1024, 29_491),
        low_band,
        16_384,
    ) < 0
    {
        return Activity::Speech;
    }

    Activity::Noise
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g729::analysis::{
        autocorrelation, lag_window, lp_to_lsp, Levinson, PreProcessor, WINDOW,
    };
    use crate::g729::weighting::lsp_to_normalised_lsf;

    /// Run the decision over a sequence of windows, returning one verdict per frame.
    ///
    /// The input is conditioned exactly as the encoder conditions it — the 140 Hz high-pass halves
    /// the signal, and the decision's thresholds are absolute, so a test that skipped it would be
    /// judging a signal 6 dB louder than the one the codec ever sees.
    fn run(windows: &[[i16; WINDOW]]) -> Vec<Activity> {
        let mut preprocessor = PreProcessor::new();
        let windows: Vec<[i16; WINDOW]> = windows
            .iter()
            .map(|window| {
                let mut conditioned = *window;
                preprocessor.process(&mut conditioned);
                conditioned
            })
            .collect();
        let windows = &windows[..];

        let mut detector = VoiceActivityDetector::new();
        let mut levinson = Levinson::new();
        let mut previous_lsp = [
            30_000, 26_000, 21_000, 15_000, 8000, 0, -8000, -15_000, -21_000, -26_000,
        ];
        let mut before = Activity::Speech;
        let mut previous = Activity::Speech;
        let mut verdicts = Vec::with_capacity(windows.len());

        for (index, window) in windows.iter().enumerate() {
            let (mut correlations, exponent) = autocorrelation(window);
            lag_window(&mut correlations);
            let prediction = levinson.solve(&correlations);
            let lsp = lp_to_lsp(&prediction.coefficients, &previous_lsp);
            previous_lsp = lsp;
            let verdict = detector.decide(
                prediction.reflection[1],
                &lsp_to_normalised_lsf(&lsp),
                &correlations,
                exponent,
                window,
                index as i16 + 1,
                previous,
                before,
            );
            before = previous;
            previous = verdict;
            verdicts.push(verdict);
        }
        verdicts
    }

    /// A window of low-level white-ish noise, deterministic.
    fn noise(seed: &mut u32, level: i16) -> [i16; WINDOW] {
        std::array::from_fn(|_| {
            *seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (((*seed >> 16) & 0x7fff) as i32 - 16_384) as i16 / (32_767 / level.max(1))
        })
    }

    /// A window of a strongly voiced vowel-like signal: a pitch pulse train shaped by two formants.
    fn voiced(phase: &mut f32) -> [i16; WINDOW] {
        std::array::from_fn(|_| {
            *phase += 1.0;
            let period = 80.0;
            let position = (*phase % period) / period;
            let envelope = (-position * 6.0).exp();
            let formant = (position * period * 0.35).sin() + 0.6 * (position * period * 0.9).sin();
            (formant * envelope * 9000.0) as i16
        })
    }

    #[test]
    fn silence_after_the_estimate_settles_is_called_noise() {
        // The background estimate needs the initialisation window before it can call anything noise;
        // after that, a steady quiet input must not be transmitted as speech or the whole point of
        // discontinuous transmission is lost.
        let mut seed = 1_u32;
        let windows: Vec<[i16; WINDOW]> = (0..140).map(|_| noise(&mut seed, 40)).collect();
        let verdicts = run(&windows);

        let tail = &verdicts[120..];
        let speech = tail.iter().filter(|v| v.is_speech()).count();
        assert!(
            speech <= tail.len() / 10,
            "{speech} of {} settled noise frames called speech",
            tail.len()
        );
    }

    #[test]
    fn a_vowel_over_settled_background_is_called_speech() {
        // The complement, and the one that matters more: a talker arriving after a long silence has
        // to be transmitted from the first frames, or the word loses its onset.
        let mut seed = 7_u32;
        let mut phase = 0.0_f32;
        let mut windows: Vec<[i16; WINDOW]> = (0..120).map(|_| noise(&mut seed, 40)).collect();
        windows.extend((0..20).map(|_| voiced(&mut phase)));
        let verdicts = run(&windows);

        let spoken = &verdicts[120..];
        let speech = spoken.iter().filter(|v| v.is_speech()).count();
        assert!(
            speech >= spoken.len() * 3 / 4,
            "only {speech} of {} voiced frames called speech",
            spoken.len()
        );
    }

    #[test]
    fn the_same_input_twice_gives_the_same_decisions() {
        // The decision is a function of the input and the detector's own history, nothing else. A
        // detector that read anything ambient would make one leg of a call transmit differently
        // from another carrying the same audio.
        let mut seed = 3_u32;
        let mut phase = 0.0_f32;
        let mut windows: Vec<[i16; WINDOW]> = (0..60).map(|_| noise(&mut seed, 60)).collect();
        windows.extend((0..20).map(|_| voiced(&mut phase)));
        assert_eq!(run(&windows), run(&windows));
    }

    // The hangover that holds the decision through the quiet tail of a word is exercised by the
    // conformance run rather than here: `tstseq1` through `tstseq4` are real speech with real
    // silences, and matching the reference's decision on all 2927 of their frames says more about
    // it than any assertion over a synthetic cut could.

    #[test]
    fn a_detector_with_no_input_at_all_does_not_panic_and_stays_in_range() {
        // Digital silence is a real input — a muted leg — and the zero-crossing count, the log of a
        // zero energy and the minimum tracker all have to survive it.
        let verdicts = run(&vec![[0_i16; WINDOW]; 200]);
        assert_eq!(verdicts.len(), 200);
    }
}
