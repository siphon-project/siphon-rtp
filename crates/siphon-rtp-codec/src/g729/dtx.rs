//! The encoder's discontinuous-transmission decision and silence descriptor — ITU-T G.729 Annex B
//! §4, reference `dtx.c`.
//!
//! The voice-activity decision says a frame is background. This decides what, if anything, to send
//! about it. Most inactive frames are sent as nothing at all; a descriptor goes out only when the
//! background has actually changed, which is the whole saving — a call on hold costs two octets
//! every few frames instead of twenty every frame.
//!
//! "Changed" is two tests. The spectrum is compared against the last descriptor's using an Itakura
//! distance, computed as a correlation between the two filters' autocorrelations rather than by
//! filtering anything; and the level is compared against the last one's in the quantiser's own
//! decibel steps, so a change too small to be transmitted does not trigger a transmission. Either
//! one moving sends a new descriptor.
//!
//! There is also a floor: at least [`MIN_FRAMES_BETWEEN_DESCRIPTORS`] frames must pass between
//! descriptors whatever the tests say, so that a background sitting exactly on a decision boundary
//! cannot make the encoder send every frame.
//!
//! The descriptor is not built from the frame it is sent on. It is built from an average of the
//! autocorrelations of the last few frames, because a single frame of background is a poor estimate
//! of background and the decoder will hold whatever it is told for a long time.

use super::analysis::lp_to_lsp;
use super::analysis::{Levinson, VAD_ORDER};
use super::cng::{self, Random};
use super::filter::ORDER;
use super::lpcfunc::{interpolate_subframe_filters, COEFFICIENTS};
use super::lspdec::Predictor;
use super::overflow::{self, Overflow};
use super::sidgain;
use super::sidlsf::{self, SpectrumIndices};
use super::tables::SID_GAIN;
use super::weighting::Taming;
use crate::itu::basic_ops::{
    abs_s, add, extract_h, l_add, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r, negate,
    norm_l, round_word, shr, sub,
};

/// Frames of autocorrelation averaged into one descriptor's spectrum (`NB_SUMACF` × `NB_CURACF`).
const CURRENT_FRAMES: usize = 2;
const AVERAGED_GROUPS: usize = 3;
/// Residual energies averaged into one descriptor's level (`NB_GAIN`).
const ENERGY_HISTORY: usize = 2;
/// Frames that must pass between descriptors (`FR_SID_MIN`).
pub const MIN_FRAMES_BETWEEN_DESCRIPTORS: i16 = 3;
/// Itakura thresholds: against the reference filter, and against the past average (`FRAC_THRESH1`,
/// `FRAC_THRESH2`).
const CHANGE_THRESHOLD: i16 = 4855;
const STATIONARY_THRESHOLD: i16 = 3161;
/// How much of the previous frame's gain is carried into an untransmitted frame's (`A_GAIN0` and
/// its complement), which is what stops the comfort noise stepping when a new descriptor arrives.
const GAIN_CARRY: i16 = 28_672;
const GAIN_NEW: i16 = 4096;

/// What the encoder decided to send for one inactive frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InactiveFrame {
    /// Nothing at all: the background has not changed since the last descriptor.
    Untransmitted,
    /// A silence descriptor: two octets saying what the background now sounds like.
    Descriptor {
        /// The spectrum indices.
        spectrum: SpectrumIndices,
        /// The five-bit level index.
        gain: u16,
    },
}

/// The encoder's comfort-noise state.
#[derive(Debug, Clone)]
pub struct ComfortNoiseEncoder {
    /// Line spectral pairs of the last descriptor sent, which the encoder synthesises against.
    descriptor_lsp: [i16; ORDER],
    /// The filter the next spectrum is compared against, as an autocorrelation, and its exponent.
    reference_correlation: [i16; ORDER + 1],
    reference_exponent: i16,
    /// The average filter, kept so a stationary background can be described by it rather than by
    /// whichever frame happened to trigger the descriptor.
    average_filter: [i16; COEFFICIENTS],

    /// The last two frames' autocorrelations and their exponents.
    recent: [[i16; ORDER + 1]; CURRENT_FRAMES],
    recent_exponents: [i16; CURRENT_FRAMES],
    /// Three groups of those, summed, for the longer average.
    groups: [[i16; ORDER + 1]; AVERAGED_GROUPS],
    group_exponents: [i16; AVERAGED_GROUPS],

    /// Residual energies of the last frames and their exponents.
    energies: [i16; ENERGY_HISTORY],
    energy_exponents: [i16; ENERGY_HISTORY],
    /// How many of those are averaged into the next descriptor.
    averaged_energies: usize,

    /// Position in the two-frame cycle that feeds the longer average.
    phase: usize,
    /// The level the last descriptor asked for, and the level being played now.
    descriptor_gain: i16,
    current_gain: i16,
    /// Level of the last descriptor in decibels, for the change test.
    previous_level: i16,
    /// Whether the background has changed since the last descriptor.
    changed: bool,
    /// Frames since the last descriptor.
    since_descriptor: i16,
}

impl Default for ComfortNoiseEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ComfortNoiseEncoder {
    /// A comfort-noise encoder in its reset state (`Init_Cod_cng`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptor_lsp: [0; ORDER],
            reference_correlation: [0; ORDER + 1],
            reference_exponent: 0,
            average_filter: [0; COEFFICIENTS],
            recent: [[0; ORDER + 1]; CURRENT_FRAMES],
            // 40 is far enough below any real exponent that the first real frame wins the minimum.
            recent_exponents: [40; CURRENT_FRAMES],
            groups: [[0; ORDER + 1]; AVERAGED_GROUPS],
            group_exponents: [40; AVERAGED_GROUPS],
            energies: [0; ENERGY_HISTORY],
            energy_exponents: [40; ENERGY_HISTORY],
            averaged_energies: 0,
            phase: 0,
            descriptor_gain: 0,
            current_gain: 0,
            previous_level: 0,
            changed: false,
            since_descriptor: 0,
        }
    }

    /// Record one frame's autocorrelation, whether or not it was speech (`Update_cng`).
    ///
    /// Every frame feeds this, because the background estimate has to be ready the moment a talker
    /// stops — waiting until then would describe the tail of the last word.
    pub fn observe(
        &mut self,
        correlations: &[(i16, i16); VAD_ORDER + 1],
        exponent: i16,
        speech: bool,
    ) {
        self.recent.copy_within(..CURRENT_FRAMES - 1, 1);
        self.recent_exponents.copy_within(..CURRENT_FRAMES - 1, 1);

        self.recent_exponents[0] = negate(add(16, exponent));
        for (slot, &(high, _)) in self.recent[0].iter_mut().zip(correlations.iter()) {
            *slot = high;
        }

        self.phase = add(self.phase as i16, 1) as usize;
        if self.phase == CURRENT_FRAMES {
            self.phase = 0;
            if speech {
                self.accumulate_group();
            }
        }
    }

    /// Decide what to send for one inactive frame, and fill the frame's excitation with comfort
    /// noise (`Cod_cng`).
    ///
    /// `levinson` is the encoder's own recursion, shared deliberately: the reference calls it here
    /// from the same file-scope state the frame analysis uses, so the stale-filter fallback one path
    /// leaves behind is what the other would pick up.
    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        &mut self,
        after_speech: bool,
        levinson: &mut Levinson,
        predictor: &mut Predictor,
        previous_lsp: &mut [i16; ORDER],
        excitation: &mut [i16],
        origin: usize,
        random: &mut Random,
        taming: &mut Taming,
    ) -> (InactiveFrame, [[i16; COEFFICIENTS]; 2]) {
        self.energies.copy_within(..ENERGY_HISTORY - 1, 1);
        self.energy_exponents.copy_within(..ENERGY_HISTORY - 1, 1);

        // The spectrum of the last couple of frames, as one autocorrelation.
        let (current, exponent) = sum_correlations(&self.recent, &self.recent_exponents);
        self.energy_exponents[0] = exponent;

        let mut current_filter = [0_i16; COEFFICIENTS];
        if current[0] == 0 {
            self.energies[0] = 0;
        } else {
            let solved = levinson.solve(&widen(&current));
            current_filter = solved.coefficients;
            self.energies[0] = solved.residual_energy;
        }

        let send_descriptor;
        let level;
        let gain_index;
        if after_speech {
            // The first inactive frame after speech always sends: the decoder has no description of
            // this background at all yet.
            send_descriptor = true;
            self.since_descriptor = 0;
            self.averaged_energies = 1;
            let (index, decoded) =
                sidgain::quantise(&self.energies[..1], &self.energy_exponents[..1]);
            gain_index = index;
            level = decoded;
        } else {
            self.averaged_energies = (self.averaged_energies + 1).min(ENERGY_HISTORY);
            let (index, decoded) = sidgain::quantise(
                &self.energies[..self.averaged_energies],
                &self.energy_exponents[..self.averaged_energies],
            );
            gain_index = index;
            level = decoded;

            if itakura_exceeds(
                &self.reference_correlation,
                self.reference_exponent,
                &current,
                self.energies[0],
                CHANGE_THRESHOLD,
            ) {
                self.changed = true;
            }
            // A level difference the quantiser would not resolve is not a change.
            if sub(abs_s(sub(self.previous_level, level)), 2) > 0 {
                self.changed = true;
            }

            self.since_descriptor = add(self.since_descriptor, 1);
            if sub(self.since_descriptor, MIN_FRAMES_BETWEEN_DESCRIPTORS) < 0 {
                send_descriptor = false;
            } else {
                send_descriptor = self.changed;
                // Pinned rather than left to climb, so it cannot overflow on a long silence.
                self.since_descriptor = MIN_FRAMES_BETWEEN_DESCRIPTORS;
            }
        }

        let mut frame = InactiveFrame::Untransmitted;
        if send_descriptor {
            self.since_descriptor = 0;
            self.changed = false;

            self.average_filter = self.past_filter(levinson);
            let (correlation, exponent) = filter_correlation(&self.average_filter);
            self.reference_correlation = correlation;
            self.reference_exponent = exponent;

            // A background that has not moved is better described by the average than by the frame
            // that happened to trip the threshold.
            let filter = if itakura_exceeds(
                &self.reference_correlation,
                self.reference_exponent,
                &current,
                self.energies[0],
                STATIONARY_THRESHOLD,
            ) {
                let (correlation, exponent) = filter_correlation(&current_filter);
                self.reference_correlation = correlation;
                self.reference_exponent = exponent;
                current_filter
            } else {
                self.average_filter
            };

            let lsp = lp_to_lsp(&filter, previous_lsp);
            let (spectrum, quantised) = sidlsf::quantise(predictor, &lsp);
            self.descriptor_lsp = quantised;
            self.previous_level = level;
            self.descriptor_gain = SID_GAIN[gain_index as usize];
            frame = InactiveFrame::Descriptor {
                spectrum,
                gain: gain_index,
            };
        }

        // Step towards the descriptor's level rather than jumping to it.
        self.current_gain = if after_speech {
            self.descriptor_gain
        } else {
            add(
                mult_r(self.current_gain, GAIN_CARRY),
                mult_r(self.descriptor_gain, GAIN_NEW),
            )
        };

        cng::generate(self.current_gain, excitation, origin, random, Some(taming));

        let filters = interpolate_subframe_filters(previous_lsp, &self.descriptor_lsp);
        *previous_lsp = self.descriptor_lsp;

        if self.phase == 0 {
            self.accumulate_group();
        }

        (frame, filters)
    }

    /// The filter fitted to the longer average of autocorrelations (`Calc_pastfilt`).
    fn past_filter(&mut self, levinson: &mut Levinson) -> [i16; COEFFICIENTS] {
        let (summed, _) = sum_correlations(&self.groups, &self.group_exponents);
        if summed[0] == 0 {
            let mut flat = [0_i16; COEFFICIENTS];
            flat[0] = 4096;
            return flat;
        }
        levinson.solve(&widen(&summed)).coefficients
    }

    /// Fold the last two frames into the longer average (`Update_sumAcf`).
    fn accumulate_group(&mut self) {
        self.groups.copy_within(..AVERAGED_GROUPS - 1, 1);
        self.group_exponents.copy_within(..AVERAGED_GROUPS - 1, 1);
        let (summed, exponent) = sum_correlations(&self.recent, &self.recent_exponents);
        self.groups[0] = summed;
        self.group_exponents[0] = exponent;
    }
}

/// Sum several autocorrelations that were measured at different scales (`Calc_sum_acf`).
fn sum_correlations<const N: usize>(
    correlations: &[[i16; ORDER + 1]; N],
    exponents: &[i16; N],
) -> ([i16; ORDER + 1], i16) {
    let mut smallest = exponents[0];
    for &value in &exponents[1..] {
        if sub(value, smallest) < 0 {
            smallest = value;
        }
    }
    // Two bits of margin for the sum.
    let smallest = add(smallest, 14);

    let mut wide = [0_i32; ORDER + 1];
    for (correlation, &own) in correlations.iter().zip(exponents.iter()) {
        let shift = sub(smallest, own);
        for (slot, &value) in wide.iter_mut().zip(correlation.iter()) {
            *slot = l_add(*slot, l_shl(l_deposit_l(value), shift));
        }
    }

    let normalisation = norm_l(wide[0]);
    let mut summed = [0_i16; ORDER + 1];
    for (slot, &value) in summed.iter_mut().zip(wide.iter()) {
        *slot = extract_h(l_shl(value, normalisation));
    }
    (summed, add(smallest, sub(normalisation, 16)))
}

/// Present a tenth-order autocorrelation to the Levinson recursion, which is written against the
/// wider vector the voice-activity decision needs. The recursion reads only the first eleven.
fn widen(correlations: &[i16; ORDER + 1]) -> [(i16, i16); VAD_ORDER + 1] {
    let mut wide = [(0_i16, 0_i16); VAD_ORDER + 1];
    for (slot, &value) in wide.iter_mut().zip(correlations.iter()) {
        slot.0 = value;
    }
    wide
}

/// The autocorrelation of a filter's own coefficients, normalised (`Calc_RCoeff`).
///
/// Correlating this against a frame's autocorrelation gives the energy that filter would leave —
/// the Itakura distance — without running the filter over anything.
fn filter_correlation(filter: &[i16; COEFFICIENTS]) -> ([i16; ORDER + 1], i16) {
    let mut energy = 0_i32;
    for &coefficient in filter.iter() {
        energy = l_mac(energy, coefficient, coefficient);
    }
    let normalisation = norm_l(energy);

    let mut correlation = [0_i16; ORDER + 1];
    correlation[0] = round_word(l_shl(energy, normalisation));
    for lag in 1..=ORDER {
        let mut sum = 0_i32;
        for j in 0..=ORDER - lag {
            sum = l_mac(sum, filter[j], filter[j + lag]);
        }
        correlation[lag] = round_word(l_shl(sum, normalisation));
    }
    (correlation, normalisation)
}

/// Whether the frame's spectrum has moved away from the reference filter by more than the threshold
/// (`Cmp_filt`).
///
/// Both operands are rescaled until the correlation stops saturating, alternating which one gives
/// ground, because either can be the one with too little headroom.
fn itakura_exceeds(
    reference: &[i16; ORDER + 1],
    reference_exponent: i16,
    correlation: &[i16; ORDER + 1],
    residual_energy: i16,
    threshold: i16,
) -> bool {
    let mut shifts = [0_i16, 0];
    let mut which = 1_usize;
    let distance = loop {
        let mut flag = Overflow::clear();
        let first = shr(reference[0], shifts[0]);
        let second = shr(correlation[0], shifts[1]);
        let mut accumulator = l_shr(l_mult(first, second), 1);
        for lag in 1..=ORDER {
            let first = shr(reference[lag], shifts[0]);
            let second = shr(correlation[lag], shifts[1]);
            accumulator = overflow::l_mac(&mut flag, accumulator, first, second);
        }
        if !flag.raised() {
            break accumulator;
        }
        shifts[which] = add(shifts[which], 1);
        which = 1 - which;
    };

    let scaled = mult_r(residual_energy, threshold);
    let mut bound = l_add(l_deposit_l(scaled), l_deposit_l(residual_energy));
    // 9 = the LP coefficients' Q format doubled, minus 16, plus 1.
    let alignment = sub(add(reference_exponent, 9), add(shifts[0], shifts[1]));
    bound = l_shl(bound, alignment);

    l_sub(distance, bound) > 0
}
