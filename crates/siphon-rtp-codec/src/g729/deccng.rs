//! The decoder's comfort-noise generation — ITU-T G.729 Annex B §5, reference `dec_sid.c`.
//!
//! The mirror of [`dtx`](super::dtx): a descriptor arrives and updates what the background sounds
//! like, an untransmitted frame arrives and the decoder keeps making that background. The level is
//! stepped towards the descriptor's rather than jumped to, with the same coefficients the encoder
//! used, so the two stay together frame for frame.
//!
//! One case is worth naming. If the *first* descriptor after a talk spurt is lost, the decoder has
//! no description of this background at all — and the frame before it was speech, so continuing
//! that would be worse than silence. It recovers a level from the energy of the excitation it has
//! just been synthesising, quantising it through the encoder's own routine so that the level it
//! lands on is one the encoder could have sent.

use super::cng::{self, Random};
use super::filter::ORDER;
use super::lpcfunc::{interpolate_subframe_filters, COEFFICIENTS};
use super::lspdec::Predictor;
use super::sidgain;
use super::sidlsf::{self, SpectrumIndices};
use super::tables::SID_GAIN;
use crate::itu::basic_ops::{add, mult_r};

/// Carried and new shares of the level on an untransmitted frame (`A_GAIN0` / `A_GAIN1`).
const GAIN_CARRY: i16 = 28_672;
const GAIN_NEW: i16 = 4096;

/// The decoder's comfort-noise state.
#[derive(Debug, Clone)]
pub struct ComfortNoiseDecoder {
    /// The background's line spectral pairs, from the last descriptor. The reset value is an evenly
    /// spread spectrum, so a stream that opens on an untransmitted frame still has a filter.
    lsp: [i16; ORDER],
    /// The last descriptor's level, and the level being played now.
    descriptor_gain: i16,
    current_gain: i16,
}

impl Default for ComfortNoiseDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ComfortNoiseDecoder {
    /// A comfort-noise decoder in its reset state (`Init_Dec_cng`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            lsp: [
                31_441, 27_566, 21_458, 13_612, 4663, -4663, -13_612, -21_458, -27_566, -31_441,
            ],
            descriptor_gain: SID_GAIN[0],
            current_gain: 0,
        }
    }

    /// Produce one inactive frame's excitation and filters (`Dec_cng`).
    ///
    /// `descriptor` is `Some` on a silence descriptor and `None` on an untransmitted frame.
    /// `after_speech` says whether the frame before this one was speech, which is what decides
    /// between jumping to the new level and stepping towards it. `saved_energy` is the excitation
    /// energy the decoder has been synthesising, used only to recover a level when the first
    /// descriptor of a silence was lost.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        &mut self,
        descriptor: Option<(SpectrumIndices, u16)>,
        after_speech: bool,
        saved_energy: (i16, i16),
        predictor: &mut Predictor,
        previous_lsp: &mut [i16; ORDER],
        excitation: &mut [i16],
        origin: usize,
        random: &mut Random,
    ) -> [[i16; COEFFICIENTS]; 2] {
        match descriptor {
            Some((spectrum, gain)) => {
                self.descriptor_gain = SID_GAIN[gain as usize];
                self.lsp = sidlsf::dequantise(predictor, spectrum);
            }
            None if after_speech => {
                // The first descriptor of this silence was lost. Recover a level from what is
                // already in the excitation buffer rather than falling to nothing.
                let (index, _) = sidgain::quantise_saved(saved_energy.0, saved_energy.1);
                self.descriptor_gain = SID_GAIN[index as usize];
            }
            None => {}
        }

        self.current_gain = if after_speech {
            self.descriptor_gain
        } else {
            add(
                mult_r(self.current_gain, GAIN_CARRY),
                mult_r(self.descriptor_gain, GAIN_NEW),
            )
        };

        cng::generate(self.current_gain, excitation, origin, random, None);

        let filters = interpolate_subframe_filters(previous_lsp, &self.lsp);
        *previous_lsp = self.lsp;
        filters
    }
}
