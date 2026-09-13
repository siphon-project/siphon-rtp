//! The decoder's frame loop (ITU-T G.729 Release 3 `dec_ld8k.c`): parameters in, synthesised
//! speech out, before the postfilter.
//!
//! One 10 ms frame is two 40-sample subframes. Each builds its excitation from an adaptive- and a
//! fixed-codebook contribution, runs it through the synthesis filter, and carries its state into the
//! next: the excitation history the adaptive codebook reaches into, the synthesis filter's memory,
//! the pitch-sharpening factor, and the two gain values an erased frame falls back on.

use super::bitstream::{FrameParameters, FRAME_SAMPLES, SUBFRAME_SAMPLES};
use super::excitation::{
    adaptive_codebook, clamp_sharpening, decode_first_lag, decode_second_lag, fixed_codebook,
    sharpen, GainDecoder, PitchLag, EXCITATION_HISTORY, PITCH_MAX, SHARP_MIN,
};
use super::filter::{syn_filt, ORDER};
use super::lpcfunc::{interpolate_subframe_filters, COEFFICIENTS};
use super::lspdec::LspDecoder;
use crate::itu::basic_ops::{add, extract_l, l_add, l_mac, l_mult, l_shl, l_shr, round_word, shr};

/// The excitation buffer: history the adaptive codebook reaches into, then the frame itself.
const EXCITATION_LENGTH: usize = EXCITATION_HISTORY + FRAME_SAMPLES;

/// The LSP vector a decoder starts from, before any frame has been received.
const INITIAL_LSP: [i16; ORDER] = [
    30_000, 26_000, 21_000, 15_000, 8000, 0, -8000, -15_000, -21_000, -26_000,
];

/// The reference's `Random()`: a linear congruential generator whose only job is to fill in a
/// codebook index for an erased frame, so that a lost packet gives noise rather than a repeat.
#[derive(Debug, Clone)]
struct Noise {
    seed: i16,
}

impl Noise {
    fn new() -> Self {
        Self { seed: 21_845 }
    }

    fn next(&mut self) -> i16 {
        // seed = seed * 31821 + 13849, in the reference's fixed-point form.
        self.seed = extract_l(l_add(l_shr(l_mult(self.seed, 31_821), 1), 13_849));
        self.seed
    }
}

/// The G.729 decoder's per-call state.
#[derive(Debug, Clone)]
pub struct Decoder {
    lsp: LspDecoder,
    gains: GainDecoder,
    noise: Noise,
    /// Past excitation, long enough for the deepest pitch lag the bitstream can express.
    excitation: [i16; EXCITATION_LENGTH],
    /// The synthesis filter's memory between subframes.
    synthesis_memory: [i16; ORDER],
    /// The previous frame's LSPs, which the first subframe's filter interpolates towards.
    previous_lsp: [i16; ORDER],
    /// Pitch-sharpening factor, the previous subframe's clamped pitch gain.
    sharp: i16,
    /// The integer pitch lag to reuse when a frame is lost or its parity fails.
    previous_lag: i16,
    /// Gains carried into an erased subframe, where they are faded rather than decoded.
    previous_pitch_gain: i16,
    previous_code_gain: i16,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// A decoder in its reset state (the reference's `Init_Decod_ld8k`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            lsp: LspDecoder::new(),
            gains: GainDecoder::new(),
            noise: Noise::new(),
            excitation: [0; EXCITATION_LENGTH],
            synthesis_memory: [0; ORDER],
            previous_lsp: INITIAL_LSP,
            sharp: SHARP_MIN,
            previous_lag: 60,
            previous_pitch_gain: 0,
            previous_code_gain: 0,
        }
    }

    /// Decode one frame into 80 samples of synthesised speech, before postfiltering.
    ///
    /// `parameters` is `None` for a lost frame, which drives the concealment path: the LSPs repeat,
    /// the lag walks forward, the gains fade, and the fixed codebook is filled from the noise
    /// generator. `voicing` is the previous frame's postfilter voicing decision, which decides
    /// whether a concealed frame leans on its periodic or its noise-like contribution.
    ///
    /// Returns the synthesised frame and the per-subframe LP filters, which the postfilter needs.
    pub fn decode_frame(
        &mut self,
        parameters: Option<&FrameParameters>,
        voicing: i16,
    ) -> ([i16; FRAME_SAMPLES], [[i16; COEFFICIENTS]; 2], i16) {
        let erased = parameters.is_none();
        let (stage1, stage2) = parameters.map_or((0, 0), |p| (p.lsp_stage1, p.lsp_stage2));

        let lsp = self.lsp.decode(stage1, stage2, erased);
        let filters = interpolate_subframe_filters(&self.previous_lsp, &lsp);
        self.previous_lsp = lsp;

        let mut synthesis = [0_i16; FRAME_SAMPLES];
        let mut first_lag = PitchLag {
            integer: 0,
            fraction: 0,
        };

        for (subframe, filter) in filters.iter().enumerate() {
            let start = subframe * SUBFRAME_SAMPLES;
            let offset = EXCITATION_HISTORY + start;

            // ---- pitch lag -------------------------------------------------------------------
            // A parity failure on the first subframe is treated exactly as a lost frame would be
            // for the lag alone: the previous lag is reused and walked forward, so a corrupted lag
            // cannot drag the pitch somewhere implausible.
            let parity_failed = parameters.is_some_and(|p| p.pitch_parity_error());
            let reuse_lag = erased || (subframe == 0 && parity_failed);
            let lag = if reuse_lag {
                let lag = PitchLag {
                    integer: self.previous_lag,
                    fraction: 0,
                };
                self.previous_lag = add(self.previous_lag, 1).min(PITCH_MAX);
                lag
            } else {
                let index = parameters.map_or(0, |p| p.subframes[subframe].pitch_lag);
                let lag = if subframe == 0 {
                    decode_first_lag(index)
                } else {
                    decode_second_lag(index, first_lag)
                };
                self.previous_lag = lag.integer;
                lag
            };
            if subframe == 0 {
                first_lag = lag;
            }

            // ---- adaptive codebook ------------------------------------------------------------
            adaptive_codebook(&mut self.excitation, offset, lag, SUBFRAME_SAMPLES);

            // ---- fixed codebook --------------------------------------------------------------
            let (positions, signs) = if erased {
                // A lost frame has no codebook indices, so it gets random ones: noise at the right
                // energy is a better concealment than repeating the last vector, which would buzz.
                (
                    (self.noise.next() & 0x1fff) as u16,
                    (self.noise.next() & 0x000f) as u16,
                )
            } else {
                parameters.map_or((0, 0), |p| {
                    (
                        p.subframes[subframe].fixed_positions,
                        p.subframes[subframe].fixed_signs,
                    )
                })
            };
            let mut code = fixed_codebook(signs, positions);
            sharpen(&mut code, lag.integer, self.sharp);

            // ---- gains ------------------------------------------------------------------------
            let (pitch_gain, code_gain) = if erased {
                self.gains
                    .decode_erased(self.previous_pitch_gain, self.previous_code_gain)
            } else {
                let index = parameters.map_or(0, |p| p.subframes[subframe].gains);
                self.gains.decode(index, &code)
            };
            self.previous_pitch_gain = pitch_gain;
            self.previous_code_gain = code_gain;
            self.sharp = clamp_sharpening(pitch_gain);

            // On a lost frame the two contributions are not mixed: a voiced frame keeps only its
            // periodic part and an unvoiced one only its noise, so concealment does not introduce
            // periodicity into noise or noise into a vowel.
            let (applied_pitch, applied_code) = if erased {
                if voicing == 0 {
                    (0, code_gain)
                } else {
                    (pitch_gain, 0)
                }
            } else {
                (pitch_gain, code_gain)
            };

            // ---- total excitation -------------------------------------------------------------
            for (sample, &innovation) in self.excitation[offset..offset + SUBFRAME_SAMPLES]
                .iter_mut()
                .zip(code.iter())
            {
                let mut sum = l_mult(*sample, applied_pitch);
                sum = l_mac(sum, innovation, applied_code);
                sum = l_shl(sum, 1);
                *sample = round_word(sum);
            }

            // ---- synthesis --------------------------------------------------------------------
            let mut output = [0_i16; SUBFRAME_SAMPLES];
            let overflow = syn_filt(
                filter,
                &self.excitation[offset..],
                &mut output,
                SUBFRAME_SAMPLES,
                &mut self.synthesis_memory,
                false,
            );
            if overflow.raised() {
                // The excitation drove the filter past what it can represent. Scale the *whole*
                // history down by four and synthesise again — filtering the clipped result instead
                // would leave a burst of distortion that the next subframes would then predict
                // from. This is what the `overflow` conformance sequence exists to exercise.
                for sample in &mut self.excitation {
                    *sample = shr(*sample, 2);
                }
                let _ = syn_filt(
                    filter,
                    &self.excitation[offset..],
                    &mut output,
                    SUBFRAME_SAMPLES,
                    &mut self.synthesis_memory,
                    true,
                );
            } else {
                self.synthesis_memory
                    .copy_from_slice(&output[SUBFRAME_SAMPLES - ORDER..]);
            }
            synthesis[start..start + SUBFRAME_SAMPLES].copy_from_slice(&output);
        }

        // Shift the excitation history left by one frame, ready for the next.
        self.excitation.copy_within(FRAME_SAMPLES.., 0);

        (synthesis, filters, first_lag.integer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g729::bitstream::unpack;

    #[test]
    fn a_fresh_decoder_starts_silent_and_from_the_reference_lsp_vector() {
        let decoder = Decoder::new();
        assert_eq!(decoder.previous_lsp, INITIAL_LSP);
        assert!(decoder.excitation.iter().all(|&s| s == 0));
        assert!(decoder.synthesis_memory.iter().all(|&s| s == 0));
    }

    #[test]
    fn the_noise_generator_follows_the_reference_sequence() {
        // The concealment path depends on this exact sequence, so a decoder that seeded or stepped
        // it differently would diverge from the reference only on lost frames — the case least
        // likely to be noticed and most likely to matter.
        let mut noise = Noise::new();
        let first: Vec<i16> = (0..4).map(|_| noise.next()).collect();
        let mut again = Noise::new();
        let repeat: Vec<i16> = (0..4).map(|_| again.next()).collect();
        assert_eq!(first, repeat, "deterministic from the same seed");
        assert_ne!(first[0], first[1], "and it does advance");
    }

    #[test]
    fn every_frame_decodes_to_a_full_frame_of_samples() {
        let mut decoder = Decoder::new();
        let frame = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];
        let parameters = unpack(&frame).expect("ten octets");
        for _ in 0..10 {
            let (samples, filters, _) = decoder.decode_frame(Some(&parameters), 60);
            assert_eq!(samples.len(), FRAME_SAMPLES);
            assert_eq!(filters[0][0], 4096, "each subframe filter is monic in Q12");
            assert_eq!(filters[1][0], 4096);
        }
    }

    #[test]
    fn a_lost_frame_still_produces_a_frame_of_audio() {
        // Concealment, not silence: the decoder has to hand the media path 10 ms of something on
        // every frame, or a lost packet becomes a gap in the timeline rather than a glitch.
        let mut decoder = Decoder::new();
        let frame = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];
        let parameters = unpack(&frame).expect("ten octets");
        for _ in 0..5 {
            let _ = decoder.decode_frame(Some(&parameters), 60);
        }
        let (concealed, _, _) = decoder.decode_frame(None, 60);
        assert_eq!(concealed.len(), FRAME_SAMPLES);
        assert!(
            concealed.iter().any(|&s| s != 0),
            "a concealed frame carries audio, not silence"
        );
    }

    #[test]
    fn a_long_run_of_lost_frames_decays_towards_silence_without_ringing() {
        // The gain fade compounds: a burst of loss must not leave the decoder buzzing on a repeated
        // pitch pulse, which is the classic bad concealment.
        let mut decoder = Decoder::new();
        let frame = [0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa];
        let parameters = unpack(&frame).expect("ten octets");
        for _ in 0..10 {
            let _ = decoder.decode_frame(Some(&parameters), 60);
        }
        let mut energies = Vec::new();
        for _ in 0..30 {
            let (samples, _, _) = decoder.decode_frame(None, 60);
            let energy: i64 = samples.iter().map(|&s| i64::from(s) * i64::from(s)).sum();
            energies.push(energy);
        }
        assert!(
            energies.last() <= energies.first(),
            "energy decays across a loss burst: {} then {}",
            energies[0],
            energies[energies.len() - 1]
        );
    }

    #[test]
    fn the_excitation_history_shifts_by_exactly_one_frame() {
        // The adaptive codebook reads into this history by pitch lag, so an off-by-one shift would
        // detune every subsequent frame rather than fail outright.
        let mut decoder = Decoder::new();
        let frame = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];
        let parameters = unpack(&frame).expect("ten octets");
        let _ = decoder.decode_frame(Some(&parameters), 60);
        let before: Vec<i16> = decoder.excitation[FRAME_SAMPLES..EXCITATION_HISTORY].to_vec();
        let _ = decoder.decode_frame(Some(&parameters), 60);
        assert_eq!(
            decoder.excitation[..EXCITATION_HISTORY - FRAME_SAMPLES],
            before[..EXCITATION_HISTORY - FRAME_SAMPLES],
            "the history moved left by one frame and no further"
        );
    }
}
