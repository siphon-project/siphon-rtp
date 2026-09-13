//! The encoder's frame loop — ITU-T G.729 §3, reference `cod_ld8k.c`.
//!
//! Ten milliseconds in, ten octets out. The frame is analysed once — a linear-prediction fit over a
//! 30 ms window, converted to line spectral pairs and quantised — and then coded twice, once per
//! 5 ms subframe, as an adaptive-codebook contribution at some pitch lag plus four algebraic pulses,
//! with the two gains quantised jointly.
//!
//! Almost everything here is the plumbing between stages that each have their own module, and the
//! plumbing is where a port goes wrong: which filter a stage sees (interpolated or transmitted,
//! quantised or not), which memory it updates, and in what order. Three points are worth naming.
//!
//! The target for the pitch search is not the weighted input speech. It is built by filtering the
//! LP residual through `1/A(z)` and then `W(z)`, which is algebraically the same thing and behaves
//! far better in fixed point; the reference says so in a comment and this follows it.
//!
//! The encoder synthesises its own output every subframe and keeps the error. That local synthesis
//! is what the next subframe's filter memories are built from, so encoder and decoder stay on the
//! same excitation history — the whole codec depends on the two agreeing, and this is where they
//! are made to.
//!
//! There is an algorithmic delay of 5 ms on top of the frame: the analysis window reaches 40 samples
//! into the future, so the frame being coded ends 40 samples before the newest input.

use super::acelp::CodebookSearch;
use super::analysis::{autocorrelation, lag_window, lp_to_lsp, Levinson, PreProcessor, WINDOW};
use super::bitstream::{
    pack, pack_silence, pitch_parity, SilenceParameters, FRAME_BYTES, FRAME_SAMPLES, SILENCE_BYTES,
    SUBFRAME_SAMPLES,
};
use super::cng::{Random, INITIAL_SEED};
use super::dtx::{ComfortNoiseEncoder, InactiveFrame};
use super::excitation::{
    adaptive_codebook, clamp_sharpening, PitchLag, EXCITATION_HISTORY, PITCH_MAX, SHARP_MIN,
};
use super::filter::{convolve, residu, syn_filt, ORDER};
use super::lpcfunc::{
    interpolate_subframe_filters, lsp_to_lp, midpoint_lsp, weight_lp, COEFFICIENTS,
};
use super::pitch::{closed_loop_lag, encode_lag, first_subframe_range, open_loop_lag, pitch_gain};
use super::quagain::{distortion_terms, GainQuantiser};
use super::qualsp::LspQuantiser;
use super::vad::{Activity, VoiceActivityDetector};
use super::weighting::{lsp_to_normalised_lsf, PerceptualWeighting, Taming, TAMED_PITCH_GAIN};
use crate::itu::basic_ops::{add, extract_h, l_mac, l_mult, l_shl, round_word, sub};

/// The speech buffer: the 30 ms analysis window, which is the frame being coded plus 20 ms of
/// history and 5 ms of lookahead.
const SPEECH_HISTORY: usize = WINDOW;
/// Where the frame being coded starts in that buffer. The 40 samples after it are the lookahead the
/// analysis window needs, so the newest input sits at the very end.
const CURRENT_FRAME: usize = SPEECH_HISTORY - FRAME_SAMPLES - 40;
/// Where new input is written: the last frame's worth of the buffer.
const NEW_SPEECH: usize = SPEECH_HISTORY - FRAME_SAMPLES;

/// Weighted-speech buffer: one frame, preceded by enough history for the open-loop pitch search.
const WEIGHTED_HISTORY: usize = PITCH_MAX as usize;

/// The line spectral pairs a reset encoder starts from — evenly spread across the spectrum, so the
/// first frame's interpolation has something neutral to interpolate against.
const INITIAL_LSP: [i16; ORDER] = [
    30_000, 26_000, 21_000, 15_000, 8000, 0, -8000, -15_000, -21_000, -26_000,
];

/// What one frame of input produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodedFrame {
    /// Ten octets of coded speech.
    Speech([u8; FRAME_BYTES]),
    /// Two octets describing the background (Annex B silence descriptor).
    Silence([u8; SILENCE_BYTES]),
    /// Nothing to send: the background has not changed since the last descriptor.
    Untransmitted,
}

/// One stream's encoder state.
#[derive(Debug, Clone)]
pub struct Encoder {
    preprocessor: PreProcessor,
    levinson: Levinson,
    lsp_quantiser: LspQuantiser,
    weighting: PerceptualWeighting,
    taming: Taming,
    codebook: CodebookSearch,
    gains: GainQuantiser,
    detector: VoiceActivityDetector,
    comfort: ComfortNoiseEncoder,
    comfort_random: Random,

    /// Whether discontinuous transmission is on. Off by default: RFC 3555 §4.1.13 makes Annex B the
    /// SDP *default*, but sending descriptors to a peer that answered `annexb=no` would put a
    /// two-octet payload on a leg expecting ten, so this is switched on by the negotiation rather
    /// than assumed.
    discontinuous: bool,
    /// Frames encoded so far. The voice-activity decision needs it to know how far its background
    /// estimate has settled; it wraps the way the reference's does rather than saturating, so a long
    /// call keeps the settled behaviour instead of freezing at the cap.
    frame: i16,
    /// The two previous frames' activity decisions, which the hangover consults.
    previous_activity: Activity,
    before_previous_activity: Activity,

    /// Input speech: history, the frame being coded, and the lookahead.
    speech: [i16; SPEECH_HISTORY],
    /// Perceptually weighted speech, for the open-loop pitch search only.
    weighted: [i16; WEIGHTED_HISTORY + FRAME_SAMPLES],
    /// Excitation history and the frame being built.
    excitation: [i16; EXCITATION_HISTORY + FRAME_SAMPLES],

    /// Memory of the weighting filter used to produce `weighted`.
    weighting_memory: [i16; ORDER],
    /// Memory of the weighting filter used to produce the subframe target.
    target_memory: [i16; ORDER],
    /// Memory of the local synthesis filter.
    synthesis_memory: [i16; ORDER],
    /// The error between input and local synthesis: `ORDER` of history followed by a subframe.
    error: [i16; ORDER + SUBFRAME_SAMPLES],

    /// Unquantised line spectral pairs of the previous frame.
    previous_lsp: [i16; ORDER],
    /// Quantised line spectral pairs of the previous frame, which the decoder also has.
    previous_quantised_lsp: [i16; ORDER],
    /// Pitch sharpening for the next subframe: the previous one's quantised pitch gain, clamped.
    sharpening: i16,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// An encoder in its reset state (`Init_Coder_ld8k`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            preprocessor: PreProcessor::new(),
            levinson: Levinson::new(),
            lsp_quantiser: LspQuantiser::new(),
            weighting: PerceptualWeighting::new(),
            taming: Taming::new(),
            codebook: CodebookSearch::new(),
            gains: GainQuantiser::new(),
            detector: VoiceActivityDetector::new(),
            comfort: ComfortNoiseEncoder::new(),
            comfort_random: Random::new(INITIAL_SEED),
            discontinuous: false,
            frame: 0,
            previous_activity: Activity::Speech,
            before_previous_activity: Activity::Speech,
            speech: [0; SPEECH_HISTORY],
            weighted: [0; WEIGHTED_HISTORY + FRAME_SAMPLES],
            excitation: [0; EXCITATION_HISTORY + FRAME_SAMPLES],
            weighting_memory: [0; ORDER],
            target_memory: [0; ORDER],
            synthesis_memory: [0; ORDER],
            error: [0; ORDER + SUBFRAME_SAMPLES],
            previous_lsp: INITIAL_LSP,
            previous_quantised_lsp: INITIAL_LSP,
            sharpening: SHARP_MIN,
        }
    }

    /// Encode one 10 ms frame of 8 kHz speech into ten octets (`Coder_ld8k`).
    ///
    /// The octets carry the frame that ended 40 samples ago, not the one just handed in: the
    /// analysis window reaches into the future, so the codec runs 5 ms behind its input.
    pub fn encode(&mut self, samples: &[i16; FRAME_SAMPLES]) -> [u8; FRAME_BYTES] {
        match self.encode_frame(samples) {
            EncodedFrame::Speech(octets) => octets,
            // Unreachable with discontinuous transmission off, which is the default and the only
            // state `encode` is used in.
            EncodedFrame::Silence(_) | EncodedFrame::Untransmitted => [0; FRAME_BYTES],
        }
    }

    /// Turn Annex B discontinuous transmission on or off.
    ///
    /// With it off every frame is coded as speech, which is what a peer that answered
    /// `a=fmtp:18 annexb=no` expects. With it on, a frame the voice-activity decision calls
    /// background becomes either a two-octet silence descriptor or nothing at all.
    pub fn set_discontinuous_transmission(&mut self, enabled: bool) {
        self.discontinuous = enabled;
    }

    /// Encode one 10 ms frame, which may produce speech, a silence descriptor, or nothing
    /// (`Coder_ld8k`).
    ///
    /// The octets carry the frame that ended 40 samples ago, not the one just handed in: the
    /// analysis window reaches into the future, so the codec runs 5 ms behind its input.
    pub fn encode_frame(&mut self, samples: &[i16; FRAME_SAMPLES]) -> EncodedFrame {
        self.speech[NEW_SPEECH..].copy_from_slice(samples);
        // The high-pass also halves the signal; the decoder's output stage doubles it back.
        self.preprocessor.process(&mut self.speech[NEW_SPEECH..]);

        // The reference's own counter: it wraps back to 256 rather than saturating, which keeps the
        // decision in its settled regime instead of pinning it at the initialisation boundary.
        self.frame = if self.frame == 32_767 {
            256
        } else {
            self.frame + 1
        };

        let frame = self.code_frame();

        // Slide every buffer down one frame for the next call.
        self.speech.copy_within(FRAME_SAMPLES.., 0);
        self.weighted.copy_within(FRAME_SAMPLES.., 0);
        self.excitation.copy_within(FRAME_SAMPLES.., 0);

        frame
    }

    /// The frame's analysis and its two subframes, in the reference's order.
    fn code_frame(&mut self) -> EncodedFrame {
        // Linear prediction over the whole 30 ms window, once per frame.
        let (mut correlations, energy_exponent) = autocorrelation(&self.speech);
        // The unwindowed correlations are what the comfort-noise path averages: the lag window is a
        // fit-conditioning step for the recursion, and a background estimate wants the spectrum as
        // measured.
        let unwindowed = correlations;
        lag_window(&mut correlations);
        let prediction = self.levinson.solve(&correlations);
        let second_filter = prediction.coefficients;
        let reflection = prediction.reflection;
        let lsp = lp_to_lsp(&second_filter, &self.previous_lsp);

        // The voice-activity decision runs on the frame's own analysis, before anything is coded.
        let new_lsf = lsp_to_normalised_lsf(&lsp);
        let activity = self.detector.decide(
            reflection[1],
            &new_lsf,
            &correlations,
            energy_exponent,
            &self.speech,
            self.frame,
            self.previous_activity,
            self.before_previous_activity,
        );
        self.comfort
            .observe(&unwindowed, energy_exponent, activity.is_speech());

        // The first subframe interpolates; the second uses the frame's own filter. The unquantised
        // pair drives the perceptual weighting, and the frame always needs it — a frame that is not
        // transmitted still has to update the filter memories the next one predicts from.
        let midpoint = midpoint_lsp(&self.previous_lsp, &lsp);
        let unquantised = [lsp_to_lp(&midpoint), second_filter];
        self.previous_lsp = lsp;

        let factors = self.weighting.factors(
            &lsp_to_normalised_lsf(&midpoint),
            &new_lsf,
            &[reflection[0], reflection[1]],
        );

        let open_loop = self.weighted_speech(&unquantised, &factors);

        if self.discontinuous && !activity.is_speech() {
            let frame = self.code_inactive(&unquantised, &factors);
            self.before_previous_activity = self.previous_activity;
            self.previous_activity = activity;
            return frame;
        }

        // Every speech frame re-seeds the comfort-noise generator, so both ends start the next
        // silence from the same point however long the talk spurt was.
        self.comfort_random.reseed(INITIAL_SEED);
        self.before_previous_activity = self.previous_activity;
        self.previous_activity = activity;

        // The quantised pair, which the synthesis both ends run is built from, is only needed once
        // the frame is known to be speech.
        let (lsp_stage1, lsp_stage2, quantised_lsp) = self.lsp_quantiser.quantise(&lsp);
        let quantised = interpolate_subframe_filters(&self.previous_quantised_lsp, &quantised_lsp);
        self.previous_quantised_lsp = quantised_lsp;

        let (mut lag_min, mut lag_max) = first_subframe_range(open_loop);

        let mut parameters = [0_u16; 11];
        parameters[0] = lsp_stage1;
        parameters[1] = lsp_stage2;
        let mut next = 2;

        for subframe in 0..2 {
            let first = subframe == 0;
            let start = subframe * SUBFRAME_SAMPLES;
            let (gamma1, gamma2) = factors[subframe];
            let weighted1 = weight_lp(&unquantised[subframe], gamma1);
            let weighted2 = weight_lp(&unquantised[subframe], gamma2);
            let synthesis = &quantised[subframe];

            let impulse = impulse_response(synthesis, &weighted1, &weighted2);
            let target = self.pitch_target(synthesis, &weighted1, &weighted2, start);

            // Closed-loop pitch, searched against the residual the caller just wrote into the
            // excitation buffer — the adaptive vector itself does not exist until the lag is known.
            let origin = EXCITATION_HISTORY + start;
            let (lag, fraction) = closed_loop_lag(
                &self.excitation,
                origin,
                &target,
                &impulse,
                lag_min,
                lag_max,
                first,
            );
            let lag_index = encode_lag(lag, fraction, &mut lag_min, &mut lag_max, first);
            parameters[next] = lag_index;
            next += 1;
            if first {
                parameters[next] = pitch_parity(lag_index);
                next += 1;
            }

            adaptive_codebook(
                &mut self.excitation,
                origin,
                PitchLag {
                    integer: lag,
                    fraction,
                },
                SUBFRAME_SAMPLES,
            );
            let mut adaptive_filtered = [0_i16; SUBFRAME_SAMPLES];
            convolve(
                &self.excitation[origin..],
                &impulse,
                &mut adaptive_filtered,
                SUBFRAME_SAMPLES,
            );

            let (mut pitch_gain_value, pitch_terms) = pitch_gain(&target, &adaptive_filtered);
            // Taming caps the pitch gain where the encoder's and decoder's excitation histories
            // could diverge, which is the only defence against an erased frame ringing forever.
            let tamed = self.taming.required(lag, fraction);
            if tamed && sub(pitch_gain_value, TAMED_PITCH_GAIN) > 0 {
                pitch_gain_value = TAMED_PITCH_GAIN;
            }

            // What the algebraic codebook has left to code: the target minus the adaptive part.
            let mut residual_target = [0_i16; SUBFRAME_SAMPLES];
            for i in 0..SUBFRAME_SAMPLES {
                let scaled = l_shl(l_mult(adaptive_filtered[i], pitch_gain_value), 1);
                residual_target[i] = sub(target[i], extract_h(scaled));
            }

            let mut sharpened = impulse;
            let codeword = self.codebook.search(
                &residual_target,
                &mut sharpened,
                lag,
                self.sharpening,
                first,
            );
            parameters[next] = codeword.positions;
            parameters[next + 1] = codeword.signs;
            next += 2;

            let (terms, exponents) = distortion_terms(
                &pitch_terms,
                &target,
                &adaptive_filtered,
                &codeword.filtered,
            );
            let quantised_gains = self
                .gains
                .quantise(&codeword.code, &terms, &exponents, tamed);
            parameters[next] = quantised_gains.index;
            next += 1;

            self.sharpening = clamp_sharpening(quantised_gains.pitch);

            // The total excitation, which is also what the decoder will build.
            for i in 0..SUBFRAME_SAMPLES {
                let mut total = l_mult(self.excitation[origin + i], quantised_gains.pitch);
                total = l_mac(total, codeword.code[i], quantised_gains.code);
                self.excitation[origin + i] = round_word(l_shl(total, 1));
            }
            self.taming.update(quantised_gains.pitch, lag);

            self.update_memories(
                synthesis,
                start,
                origin,
                &target,
                &adaptive_filtered,
                &codeword.filtered,
                quantised_gains.pitch,
                quantised_gains.code,
            );
        }

        EncodedFrame::Speech(pack(parameters))
    }

    /// One inactive frame: decide whether to describe the background, and carry every filter memory
    /// forward as if the frame had been coded (`Cod_cng` plus the memory update around it).
    ///
    /// The memories matter more than the frame does. The encoder has to stay on the same excitation
    /// history as the decoder across a silence, or the first frame of the next word is coded against
    /// a state the decoder does not have.
    fn code_inactive(
        &mut self,
        unquantised: &[[i16; COEFFICIENTS]; 2],
        factors: &[(i16, i16); 2],
    ) -> EncodedFrame {
        let after_speech = self.previous_activity.is_speech();
        let (frame, quantised) = {
            let Self {
                comfort,
                levinson,
                lsp_quantiser,
                previous_quantised_lsp,
                excitation,
                comfort_random,
                taming,
                ..
            } = self;
            comfort.encode(
                after_speech,
                levinson,
                lsp_quantiser.predictor_mut(),
                previous_quantised_lsp,
                excitation,
                EXCITATION_HISTORY,
                comfort_random,
                taming,
            )
        };

        for subframe in 0..2 {
            let start = subframe * SUBFRAME_SAMPLES;
            let origin = EXCITATION_HISTORY + start;
            let (gamma1, gamma2) = factors[subframe];
            let numerator = weight_lp(&unquantised[subframe], gamma1);
            let denominator = weight_lp(&unquantised[subframe], gamma2);

            let mut excitation = [0_i16; SUBFRAME_SAMPLES];
            excitation.copy_from_slice(&self.excitation[origin..origin + SUBFRAME_SAMPLES]);
            let mut synthesised = [0_i16; SUBFRAME_SAMPLES];
            let _ = syn_filt(
                &quantised[subframe],
                &excitation,
                &mut synthesised,
                SUBFRAME_SAMPLES,
                &mut self.synthesis_memory,
                true,
            );

            for (index, &sample) in synthesised.iter().enumerate() {
                self.error[ORDER + index] = sub(self.speech[CURRENT_FRAME + start + index], sample);
            }
            let mut weighted = [0_i16; SUBFRAME_SAMPLES];
            residu(
                &numerator,
                &self.error,
                ORDER,
                &mut weighted,
                SUBFRAME_SAMPLES,
            );
            let mut filtered = [0_i16; SUBFRAME_SAMPLES];
            let _ = syn_filt(
                &denominator,
                &weighted,
                &mut filtered,
                SUBFRAME_SAMPLES,
                &mut self.target_memory,
                true,
            );

            self.error.copy_within(SUBFRAME_SAMPLES.., 0);
        }

        // A silence resets the sharpening, so the first subframe of the next talk spurt does not
        // fold in a pitch gain measured on noise.
        self.sharpening = SHARP_MIN;

        match frame {
            InactiveFrame::Untransmitted => EncodedFrame::Untransmitted,
            InactiveFrame::Descriptor { spectrum, gain } => {
                EncodedFrame::Silence(pack_silence(SilenceParameters {
                    lsp_mode: spectrum.mode,
                    lsp_stage1: spectrum.stage1,
                    lsp_stage2: spectrum.stage2,
                    gain,
                }))
            }
        }
    }

    /// Filter the frame through `W(z)` and return the open-loop pitch lag it suggests.
    ///
    /// This is the only use of the weighted speech, and the estimate is only a centre for the
    /// closed-loop search, so it runs on the unquantised filters: it costs nothing to be slightly
    /// wrong here and the decoder never sees it.
    fn weighted_speech(
        &mut self,
        filters: &[[i16; COEFFICIENTS]; 2],
        factors: &[(i16, i16); 2],
    ) -> i16 {
        for subframe in 0..2 {
            let start = subframe * SUBFRAME_SAMPLES;
            let (gamma1, gamma2) = factors[subframe];
            let numerator = weight_lp(&filters[subframe], gamma1);
            let denominator = weight_lp(&filters[subframe], gamma2);

            let mut block = [0_i16; SUBFRAME_SAMPLES];
            residu(
                &numerator,
                &self.speech,
                CURRENT_FRAME + start,
                &mut block,
                SUBFRAME_SAMPLES,
            );
            let mut filtered = [0_i16; SUBFRAME_SAMPLES];
            let _ = syn_filt(
                &denominator,
                &block,
                &mut filtered,
                SUBFRAME_SAMPLES,
                &mut self.weighting_memory,
                true,
            );
            self.weighted[WEIGHTED_HISTORY + start..WEIGHTED_HISTORY + start + SUBFRAME_SAMPLES]
                .copy_from_slice(&filtered);
        }
        open_loop_lag(&self.weighted)
    }

    /// The target the pitch and codebook searches both match, and the LP residual they search
    /// against, which this writes into the excitation buffer.
    ///
    /// The reference builds the target by filtering the residual through `1/A(z)` and then `W(z)`
    /// rather than by subtracting the filters' zero-input response from the weighted speech. The two
    /// are algebraically the same; the reference notes that this arrangement behaves better in fixed
    /// point, and it is the one the vectors were generated with.
    fn pitch_target(
        &mut self,
        synthesis: &[i16; COEFFICIENTS],
        weighted1: &[i16; COEFFICIENTS],
        weighted2: &[i16; COEFFICIENTS],
        start: usize,
    ) -> [i16; SUBFRAME_SAMPLES] {
        let origin = EXCITATION_HISTORY + start;
        let mut lp_residual = [0_i16; SUBFRAME_SAMPLES];
        residu(
            synthesis,
            &self.speech,
            CURRENT_FRAME + start,
            &mut lp_residual,
            SUBFRAME_SAMPLES,
        );
        self.excitation[origin..origin + SUBFRAME_SAMPLES].copy_from_slice(&lp_residual);

        // The error signal, kept in place after its ORDER samples of history so the inverse filter
        // below can reach back into them.
        let mut filtered = [0_i16; SUBFRAME_SAMPLES];
        let (history, _) = self.error.split_at_mut(ORDER);
        let mut memory = [0_i16; ORDER];
        memory.copy_from_slice(history);
        let _ = syn_filt(
            synthesis,
            &lp_residual,
            &mut filtered,
            SUBFRAME_SAMPLES,
            &mut memory,
            false,
        );
        self.error[ORDER..].copy_from_slice(&filtered);

        let mut target = [0_i16; SUBFRAME_SAMPLES];
        residu(weighted1, &self.error, ORDER, &mut target, SUBFRAME_SAMPLES);
        let mut weighted = [0_i16; SUBFRAME_SAMPLES];
        let _ = syn_filt(
            weighted2,
            &target,
            &mut weighted,
            SUBFRAME_SAMPLES,
            &mut self.target_memory,
            false,
        );
        weighted
    }

    /// Synthesise the subframe locally and carry both filter memories into the next one.
    ///
    /// The synthesis memory is updated by the filter itself; the other two are updated by
    /// subtraction, which is the same answer as refiltering and is what the reference does — the
    /// signals it needs are all already computed.
    #[allow(clippy::too_many_arguments)]
    fn update_memories(
        &mut self,
        synthesis: &[i16; COEFFICIENTS],
        start: usize,
        origin: usize,
        target: &[i16; SUBFRAME_SAMPLES],
        adaptive_filtered: &[i16; SUBFRAME_SAMPLES],
        code_filtered: &[i16; SUBFRAME_SAMPLES],
        pitch_gain_value: i16,
        code_gain: i16,
    ) {
        let mut synthesised = [0_i16; SUBFRAME_SAMPLES];
        let mut excitation = [0_i16; SUBFRAME_SAMPLES];
        excitation.copy_from_slice(&self.excitation[origin..origin + SUBFRAME_SAMPLES]);
        let _ = syn_filt(
            synthesis,
            &excitation,
            &mut synthesised,
            SUBFRAME_SAMPLES,
            &mut self.synthesis_memory,
            true,
        );

        for (slot, i) in (SUBFRAME_SAMPLES - ORDER..SUBFRAME_SAMPLES).enumerate() {
            self.error[slot] = sub(self.speech[CURRENT_FRAME + start + i], synthesised[i]);
            let adaptive = extract_h(l_shl(l_mult(adaptive_filtered[i], pitch_gain_value), 1));
            let code = extract_h(l_shl(l_mult(code_filtered[i], code_gain), 2));
            self.target_memory[slot] = sub(target[i], add(adaptive, code));
        }
    }
}

/// The impulse response of the weighted synthesis filter `A(z/γ1) / (Â(z)·A(z/γ2))`, truncated to a
/// subframe.
///
/// Every search downstream works against this rather than against the filters themselves: with it,
/// "what would this excitation sound like" is a convolution.
fn impulse_response(
    synthesis: &[i16; COEFFICIENTS],
    weighted1: &[i16; COEFFICIENTS],
    weighted2: &[i16; COEFFICIENTS],
) -> [i16; SUBFRAME_SAMPLES] {
    // The numerator's coefficients, zero-padded to a subframe: driving 1/Â(z) with them gives the
    // response of the ratio.
    let mut driver = [0_i16; SUBFRAME_SAMPLES];
    driver[..COEFFICIENTS].copy_from_slice(weighted1);

    let mut response = [0_i16; SUBFRAME_SAMPLES];
    let mut memory = [0_i16; ORDER];
    let _ = syn_filt(
        synthesis,
        &driver,
        &mut response,
        SUBFRAME_SAMPLES,
        &mut memory,
        false,
    );

    let mut shaped = [0_i16; SUBFRAME_SAMPLES];
    let mut memory = [0_i16; ORDER];
    let _ = syn_filt(
        weighted2,
        &response,
        &mut shaped,
        SUBFRAME_SAMPLES,
        &mut memory,
        false,
    );
    shaped
}
