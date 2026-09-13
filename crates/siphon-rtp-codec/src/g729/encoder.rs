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
use super::bitstream::{pack, pitch_parity, FRAME_BYTES, FRAME_SAMPLES, SUBFRAME_SAMPLES};
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
        self.speech[NEW_SPEECH..].copy_from_slice(samples);
        // The high-pass also halves the signal; the decoder's output stage doubles it back.
        self.preprocessor.process(&mut self.speech[NEW_SPEECH..]);

        let parameters = self.code_frame();

        // Slide every buffer down one frame for the next call.
        self.speech.copy_within(FRAME_SAMPLES.., 0);
        self.weighted.copy_within(FRAME_SAMPLES.., 0);
        self.excitation.copy_within(FRAME_SAMPLES.., 0);

        pack(parameters)
    }

    /// The frame's analysis and its two subframes, in the reference's order.
    fn code_frame(&mut self) -> [u16; 11] {
        // Linear prediction over the whole 30 ms window, once per frame.
        let mut correlations = autocorrelation(&self.speech);
        lag_window(&mut correlations);
        let (second_filter, reflection) = self.levinson.solve(&correlations);
        let lsp = lp_to_lsp(&second_filter, &self.previous_lsp);

        let (lsp_stage1, lsp_stage2, quantised_lsp) = self.lsp_quantiser.quantise(&lsp);

        // The first subframe interpolates; the second uses the frame's own filter. The unquantised
        // pair drives the perceptual weighting, the quantised pair the synthesis both ends run.
        let midpoint = midpoint_lsp(&self.previous_lsp, &lsp);
        let unquantised = [lsp_to_lp(&midpoint), second_filter];
        let quantised = interpolate_subframe_filters(&self.previous_quantised_lsp, &quantised_lsp);

        self.previous_lsp = lsp;
        self.previous_quantised_lsp = quantised_lsp;

        let factors = self.weighting.factors(
            &lsp_to_normalised_lsf(&midpoint),
            &lsp_to_normalised_lsf(&lsp),
            &[reflection[0], reflection[1]],
        );

        let open_loop = self.weighted_speech(&unquantised, &factors);
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

        parameters
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
