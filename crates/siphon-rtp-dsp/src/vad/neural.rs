//! A neural voice-activity detector: a hand-written forward pass of the Silero VAD v5 network.
//!
//! The energy detector next door is a *gate* — it answers "is something loud here". This is a
//! *speech classifier*: it answers "is what is here speech", which is what turn-taking and
//! barge-in actually need. Breathing, mains hum, fan noise and line noise all clear an energy
//! threshold; none of them get past this.
//!
//! ## Why the network is written out by hand
//!
//! The published model is a fixed graph of ~309 K parameters over four operator kinds — strided
//! 1-D convolution, ReLU, one LSTM cell, and a sigmoid ([`super::kernel`]). Running it through a
//! C++ inference runtime would cost the single-static-binary property this project is built on,
//! and a general optimising graph engine is a large dependency surface for a graph this small. So
//! the forward pass is written out directly against [`siphon_rtp_simd`], the same SIMD primitives
//! the polyphase resampler uses, and the parameters are embedded ([`super::weights`]).
//!
//! ## Framing, and the latency floor it sets
//!
//! The network consumes exactly **512 samples at 16 kHz (32 ms)** plus 64 samples of left context
//! carried from the previous window, and its LSTM state carries across windows. That framing is
//! what it was trained on, so it is not negotiable: re-windowing the input to the engine's 20 ms
//! media tick would change the quality being promised. [`NeuralVadStream`] therefore runs the
//! network on **its own cadence, fed from the frame clock** — it accumulates whatever the leg's
//! ptime delivers and fires the network on each completed 512-sample window.
//!
//! The floor this sets on turn detection is **32 ms** (the window must fill) **plus the
//! accumulation remainder** (up to one media frame, since a window boundary rarely lands on a
//! frame boundary), before any minimum-speech-run gate is applied on top. At the usual 20 ms
//! ptime, a decision lands 32–52 ms after the audio it describes.
//!
//! ## Sample rate
//!
//! Only the 16 kHz parameter set is embedded. A leg at any other rate is **resampled into the
//! detector** by [`NeuralVadStream`] using the crate's own polyphase [`crate::Resampler`] — the
//! alternative, refusing the configuration, would make the neural detector unavailable on exactly
//! the narrowband G.711 legs that dominate telephony. The upstream graph does carry a separate
//! native 8 kHz branch (256-sample window, 128-point transform); embedding it as well is a
//! possible future refinement, not a correctness gap.

use crate::resample::Resampler;

use super::kernel::{
    conv1d_filter_bank, conv1d_k3_pad1, encoder_output_length, relu_in_place, sigmoid,
};
use super::weights::{
    weights, NeuralWeights, ENCODER_STAGES, HIDDEN_SIZE, SPECTRUM_BINS, STFT_FILTERS, STFT_HOP,
    STFT_KERNEL,
};
use super::VadError;

/// The only sample rate the embedded parameter set covers.
pub const NEURAL_VAD_SAMPLE_RATE_HZ: u32 = 16_000;

/// Samples the network consumes per inference: 512 at 16 kHz, i.e. 32 ms.
pub const NEURAL_VAD_WINDOW_SAMPLES: usize = 512;

/// Trained parameters embedded in the binary (~1.2 MB of `f32`).
pub const NEURAL_VAD_PARAMETER_COUNT: usize = super::weights::PARAMETER_COUNT;

/// Samples of the previous window prepended as left context.
pub const NEURAL_VAD_CONTEXT_SAMPLES: usize = 64;

/// Window duration in milliseconds — the floor on turn-detection latency before accumulation.
pub const NEURAL_VAD_WINDOW_MS: u32 =
    (NEURAL_VAD_WINDOW_SAMPLES as u32 * 1000) / NEURAL_VAD_SAMPLE_RATE_HZ;

/// Default probability at or above which a window starts speech (the upstream default).
pub const NEURAL_VAD_SPEECH_THRESHOLD: f32 = 0.5;

/// Default probability below which speech ends. Lower than the start threshold on purpose: the
/// hysteresis band stops a talker being chopped up by a single hesitant window.
pub const NEURAL_VAD_SILENCE_THRESHOLD: f32 = 0.35;

/// Reflection padding applied to the right of the model input before the transform.
const REFLECT_PAD: usize = NEURAL_VAD_CONTEXT_SAMPLES;
/// Model input length: left context plus the window.
const MODEL_INPUT_SAMPLES: usize = NEURAL_VAD_CONTEXT_SAMPLES + NEURAL_VAD_WINDOW_SAMPLES;
/// Padded length the transform sees.
const PADDED_SAMPLES: usize = MODEL_INPUT_SAMPLES + REFLECT_PAD;
/// Transform frames per window: `(640 - 256) / 128 + 1`.
const STFT_FRAMES: usize = (PADDED_SAMPLES - STFT_KERNEL) / STFT_HOP + 1;
/// `i16` full scale, the divisor that puts the input in the [-1, 1) range the model was trained on.
const FULL_SCALE: f32 = 32_768.0;

/// The network itself: one 512-sample window in, one speech probability out.
///
/// Stateful across calls — the LSTM cell and the 64-sample left context both carry — so a single
/// instance belongs to a single audio stream, and [`NeuralVad::reset`] is what a discontinuity
/// calls. All scratch is allocated once in [`NeuralVad::new`]; a window costs no heap.
#[derive(Debug)]
pub struct NeuralVad {
    /// Process-wide parameters (see [`super::weights::weights`]).
    parameters: &'static NeuralWeights,
    /// Tail of the previous window, in model scale.
    context: [f32; NEURAL_VAD_CONTEXT_SAMPLES],
    /// LSTM hidden state.
    hidden: [f32; HIDDEN_SIZE],
    /// LSTM cell state.
    cell: [f32; HIDDEN_SIZE],
    /// `[640]` — context, window and the reflected tail, in model scale.
    padded: Vec<f32>,
    /// `[STFT_FRAMES][258]` time-major — the raw transform output.
    transform: Vec<f32>,
    /// `[STFT_FRAMES][129]` time-major — magnitudes, the first encoder stage's input.
    magnitude: Vec<f32>,
    /// Encoder ping-pong buffers, each sized for the largest intermediate activation.
    activation_front: Vec<f32>,
    /// See [`NeuralVad::activation_front`].
    activation_back: Vec<f32>,
    /// `[4 * 128]` LSTM gate pre-activations.
    gates: Vec<f32>,
    /// `[128]` — `relu(hidden)`, the output convolution's input. Separate from `hidden`, which is
    /// carried state and must not be rectified in place.
    rectified: Vec<f32>,
}

impl NeuralVad {
    /// A detector with zeroed state, ready for the first window of a stream.
    ///
    /// The first call decodes the embedded parameters for the whole process; later calls only
    /// allocate this instance's ~12 KB of scratch.
    #[must_use]
    pub fn new() -> Self {
        let largest_activation = ENCODER_STAGES
            .iter()
            .map(|&(_, out_channels, _)| out_channels * STFT_FRAMES)
            .max()
            .unwrap_or(STFT_FRAMES * HIDDEN_SIZE);
        Self {
            parameters: weights(),
            context: [0.0; NEURAL_VAD_CONTEXT_SAMPLES],
            hidden: [0.0; HIDDEN_SIZE],
            cell: [0.0; HIDDEN_SIZE],
            padded: vec![0.0; PADDED_SAMPLES],
            transform: vec![0.0; STFT_FRAMES * STFT_FILTERS],
            magnitude: vec![0.0; STFT_FRAMES * SPECTRUM_BINS],
            activation_front: vec![0.0; largest_activation],
            activation_back: vec![0.0; largest_activation],
            gates: vec![0.0; 4 * HIDDEN_SIZE],
            rectified: vec![0.0; HIDDEN_SIZE],
        }
    }

    /// Clear the LSTM state and the left context — a stream discontinuity, a re-INVITE, a new call.
    pub fn reset(&mut self) {
        self.context = [0.0; NEURAL_VAD_CONTEXT_SAMPLES];
        self.hidden = [0.0; HIDDEN_SIZE];
        self.cell = [0.0; HIDDEN_SIZE];
    }

    /// Run the network over one window and return the speech probability in `[0, 1]`.
    ///
    /// `window` must be exactly [`NEURAL_VAD_WINDOW_SAMPLES`] samples of 16 kHz mono PCM.
    ///
    /// # Errors
    /// [`VadError::WindowLength`] if the slice is not exactly one window.
    pub fn speech_probability(&mut self, window: &[i16]) -> Result<f32, VadError> {
        if window.len() != NEURAL_VAD_WINDOW_SAMPLES {
            return Err(VadError::WindowLength {
                expected: NEURAL_VAD_WINDOW_SAMPLES,
                got: window.len(),
            });
        }

        // [ left context | window | reflect(window tail) ]
        self.padded[..NEURAL_VAD_CONTEXT_SAMPLES].copy_from_slice(&self.context);
        for (slot, &sample) in self.padded[NEURAL_VAD_CONTEXT_SAMPLES..MODEL_INPUT_SAMPLES]
            .iter_mut()
            .zip(window.iter())
        {
            *slot = f32::from(sample) / FULL_SCALE;
        }
        // Reflect padding excludes the edge sample itself: out[n + j] = in[n - 2 - j].
        for offset in 0..REFLECT_PAD {
            self.padded[MODEL_INPUT_SAMPLES + offset] =
                self.padded[MODEL_INPUT_SAMPLES - 2 - offset];
        }

        // The STFT is a convolution against a fixed Fourier basis: rows 0..129 are the real part,
        // rows 129..258 the imaginary part, and the encoder consumes their magnitude.
        let frames = conv1d_filter_bank(
            &self.padded,
            &self.parameters.stft_basis,
            STFT_FILTERS,
            STFT_KERNEL,
            STFT_HOP,
            &mut self.transform,
        );
        debug_assert_eq!(frames, STFT_FRAMES);
        for frame in 0..frames {
            let row = &self.transform[frame * STFT_FILTERS..(frame + 1) * STFT_FILTERS];
            let out = &mut self.magnitude[frame * SPECTRUM_BINS..(frame + 1) * SPECTRUM_BINS];
            for (bin, slot) in out.iter_mut().enumerate() {
                let real = row[bin];
                let imaginary = row[SPECTRUM_BINS + bin];
                *slot = real.mul_add(real, imaginary * imaginary).sqrt();
            }
        }

        // Four convolution + ReLU stages, ping-ponging between the two activation buffers:
        // `destination` is the free buffer, `previous` holds the stage output just written.
        let parameters = self.parameters;
        let mut destination: &mut [f32] = &mut self.activation_front;
        let mut previous: &mut [f32] = &mut self.activation_back;
        let mut source_length = frames;
        let mut input_is_magnitude = true;
        for stage in &parameters.encoder {
            let out_length = encoder_output_length(source_length, stage.stride);
            let out_channels = stage.bias.len();
            let input: &[f32] = if input_is_magnitude {
                &self.magnitude[..source_length * stage.in_channels]
            } else {
                &previous[..source_length * stage.in_channels]
            };
            conv1d_k3_pad1(
                input,
                source_length,
                stage.in_channels,
                &stage.weight,
                &stage.bias,
                stage.stride,
                destination,
            );
            relu_in_place(&mut destination[..out_length * out_channels]);
            std::mem::swap(&mut destination, &mut previous);
            source_length = out_length;
            input_is_magnitude = false;
        }

        // The encoder collapses the time axis to a single 128-channel feature vector, sitting in
        // whichever buffer the last stage wrote (`previous` after the final swap).
        debug_assert_eq!(source_length, 1);
        // `lstm_cell_step` borrows the feature immutably while mutating the state, so stage it.
        self.rectified.copy_from_slice(&previous[..HIDDEN_SIZE]);
        super::kernel::lstm_cell_step(
            &self.rectified,
            &self.parameters.lstm_weight_ih,
            &self.parameters.lstm_weight_hh,
            &self.parameters.lstm_bias_ih,
            &self.parameters.lstm_bias_hh,
            &mut self.gates,
            &mut self.hidden,
            &mut self.cell,
        );

        // ReLU, then the k = 1 output convolution, then the sigmoid.
        self.rectified.copy_from_slice(&self.hidden);
        relu_in_place(&mut self.rectified);
        let logit = self.parameters.output_bias
            + siphon_rtp_simd::fir_dot_f32(&self.parameters.output_weight, &self.rectified);

        // Carry the window's tail as the next window's left context.
        self.context.copy_from_slice(
            &self.padded[MODEL_INPUT_SAMPLES - NEURAL_VAD_CONTEXT_SAMPLES..MODEL_INPUT_SAMPLES],
        );

        Ok(sigmoid(logit))
    }
}

impl Default for NeuralVad {
    fn default() -> Self {
        Self::new()
    }
}

/// Adapts the engine's media frame clock to the network's 512-sample window.
///
/// Callers push whole media frames at the leg's own rate and ptime; the stream resamples to 16 kHz
/// when it has to, accumulates, runs the network on each completed window, and applies the
/// start/stop hysteresis. Between windows it **holds** the last decision, so a per-frame caller
/// always gets an answer.
#[derive(Debug)]
pub struct NeuralVadStream {
    detector: NeuralVad,
    /// `Some` when the leg is not already at 16 kHz.
    resampler: Option<Resampler>,
    /// Scratch for the resampler's output; reused, never reallocated after warm-up.
    resampled: Vec<i16>,
    /// The window being filled.
    window: [i16; NEURAL_VAD_WINDOW_SAMPLES],
    /// Samples already in `window`.
    filled: usize,
    /// Probability of the most recent completed window.
    probability: f32,
    /// Held decision, subject to the hysteresis band.
    speaking: bool,
    speech_threshold: f32,
    silence_threshold: f32,
}

impl NeuralVadStream {
    /// A stream detector for a leg at `input_rate_hz`, using the default hysteresis band.
    ///
    /// # Errors
    /// [`VadError::ZeroRate`] if the rate is zero; [`VadError::Resample`] if a resampler to
    /// 16 kHz cannot be built for it.
    pub fn new(input_rate_hz: u32) -> Result<Self, VadError> {
        Self::with_thresholds(
            input_rate_hz,
            NEURAL_VAD_SPEECH_THRESHOLD,
            NEURAL_VAD_SILENCE_THRESHOLD,
        )
    }

    /// A stream detector with an explicit hysteresis band.
    ///
    /// `speech_threshold` is the probability at or above which speech starts; `silence_threshold`
    /// the probability below which it stops. The silence threshold is clamped to at most the
    /// speech threshold, so a caller cannot accidentally configure an inverted band.
    ///
    /// # Errors
    /// [`VadError::ZeroRate`] if the rate is zero; [`VadError::Resample`] if a resampler to
    /// 16 kHz cannot be built for it.
    pub fn with_thresholds(
        input_rate_hz: u32,
        speech_threshold: f32,
        silence_threshold: f32,
    ) -> Result<Self, VadError> {
        if input_rate_hz == 0 {
            return Err(VadError::ZeroRate);
        }
        let resampler = if input_rate_hz == NEURAL_VAD_SAMPLE_RATE_HZ {
            None
        } else {
            Some(Resampler::new(input_rate_hz, NEURAL_VAD_SAMPLE_RATE_HZ)?)
        };
        Ok(Self {
            detector: NeuralVad::new(),
            resampler,
            // One 120 ms frame at 16 kHz is the longest a leg can hand us (the bridge's ptime
            // ceiling); reserve that up front so the hot path never grows the vector.
            resampled: Vec::with_capacity(NEURAL_VAD_SAMPLE_RATE_HZ as usize / 1000 * 120),
            window: [0; NEURAL_VAD_WINDOW_SAMPLES],
            filled: 0,
            probability: 0.0,
            speaking: false,
            speech_threshold,
            silence_threshold: silence_threshold.min(speech_threshold),
        })
    }

    /// The leg sample rate this stream was built for.
    #[must_use]
    pub fn input_rate_hz(&self) -> u32 {
        self.resampler
            .as_ref()
            .map_or(NEURAL_VAD_SAMPLE_RATE_HZ, Resampler::input_rate)
    }

    /// Probability of the most recently completed window (0.0 before the first one).
    #[must_use]
    pub fn probability(&self) -> f32 {
        self.probability
    }

    /// Feed one media frame at the leg's rate; returns the held speech decision.
    ///
    /// A frame that does not complete a window leaves the decision where it was — the network runs
    /// on its own 32 ms cadence, not the caller's.
    pub fn is_speech(&mut self, frame: &[i16]) -> bool {
        if self.resampler.is_some() {
            self.resampled.clear();
            if let Some(resampler) = self.resampler.as_mut() {
                resampler.process(frame, &mut self.resampled);
            }
            // Borrow-splitting: the resampled scratch and the window live on the same struct.
            let mut offset = 0;
            while offset < self.resampled.len() {
                let take =
                    (NEURAL_VAD_WINDOW_SAMPLES - self.filled).min(self.resampled.len() - offset);
                self.window[self.filled..self.filled + take]
                    .copy_from_slice(&self.resampled[offset..offset + take]);
                self.filled += take;
                offset += take;
                self.run_if_window_complete();
            }
        } else {
            let mut offset = 0;
            while offset < frame.len() {
                let take = (NEURAL_VAD_WINDOW_SAMPLES - self.filled).min(frame.len() - offset);
                self.window[self.filled..self.filled + take]
                    .copy_from_slice(&frame[offset..offset + take]);
                self.filled += take;
                offset += take;
                self.run_if_window_complete();
            }
        }
        self.speaking
    }

    /// Drop the accumulator, the LSTM state and the held decision.
    pub fn reset(&mut self) {
        self.detector.reset();
        if let Some(resampler) = self.resampler.as_mut() {
            resampler.reset();
        }
        self.filled = 0;
        self.probability = 0.0;
        self.speaking = false;
    }

    fn run_if_window_complete(&mut self) {
        if self.filled < NEURAL_VAD_WINDOW_SAMPLES {
            return;
        }
        self.filled = 0;
        match self.detector.speech_probability(&self.window) {
            Ok(probability) => {
                self.probability = probability;
                if self.speaking {
                    if probability < self.silence_threshold {
                        self.speaking = false;
                    }
                } else if probability >= self.speech_threshold {
                    self.speaking = true;
                }
            }
            Err(error) => {
                // Unreachable: the window is a fixed-size array of exactly the right length. Log
                // rather than swallow, and leave the held decision alone.
                debug_assert!(false, "neural VAD window length invariant broken: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_constants_match_the_published_framing() {
        assert_eq!(NEURAL_VAD_WINDOW_SAMPLES, 512);
        assert_eq!(NEURAL_VAD_CONTEXT_SAMPLES, 64);
        assert_eq!(MODEL_INPUT_SAMPLES, 576);
        assert_eq!(PADDED_SAMPLES, 640);
        assert_eq!(STFT_FRAMES, 4);
        assert_eq!(NEURAL_VAD_WINDOW_MS, 32);
    }

    #[test]
    fn a_wrong_length_window_is_rejected() {
        let mut detector = NeuralVad::new();
        let error = detector.speech_probability(&[0i16; 256]).unwrap_err();
        assert_eq!(
            error,
            VadError::WindowLength {
                expected: 512,
                got: 256
            }
        );
        assert!(detector.speech_probability(&[]).is_err());
    }

    #[test]
    fn silence_yields_a_low_probability() {
        let mut detector = NeuralVad::new();
        for _ in 0..8 {
            let probability = detector.speech_probability(&[0i16; 512]).expect("window");
            assert!(
                (0.0..=1.0).contains(&probability),
                "probability out of range: {probability}"
            );
            assert!(
                probability < 0.1,
                "digital silence read as speech: {probability}"
            );
        }
    }

    #[test]
    fn a_pure_tone_is_not_speech() {
        // A loud 1 kHz sine clears any energy threshold; a speech classifier must still say no.
        let mut detector = NeuralVad::new();
        let mut worst = 0.0f32;
        for window in 0..16 {
            let frame: Vec<i16> = (0..512)
                .map(|index| {
                    let sample = window * 512 + index;
                    let phase = 2.0 * std::f32::consts::PI * 1000.0 * sample as f32 / 16_000.0;
                    (phase.sin() * 8000.0) as i16
                })
                .collect();
            worst = worst.max(detector.speech_probability(&frame).expect("window"));
        }
        assert!(
            worst < 0.5,
            "a steady tone was classified as speech: {worst}"
        );
    }

    #[test]
    fn reset_restores_the_initial_state() {
        // Same input, same output, once the carried state is cleared.
        let frame: Vec<i16> = (0..512)
            .map(|index| ((index as f32 * 0.31).sin() * 6000.0) as i16)
            .collect();
        let mut detector = NeuralVad::new();
        let first = detector.speech_probability(&frame).expect("window");
        for _ in 0..5 {
            detector.speech_probability(&frame).expect("window");
        }
        detector.reset();
        let again = detector.speech_probability(&frame).expect("window");
        assert_eq!(first.to_bits(), again.to_bits(), "reset must be exact");
    }

    #[test]
    fn stream_rejects_a_zero_sample_rate() {
        assert_eq!(NeuralVadStream::new(0).unwrap_err(), VadError::ZeroRate);
    }

    #[test]
    fn stream_at_the_native_rate_installs_no_resampler() {
        let stream = NeuralVadStream::new(16_000).expect("build");
        assert!(stream.resampler.is_none());
        assert_eq!(stream.input_rate_hz(), 16_000);
    }

    #[test]
    fn stream_at_eight_kilohertz_resamples_into_the_detector() {
        let stream = NeuralVadStream::new(8_000).expect("build");
        assert!(stream.resampler.is_some());
        assert_eq!(stream.input_rate_hz(), 8_000);
    }

    #[test]
    fn stream_holds_its_decision_between_windows() {
        // 20 ms frames at 16 kHz are 320 samples: a window completes every 1.6 frames, so most
        // frames must return the previous answer rather than a fresh one.
        let mut stream = NeuralVadStream::new(16_000).expect("build");
        let frame = [0i16; 320];
        for _ in 0..10 {
            assert!(!stream.is_speech(&frame));
        }
        assert!(stream.probability() < 0.1);
    }

    #[test]
    fn stream_accepts_any_frame_length() {
        // The bridge does not promise 20 ms or power-of-two frames; a leg may run 10 ms or 120 ms.
        for frame_samples in [80usize, 160, 320, 512, 960, 1920] {
            let mut stream = NeuralVadStream::new(16_000).expect("build");
            let frame = vec![0i16; frame_samples];
            for _ in 0..20 {
                stream.is_speech(&frame);
            }
            assert!(stream.filled < NEURAL_VAD_WINDOW_SAMPLES);
        }
    }

    #[test]
    fn stream_hysteresis_band_is_never_inverted() {
        let stream = NeuralVadStream::with_thresholds(16_000, 0.4, 0.9).expect("build");
        assert!(stream.silence_threshold <= stream.speech_threshold);
    }

    #[test]
    fn stream_reset_clears_the_partial_window_and_the_decision() {
        let mut stream = NeuralVadStream::new(16_000).expect("build");
        stream.is_speech(&[1000i16; 320]);
        assert_eq!(stream.filled, 320);
        stream.reset();
        assert_eq!(stream.filled, 0);
        assert!(!stream.speaking);
        assert_eq!(stream.probability(), 0.0);
    }
}
