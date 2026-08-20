//! Voice activity detection: a cheap energy gate and a neural speech classifier, on one interface.
//!
//! | detector | what it answers | cost per 20 ms frame | when to pick it |
//! |---|---|---|---|
//! | [`EnergyVad`] | "is something loud here" | ~30 ns | a gate: mute detection, cheap talk-spurt marking, anything where a false start is harmless |
//! | [`NeuralVad`] | "is what is here speech" | see `neural_vad_16k_window` in the crate bench | turn taking and barge-in, where a false start cuts off the prompt |
//!
//! The energy detector stays the default. It is exact, free, and correct for what it claims — but
//! it fires on breathing, mains hum, fan noise and acoustic echo, all of which clear an absolute
//! energy threshold, so as a *turn* detector it interrupts on things that are not a turn.
//!
//! Three pieces make the neural path usable from the engine's frame clock:
//!
//!   * [`NeuralVad`] — the forward pass, one 512-sample 16 kHz window at a time.
//!   * [`NeuralVadStream`] — the frame-clock adapter: resamples the leg to 16 kHz if it has to,
//!     accumulates into windows, runs the network on its own 32 ms cadence, applies the
//!     start/stop hysteresis, and holds the decision between windows.
//!   * [`SpeechRunGate`] — the leading minimum-speech-run gate, usable with **either** detector.
//!
//! [`VoiceDetector`] is the enum a caller stores when the choice is made at call setup.

mod energy;
mod gate;
mod kernel;
mod neural;
mod weights;

pub use energy::EnergyVad;
pub use gate::SpeechRunGate;
pub use neural::{
    NeuralVad, NeuralVadStream, NEURAL_VAD_CONTEXT_SAMPLES, NEURAL_VAD_PARAMETER_COUNT,
    NEURAL_VAD_SAMPLE_RATE_HZ, NEURAL_VAD_SILENCE_THRESHOLD, NEURAL_VAD_SPEECH_THRESHOLD,
    NEURAL_VAD_WINDOW_MS, NEURAL_VAD_WINDOW_SAMPLES,
};

use crate::resample::ResampleError;

/// Errors selecting or driving a voice-activity detector.
///
/// [`EnergyVad`] is infallible and reports nothing here; everything below concerns the neural
/// detector, whose input framing and sample rate are fixed by the network.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VadError {
    /// A sample rate of zero was offered for the neural detector.
    #[error("neural VAD input sample rate must be non-zero")]
    ZeroRate,
    /// The network was handed something other than one full window.
    #[error("neural VAD window must be exactly {expected} samples, got {got}")]
    WindowLength {
        /// Samples the network requires (512 at 16 kHz).
        expected: usize,
        /// Samples actually supplied.
        got: usize,
    },
    /// The leg's rate could not be converted to the network's 16 kHz input.
    #[error("neural VAD cannot resample the leg into its 16 kHz input: {0}")]
    Resample(#[from] ResampleError),
}

/// The detector a leg runs, chosen once at setup.
///
/// An enum rather than a trait object: the choice is per call, the per-frame path is hot, and a
/// `Box<dyn …>` would add a vtable hop and an allocation to something that has exactly two
/// implementations. The neural variant is boxed because its scratch dwarfs the energy one's three
/// integers, and the enum is stored inline in the bridge.
#[derive(Debug)]
pub enum VoiceDetector {
    /// The mean-square energy gate with hangover.
    Energy(EnergyVad),
    /// The neural speech classifier, with its frame-clock adapter.
    Neural(Box<NeuralVadStream>),
}

impl VoiceDetector {
    /// Build the energy detector.
    #[must_use]
    pub fn energy(threshold: i64, hangover_frames: u32) -> Self {
        Self::Energy(EnergyVad::new(threshold, hangover_frames))
    }

    /// Build the neural detector for a leg running at `input_rate_hz`.
    ///
    /// # Errors
    /// Whatever [`NeuralVadStream::new`] rejects — a zero rate, or a rate no resampler covers.
    pub fn neural(input_rate_hz: u32) -> Result<Self, VadError> {
        Ok(Self::Neural(Box::new(NeuralVadStream::new(input_rate_hz)?)))
    }

    /// Classify one media frame at the leg's own rate and ptime.
    pub fn is_speech(&mut self, frame: &[i16]) -> bool {
        match self {
            Self::Energy(vad) => vad.is_speech(frame),
            Self::Neural(stream) => stream.is_speech(frame),
        }
    }

    /// Drop all carried state (hangover, LSTM, accumulator) on a stream discontinuity.
    pub fn reset(&mut self) {
        match self {
            Self::Energy(vad) => vad.reset(),
            Self::Neural(stream) => stream.reset(),
        }
    }

    /// True when this is the neural detector — for logging and metrics, not for control flow.
    #[must_use]
    pub fn is_neural(&self) -> bool {
        matches!(self, Self::Neural(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn energy_variant_classifies_like_the_bare_detector() {
        let frame: Vec<i16> = (0..160)
            .map(|index| if index % 2 == 0 { 4000 } else { -4000 })
            .collect();
        let mut detector = VoiceDetector::energy(1_000_000, 3);
        let mut bare = EnergyVad::new(1_000_000, 3);
        for _ in 0..6 {
            assert_eq!(detector.is_speech(&frame), bare.is_speech(&frame));
            assert_eq!(
                detector.is_speech(&[0i16; 160]),
                bare.is_speech(&[0i16; 160])
            );
        }
        assert!(!detector.is_neural());
    }

    #[test]
    fn neural_variant_builds_for_both_telephony_rates() {
        for rate in [8_000u32, 16_000] {
            let mut detector = VoiceDetector::neural(rate).expect("build");
            assert!(detector.is_neural());
            let frame = vec![0i16; rate as usize / 50];
            for _ in 0..10 {
                assert!(!detector.is_speech(&frame), "silence is never speech");
            }
            detector.reset();
        }
    }

    #[test]
    fn neural_variant_rejects_a_zero_rate() {
        assert_eq!(VoiceDetector::neural(0).unwrap_err(), VadError::ZeroRate);
    }

    #[test]
    fn vad_error_messages_name_the_problem() {
        assert_eq!(
            VadError::ZeroRate.to_string(),
            "neural VAD input sample rate must be non-zero"
        );
        assert_eq!(
            VadError::WindowLength {
                expected: 512,
                got: 320
            }
            .to_string(),
            "neural VAD window must be exactly 512 samples, got 320"
        );
        assert_eq!(
            VadError::from(ResampleError::ZeroRate).to_string(),
            "neural VAD cannot resample the leg into its 16 kHz input: sample rate must be non-zero"
        );
    }
}
