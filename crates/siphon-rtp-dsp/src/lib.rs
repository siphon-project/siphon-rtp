//! siphon-rtp-dsp — pure-Rust audio DSP for the media plane.
//!
//! [`resample`] (telephony ↔ voice-AI rate conversion) lands first; VAD, noise suppression, and
//! the AEC follow on the same NIC-free, synchronous, **deterministic** footing (driven by a logical
//! sample-clock, never `Instant::now()`), so every unit golden-tests without audio hardware.
//!
//! Voice activity detection ([`vad`]) ships two detectors on one interface: the cheap
//! [`EnergyVad`] gate and [`NeuralVad`], a hand-written pure-Rust forward pass of the Silero VAD
//! v5 network (~309 K embedded parameters, no inference runtime, no C).
//!
//! Noise suppression ([`ns`]) is built from a safe, self-contained radix-2 real [`fft`] and a
//! √Hann WOLA framing ([`window`]); the FFT twiddle/bit-reversal convention matches the in-tree
//! libopus KISS-FFT port (`siphon-rtp-codec` `opus/celt/mdct.rs`), validated transitively against a
//! direct DFT.
#![forbid(unsafe_code)]

pub mod aec;
pub mod fft;
pub mod ns;
pub mod res;
pub mod resample;
mod spectral;
pub mod vad;
pub mod window;

pub use aec::{AecError, EchoCanceller};
pub use fft::{Complex, RealFft};
pub use ns::NoiseSuppressor;
pub use res::ResidualEchoSuppressor;
pub use resample::{ResampleError, Resampler};
pub use vad::{
    EnergyVad, NeuralVad, NeuralVadStream, SpeechRunGate, VadError, VoiceDetector,
    NEURAL_VAD_SAMPLE_RATE_HZ, NEURAL_VAD_WINDOW_MS, NEURAL_VAD_WINDOW_SAMPLES,
};
pub use window::{WolaAnalyzer, WolaProcessor};

/// Errors constructing a DSP block (noise suppressor, WOLA framing, FFT).
///
/// The resampler keeps its own [`ResampleError`] for source compatibility; everything added for
/// noise suppression reports through this shared type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DspError {
    /// A sample rate the noise suppressor does not support (only 8000 and 16000 Hz).
    #[error("unsupported sample rate {rate} Hz (noise suppression supports 8000 and 16000)")]
    InvalidSampleRate {
        /// The rejected sample rate in Hz.
        rate: u32,
    },
    /// A pipeline frame length that is not a positive number of samples.
    #[error("invalid frame length {length} (must be non-zero)")]
    InvalidFrameLength {
        /// The rejected frame length in samples.
        length: usize,
    },
    /// An FFT size that is not a power of two of at least 4.
    #[error("invalid FFT size {size} (must be a power of two >= 4)")]
    InvalidFftSize {
        /// The rejected FFT size.
        size: usize,
    },
}
