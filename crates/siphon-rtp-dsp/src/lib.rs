//! siphon-rtp-dsp — pure-Rust audio DSP for the media plane.
//!
//! [`resample`] (telephony ↔ voice-AI rate conversion) lands first; VAD, noise suppression, and
//! the AEC follow on the same NIC-free, synchronous, **deterministic** footing (driven by a logical
//! sample-clock, never `Instant::now()`), so every unit golden-tests without audio hardware.
#![forbid(unsafe_code)]

pub mod resample;

pub use resample::{ResampleError, Resampler};
