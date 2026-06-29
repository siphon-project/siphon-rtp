//! A cheap energy-based voice-activity detector — the zero-dependency barge-in fallback.
//!
//! Per frame it compares mean-square energy to a threshold, with a **hangover** so brief dips
//! inside speech don't chop it off. This is the lightweight default; the Silero-via-ONNX VAD is the
//! quality option on the same per-frame interface. Deterministic (energy only, no clock), so it
//! golden-tests directly. It drives WS-bridge barge-in and the OpenAI `input_audio_buffer.commit`.

/// A frame-by-frame energy VAD with hangover.
#[derive(Debug, Clone)]
pub struct EnergyVad {
    /// Mean-square energy at/above which a frame is speech.
    threshold: i64,
    /// Frames to keep flagged as speech after energy drops below the threshold.
    hangover_frames: u32,
    /// Remaining hangover frames.
    hangover: u32,
}

impl EnergyVad {
    /// A VAD with the given mean-square `threshold` and `hangover_frames` (frames of trailing
    /// speech after energy falls). A reasonable 8 kHz/20 ms start is `threshold ≈ 1_000_000`,
    /// `hangover_frames ≈ 5` (~100 ms).
    #[must_use]
    pub fn new(threshold: i64, hangover_frames: u32) -> Self {
        Self {
            threshold,
            hangover_frames,
            hangover: 0,
        }
    }

    /// Mean-square energy of a frame (sum of squares / length).
    #[must_use]
    pub fn energy(frame: &[i16]) -> i64 {
        if frame.is_empty() {
            return 0;
        }
        // SIMD sum-of-squares (AVX2 + scalar fallback); exact i64, bit-identical to the scalar sum.
        siphon_rtp_simd::sum_sq_i16(frame) / frame.len() as i64
    }

    /// Classify one frame, returning whether it is (or is held as) speech.
    pub fn is_speech(&mut self, frame: &[i16]) -> bool {
        if Self::energy(frame) >= self.threshold {
            self.hangover = self.hangover_frames;
            true
        } else if self.hangover > 0 {
            self.hangover -= 1;
            true
        } else {
            false
        }
    }

    /// Reset the hangover state (e.g. on a stream discontinuity).
    pub fn reset(&mut self) {
        self.hangover = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(amplitude: i16, len: usize) -> Vec<i16> {
        (0..len)
            .map(|index| if index % 2 == 0 { amplitude } else { -amplitude })
            .collect()
    }

    #[test]
    fn silence_is_not_speech() {
        let mut vad = EnergyVad::new(1_000_000, 5);
        assert!(!vad.is_speech(&[0i16; 160]));
    }

    #[test]
    fn loud_frame_is_speech() {
        let mut vad = EnergyVad::new(1_000_000, 5);
        // amplitude 4000 → energy 16_000_000 ≫ threshold.
        assert!(vad.is_speech(&tone(4000, 160)));
    }

    #[test]
    fn hangover_holds_speech_through_brief_dips() {
        let mut vad = EnergyVad::new(1_000_000, 3);
        assert!(vad.is_speech(&tone(4000, 160))); // speech, arms hangover = 3
        // Three silent frames are still held as speech.
        assert!(vad.is_speech(&[0i16; 160]));
        assert!(vad.is_speech(&[0i16; 160]));
        assert!(vad.is_speech(&[0i16; 160]));
        // The fourth silent frame is finally non-speech.
        assert!(!vad.is_speech(&[0i16; 160]));
    }

    #[test]
    fn energy_is_mean_square() {
        // Constant amplitude 100 → energy 10_000.
        assert_eq!(EnergyVad::energy(&[100i16; 64]), 10_000);
        assert_eq!(EnergyVad::energy(&[]), 0);
    }

    #[test]
    fn reset_clears_hangover() {
        let mut vad = EnergyVad::new(1_000_000, 5);
        assert!(vad.is_speech(&tone(4000, 160)));
        vad.reset();
        assert!(!vad.is_speech(&[0i16; 160]), "hangover cleared by reset");
    }
}
