//! A **leading** minimum-speech-run gate for either detector's per-frame decision.
//!
//! Both detectors already have a *trailing* hold — the energy VAD's hangover, the neural one's
//! hysteresis band — so speech is not chopped up at its end. Neither has a *leading* requirement:
//! the speech-start edge fires on the very first frame that reads as speech, which is what makes
//! barge-in interrupt the prompt on a cough, a door, a keyboard, or one burst of echo.
//!
//! This is one counter. It holds the speech-start edge until the raw decision has been speech for
//! `required_frames` **consecutive** frames, and it drops back to silence as soon as the raw
//! decision does (the trailing hold belongs to the detector, not here — putting it in both places
//! would double it).
//!
//! Cost: the gate delays a genuine speech start by `required_frames - 1` frames. At the default of
//! one frame it is exactly a pass-through, which is why the existing energy path is byte-identical
//! with the gate installed.

/// Holds the speech-start edge until speech has run for a configured number of frames.
#[derive(Debug, Clone)]
pub struct SpeechRunGate {
    /// Consecutive raw-speech frames needed before the gate reports speech. Never zero.
    required_frames: u32,
    /// Consecutive raw-speech frames seen so far.
    run: u32,
    /// The gated decision.
    active: bool,
}

impl SpeechRunGate {
    /// A gate requiring `required_frames` consecutive speech frames. Zero is treated as one (no
    /// leading requirement), so the gate is always a well-defined pass-through at its minimum.
    #[must_use]
    pub fn new(required_frames: u32) -> Self {
        Self {
            required_frames: required_frames.max(1),
            run: 0,
            active: false,
        }
    }

    /// A gate expressed in milliseconds of continuous speech at a given frame duration.
    ///
    /// Rounds **up**, so a caller asking for 60 ms at a 25 ms ptime gets three frames (75 ms)
    /// rather than two (50 ms) — under-delivering on a debounce is the failure that matters.
    #[must_use]
    pub fn from_duration(minimum_speech_ms: u32, frame_duration_ms: u32) -> Self {
        let frame_duration_ms = frame_duration_ms.max(1);
        Self::new(minimum_speech_ms.div_ceil(frame_duration_ms))
    }

    /// Frames of continuous speech this gate requires.
    #[must_use]
    pub fn required_frames(&self) -> u32 {
        self.required_frames
    }

    /// True when the gate is a pass-through (no leading requirement).
    #[must_use]
    pub fn is_transparent(&self) -> bool {
        self.required_frames <= 1
    }

    /// Feed one raw per-frame decision; returns the gated decision.
    pub fn update(&mut self, speech: bool) -> bool {
        if speech {
            if self.run < self.required_frames {
                self.run += 1;
            }
            if self.run >= self.required_frames {
                self.active = true;
            }
        } else {
            self.run = 0;
            self.active = false;
        }
        self.active
    }

    /// Current gated decision without advancing the counter.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Drop the run counter and the gated state.
    pub fn reset(&mut self) {
        self.run = 0;
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_frame_gate_is_a_pass_through() {
        let mut gate = SpeechRunGate::new(1);
        assert!(gate.is_transparent());
        assert!(gate.update(true));
        assert!(!gate.update(false));
        assert!(gate.update(true));
    }

    #[test]
    fn zero_required_frames_is_clamped_to_a_pass_through() {
        let mut gate = SpeechRunGate::new(0);
        assert_eq!(gate.required_frames(), 1);
        assert!(gate.update(true));
    }

    #[test]
    fn an_isolated_speech_frame_produces_no_edge() {
        // The cough / door-slam / echo-burst case: one frame of speech in a sea of silence.
        let mut gate = SpeechRunGate::new(3);
        assert!(!gate.update(false));
        assert!(!gate.update(true), "one frame must not open the gate");
        assert!(!gate.update(false));
        assert!(!gate.update(false));
        assert!(!gate.is_active());
    }

    #[test]
    fn a_run_shorter_than_the_threshold_produces_no_edge() {
        let mut gate = SpeechRunGate::new(4);
        for _ in 0..3 {
            assert!(!gate.update(true));
        }
        assert!(!gate.update(false));
        assert!(!gate.is_active());
    }

    #[test]
    fn a_run_at_the_threshold_opens_the_gate_on_that_frame() {
        let mut gate = SpeechRunGate::new(3);
        assert!(!gate.update(true));
        assert!(!gate.update(true));
        assert!(
            gate.update(true),
            "the third consecutive frame opens the gate"
        );
        assert!(gate.update(true), "and it stays open");
    }

    #[test]
    fn a_broken_run_restarts_the_count() {
        let mut gate = SpeechRunGate::new(3);
        gate.update(true);
        gate.update(true);
        assert!(!gate.update(false), "the run is broken");
        assert!(!gate.update(true), "counting restarts from one");
        assert!(!gate.update(true));
        assert!(gate.update(true));
    }

    #[test]
    fn the_gate_closes_as_soon_as_the_raw_decision_does() {
        // The trailing hold lives in the detector (hangover / hysteresis); the gate must not add
        // a second one, or the two would compound.
        let mut gate = SpeechRunGate::new(2);
        gate.update(true);
        assert!(gate.update(true));
        assert!(!gate.update(false));
    }

    #[test]
    fn duration_conversion_rounds_up() {
        assert_eq!(SpeechRunGate::from_duration(0, 20).required_frames(), 1);
        assert_eq!(SpeechRunGate::from_duration(20, 20).required_frames(), 1);
        assert_eq!(SpeechRunGate::from_duration(21, 20).required_frames(), 2);
        assert_eq!(SpeechRunGate::from_duration(60, 20).required_frames(), 3);
        assert_eq!(SpeechRunGate::from_duration(60, 25).required_frames(), 3);
        // A zero frame duration must not divide by zero.
        assert_eq!(SpeechRunGate::from_duration(60, 0).required_frames(), 60);
    }

    #[test]
    fn reset_closes_the_gate_and_drops_the_run() {
        let mut gate = SpeechRunGate::new(2);
        gate.update(true);
        assert!(gate.update(true));
        gate.reset();
        assert!(!gate.is_active());
        assert!(!gate.update(true), "the run restarts after a reset");
    }
}
