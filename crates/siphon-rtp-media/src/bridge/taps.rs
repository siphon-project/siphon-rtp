//! Recording taps on a **takeover** bridge: copies of the call's decoded audio for a recording,
//! taken inside [`super::session::BridgeSession::tick`].
//!
//! A takeover call never reaches the media pipeline — the WS server is the caller's far side — so
//! the pipeline's post-decode fan-out, where every other decoded recording taps, has nothing to give
//! it. The bridge session decodes the caller's uplink and renders the bot's downlink in one task,
//! once per ptime, so that is where the two parties exist side by side as PCM, and where the taps
//! sit.
//!
//! Both sides are fed at the **leg's** decoded rate, mono — the same contract a pipeline fork
//! sink has ([`MediaSink::write_pcm`]), so a recording's sinks resample into the file's rate the
//! way they always do, and the same sink can move between the pipeline and a bridge unchanged.

use crate::fanout::MediaSink;

/// Recording sinks taken off a bridge to move them elsewhere: `(caller, heard)`.
pub type TakenRecordingTaps = (Vec<Box<dyn MediaSink>>, Vec<Box<dyn MediaSink>>);

/// Which party a takeover recording tap hears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapSide {
    /// What the caller said: the decoded uplink **before** any bot-facing processing (noise
    /// suppression, echo cancellation, turn-taking), so the record holds the caller, not the input
    /// the bot was given.
    Caller,
    /// What the caller heard: the bot's downlink as rendered toward the call, after barge-in has
    /// had its say — a frame flushed by an interruption was never played, so it is never recorded.
    Heard,
}

/// The recording sinks on one bridge session, keyed by each sink's [`MediaSink::tag`] (the
/// recording id), so two recordings on one call never share a slot and a stop removes exactly its
/// own.
#[derive(Default)]
pub struct RecordingTaps {
    caller: Vec<Box<dyn MediaSink>>,
    heard: Vec<Box<dyn MediaSink>>,
}

impl RecordingTaps {
    /// Attach `sink` to `side`.
    pub fn add(&mut self, side: TapSide, sink: Box<dyn MediaSink>) {
        match side {
            TapSide::Caller => self.caller.push(sink),
            TapSide::Heard => self.heard.push(sink),
        }
    }

    /// Detach and finish every sink tagged `tag`, leaving any other attached.
    pub fn remove_tagged(&mut self, tag: &str) {
        for sinks in [&mut self.caller, &mut self.heard] {
            for sink in sinks.iter_mut() {
                if sink.tag() == Some(tag) {
                    sink.finish();
                }
            }
            sinks.retain(|sink| sink.tag() != Some(tag));
        }
    }

    /// Detach every sink, **unfinished**, to move it onto another media path: `(caller, heard)`.
    /// A recording moved this way keeps its file open; one that is merely dropped ends.
    pub fn take_all(&mut self) -> TakenRecordingTaps {
        (
            std::mem::take(&mut self.caller),
            std::mem::take(&mut self.heard),
        )
    }

    /// Whether any sink is attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.caller.is_empty() && self.heard.is_empty()
    }

    /// Feed one decoded caller frame (leg rate, mono).
    pub(crate) fn write_caller(&mut self, pcm: &[i16]) {
        for sink in &mut self.caller {
            sink.write_pcm(pcm);
        }
    }

    /// Feed one rendered downlink frame (leg rate, mono).
    pub(crate) fn write_heard(&mut self, pcm: &[i16]) {
        for sink in &mut self.heard {
            sink.write_pcm(pcm);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that records what reached it and whether it was finished, under `tag`.
    struct Probe {
        tag: &'static str,
        written: std::sync::Arc<std::sync::Mutex<Vec<i16>>>,
        finished: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl MediaSink for Probe {
        fn write_pcm(&mut self, pcm: &[i16]) {
            if let Ok(mut written) = self.written.lock() {
                written.extend_from_slice(pcm);
            }
        }
        fn finish(&mut self) {
            self.finished
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        fn tag(&self) -> Option<&str> {
            Some(self.tag)
        }
    }

    type Written = std::sync::Arc<std::sync::Mutex<Vec<i16>>>;
    type Finished = std::sync::Arc<std::sync::atomic::AtomicBool>;

    fn probe(tag: &'static str) -> (Box<dyn MediaSink>, Written, Finished) {
        let written = Written::default();
        let finished = Finished::default();
        (
            Box::new(Probe {
                tag,
                written: written.clone(),
                finished: finished.clone(),
            }),
            written,
            finished,
        )
    }

    #[test]
    fn each_side_feeds_only_its_own_sinks() {
        let mut taps = RecordingTaps::default();
        let (caller, caller_written, _) = probe("rec-1");
        let (heard, heard_written, _) = probe("rec-1");
        taps.add(TapSide::Caller, caller);
        taps.add(TapSide::Heard, heard);
        taps.write_caller(&[1, 2]);
        taps.write_heard(&[7]);
        assert_eq!(*caller_written.lock().expect("lock"), vec![1, 2]);
        assert_eq!(*heard_written.lock().expect("lock"), vec![7]);
    }

    #[test]
    fn removing_one_recording_finishes_it_and_leaves_the_other_attached() {
        let mut taps = RecordingTaps::default();
        let (first, _, first_finished) = probe("rec-1");
        let (second, second_written, second_finished) = probe("rec-2");
        taps.add(TapSide::Caller, first);
        taps.add(TapSide::Caller, second);
        taps.remove_tagged("rec-1");
        assert!(first_finished.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!second_finished.load(std::sync::atomic::Ordering::SeqCst));
        taps.write_caller(&[3]);
        assert_eq!(*second_written.lock().expect("lock"), vec![3]);
        assert!(!taps.is_empty());
    }

    #[test]
    fn taking_every_sink_moves_them_unfinished() {
        let mut taps = RecordingTaps::default();
        let (caller, _, caller_finished) = probe("rec-1");
        let (heard, _, heard_finished) = probe("rec-1");
        taps.add(TapSide::Caller, caller);
        taps.add(TapSide::Heard, heard);
        let (callers, heards) = taps.take_all();
        assert_eq!((callers.len(), heards.len()), (1, 1));
        assert!(taps.is_empty());
        assert!(!caller_finished.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!heard_finished.load(std::sync::atomic::Ordering::SeqCst));
    }
}
