//! Fan-out: one decoded PCM stream feeding many [`MediaSink`]s.
//!
//! The tap sits post-decode (pre per-direction processing), so a single decode drives every
//! consumer: a WAV/object-storage recorder, a WS bridge, an RTP fork leg, a mixer bus. This is
//! the media side of call recording and SIPREC forking — add a sink, not a new code path.

/// A consumer of decoded PCM frames.
pub trait MediaSink: Send {
    /// Receive one decoded PCM frame (native rate, mono unless the sink negotiated otherwise).
    fn write_pcm(&mut self, pcm: &[i16]);

    /// Flush/finalize the sink at end of stream (close a file, send a final WS frame, …).
    fn finish(&mut self) {}
}

/// Distributes each PCM frame to every attached sink.
#[derive(Default)]
pub struct FanOut {
    sinks: Vec<Box<dyn MediaSink>>,
}

impl FanOut {
    /// An empty fan-out.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a sink.
    pub fn add(&mut self, sink: Box<dyn MediaSink>) {
        self.sinks.push(sink);
    }

    /// Number of attached sinks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// Whether no sinks are attached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Write one PCM frame to every sink.
    pub fn write_pcm(&mut self, pcm: &[i16]) {
        for sink in &mut self.sinks {
            sink.write_pcm(pcm);
        }
    }

    /// Finalize every sink.
    pub fn finish(&mut self) {
        for sink in &mut self.sinks {
            sink.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A sink that records what it received, for assertions.
    #[derive(Clone, Default)]
    struct CapturingSink {
        frames: Arc<Mutex<Vec<Vec<i16>>>>,
        finished: Arc<Mutex<bool>>,
    }

    impl MediaSink for CapturingSink {
        fn write_pcm(&mut self, pcm: &[i16]) {
            self.frames.lock().expect("lock").push(pcm.to_vec());
        }
        fn finish(&mut self) {
            *self.finished.lock().expect("lock") = true;
        }
    }

    #[test]
    fn distributes_frames_to_every_sink() {
        let first = CapturingSink::default();
        let second = CapturingSink::default();
        let mut fanout = FanOut::new();
        fanout.add(Box::new(first.clone()));
        fanout.add(Box::new(second.clone()));
        assert_eq!(fanout.len(), 2);

        fanout.write_pcm(&[1, 2, 3]);
        fanout.write_pcm(&[4, 5, 6]);
        fanout.finish();

        for sink in [&first, &second] {
            let frames = sink.frames.lock().expect("lock");
            assert_eq!(*frames, vec![vec![1, 2, 3], vec![4, 5, 6]]);
            assert!(*sink.finished.lock().expect("lock"));
        }
    }

    #[test]
    fn empty_fanout_is_a_noop() {
        let mut fanout = FanOut::new();
        assert!(fanout.is_empty());
        fanout.write_pcm(&[1, 2, 3]); // must not panic with no sinks
        fanout.finish();
    }
}
