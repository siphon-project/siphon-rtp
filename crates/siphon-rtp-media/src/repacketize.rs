//! A linear-PCM **repacketizer**: decouples the ingress packetization interval from the egress one.
//!
//! A transcoding leg decodes each ingress RTP payload to linear PCM at the egress codec's sample rate,
//! then must re-emit that audio at a *different* frame duration (the egress `ptime`). The engine's
//! ptime override (rtpengine's `ptime=<N>` flag) and any ingress/egress `a=ptime` mismatch both land
//! here: a 20 ms ingress stream may be re-emitted as 40 ms packets (2:1), 10 ms packets (1:2), or a
//! fractional ratio (30 ms → 20 ms) that buffers across packets.
//!
//! The repacketizer is a pure FIFO of PCM samples in the **egress sample domain** (after any
//! resample), with a fixed, preallocated accumulator — **zero per-frame heap allocation** on the hot
//! path once warmed. It carries no RTP metadata; the caller (such as the engine's transcode
//! `Direction`) owns the egress sequence number / timestamp / marker and advances them per drained
//! frame (RFC 3550 §5.1). The FIFO is sample-exact: samples are never lost, duplicated, or reordered
//! across the stream, so a fractional ratio stays byte-accounted over many packets.

/// A fixed-capacity linear-PCM FIFO that re-frames a stream from its ingress framing to a target
/// egress frame size. Sample-exact and allocation-free in steady state.
#[derive(Debug)]
pub struct Repacketizer {
    /// Buffered egress-domain PCM samples awaiting a full egress frame. Preallocated to hold one
    /// leftover partial frame plus one maximal push, so [`Repacketizer::push`] never reallocates.
    accumulator: Vec<i16>,
    /// Samples drained per egress frame — the egress codec's `frame_samples` (clock-rate × ptime ÷
    /// 1000). `0` disables draining (a degenerate/relay configuration): audio only buffers.
    frame_samples: usize,
}

impl Repacketizer {
    /// Build a repacketizer that drains `frame_samples` PCM samples per egress frame, sized so a push
    /// of up to `max_push_samples` never triggers a reallocation. A leftover partial frame is strictly
    /// `< frame_samples`, so `frame_samples + max_push_samples` is a safe steady-state ceiling.
    #[must_use]
    pub fn new(frame_samples: usize, max_push_samples: usize) -> Self {
        Self {
            accumulator: Vec::with_capacity(frame_samples + max_push_samples),
            frame_samples,
        }
    }

    /// The egress frame size in samples (the drain quantum).
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    /// Samples currently buffered (`< frame_samples` after a full drain loop). For tests / accounting.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.accumulator.len()
    }

    /// Append decoded egress-domain PCM to the FIFO. Does not reallocate while the total stays within
    /// the capacity reserved at construction (leftover `< frame_samples`, plus one `max_push_samples`).
    pub fn push(&mut self, pcm: &[i16]) {
        self.accumulator.extend_from_slice(pcm);
    }

    /// Drain exactly one egress frame into `frame`, returning the sample count written, or `None` when
    /// fewer than `frame_samples` samples are buffered (or the codec has no egress framing). The FIFO
    /// tail is shifted down in place — no allocation. `frame` must be at least `frame_samples` long;
    /// a shorter buffer yields `None` rather than a panic (a caller-side sizing bug, never on the wire).
    pub fn next_frame(&mut self, frame: &mut [i16]) -> Option<usize> {
        let count = self.frame_samples;
        if count == 0 || self.accumulator.len() < count || frame.len() < count {
            return None;
        }
        frame[..count].copy_from_slice(&self.accumulator[..count]);
        // Shift the remaining tail to the front and shrink; in place, so no heap traffic.
        self.accumulator.copy_within(count.., 0);
        let remaining = self.accumulator.len() - count;
        self.accumulator.truncate(remaining);
        Some(count)
    }

    /// Discard all buffered samples (e.g. on teardown). Keeps the reserved capacity.
    pub fn clear(&mut self) {
        self.accumulator.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A drain helper: pull every available egress frame, returning the concatenated drained samples
    /// and the frame count, so a test can assert both sample-exactness and packet count.
    fn drain_all(repacketizer: &mut Repacketizer) -> (Vec<i16>, usize) {
        let mut scratch = [0i16; 4096];
        let mut drained = Vec::new();
        let mut frames = 0;
        while let Some(count) = repacketizer.next_frame(&mut scratch) {
            drained.extend_from_slice(&scratch[..count]);
            frames += 1;
        }
        (drained, frames)
    }

    #[test]
    fn integer_upshift_20ms_to_40ms_buffers_then_drains_one_frame() {
        // 8 kHz: 20 ms ingress = 160 samples, 40 ms egress = 320 samples (2:1).
        let mut repacketizer = Repacketizer::new(320, 160);
        repacketizer.push(&[1i16; 160]);
        let (_first, frames) = drain_all(&mut repacketizer);
        assert_eq!(
            frames, 0,
            "one 20 ms frame is not yet a full 40 ms egress frame"
        );
        assert_eq!(
            repacketizer.buffered(),
            160,
            "held pending the second frame"
        );

        repacketizer.push(&[2i16; 160]);
        let (drained, frames) = drain_all(&mut repacketizer);
        assert_eq!(
            frames, 1,
            "two 20 ms frames make exactly one 40 ms egress packet"
        );
        assert_eq!(drained.len(), 320);
        assert_eq!(
            &drained[..160],
            &[1i16; 160][..],
            "first half is the first frame"
        );
        assert_eq!(
            &drained[160..],
            &[2i16; 160][..],
            "second half is the second frame"
        );
        assert_eq!(repacketizer.buffered(), 0);
    }

    #[test]
    fn integer_downshift_20ms_to_10ms_emits_two_frames() {
        // 8 kHz: 20 ms ingress = 160 samples, 10 ms egress = 80 samples (1:2).
        let mut repacketizer = Repacketizer::new(80, 160);
        let ramp: Vec<i16> = (0..160).collect();
        repacketizer.push(&ramp);
        let (drained, frames) = drain_all(&mut repacketizer);
        assert_eq!(
            frames, 2,
            "one 20 ms frame splits into two 10 ms egress packets"
        );
        assert_eq!(drained, ramp, "samples preserved in order across the split");
        assert_eq!(repacketizer.buffered(), 0);
    }

    #[test]
    fn fractional_30ms_to_20ms_is_sample_exact_across_the_stream() {
        // 8 kHz: 30 ms ingress = 240 samples, 20 ms egress = 160 samples (3:2, fractional buffering).
        let mut repacketizer = Repacketizer::new(160, 240);
        let mut expected: Vec<i16> = Vec::new();
        let mut drained_total: Vec<i16> = Vec::new();
        let mut next_sample: i16 = 0;
        for _ingress_frame in 0..10 {
            let frame: Vec<i16> = (0..240)
                .map(|_| {
                    let value = next_sample;
                    next_sample = next_sample.wrapping_add(1);
                    value
                })
                .collect();
            expected.extend_from_slice(&frame);
            repacketizer.push(&frame);
            let (drained, _frames) = drain_all(&mut repacketizer);
            drained_total.extend_from_slice(&drained);
        }
        // Every drained egress frame is exactly 160 samples, and the concatenation of all drained
        // frames is the exact prefix of the pushed stream — nothing lost, duplicated, or reordered.
        assert_eq!(
            drained_total.len() % 160,
            0,
            "each egress frame is a full 20 ms"
        );
        let leftover = expected.len() - drained_total.len();
        assert!(leftover < 160, "leftover is a partial egress frame");
        assert_eq!(repacketizer.buffered(), leftover);
        assert_eq!(
            drained_total.as_slice(),
            &expected[..drained_total.len()],
            "the egress stream is a sample-exact FIFO of the ingress stream"
        );
    }

    #[test]
    fn variable_ingress_fill_still_drains_full_frames_only() {
        // Jittery ingress: frames of 100, 40, 300, 20 samples into an 80-sample egress frame.
        let mut repacketizer = Repacketizer::new(80, 320);
        let mut expected: Vec<i16> = Vec::new();
        let mut drained_total: Vec<i16> = Vec::new();
        let mut next_sample: i16 = -1000;
        for &fill in &[100usize, 40, 300, 20] {
            let frame: Vec<i16> = (0..fill)
                .map(|_| {
                    let value = next_sample;
                    next_sample = next_sample.wrapping_add(1);
                    value
                })
                .collect();
            expected.extend_from_slice(&frame);
            repacketizer.push(&frame);
            let (drained, _frames) = drain_all(&mut repacketizer);
            drained_total.extend_from_slice(&drained);
        }
        assert_eq!(drained_total.len() % 80, 0);
        assert_eq!(drained_total.as_slice(), &expected[..drained_total.len()]);
        assert_eq!(
            repacketizer.buffered(),
            expected.len() - drained_total.len()
        );
    }

    #[test]
    fn zero_frame_samples_never_drains() {
        let mut repacketizer = Repacketizer::new(0, 160);
        repacketizer.push(&[7i16; 160]);
        let mut scratch = [0i16; 160];
        assert_eq!(repacketizer.next_frame(&mut scratch), None);
        assert_eq!(
            repacketizer.buffered(),
            160,
            "audio buffers but never drains"
        );
    }

    #[test]
    fn too_small_scratch_yields_none_not_panic() {
        let mut repacketizer = Repacketizer::new(160, 160);
        repacketizer.push(&[3i16; 160]);
        let mut scratch = [0i16; 80]; // smaller than one egress frame
        assert_eq!(repacketizer.next_frame(&mut scratch), None);
    }

    #[test]
    fn clear_drops_buffered_samples() {
        let mut repacketizer = Repacketizer::new(160, 160);
        repacketizer.push(&[1i16; 100]);
        repacketizer.clear();
        assert_eq!(repacketizer.buffered(), 0);
    }
}
