//! A sequence-driven jitter buffer with packet-loss signalling.
//!
//! The buffer absorbs reordering and arrival jitter and emits payloads in RTP sequence order. It
//! holds no wall clock: the **consumer's [`JitterBuffer::pop`] cadence is the logical sample-tick
//! clock** (one `pop` per frame interval), which makes its behaviour fully deterministic and
//! unit-testable. On a gap it emits [`JitterOutput::Conceal`] so the leg drives the decoder's
//! `conceal()`; on underrun it re-primes. Sequence wrap (RFC 1982 serial arithmetic) is handled
//! via `wrapping_sub` distance.

use std::collections::HashMap;

use bytes::Bytes;

/// What one [`JitterBuffer::pop`] yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitterOutput {
    /// The payload for the next sequence number.
    Packet(Bytes),
    /// A gap: the next sequence was lost but later packets are buffered — conceal one frame.
    Conceal,
    /// Not enough buffered yet (priming) or buffer drained (underrun) — no frame this tick.
    Starved,
}

/// What [`JitterBuffer::push`] did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// Buffered for playout.
    Accepted,
    /// Already buffered — dropped.
    Duplicate,
    /// Older than the playout cursor — dropped.
    Late,
}

/// Counters for observability (feed the control protocol's `query` and the MOS estimator).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterStats {
    /// Packets dropped as duplicates.
    pub duplicates: u64,
    /// Packets dropped for arriving after their playout slot.
    pub lates: u64,
    /// Sequence slots concealed (lost) or discarded on overflow.
    pub losses: u64,
}

/// How many non-audio sequence numbers seen before the first audio packet are remembered: the most
/// recent ones, in a fixed array, so nothing allocates.
const EARLY_SKIPS: usize = 8;

/// A jitter buffer holding RTP payloads keyed by 16-bit sequence number.
#[derive(Debug)]
pub struct JitterBuffer {
    target_depth: usize,
    max_depth: usize,
    buffer: HashMap<u16, Bytes>,
    /// Sequence numbers consumed by packets that carry no audio (RFC 4733 telephone-events share the
    /// audio stream's sequence space): the playout cursor steps over them instead of reading the gap
    /// as a lost packet.
    skipped: std::collections::HashSet<u16>,
    /// Non-audio sequence numbers seen before the first audio packet set the playout origin, applied
    /// (those at or after it) once it does.
    early_skips: [u16; EARLY_SKIPS],
    /// How many entries of `early_skips` are in use, and where the next one goes (a ring: the oldest
    /// is replaced once it is full).
    early_len: usize,
    early_next: usize,
    next_out: Option<u16>,
    primed: bool,
    stats: JitterStats,
}

impl JitterBuffer {
    /// Create a buffer that primes at `target_depth` packets and caps occupancy at `max_depth`
    /// (older slots are dropped beyond the cap to bound latency). `max_depth` is raised to at
    /// least `target_depth`.
    #[must_use]
    pub fn new(target_depth: usize, max_depth: usize) -> Self {
        let target_depth = target_depth.max(1);
        Self {
            target_depth,
            max_depth: max_depth.max(target_depth),
            buffer: HashMap::new(),
            skipped: std::collections::HashSet::new(),
            early_skips: [0; EARLY_SKIPS],
            early_len: 0,
            early_next: 0,
            next_out: None,
            primed: false,
            stats: JitterStats::default(),
        }
    }

    /// Current counters.
    #[must_use]
    pub fn stats(&self) -> JitterStats {
        self.stats
    }

    /// Number of packets currently buffered.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Offer a packet to the buffer.
    pub fn push(&mut self, sequence: u16, payload: Bytes) -> PushResult {
        let Some(base) = self.next_out else {
            // First packet seen sets the playout origin.
            self.next_out = Some(sequence);
            self.buffer.insert(sequence, payload);
            // Non-audio packets that arrived first and belong after the origin (serial order, so a
            // wrap is fine) are stepped over like any other.
            let early = self.early_skips;
            let used = std::mem::take(&mut self.early_len);
            self.early_next = 0;
            for early in early.into_iter().take(used) {
                if early != sequence && early.wrapping_sub(sequence) < 0x8000 {
                    self.skipped.insert(early);
                }
            }
            return PushResult::Accepted;
        };

        let distance = sequence.wrapping_sub(base);
        if distance >= 0x8000 {
            // Behind the playout cursor — too late to play.
            self.stats.lates += 1;
            return PushResult::Late;
        }
        if self.buffer.contains_key(&sequence) {
            self.stats.duplicates += 1;
            return PushResult::Duplicate;
        }
        self.buffer.insert(sequence, payload);
        self.enforce_cap();
        PushResult::Accepted
    }

    /// Note that `sequence` was consumed by a packet that carries no audio, so the playout cursor
    /// steps over it and no concealment is generated for it (RFC 4733 §2.2: events and audio share one
    /// sequence number space). Ahead of the cursor it is remembered; at the cursor it is stepped
    /// over at once; behind it or before the first audio packet it means nothing and is ignored.
    pub fn skip(&mut self, sequence: u16) {
        let Some(base) = self.next_out else {
            // Before the first audio packet there is no cursor to compare with: kept, bounded, and
            // applied when the origin is set.
            self.early_skips[self.early_next] = sequence;
            self.early_next = (self.early_next + 1) % EARLY_SKIPS;
            self.early_len = (self.early_len + 1).min(EARLY_SKIPS);
            return;
        };
        let distance = sequence.wrapping_sub(base);
        if distance >= 0x8000 {
            return;
        }
        if self.skipped.len() < self.max_depth.saturating_mul(8) {
            self.skipped.insert(sequence);
        }
        let _ = self.step_over_skipped();
    }

    /// How many skipped sequence numbers are being remembered (bounded by the cursor's progress).
    #[cfg(test)]
    fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Advance the cursor past every consecutive skipped sequence; whether it moved.
    fn step_over_skipped(&mut self) -> bool {
        // The common path has nothing skipped: no hashing (`HashSet::remove` hashes its key even
        // when the set is empty).
        if self.skipped.is_empty() {
            return false;
        }
        let mut moved = false;
        while let Some(base) = self.next_out {
            if self.skipped.remove(&base) && !self.buffer.contains_key(&base) {
                self.next_out = Some(base.wrapping_add(1));
                moved = true;
            } else {
                break;
            }
        }
        moved
    }

    /// Drop the oldest slots until occupancy is within `max_depth`, advancing the cursor past the
    /// discarded sequences (counted as losses).
    fn enforce_cap(&mut self) {
        while self.buffer.len() > self.max_depth {
            if let Some(base) = self.next_out {
                // A number a non-audio packet consumed is passed without being a loss, and its entry
                // goes with it: the cursor never leaves a stale skip behind.
                if self.skipped.remove(&base) {
                    self.next_out = Some(base.wrapping_add(1));
                    continue;
                }
                self.buffer.remove(&base);
                self.next_out = Some(base.wrapping_add(1));
                self.stats.losses += 1;
            } else {
                break;
            }
        }
    }

    /// Emit the next frame for this tick.
    pub fn pop(&mut self) -> JitterOutput {
        let Some(base) = self.next_out else {
            return JitterOutput::Starved;
        };
        if !self.primed {
            if self.buffer.len() >= self.target_depth {
                self.primed = true;
            } else {
                return JitterOutput::Starved;
            }
        }

        if let Some(payload) = self.buffer.remove(&base) {
            self.next_out = Some(base.wrapping_add(1));
            return JitterOutput::Packet(payload);
        }

        self.pop_miss()
    }

    /// Nothing is buffered at the cursor: a number a non-audio packet consumed is stepped over, an
    /// empty buffer is an underrun, and a later packet makes the number a genuine loss. Out of line:
    /// the common path, a packet at the cursor, never gets here.
    #[inline(never)]
    fn pop_miss(&mut self) -> JitterOutput {
        let _ = self.step_over_skipped();
        let Some(base) = self.next_out else {
            return JitterOutput::Starved;
        };
        if let Some(payload) = self.buffer.remove(&base) {
            self.next_out = Some(base.wrapping_add(1));
            return JitterOutput::Packet(payload);
        }
        if self.buffer.is_empty() {
            // Underrun: nothing to play and nothing ahead — re-prime before resuming.
            self.primed = false;
            return JitterOutput::Starved;
        }

        // A later packet is buffered, so this sequence is genuinely lost.
        self.next_out = Some(base.wrapping_add(1));
        self.stats.losses += 1;
        JitterOutput::Conceal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(byte: u8) -> Bytes {
        Bytes::from(vec![byte; 4])
    }

    #[test]
    fn primes_then_plays_in_order() {
        let mut buffer = JitterBuffer::new(2, 8);
        assert_eq!(buffer.push(100, payload(0)), PushResult::Accepted);
        // Not yet at target depth.
        assert_eq!(buffer.pop(), JitterOutput::Starved);
        assert_eq!(buffer.push(101, payload(1)), PushResult::Accepted);
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(0)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(1)));
        // Drained.
        assert_eq!(buffer.pop(), JitterOutput::Starved);
    }

    #[test]
    fn reorders_within_window() {
        let mut buffer = JitterBuffer::new(2, 8);
        buffer.push(10, payload(0));
        buffer.push(12, payload(2));
        buffer.push(11, payload(1));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(0)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(1)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(2)));
    }

    #[test]
    fn a_skipped_sequence_is_stepped_over_and_never_concealed() {
        // Audio 0, ten non-audio packets 1..=10, audio 11: no concealment, and no extra wait.
        let mut buffer = JitterBuffer::new(1, 16);
        buffer.push(0, payload(0));
        for sequence in 1..=10 {
            buffer.skip(sequence);
        }
        buffer.push(11, payload(11));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(0)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(11)));
        assert_eq!(buffer.stats().losses, 0);
        // Skipped ahead of the cursor, in any order, and a genuinely lost one is still concealed.
        let mut buffer = JitterBuffer::new(1, 16);
        buffer.push(0, payload(0));
        buffer.skip(2);
        buffer.skip(1);
        buffer.push(4, payload(4)); // 3 is lost
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(0)));
        assert_eq!(buffer.pop(), JitterOutput::Conceal);
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(4)));
        assert_eq!(buffer.stats().losses, 1);
    }

    #[test]
    fn a_skip_before_the_first_audio_packet_is_applied_when_the_origin_is_set() {
        // Event 11 arrives first, then audio 10 and 12: 11 is not a loss.
        let mut buffer = JitterBuffer::new(1, 16);
        buffer.skip(11);
        buffer.push(10, payload(10));
        buffer.push(12, payload(12));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(10)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(12)));
        assert_eq!(buffer.stats().losses, 0);
        // Across the 16-bit wrap, and an event from before the origin is nothing.
        let mut buffer = JitterBuffer::new(1, 16);
        buffer.skip(0);
        buffer.skip(65_534);
        buffer.push(65_535, payload(1));
        buffer.push(1, payload(2));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(1)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(2)));
        assert_eq!(buffer.stats().losses, 0);
        assert_eq!(buffer.skipped_len(), 0);
    }

    #[test]
    fn the_early_skips_kept_are_the_most_recent_ones() {
        // Eight old non-audio numbers fill the list; the newest (10) must displace the oldest, not be
        // dropped: audio 9 sets the origin and 10 is ahead of it.
        let mut buffer = JitterBuffer::new(1, 1);
        for sequence in 1..=8 {
            buffer.skip(sequence);
        }
        buffer.skip(10);
        buffer.push(9, payload(9));
        buffer.push(11, payload(11));
        // 9 was dropped by the one-slot buffer's own overflow; 10 is not a loss.
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(11)));
        assert_eq!(buffer.stats().losses, 1);
    }

    #[test]
    fn the_cursor_prunes_skips_when_overflow_moves_it_so_a_small_buffer_never_fills_up() {
        // Capacity 1, the same pattern over and over: audio, a non-audio packet, audio. Overflow walks
        // the cursor past each skipped number; its entry must go with it, or the bounded set fills
        // with stale numbers and skipping silently stops working.
        let mut buffer = JitterBuffer::new(1, 1);
        let mut sequence = 0u16;
        for _ in 0..20_000 {
            // Audio, two non-audio packets, two more audio: the overflow walks the cursor over both.
            buffer.push(sequence, payload(1));
            buffer.skip(sequence.wrapping_add(1));
            buffer.skip(sequence.wrapping_add(2));
            buffer.push(sequence.wrapping_add(3), payload(2));
            buffer.push(sequence.wrapping_add(4), payload(3));
            sequence = sequence.wrapping_add(5);
            assert_eq!(buffer.skipped_len(), 0, "stale skips accumulate");
        }
    }

    #[test]
    fn conceals_a_lost_packet() {
        let mut buffer = JitterBuffer::new(2, 8);
        buffer.push(0, payload(0));
        buffer.push(1, payload(1));
        buffer.push(3, payload(3)); // seq 2 lost
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(0)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(1)));
        assert_eq!(buffer.pop(), JitterOutput::Conceal);
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(3)));
        assert_eq!(buffer.stats().losses, 1);
    }

    #[test]
    fn rejects_duplicates_and_late_packets() {
        let mut buffer = JitterBuffer::new(1, 8);
        buffer.push(5, payload(5));
        assert_eq!(buffer.push(5, payload(5)), PushResult::Duplicate);
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(5)));
        // seq 5 already played; offering 4 is late.
        assert_eq!(buffer.push(4, payload(4)), PushResult::Late);
        assert_eq!(buffer.stats().duplicates, 1);
        assert_eq!(buffer.stats().lates, 1);
    }

    #[test]
    fn handles_sequence_wrap() {
        let mut buffer = JitterBuffer::new(2, 8);
        buffer.push(0xFFFE, payload(0));
        buffer.push(0xFFFF, payload(1));
        buffer.push(0x0000, payload(2));
        buffer.push(0x0001, payload(3));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(0)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(1)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(2)));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(3)));
    }

    #[test]
    fn caps_occupancy_and_advances() {
        let mut buffer = JitterBuffer::new(1, 3);
        // Fill beyond the cap; the oldest slot is discarded.
        for sequence in 0..5u16 {
            buffer.push(sequence, payload(sequence as u8));
        }
        assert!(buffer.buffered() <= 3);
        assert!(buffer.stats().losses >= 1, "overflow drops count as loss");
    }

    #[test]
    fn underrun_then_refill_resumes() {
        let mut buffer = JitterBuffer::new(1, 8);
        buffer.push(0, payload(0));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(0)));
        // Underrun.
        assert_eq!(buffer.pop(), JitterOutput::Starved);
        // Refill resumes from the next expected sequence.
        buffer.push(1, payload(1));
        assert_eq!(buffer.pop(), JitterOutput::Packet(payload(1)));
    }
}

// Property test: under an arbitrary logical schedule of push/pop operations (arbitrary sequence
// numbers, so arbitrary loss / reorder / duplication / 16-bit wrap, interleaved with playout ticks),
// the buffer must never panic and must keep occupancy bounded by `max_depth`. The schedule *is* the
// logical clock, so this is deterministic with no `Instant::now()` (house rule).
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Push(u16),
        Pop,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![any::<u16>().prop_map(Op::Push), Just(Op::Pop)]
    }

    proptest! {
        #[test]
        fn arbitrary_schedule_never_panics_and_stays_bounded(
            target in 1usize..8,
            extra in 0usize..16,
            ops in prop::collection::vec(op(), 0..600),
        ) {
            let max_depth = target + extra;
            let mut buffer = JitterBuffer::new(target, max_depth);
            for step in ops {
                match step {
                    // The payload contents are irrelevant to the occupancy invariant under test.
                    Op::Push(sequence) => {
                        let _ = buffer.push(sequence, Bytes::from(vec![sequence as u8]));
                    }
                    Op::Pop => {
                        let _ = buffer.pop();
                    }
                }
                prop_assert!(
                    buffer.buffered() <= max_depth,
                    "occupancy {} exceeded max_depth {}",
                    buffer.buffered(),
                    max_depth,
                );
            }
        }
    }
}
