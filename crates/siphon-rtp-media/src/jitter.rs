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

/// A jitter buffer holding RTP payloads keyed by 16-bit sequence number.
#[derive(Debug)]
pub struct JitterBuffer {
    target_depth: usize,
    max_depth: usize,
    buffer: HashMap<u16, Bytes>,
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

    /// Drop the oldest slots until occupancy is within `max_depth`, advancing the cursor past the
    /// discarded sequences (counted as losses).
    fn enforce_cap(&mut self) {
        while self.buffer.len() > self.max_depth {
            if let Some(base) = self.next_out {
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
