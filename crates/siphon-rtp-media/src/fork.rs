//! An RTP fork [`MediaSink`] for `Subscribe` / SIPREC: re-encode decoded PCM into RTP for a
//! subscriber leg.
//!
//! Plugged into a [`crate::fanout::FanOut`], one decode of the primary stream feeds both the relay
//! and this fork — the fork re-encodes each PCM frame, packetizes it (RFC 3550 §5, via
//! [`crate::rtp::write_packet`]) with its own egress sequence/timestamp/SSRC (mirroring
//! [`crate::leg::MediaLeg::encode_rtp`]), and hands the bytes to a bounded `flume` channel the
//! subscriber's egress task drains. The channel is **bounded with a drop-on-full policy**: late
//! media is worthless, so a full mailbox drops a frame rather than blocking the decode (project
//! rule: "drop a frame before growing a queue"). Encode errors are likewise counted and dropped,
//! never propagated — a fork must never stall or crash the primary call.

use bytes::Bytes;
use siphon_rtp_codec::Encoder;

use crate::fanout::MediaSink;
use crate::rtp::{write_packet, RtpHeader, FIXED_HEADER_LEN};

/// Largest codec payload the egress buffer accommodates (mirrors [`crate::leg`]'s `MAX_PAYLOAD`).
const MAX_PAYLOAD: usize = 1500;
/// Scratch buffer big enough for a 12-byte RTP header plus the largest codec payload.
const PACKET_BUFFER_LEN: usize = FIXED_HEADER_LEN + MAX_PAYLOAD;

/// Re-encodes decoded PCM frames into RTP packets for a subscriber leg, emitting them on a bounded
/// channel with a drop-on-full overflow policy.
pub struct RtpForkSink {
    encoder: Box<dyn Encoder>,
    output: flume::Sender<Bytes>,
    egress_sequence: u16,
    egress_timestamp: u32,
    egress_ssrc: u32,
    egress_payload_type: u8,
    frame_samples: u32,
    /// Reusable scratch buffer for one packet — no per-frame heap allocation for serialization.
    scratch: Box<[u8; PACKET_BUFFER_LEN]>,
    /// Frames dropped because the channel was full (overflow) or the encode failed.
    dropped: u64,
    /// Frames successfully forwarded.
    forwarded: u64,
}

impl RtpForkSink {
    /// Build a fork sink. `egress_ssrc` and `egress_payload_type` stamp the packets this fork emits
    /// for the subscriber; the egress timestamp advances by one codec frame per emitted packet
    /// (same contract as [`crate::leg::MediaLeg::encode_rtp`]). `output` is the bounded channel the
    /// subscriber's egress task drains; build it with [`flume::bounded`] so a stall drops media.
    #[must_use]
    pub fn new(
        encoder: Box<dyn Encoder>,
        output: flume::Sender<Bytes>,
        egress_ssrc: u32,
        egress_payload_type: u8,
    ) -> Self {
        let frame_samples = encoder.frame_samples() as u32;
        Self {
            encoder,
            output,
            egress_sequence: 0,
            egress_timestamp: 0,
            egress_ssrc,
            egress_payload_type,
            frame_samples,
            scratch: Box::new([0u8; PACKET_BUFFER_LEN]),
            dropped: 0,
            forwarded: 0,
        }
    }

    /// Frames forwarded to the subscriber so far.
    #[must_use]
    pub fn forwarded(&self) -> u64 {
        self.forwarded
    }

    /// Frames dropped (channel full or encode error) so far.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Encode one PCM frame and send the RTP packet, advancing the egress counters. On encode error
    /// or a full channel the frame is dropped (counted) — the fork never blocks or fails the
    /// primary decode. Returns `true` if the packet was forwarded.
    fn forward(&mut self, pcm: &[i16]) -> bool {
        let header = RtpHeader {
            marker: false,
            payload_type: self.egress_payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };

        // Encode into the tail of the scratch buffer (after the header), then frame in place. We
        // encode into a separate region to keep the borrow simple and avoid a second buffer.
        let mut payload = [0u8; MAX_PAYLOAD];
        let payload_len = match self.encoder.encode(pcm, &mut payload) {
            Ok(len) => len,
            Err(_) => {
                // A bad frame size / oversized payload is dropped, not propagated: a misbehaving
                // fork must not stall the call. (The error is observable via `dropped()`.)
                self.dropped += 1;
                return false;
            }
        };

        let total = match write_packet(&header, &payload[..payload_len], self.scratch.as_mut_slice())
        {
            Ok(total) => total,
            Err(_) => {
                self.dropped += 1;
                return false;
            }
        };

        // Advance the egress counters regardless of send outcome: dropping a packet must still move
        // the subscriber's sequence/timestamp forward so the gap is visible as loss, not as a
        // stalled clock (RFC 3550 §5.1).
        self.egress_sequence = self.egress_sequence.wrapping_add(1);
        self.egress_timestamp = self.egress_timestamp.wrapping_add(self.frame_samples);

        // Bounded, non-blocking: a full mailbox drops this frame (late media is worthless) rather
        // than blocking the shared decode. Disconnect (subscriber gone) is also a drop.
        match self.output.try_send(Bytes::copy_from_slice(&self.scratch[..total])) {
            Ok(()) => {
                self.forwarded += 1;
                true
            }
            Err(_) => {
                self.dropped += 1;
                false
            }
        }
    }
}

impl MediaSink for RtpForkSink {
    fn write_pcm(&mut self, pcm: &[i16]) {
        let _ = self.forward(pcm);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpPacket;
    use siphon_rtp_codec::g711::G711;

    const SUBSCRIBER_SSRC: u32 = 0xFEED_BEEF;
    const PCMU_PAYLOAD_TYPE: u8 = 0;

    fn ulaw_fork(output: flume::Sender<Bytes>) -> RtpForkSink {
        RtpForkSink::new(
            Box::new(G711::ulaw()),
            output,
            SUBSCRIBER_SSRC,
            PCMU_PAYLOAD_TYPE,
        )
    }

    #[test]
    fn forwards_well_formed_rtp_with_correct_ssrc_and_pt() {
        let (sender, receiver) = flume::bounded(8);
        let mut fork = ulaw_fork(sender);
        let pcm = [1234i16; 160];
        fork.write_pcm(&pcm);

        let packet_bytes = receiver.try_recv().expect("one packet");
        let packet = RtpPacket::parse(&packet_bytes).expect("parse");
        assert_eq!(packet.ssrc, SUBSCRIBER_SSRC);
        assert_eq!(packet.payload_type, PCMU_PAYLOAD_TYPE);
        assert_eq!(packet.sequence, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.payload.len(), 160, "160-sample G.711 frame → 160-byte payload");
        assert_eq!(fork.forwarded(), 1);
        assert_eq!(fork.dropped(), 0);
    }

    #[test]
    fn sequence_and_timestamp_advance_per_frame() {
        let (sender, receiver) = flume::bounded(8);
        let mut fork = ulaw_fork(sender);
        let pcm = [0i16; 160];
        for _ in 0..3 {
            fork.write_pcm(&pcm);
        }

        let mut previous_sequence = None;
        for expected_timestamp in [0u32, 160, 320] {
            let bytes = receiver.try_recv().expect("packet");
            let packet = RtpPacket::parse(&bytes).expect("parse");
            assert_eq!(packet.timestamp, expected_timestamp);
            if let Some(previous) = previous_sequence {
                assert_eq!(packet.sequence, previous + 1, "sequence advances by one");
            }
            previous_sequence = Some(packet.sequence);
        }
        assert_eq!(fork.forwarded(), 3);
    }

    #[test]
    fn full_channel_drops_rather_than_blocks() {
        // Capacity 2; push 5 frames — the decode must not block, and 3 are dropped.
        let (sender, receiver) = flume::bounded(2);
        let mut fork = ulaw_fork(sender);
        let pcm = [7i16; 160];
        for _ in 0..5 {
            fork.write_pcm(&pcm); // never blocks even though nothing is draining
        }
        assert_eq!(fork.forwarded(), 2, "only the bounded capacity made it through");
        assert_eq!(fork.dropped(), 3, "the rest were dropped, not queued");

        // The two buffered packets are still well-formed and the dropped frames left a sequence gap.
        let first_bytes = receiver.try_recv().expect("first");
        let second_bytes = receiver.try_recv().expect("second");
        let first = RtpPacket::parse(&first_bytes).expect("parse");
        let second = RtpPacket::parse(&second_bytes).expect("parse");
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert!(receiver.try_recv().is_err(), "only two were buffered");
    }

    #[test]
    fn timestamp_advances_even_when_dropped() {
        // Drops still advance the clock so the gap reads as loss, not a stalled timestamp.
        let (sender, receiver) = flume::bounded(1);
        let mut fork = ulaw_fork(sender);
        let pcm = [0i16; 160];
        fork.write_pcm(&pcm); // forwarded, ts 0
        fork.write_pcm(&pcm); // dropped, but advances ts
        fork.write_pcm(&pcm); // dropped, but advances ts

        let first_bytes = receiver.try_recv().expect("first");
        let first = RtpPacket::parse(&first_bytes).expect("parse");
        assert_eq!(first.timestamp, 0);
        // The next forwarded frame (after draining) reflects the advanced clock.
        fork.write_pcm(&pcm);
        let next_bytes = receiver.try_recv().expect("next");
        let next = RtpPacket::parse(&next_bytes).expect("parse");
        assert_eq!(next.timestamp, 160 * 3, "clock advanced across the dropped frames");
        assert_eq!(next.sequence, 3);
    }

    #[test]
    fn disconnected_receiver_drops_without_panic() {
        let (sender, receiver) = flume::bounded(4);
        let mut fork = ulaw_fork(sender);
        drop(receiver); // subscriber leg torn down
        fork.write_pcm(&[0i16; 160]); // must not panic
        assert_eq!(fork.forwarded(), 0);
        assert_eq!(fork.dropped(), 1);
    }

    #[test]
    fn bad_frame_size_is_dropped_not_propagated() {
        // G.711 decodes any length, but an oversized PCM frame (> MAX_PAYLOAD) overflows the encode
        // output buffer → CodecError, which the fork swallows as a drop.
        let (sender, receiver) = flume::bounded(4);
        let mut fork = ulaw_fork(sender);
        let oversized = vec![0i16; MAX_PAYLOAD + 1];
        fork.write_pcm(&oversized); // must not panic or block
        assert_eq!(fork.forwarded(), 0);
        assert_eq!(fork.dropped(), 1);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn finish_is_a_noop_and_does_not_close_channel() {
        let (sender, receiver) = flume::bounded(4);
        let mut fork = ulaw_fork(sender);
        fork.write_pcm(&[0i16; 160]);
        fork.finish(); // default no-op
        assert!(receiver.try_recv().is_ok(), "buffered packet survives finish");
    }

    #[test]
    fn works_as_a_boxed_media_sink() {
        // The fork plugs into a FanOut alongside the relay path.
        use crate::fanout::FanOut;
        let (sender, receiver) = flume::bounded(8);
        let mut fanout = FanOut::new();
        fanout.add(Box::new(ulaw_fork(sender)));
        fanout.write_pcm(&[100i16; 160]);
        assert!(receiver.try_recv().is_ok(), "fork received the fanned-out frame");
    }
}
