//! Per-receiver RTP translator for one-to-many forwarding (RFC 3550 §7.1 / §7.2).
//!
//! A forwarding room relays ONE selected talker's payload, unchanged, to N receivers. Each receiver
//! must see a single stable outbound stream however often the talker changes, so every receiving
//! seat owns one [`Translator`]: a fixed egress SSRC chosen at construction, with sequence numbers
//! and timestamps that stay continuous across talker changes (RFC 3550 §5.1, §7.2).
//!
//! # Header policy
//! * Payload type and payload bytes are copied as-is (RFC 3550 §7.1: a translator does not touch the
//!   encoding). Padding is preserved: the P bit and the padding octets are carried over (§5.1).
//! * The CSRC list is **dropped** (CC = 0). The egress SSRC is the stream's only source identifier;
//!   the inbound SSRC and any CSRCs belong to the inbound leg's identifier space and would be
//!   meaningless to the receiver (§7.3 lets a mixer set CSRCs; this relay does not attribute).
//! * The header extension is **dropped** (X = 0). Extension IDs are negotiated per leg (RFC 8285 §6),
//!   so the inbound mapping does not hold on the egress leg.
//!
//! # Rebasing
//! The first packet of every talker run starts a new mapping: the out sequence is the last one sent
//! plus one, the out timestamp is the last one sent plus the elapsed caller clock since the last
//! forwarded packet (at least one tick so it strictly advances), and the marker bit is set (§5.1: a
//! talk-spurt start). Inside a run the mapping is a fixed offset, so in-source loss stays visible to
//! the receiver, and reordered or duplicate packets map to the same out values every time.
//!
//! # Stale packets
//! After a switch away from source A, late packets of A are dropped ([`Forwarded::DroppedStale`])
//! rather than mapped: they would land behind the rebase point and break monotonicity. A packet of A
//! is stale when its sequence number is not ahead (RFC 1982 serial arithmetic) of the last one seen
//! from A; an A packet ahead of it is A talking again and rebases. Only the immediately previous
//! source is remembered. Caveat: if A resumes with a sequence jump of 2^15 or more it is mistaken
//! for stale; a sender that does this has restarted and normally picks a new SSRC (§8.1).

use crate::rtp::{write_packet, RtpError, RtpHeader, RtpPacket, FIXED_HEADER_LEN};

/// Errors from [`Translator::translate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranslatorError {
    /// The inbound packet is malformed, or the output buffer is too small.
    #[error("rtp translation failed: {0}")]
    Rtp(#[from] RtpError),
}

/// What [`Translator::translate`] did with an inbound packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forwarded {
    /// The packet was rewritten into the output buffer.
    Packet {
        /// Length of the rewritten packet in the output buffer.
        length: usize,
        /// True when this packet started a new talker run (its marker bit is set).
        rebased: bool,
    },
    /// A late packet of the previous source, dropped; nothing was written.
    DroppedStale,
}

/// Mapping state of the source currently being forwarded.
#[derive(Debug, Clone, Copy)]
struct Source {
    ssrc: u32,
    first_sequence: u16,
    first_timestamp: u32,
    base_sequence: u16,
    base_timestamp: u32,
    highest_sequence: u16,
}

/// Serial-number "a is ahead of b" on 16 bits (RFC 1982).
fn ahead16(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) > 0
}

/// One receiving seat's egress stream: stable SSRC, continuous sequence and timestamp.
#[derive(Debug, Clone)]
pub struct Translator {
    egress_ssrc: u32,
    initial_sequence: u16,
    initial_timestamp: u32,
    source: Option<Source>,
    /// Last retired source: `(ssrc, highest sequence seen)`, for the stale check.
    previous: Option<(u32, u16)>,
    sent_any: bool,
    last_sequence: u16,
    last_timestamp: u32,
    last_clock: u32,
    packets_sent: u32,
    octets_sent: u32,
}

impl Translator {
    /// Create a translator. `initial_sequence` / `initial_timestamp` are the first packet's egress
    /// values; callers should randomise them (RFC 3550 §5.1).
    #[must_use]
    pub fn new(egress_ssrc: u32, initial_sequence: u16, initial_timestamp: u32) -> Self {
        Self {
            egress_ssrc,
            initial_sequence,
            initial_timestamp,
            source: None,
            previous: None,
            sent_any: false,
            last_sequence: initial_sequence,
            last_timestamp: initial_timestamp,
            last_clock: 0,
            packets_sent: 0,
            octets_sent: 0,
        }
    }

    /// The egress SSRC (RTCP SR sender SSRC, RFC 3550 §6.4.1).
    #[must_use]
    pub fn egress_ssrc(&self) -> u32 {
        self.egress_ssrc
    }

    /// Packets sent, for the SR sender's packet count (RFC 3550 §6.4.1; wraps at 2^32).
    #[must_use]
    pub fn packets_sent(&self) -> u32 {
        self.packets_sent
    }

    /// Payload octets sent, for the SR sender's octet count (RFC 3550 §6.4.1; excludes header and
    /// padding, wraps at 2^32).
    #[must_use]
    pub fn octets_sent(&self) -> u32 {
        self.octets_sent
    }

    /// The highest egress RTP timestamp sent, for the SR RTP timestamp field. Before any packet this
    /// is the initial timestamp.
    #[must_use]
    pub fn last_timestamp(&self) -> u32 {
        self.last_timestamp
    }

    /// The highest egress sequence number sent.
    #[must_use]
    pub fn last_sequence(&self) -> u16 {
        self.last_sequence
    }

    /// Signal a talker change explicitly: the next packet starts a new run even if it carries the
    /// current source's SSRC. A switch signalled before any packet is a no-op.
    pub fn switch_source(&mut self) {
        if let Some(source) = self.source.take() {
            self.previous = Some((source.ssrc, source.highest_sequence));
        }
    }

    /// Rewrite `inbound` (an unprotected RTP packet from the current source) into `out`.
    /// `clock` is the caller's logical arrival clock in RTP timestamp units (wrapping), used only to
    /// size the timestamp gap at a rebase.
    ///
    /// # Errors
    /// [`TranslatorError::Rtp`] for a malformed inbound packet or too small an `out`; on error no
    /// state changes.
    pub fn translate(
        &mut self,
        inbound: &[u8],
        clock: u32,
        out: &mut [u8],
    ) -> Result<Forwarded, TranslatorError> {
        let packet = RtpPacket::parse(inbound)?;

        // Same source, no pending switch: fixed-offset mapping (also covers reorder/duplicates).
        let mapped = match self.source {
            Some(source) if source.ssrc == packet.ssrc => Some((
                source
                    .base_sequence
                    .wrapping_add(packet.sequence.wrapping_sub(source.first_sequence)),
                source
                    .base_timestamp
                    .wrapping_add(packet.timestamp.wrapping_sub(source.first_timestamp)),
            )),
            _ => None,
        };

        let rebase = mapped.is_none();
        if rebase {
            // A late packet of the previous source must not switch back to it.
            if let Some((ssrc, highest)) = self.previous {
                if ssrc == packet.ssrc && !ahead16(packet.sequence, highest) {
                    return Ok(Forwarded::DroppedStale);
                }
            }
        }

        let (out_sequence, out_timestamp) = match mapped {
            Some(values) => values,
            None if self.sent_any => {
                let elapsed = clock.wrapping_sub(self.last_clock);
                // A clock that ran backwards (>= 2^31) still advances the timestamp by one tick.
                let elapsed = if elapsed == 0 || elapsed >= 0x8000_0000 {
                    1
                } else {
                    elapsed
                };
                (
                    self.last_sequence.wrapping_add(1),
                    self.last_timestamp.wrapping_add(elapsed),
                )
            }
            None => (self.initial_sequence, self.initial_timestamp),
        };

        // Padding is carried over (RFC 3550 §5.1): P bit plus the trailing octets.
        let padding = if inbound[0] & 0x20 != 0 {
            inbound.len() - packet.payload.len() - header_len(inbound)
        } else {
            0
        };
        let total = FIXED_HEADER_LEN + packet.payload.len() + padding;
        if out.len() < total {
            return Err(RtpError::OutputTooSmall {
                needed: total,
                have: out.len(),
            }
            .into());
        }

        let header = RtpHeader {
            marker: rebase || packet.marker,
            payload_type: packet.payload_type,
            sequence: out_sequence,
            timestamp: out_timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut length = write_packet(&header, packet.payload, out)?;
        if padding > 0 {
            out[0] |= 0x20;
            out[length..length + padding].copy_from_slice(&inbound[inbound.len() - padding..]);
            length += padding;
        }

        // Commit state only after the packet was written.
        if rebase {
            if let Some(source) = self.source.take() {
                self.previous = Some((source.ssrc, source.highest_sequence));
            }
            self.source = Some(Source {
                ssrc: packet.ssrc,
                first_sequence: packet.sequence,
                first_timestamp: packet.timestamp,
                base_sequence: out_sequence,
                base_timestamp: out_timestamp,
                highest_sequence: packet.sequence,
            });
        } else if let Some(source) = self.source.as_mut() {
            if ahead16(packet.sequence, source.highest_sequence) {
                source.highest_sequence = packet.sequence;
            }
        }
        if !self.sent_any || ahead16(out_sequence, self.last_sequence) {
            self.last_sequence = out_sequence;
        }
        if !self.sent_any || (out_timestamp.wrapping_sub(self.last_timestamp) as i32) > 0 {
            self.last_timestamp = out_timestamp;
        }
        self.last_clock = clock;
        self.sent_any = true;
        self.packets_sent = self.packets_sent.wrapping_add(1);
        self.octets_sent = self.octets_sent.wrapping_add(packet.payload.len() as u32);
        Ok(Forwarded::Packet {
            length,
            rebased: rebase,
        })
    }
}

/// Bytes of fixed header + CSRCs + extension in an already-validated packet.
fn header_len(inbound: &[u8]) -> usize {
    let mut offset = FIXED_HEADER_LEN + 4 * (inbound[0] & 0x0F) as usize;
    if inbound[0] & 0x10 != 0 {
        let words = u16::from_be_bytes([inbound[offset + 2], inbound[offset + 3]]) as usize;
        offset += 4 + words * 4;
    }
    offset
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const EGRESS: u32 = 0xE0E0_0001;

    fn packet(ssrc: u32, sequence: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 96,
            sequence,
            timestamp,
            ssrc,
        };
        let mut buffer = vec![0u8; 12 + payload.len()];
        write_packet(&header, payload, &mut buffer).unwrap();
        buffer
    }

    /// Translate and parse the result back: `(marker, sequence, timestamp, ssrc)`.
    fn run(translator: &mut Translator, inbound: &[u8], clock: u32) -> (bool, u16, u32, u32) {
        let mut out = [0u8; 512];
        let Forwarded::Packet { length, .. } =
            translator.translate(inbound, clock, &mut out).unwrap()
        else {
            panic!("expected forwarded");
        };
        let parsed = RtpPacket::parse(&out[..length]).unwrap();
        (
            parsed.marker,
            parsed.sequence,
            parsed.timestamp,
            parsed.ssrc,
        )
    }

    #[test]
    fn payload_and_payload_type_are_byte_identical() {
        let payload: Vec<u8> = (0..160u32).map(|value| (value * 7) as u8).collect();
        let mut translator = Translator::new(EGRESS, 100, 5000);
        let mut out = [0u8; 512];
        let inbound = packet(1, 10, 1000, &payload);
        let Forwarded::Packet { length, .. } = translator.translate(&inbound, 0, &mut out).unwrap()
        else {
            panic!()
        };
        let parsed = RtpPacket::parse(&out[..length]).unwrap();
        assert_eq!(parsed.payload, &payload[..]);
        assert_eq!(parsed.payload_type, 96);
        assert_eq!(length, 12 + 160);
    }

    #[test]
    fn first_packet_uses_initial_values_with_marker() {
        let mut translator = Translator::new(EGRESS, 100, 5000);
        assert_eq!(
            run(&mut translator, &packet(1, 10, 1000, b"a"), 0),
            (true, 100, 5000, EGRESS)
        );
        assert_eq!(
            run(&mut translator, &packet(1, 11, 1160, b"a"), 160),
            (false, 101, 5160, EGRESS)
        );
    }

    #[test]
    fn continuity_across_a_b_a_switches_with_marker_on_first_after_each() {
        let mut translator = Translator::new(EGRESS, 100, 5000);
        assert_eq!(
            run(&mut translator, &packet(0xA, 500, 9000, b"a"), 0),
            (true, 100, 5000, EGRESS)
        );
        assert_eq!(
            run(&mut translator, &packet(0xA, 501, 9160, b"a"), 160),
            (false, 101, 5160, EGRESS)
        );
        assert_eq!(
            run(&mut translator, &packet(0xB, 7, 70, b"b"), 480),
            (true, 102, 5480, EGRESS)
        );
        assert_eq!(
            run(&mut translator, &packet(0xB, 8, 230, b"b"), 640),
            (false, 103, 5640, EGRESS)
        );
        assert_eq!(
            run(&mut translator, &packet(0xA, 502, 9320, b"a"), 800),
            (true, 104, 5800, EGRESS)
        );
        assert_eq!(
            run(&mut translator, &packet(0xA, 503, 9480, b"a"), 960),
            (false, 105, 5960, EGRESS)
        );
    }

    #[test]
    fn explicit_switch_rebases_even_with_the_same_ssrc() {
        let mut translator = Translator::new(EGRESS, 1, 1000);
        run(&mut translator, &packet(5, 50, 500, b"x"), 0);
        translator.switch_source();
        assert_eq!(
            run(&mut translator, &packet(5, 51, 660, b"x"), 160),
            (true, 2, 1160, EGRESS)
        );
    }

    #[test]
    fn in_source_gap_is_preserved() {
        let mut translator = Translator::new(EGRESS, 100, 5000);
        run(&mut translator, &packet(1, 10, 1000, b"a"), 0);
        assert_eq!(
            run(&mut translator, &packet(1, 13, 1480, b"a"), 480),
            (false, 103, 5480, EGRESS)
        );
    }

    #[test]
    fn sequence_wraps_at_65535() {
        let mut translator = Translator::new(EGRESS, 65534, 5000);
        run(&mut translator, &packet(1, 65534, 1000, b"a"), 0);
        assert_eq!(
            run(&mut translator, &packet(1, 65535, 1160, b"a"), 160).1,
            65535
        );
        assert_eq!(run(&mut translator, &packet(1, 0, 1320, b"a"), 320).1, 0);
        assert_eq!(run(&mut translator, &packet(1, 1, 1480, b"a"), 480).1, 1);
    }

    #[test]
    fn timestamp_wraps() {
        let mut translator = Translator::new(EGRESS, 1, u32::MAX - 100);
        run(&mut translator, &packet(1, 1, u32::MAX - 50, b"a"), 0);
        assert_eq!(run(&mut translator, &packet(1, 2, 110, b"a"), 160).2, 60);
        assert_eq!(run(&mut translator, &packet(2, 9, 0, b"a"), 320).2, 220);
    }

    #[test]
    fn reordered_and_duplicate_packets_map_consistently() {
        let mut translator = Translator::new(EGRESS, 100, 5000);
        run(&mut translator, &packet(1, 10, 1000, b"a"), 0);
        run(&mut translator, &packet(1, 12, 1320, b"a"), 320);
        assert_eq!(
            run(&mut translator, &packet(1, 11, 1160, b"a"), 330),
            (false, 101, 5160, EGRESS)
        );
        assert_eq!(
            run(&mut translator, &packet(1, 12, 1320, b"a"), 340),
            (false, 102, 5320, EGRESS)
        );
        assert_eq!(translator.last_sequence(), 102);
        assert_eq!(translator.last_timestamp(), 5320);
        assert_eq!(run(&mut translator, &packet(1, 13, 1480, b"a"), 350).1, 103);
    }

    #[test]
    fn stale_old_source_packet_after_switch_is_dropped() {
        let mut translator = Translator::new(EGRESS, 100, 5000);
        run(&mut translator, &packet(0xA, 10, 1000, b"a"), 0);
        run(&mut translator, &packet(0xA, 11, 1160, b"a"), 160);
        run(&mut translator, &packet(0xB, 1, 0, b"b"), 320);
        let mut out = [0u8; 64];
        for sequence in [11u16, 10] {
            assert_eq!(
                translator
                    .translate(&packet(0xA, sequence, 1000, b"a"), 330, &mut out)
                    .unwrap(),
                Forwarded::DroppedStale
            );
        }
        assert_eq!(translator.packets_sent(), 3);
        // B is still the current source and unmarked.
        assert_eq!(
            run(&mut translator, &packet(0xB, 2, 160, b"b"), 340),
            (false, 103, 5480, EGRESS)
        );
        // A talking again (ahead of its high-water mark) rebases.
        assert!(run(&mut translator, &packet(0xA, 12, 1320, b"a"), 500).0);
    }

    #[test]
    fn counters_track_packets_octets_and_last_timestamp() {
        let mut translator = Translator::new(EGRESS, 100, 5000);
        assert_eq!(translator.egress_ssrc(), EGRESS);
        assert_eq!(translator.last_timestamp(), 5000);
        run(&mut translator, &packet(1, 1, 0, &[0u8; 160]), 0);
        run(&mut translator, &packet(1, 2, 160, &[0u8; 100]), 160);
        assert_eq!(translator.packets_sent(), 2);
        assert_eq!(translator.octets_sent(), 260);
        assert_eq!(translator.last_timestamp(), 5160);
    }

    #[test]
    fn csrcs_and_extension_are_dropped_padding_is_kept() {
        // V=2, P=1, X=1, CC=1; one CSRC; one-word extension; payload "abc"; 4 padding octets.
        let mut inbound = vec![0xB1, 96, 0, 7, 0, 0, 0, 100, 0, 0, 0, 9];
        inbound.extend_from_slice(&[0, 0, 0, 0x77]);
        inbound.extend_from_slice(&[0xBE, 0xDE, 0, 1, 1, 2, 3, 4]);
        inbound.extend_from_slice(b"abc");
        inbound.extend_from_slice(&[0, 0, 0, 4]);
        let mut translator = Translator::new(EGRESS, 1, 1);
        let mut out = [0u8; 128];
        let Forwarded::Packet { length, .. } = translator.translate(&inbound, 0, &mut out).unwrap()
        else {
            panic!()
        };
        assert_eq!(out[0], 0xA0); // V=2, P=1, X=0, CC=0
        assert_eq!(length, 12 + 3 + 4);
        let parsed = RtpPacket::parse(&out[..length]).unwrap();
        assert_eq!(parsed.payload, b"abc");
        assert_eq!(parsed.csrc_count, 0);
        assert_eq!(&out[length - 4..length], &[0, 0, 0, 4]);
        assert_eq!(translator.octets_sent(), 3);
    }

    #[test]
    fn output_buffer_too_small_errors_without_state_change() {
        let mut translator = Translator::new(EGRESS, 100, 5000);
        let inbound = packet(1, 1, 0, &[0u8; 160]);
        let mut small = [0u8; 100];
        assert_eq!(
            translator.translate(&inbound, 0, &mut small),
            Err(TranslatorError::Rtp(RtpError::OutputTooSmall {
                needed: 172,
                have: 100
            }))
        );
        assert_eq!(translator.packets_sent(), 0);
        assert_eq!(run(&mut translator, &inbound, 0), (true, 100, 5000, EGRESS));
    }

    #[test]
    fn malformed_input_errors() {
        let mut translator = Translator::new(EGRESS, 1, 1);
        let mut out = [0u8; 64];
        assert_eq!(
            translator.translate(&[], 0, &mut out),
            Err(TranslatorError::Rtp(RtpError::TooShort))
        );
        assert_eq!(
            translator.translate(&[0x40; 12], 0, &mut out),
            Err(TranslatorError::Rtp(RtpError::BadVersion(1)))
        );
        let mut bad_padding = packet(1, 1, 1, b"a");
        bad_padding[0] |= 0x20;
        *bad_padding.last_mut().unwrap() = 0;
        assert_eq!(
            translator.translate(&bad_padding, 0, &mut out),
            Err(TranslatorError::Rtp(RtpError::BadPadding))
        );
        assert!(TranslatorError::Rtp(RtpError::TooShort)
            .to_string()
            .contains("too short"));
    }

    proptest! {
        #[test]
        fn in_order_schedules_keep_sequence_and_timestamp_continuous(
            steps in proptest::collection::vec((0u8..3, 1u32..2000), 1..200),
            initial_sequence in any::<u16>(),
            initial_timestamp in any::<u32>(),
            start_clock in any::<u32>(),
        ) {
            let mut translator = Translator::new(EGRESS, initial_sequence, initial_timestamp);
            let mut counters = [(100u16, 7000u32); 3];
            let mut clock = start_clock;
            let mut previous: Option<(u16, u32)> = None;
            let mut out = [0u8; 64];
            for (source, advance) in steps {
                clock = clock.wrapping_add(advance);
                let (sequence, timestamp) = counters[source as usize];
                counters[source as usize] = (sequence.wrapping_add(1), timestamp.wrapping_add(160));
                let inbound = packet(u32::from(source) + 1, sequence, timestamp, b"xy");
                let outcome = translator.translate(&inbound, clock, &mut out).unwrap();
                if let Forwarded::Packet { length, .. } = outcome {
                    let parsed = RtpPacket::parse(&out[..length]).unwrap();
                    prop_assert_eq!(parsed.ssrc, EGRESS);
                    if let Some((last_sequence, last_timestamp)) = previous {
                        prop_assert_eq!(parsed.sequence, last_sequence.wrapping_add(1));
                        prop_assert!((parsed.timestamp.wrapping_sub(last_timestamp) as i32) >= 0);
                    }
                    previous = Some((parsed.sequence, parsed.timestamp));
                }
            }
        }

        #[test]
        fn arbitrary_bytes_never_panic(
            data in proptest::collection::vec(any::<u8>(), 0..64),
            clock in any::<u32>(),
        ) {
            let mut translator = Translator::new(EGRESS, 1, 1);
            let mut out = [0u8; 16];
            let _ = translator.translate(&data, clock, &mut out);
            translator.switch_source();
            let _ = translator.translate(&data, clock, &mut out);
        }
    }
}
