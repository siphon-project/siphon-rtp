//! RTP packet parsing and construction (RFC 3550 §5).
//!
//! Parsing is zero-copy: [`RtpPacket::parse`] borrows the input and exposes the payload as a
//! slice (padding stripped, CSRC list and header extension skipped). Construction writes a plain
//! 12-byte header into a caller-owned buffer — no per-packet heap allocation on the hot path.

/// Errors from RTP parsing/serialization.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RtpError {
    /// The buffer is shorter than the fields it claims to contain.
    #[error("RTP packet too short")]
    TooShort,
    /// The version field was not 2.
    #[error("unsupported RTP version {0}")]
    BadVersion(u8),
    /// The padding count was zero or exceeded the available payload.
    #[error("invalid RTP padding")]
    BadPadding,
    /// The output buffer cannot hold the packet.
    #[error("output buffer too small: need {needed}, have {have}")]
    OutputTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        have: usize,
    },
    /// More contributing sources than the 4-bit CC field can carry (RFC 3550 §5.1).
    #[error("too many CSRCs: {count} exceeds the {max} the CC field holds")]
    TooManyCsrcs {
        /// The CSRC count requested.
        count: usize,
        /// The enforced ceiling ([`MAX_CSRC_COUNT`]).
        max: usize,
    },
}

/// RTP version this implementation speaks.
pub const RTP_VERSION: u8 = 2;
/// Fixed RTP header size before CSRCs / extension (RFC 3550 §5.1).
pub const FIXED_HEADER_LEN: usize = 12;

/// A parsed RTP packet borrowing its source buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    /// Marker bit (codec-specific; e.g. talk-spurt start, DTMF end).
    pub marker: bool,
    /// Payload type (RFC 3551 / dynamically negotiated).
    pub payload_type: u8,
    /// Sequence number (per-packet, wraps).
    pub sequence: u16,
    /// Media timestamp (codec sample clock).
    pub timestamp: u32,
    /// Synchronization source identifier.
    pub ssrc: u32,
    /// Number of contributing sources present in the header (their values are skipped).
    pub csrc_count: u8,
    /// The contributing-source (CSRC) list bytes, immediately after the fixed header — `csrc_count`
    /// big-endian `u32`s (RFC 3550 §5.1). An RTP mixer stamps these to identify the sources of the
    /// payload; read one with [`RtpPacket::csrc`]. Empty when `csrc_count == 0`.
    pub csrcs: &'a [u8],
    /// The media payload (header, CSRCs, extension, and any padding removed).
    pub payload: &'a [u8],
}

impl<'a> RtpPacket<'a> {
    /// Parse one RTP packet from `buffer`, validating lengths without panicking.
    pub fn parse(buffer: &'a [u8]) -> Result<Self, RtpError> {
        if buffer.len() < FIXED_HEADER_LEN {
            return Err(RtpError::TooShort);
        }
        let byte0 = buffer[0];
        let version = byte0 >> 6;
        if version != RTP_VERSION {
            return Err(RtpError::BadVersion(version));
        }
        let has_padding = byte0 & 0x20 != 0;
        let has_extension = byte0 & 0x10 != 0;
        let csrc_count = byte0 & 0x0F;

        let byte1 = buffer[1];
        let marker = byte1 & 0x80 != 0;
        let payload_type = byte1 & 0x7F;
        let sequence = u16::from_be_bytes([buffer[2], buffer[3]]);
        let timestamp = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let ssrc = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);

        let csrc_bytes = 4 * csrc_count as usize;
        let mut offset = FIXED_HEADER_LEN + csrc_bytes;
        if buffer.len() < offset {
            return Err(RtpError::TooShort);
        }
        let csrcs = &buffer[FIXED_HEADER_LEN..offset];
        if has_extension {
            if buffer.len() < offset + 4 {
                return Err(RtpError::TooShort);
            }
            let words = u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]) as usize;
            offset += 4 + words * 4;
            if buffer.len() < offset {
                return Err(RtpError::TooShort);
            }
        }

        let mut end = buffer.len();
        if has_padding {
            let pad = buffer[end - 1] as usize;
            if pad == 0 || pad > end - offset {
                return Err(RtpError::BadPadding);
            }
            end -= pad;
        }

        Ok(RtpPacket {
            marker,
            payload_type,
            sequence,
            timestamp,
            ssrc,
            csrc_count,
            csrcs,
            payload: &buffer[offset..end],
        })
    }

    /// The `index`-th contributing source (CSRC), or `None` past [`RtpPacket::csrc_count`]
    /// (RFC 3550 §5.1). A multiparty RTT receiver reads CSRC 0 to attribute the packet to its source
    /// (RFC 9071 §4.2).
    #[must_use]
    pub fn csrc(&self, index: usize) -> Option<u32> {
        let start = index.checked_mul(4)?;
        let bytes = self.csrcs.get(start..start + 4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// The mutable fields needed to emit a fresh RTP packet (no CSRCs / extension / padding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    /// Marker bit.
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence: u16,
    /// Media timestamp.
    pub timestamp: u32,
    /// Synchronization source.
    pub ssrc: u32,
}

/// The largest CSRC count the 4-bit CC field can carry (RFC 3550 §5.1).
pub const MAX_CSRC_COUNT: usize = 15;

/// Write `header` + `payload` as a 12-byte-header RTP packet into `out`, returning its length.
pub fn write_packet(header: &RtpHeader, payload: &[u8], out: &mut [u8]) -> Result<usize, RtpError> {
    write_packet_with_csrcs(header, &[], payload, out)
}

/// Write `header` + a CSRC list + `payload` as an RTP packet into `out`, returning its length
/// (RFC 3550 §5.1). The CSRC list carries the contributing sources' SSRCs — an RTP **mixer** stamps
/// it so a receiver can attribute the payload to its originating source(s); this is exactly the
/// source-identification RFC 9071 §4.2 requires for multiparty real-time text (the mixer relabels its
/// egress stream with the contributing participant's SSRC as a CSRC). `write_packet` is the CC=0 case.
///
/// # Errors
/// [`RtpError::OutputTooSmall`] if `out` cannot hold the header + CSRCs + payload;
/// [`RtpError::TooManyCsrcs`] if `csrcs` exceeds the [`MAX_CSRC_COUNT`] the 4-bit CC field holds.
pub fn write_packet_with_csrcs(
    header: &RtpHeader,
    csrcs: &[u32],
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, RtpError> {
    if csrcs.len() > MAX_CSRC_COUNT {
        return Err(RtpError::TooManyCsrcs {
            count: csrcs.len(),
            max: MAX_CSRC_COUNT,
        });
    }
    let csrc_bytes = csrcs.len() * 4;
    let total = FIXED_HEADER_LEN + csrc_bytes + payload.len();
    if out.len() < total {
        return Err(RtpError::OutputTooSmall {
            needed: total,
            have: out.len(),
        });
    }
    // V=2, P=0, X=0, CC=csrcs.len() (RFC 3550 §5.1: CC counts the contributing sources present).
    out[0] = (RTP_VERSION << 6) | (csrcs.len() as u8 & 0x0F);
    out[1] = ((header.marker as u8) << 7) | (header.payload_type & 0x7F);
    out[2..4].copy_from_slice(&header.sequence.to_be_bytes());
    out[4..8].copy_from_slice(&header.timestamp.to_be_bytes());
    out[8..12].copy_from_slice(&header.ssrc.to_be_bytes());
    for (index, csrc) in csrcs.iter().enumerate() {
        let start = FIXED_HEADER_LEN + index * 4;
        out[start..start + 4].copy_from_slice(&csrc.to_be_bytes());
    }
    out[FIXED_HEADER_LEN + csrc_bytes..total].copy_from_slice(payload);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A µ-law packet: V2, PT0, marker set, seq 0x0102, ts 0x0A0B0C0D, ssrc 0x11223344, 4B payload.
    const SAMPLE: [u8; 16] = [
        0x80, 0x80, 0x01, 0x02, 0x0A, 0x0B, 0x0C, 0x0D, 0x11, 0x22, 0x33, 0x44, 0xDE, 0xAD, 0xBE,
        0xEF,
    ];

    #[test]
    fn parses_fixed_header() {
        let packet = RtpPacket::parse(&SAMPLE).expect("parse");
        assert!(packet.marker);
        assert_eq!(packet.payload_type, 0);
        assert_eq!(packet.sequence, 0x0102);
        assert_eq!(packet.timestamp, 0x0A0B_0C0D);
        assert_eq!(packet.ssrc, 0x1122_3344);
        assert_eq!(packet.csrc_count, 0);
        assert_eq!(packet.payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn build_then_parse_roundtrip() {
        let header = RtpHeader {
            marker: false,
            payload_type: 8,
            sequence: 40000,
            timestamp: 160 * 7,
            ssrc: 0xCAFE_BABE,
        };
        let payload = [1u8, 2, 3, 4, 5];
        let mut out = [0u8; 32];
        let len = write_packet(&header, &payload, &mut out).expect("write");
        assert_eq!(len, FIXED_HEADER_LEN + payload.len());

        let parsed = RtpPacket::parse(&out[..len]).expect("parse");
        assert!(!parsed.marker);
        assert_eq!(parsed.payload_type, 8);
        assert_eq!(parsed.sequence, 40000);
        assert_eq!(parsed.timestamp, 160 * 7);
        assert_eq!(parsed.ssrc, 0xCAFE_BABE);
        assert_eq!(parsed.payload, &payload);
    }

    #[test]
    fn skips_csrcs() {
        // CC=2 → two 4-byte CSRCs between the fixed header and payload.
        let mut buffer = vec![0x82, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        buffer.extend_from_slice(&[0xAA; 8]); // 2 CSRCs
        buffer.extend_from_slice(&[0x77, 0x88]); // payload
        let packet = RtpPacket::parse(&buffer).expect("parse");
        assert_eq!(packet.csrc_count, 2);
        assert_eq!(packet.payload, &[0x77, 0x88]);
        assert_eq!(packet.csrc(0), Some(0xAAAA_AAAA));
        assert_eq!(packet.csrc(1), Some(0xAAAA_AAAA));
        assert_eq!(packet.csrc(2), None, "past the CSRC count");
    }

    #[test]
    fn writes_and_parses_a_single_csrc() {
        // An RTP mixer stamps the contributing source's SSRC as CSRC 0 (RFC 3550 §5.1 / RFC 9071 §4.2).
        let header = RtpHeader {
            marker: true,
            payload_type: 98,
            sequence: 7,
            timestamp: 3000,
            ssrc: 0xFEED_F00D,
        };
        let mut out = [0u8; 64];
        let len = write_packet_with_csrcs(&header, &[0x1234_5678], b"Hi", &mut out).expect("write");
        // Fixed header (12) + one CSRC (4) + payload (2).
        assert_eq!(len, FIXED_HEADER_LEN + 4 + 2);
        assert_eq!(out[0] & 0x0F, 1, "CC field counts the one CSRC");

        let packet = RtpPacket::parse(&out[..len]).expect("parse");
        assert!(packet.marker);
        assert_eq!(packet.payload_type, 98);
        assert_eq!(packet.ssrc, 0xFEED_F00D);
        assert_eq!(packet.csrc_count, 1);
        assert_eq!(
            packet.csrc(0),
            Some(0x1234_5678),
            "source identity preserved"
        );
        assert_eq!(packet.payload, b"Hi");
    }

    #[test]
    fn write_packet_is_the_zero_csrc_case() {
        // `write_packet` must be byte-identical to `write_packet_with_csrcs(.., &[], ..)`.
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence: 42,
            timestamp: 160,
            ssrc: 0xABCD_1234,
        };
        let mut plain = [0u8; 32];
        let mut via_csrc = [0u8; 32];
        let plain_len = write_packet(&header, &[9, 8, 7], &mut plain).expect("plain");
        let csrc_len =
            write_packet_with_csrcs(&header, &[], &[9, 8, 7], &mut via_csrc).expect("csrc");
        assert_eq!(&plain[..plain_len], &via_csrc[..csrc_len]);
    }

    #[test]
    fn write_rejects_more_than_fifteen_csrcs() {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
        };
        let csrcs = [0u32; MAX_CSRC_COUNT + 1];
        let mut out = [0u8; 128];
        assert!(matches!(
            write_packet_with_csrcs(&header, &csrcs, &[1], &mut out),
            Err(RtpError::TooManyCsrcs { count, max }) if count == MAX_CSRC_COUNT + 1 && max == MAX_CSRC_COUNT
        ));
    }

    #[test]
    fn skips_header_extension() {
        // X=1, extension = 1 word (4 bytes) of data after the 4-byte ext header.
        let mut buffer = vec![0x90, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        buffer.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01]); // ext header: id, length=1 word
        buffer.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // ext data
        buffer.extend_from_slice(&[0x99]); // payload
        let packet = RtpPacket::parse(&buffer).expect("parse");
        assert_eq!(packet.payload, &[0x99]);
    }

    #[test]
    fn strips_padding() {
        // P=1; 3 padding bytes at the end, last byte = 3.
        let mut buffer = vec![0xA0, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        buffer.extend_from_slice(&[0x42]); // 1 payload byte
        buffer.extend_from_slice(&[0x00, 0x00, 0x03]); // padding, count=3
        let packet = RtpPacket::parse(&buffer).expect("parse");
        assert_eq!(packet.payload, &[0x42]);
    }

    #[test]
    fn rejects_short_and_bad_version() {
        assert_eq!(RtpPacket::parse(&[0u8; 8]), Err(RtpError::TooShort));
        let mut bad = SAMPLE;
        bad[0] = 0x40; // version 1
        assert_eq!(RtpPacket::parse(&bad), Err(RtpError::BadVersion(1)));
    }

    #[test]
    fn rejects_bad_padding() {
        let mut buffer = vec![0xA0, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        buffer.extend_from_slice(&[0x10]); // last byte = 16 > available
        assert_eq!(RtpPacket::parse(&buffer), Err(RtpError::BadPadding));
    }

    #[test]
    fn write_rejects_small_output() {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 0,
            ssrc: 0,
        };
        let mut out = [0u8; 8];
        assert!(matches!(
            write_packet(&header, &[1, 2, 3, 4], &mut out),
            Err(RtpError::OutputTooSmall { .. })
        ));
    }

    use proptest::prelude::*;

    proptest! {
        /// A hostile datagram off the network must decode-or-error — never panic / OOB / spin.
        #[test]
        fn parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = RtpPacket::parse(&bytes);
        }

        /// `parse(write(header, payload))` round-trips every field over arbitrary valid headers.
        #[test]
        fn write_then_parse_roundtrips(
            marker in any::<bool>(),
            payload_type in 0u8..=127,
            sequence in any::<u16>(),
            timestamp in any::<u32>(),
            ssrc in any::<u32>(),
            payload in prop::collection::vec(any::<u8>(), 0..1400),
        ) {
            let header = RtpHeader { marker, payload_type, sequence, timestamp, ssrc };
            let mut out = vec![0u8; FIXED_HEADER_LEN + payload.len()];
            let len = write_packet(&header, &payload, &mut out).expect("sized buffer fits");
            let parsed = RtpPacket::parse(&out[..len]).expect("parse our own packet");
            prop_assert_eq!(parsed.marker, marker);
            prop_assert_eq!(parsed.payload_type, payload_type);
            prop_assert_eq!(parsed.sequence, sequence);
            prop_assert_eq!(parsed.timestamp, timestamp);
            prop_assert_eq!(parsed.ssrc, ssrc);
            prop_assert_eq!(parsed.payload, &payload[..]);
        }
    }
}
