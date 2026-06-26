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

        let mut offset = FIXED_HEADER_LEN + 4 * csrc_count as usize;
        if buffer.len() < offset {
            return Err(RtpError::TooShort);
        }
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
            payload: &buffer[offset..end],
        })
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

/// Write `header` + `payload` as a 12-byte-header RTP packet into `out`, returning its length.
pub fn write_packet(header: &RtpHeader, payload: &[u8], out: &mut [u8]) -> Result<usize, RtpError> {
    let total = FIXED_HEADER_LEN + payload.len();
    if out.len() < total {
        return Err(RtpError::OutputTooSmall {
            needed: total,
            have: out.len(),
        });
    }
    out[0] = RTP_VERSION << 6; // V=2, P=0, X=0, CC=0
    out[1] = ((header.marker as u8) << 7) | (header.payload_type & 0x7F);
    out[2..4].copy_from_slice(&header.sequence.to_be_bytes());
    out[4..8].copy_from_slice(&header.timestamp.to_be_bytes());
    out[8..12].copy_from_slice(&header.ssrc.to_be_bytes());
    out[FIXED_HEADER_LEN..total].copy_from_slice(payload);
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
