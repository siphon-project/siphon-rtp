//! Reading PDU headers **from** a peer.
//!
//! The delivery client is mostly a writer, but it has to read two things off the connection to the
//! Mediation Function: where each PDU ends (so a TCP byte stream can be split back into PDUs) and
//! whether one is a keepalive acknowledgement. That is a parser fed by an untrusted network peer,
//! so it never panics, never indexes without a bounds check, and never trusts a length field far
//! enough to allocate on it.
//!
//! The enumerated fields are kept as **raw** `u16`s rather than mapped into this crate's closed
//! enums. A peer may legitimately send a PDU type, payload format or direction from a later
//! specification revision; refusing it here — or, worse, silently coercing it — would turn a
//! forward-compatible peer into a connection failure. The delivery client only needs to recognise
//! the types it acts on, and can ignore the rest.

use crate::{HEADER_LEN, VERSION_MAJOR, VERSION_MINOR};

/// Why an inbound PDU header could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`HEADER_LEN`] bytes are available. Not an error on a stream transport — the
    /// caller should read more and retry — which is why it carries how many bytes are needed.
    Incomplete {
        /// Total bytes needed before the header can be read.
        needed: usize,
    },
    /// `Header Length` is smaller than the fixed header, so the conditional-attribute block would
    /// have a negative size. A malformed or hostile peer.
    HeaderLengthTooSmall {
        /// The value the peer sent.
        header_length: u32,
    },
    /// The declared PDU does not fit in `usize` on this platform.
    LengthOverflow,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete { needed } => {
                write!(formatter, "need {needed} bytes for a PDU header")
            }
            Self::HeaderLengthTooSmall { header_length } => write!(
                formatter,
                "Header Length {header_length} is below the {HEADER_LEN}-byte fixed header"
            ),
            Self::LengthOverflow => write!(formatter, "declared PDU length overflows usize"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The fixed header of a PDU received from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundHeader {
    /// PDU format major version (high byte of `Version`).
    pub version_major: u8,
    /// PDU format minor version (low byte of `Version`).
    pub version_minor: u8,
    /// Raw PDU Type. Compare against [`crate::PduType::to_u16`] rather than assuming it is one of
    /// the four this crate models.
    pub pdu_type: u16,
    /// Declared header size: the fixed 40 bytes plus the conditional-attribute block.
    pub header_length: u32,
    /// Declared payload size.
    pub payload_length: u32,
    /// Raw Payload Format.
    pub payload_format: u16,
    /// Raw Payload Direction.
    pub payload_direction: u16,
    /// The interception task identifier, carried opaquely.
    pub xid: [u8; 16],
    /// The session correlation, carried opaquely.
    pub correlation_id: u64,
}

impl InboundHeader {
    /// Read a fixed header from the front of `bytes`.
    ///
    /// Only the header is consumed; [`InboundHeader::total_len`] says how long the whole PDU is, so
    /// a stream reader can wait for the rest.
    ///
    /// # Errors
    ///
    /// [`ParseError::Incomplete`] when fewer than [`HEADER_LEN`] bytes are available;
    /// [`ParseError::HeaderLengthTooSmall`] when `Header Length` undercuts the fixed header.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LEN {
            return Err(ParseError::Incomplete { needed: HEADER_LEN });
        }
        // Every read below is inside the length check above; the slices are fixed-size so the
        // array conversions cannot fail.
        let header_length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if (header_length as usize) < HEADER_LEN {
            return Err(ParseError::HeaderLengthTooSmall { header_length });
        }
        let mut xid = [0u8; 16];
        xid.copy_from_slice(&bytes[16..32]);
        let mut correlation = [0u8; 8];
        correlation.copy_from_slice(&bytes[32..40]);

        Ok(Self {
            version_major: bytes[0],
            version_minor: bytes[1],
            pdu_type: u16::from_be_bytes([bytes[2], bytes[3]]),
            header_length,
            payload_length: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            payload_format: u16::from_be_bytes([bytes[12], bytes[13]]),
            payload_direction: u16::from_be_bytes([bytes[14], bytes[15]]),
            xid,
            correlation_id: u64::from_be_bytes(correlation),
        })
    }

    /// Total wire size of this PDU: `Header Length + Payload Length`.
    ///
    /// This is the framing a stream transport splits on. Computed in `u64` and only then narrowed,
    /// so two large-but-legal `u32`s cannot wrap into a small length and desynchronise the stream.
    ///
    /// # Errors
    ///
    /// [`ParseError::LengthOverflow`] if the total does not fit `usize`.
    pub fn total_len(&self) -> Result<usize, ParseError> {
        let total = u64::from(self.header_length) + u64::from(self.payload_length);
        usize::try_from(total).map_err(|_| ParseError::LengthOverflow)
    }

    /// Size of the conditional-attribute block: `Header Length` beyond the fixed header. Never
    /// underflows — [`InboundHeader::parse`] rejects a `Header Length` below [`HEADER_LEN`].
    #[must_use]
    pub fn attributes_len(&self) -> usize {
        self.header_length as usize - HEADER_LEN
    }

    /// Whether the peer's PDU format version is the one this crate writes. A mismatch is worth
    /// logging, but it is the caller's policy decision whether to keep the connection.
    #[must_use]
    pub fn version_matches(&self) -> bool {
        self.version_major == VERSION_MAJOR && self.version_minor == VERSION_MINOR
    }

    /// Whether this is a keepalive acknowledgement (PDU type 4) — what the Mediation Function
    /// answers an idle-connection keepalive with.
    #[must_use]
    pub fn is_keepalive_acknowledgement(&self) -> bool {
        self.pdu_type == crate::PduType::KeepaliveAcknowledgement.to_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, PayloadDirection, PduHeader, PduType};

    #[test]
    fn reads_back_a_header_this_crate_wrote() {
        // Not the conformance check — that is the independent decoder in tests/dissector.rs. This
        // only pins that the reader agrees with the writer on field placement.
        let header = PduHeader::x3_rtp(
            [0x5a; 16],
            0x0102_0304_0506_0708,
            PayloadDirection::ToTarget,
        );
        let mut pdu = Vec::new();
        encode(&header, &[0u8; 8], &[0u8; 20], &mut pdu).expect("encode");

        let parsed = InboundHeader::parse(&pdu).expect("parse");
        assert_eq!(parsed.version_major, VERSION_MAJOR);
        assert_eq!(parsed.version_minor, VERSION_MINOR);
        assert_eq!(parsed.pdu_type, PduType::X3.to_u16());
        assert_eq!(parsed.header_length, (HEADER_LEN + 8) as u32);
        assert_eq!(parsed.payload_length, 20);
        assert_eq!(
            parsed.payload_direction,
            PayloadDirection::ToTarget.to_u16()
        );
        assert_eq!(parsed.xid, [0x5a; 16]);
        assert_eq!(parsed.correlation_id, 0x0102_0304_0506_0708);
        assert_eq!(parsed.attributes_len(), 8);
        assert_eq!(parsed.total_len().expect("total"), pdu.len());
        assert!(parsed.version_matches());
    }

    #[test]
    fn recognises_a_keepalive_acknowledgement() {
        let mut pdu = Vec::new();
        encode(&PduHeader::keepalive(), &[], &[], &mut pdu).expect("encode");
        // Rewrite the type in place: the peer sends 4 where we send 3.
        pdu[2..4].copy_from_slice(&PduType::KeepaliveAcknowledgement.to_u16().to_be_bytes());

        let parsed = InboundHeader::parse(&pdu).expect("parse");
        assert!(parsed.is_keepalive_acknowledgement());
        assert_eq!(parsed.total_len().expect("total"), HEADER_LEN);
    }

    #[test]
    fn a_keepalive_is_not_its_own_acknowledgement() {
        let mut pdu = Vec::new();
        encode(&PduHeader::keepalive(), &[], &[], &mut pdu).expect("encode");
        assert!(!InboundHeader::parse(&pdu)
            .expect("parse")
            .is_keepalive_acknowledgement());
    }

    #[test]
    fn asks_for_more_bytes_rather_than_failing_on_a_short_read() {
        // A stream transport hits this on every partial read; it must be a "read more", not an
        // error that tears the connection down.
        for length in 0..HEADER_LEN {
            assert_eq!(
                InboundHeader::parse(&vec![0u8; length]),
                Err(ParseError::Incomplete { needed: HEADER_LEN }),
                "length {length}"
            );
        }
    }

    #[test]
    fn rejects_a_header_length_below_the_fixed_header() {
        // Would underflow `attributes_len`. A hostile peer's cheapest attack on a naive reader.
        let mut pdu = Vec::new();
        encode(&PduHeader::keepalive(), &[], &[], &mut pdu).expect("encode");
        pdu[4..8].copy_from_slice(&39u32.to_be_bytes());
        assert_eq!(
            InboundHeader::parse(&pdu),
            Err(ParseError::HeaderLengthTooSmall { header_length: 39 })
        );
    }

    #[test]
    fn accepts_a_header_length_of_exactly_the_fixed_header() {
        let mut pdu = Vec::new();
        encode(&PduHeader::keepalive(), &[], &[], &mut pdu).expect("encode");
        let parsed = InboundHeader::parse(&pdu).expect("parse");
        assert_eq!(parsed.attributes_len(), 0);
    }

    #[test]
    fn two_large_lengths_do_not_wrap_into_a_small_total() {
        // The desynchronisation bug: if the total were computed in u32, 0xffff_ffff + 0xffff_ffff
        // would wrap to a small number and the reader would resume mid-PDU.
        let header = InboundHeader {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            pdu_type: PduType::X3.to_u16(),
            header_length: u32::MAX,
            payload_length: u32::MAX,
            payload_format: 8,
            payload_direction: 3,
            xid: [0; 16],
            correlation_id: 1,
        };
        let total = header.total_len().expect("64-bit usize holds this");
        assert_eq!(total, u32::MAX as usize * 2);
    }

    #[test]
    fn keeps_enumerated_fields_raw_so_a_newer_peer_is_not_rejected() {
        // A PDU type from a later revision must parse, not error: the client ignores what it does
        // not act on rather than dropping the connection.
        let mut pdu = Vec::new();
        encode(&PduHeader::keepalive(), &[], &[], &mut pdu).expect("encode");
        pdu[2..4].copy_from_slice(&999u16.to_be_bytes());
        pdu[12..14].copy_from_slice(&888u16.to_be_bytes());

        let parsed = InboundHeader::parse(&pdu).expect("an unknown type still parses");
        assert_eq!(parsed.pdu_type, 999);
        assert_eq!(parsed.payload_format, 888);
        assert!(!parsed.is_keepalive_acknowledgement());
    }

    #[test]
    fn reports_a_version_mismatch_without_refusing_to_parse() {
        let mut pdu = Vec::new();
        encode(&PduHeader::keepalive(), &[], &[], &mut pdu).expect("encode");
        pdu[0] = 9;
        let parsed = InboundHeader::parse(&pdu).expect("parse");
        assert_eq!(parsed.version_major, 9);
        assert!(!parsed.version_matches());
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // A cheap standing guard beside the libFuzzer target: every length and a rolling byte
        // pattern, asserting only that nothing panics and that a success is self-consistent.
        for length in 0..=(HEADER_LEN + 8) {
            for seed in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let bytes: Vec<u8> = (0..length)
                    .map(|index| seed.wrapping_add(index as u8))
                    .collect();
                if let Ok(parsed) = InboundHeader::parse(&bytes) {
                    assert!(parsed.header_length as usize >= HEADER_LEN);
                    let _ = parsed.total_len();
                    let _ = parsed.attributes_len();
                }
            }
        }
    }

    #[test]
    fn error_messages_describe_the_failure() {
        assert!(ParseError::Incomplete { needed: 40 }
            .to_string()
            .contains("40"));
        assert!(ParseError::HeaderLengthTooSmall { header_length: 3 }
            .to_string()
            .contains('3'));
        assert!(ParseError::LengthOverflow.to_string().contains("overflow"));
    }
}
