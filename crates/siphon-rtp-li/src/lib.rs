//! ETSI TS 103 221-2 X2/X3 PDU framing — the wire format a Mediation/Delivery Function ingests for
//! lawful-interception Interception Related Information (X2) and Content of Communication (X3).
//!
//! This crate owns clause 5 and nothing else: no sockets, no engine types, no interpretation of the
//! identifiers it carries. The engine frames intercepted media with it and ships the bytes; the XID
//! and Correlation ID originate in the signalling plane's X1 provisioning and are copied through
//! opaquely.
//!
//! A PDU is a fixed 40-byte big-endian header, then a block of Type-Length-Value conditional
//! attributes, then the payload:
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-------------------------------+-------------------------------+
//! |            Version            |           PDU Type            |
//! +-------------------------------+-------------------------------+
//! |                         Header Length                         |
//! +---------------------------------------------------------------+
//! |                         Payload Length                        |
//! +-------------------------------+-------------------------------+
//! |        Payload Format         |       Payload Direction       |
//! +-------------------------------+-------------------------------+
//! |                                                               |
//! |                          XID (16 bytes)                       |
//! |                                                               |
//! +---------------------------------------------------------------+
//! |                     Correlation ID (8 bytes)                  |
//! +---------------------------------------------------------------+
//! |            Conditional attributes (TLV), then payload         |
//! +---------------------------------------------------------------+
//! ```
//!
//! # Conformance
//!
//! Written against **ETSI TS 103 221-2 V1.4.1 (2021-04)**. Every constant carries its clause
//! citation at the point it is enforced.
//!
//! The wire format has an authoritative external definition, so a round-trip against this crate's
//! own reader would prove nothing — a shared encode/decode bug passes one. It is checked three ways:
//!
//! - byte-exact fixtures built by hand from the specification;
//! - a known-answer test against the header of a PDU captured from an unrelated implementation
//!   (see the tests in this module), which is what caught [`VERSION_MAJOR`] being reversed;
//! - an independent decoder — a third-party Wireshark dissector driven by `tshark` — in
//!   `tests/dissector.rs`, which also confirms the payload hands off to Wireshark's RTP dissector.
#![forbid(unsafe_code)]

pub mod attributes;
pub mod clock;
pub mod inbound;

use std::fmt;

/// The fixed PDU header size in bytes (TS 103 221-2 V1.4.1 §5.2). Every conditional attribute is
/// counted *after* this, in `Header Length`.
pub const HEADER_LEN: usize = 40;

/// PDU format major version, written to the **high** byte of the 2-byte `Version` field
/// (TS 103 221-2 V1.4.1 §5.2.1). The version on the wire is `0.5`, so these two bytes are `00 05`.
///
/// # Why 0 and not 5
///
/// The PDU format carries its own version, which is **not** the version of the specification
/// document (V1.4.1). It is easy to read the field the other way round and emit `05 00`; that is
/// wrong and a conformant Mediation Function rejects it. Three independent sources settle it:
///
/// - a real captured X2 PDU (`sipgate/li-lib-x1x2x3`, `x2-demo-01.pcap`) opens with the bytes
///   `00 05` — see the known-answer test in this module;
/// - that library's `PduObject` pins `MAJOR_VERSION = 0` / `MINOR_VERSION = 5` and **throws** on
///   any other value, so it would reject a PDU framed the other way;
/// - a third-party Wireshark dissector reads that same capture back as "Major: 0, Minor: 5".
///
/// Kept as two named constants so a future format revision is a one-line change with a failing
/// fixture, rather than a literal buried in the encoder.
pub const VERSION_MAJOR: u8 = 0;

/// PDU format minor version, written to the low byte of the `Version` field
/// (TS 103 221-2 V1.4.1 §5.2.1). See [`VERSION_MAJOR`] for the evidence behind `0.5`.
pub const VERSION_MINOR: u8 = 5;

/// A Correlation ID of zero, used only by keepalive PDUs. Clause 6 requires a *non-zero*
/// correlation on X2/X3 PDUs so the two interfaces' records for one session can be tied together;
/// [`encode`] enforces that.
const NIL_CORRELATION_ID: u64 = 0;

/// An all-zero XID, used only by keepalive PDUs (TS 103 221-2 V1.4.1 §5.2.7).
pub const NIL_XID: [u8; 16] = [0u8; 16];

/// What went wrong framing a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiError {
    /// An X2 or X3 PDU carried a zero Correlation ID. TS 103 221-2 V1.4.1 clause 6 requires a
    /// non-zero correlation so the Mediation Function can tie a session's X2 and X3 records
    /// together; delivering zero would produce content that cannot be correlated to its IRI.
    ZeroCorrelationId,
    /// The header (40 bytes plus the conditional attributes) does not fit the `Header Length`
    /// field's `u32`.
    HeaderTooLarge {
        /// The attribute block length that overflowed.
        attributes_len: usize,
    },
    /// The payload does not fit the `Payload Length` field's `u32`.
    PayloadTooLarge {
        /// The payload length that overflowed.
        payload_len: usize,
    },
}

impl fmt::Display for LiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCorrelationId => write!(
                formatter,
                "X2/X3 PDU requires a non-zero Correlation ID (TS 103 221-2 clause 6)"
            ),
            Self::HeaderTooLarge { attributes_len } => write!(
                formatter,
                "conditional attribute block of {attributes_len} bytes overflows Header Length"
            ),
            Self::PayloadTooLarge { payload_len } => write!(
                formatter,
                "payload of {payload_len} bytes overflows Payload Length"
            ),
        }
    }
}

impl std::error::Error for LiError {}

/// PDU Type (TS 103 221-2 V1.4.1 §5.2.2) — which interface, or a connection-liveness exchange.
///
/// Deliberately **not** `#[non_exhaustive]`: this is the emit-side selector for a closed set defined
/// by the specification. A later TS revision adding a type is a deliberate upgrade of this crate,
/// not something a downstream `match` should silently absorb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    /// Interception Related Information. Produced by the signalling plane, not by this engine.
    X2,
    /// Content of Communication — intercepted media.
    X3,
    /// Sent on an idle connection to keep it (and any NAT/firewall state) alive.
    Keepalive,
    /// The peer's answer to a [`PduType::Keepalive`].
    KeepaliveAcknowledgement,
}

impl PduType {
    /// The on-wire value (TS 103 221-2 V1.4.1 table 3).
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::X2 => 1,
            Self::X3 => 2,
            Self::Keepalive => 3,
            Self::KeepaliveAcknowledgement => 4,
        }
    }

    /// Whether clause 6's non-zero Correlation ID requirement applies to this PDU type. Keepalives
    /// belong to no session, so they carry a nil correlation and a [`NIL_XID`].
    #[must_use]
    const fn requires_correlation(self) -> bool {
        matches!(self, Self::X2 | Self::X3)
    }
}

/// Payload Format (TS 103 221-2 V1.4.1 §5.2.5) — how the Mediation Function should read the payload.
///
/// Only the variants this engine can actually emit are modelled; the remaining specification values
/// (ETSI TS 102 232-1, 3GPP TS 33.128, ETSI TS 133 108, proprietary, DHCP, RADIUS, GTP-U, MSRP) have
/// no producer here, and inventing an emit path for a format nothing generates would be a stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// No payload — the format a keepalive carries.
    Keepalive,
    /// A bare IPv4 packet.
    Ipv4Packet,
    /// A bare IPv6 packet.
    Ipv6Packet,
    /// An Ethernet frame.
    EthernetFrame,
    /// An RTP packet, header included. What X3 media delivery uses.
    RtpPacket,
    /// A SIP message.
    SipMessage,
}

impl PayloadFormat {
    /// The on-wire value (TS 103 221-2 V1.4.1 table 6).
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Keepalive => 0,
            Self::Ipv4Packet => 5,
            Self::Ipv6Packet => 6,
            Self::EthernetFrame => 7,
            Self::RtpPacket => 8,
            Self::SipMessage => 9,
        }
    }
}

/// Payload Direction (TS 103 221-2 V1.4.1 §5.2.6) — **target-relative**, not leg-relative.
///
/// This is the field that makes the intercept target's identity a required input: the engine knows
/// which leg is which, but only the warrant knows which leg is the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadDirection {
    /// Reserved for keepalive PDUs.
    Keepalive,
    /// The direction could not be determined.
    Unknown,
    /// Sent **to** the target — on a two-party call, the far end's media.
    ToTarget,
    /// Sent **from** the target — the target's own media.
    FromTarget,
    /// Carries both directions (a combined stream).
    MultipleDirection,
    /// Direction is not a meaningful concept for this payload.
    NotApplicable,
}

impl PayloadDirection {
    /// The on-wire value (TS 103 221-2 V1.4.1 table 7).
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Keepalive => 0,
            Self::Unknown => 1,
            Self::ToTarget => 2,
            Self::FromTarget => 3,
            Self::MultipleDirection => 4,
            Self::NotApplicable => 5,
        }
    }
}

/// The fixed part of a PDU header — everything before the conditional attributes.
///
/// `xid` and `correlation_id` are carried **opaquely**: they are provisioned over X1 in the
/// signalling plane and this crate never interprets them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduHeader {
    /// Which interface this PDU belongs to.
    pub pdu_type: PduType,
    /// How to read the payload.
    pub payload_format: PayloadFormat,
    /// Target-relative direction of the intercepted traffic.
    pub payload_direction: PayloadDirection,
    /// The 16-byte interception task identifier, provisioned over X1.
    pub xid: [u8; 16],
    /// The 8-byte session correlation. Must be non-zero on X2/X3 (clause 6).
    pub correlation_id: u64,
}

impl PduHeader {
    /// An X3 (Content of Communication) header carrying one RTP packet.
    #[must_use]
    pub const fn x3_rtp(
        xid: [u8; 16],
        correlation_id: u64,
        payload_direction: PayloadDirection,
    ) -> Self {
        Self {
            pdu_type: PduType::X3,
            payload_format: PayloadFormat::RtpPacket,
            payload_direction,
            xid,
            correlation_id,
        }
    }

    /// A keepalive header: no session, so a [`NIL_XID`] and a nil correlation
    /// (TS 103 221-2 V1.4.1 §5.2.2).
    #[must_use]
    pub const fn keepalive() -> Self {
        Self {
            pdu_type: PduType::Keepalive,
            payload_format: PayloadFormat::Keepalive,
            payload_direction: PayloadDirection::Keepalive,
            xid: NIL_XID,
            correlation_id: NIL_CORRELATION_ID,
        }
    }
}

/// Frame one PDU into `out`, which is **cleared first** and then filled with the complete PDU:
/// the 40-byte header, the `attributes` block verbatim, then `payload`.
///
/// `attributes` is an already-encoded conditional-attribute block — build it with
/// [`attributes::AttributeWriter`]. It is not re-validated here; its length is what `Header Length`
/// counts beyond [`HEADER_LEN`], which is why the writer emits no padding (TS 103 221-2 V1.4.1
/// §5.3: attributes are contiguous TLVs, each exactly `4 + length` bytes).
///
/// The buffer is caller-owned so a delivery path can recycle one allocation across packets rather
/// than allocating per intercepted frame.
///
/// # Errors
///
/// [`LiError::ZeroCorrelationId`] if an X2/X3 PDU carries a zero Correlation ID (clause 6);
/// [`LiError::HeaderTooLarge`] / [`LiError::PayloadTooLarge`] if a length field would overflow.
pub fn encode(
    header: &PduHeader,
    attributes: &[u8],
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), LiError> {
    // Clause 6: a session's X2 and X3 records are tied together by a shared non-zero Correlation ID.
    // Emitting zero would deliver content the Mediation Function cannot attach to any IRI, so this
    // is refused at the point of framing rather than discovered at the agency.
    if header.pdu_type.requires_correlation() && header.correlation_id == NIL_CORRELATION_ID {
        return Err(LiError::ZeroCorrelationId);
    }
    let header_length = HEADER_LEN
        .checked_add(attributes.len())
        .and_then(|total| u32::try_from(total).ok())
        .ok_or(LiError::HeaderTooLarge {
            attributes_len: attributes.len(),
        })?;
    let payload_length = u32::try_from(payload.len()).map_err(|_| LiError::PayloadTooLarge {
        payload_len: payload.len(),
    })?;

    out.clear();
    out.reserve(HEADER_LEN + attributes.len() + payload.len());
    // §5.2.1 Version: major in the high byte, minor in the low byte.
    out.push(VERSION_MAJOR);
    out.push(VERSION_MINOR);
    // §5.2.2 PDU Type, §5.2.3 Header Length, §5.2.4 Payload Length — all big-endian.
    out.extend_from_slice(&header.pdu_type.to_u16().to_be_bytes());
    out.extend_from_slice(&header_length.to_be_bytes());
    out.extend_from_slice(&payload_length.to_be_bytes());
    // §5.2.5 Payload Format, §5.2.6 Payload Direction.
    out.extend_from_slice(&header.payload_format.to_u16().to_be_bytes());
    out.extend_from_slice(&header.payload_direction.to_u16().to_be_bytes());
    // §5.2.7 XID (16 bytes), §5.2.8 Correlation ID (8 bytes).
    out.extend_from_slice(&header.xid);
    out.extend_from_slice(&header.correlation_id.to_be_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN, "fixed header must be 40 bytes");
    // §5.3 conditional attributes, then the payload.
    out.extend_from_slice(attributes);
    out.extend_from_slice(payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recognisable XID: the 16 bytes 0x00..0x0f, so a misordered or misaligned copy is obvious in
    /// a failure diff rather than looking like plausible data.
    const TEST_XID: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn encodes_the_fixed_x3_header_byte_for_byte() {
        // Built by hand from TS 103 221-2 V1.4.1 §5.2, NOT by reading this crate's own encoder back:
        // a shared encode/decode bug passes a round-trip, so the fixture is the independent term.
        let header = PduHeader::x3_rtp(
            TEST_XID,
            0x1122_3344_5566_7788,
            PayloadDirection::FromTarget,
        );
        let payload = [0xaa, 0xbb, 0xcc, 0xdd];
        let mut out = Vec::new();
        encode(&header, &[], &payload, &mut out).expect("encode");

        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x00, 0x05,             // Version: major 0, minor 5
            0x00, 0x02,             // PDU Type: 2 (X3)
            0x00, 0x00, 0x00, 0x28, // Header Length: 40, no conditional attributes
            0x00, 0x00, 0x00, 0x04, // Payload Length: 4
            0x00, 0x08,             // Payload Format: 8 (RTP packet)
            0x00, 0x03,             // Payload Direction: 3 (sent from the target)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // XID
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Correlation ID
            0xaa, 0xbb, 0xcc, 0xdd, // payload
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn header_length_counts_the_attribute_block_and_payload_length_does_not() {
        let header = PduHeader::x3_rtp(TEST_XID, 1, PayloadDirection::ToTarget);
        // Two eight-byte TLVs: 2 x (4-byte tag + 4-byte value) = 16 bytes of attributes.
        let attributes = [0u8; 16];
        let payload = [0u8; 160];
        let mut out = Vec::new();
        encode(&header, &attributes, &payload, &mut out).expect("encode");

        assert_eq!(
            u32::from_be_bytes([out[4], out[5], out[6], out[7]]),
            (HEADER_LEN + attributes.len()) as u32,
            "Header Length counts the fixed header plus the attribute block"
        );
        assert_eq!(
            u32::from_be_bytes([out[8], out[9], out[10], out[11]]),
            payload.len() as u32,
            "Payload Length counts only the payload"
        );
        assert_eq!(out.len(), HEADER_LEN + attributes.len() + payload.len());
    }

    #[test]
    fn attributes_sit_between_the_header_and_the_payload() {
        let header = PduHeader::x3_rtp(TEST_XID, 1, PayloadDirection::FromTarget);
        let attributes = [0xa0, 0xa1, 0xa2, 0xa3];
        let payload = [0xf0, 0xf1];
        let mut out = Vec::new();
        encode(&header, &attributes, &payload, &mut out).expect("encode");

        assert_eq!(&out[HEADER_LEN..HEADER_LEN + 4], &attributes);
        assert_eq!(&out[HEADER_LEN + 4..], &payload);
    }

    #[test]
    fn direction_is_target_relative_not_leg_relative() {
        // The whole reason the intercept target's leg is a required input: 2 and 3 are defined
        // against the target, and the engine cannot infer which party that is.
        assert_eq!(PayloadDirection::ToTarget.to_u16(), 2);
        assert_eq!(PayloadDirection::FromTarget.to_u16(), 3);
    }

    #[test]
    fn pdu_and_format_values_match_the_specification_tables() {
        assert_eq!(PduType::X2.to_u16(), 1);
        assert_eq!(PduType::X3.to_u16(), 2);
        assert_eq!(PduType::Keepalive.to_u16(), 3);
        assert_eq!(PduType::KeepaliveAcknowledgement.to_u16(), 4);
        assert_eq!(PayloadFormat::Keepalive.to_u16(), 0);
        assert_eq!(PayloadFormat::RtpPacket.to_u16(), 8);
        assert_eq!(PayloadFormat::SipMessage.to_u16(), 9);
    }

    #[test]
    fn keepalive_carries_a_nil_xid_an_empty_payload_and_no_direction() {
        let mut out = Vec::new();
        encode(&PduHeader::keepalive(), &[], &[], &mut out).expect("encode");

        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x00, 0x05,             // Version
            0x00, 0x03,             // PDU Type: 3 (keepalive)
            0x00, 0x00, 0x00, 0x28, // Header Length: 40
            0x00, 0x00, 0x00, 0x00, // Payload Length: 0
            0x00, 0x00,             // Payload Format: 0 (keepalive)
            0x00, 0x00,             // Payload Direction: 0 (keepalive)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // nil XID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // nil Correlation ID
        ];
        assert_eq!(out, expected);
        assert_eq!(out.len(), HEADER_LEN);
    }

    #[test]
    fn reproduces_the_header_of_a_captured_pdu_from_another_implementation() {
        // A known-answer test, not a round-trip. These 40 bytes were produced by a *different*
        // implementation and captured on the wire (`sipgate/li-lib-x1x2x3`, test resource
        // `x2-demo-01.pcap`): an X2 PDU carrying a SIP REGISTER, one 41-byte conditional attribute
        // (type 17, Matched Target Identifier) and a 539-byte payload.
        //
        // Only the fixed header is asserted. It is the framing under test, it is what X2 and X3
        // share, and unlike the captured payload it carries no subscriber data — the XID is a random
        // UUID and the correlation is 1.
        //
        // This is the test that caught the version field being the wrong way round.
        #[rustfmt::skip]
        let captured_header: &[u8] = &[
            0x00, 0x05,             // Version: major 0, minor 5
            0x00, 0x01,             // PDU Type: 1 (X2)
            0x00, 0x00, 0x00, 0x51, // Header Length: 81 = 40 + a 41-byte attribute block
            0x00, 0x00, 0x02, 0x1b, // Payload Length: 539
            0x00, 0x09,             // Payload Format: 9 (SIP message)
            0x00, 0x03,             // Payload Direction: 3 (sent from the target)
            0x8c, 0x29, 0x2f, 0xa1, 0x58, 0x31, 0x46, 0xec, // XID
            0x86, 0xbe, 0xbd, 0x85, 0xf2, 0x08, 0x32, 0x99,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Correlation ID: 1
        ];

        let header = PduHeader {
            pdu_type: PduType::X2,
            payload_format: PayloadFormat::SipMessage,
            payload_direction: PayloadDirection::FromTarget,
            xid: [
                0x8c, 0x29, 0x2f, 0xa1, 0x58, 0x31, 0x46, 0xec, 0x86, 0xbe, 0xbd, 0x85, 0xf2, 0x08,
                0x32, 0x99,
            ],
            correlation_id: 1,
        };
        // The header only depends on these two lengths, not on their contents.
        let attributes = vec![0u8; 41];
        let payload = vec![0u8; 539];
        let mut out = Vec::new();
        encode(&header, &attributes, &payload, &mut out).expect("encode");

        assert_eq!(&out[..HEADER_LEN], captured_header);
    }

    #[test]
    fn refuses_an_x3_pdu_with_a_zero_correlation_id() {
        // Clause 6: content the Mediation Function cannot tie to its IRI is worse than no content,
        // because it reads as a successful delivery.
        let header = PduHeader::x3_rtp(TEST_XID, 0, PayloadDirection::FromTarget);
        let mut out = Vec::new();
        assert_eq!(
            encode(&header, &[], &[0x01], &mut out),
            Err(LiError::ZeroCorrelationId)
        );
    }

    #[test]
    fn keepalive_is_exempt_from_the_non_zero_correlation_requirement() {
        let mut out = Vec::new();
        assert!(encode(&PduHeader::keepalive(), &[], &[], &mut out).is_ok());
    }

    #[test]
    fn encode_clears_the_caller_buffer_so_it_can_be_recycled() {
        let header = PduHeader::x3_rtp(TEST_XID, 1, PayloadDirection::FromTarget);
        let mut out = vec![0xde; 512];
        encode(&header, &[], &[0x01, 0x02], &mut out).expect("encode");
        assert_eq!(out.len(), HEADER_LEN + 2);
        assert_eq!(
            out[0], VERSION_MAJOR,
            "stale bytes must not survive a reuse"
        );
    }

    #[test]
    fn error_messages_name_the_clause_they_enforce() {
        assert!(LiError::ZeroCorrelationId.to_string().contains("clause 6"));
        assert!(LiError::HeaderTooLarge { attributes_len: 9 }
            .to_string()
            .contains('9'));
        assert!(LiError::PayloadTooLarge { payload_len: 7 }
            .to_string()
            .contains('7'));
    }
}
