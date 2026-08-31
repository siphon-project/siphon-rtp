//! Conditional attributes (ETSI TS 103 221-2 V1.4.1 §5.3) — the Type-Length-Value block that sits
//! between the fixed header and the payload.
//!
//! Each attribute is a 2-byte type, a 2-byte length, then exactly that many value bytes. Attributes
//! are **contiguous**: the next one begins at `4 + length`, with no alignment or padding. Getting
//! that wrong is silent — an unexpected pad byte desynchronises every attribute after the first
//! odd-length one — so it is asserted directly in the tests here and again against an independent
//! decoder in `tests/dissector.rs`.

use std::net::{IpAddr, SocketAddr};

/// Conditional attribute type codes (TS 103 221-2 V1.4.1 table 8).
pub mod attribute_type {
    /// ETSI TS 102 232-1 defined attribute.
    pub const ETSI_102_232_1: u16 = 1;
    /// 3GPP TS 33.128 defined attribute.
    pub const THREE_GPP_33_128: u16 = 2;
    /// ETSI TS 133 108 defined attribute.
    pub const ETSI_133_108: u16 = 3;
    /// Proprietary attribute.
    pub const PROPRIETARY: u16 = 4;
    /// Domain ID (DID).
    pub const DOMAIN_ID: u16 = 5;
    /// Network Function ID (NFID) — which network element produced the PDU.
    pub const NETWORK_FUNCTION_ID: u16 = 6;
    /// Interception Point ID (IPID) — where within that element the intercept was taken.
    pub const INTERCEPTION_POINT_ID: u16 = 7;
    /// Per-connection sequence number, so the Mediation Function can detect delivery loss.
    pub const SEQUENCE_NUMBER: u16 = 8;
    /// Absolute time the intercepted packet was observed.
    pub const TIMESTAMP: u16 = 9;
    /// Source IPv4 address of the intercepted packet.
    pub const SOURCE_IPV4: u16 = 10;
    /// Destination IPv4 address of the intercepted packet.
    pub const DESTINATION_IPV4: u16 = 11;
    /// Source IPv6 address of the intercepted packet.
    pub const SOURCE_IPV6: u16 = 12;
    /// Destination IPv6 address of the intercepted packet.
    pub const DESTINATION_IPV6: u16 = 13;
    /// Source transport port of the intercepted packet.
    pub const SOURCE_PORT: u16 = 14;
    /// Destination transport port of the intercepted packet.
    pub const DESTINATION_PORT: u16 = 15;
    /// IP protocol number carrying the intercepted packet.
    pub const IP_PROTOCOL: u16 = 16;
    /// Matched target identifier.
    pub const MATCHED_TARGET_IDENTIFIER: u16 = 17;
    /// Other target identifier.
    pub const OTHER_TARGET_IDENTIFIER: u16 = 18;
}

/// IANA protocol number for UDP — what relayed RTP always rides
/// (attribute [`attribute_type::IP_PROTOCOL`]).
pub const IP_PROTOCOL_UDP: u8 = 17;

/// The TLV header size: 2-byte type + 2-byte length.
const TLV_HEADER_LEN: usize = 4;

/// Builds a conditional-attribute block into a caller-owned buffer.
///
/// The buffer is borrowed rather than owned so a delivery path can recycle one allocation across
/// every intercepted packet. [`AttributeWriter::new`] clears it; each method appends one complete
/// TLV.
///
/// A value longer than `u16::MAX` cannot be expressed in the 2-byte length field, so the two
/// variable-length writers ([`AttributeWriter::text`] and [`AttributeWriter::raw`]) **truncate** to
/// that bound rather than emit a length that disagrees with the bytes that follow it — a mismatch
/// there would desynchronise the receiver's whole attribute walk. The only variable-length
/// attributes this engine emits are the operator-configured NFID and IPID, which are identifiers,
/// not payloads.
#[derive(Debug)]
pub struct AttributeWriter<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> AttributeWriter<'a> {
    /// Start a new attribute block, clearing `out`.
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        out.clear();
        Self { out }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether no attribute has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Append one raw TLV. `value` is truncated to `u16::MAX` so the emitted length always matches
    /// the bytes that follow it.
    pub fn raw(&mut self, attribute_type: u16, value: &[u8]) -> &mut Self {
        let value = &value[..value.len().min(usize::from(u16::MAX))];
        self.out.reserve(TLV_HEADER_LEN + value.len());
        self.out.extend_from_slice(&attribute_type.to_be_bytes());
        // Cast is bounded by the truncation above.
        self.out
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.out.extend_from_slice(value);
        self
    }

    /// Append a UTF-8 text attribute (the Network Function ID and Interception Point ID are
    /// operator-configured strings). No terminator: the TLV length delimits it.
    pub fn text(&mut self, attribute_type: u16, value: &str) -> &mut Self {
        self.raw(attribute_type, value.as_bytes())
    }

    /// Network Function ID (type 6) — which network element produced this PDU.
    pub fn network_function_id(&mut self, value: &str) -> &mut Self {
        self.text(attribute_type::NETWORK_FUNCTION_ID, value)
    }

    /// Interception Point ID (type 7) — where in that element the intercept was taken.
    pub fn interception_point_id(&mut self, value: &str) -> &mut Self {
        self.text(attribute_type::INTERCEPTION_POINT_ID, value)
    }

    /// Sequence number (type 8), 4 bytes big-endian. Counts per delivery connection, so the
    /// Mediation Function can tell a gap in delivery from a gap in the intercepted stream.
    pub fn sequence_number(&mut self, sequence: u32) -> &mut Self {
        self.raw(attribute_type::SEQUENCE_NUMBER, &sequence.to_be_bytes())
    }

    /// Timestamp (type 9), 8 bytes: a 4-byte big-endian Unix seconds count followed by a 4-byte
    /// big-endian nanoseconds remainder.
    ///
    /// This is an **absolute** wall-clock time, not a capture-relative one — which is why the
    /// engine cannot hand a datapath receive-clock reading straight through (see
    /// [`crate::clock::WallClockAnchor`]).
    pub fn timestamp(&mut self, unix_seconds: u32, nanoseconds: u32) -> &mut Self {
        let mut value = [0u8; 8];
        value[0..4].copy_from_slice(&unix_seconds.to_be_bytes());
        value[4..8].copy_from_slice(&nanoseconds.to_be_bytes());
        self.raw(attribute_type::TIMESTAMP, &value)
    }

    /// Source address and port (types 10/12 and 14). The address family selects the attribute type,
    /// so an IPv6 leg emits type 12 and an IPv4 leg type 10.
    pub fn source(&mut self, address: SocketAddr) -> &mut Self {
        self.address(
            address.ip(),
            attribute_type::SOURCE_IPV4,
            attribute_type::SOURCE_IPV6,
        );
        self.port(attribute_type::SOURCE_PORT, address.port())
    }

    /// Destination address and port (types 11/13 and 15) — the engine endpoint the intercepted
    /// packet arrived on.
    pub fn destination(&mut self, address: SocketAddr) -> &mut Self {
        self.address(
            address.ip(),
            attribute_type::DESTINATION_IPV4,
            attribute_type::DESTINATION_IPV6,
        );
        self.port(attribute_type::DESTINATION_PORT, address.port())
    }

    /// IP protocol number (type 16), 1 byte.
    pub fn ip_protocol(&mut self, protocol: u8) -> &mut Self {
        self.raw(attribute_type::IP_PROTOCOL, &[protocol])
    }

    /// Write an address as its family's attribute type, in network byte order.
    fn address(&mut self, ip: IpAddr, ipv4_type: u16, ipv6_type: u16) -> &mut Self {
        match ip {
            IpAddr::V4(v4) => self.raw(ipv4_type, &v4.octets()),
            IpAddr::V6(v6) => self.raw(ipv6_type, &v6.octets()),
        }
    }

    /// Write a port as a 2-byte big-endian value.
    fn port(&mut self, attribute_type: u16, port: u16) -> &mut Self {
        self.raw(attribute_type, &port.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn writes_a_tlv_as_type_length_then_value() {
        let mut buffer = Vec::new();
        AttributeWriter::new(&mut buffer).raw(0x1234, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(
            buffer,
            &[
                0x12, 0x34, // type
                0x00, 0x03, // length
                0xaa, 0xbb, 0xcc, // value
            ]
        );
    }

    #[test]
    fn attributes_are_contiguous_with_no_alignment_padding() {
        // The failure this pins: a 1-byte IP-protocol attribute followed by anything. If the writer
        // padded to a 4-byte boundary, the next attribute would start three bytes late and every
        // attribute after it would be misread. Confirmed against two independent decoders, both of
        // which advance strictly by `4 + length`.
        let mut buffer = Vec::new();
        AttributeWriter::new(&mut buffer)
            .ip_protocol(IP_PROTOCOL_UDP)
            .sequence_number(1);
        assert_eq!(
            buffer,
            &[
                0x00, 0x10, 0x00, 0x01, 0x11, // type 16, length 1, value 17 (UDP)
                0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, // type 8, length 4, value 1
            ],
            "an odd-length attribute must not be followed by padding"
        );
    }

    #[test]
    fn encodes_the_timestamp_as_unix_seconds_then_nanoseconds() {
        // Not an NTP 64-bit timestamp: 4 bytes of Unix seconds, then 4 bytes of nanoseconds.
        // Confirmed independently by both third-party decoders.
        let mut buffer = Vec::new();
        AttributeWriter::new(&mut buffer).timestamp(0x6512_3456, 123_456_789);
        assert_eq!(
            buffer,
            &[
                0x00, 0x09, // type 9
                0x00, 0x08, // length 8
                0x65, 0x12, 0x34, 0x56, // Unix seconds
                0x07, 0x5b, 0xcd, 0x15, // nanoseconds (123_456_789)
            ]
        );
    }

    #[test]
    fn selects_the_attribute_type_from_the_address_family() {
        let mut v4 = Vec::new();
        AttributeWriter::new(&mut v4)
            .source(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 16384)));
        assert_eq!(
            v4,
            &[
                0x00, 0x0a, 0x00, 0x04, 203, 0, 113, 9, // type 10 (source IPv4)
                0x00, 0x0e, 0x00, 0x02, 0x40, 0x00, // type 14 (source port) = 16384
            ]
        );

        let mut v6 = Vec::new();
        let address = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        AttributeWriter::new(&mut v6).destination(SocketAddr::from((address, 5004)));
        assert_eq!(
            v6,
            &[
                0x00, 0x0d, 0x00, 0x10, // type 13 (destination IPv6), length 16
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //
                0x00, 0x0f, 0x00, 0x02, 0x13, 0x8c, // type 15 (destination port) = 5004
            ]
        );
    }

    #[test]
    fn text_attributes_carry_no_terminator() {
        let mut buffer = Vec::new();
        AttributeWriter::new(&mut buffer).network_function_id("sbc-01");
        assert_eq!(
            buffer,
            &[0x00, 0x06, 0x00, 0x06, b's', b'b', b'c', b'-', b'0', b'1'],
        );
    }

    #[test]
    fn attribute_type_codes_match_the_specification_table() {
        assert_eq!(attribute_type::NETWORK_FUNCTION_ID, 6);
        assert_eq!(attribute_type::INTERCEPTION_POINT_ID, 7);
        assert_eq!(attribute_type::SEQUENCE_NUMBER, 8);
        assert_eq!(attribute_type::TIMESTAMP, 9);
        assert_eq!(attribute_type::SOURCE_IPV4, 10);
        assert_eq!(attribute_type::DESTINATION_IPV4, 11);
        assert_eq!(attribute_type::SOURCE_IPV6, 12);
        assert_eq!(attribute_type::DESTINATION_IPV6, 13);
        assert_eq!(attribute_type::SOURCE_PORT, 14);
        assert_eq!(attribute_type::DESTINATION_PORT, 15);
        assert_eq!(attribute_type::IP_PROTOCOL, 16);
    }

    #[test]
    fn truncates_a_value_too_long_for_the_length_field() {
        // The emitted length must always describe the bytes that actually follow it; a value that
        // cannot fit is cut, never allowed to disagree with its header.
        let oversized = vec![0x5au8; usize::from(u16::MAX) + 32];
        let mut buffer = Vec::new();
        AttributeWriter::new(&mut buffer).raw(attribute_type::PROPRIETARY, &oversized);

        let declared = u16::from_be_bytes([buffer[2], buffer[3]]);
        assert_eq!(declared, u16::MAX);
        assert_eq!(buffer.len(), TLV_HEADER_LEN + usize::from(u16::MAX));
    }

    #[test]
    fn new_clears_the_buffer_so_it_can_be_recycled() {
        let mut buffer = vec![0xff; 64];
        AttributeWriter::new(&mut buffer).sequence_number(7);
        assert_eq!(buffer, &[0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x07]);
    }

    #[test]
    fn reports_length_and_emptiness() {
        let mut buffer = Vec::new();
        let mut writer = AttributeWriter::new(&mut buffer);
        assert!(writer.is_empty());
        assert_eq!(writer.len(), 0);
        writer.sequence_number(1);
        assert!(!writer.is_empty());
        assert_eq!(writer.len(), 8);
    }
}
