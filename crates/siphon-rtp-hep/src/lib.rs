//! HEP version 3 (Homer Encapsulation Protocol) packet encoding — the wire format Homer/`captagent`
//! ingest, for exporting media QoS (RTCP, MOS) and signalling captures off the engine.
//!
//! Pure Rust, zero deps: a HEP3 packet is the ASCII id `HEP3`, a 16-bit total length, then a series
//! of TLV **chunks** (`vendor-id`, `type-id`, `length`, value). This crate builds exactly that wire
//! shape so the engine can ship RTCP/QoS to a Homer capture node, matching what Homer expects
//! byte-for-byte (the project's "telemetry: HEP3 wire format exactly as Homer/captagent expect" rule).
//!
//! Reference: the HEP3 format as implemented by Homer/`captagent` (generic chunk vendor id `0x0000`,
//! the standard chunk type ids enumerated in [`chunk`]).
#![forbid(unsafe_code)]

pub mod mos;

use std::net::{IpAddr, SocketAddr};

/// HEP3 magic id (first four bytes of every packet).
pub const MAGIC: &[u8; 4] = b"HEP3";

/// Per-chunk header size: vendor-id (2) + type-id (2) + length (2).
const CHUNK_HEADER_LEN: usize = 6;
/// HEP3 packet header size: magic (4) + total length (2).
const PACKET_HEADER_LEN: usize = 6;

/// The generic chunk vendor id (Homer's built-in chunks).
const VENDOR_GENERIC: u16 = 0x0000;

/// Standard HEP3 chunk type ids (vendor `0x0000`).
pub mod chunk {
    /// IP protocol family (1 byte: `2` = AF_INET, `10` = AF_INET6).
    pub const IP_FAMILY: u16 = 0x0001;
    /// IP protocol id (1 byte: `17` = UDP, `6` = TCP).
    pub const IP_PROTOCOL: u16 = 0x0002;
    /// IPv4 source address (4 bytes).
    pub const IPV4_SRC: u16 = 0x0003;
    /// IPv4 destination address (4 bytes).
    pub const IPV4_DST: u16 = 0x0004;
    /// IPv6 source address (16 bytes).
    pub const IPV6_SRC: u16 = 0x0005;
    /// IPv6 destination address (16 bytes).
    pub const IPV6_DST: u16 = 0x0006;
    /// Source port (2 bytes).
    pub const SRC_PORT: u16 = 0x0007;
    /// Destination port (2 bytes).
    pub const DST_PORT: u16 = 0x0008;
    /// Capture timestamp, seconds (4 bytes).
    pub const TIMESTAMP_SECS: u16 = 0x0009;
    /// Capture timestamp, microseconds (4 bytes).
    pub const TIMESTAMP_MICROS: u16 = 0x000a;
    /// Captured protocol type (1 byte: e.g. `1` = SIP, `5` = RTCP, `34` = RTP, `35` = RTCP-JSON).
    pub const PROTOCOL_TYPE: u16 = 0x000b;
    /// Capture agent id (4 bytes).
    pub const CAPTURE_AGENT_ID: u16 = 0x000c;
    /// Correlation id (variable) — groups related captures (the call-id).
    pub const CORRELATION_ID: u16 = 0x0011;
    /// Captured payload (variable) — the RTCP datagram or a QoS/MOS JSON document.
    pub const PAYLOAD: u16 = 0x000f;
}

/// Captured protocol-type values for the [`chunk::PROTOCOL_TYPE`] chunk.
pub mod protocol_type {
    /// A SIP message.
    pub const SIP: u8 = 1;
    /// An RTCP datagram.
    pub const RTCP: u8 = 5;
    /// An RTP datagram.
    pub const RTP: u8 = 34;
    /// A JSON QoS/MOS report (Homer's "report" capture).
    pub const REPORT_JSON: u8 = 35;
}

/// One HEP3 capture: the transport 5-tuple, a capture timestamp, the protocol type, and the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    /// Source transport address of the captured packet.
    pub src: SocketAddr,
    /// Destination transport address of the captured packet.
    pub dst: SocketAddr,
    /// Capture wall-clock seconds (caller-supplied so encoding stays deterministic/testable).
    pub timestamp_secs: u32,
    /// Capture wall-clock microseconds.
    pub timestamp_micros: u32,
    /// Captured protocol type (see [`protocol_type`]).
    pub protocol_type: u8,
    /// The capturing agent's id (configured per engine instance).
    pub capture_agent_id: u32,
    /// Optional correlation id (the call-id), so Homer groups the legs of one call.
    pub correlation_id: Option<String>,
    /// The captured payload bytes (an RTCP datagram, or a QoS/MOS JSON document).
    pub payload: Vec<u8>,
}

impl Capture {
    /// Encode this capture as a HEP3 packet. The src/dst families must match (both v4 or both v6);
    /// on a mismatch the destination is encoded in the source's family is **not** attempted — the
    /// encoder uses each address's own family chunk, and the `IP_FAMILY` chunk reflects the source.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut chunks = Vec::with_capacity(96 + self.payload.len());

        let family = match self.src.ip() {
            IpAddr::V4(_) => 2,  // AF_INET
            IpAddr::V6(_) => 10, // AF_INET6
        };
        push_chunk(&mut chunks, chunk::IP_FAMILY, &[family]);
        push_chunk(&mut chunks, chunk::IP_PROTOCOL, &[17]); // UDP

        push_ip(&mut chunks, self.src.ip(), chunk::IPV4_SRC, chunk::IPV6_SRC);
        push_ip(&mut chunks, self.dst.ip(), chunk::IPV4_DST, chunk::IPV6_DST);
        push_chunk(&mut chunks, chunk::SRC_PORT, &self.src.port().to_be_bytes());
        push_chunk(&mut chunks, chunk::DST_PORT, &self.dst.port().to_be_bytes());

        push_chunk(
            &mut chunks,
            chunk::TIMESTAMP_SECS,
            &self.timestamp_secs.to_be_bytes(),
        );
        push_chunk(
            &mut chunks,
            chunk::TIMESTAMP_MICROS,
            &self.timestamp_micros.to_be_bytes(),
        );
        push_chunk(&mut chunks, chunk::PROTOCOL_TYPE, &[self.protocol_type]);
        push_chunk(
            &mut chunks,
            chunk::CAPTURE_AGENT_ID,
            &self.capture_agent_id.to_be_bytes(),
        );
        if let Some(correlation_id) = &self.correlation_id {
            push_chunk(&mut chunks, chunk::CORRELATION_ID, correlation_id.as_bytes());
        }
        push_chunk(&mut chunks, chunk::PAYLOAD, &self.payload);

        let total = PACKET_HEADER_LEN + chunks.len();
        let mut packet = Vec::with_capacity(total);
        packet.extend_from_slice(MAGIC);
        // The total length is a 16-bit field; HEP3 packets are far below 64 KiB in practice.
        packet.extend_from_slice(&(total as u16).to_be_bytes());
        packet.extend_from_slice(&chunks);
        packet
    }
}

fn push_ip(buf: &mut Vec<u8>, ip: IpAddr, v4_type: u16, v6_type: u16) {
    match ip {
        IpAddr::V4(addr) => push_chunk(buf, v4_type, &addr.octets()),
        IpAddr::V6(addr) => push_chunk(buf, v6_type, &addr.octets()),
    }
}

/// Append one generic-vendor TLV chunk: vendor-id, type-id, length (including this 6-byte header),
/// then the value.
fn push_chunk(buf: &mut Vec<u8>, type_id: u16, value: &[u8]) {
    buf.extend_from_slice(&VENDOR_GENERIC.to_be_bytes());
    buf.extend_from_slice(&type_id.to_be_bytes());
    let length = (CHUNK_HEADER_LEN + value.len()) as u16;
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk a HEP3 packet's chunks into `(type_id, value)` pairs, validating the framing.
    fn decode_chunks(packet: &[u8]) -> Vec<(u16, Vec<u8>)> {
        assert_eq!(&packet[..4], MAGIC, "HEP3 magic");
        let total = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        assert_eq!(total, packet.len(), "total-length field matches the packet");
        let mut chunks = Vec::new();
        let mut offset = PACKET_HEADER_LEN;
        while offset + CHUNK_HEADER_LEN <= packet.len() {
            let type_id = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
            let length = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]) as usize;
            assert!(length >= CHUNK_HEADER_LEN, "chunk length covers its header");
            let value = packet[offset + CHUNK_HEADER_LEN..offset + length].to_vec();
            chunks.push((type_id, value));
            offset += length;
        }
        assert_eq!(offset, packet.len(), "chunks tile the packet exactly");
        chunks
    }

    fn value(chunks: &[(u16, Vec<u8>)], type_id: u16) -> Option<&[u8]> {
        chunks
            .iter()
            .find(|(id, _)| *id == type_id)
            .map(|(_, v)| v.as_slice())
    }

    #[test]
    fn encodes_ipv4_rtcp_capture() {
        let capture = Capture {
            src: "198.51.100.7:6000".parse().unwrap(),
            dst: "203.0.113.9:6002".parse().unwrap(),
            timestamp_secs: 0x1122_3344,
            timestamp_micros: 500_000,
            protocol_type: protocol_type::RTCP,
            capture_agent_id: 42,
            correlation_id: Some("call-abc@host".into()),
            payload: vec![0x80, 0xC8, 0x00, 0x06],
        };
        let packet = capture.encode();
        let chunks = decode_chunks(&packet);

        assert_eq!(value(&chunks, chunk::IP_FAMILY), Some(&[2u8][..]), "AF_INET");
        assert_eq!(value(&chunks, chunk::IP_PROTOCOL), Some(&[17u8][..]), "UDP");
        assert_eq!(value(&chunks, chunk::IPV4_SRC), Some(&[198, 51, 100, 7][..]));
        assert_eq!(value(&chunks, chunk::IPV4_DST), Some(&[203, 0, 113, 9][..]));
        assert_eq!(value(&chunks, chunk::SRC_PORT), Some(&6000u16.to_be_bytes()[..]));
        assert_eq!(value(&chunks, chunk::DST_PORT), Some(&6002u16.to_be_bytes()[..]));
        assert_eq!(
            value(&chunks, chunk::TIMESTAMP_SECS),
            Some(&0x1122_3344u32.to_be_bytes()[..])
        );
        assert_eq!(
            value(&chunks, chunk::PROTOCOL_TYPE),
            Some(&[protocol_type::RTCP][..])
        );
        assert_eq!(
            value(&chunks, chunk::CAPTURE_AGENT_ID),
            Some(&42u32.to_be_bytes()[..])
        );
        assert_eq!(
            value(&chunks, chunk::CORRELATION_ID),
            Some(b"call-abc@host".as_slice())
        );
        assert_eq!(
            value(&chunks, chunk::PAYLOAD),
            Some(&[0x80, 0xC8, 0x00, 0x06][..])
        );
        // No IPv6 chunks for a v4 capture.
        assert!(value(&chunks, chunk::IPV6_SRC).is_none());
    }

    #[test]
    fn encodes_ipv6_capture_with_v6_chunks() {
        let capture = Capture {
            src: "[2001:db8::1]:5000".parse().unwrap(),
            dst: "[2001:db8::2]:5002".parse().unwrap(),
            timestamp_secs: 1,
            timestamp_micros: 0,
            protocol_type: protocol_type::REPORT_JSON,
            capture_agent_id: 1,
            correlation_id: None,
            payload: br#"{"mos":4.2}"#.to_vec(),
        };
        let packet = capture.encode();
        let chunks = decode_chunks(&packet);

        assert_eq!(value(&chunks, chunk::IP_FAMILY), Some(&[10u8][..]), "AF_INET6");
        assert_eq!(value(&chunks, chunk::IPV6_SRC).map(|v| v.len()), Some(16));
        assert!(value(&chunks, chunk::IPV4_SRC).is_none());
        // No correlation id chunk when none is supplied.
        assert!(value(&chunks, chunk::CORRELATION_ID).is_none());
        assert_eq!(value(&chunks, chunk::PAYLOAD), Some(&br#"{"mos":4.2}"#[..]));
    }

    #[test]
    fn payload_chunk_length_is_self_describing() {
        let capture = Capture {
            src: "127.0.0.1:1".parse().unwrap(),
            dst: "127.0.0.1:2".parse().unwrap(),
            timestamp_secs: 0,
            timestamp_micros: 0,
            protocol_type: protocol_type::RTP,
            capture_agent_id: 0,
            correlation_id: None,
            payload: vec![0xAB; 200],
        };
        let packet = capture.encode();
        // Total length round-trips through the header even for a larger payload.
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]) as usize,
            packet.len()
        );
        let chunks = decode_chunks(&packet);
        assert_eq!(value(&chunks, chunk::PAYLOAD).map(|v| v.len()), Some(200));
    }
}
