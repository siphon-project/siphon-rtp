//! A pure-Rust libpcap (classic `.pcap`) writer for raw-RTP call recording.
//!
//! rtpengine's default recording mode captures the media packets to a `.pcap` so they can be
//! replayed or dissected offline. We do the same: each accepted RTP/RTCP datagram is wrapped in
//! synthetic Ethernet + IPv4/IPv6 + UDP headers built from the real 5-tuple (observed source →
//! engine endpoint) and appended as one pcap record. The RTP payload is copied byte-for-byte — no
//! decode/re-encode — so a capture works for any codec (G.711, AMR-WB, …) regardless of whether the
//! engine has a decoder for it, and Wireshark's RTP dissector decodes the result directly.
//!
//! Format references:
//! - libpcap file format (global header + per-packet record) — the classic `application/vnd.tcpdump.pcap`.
//! - Ethernet II (IEEE 802.3) framing; IPv4 (RFC 791), IPv6 (RFC 8200), UDP (RFC 768).
//!
//! The module is a pure encoder: [`global_header`] once, then [`frame`] per packet. The engine owns
//! the drain task that stamps the wall-clock capture time and streams the bytes to disk, so this
//! module holds no clock and no I/O — it is fully deterministic and unit-testable.

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;

/// libpcap magic in native (host) byte order. Written little-endian here, so a reader sees the
/// bytes `d4 c3 b2 a1` and infers little-endian fields.
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
/// libpcap major/minor version (2.4 — the universally-supported classic format).
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
/// `LINKTYPE_ETHERNET` — each record is a full Ethernet II frame. RTP recordings conventionally use
/// Ethernet framing so the standard dissector chain (Ethernet → IP → UDP → RTP) applies.
const LINKTYPE_ETHERNET: u32 = 1;
/// Snapshot length: the maximum bytes captured per packet. A media datagram plus its 42/62-byte
/// synthetic headers is far below this, so nothing is ever truncated.
const SNAPLEN: u32 = 65_535;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IP_PROTO_UDP: u8 = 17;

/// One accepted media datagram to capture: the observed 5-tuple, the verbatim wire bytes, and the
/// arrival time.
///
/// `source` is the peer's observed source address (post source-gate) and `destination` is the
/// engine endpoint the datagram arrived on, so the capture reflects exactly what was on the wire.
/// `payload` is the RTP/RTCP packet, copied byte-for-byte. `timestamp_micros` is the datagram's
/// arrival time in microseconds (the datapath's receive-clock reading — a logical clock on the
/// loopback backend, so captures are deterministic; a monotonic microsecond clock on XDP). It is a
/// relative timeline, which is exactly what RTP timing analysis needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPacket {
    /// The peer's observed source address (where the datagram came from).
    pub source: SocketAddr,
    /// The engine endpoint the datagram was received on (the capture's destination).
    pub destination: SocketAddr,
    /// The RTP/RTCP packet bytes, verbatim.
    pub payload: Bytes,
    /// Arrival time in microseconds (datapath receive clock).
    pub timestamp_micros: u64,
}

impl CapturedPacket {
    /// A captured datagram from `source` to `destination` carrying `payload`, received at
    /// `timestamp_micros` (datapath receive-clock microseconds).
    #[must_use]
    pub fn new(
        source: SocketAddr,
        destination: SocketAddr,
        payload: Bytes,
        timestamp_micros: u64,
    ) -> Self {
        Self {
            source,
            destination,
            payload,
            timestamp_micros,
        }
    }
}

/// The 24-byte libpcap global header (little-endian, `LINKTYPE_ETHERNET`). Written once at the head
/// of every recording, before any [`frame`].
#[must_use]
pub fn global_header() -> [u8; 24] {
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&VERSION_MAJOR.to_le_bytes());
    header[6..8].copy_from_slice(&VERSION_MINOR.to_le_bytes());
    // thiszone (GMT offset) = 0, sigfigs = 0 — bytes 8..16 stay zero.
    header[16..20].copy_from_slice(&SNAPLEN.to_le_bytes());
    header[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    header
}

/// Encode one pcap record: the 16-byte record header (capture time + lengths) followed by the
/// synthetic Ethernet/IP/UDP frame that carries `packet.payload`. The capture time is taken from
/// `packet.timestamp_micros`, so this function stays clock-free and deterministic.
///
/// The IP family is taken from the addresses: a v4 source → v4 destination yields an IPv4 frame, v6
/// → v6 an IPv6 frame. A mixed-family pair (which never occurs on one relayed leg) falls back to the
/// destination's family, coercing the source to an unspecified address of that family.
#[must_use]
pub fn frame(packet: &CapturedPacket) -> Vec<u8> {
    let timestamp_secs = packet.timestamp_micros / 1_000_000;
    let timestamp_micros = (packet.timestamp_micros % 1_000_000) as u32;
    let ethernet = ethernet_frame(packet);
    let mut record = Vec::with_capacity(16 + ethernet.len());
    // Record header (file endianness = little-endian): ts_sec, ts_usec, incl_len, orig_len. Seconds
    // are truncated to 32 bits (libpcap's field width) — correct until 2106.
    record.extend_from_slice(&(timestamp_secs as u32).to_le_bytes());
    record.extend_from_slice(&timestamp_micros.to_le_bytes());
    record.extend_from_slice(&(ethernet.len() as u32).to_le_bytes());
    record.extend_from_slice(&(ethernet.len() as u32).to_le_bytes());
    record.extend_from_slice(&ethernet);
    record
}

/// Build the Ethernet II frame (zeroed MACs) wrapping an IPv4/IPv6 + UDP datagram for `packet`.
fn ethernet_frame(packet: &CapturedPacket) -> Vec<u8> {
    let ipv6 = matches!(packet.destination.ip(), IpAddr::V6(_));
    let ethertype = if ipv6 { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 };

    let ip_datagram = if ipv6 {
        ipv6_datagram(packet)
    } else {
        ipv4_datagram(packet)
    };

    let mut frame = Vec::with_capacity(14 + ip_datagram.len());
    frame.extend_from_slice(&[0u8; 6]); // destination MAC
    frame.extend_from_slice(&[0u8; 6]); // source MAC
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(&ip_datagram);
    frame
}

/// IPv4 (RFC 791) header + UDP (RFC 768) datagram carrying the payload. The IPv4 header checksum is
/// computed; the UDP checksum is computed over the pseudo-header too (0 would be legal for IPv4, but
/// a correct checksum keeps Wireshark from flagging the frame).
fn ipv4_datagram(packet: &CapturedPacket) -> Vec<u8> {
    let source = ipv4_octets(packet.source.ip());
    let destination = ipv4_octets(packet.destination.ip());
    let udp = udp_datagram(
        packet.source.port(),
        packet.destination.port(),
        &packet.payload,
        &pseudo_header_ipv4(&source, &destination, &packet.payload),
    );
    let total_len = (20 + udp.len()) as u16;

    let mut header = Vec::with_capacity(20 + udp.len());
    header.push(0x45); // version 4, IHL 5 (20-byte header, no options)
    header.push(0x00); // DSCP / ECN
    header.extend_from_slice(&total_len.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes()); // identification
    header.extend_from_slice(&0x4000u16.to_be_bytes()); // flags = Don't Fragment, fragment offset 0
    header.push(64); // TTL
    header.push(IP_PROTO_UDP);
    header.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    header.extend_from_slice(&source);
    header.extend_from_slice(&destination);
    let checksum = internet_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    header.extend_from_slice(&udp);
    header
}

/// IPv6 (RFC 8200) header + UDP datagram. IPv6 mandates a UDP checksum, so it is always computed.
fn ipv6_datagram(packet: &CapturedPacket) -> Vec<u8> {
    let source = ipv6_octets(packet.source.ip());
    let destination = ipv6_octets(packet.destination.ip());
    let udp = udp_datagram(
        packet.source.port(),
        packet.destination.port(),
        &packet.payload,
        &pseudo_header_ipv6(&source, &destination, &packet.payload),
    );
    let payload_len = udp.len() as u16;

    let mut header = Vec::with_capacity(40 + udp.len());
    header.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6, traffic class 0, flow 0
    header.extend_from_slice(&payload_len.to_be_bytes());
    header.push(IP_PROTO_UDP); // next header
    header.push(64); // hop limit
    header.extend_from_slice(&source);
    header.extend_from_slice(&destination);
    header.extend_from_slice(&udp);
    header
}

/// UDP (RFC 768) header + payload. `pseudo_header` is the IP pseudo-header prefix the checksum spans.
fn udp_datagram(
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    pseudo_header: &[u8],
) -> Vec<u8> {
    let length = (8 + payload.len()) as u16;
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&length.to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    datagram.extend_from_slice(payload);

    // Checksum spans the pseudo-header then the UDP header+payload (RFC 768 / RFC 8200 §8.1).
    let mut checksummed = Vec::with_capacity(pseudo_header.len() + datagram.len());
    checksummed.extend_from_slice(pseudo_header);
    checksummed.extend_from_slice(&datagram);
    let mut checksum = internet_checksum(&checksummed);
    // A computed UDP checksum of zero is transmitted as 0xFFFF (RFC 768) so it is never mistaken for
    // "no checksum".
    if checksum == 0 {
        checksum = 0xffff;
    }
    datagram[6..8].copy_from_slice(&checksum.to_be_bytes());
    datagram
}

/// IPv4 UDP pseudo-header (RFC 768): src addr, dst addr, zero, protocol, UDP length.
fn pseudo_header_ipv4(source: &[u8; 4], destination: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let udp_length = (8 + payload.len()) as u16;
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(source);
    pseudo.extend_from_slice(destination);
    pseudo.push(0);
    pseudo.push(IP_PROTO_UDP);
    pseudo.extend_from_slice(&udp_length.to_be_bytes());
    pseudo
}

/// IPv6 UDP pseudo-header (RFC 8200 §8.1): src addr, dst addr, upper-layer length (32-bit), zeros,
/// next header.
fn pseudo_header_ipv6(source: &[u8; 16], destination: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let udp_length = (8 + payload.len()) as u32;
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(source);
    pseudo.extend_from_slice(destination);
    pseudo.extend_from_slice(&udp_length.to_be_bytes());
    pseudo.extend_from_slice(&[0u8, 0, 0]);
    pseudo.push(IP_PROTO_UDP);
    pseudo
}

/// The Internet checksum (RFC 1071): one's-complement sum of 16-bit big-endian words, folded, then
/// complemented. An odd trailing byte is padded with a zero low byte.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The four IPv4 octets of an address, or the unspecified address for a v6 input (never happens on a
/// v4-classified leg; a defensive fallback).
fn ipv4_octets(ip: IpAddr) -> [u8; 4] {
    match ip {
        IpAddr::V4(addr) => addr.octets(),
        IpAddr::V6(_) => [0, 0, 0, 0],
    }
}

/// The sixteen IPv6 octets of an address; a v4 input is mapped into the IPv4-mapped v6 range.
fn ipv6_octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(addr) => addr.octets(),
        IpAddr::V4(addr) => addr.to_ipv6_mapped().octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn read_u16_be(bytes: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    #[test]
    fn global_header_matches_the_libpcap_layout() {
        let header = global_header();
        // Magic little-endian: 0xa1b2c3d4 → d4 c3 b2 a1.
        assert_eq!(&header[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(read_u16_le(&header, 4), 2, "version major");
        assert_eq!(read_u16_le(&header, 6), 4, "version minor");
        assert_eq!(read_u32_le(&header, 8), 0, "thiszone");
        assert_eq!(read_u32_le(&header, 12), 0, "sigfigs");
        assert_eq!(read_u32_le(&header, 16), 65_535, "snaplen");
        assert_eq!(read_u32_le(&header, 20), 1, "LINKTYPE_ETHERNET");
    }

    fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    #[test]
    fn ipv4_record_wraps_the_payload_in_ethernet_ip_udp() {
        let payload = Bytes::from_static(&[0x80, 0x00, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef]);
        let packet = CapturedPacket::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 40_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 7_000),
            payload.clone(),
            1234 * 1_000_000 + 567, // 1234 s + 567 µs since the datapath epoch
        );
        let record = frame(&packet);

        // Record header (little-endian): ts split into secs + micros, then incl_len == orig_len.
        assert_eq!(read_u32_le(&record, 0), 1234, "ts_sec");
        assert_eq!(read_u32_le(&record, 4), 567, "ts_usec");
        let frame_len = 14 + 20 + 8 + payload.len();
        assert_eq!(read_u32_le(&record, 8), frame_len as u32, "incl_len");
        assert_eq!(read_u32_le(&record, 12), frame_len as u32, "orig_len");
        assert_eq!(record.len(), 16 + frame_len);

        let eth = &record[16..];
        // Ethernet: zeroed MACs, IPv4 ethertype.
        assert_eq!(&eth[0..12], &[0u8; 12], "zeroed MACs");
        assert_eq!(read_u16_be(eth, 12), ETHERTYPE_IPV4, "IPv4 ethertype");

        let ip = &eth[14..];
        assert_eq!(ip[0], 0x45, "IPv4 version+IHL");
        assert_eq!(
            read_u16_be(ip, 2),
            (20 + 8 + payload.len()) as u16,
            "IP total length"
        );
        assert_eq!(ip[9], IP_PROTO_UDP, "protocol = UDP");
        assert_eq!(&ip[12..16], &[203, 0, 113, 5], "source IP");
        assert_eq!(&ip[16..20], &[198, 51, 100, 9], "destination IP");
        // The IPv4 header checksum must make the header sum to zero (RFC 1071).
        assert_eq!(
            internet_checksum(&ip[0..20]),
            0,
            "valid IPv4 header checksum"
        );

        let udp = &ip[20..];
        assert_eq!(read_u16_be(udp, 0), 40_000, "UDP source port");
        assert_eq!(read_u16_be(udp, 2), 7_000, "UDP destination port");
        assert_eq!(
            read_u16_be(udp, 4),
            (8 + payload.len()) as u16,
            "UDP length"
        );
        assert_eq!(&udp[8..], &payload[..], "RTP payload byte-for-byte");
    }

    #[test]
    fn ipv4_udp_checksum_validates_over_the_pseudo_header() {
        let payload = Bytes::from_static(&[0x01, 0x02, 0x03]); // odd length exercises the pad path
        let packet = CapturedPacket::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5_004),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5_006),
            payload.clone(),
            1_000_000,
        );
        let record = frame(&packet);
        let ip = &record[16 + 14..];
        let udp = &ip[20..];
        // Recompute the checksum over pseudo-header + UDP datagram; a correct one sums to zero.
        let mut buffer = pseudo_header_ipv4(&[10, 0, 0, 1], &[10, 0, 0, 2], &payload);
        buffer.extend_from_slice(udp);
        assert_eq!(
            internet_checksum(&buffer),
            0,
            "valid UDP checksum over pseudo-header"
        );
    }

    #[test]
    fn ipv6_record_uses_ipv6_framing_and_mandatory_udp_checksum() {
        let payload = Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let packet = CapturedPacket::new(
            SocketAddr::new(IpAddr::V6(source), 6_000),
            SocketAddr::new(IpAddr::V6(destination), 6_002),
            payload.clone(),
            1_000_000,
        );
        let record = frame(&packet);
        let eth = &record[16..];
        assert_eq!(read_u16_be(eth, 12), ETHERTYPE_IPV6, "IPv6 ethertype");

        let ip = &eth[14..];
        assert_eq!(ip[0] >> 4, 6, "IP version 6");
        assert_eq!(
            read_u16_be(ip, 4),
            (8 + payload.len()) as u16,
            "IPv6 payload length"
        );
        assert_eq!(ip[6], IP_PROTO_UDP, "next header = UDP");
        assert_eq!(&ip[8..24], &source.octets(), "source IPv6");
        assert_eq!(&ip[24..40], &destination.octets(), "destination IPv6");

        let udp = &ip[40..];
        assert_eq!(read_u16_be(udp, 0), 6_000, "UDP source port");
        assert_ne!(
            read_u16_be(udp, 6),
            0,
            "IPv6 UDP checksum is mandatory (non-zero)"
        );
        assert_eq!(&udp[8..], &payload[..], "payload verbatim");
        // The checksum validates over the IPv6 pseudo-header.
        let mut buffer = pseudo_header_ipv6(&source.octets(), &destination.octets(), &payload);
        buffer.extend_from_slice(udp);
        assert_eq!(internet_checksum(&buffer), 0, "valid IPv6 UDP checksum");
    }

    #[test]
    fn internet_checksum_folds_carries() {
        // Two words that overflow 16 bits, forcing the carry-fold path.
        assert_eq!(internet_checksum(&[0xff, 0xff, 0xff, 0xff]), 0x0000);
        // A single all-zero word complements to all-ones.
        assert_eq!(internet_checksum(&[0x00, 0x00]), 0xffff);
    }
}
