//! L2/L3/L4 frame construction for the AF_XDP TX path.
//!
//! An AF_XDP TX descriptor points at a UMEM frame holding a **complete Ethernet frame** — the NIC
//! transmits exactly those bytes (in copy mode the kernel still expects L2 present). So to send a
//! UDP datagram we hand-build Ethernet + IPv4 + UDP headers in front of the payload and compute the
//! IPv4 and UDP checksums ourselves; nothing below us does it for us.
//!
//! References:
//! - Ethernet II frame: dst MAC (6) ‖ src MAC (6) ‖ ethertype (2) — IEEE 802.3.
//! - IPv4 header: RFC 791 §3.1 (20-byte, no options). Header checksum: RFC 1071.
//! - UDP header + checksum over the IPv4 pseudo-header: RFC 768 / RFC 1071.
//!
//! IPv4 only, matching the rest of the XDP ABI (`siphon-rtp-ebpf-common` is IPv4-first). All
//! multi-byte protocol fields are written network byte order.

use core::net::Ipv4Addr;

/// Ethernet II header length: dst MAC ‖ src MAC ‖ ethertype.
pub const ETH_HDR_LEN: usize = 14;
/// IPv4 header length with no options (the only form we emit).
pub const IPV4_HDR_LEN: usize = 20;
/// UDP header length.
pub const UDP_HDR_LEN: usize = 8;
/// Total L2+L3+L4 header bytes prepended to a UDP payload.
pub const TOTAL_HDR_LEN: usize = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;

/// EtherType for IPv4 (IEEE 802 / RFC 894).
pub const ETH_P_IP: u16 = 0x0800;
/// IPv4 protocol number for UDP (RFC 790 / IANA).
pub const IPPROTO_UDP: u8 = 17;

/// A 6-byte Ethernet MAC address.
pub type MacAddr = [u8; 6];

/// The fully-resolved L2/L3/L4 transport for one outbound frame: the addresses every header field
/// is filled from. The caller resolves the next-hop MAC (ARP / `rtnetlink` neighbour table) before
/// building the frame — header construction itself never touches the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameAddrs {
    /// Source MAC (the egress interface's hardware address).
    pub src_mac: MacAddr,
    /// Destination MAC (the resolved next-hop / gateway hardware address).
    pub dst_mac: MacAddr,
    /// Source IPv4 (the engine-local relay address).
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 (the peer we forward toward).
    pub dst_ip: Ipv4Addr,
    /// Source UDP port (the engine-local media port).
    pub src_port: u16,
    /// Destination UDP port (the peer's media port).
    pub dst_port: u16,
}

/// Build a complete Ethernet+IPv4+UDP frame for `payload` into `out`, returning the total frame
/// length. `out` must hold at least [`TOTAL_HDR_LEN`] `+ payload.len()` bytes; on too small a buffer
/// it returns `None` (the caller pre-sizes UMEM frames, so this is a guard, not a hot path).
///
/// Computes the IPv4 header checksum (RFC 1071) and the UDP checksum over the IPv4 pseudo-header
/// (RFC 768). A computed UDP checksum of `0x0000` is transmitted as `0xFFFF` per RFC 768 (a real
/// zero means "no checksum", which we never intend on IPv4).
#[must_use]
pub fn build_udp_frame(addrs: &FrameAddrs, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = TOTAL_HDR_LEN + payload.len();
    // IPv4 total length and UDP length are 16-bit fields; refuse anything that would overflow them.
    if out.len() < total || IPV4_HDR_LEN + UDP_HDR_LEN + payload.len() > u16::MAX as usize {
        return None;
    }

    // --- Ethernet II ---------------------------------------------------------------------------
    out[0..6].copy_from_slice(&addrs.dst_mac);
    out[6..12].copy_from_slice(&addrs.src_mac);
    out[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());

    // --- IPv4 (RFC 791 §3.1) -------------------------------------------------------------------
    let ip = &mut out[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN];
    let ip_total_len = (IPV4_HDR_LEN + UDP_HDR_LEN + payload.len()) as u16;
    ip[0] = 0x45; // version 4, IHL 5 (20 bytes, no options)
    ip[1] = 0x00; // DSCP/ECN 0
    ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification (0 — DF set, never fragmented)
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, fragment offset 0
    ip[8] = 64; // TTL
    ip[9] = IPPROTO_UDP;
    ip[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip[12..16].copy_from_slice(&addrs.src_ip.octets());
    ip[16..20].copy_from_slice(&addrs.dst_ip.octets());
    let ip_checksum = ones_complement_checksum(ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // --- UDP (RFC 768) -------------------------------------------------------------------------
    let udp_len = (UDP_HDR_LEN + payload.len()) as u16;
    let udp_start = ETH_HDR_LEN + IPV4_HDR_LEN;
    {
        let udp = &mut out[udp_start..udp_start + UDP_HDR_LEN];
        udp[0..2].copy_from_slice(&addrs.src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&addrs.dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    }
    out[udp_start + UDP_HDR_LEN..total].copy_from_slice(payload);

    // UDP checksum spans the pseudo-header + UDP header + payload (RFC 768).
    let udp_checksum = udp_checksum(addrs.src_ip, addrs.dst_ip, &out[udp_start..total], udp_len);
    let udp_checksum = if udp_checksum == 0 {
        0xFFFF
    } else {
        udp_checksum
    };
    out[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    Some(total)
}

/// The RFC 1071 one's-complement sum over `data`, folded and inverted — the form used for both the
/// IPv4 header checksum and (with a pseudo-header prefix) the UDP checksum. Handles an odd final
/// byte by zero-padding it on the right (RFC 1071 §1).
#[must_use]
pub fn ones_complement_checksum(data: &[u8]) -> u16 {
    !fold(sum_be16(data)) // one's complement of the folded sum
}

/// Accumulate `data` as big-endian 16-bit words into a 32-bit running sum (caller folds + inverts).
fn sum_be16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Odd trailing byte is the high byte of a word whose low byte is zero (RFC 1071 §1).
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    sum
}

/// Fold a 32-bit accumulator down to 16 bits by adding the carries back in (RFC 1071).
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// The UDP checksum (RFC 768): the one's-complement sum over the IPv4 pseudo-header
/// (src ‖ dst ‖ zero ‖ protocol ‖ udp_len) plus the UDP header and payload (`udp_segment`).
#[must_use]
pub fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8], udp_len: u16) -> u16 {
    let mut sum = 0u32;
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u32::from(u16::from_be_bytes([src[0], src[1]]));
    sum += u32::from(u16::from_be_bytes([src[2], src[3]]));
    sum += u32::from(u16::from_be_bytes([dst[0], dst[1]]));
    sum += u32::from(u16::from_be_bytes([dst[2], dst[3]]));
    sum += u32::from(IPPROTO_UDP); // zero byte ‖ protocol
    sum += u32::from(udp_len);
    sum += sum_be16(udp_segment);
    !fold(sum)
}

/// A parsed inbound IPv4/UDP frame: the source transport and the byte range of the UDP payload
/// within the original frame buffer. Returned by [`parse_udp_frame`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedFrame {
    /// Source IPv4 (host order, ready for `Ipv4Addr`).
    pub src_ip: Ipv4Addr,
    /// Source UDP port (host order).
    pub src_port: u16,
    /// Destination IPv4 (host order) — the engine-local relay address the flow keys on.
    pub dst_ip: Ipv4Addr,
    /// Destination UDP port (host order).
    pub dst_port: u16,
    /// Offset of the UDP payload start within the frame buffer.
    pub payload_offset: usize,
    /// Length of the UDP payload.
    pub payload_len: usize,
}

/// Parse an Ethernet+IPv4+UDP frame `frame` (as it lands in a UMEM RX descriptor), returning the
/// transport 4-tuple and the payload slice bounds, or `None` if it is not a well-formed IPv4/UDP
/// frame (wrong ethertype, truncated, IHL options past the buffer, non-UDP, or a UDP length the
/// buffer cannot satisfy). The kernel classifier already filtered to UDP, but userspace re-validates
/// every bound before indexing — a hostile/truncated frame must error, never panic (the fuzz target).
#[must_use]
pub fn parse_udp_frame(frame: &[u8]) -> Option<ParsedFrame> {
    if frame.len() < ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_IP {
        return None;
    }
    let version_ihl = frame[ETH_HDR_LEN];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if ihl < IPV4_HDR_LEN {
        return None;
    }
    let udp_offset = ETH_HDR_LEN + ihl;
    // The UDP header must fit after the (variable-length) IPv4 header.
    if frame.len() < udp_offset + UDP_HDR_LEN {
        return None;
    }
    if frame[ETH_HDR_LEN + 9] != IPPROTO_UDP {
        return None;
    }
    let src_ip = Ipv4Addr::new(
        frame[ETH_HDR_LEN + 12],
        frame[ETH_HDR_LEN + 13],
        frame[ETH_HDR_LEN + 14],
        frame[ETH_HDR_LEN + 15],
    );
    let dst_ip = Ipv4Addr::new(
        frame[ETH_HDR_LEN + 16],
        frame[ETH_HDR_LEN + 17],
        frame[ETH_HDR_LEN + 18],
        frame[ETH_HDR_LEN + 19],
    );
    let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);
    let udp_len = u16::from_be_bytes([frame[udp_offset + 4], frame[udp_offset + 5]]) as usize;
    // The UDP length covers the 8-byte header + payload; clamp to what the frame actually holds so a
    // lying length field cannot make us read past the buffer.
    if udp_len < UDP_HDR_LEN {
        return None;
    }
    let payload_offset = udp_offset + UDP_HDR_LEN;
    let claimed_payload = udp_len - UDP_HDR_LEN;
    let available = frame.len() - payload_offset;
    let payload_len = claimed_payload.min(available);
    Some(ParsedFrame {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        payload_offset,
        payload_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const DST_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    fn addrs() -> FrameAddrs {
        FrameAddrs {
            src_mac: SRC_MAC,
            dst_mac: DST_MAC,
            // 3GPP test range / documentation ranges only (no real subscriber data).
            src_ip: Ipv4Addr::new(198, 51, 100, 1),
            dst_ip: Ipv4Addr::new(203, 0, 113, 5),
            src_port: 5000,
            dst_port: 6000,
        }
    }

    #[test]
    fn ones_complement_checksum_of_a_known_ipv4_header() {
        // RFC 1071 worked example header bytes; the well-known correct checksum is 0xB861.
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ones_complement_checksum(&header), 0xB861);
    }

    #[test]
    fn checksum_over_correct_header_verifies_to_zero() {
        // A correctly-checksummed header sums (including its own checksum) to 0xFFFF, i.e. the
        // one's-complement check yields 0 — the receiver's validation (RFC 1071 §1).
        let mut header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let checksum = ones_complement_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(ones_complement_checksum(&header), 0);
    }

    #[test]
    fn build_frame_lays_out_every_header_field() {
        let payload = b"audio-frame";
        let mut out = [0u8; 256];
        let len = build_udp_frame(&addrs(), payload, &mut out).expect("build");
        assert_eq!(len, TOTAL_HDR_LEN + payload.len());

        // Ethernet: dst, src, ethertype.
        assert_eq!(&out[0..6], &DST_MAC);
        assert_eq!(&out[6..12], &SRC_MAC);
        assert_eq!(&out[12..14], &ETH_P_IP.to_be_bytes());

        // IPv4: version/IHL, protocol, addresses, total length.
        assert_eq!(out[ETH_HDR_LEN], 0x45);
        assert_eq!(out[ETH_HDR_LEN + 9], IPPROTO_UDP);
        let ip_total = u16::from_be_bytes([out[ETH_HDR_LEN + 2], out[ETH_HDR_LEN + 3]]);
        assert_eq!(
            ip_total as usize,
            IPV4_HDR_LEN + UDP_HDR_LEN + payload.len()
        );
        assert_eq!(&out[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16], &[198, 51, 100, 1]);
        assert_eq!(&out[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20], &[203, 0, 113, 5]);

        // UDP: ports, length, payload tail.
        let udp = ETH_HDR_LEN + IPV4_HDR_LEN;
        assert_eq!(u16::from_be_bytes([out[udp], out[udp + 1]]), 5000);
        assert_eq!(u16::from_be_bytes([out[udp + 2], out[udp + 3]]), 6000);
        assert_eq!(
            u16::from_be_bytes([out[udp + 4], out[udp + 5]]) as usize,
            UDP_HDR_LEN + payload.len()
        );
        assert_eq!(&out[udp + UDP_HDR_LEN..len], payload);
    }

    #[test]
    fn build_frame_ipv4_checksum_validates_at_receiver() {
        let mut out = [0u8; 256];
        let _ = build_udp_frame(&addrs(), b"x", &mut out).expect("build");
        let ip = &out[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN];
        // A receiver re-summing the header (checksum field included) must get 0 (RFC 1071).
        assert_eq!(ones_complement_checksum(ip), 0);
    }

    #[test]
    fn build_frame_udp_checksum_validates_at_receiver() {
        let payload = b"verify-udp-checksum";
        let mut out = [0u8; 256];
        let len = build_udp_frame(&addrs(), payload, &mut out).expect("build");
        // Re-running the UDP checksum over the segment (its checksum field included) yields 0 for a
        // valid datagram (RFC 768 / 1071), unless the transmitted value was the 0x0000→0xFFFF
        // substitution — in which case the recomputation is 0xFFFF. Neither indicates corruption.
        let udp_start = ETH_HDR_LEN + IPV4_HDR_LEN;
        let udp_len = (UDP_HDR_LEN + payload.len()) as u16;
        let check = udp_checksum(
            addrs().src_ip,
            addrs().dst_ip,
            &out[udp_start..len],
            udp_len,
        );
        assert!(check == 0 || check == 0xFFFF);
    }

    #[test]
    fn build_frame_rejects_too_small_buffer() {
        let mut out = [0u8; TOTAL_HDR_LEN]; // no room for any payload
        assert_eq!(build_udp_frame(&addrs(), b"x", &mut out), None);
    }

    #[test]
    fn build_frame_with_empty_payload_is_a_bare_header_datagram() {
        let mut out = [0u8; 64];
        let len = build_udp_frame(&addrs(), &[], &mut out).expect("build");
        assert_eq!(len, TOTAL_HDR_LEN);
        let udp = ETH_HDR_LEN + IPV4_HDR_LEN;
        assert_eq!(
            u16::from_be_bytes([out[udp + 4], out[udp + 5]]) as usize,
            UDP_HDR_LEN
        );
    }

    #[test]
    fn parse_round_trips_a_built_frame() {
        let payload = b"round-trip-payload";
        let mut out = [0u8; 256];
        let len = build_udp_frame(&addrs(), payload, &mut out).expect("build");
        let parsed = parse_udp_frame(&out[..len]).expect("parse");
        assert_eq!(parsed.src_ip, Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(parsed.dst_ip, Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(parsed.src_port, 5000);
        assert_eq!(parsed.dst_port, 6000);
        assert_eq!(
            &out[parsed.payload_offset..parsed.payload_offset + parsed.payload_len],
            payload
        );
    }

    #[test]
    fn parse_rejects_truncated_or_non_ipv4_udp_frames() {
        // Too short for even the minimum headers.
        assert_eq!(parse_udp_frame(&[0u8; 10]), None);

        // Right length, wrong ethertype (ARP 0x0806).
        let mut frame = [0u8; TOTAL_HDR_LEN + 4];
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert_eq!(parse_udp_frame(&frame), None);

        // IPv4 but TCP, not UDP.
        let mut frame = [0u8; TOTAL_HDR_LEN + 4];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[ETH_HDR_LEN] = 0x45;
        frame[ETH_HDR_LEN + 9] = 6; // IPPROTO_TCP
        assert_eq!(parse_udp_frame(&frame), None);
    }

    #[test]
    fn parse_clamps_a_lying_udp_length() {
        // A UDP length field claiming far more payload than the frame holds must clamp to the bytes
        // actually present, never index past the buffer (hostile-bitstream safety / fuzz target).
        let payload = b"short";
        let mut out = [0u8; 256];
        let len = build_udp_frame(&addrs(), payload, &mut out).expect("build");
        let udp = ETH_HDR_LEN + IPV4_HDR_LEN;
        out[udp + 4..udp + 6].copy_from_slice(&60000u16.to_be_bytes()); // lie: huge UDP length
        let parsed = parse_udp_frame(&out[..len]).expect("parse");
        assert_eq!(parsed.payload_len, payload.len());
    }
}
