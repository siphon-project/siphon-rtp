//! RTCP compound-packet parsing (RFC 3550 §6) — enough to drive relay, statistics, and the
//! later MOS estimation: Sender Reports, Receiver Reports, and their reception report blocks.
//! SDES/BYE/APP are recognized and skipped. Construction of our own RR/SR comes with the
//! statistics work; this slice is the read path.

/// Errors from RTCP parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RtcpError {
    /// A packet (or the compound) was truncated.
    #[error("RTCP packet too short")]
    TooShort,
    /// The version field was not 2.
    #[error("unsupported RTCP version {0}")]
    BadVersion(u8),
    /// A sub-packet's length field overran the buffer.
    #[error("RTCP length field overruns buffer")]
    BadLength,
}

/// RTCP packet types (RFC 3550 §6 / 12.1).
pub mod packet_type {
    /// Sender Report.
    pub const SENDER_REPORT: u8 = 200;
    /// Receiver Report.
    pub const RECEIVER_REPORT: u8 = 201;
    /// Source Description.
    pub const SOURCE_DESCRIPTION: u8 = 202;
    /// Goodbye.
    pub const BYE: u8 = 203;
    /// Application-defined.
    pub const APP: u8 = 204;
}

/// One reception report block (RFC 3550 §6.4.1) — the per-source quality the MOS model consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportBlock {
    /// SSRC this report is about.
    pub ssrc: u32,
    /// Fraction of packets lost since the last report (8.8 fixed-point numerator over 256).
    pub fraction_lost: u8,
    /// Cumulative packets lost (24-bit signed, carried in an i32).
    pub cumulative_lost: i32,
    /// Extended highest sequence number received.
    pub highest_sequence: u32,
    /// Interarrival jitter (timestamp units).
    pub jitter: u32,
    /// Middle 32 bits of the last SR's NTP timestamp.
    pub last_sender_report: u32,
    /// Delay since the last SR (1/65536 s units).
    pub delay_since_last_sr: u32,
}

const REPORT_BLOCK_LEN: usize = 24;

impl ReportBlock {
    fn parse(buffer: &[u8]) -> Option<Self> {
        if buffer.len() < REPORT_BLOCK_LEN {
            return None;
        }
        let cumulative_raw = u32::from_be_bytes([0, buffer[5], buffer[6], buffer[7]]);
        // Sign-extend the 24-bit cumulative-lost field.
        let cumulative_lost = if cumulative_raw & 0x0080_0000 != 0 {
            (cumulative_raw | 0xFF00_0000) as i32
        } else {
            cumulative_raw as i32
        };
        Some(ReportBlock {
            ssrc: be32(&buffer[0..4]),
            fraction_lost: buffer[4],
            cumulative_lost,
            highest_sequence: be32(&buffer[8..12]),
            jitter: be32(&buffer[12..16]),
            last_sender_report: be32(&buffer[16..20]),
            delay_since_last_sr: be32(&buffer[20..24]),
        })
    }
}

/// A Sender Report (RFC 3550 §6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    /// Sender SSRC.
    pub ssrc: u32,
    /// NTP timestamp (64-bit, when this report was sent).
    pub ntp_timestamp: u64,
    /// RTP timestamp corresponding to the NTP time.
    pub rtp_timestamp: u32,
    /// Cumulative packets sent.
    pub packet_count: u32,
    /// Cumulative payload octets sent.
    pub octet_count: u32,
    /// Reception report blocks.
    pub reports: Vec<ReportBlock>,
}

/// A Receiver Report (RFC 3550 §6.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    /// Reporter SSRC.
    pub ssrc: u32,
    /// Reception report blocks.
    pub reports: Vec<ReportBlock>,
}

/// One element of a parsed RTCP compound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    /// A Sender Report.
    SenderReport(SenderReport),
    /// A Receiver Report.
    ReceiverReport(ReceiverReport),
    /// A recognized but unparsed packet type (SDES/BYE/APP/unknown).
    Other {
        /// The RTCP packet type byte.
        packet_type: u8,
    },
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_report_blocks(body: &[u8], count: usize) -> Vec<ReportBlock> {
    let mut reports = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * REPORT_BLOCK_LEN;
        match body.get(start..start + REPORT_BLOCK_LEN).and_then(ReportBlock::parse) {
            Some(block) => reports.push(block),
            None => break,
        }
    }
    reports
}

/// Parse a (possibly compound) RTCP packet into its constituent reports.
pub fn parse_compound(buffer: &[u8]) -> Result<Vec<RtcpPacket>, RtcpError> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < buffer.len() {
        if buffer.len() - offset < 4 {
            return Err(RtcpError::TooShort);
        }
        let header = &buffer[offset..];
        let version = header[0] >> 6;
        if version != 2 {
            return Err(RtcpError::BadVersion(version));
        }
        let report_count = (header[0] & 0x1F) as usize;
        let packet_type = header[1];
        let length_words = u16::from_be_bytes([header[2], header[3]]) as usize;
        let packet_len = (length_words + 1) * 4;
        if offset + packet_len > buffer.len() {
            return Err(RtcpError::BadLength);
        }
        let body = &buffer[offset + 4..offset + packet_len];

        match packet_type {
            packet_type::SENDER_REPORT if body.len() >= 24 => {
                packets.push(RtcpPacket::SenderReport(SenderReport {
                    ssrc: be32(&body[0..4]),
                    ntp_timestamp: (u64::from(be32(&body[4..8])) << 32) | u64::from(be32(&body[8..12])),
                    rtp_timestamp: be32(&body[12..16]),
                    packet_count: be32(&body[16..20]),
                    octet_count: be32(&body[20..24]),
                    reports: read_report_blocks(body.get(24..).unwrap_or(&[]), report_count),
                }));
            }
            packet_type::RECEIVER_REPORT if body.len() >= 4 => {
                packets.push(RtcpPacket::ReceiverReport(ReceiverReport {
                    ssrc: be32(&body[0..4]),
                    reports: read_report_blocks(body.get(4..).unwrap_or(&[]), report_count),
                }));
            }
            other => packets.push(RtcpPacket::Other { packet_type: other }),
        }
        offset += packet_len;
    }
    Ok(packets)
}

/// The two media kinds an rtcp-mux socket carries (RFC 5761 §4): inspect the second byte and
/// classify by payload-type range. RTCP packet types occupy 64..=95 once the marker bit is masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxKind {
    /// An RTP packet.
    Rtp,
    /// An RTCP packet.
    Rtcp,
}

/// Classify a datagram on an rtcp-mux socket as RTP or RTCP (RFC 5761).
#[must_use]
pub fn demux(datagram: &[u8]) -> Option<MuxKind> {
    let second = *datagram.get(1)?;
    let payload_type = second & 0x7F;
    if (64..=95).contains(&payload_type) {
        Some(MuxKind::Rtcp)
    } else {
        Some(MuxKind::Rtp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_receiver_report_with_block() {
        // RR: V2, RC=1, PT=201, length=7 words (32 bytes total). Reporter ssrc + 1 report block.
        let mut buffer = vec![0x81, 201, 0x00, 0x07];
        buffer.extend_from_slice(&0xAAAA_BBBBu32.to_be_bytes()); // reporter ssrc
        // report block
        buffer.extend_from_slice(&0x1111_2222u32.to_be_bytes()); // ssrc
        buffer.push(0x10); // fraction lost
        buffer.extend_from_slice(&[0x00, 0x00, 0x05]); // cumulative lost = 5
        buffer.extend_from_slice(&0x0000_2710u32.to_be_bytes()); // highest seq
        buffer.extend_from_slice(&0x0000_0040u32.to_be_bytes()); // jitter
        buffer.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // lsr
        buffer.extend_from_slice(&0x0000_0080u32.to_be_bytes()); // dlsr

        let packets = parse_compound(&buffer).expect("parse");
        assert_eq!(packets.len(), 1);
        match &packets[0] {
            RtcpPacket::ReceiverReport(report) => {
                assert_eq!(report.ssrc, 0xAAAA_BBBB);
                assert_eq!(report.reports.len(), 1);
                let block = report.reports[0];
                assert_eq!(block.ssrc, 0x1111_2222);
                assert_eq!(block.fraction_lost, 0x10);
                assert_eq!(block.cumulative_lost, 5);
                assert_eq!(block.jitter, 0x40);
                assert_eq!(block.delay_since_last_sr, 0x80);
            }
            other => panic!("expected RR, got {other:?}"),
        }
    }

    #[test]
    fn parses_sender_report() {
        // SR: V2, RC=0, PT=200, length=6 words (28 bytes).
        let mut buffer = vec![0x80, 200, 0x00, 0x06];
        buffer.extend_from_slice(&0x0102_0304u32.to_be_bytes()); // ssrc
        buffer.extend_from_slice(&0x1111_1111u32.to_be_bytes()); // ntp msw
        buffer.extend_from_slice(&0x2222_2222u32.to_be_bytes()); // ntp lsw
        buffer.extend_from_slice(&0x0000_1000u32.to_be_bytes()); // rtp ts
        buffer.extend_from_slice(&0x0000_00C8u32.to_be_bytes()); // packet count = 200
        buffer.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // octet count

        let packets = parse_compound(&buffer).expect("parse");
        match &packets[0] {
            RtcpPacket::SenderReport(report) => {
                assert_eq!(report.ssrc, 0x0102_0304);
                assert_eq!(report.ntp_timestamp, 0x1111_1111_2222_2222);
                assert_eq!(report.rtp_timestamp, 0x0000_1000);
                assert_eq!(report.packet_count, 200);
                assert_eq!(report.octet_count, 0x0001_0000);
                assert!(report.reports.is_empty());
            }
            other => panic!("expected SR, got {other:?}"),
        }
    }

    #[test]
    fn parses_compound_sr_then_sdes() {
        let mut buffer = vec![0x80, 200, 0x00, 0x06];
        buffer.extend_from_slice(&[0u8; 24]);
        // SDES: V2, SC=1, PT=202, length=1 word (8 bytes total).
        buffer.extend_from_slice(&[0x81, 202, 0x00, 0x01, 0, 0, 0, 0]);
        let packets = parse_compound(&buffer).expect("parse");
        assert_eq!(packets.len(), 2);
        assert!(matches!(packets[0], RtcpPacket::SenderReport(_)));
        assert!(matches!(
            packets[1],
            RtcpPacket::Other {
                packet_type: packet_type::SOURCE_DESCRIPTION
            }
        ));
    }

    #[test]
    fn rejects_overrun_length() {
        // Claims 100 words but the buffer is tiny.
        let buffer = vec![0x80, 201, 0x00, 0x64, 0, 0, 0, 0];
        assert_eq!(parse_compound(&buffer), Err(RtcpError::BadLength));
    }

    #[test]
    fn demux_classifies_rtp_and_rtcp() {
        // RTP PT 0 (µ-law).
        assert_eq!(demux(&[0x80, 0x00]), Some(MuxKind::Rtp));
        // RTCP PT 200 (SR) → 200 & 0x7f = 72, in 64..=95.
        assert_eq!(demux(&[0x80, 200]), Some(MuxKind::Rtcp));
        // RTCP PT 201 (RR) → 73.
        assert_eq!(demux(&[0x80, 201]), Some(MuxKind::Rtcp));
        assert_eq!(demux(&[0x80]), None);
    }

    use proptest::prelude::*;

    proptest! {
        /// Arbitrary (malformed / truncated / compound) bytes must decode-or-error, never panic.
        #[test]
        fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_compound(&bytes);
            let _ = demux(&bytes);
        }
    }
}
