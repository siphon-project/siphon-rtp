//! RTCP compound-packet parsing and construction (RFC 3550 §6), driving relay, statistics, and the
//! G.107 MOS estimation. Parses Sender Reports, Receiver Reports, and their reception report blocks
//! (SDES/BYE/APP are recognized and skipped), and builds our own minimal SR/RR for the per-leg
//! reception reports the engine emits. APP packets (RFC 3550 §6.7), which carry MCPTT floor control
//! (3GPP TS 24.380 §8), have their own zero-copy reader [`app_packets`] and builder [`write_app`].

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
    /// The padding bit was set but the padding count was zero or longer than the packet's data.
    #[error("RTCP padding count is invalid")]
    BadPadding,
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

/// Length of a Sender Report header (no reception-report blocks), RFC 3550 §6.4.1.
pub const SENDER_REPORT_LEN: usize = 28;
/// Length of one reception-report block, RFC 3550 §6.4.1.
pub const RECEPTION_REPORT_LEN: usize = 24;

/// A reception-report block (RFC 3550 §6.4.1) — the engine's view of one inbound stream, as it writes
/// it into an outbound SR/RR. Every field is now measured per leg: `fraction_lost` (the per-interval
/// 8-bit ratio, `MediaLeg::fraction_lost_since_last_report`), cumulative loss, the extended highest
/// sequence, the interarrival `jitter` estimate, and `last_sr` / `delay_last_sr` (LSR/DLSR echoed from
/// the peer's most recent Sender Report) — so the peer can compute reception quality and round-trip
/// time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceptionReport {
    /// SSRC of the source being reported on.
    pub ssrc: u32,
    /// Fraction of packets lost since the previous report (`0..=255` ⇒ `0..1`).
    pub fraction_lost: u8,
    /// Cumulative packets lost (24-bit; the top byte is ignored).
    pub cumulative_lost: u32,
    /// Extended highest sequence number received.
    pub extended_highest_seq: u32,
    /// Interarrival jitter estimate.
    pub jitter: u32,
    /// Middle 32 bits of the last SR's NTP timestamp from this source.
    pub last_sr: u32,
    /// Delay since the last SR, in 1/65536 s.
    pub delay_last_sr: u32,
}

/// Write an RTCP **Sender Report** with `reports` reception blocks (`RC = reports.len()`, capped at
/// 31) into `out`, returning its length — or `None` if `out` is too small. The conference emits one
/// per egress stream so a receiver gets the NTP↔RTP mapping (lip-sync) + liveness, plus the engine's
/// reception report on that participant's inbound stream (RFC 3550 §6.4.1).
#[must_use]
pub fn write_sender_report(
    ssrc: u32,
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    reports: &[ReceptionReport],
    out: &mut [u8],
) -> Option<usize> {
    let report_count = reports.len().min(31);
    let total = SENDER_REPORT_LEN + report_count * RECEPTION_REPORT_LEN;
    if out.len() < total {
        return None;
    }
    out[0] = 0x80 | report_count as u8; // V=2, P=0, RC
    out[1] = 200; // PT = SR
    let length_words = (total / 4 - 1) as u16;
    out[2..4].copy_from_slice(&length_words.to_be_bytes());
    out[4..8].copy_from_slice(&ssrc.to_be_bytes());
    out[8..16].copy_from_slice(&ntp_timestamp.to_be_bytes());
    out[16..20].copy_from_slice(&rtp_timestamp.to_be_bytes());
    out[20..24].copy_from_slice(&packet_count.to_be_bytes());
    out[24..28].copy_from_slice(&octet_count.to_be_bytes());
    for (index, report) in reports.iter().take(report_count).enumerate() {
        let base = SENDER_REPORT_LEN + index * RECEPTION_REPORT_LEN;
        out[base..base + 4].copy_from_slice(&report.ssrc.to_be_bytes());
        // Fraction lost (1 byte) + cumulative lost (low 24 bits).
        out[base + 4] = report.fraction_lost;
        let cumulative = (report.cumulative_lost & 0x00FF_FFFF).to_be_bytes();
        out[base + 5..base + 8].copy_from_slice(&cumulative[1..4]);
        out[base + 8..base + 12].copy_from_slice(&report.extended_highest_seq.to_be_bytes());
        out[base + 12..base + 16].copy_from_slice(&report.jitter.to_be_bytes());
        out[base + 16..base + 20].copy_from_slice(&report.last_sr.to_be_bytes());
        out[base + 20..base + 24].copy_from_slice(&report.delay_last_sr.to_be_bytes());
    }
    Some(total)
}

/// Length of [`write_goodbye`]'s compound: an empty Receiver Report (8 bytes) and a one-source BYE
/// (8 bytes).
pub const GOODBYE_LEN: usize = 16;

/// Write the compound RTCP packet that says `ssrc` is leaving (RFC 3550 §6.6) into `out`, returning
/// its length — or `None` if `out` is shorter than [`GOODBYE_LEN`].
///
/// A compound packet must open with a report (RFC 3550 §6.1), so the BYE is preceded by an empty
/// Receiver Report (`RC = 0`) from the same SSRC. Reason text is optional and omitted. The engine
/// sends one when a stream it was relaying to a party is replaced by one it originates, so the party
/// sees the old source end rather than go silent (RFC 3550 §6.3.7).
#[must_use]
pub fn write_goodbye(ssrc: u32, out: &mut [u8]) -> Option<usize> {
    let compound = out.get_mut(..GOODBYE_LEN)?;
    let ssrc = ssrc.to_be_bytes();
    // RR: V=2, P=0, RC=0, PT=201, length 1 (two 32-bit words), sender SSRC.
    compound[0..4].copy_from_slice(&[0x80, packet_type::RECEIVER_REPORT, 0, 1]);
    compound[4..8].copy_from_slice(&ssrc);
    // BYE: V=2, P=0, SC=1, PT=203, length 1, the one source leaving.
    compound[8..12].copy_from_slice(&[0x81, packet_type::BYE, 0, 1]);
    compound[12..16].copy_from_slice(&ssrc);
    Some(GOODBYE_LEN)
}

fn read_report_blocks(body: &[u8], count: usize) -> Vec<ReportBlock> {
    let mut reports = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * REPORT_BLOCK_LEN;
        match body
            .get(start..start + REPORT_BLOCK_LEN)
            .and_then(ReportBlock::parse)
        {
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
                    ntp_timestamp: (u64::from(be32(&body[4..8])) << 32)
                        | u64::from(be32(&body[8..12])),
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

/// Length of an APP packet with no application data: header word, SSRC, name (RFC 3550 §6.7).
pub const APP_HEADER_LEN: usize = 12;
/// Most application data one APP packet can carry: the 16-bit length field counts the 32-bit words
/// after the first, so a packet is at most 65536 words, two of which are the SSRC and name.
pub const APP_MAX_DATA_LEN: usize = (u16::MAX as usize + 1) * 4 - APP_HEADER_LEN;

/// One RTCP APP packet (RFC 3550 §6.7), borrowed from the datagram it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppPacket<'a> {
    /// The 5-bit subtype. For MCPTT the top bit is the acknowledgement-required flag
    /// (3GPP TS 24.380 §8.2.2.1, the 'x' bit), so it is kept rather than masked off.
    pub subtype: u8,
    /// SSRC of the sender.
    pub ssrc: u32,
    /// The 4-octet name (`MCPT`, `MCPC`, `MCMC`, ... per TS 24.380 §8.1.2). Not checked for ASCII
    /// on receive; what to do with an unexpected name is the consumer's decision.
    pub name: [u8; 4],
    /// The application-dependent data after the name, padding removed.
    pub data: &'a [u8],
}

/// Iterator over the APP packets in one datagram, from [`app_packets`].
#[derive(Debug, Clone)]
pub struct AppPackets<'a> {
    buffer: &'a [u8],
    offset: usize,
    failed: bool,
}

/// Walk every RTCP packet in `datagram` and yield the APP packets, skipping the others.
///
/// No compound rule is applied (RFC 3550 §6.1 wants an SR or RR first): MCPTT floor messages are
/// standalone APP packets that "are not to be sent in compound RTCP packets, but more than one media
/// plane control message can be sent in a single IP packet" (3GPP TS 24.380 §8.1.1). The same walk
/// reads an APP part out of an ordinary audio RTCP compound.
///
/// A malformed packet yields one `Err` and ends the walk: its length cannot be trusted, so nothing
/// after it can be located.
#[must_use]
pub fn app_packets(datagram: &[u8]) -> AppPackets<'_> {
    AppPackets {
        buffer: datagram,
        offset: 0,
        failed: false,
    }
}

impl<'a> Iterator for AppPackets<'a> {
    type Item = Result<AppPacket<'a>, RtcpError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.failed && self.offset < self.buffer.len() {
            let result = self.read_one();
            if result.is_err() {
                self.failed = true;
            }
            match result {
                Ok(None) => continue,
                Ok(Some(app)) => return Some(Ok(app)),
                Err(error) => return Some(Err(error)),
            }
        }
        None
    }
}

impl<'a> AppPackets<'a> {
    /// Read the packet at `offset` and step past it: `Ok(None)` for a packet that is not APP.
    fn read_one(&mut self) -> Result<Option<AppPacket<'a>>, RtcpError> {
        let rest = &self.buffer[self.offset..];
        let header = rest.get(..4).ok_or(RtcpError::TooShort)?;
        let version = header[0] >> 6;
        if version != 2 {
            return Err(RtcpError::BadVersion(version));
        }
        let padded = header[0] & 0x20 != 0;
        let subtype = header[0] & 0x1F;
        let packet_type = header[1];
        let packet_len = (usize::from(u16::from_be_bytes([header[2], header[3]])) + 1) * 4;
        let packet = rest.get(..packet_len).ok_or(RtcpError::BadLength)?;
        self.offset += packet_len;
        if packet_type != packet_type::APP {
            return Ok(None);
        }
        if packet.len() < APP_HEADER_LEN {
            return Err(RtcpError::TooShort);
        }
        let mut data = &packet[APP_HEADER_LEN..];
        if padded {
            // RFC 3550 §6.4.1: the last octet counts the padding octets, itself included.
            let count = usize::from(*data.last().ok_or(RtcpError::BadPadding)?);
            if count == 0 || count > data.len() {
                return Err(RtcpError::BadPadding);
            }
            data = &data[..data.len() - count];
        }
        Ok(Some(AppPacket {
            subtype,
            ssrc: be32(&packet[4..8]),
            name: [packet[8], packet[9], packet[10], packet[11]],
            data,
        }))
    }
}

/// Why [`write_app`] refused to build a packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppWriteError {
    /// The subtype field is 5 bits (RFC 3550 §6.7).
    #[error("RTCP APP subtype {0} does not fit in 5 bits")]
    SubtypeOutOfRange(u8),
    /// The name must be four ASCII characters (RFC 3550 §6.7).
    #[error("RTCP APP name is not ASCII")]
    NonAsciiName,
    /// Application data must be a multiple of 32 bits (RFC 3550 §6.7, TS 24.380 §8.1.3).
    #[error("RTCP APP data length {0} is not a multiple of 4")]
    Unaligned(usize),
    /// More data than the 16-bit length field can describe.
    #[error("RTCP APP data length {0} exceeds the length field")]
    TooLong(usize),
    /// `out` cannot hold the packet.
    #[error("RTCP APP needs a {needed}-byte buffer")]
    BufferTooSmall {
        /// Bytes the packet takes.
        needed: usize,
    },
}

/// Write one RTCP APP packet (RFC 3550 §6.7) into `out`, returning its length.
///
/// The packet is written unpadded (P=0, as TS 24.380 §8.1.2 requires for floor control). `data` is
/// copied as given: its field coding (TS 24.380 §8.1.3) belongs to the caller, so data that is not a
/// whole number of words is refused rather than padded behind the caller's back.
pub fn write_app(
    subtype: u8,
    ssrc: u32,
    name: [u8; 4],
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, AppWriteError> {
    if subtype > 0x1F {
        return Err(AppWriteError::SubtypeOutOfRange(subtype));
    }
    if !name.is_ascii() {
        return Err(AppWriteError::NonAsciiName);
    }
    if !data.len().is_multiple_of(4) {
        return Err(AppWriteError::Unaligned(data.len()));
    }
    if data.len() > APP_MAX_DATA_LEN {
        return Err(AppWriteError::TooLong(data.len()));
    }
    let total = APP_HEADER_LEN + data.len();
    let packet = out
        .get_mut(..total)
        .ok_or(AppWriteError::BufferTooSmall { needed: total })?;
    let length_words =
        u16::try_from(total / 4 - 1).map_err(|_| AppWriteError::TooLong(data.len()))?;
    packet[0] = 0x80 | subtype; // V=2, P=0
    packet[1] = packet_type::APP;
    packet[2..4].copy_from_slice(&length_words.to_be_bytes());
    packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
    packet[8..12].copy_from_slice(&name);
    packet[APP_HEADER_LEN..].copy_from_slice(data);
    Ok(total)
}

/// Rewrite the **sender SSRC** of every Sender and Receiver Report in a compound packet, in place.
///
/// For a relay that re-originates RTP under its own SSRC (the transcode path does — the peer never
/// sees the far party's SSRC), relaying RTCP untouched leaves the two disagreeing: the party receives
/// media from the engine's egress SSRC and reports *about* it from the far party's. That is not
/// cosmetic. RFC 3550 §6.4.1 defines LSR as the middle 32 bits of the NTP timestamp from the most
/// recent SR **from source SSRC_n**, so a conforming receiver files the relayed SR under a source it
/// receives no RTP from, and its report block for the stream it *does* receive carries `LSR = 0` —
/// which makes the engine's passive round-trip estimate uncomputable, and leaves a passive monitor
/// unable to correlate a leg's RTP with its RTCP at all.
///
/// Rewriting the sender SSRC to the SSRC the receiving party actually sees makes one coherent source
/// of the pair. Report *blocks* inside are deliberately left alone: their SSRC identifies the stream
/// being reported on, which is the receiving party's own, and translating that needs the peer
/// direction's ingress SSRC — state a single direction does not hold. That remains a known gap for
/// the far end's own statistics; it does not affect the round-trip estimate, which keys on the
/// engine's egress SSRC.
///
/// Returns the number of reports rewritten. A malformed or truncated compound is left untouched
/// (rewriting half a packet would be worse than relaying it verbatim).
pub fn rewrite_report_sender_ssrc(buffer: &mut [u8], ssrc: u32) -> usize {
    // Validate the whole compound before mutating any of it, so a truncated tail cannot leave a
    // half-rewritten datagram on the wire.
    let mut offset = 0;
    while offset < buffer.len() {
        let Some(header) = buffer.get(offset..offset + 4) else {
            return 0;
        };
        if header[0] >> 6 != 2 {
            return 0;
        }
        let packet_len = (u16::from_be_bytes([header[2], header[3]]) as usize + 1) * 4;
        if packet_len == 0 || offset + packet_len > buffer.len() {
            return 0;
        }
        offset += packet_len;
    }

    let mut rewritten = 0;
    let mut offset = 0;
    while offset < buffer.len() {
        let packet_type = buffer[offset + 1];
        let packet_len =
            (u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]) as usize + 1) * 4;
        // The sender SSRC is the first word of the body in both report shapes (RFC 3550 §6.4.1/§6.4.2).
        if matches!(
            packet_type,
            packet_type::SENDER_REPORT | packet_type::RECEIVER_REPORT
        ) && packet_len >= 8
        {
            buffer[offset + 4..offset + 8].copy_from_slice(&ssrc.to_be_bytes());
            rewritten += 1;
        }
        offset += packet_len;
    }
    rewritten
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
mod goodbye_tests {
    use super::*;

    #[test]
    fn a_goodbye_is_an_empty_receiver_report_then_a_one_source_bye() {
        let mut buffer = [0u8; GOODBYE_LEN];
        assert_eq!(write_goodbye(0xDEAD_BEEF, &mut buffer), Some(GOODBYE_LEN));
        assert_eq!(
            buffer,
            [
                0x80, 201, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, // RR, RC=0
                0x81, 203, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, // BYE, SC=1
            ]
        );
        let packets = parse_compound(&buffer).expect("a well-formed compound");
        assert_eq!(packets.len(), 2, "both sub-packets parse");
        assert!(matches!(
            &packets[0],
            RtcpPacket::ReceiverReport(report) if report.ssrc == 0xDEAD_BEEF && report.reports.is_empty()
        ));
        assert!(matches!(
            &packets[1],
            RtcpPacket::Other {
                packet_type: 203,
                ..
            }
        ));
    }

    #[test]
    fn a_goodbye_refuses_a_buffer_too_short_to_hold_it() {
        let mut buffer = [0u8; GOODBYE_LEN - 1];
        assert_eq!(write_goodbye(1, &mut buffer), None);
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
    fn writes_a_parseable_sender_report() {
        // The SR we build must round-trip through the parser, field for field.
        let mut buffer = [0u8; 64];
        let len = write_sender_report(
            0xDEAD_BEEF,
            0x1122_3344_5566_7788,
            0x0001_0000,
            42,
            6720,
            &[],
            &mut buffer,
        )
        .expect("write");
        assert_eq!(len, SENDER_REPORT_LEN);
        let packets = parse_compound(&buffer[..len]).expect("parse");
        assert_eq!(packets.len(), 1);
        match &packets[0] {
            RtcpPacket::SenderReport(report) => {
                assert_eq!(report.ssrc, 0xDEAD_BEEF);
                assert_eq!(report.ntp_timestamp, 0x1122_3344_5566_7788);
                assert_eq!(report.rtp_timestamp, 0x0001_0000);
                assert_eq!(report.packet_count, 42);
                assert_eq!(report.octet_count, 6720);
                assert!(report.reports.is_empty(), "no reception blocks (RC = 0)");
            }
            other => panic!("expected SR, got {other:?}"),
        }
    }

    #[test]
    fn writes_a_sender_report_with_a_reception_block() {
        // SR + one reception report (RC = 1) round-trips through the parser.
        let report = ReceptionReport {
            ssrc: 0xAABB_CCDD,
            fraction_lost: 0,
            cumulative_lost: 5,
            extended_highest_seq: 0x0001_2345,
            ..ReceptionReport::default()
        };
        let mut buffer = [0u8; 64];
        let len = write_sender_report(
            0x1111_2222,
            0,
            0x0000_1000,
            100,
            16_000,
            &[report],
            &mut buffer,
        )
        .expect("write");
        assert_eq!(len, SENDER_REPORT_LEN + RECEPTION_REPORT_LEN);
        let packets = parse_compound(&buffer[..len]).expect("parse");
        match &packets[0] {
            RtcpPacket::SenderReport(sr) => {
                assert_eq!(sr.ssrc, 0x1111_2222);
                assert_eq!(sr.reports.len(), 1, "one reception block");
                let block = &sr.reports[0];
                assert_eq!(block.ssrc, 0xAABB_CCDD);
                assert_eq!(block.cumulative_lost, 5);
                assert_eq!(block.highest_sequence, 0x0001_2345);
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

    /// TS 24.380 §8.2.4 Floor Request (subtype '00000') carrying a Floor Priority field
    /// (§8.2.3.2: field ID 0, length 2, priority 5, one spare octet). Cross-checked with tshark's
    /// RTCP MCPT dissector, which reads it as "Floor Request, Floor Priority: 5".
    const FLOOR_REQUEST: [u8; 16] = [
        0x80, 0xCC, 0x00, 0x03, // V=2 P=0 subtype=0, PT=204, length=3 words
        0x11, 0x22, 0x33, 0x44, // SSRC of the requesting floor participant
        b'M', b'C', b'P', b'T', // name
        0x00, 0x02, 0x05, 0x00, // Floor Priority field
    ];

    /// TS 24.380 §8.2.5 Floor Granted with the acknowledgement bit set (subtype 'x0001', x=1 ⇒ 17),
    /// a Duration field (§8.2.3.3: ID 1, length 2, 30 s) and an Audio SSRC of Granted Participant
    /// field (§8.2.3.16: ID 14, length 6, SSRC, two spare octets). tshark reads it as
    /// "Floor Granted(ack req), Duration: 30 seconds, SSRC: 305419896".
    const FLOOR_GRANTED: [u8; 24] = [
        0x91, 0xCC, 0x00, 0x05, // V=2 P=0 subtype=17, PT=204, length=5 words
        0xAA, 0xBB, 0xCC, 0xDD, // RTCP SSRC of the floor control server
        b'M', b'C', b'P', b'T', // name
        0x01, 0x02, 0x00, 0x1E, // Duration field
        0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, // Audio SSRC of Granted Participant
    ];

    #[test]
    fn reads_a_floor_request_app_packet() {
        let packets: Vec<_> = app_packets(&FLOOR_REQUEST).collect();
        assert_eq!(packets.len(), 1);
        let app = packets[0].as_ref().expect("valid APP");
        assert_eq!(app.subtype, 0);
        assert_eq!(app.ssrc, 0x1122_3344);
        assert_eq!(&app.name, b"MCPT");
        assert_eq!(app.data, &FLOOR_REQUEST[12..]);
    }

    #[test]
    fn reads_the_acknowledgement_bit_as_part_of_the_subtype() {
        let app = app_packets(&FLOOR_GRANTED)
            .next()
            .expect("one packet")
            .expect("valid APP");
        assert_eq!(
            app.subtype, 0b1_0001,
            "x bit + Floor Granted (TS 24.380 §8.2.2.1)"
        );
        assert_eq!(app.ssrc, 0xAABB_CCDD);
        assert_eq!(app.data, &FLOOR_GRANTED[12..]);
    }

    #[test]
    fn reads_several_standalone_app_packets_in_one_datagram() {
        // TS 24.380 §8.1.1: not a compound packet (no SR/RR first), but several messages may
        // share one IP packet.
        let mut datagram = FLOOR_REQUEST.to_vec();
        datagram.extend_from_slice(&FLOOR_GRANTED);
        let packets: Vec<_> = app_packets(&datagram)
            .collect::<Result<_, _>>()
            .expect("both valid");
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].subtype, 0);
        assert_eq!(packets[1].subtype, 17);
    }

    #[test]
    fn skips_reports_and_yields_app_parts_of_a_compound() {
        // An audio RTCP compound (SR first, RFC 3550 §6.1) with an APP part some clients append.
        let mut datagram = vec![0x80, 200, 0x00, 0x06];
        datagram.extend_from_slice(&[0u8; 24]);
        datagram.extend_from_slice(&FLOOR_REQUEST);
        let packets: Vec<_> = app_packets(&datagram)
            .collect::<Result<_, _>>()
            .expect("valid");
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].ssrc, 0x1122_3344);
    }

    #[test]
    fn strips_rtcp_padding_from_app_data() {
        // RFC 3550 §6.4.1: P=1, the last octet counts the padding octets (including itself).
        let mut datagram = FLOOR_REQUEST.to_vec();
        datagram[0] |= 0x20;
        datagram[3] = 4; // one more word
        datagram.extend_from_slice(&[0, 0, 0, 4]);
        let app = app_packets(&datagram).next().expect("one").expect("valid");
        assert_eq!(app.data, &FLOOR_REQUEST[12..]);
    }

    #[test]
    fn refuses_padding_longer_than_the_application_data() {
        let mut datagram = FLOOR_REQUEST.to_vec();
        datagram[0] |= 0x20;
        datagram[15] = 9; // claims 9 padding octets, only 4 data octets exist
        assert_eq!(
            app_packets(&datagram).next(),
            Some(Err(RtcpError::BadPadding))
        );
        datagram[15] = 0; // a zero padding count is equally invalid
        assert_eq!(
            app_packets(&datagram).next(),
            Some(Err(RtcpError::BadPadding))
        );
    }

    #[test]
    fn refuses_an_app_packet_without_room_for_ssrc_and_name() {
        // Length 1 word: only the SSRC, no name (RFC 3550 §6.7 needs both).
        let datagram = [0x80, 0xCC, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(
            app_packets(&datagram).next(),
            Some(Err(RtcpError::TooShort))
        );
    }

    #[test]
    fn stops_after_the_first_malformed_packet() {
        let mut datagram = FLOOR_REQUEST.to_vec();
        datagram.extend_from_slice(&[0x80, 0xCC, 0x00, 0x09]); // overruns the buffer
        let results: Vec<_> = app_packets(&datagram).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_eq!(results[1], Err(RtcpError::BadLength));
    }

    #[test]
    fn rejects_a_non_version_2_header() {
        let mut datagram = FLOOR_REQUEST;
        datagram[0] = 0x40 | (datagram[0] & 0x3F);
        assert_eq!(
            app_packets(&datagram).next(),
            Some(Err(RtcpError::BadVersion(1)))
        );
    }

    #[test]
    fn an_empty_datagram_has_no_app_packets() {
        assert_eq!(app_packets(&[]).next(), None);
    }

    #[test]
    fn writes_the_floor_request_vector_byte_for_byte() {
        let mut out = [0u8; 64];
        let len =
            write_app(0, 0x1122_3344, *b"MCPT", &FLOOR_REQUEST[12..], &mut out).expect("write");
        assert_eq!(&out[..len], &FLOOR_REQUEST);
    }

    #[test]
    fn writes_the_floor_granted_vector_byte_for_byte() {
        let mut out = [0u8; 64];
        let len =
            write_app(17, 0xAABB_CCDD, *b"MCPT", &FLOOR_GRANTED[12..], &mut out).expect("write");
        assert_eq!(&out[..len], &FLOOR_GRANTED);
    }

    #[test]
    fn writes_an_app_packet_with_no_application_data() {
        let mut out = [0u8; 12];
        let len = write_app(5, 1, *b"MCPC", &[], &mut out).expect("write");
        assert_eq!(
            &out[..len],
            &[0x85, 0xCC, 0, 2, 0, 0, 0, 1, b'M', b'C', b'P', b'C']
        );
    }

    #[test]
    fn write_app_refuses_a_subtype_wider_than_five_bits() {
        let mut out = [0u8; 64];
        assert_eq!(
            write_app(32, 0, *b"MCPT", &[], &mut out),
            Err(AppWriteError::SubtypeOutOfRange(32))
        );
    }

    #[test]
    fn write_app_refuses_data_that_is_not_word_aligned() {
        // RFC 3550 §6.7 / TS 24.380 §8.1.3: application data is a multiple of 32 bits. The
        // caller owns the field coding, so the engine refuses rather than padding it silently.
        let mut out = [0u8; 64];
        assert_eq!(
            write_app(0, 0, *b"MCPT", &[0, 2, 5], &mut out),
            Err(AppWriteError::Unaligned(3))
        );
    }

    #[test]
    fn write_app_refuses_a_non_ascii_name() {
        let mut out = [0u8; 64];
        assert_eq!(
            write_app(0, 0, [b'M', 0xC3, b'P', b'T'], &[], &mut out),
            Err(AppWriteError::NonAsciiName)
        );
    }

    #[test]
    fn write_app_refuses_a_short_buffer() {
        let mut out = [0u8; 15];
        assert_eq!(
            write_app(0, 0, *b"MCPT", &FLOOR_REQUEST[12..], &mut out),
            Err(AppWriteError::BufferTooSmall { needed: 16 })
        );
    }

    #[test]
    fn write_app_refuses_data_past_the_length_field() {
        // The 16-bit length counts words after the first, so a packet tops out at 65536 words.
        let data = vec![0u8; APP_MAX_DATA_LEN + 4];
        let mut out = vec![0u8; data.len() + APP_HEADER_LEN];
        assert_eq!(
            write_app(0, 0, *b"MCPT", &data, &mut out),
            Err(AppWriteError::TooLong(data.len()))
        );
        let data = vec![0u8; APP_MAX_DATA_LEN];
        assert!(write_app(0, 0, *b"MCPT", &data, &mut out).is_ok());
    }

    #[test]
    fn app_write_error_messages_name_the_problem() {
        assert_eq!(
            AppWriteError::SubtypeOutOfRange(40).to_string(),
            "RTCP APP subtype 40 does not fit in 5 bits"
        );
        assert_eq!(
            AppWriteError::Unaligned(3).to_string(),
            "RTCP APP data length 3 is not a multiple of 4"
        );
        assert_eq!(
            AppWriteError::BufferTooSmall { needed: 16 }.to_string(),
            "RTCP APP needs a 16-byte buffer"
        );
        assert_eq!(
            RtcpError::BadPadding.to_string(),
            "RTCP padding count is invalid"
        );
    }

    #[test]
    fn parse_compound_still_reports_app_as_other() {
        let packets = parse_compound(&FLOOR_REQUEST).expect("parse");
        assert_eq!(
            packets,
            vec![RtcpPacket::Other {
                packet_type: packet_type::APP
            }]
        );
    }

    use proptest::prelude::*;

    proptest! {
        /// Arbitrary (malformed / truncated / compound) bytes must decode-or-error, never panic.
        #[test]
        fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_compound(&bytes);
            let _ = demux(&bytes);
            for result in app_packets(&bytes) {
                let _ = result;
            }
        }

        /// What `write_app` builds, `app_packets` reads back field for field.
        #[test]
        fn written_app_packets_read_back(
            subtype in 0u8..32,
            ssrc in any::<u32>(),
            name in prop::array::uniform4(0x20u8..0x7F),
            words in prop::collection::vec(any::<[u8; 4]>(), 0..64),
        ) {
            let data: Vec<u8> = words.concat();
            let mut out = vec![0u8; APP_HEADER_LEN + data.len()];
            let len = write_app(subtype, ssrc, name, &data, &mut out).expect("write");
            let packets: Vec<_> = app_packets(&out[..len]).collect();
            prop_assert_eq!(packets.len(), 1);
            let app = packets[0].as_ref().expect("valid");
            prop_assert_eq!(app.subtype, subtype);
            prop_assert_eq!(app.ssrc, ssrc);
            prop_assert_eq!(app.name, name);
            prop_assert_eq!(app.data, &data[..]);
        }
    }
}
