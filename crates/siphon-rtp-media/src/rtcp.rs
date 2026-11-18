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

/// One packet of a compound RTCP datagram: its header fields and body (RFC 3550 §6.4).
struct Part<'a> {
    report_count: usize,
    packet_type: u8,
    body: &'a [u8],
}

/// The packet of `buffer` at `offset`, header-checked, and where the next one starts.
fn part_at(buffer: &[u8], offset: usize) -> Result<(Part<'_>, usize), RtcpError> {
    if buffer.len() - offset < 4 {
        return Err(RtcpError::TooShort);
    }
    let header = &buffer[offset..];
    let version = header[0] >> 6;
    if version != 2 {
        return Err(RtcpError::BadVersion(version));
    }
    let length_words = u16::from_be_bytes([header[2], header[3]]) as usize;
    let packet_len = (length_words + 1) * 4;
    if offset + packet_len > buffer.len() {
        return Err(RtcpError::BadLength);
    }
    let part = Part {
        report_count: (header[0] & 0x1F) as usize,
        packet_type: header[1],
        body: &buffer[offset + 4..offset + packet_len],
    };
    Ok((part, offset + packet_len))
}

/// The reception report blocks of an SR or RR part, empty for any other packet.
fn blocks_of<'a>(part: &Part<'a>) -> (&'a [u8], usize) {
    match part.packet_type {
        packet_type::SENDER_REPORT if part.body.len() >= 24 => {
            (&part.body[24..], part.report_count)
        }
        packet_type::RECEIVER_REPORT if part.body.len() >= 4 => {
            (&part.body[4..], part.report_count)
        }
        _ => (&[], 0),
    }
}

/// Parse a (possibly compound) RTCP packet into its constituent reports.
pub fn parse_compound(buffer: &[u8]) -> Result<Vec<RtcpPacket>, RtcpError> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < buffer.len() {
        let (part, next) = part_at(buffer, offset)?;
        let body = part.body;
        match part.packet_type {
            packet_type::SENDER_REPORT if body.len() >= 24 => {
                packets.push(RtcpPacket::SenderReport(SenderReport {
                    ssrc: be32(&body[0..4]),
                    ntp_timestamp: (u64::from(be32(&body[4..8])) << 32)
                        | u64::from(be32(&body[8..12])),
                    rtp_timestamp: be32(&body[12..16]),
                    packet_count: be32(&body[16..20]),
                    octet_count: be32(&body[20..24]),
                    reports: read_report_blocks(body.get(24..).unwrap_or(&[]), part.report_count),
                }));
            }
            packet_type::RECEIVER_REPORT if body.len() >= 4 => {
                packets.push(RtcpPacket::ReceiverReport(ReceiverReport {
                    ssrc: be32(&body[0..4]),
                    reports: read_report_blocks(body.get(4..).unwrap_or(&[]), part.report_count),
                }));
            }
            other => packets.push(RtcpPacket::Other { packet_type: other }),
        }
        offset = next;
    }
    Ok(packets)
}

/// Hand every reception report block of the SR and RR packets of a (possibly compound) datagram to
/// `visit`, in order, without allocating (the walk [`parse_compound`] makes, minus the vectors).
///
/// The whole datagram is checked first: when any packet in it is malformed nothing is visited and
/// the same error [`parse_compound`] gives is returned.
///
/// # Errors
/// [`RtcpError`] for a datagram [`parse_compound`] refuses.
pub fn for_each_report_block(
    buffer: &[u8],
    mut visit: impl FnMut(&ReportBlock),
) -> Result<(), RtcpError> {
    let mut offset = 0;
    while offset < buffer.len() {
        offset = part_at(buffer, offset)?.1;
    }
    let mut offset = 0;
    while offset < buffer.len() {
        let (part, next) = part_at(buffer, offset)?;
        let (blocks, count) = blocks_of(&part);
        for index in 0..count {
            let start = index * REPORT_BLOCK_LEN;
            match blocks
                .get(start..start + REPORT_BLOCK_LEN)
                .and_then(ReportBlock::parse)
            {
                Some(block) => visit(&block),
                None => break,
            }
        }
        offset = next;
    }
    Ok(())
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

/// RTCP transport-layer feedback packet type (RFC 4585 §6.1, RTPFB).
pub const RTPFB: u8 = 205;
/// RTCP payload-specific feedback packet type (RFC 4585 §6.1, PSFB).
pub const PSFB: u8 = 206;
/// RTPFB format of a Generic NACK (RFC 4585 §6.2.1).
const FORMAT_GENERIC_NACK: u8 = 1;
/// PSFB format of a Picture Loss Indication (RFC 4585 §6.3.1).
const FORMAT_PLI: u8 = 1;
/// PSFB format of a Full Intra Request (RFC 5104 §4.3.1).
const FORMAT_FIR: u8 = 4;

/// Length of [`write_pli`]'s packet: header, sender SSRC, media source SSRC (RFC 4585 §6.1).
pub const PLI_LEN: usize = 12;
/// Length of [`write_fir`]'s packet: the common feedback header and one FCI entry (RFC 5104
/// §4.3.1.1).
pub const FIR_LEN: usize = 20;
/// Length of [`write_nack`]'s packet: the common feedback header and one FCI entry (RFC 4585 §6.2.1).
pub const NACK_LEN: usize = 16;
/// Length of [`write_empty_receiver_report`]'s packet (RFC 3550 §6.4.2 with RC = 0).
pub const EMPTY_RECEIVER_REPORT_LEN: usize = 8;

/// The common header of a feedback packet (RFC 4585 §6.1) and the two SSRCs after it.
fn write_feedback_header(
    packet_type: u8,
    format: u8,
    length_words: u16,
    sender_ssrc: u32,
    media_ssrc: u32,
    out: &mut [u8],
) {
    out[0] = 0x80 | format; // V=2, P=0, FMT
    out[1] = packet_type;
    out[2..4].copy_from_slice(&length_words.to_be_bytes());
    out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
    out[8..12].copy_from_slice(&media_ssrc.to_be_bytes());
}

/// Write a Picture Loss Indication (RFC 4585 §6.3.1: PSFB, FMT 1, no FCI) from `sender_ssrc` about
/// the stream `media_ssrc`, returning its length, or `None` when `out` is shorter than [`PLI_LEN`].
#[must_use]
pub fn write_pli(sender_ssrc: u32, media_ssrc: u32, out: &mut [u8]) -> Option<usize> {
    let packet = out.get_mut(..PLI_LEN)?;
    write_feedback_header(PSFB, FORMAT_PLI, 2, sender_ssrc, media_ssrc, packet);
    Some(PLI_LEN)
}

/// Write a Full Intra Request with one entry (RFC 5104 §4.3.1.1: PSFB, FMT 4) asking `target_ssrc`
/// for a decoder refresh point, returning its length, or `None` when `out` is shorter than
/// [`FIR_LEN`].
///
/// The header's media source SSRC is 0 (§4.3.1.2: the targets are named in the entries), and
/// `sequence` is the command sequence number: it increments for each new request, and a repeat of
/// one that was not answered carries the same number so a receiver that did act on the first can
/// tell (§4.3.1.2).
#[must_use]
pub fn write_fir(
    sender_ssrc: u32,
    target_ssrc: u32,
    sequence: u8,
    out: &mut [u8],
) -> Option<usize> {
    let packet = out.get_mut(..FIR_LEN)?;
    write_feedback_header(PSFB, FORMAT_FIR, 4, sender_ssrc, 0, packet);
    packet[12..16].copy_from_slice(&target_ssrc.to_be_bytes());
    packet[16] = sequence;
    packet[17..20].copy_from_slice(&[0, 0, 0]); // reserved
    Some(FIR_LEN)
}

/// Write a Generic NACK with one FCI entry (RFC 4585 §6.2.1: RTPFB, FMT 1): `pid` is the first
/// sequence number lost and bit `n` of `blp` says whether `pid + n + 1` was lost too. Returns its
/// length, or `None` when `out` is shorter than [`NACK_LEN`].
#[must_use]
pub fn write_nack(
    sender_ssrc: u32,
    media_ssrc: u32,
    pid: u16,
    blp: u16,
    out: &mut [u8],
) -> Option<usize> {
    let packet = out.get_mut(..NACK_LEN)?;
    write_feedback_header(
        RTPFB,
        FORMAT_GENERIC_NACK,
        3,
        sender_ssrc,
        media_ssrc,
        packet,
    );
    packet[12..14].copy_from_slice(&pid.to_be_bytes());
    packet[14..16].copy_from_slice(&blp.to_be_bytes());
    Some(NACK_LEN)
}

/// Write an empty Receiver Report from `ssrc` (RFC 3550 §6.4.2, RC = 0): the report every compound
/// opens with when the sender has sent no media (§6.1; RFC 4585 §3.1 for feedback), returning its
/// length, or `None` when `out` is shorter than [`EMPTY_RECEIVER_REPORT_LEN`].
#[must_use]
pub fn write_empty_receiver_report(ssrc: u32, out: &mut [u8]) -> Option<usize> {
    let packet = out.get_mut(..EMPTY_RECEIVER_REPORT_LEN)?;
    packet[0..4].copy_from_slice(&[0x80, packet_type::RECEIVER_REPORT, 0, 1]);
    packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
    Some(EMPTY_RECEIVER_REPORT_LEN)
}

/// Write a Source Description with one chunk for `ssrc` carrying its CNAME (RFC 3550 §6.5, §6.5.1),
/// returning its length, or `None` when `cname` is over the 255 octets an item holds (§6.5) or `out`
/// is too short.
///
/// The item list ends with at least one null octet, and more follow to the next 32-bit boundary.
#[must_use]
pub fn write_sdes_cname(ssrc: u32, cname: &str, out: &mut [u8]) -> Option<usize> {
    const ITEM_CNAME: u8 = 1;
    let text = cname.as_bytes();
    if text.len() > usize::from(u8::MAX) {
        return None;
    }
    // Header, SSRC, item type and length, the text, and the terminating null; then word padding.
    let total = (4 + 4 + 2 + text.len() + 1).next_multiple_of(4);
    let packet = out.get_mut(..total)?;
    let length_words = u16::try_from(total / 4 - 1).ok()?;
    packet[0] = 0x81; // V=2, P=0, SC=1
    packet[1] = packet_type::SOURCE_DESCRIPTION;
    packet[2..4].copy_from_slice(&length_words.to_be_bytes());
    packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
    packet[8] = ITEM_CNAME;
    packet[9] = text.len() as u8;
    packet[10..10 + text.len()].copy_from_slice(text);
    packet[10 + text.len()..].fill(0);
    Some(total)
}

/// One Full Intra Request entry (RFC 5104 §4.3.1.1): the stream asked for a refresh point and the
/// command sequence number of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirEntry {
    /// SSRC of the stream the sender asks to refresh.
    pub ssrc: u32,
    /// Command sequence number (RFC 5104 §4.3.1.2).
    pub sequence: u8,
}

/// The entries of one Full Intra Request, borrowed from the datagram (8 octets each; a ragged tail
/// shorter than an entry is ignored).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirEntries<'a> {
    fci: &'a [u8],
}

impl Iterator for FirEntries<'_> {
    type Item = FirEntry;

    fn next(&mut self) -> Option<FirEntry> {
        let entry = self.fci.get(..8)?;
        self.fci = &self.fci[8..];
        Some(FirEntry {
            ssrc: be32(&entry[0..4]),
            sequence: entry[4],
        })
    }
}

/// One feedback message read out of a datagram by [`feedback_packets`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback<'a> {
    /// A Picture Loss Indication (RFC 4585 §6.3.1).
    Pli {
        /// SSRC of the sender of the feedback.
        sender_ssrc: u32,
        /// SSRC of the stream that lost a picture.
        media_ssrc: u32,
    },
    /// A Full Intra Request (RFC 5104 §4.3.1).
    Fir {
        /// SSRC of the sender of the request.
        sender_ssrc: u32,
        /// The streams it asks to refresh.
        entries: FirEntries<'a>,
    },
    /// One FCI entry of a Generic NACK (RFC 4585 §6.2.1): a packet in a stream lost, and the 16
    /// that follow it.
    GenericNack {
        /// SSRC of the sender of the feedback.
        sender_ssrc: u32,
        /// SSRC of the stream that lost packets.
        media_ssrc: u32,
        /// First sequence number lost.
        pid: u16,
        /// Bit `n` set: `pid + n + 1` was lost too.
        blp: u16,
    },
}

/// Iterator over the feedback messages of one datagram, from [`feedback_packets`].
#[derive(Debug, Clone)]
pub struct FeedbackPackets<'a> {
    buffer: &'a [u8],
    offset: usize,
    failed: bool,
    /// The rest of a Generic NACK's FCI, one item per 4 octets, with its two SSRCs.
    nack: Option<(u32, u32, &'a [u8])>,
}

/// Walk every RTCP packet in `datagram` and yield the feedback messages in it (PLI, FIR, Generic
/// NACK), skipping every other packet.
///
/// No compound rule is applied: feedback rides in a compound (RFC 4585 §3.1) or alone in a
/// reduced-size packet (RFC 5506). A Generic NACK with several FCI entries yields one item each.
/// A malformed packet yields one `Err` and ends the walk: its length cannot be trusted, so nothing
/// after it can be located. Nothing is allocated.
#[must_use]
pub fn feedback_packets(datagram: &[u8]) -> FeedbackPackets<'_> {
    FeedbackPackets {
        buffer: datagram,
        offset: 0,
        failed: false,
        nack: None,
    }
}

impl<'a> Iterator for FeedbackPackets<'a> {
    type Item = Result<Feedback<'a>, RtcpError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((sender_ssrc, media_ssrc, fci)) = self.nack {
                if let Some(entry) = fci.get(..4) {
                    self.nack = Some((sender_ssrc, media_ssrc, &fci[4..]));
                    return Some(Ok(Feedback::GenericNack {
                        sender_ssrc,
                        media_ssrc,
                        pid: u16::from_be_bytes([entry[0], entry[1]]),
                        blp: u16::from_be_bytes([entry[2], entry[3]]),
                    }));
                }
                self.nack = None;
            }
            if self.failed || self.offset >= self.buffer.len() {
                return None;
            }
            match self.read_one() {
                Ok(Some(feedback)) => return Some(Ok(feedback)),
                Ok(None) => {}
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

impl<'a> FeedbackPackets<'a> {
    /// Read the packet at `offset` and step past it: the first message of a feedback packet, or
    /// `Ok(None)` for a packet with none (another type, a format this does not read, a NACK whose
    /// entries follow from [`Iterator::next`]).
    fn read_one(&mut self) -> Result<Option<Feedback<'a>>, RtcpError> {
        let rest = &self.buffer[self.offset..];
        let header = rest.get(..4).ok_or(RtcpError::TooShort)?;
        let version = header[0] >> 6;
        if version != 2 {
            return Err(RtcpError::BadVersion(version));
        }
        let padded = header[0] & 0x20 != 0;
        let format = header[0] & 0x1F;
        let packet_type = header[1];
        let packet_len = (usize::from(u16::from_be_bytes([header[2], header[3]])) + 1) * 4;
        let packet = rest.get(..packet_len).ok_or(RtcpError::BadLength)?;
        self.offset += packet_len;
        if !matches!(
            (packet_type, format),
            (RTPFB, FORMAT_GENERIC_NACK) | (PSFB, FORMAT_PLI | FORMAT_FIR)
        ) {
            return Ok(None);
        }
        // Header, sender SSRC and media source SSRC (RFC 4585 §6.1), then the FCI.
        if packet.len() < PLI_LEN {
            return Err(RtcpError::TooShort);
        }
        let mut fci = &packet[PLI_LEN..];
        if padded {
            // RFC 3550 §6.4.1: the last octet counts the padding octets, itself included.
            let count = usize::from(*packet.last().ok_or(RtcpError::BadPadding)?);
            if count == 0 || count > fci.len() {
                return Err(RtcpError::BadPadding);
            }
            fci = &fci[..fci.len() - count];
        }
        let (sender_ssrc, media_ssrc) = (be32(&packet[4..8]), be32(&packet[8..12]));
        match (packet_type, format) {
            (PSFB, FORMAT_PLI) => Ok(Some(Feedback::Pli {
                sender_ssrc,
                media_ssrc,
            })),
            (PSFB, _) => Ok(Some(Feedback::Fir {
                sender_ssrc,
                entries: FirEntries { fci },
            })),
            _ => {
                self.nack = Some((sender_ssrc, media_ssrc, fci));
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod feedback_tests {
    use super::*;

    /// RFC 4585 §6.3.1 / §6.1: V=2, P=0, FMT=1, PT=206 (PSFB), length 2, sender, media source.
    const PLI: [u8; 12] = [
        0x81, 0xCE, 0x00, 0x02, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
    ];
    /// RFC 5104 §4.3.1.1: FMT=4, PT=206, length 4; the media source SSRC is 0 (§4.3.1.2), the one FCI
    /// entry carries the target SSRC, the command sequence number 5 and 24 reserved bits.
    const FIR: [u8; 20] = [
        0x84, 0xCE, 0x00, 0x04, 0x11, 0x11, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x44,
        0x44, 0x05, 0x00, 0x00, 0x00,
    ];
    /// RFC 4585 §6.2.1: FMT=1, PT=205 (RTPFB), length 3; FCI is PID 0x1234 and BLP 0x8001.
    const NACK: [u8; 16] = [
        0x81, 0xCD, 0x00, 0x03, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x12, 0x34, 0x80,
        0x01,
    ];

    #[test]
    fn a_pli_is_the_rfc_4585_layout() {
        let mut out = [0u8; 12];
        assert_eq!(write_pli(0x1111_2222, 0x3333_4444, &mut out), Some(12));
        assert_eq!(out, PLI);
        assert_eq!(write_pli(1, 2, &mut [0u8; 11]), None);
    }

    #[test]
    fn a_fir_is_the_rfc_5104_layout() {
        let mut out = [0u8; 20];
        assert_eq!(write_fir(0x1111_2222, 0x3333_4444, 5, &mut out), Some(20));
        assert_eq!(out, FIR);
        assert_eq!(write_fir(1, 2, 3, &mut [0u8; 19]), None);
    }

    #[test]
    fn a_generic_nack_is_the_rfc_4585_layout() {
        let mut out = [0u8; 16];
        assert_eq!(
            write_nack(0x1111_2222, 0x3333_4444, 0x1234, 0x8001, &mut out),
            Some(16)
        );
        assert_eq!(out, NACK);
        assert_eq!(write_nack(1, 2, 3, 4, &mut [0u8; 15]), None);
    }

    #[test]
    fn an_empty_receiver_report_is_rc_zero_and_the_sender() {
        let mut out = [0u8; 8];
        assert_eq!(write_empty_receiver_report(0xAABB_CCDD, &mut out), Some(8));
        assert_eq!(out, [0x80, 0xC9, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(write_empty_receiver_report(1, &mut [0u8; 7]), None);
    }

    #[test]
    fn an_sdes_cname_is_one_chunk_with_a_null_terminated_item_padded_to_a_word() {
        // RFC 3550 §6.5: SSRC, item type 1, length 3, "abc", then nulls to the next 32-bit boundary
        // (at least one, which ends the list).
        let mut out = [0u8; 16];
        assert_eq!(write_sdes_cname(0xAABB_CCDD, "abc", &mut out), Some(16));
        assert_eq!(
            out,
            [
                0x81, 0xCA, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x03, b'a', b'b', b'c', 0, 0,
                0
            ]
        );
        // A name that ends on a word boundary still gets a whole word of nulls.
        let mut out = [0u8; 16];
        assert_eq!(write_sdes_cname(1, "ab", &mut out), Some(16));
        assert_eq!(out[8..], [0x01, 0x02, b'a', b'b', 0, 0, 0, 0]);
        assert_eq!(out[2..4], [0x00, 0x03]);
        assert_eq!(write_sdes_cname(1, "abc", &mut [0u8; 15]), None);
        assert_eq!(write_sdes_cname(1, &"x".repeat(256), &mut [0u8; 400]), None);
    }

    #[test]
    fn the_compound_pieces_parse_as_a_compound() {
        let mut out = [0u8; 64];
        let mut length = write_empty_receiver_report(7, &mut out).unwrap();
        length += write_sdes_cname(7, "cname", &mut out[length..]).unwrap();
        length += write_pli(7, 9, &mut out[length..]).unwrap();
        let packets = parse_compound(&out[..length]).unwrap();
        assert_eq!(packets.len(), 3);
        assert!(matches!(&packets[0], RtcpPacket::ReceiverReport(report) if report.ssrc == 7));
        assert!(matches!(
            &packets[2],
            RtcpPacket::Other { packet_type: 206 }
        ));
    }

    fn feedback_of(datagram: &[u8]) -> Vec<Feedback<'_>> {
        feedback_packets(datagram).map(Result::unwrap).collect()
    }

    #[test]
    fn a_pli_is_read_back() {
        assert_eq!(
            feedback_of(&PLI),
            [Feedback::Pli {
                sender_ssrc: 0x1111_2222,
                media_ssrc: 0x3333_4444
            }]
        );
    }

    #[test]
    fn a_fir_is_read_back_with_its_entries() {
        let feedback = feedback_of(&FIR);
        let [Feedback::Fir {
            sender_ssrc,
            entries,
        }] = feedback.as_slice()
        else {
            panic!("one fir: {feedback:?}");
        };
        assert_eq!(*sender_ssrc, 0x1111_2222);
        assert_eq!(
            entries.collect::<Vec<_>>(),
            [FirEntry {
                ssrc: 0x3333_4444,
                sequence: 5
            }]
        );
    }

    #[test]
    fn a_fir_with_two_entries_yields_both_and_ignores_a_ragged_tail() {
        let mut datagram = vec![
            0x84, 0xCE, 0x00, 0x06, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 10, 1, 0, 0, 0, 0, 0, 0, 11,
            2, 0, 0, 0,
        ];
        let feedback = feedback_of(&datagram);
        let [Feedback::Fir { entries, .. }] = feedback.as_slice() else {
            panic!("one fir");
        };
        assert_eq!(
            entries
                .map(|entry| (entry.ssrc, entry.sequence))
                .collect::<Vec<_>>(),
            [(10, 1), (11, 2)]
        );
        // Four stray octets after the entries (a length that does not divide into entries).
        datagram[3] = 0x07;
        datagram.extend_from_slice(&[9, 9, 9, 9]);
        let feedback = feedback_of(&datagram);
        let [Feedback::Fir { entries, .. }] = feedback.as_slice() else {
            panic!("one fir");
        };
        assert_eq!(entries.count(), 2);
    }

    #[test]
    fn a_generic_nack_is_read_back_one_item_per_fci() {
        assert_eq!(
            feedback_of(&NACK),
            [Feedback::GenericNack {
                sender_ssrc: 0x1111_2222,
                media_ssrc: 0x3333_4444,
                pid: 0x1234,
                blp: 0x8001
            }]
        );
        // Two FCI entries in one packet (RFC 4585 §6.1: length 4).
        let two = [
            0x81, 0xCD, 0x00, 0x04, 0, 0, 0, 1, 0, 0, 0, 2, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20,
            0x00, 0x01,
        ];
        assert_eq!(
            feedback_of(&two),
            [
                Feedback::GenericNack {
                    sender_ssrc: 1,
                    media_ssrc: 2,
                    pid: 0x10,
                    blp: 0
                },
                Feedback::GenericNack {
                    sender_ssrc: 1,
                    media_ssrc: 2,
                    pid: 0x20,
                    blp: 1
                },
            ]
        );
    }

    #[test]
    fn feedback_is_found_in_a_compound_and_in_a_reduced_size_packet() {
        // RFC 4585 §3.1: RR, SDES, then the feedback. RFC 5506: the feedback alone.
        let mut compound = vec![0x80, 0xC9, 0x00, 0x01, 0x11, 0x11, 0x22, 0x22];
        let mut sdes = [0u8; 16];
        write_sdes_cname(0x1111_2222, "abc", &mut sdes).unwrap();
        compound.extend_from_slice(&sdes);
        compound.extend_from_slice(&PLI);
        compound.extend_from_slice(&NACK);
        assert_eq!(feedback_of(&compound).len(), 2);
        assert_eq!(feedback_of(&PLI).len(), 1);
        assert!(feedback_of(&[0x80, 0xC9, 0x00, 0x01, 0, 0, 0, 1]).is_empty());
    }

    #[test]
    fn a_feedback_packet_shorter_than_its_header_is_an_error_not_a_panic() {
        // A PLI that stops after the sender SSRC, a FIR and a NACK likewise.
        for (type_byte, format) in [(0xCE, 1u8), (0xCE, 4), (0xCD, 1)] {
            let datagram = [0x80 | format, type_byte, 0x00, 0x01, 0, 0, 0, 1];
            let results: Vec<_> = feedback_packets(&datagram).collect();
            assert_eq!(
                results,
                [Err(RtcpError::TooShort)],
                "{type_byte:#x} {format}"
            );
        }
    }

    #[test]
    fn a_length_that_overruns_the_datagram_ends_the_walk_with_one_error() {
        let datagram = [0x81, 0xCE, 0x00, 0x09, 0, 0, 0, 1, 0, 0, 0, 2];
        let results: Vec<_> = feedback_packets(&datagram).collect();
        assert_eq!(results, [Err(RtcpError::BadLength)]);
        let mut with_good_first = PLI.to_vec();
        with_good_first.extend_from_slice(&datagram);
        let results: Vec<_> = feedback_packets(&with_good_first).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_eq!(results[1], Err(RtcpError::BadLength));
    }

    #[test]
    fn a_wrong_version_is_an_error() {
        let mut datagram = PLI;
        datagram[0] = 0x41;
        let results: Vec<_> = feedback_packets(&datagram).collect();
        assert_eq!(results, [Err(RtcpError::BadVersion(1))]);
    }

    #[test]
    fn padding_is_not_read_as_a_fir_entry() {
        // P=1: the last octet counts the padding (RFC 3550 §6.4.1).
        let datagram = [
            0xA4, 0xCE, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 10, 3, 0, 0, 0, 0, 0, 0, 4,
        ];
        let feedback = feedback_of(&datagram);
        let [Feedback::Fir { entries, .. }] = feedback.as_slice() else {
            panic!("one fir");
        };
        assert_eq!(entries.count(), 1);
    }

    #[test]
    fn walking_feedback_allocates_nothing() {
        // The iterator borrows the datagram and yields by value: it holds no Vec (a compile-time
        // property, pinned here by walking a stack array and a borrowed FIR entry list).
        let datagram = NACK;
        let mut seen = 0;
        for item in feedback_packets(&datagram) {
            let Ok(Feedback::GenericNack { pid, .. }) = item else {
                panic!("nack");
            };
            seen += u32::from(pid);
        }
        assert_eq!(seen, 0x1234);
    }

    use proptest::prelude::*;

    proptest! {
        /// Arbitrary bytes decode-or-error, never panic, never spin.
        #[test]
        fn feedback_packets_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            for item in feedback_packets(&bytes) {
                if let Ok(Feedback::Fir { entries, .. }) = item {
                    for entry in entries {
                        let _ = entry;
                    }
                }
            }
        }

        #[test]
        fn a_written_pli_reads_back(sender in any::<u32>(), media in any::<u32>()) {
            let mut out = [0u8; 12];
            let length = write_pli(sender, media, &mut out).unwrap();
            let items = feedback_of(&out[..length]);
            prop_assert_eq!(items, vec![Feedback::Pli { sender_ssrc: sender, media_ssrc: media }]);
        }

        #[test]
        fn a_written_fir_reads_back(sender in any::<u32>(), target in any::<u32>(), sequence in any::<u8>()) {
            let mut out = [0u8; 20];
            let length = write_fir(sender, target, sequence, &mut out).unwrap();
            let items = feedback_of(&out[..length]);
            prop_assert_eq!(items.len(), 1);
            let Feedback::Fir { sender_ssrc, entries } = items[0] else { panic!("fir") };
            prop_assert_eq!(sender_ssrc, sender);
            prop_assert_eq!(entries.collect::<Vec<_>>(), vec![FirEntry { ssrc: target, sequence }]);
        }

        #[test]
        fn a_written_nack_reads_back(
            sender in any::<u32>(), media in any::<u32>(), pid in any::<u16>(), blp in any::<u16>()
        ) {
            let mut out = [0u8; 16];
            let length = write_nack(sender, media, pid, blp, &mut out).unwrap();
            prop_assert_eq!(
                feedback_of(&out[..length]),
                vec![Feedback::GenericNack { sender_ssrc: sender, media_ssrc: media, pid, blp }]
            );
        }

        #[test]
        fn a_written_sdes_cname_parses_as_a_compound(ssrc in any::<u32>(), name in "[a-z0-9]{0,64}") {
            let mut out = [0u8; 96];
            let length = write_sdes_cname(ssrc, &name, &mut out).unwrap();
            prop_assert_eq!(length % 4, 0);
            let packets = parse_compound(&out[..length]).unwrap();
            prop_assert_eq!(packets, vec![RtcpPacket::Other { packet_type: 202 }]);
        }
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

    fn blocks_by_parse_compound(buffer: &[u8]) -> Option<Vec<ReportBlock>> {
        let packets = parse_compound(buffer).ok()?;
        Some(
            packets
                .into_iter()
                .flat_map(|packet| match packet {
                    RtcpPacket::SenderReport(report) => report.reports,
                    RtcpPacket::ReceiverReport(report) => report.reports,
                    RtcpPacket::Other { .. } => Vec::new(),
                })
                .collect(),
        )
    }

    fn blocks_by_walk(buffer: &[u8]) -> Option<Vec<ReportBlock>> {
        let mut blocks = Vec::new();
        for_each_report_block(buffer, |block| blocks.push(*block)).ok()?;
        Some(blocks)
    }

    #[test]
    fn for_each_report_block_visits_what_parse_compound_returns() {
        let report = ReceptionReport {
            ssrc: 0xAABB_CCDD,
            cumulative_lost: 5,
            extended_highest_seq: 0x0001_2345,
            ..ReceptionReport::default()
        };
        let mut buffer = [0u8; 128];
        let mut len = write_sender_report(
            0x1111_2222,
            0,
            0x0000_1000,
            100,
            16_000,
            &[report, report],
            &mut buffer,
        )
        .expect("write");
        len += write_app(3, 0x1111_2222, *b"TEST", &[0; 4], &mut buffer[len..]).expect("app");
        let walked = blocks_by_walk(&buffer[..len]).expect("well formed");
        assert_eq!(walked.len(), 2);
        assert_eq!(walked, blocks_by_parse_compound(&buffer[..len]).unwrap());
        // A receiver report carries its blocks too, and a datagram with none yields none.
        let mut rr = [0x81, 201, 0, 7, 0, 0, 0, 1].to_vec();
        rr.extend_from_slice(&[0u8; 24]);
        assert_eq!(blocks_by_walk(&rr).unwrap().len(), 1);
        assert_eq!(blocks_by_walk(&FLOOR_REQUEST), Some(Vec::new()));
    }

    #[test]
    fn for_each_report_block_visits_nothing_of_a_malformed_datagram() {
        let mut buffer = [0u8; 128];
        let len = write_sender_report(1, 0, 0, 0, 0, &[ReceptionReport::default()], &mut buffer)
            .expect("write");
        // A good SR followed by a packet whose length runs past the datagram.
        let mut bad = buffer[..len].to_vec();
        bad.extend_from_slice(&[0x80, 204, 0x00, 0x09, 1, 2, 3, 4]);
        assert_eq!(
            for_each_report_block(&bad, |_| panic!("visited")),
            Err(RtcpError::BadLength)
        );
        assert_eq!(
            for_each_report_block(&[0x80, 200], |_| ()),
            Err(RtcpError::TooShort)
        );
        let mut version = buffer[..len].to_vec();
        version[0] = 0x40;
        assert_eq!(
            for_each_report_block(&version, |_| ()),
            Err(RtcpError::BadVersion(1))
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
            prop_assert_eq!(blocks_by_walk(&bytes), blocks_by_parse_compound(&bytes));
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
