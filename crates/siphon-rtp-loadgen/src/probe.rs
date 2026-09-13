//! The instrumented RTP packet the harness sends through the relay.
//!
//! It has to be a real RTP packet: the relay's layer-1 demux only forwards RTP/RTCP (RFC 7983 §7),
//! so a fixture of arbitrary bytes is dropped at the gate and the run measures nothing. It also has
//! to carry its own identity, because the relay forwards the payload **verbatim** — which is what
//! lets the receiving side recover the send time and the stream's own sequence without keeping any
//! per-packet state on the sending side.
//!
//! Layout — a 12-byte fixed RTP header (RFC 3550 §5.1) followed by a 160-byte G.711 payload, the
//! 20 ms frame at 8 kHz that sets the 50 pps working assumption used throughout the docs:
//!
//! ```text
//! 0            12            20        24        28                     172
//! +------------+-------------+---------+---------+----------------------+
//! | RTP header | send nanos  | stream  | ordinal | 0xFF filler          |
//! |  (12 B)    |  u64 BE     | u32 BE  | u32 BE  |  (148 B)             |
//! +------------+-------------+---------+---------+----------------------+
//! ```
//!
//! The ordinal is a **u32 in the payload**, not the u16 RTP sequence number, deliberately: at 50 pps
//! a u16 wraps every ~22 minutes, and loss accounting that has to reason about wrap is loss
//! accounting that gets it wrong under exactly the packet loss it exists to measure.

/// Fixed RTP header length, no CSRCs, no extension (RFC 3550 §5.1).
pub const RTP_HEADER_LEN: usize = 12;
/// G.711 samples in one 20 ms frame at 8 kHz — the payload size the whole capacity model assumes.
pub const PAYLOAD_LEN: usize = 160;
/// Total probe packet size.
pub const PACKET_LEN: usize = RTP_HEADER_LEN + PAYLOAD_LEN;

/// RTP payload type 0: PCMU (G.711 µ-law), RFC 3551 §6.
const PAYLOAD_TYPE_PCMU: u8 = 0;
/// Version 2, no padding, no extension, no CSRCs — the first header byte (RFC 3550 §5.1).
const VERSION_FLAGS: u8 = 0x80;
/// RTP timestamp increment per 20 ms frame at 8 kHz.
const TIMESTAMP_PER_FRAME: u32 = 160;

/// Byte offsets of the instrumentation fields within the payload.
const OFFSET_SEND_NANOS: usize = RTP_HEADER_LEN;
const OFFSET_STREAM: usize = OFFSET_SEND_NANOS + 8;
const OFFSET_ORDINAL: usize = OFFSET_STREAM + 4;
const OFFSET_FILLER: usize = OFFSET_ORDINAL + 4;

/// What the harness recovers from a probe packet on the receiving side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// Nanoseconds since the run's shared monotonic epoch, as stamped by the sender.
    pub send_nanos: u64,
    /// Which synthetic stream sent it.
    pub stream: u32,
    /// Monotonic per-stream counter, used for loss and reordering accounting.
    pub ordinal: u32,
    /// The SSRC from the RTP header, so a test can prove the relay did not rewrite it.
    pub ssrc: u32,
}

/// Write one probe packet into `buffer`, which must be at least [`PACKET_LEN`] bytes.
///
/// Returns the number of bytes written, or `None` if the buffer is too small — the hot path is a
/// caller-owned buffer reused across sends, so this never allocates.
pub fn write_packet(
    buffer: &mut [u8],
    ssrc: u32,
    stream: u32,
    ordinal: u32,
    send_nanos: u64,
) -> Option<usize> {
    let packet = buffer.get_mut(..PACKET_LEN)?;

    packet[0] = VERSION_FLAGS;
    packet[1] = PAYLOAD_TYPE_PCMU;
    // The wire sequence number still advances so the packet is well-formed to any dissector and to
    // the relay's own RFC 3550 §A.1 loss counter; the payload ordinal is what we account on.
    packet[2..4].copy_from_slice(&(ordinal as u16).to_be_bytes());
    packet[4..8].copy_from_slice(&ordinal.wrapping_mul(TIMESTAMP_PER_FRAME).to_be_bytes());
    packet[8..12].copy_from_slice(&ssrc.to_be_bytes());

    packet[OFFSET_SEND_NANOS..OFFSET_STREAM].copy_from_slice(&send_nanos.to_be_bytes());
    packet[OFFSET_STREAM..OFFSET_ORDINAL].copy_from_slice(&stream.to_be_bytes());
    packet[OFFSET_ORDINAL..OFFSET_FILLER].copy_from_slice(&ordinal.to_be_bytes());
    packet[OFFSET_FILLER..PACKET_LEN].fill(0xFF);

    Some(PACKET_LEN)
}

/// Recover the instrumentation from a received packet, or `None` if it is not one of ours.
#[must_use]
pub fn parse_packet(packet: &[u8]) -> Option<Probe> {
    if packet.len() < PACKET_LEN {
        return None;
    }
    // Reject anything that is not the RTP shape we emitted, so a stray RTCP or STUN packet on the
    // same port is counted as neither delivered nor lost.
    if packet[0] != VERSION_FLAGS || packet[1] != PAYLOAD_TYPE_PCMU {
        return None;
    }

    let ssrc = u32::from_be_bytes(packet[8..12].try_into().ok()?);
    let send_nanos = u64::from_be_bytes(packet[OFFSET_SEND_NANOS..OFFSET_STREAM].try_into().ok()?);
    let stream = u32::from_be_bytes(packet[OFFSET_STREAM..OFFSET_ORDINAL].try_into().ok()?);
    let ordinal = u32::from_be_bytes(packet[OFFSET_ORDINAL..OFFSET_FILLER].try_into().ok()?);

    Some(Probe {
        send_nanos,
        stream,
        ordinal,
        ssrc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_wellformed_rfc3550_header() {
        let mut buffer = [0u8; PACKET_LEN];
        let written = write_packet(&mut buffer, 0xDEAD_BEEF, 7, 1, 0).expect("write");
        assert_eq!(written, PACKET_LEN);
        assert_eq!(written, 172);

        // Asserted as explicit bytes, not by re-parsing: a shared encode/decode bug passes a round
        // trip, so the wire shape is pinned independently of our own parser.
        assert_eq!(buffer[0], 0x80, "version 2, no padding/extension/CSRC");
        assert_eq!(buffer[1], 0x00, "PCMU, marker clear");
        assert_eq!(&buffer[2..4], &[0x00, 0x01], "sequence 1, big-endian");
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0xA0], "timestamp 160");
        assert_eq!(&buffer[8..12], &[0xDE, 0xAD, 0xBE, 0xEF], "ssrc");
    }

    #[test]
    fn round_trips_the_instrumentation_fields() {
        let mut buffer = [0u8; PACKET_LEN];
        write_packet(
            &mut buffer,
            0x0A0A_0A0A,
            4_000_000_000,
            3_000_000_000,
            u64::MAX,
        )
        .expect("write");
        let probe = parse_packet(&buffer).expect("parse");
        assert_eq!(probe.ssrc, 0x0A0A_0A0A);
        assert_eq!(probe.stream, 4_000_000_000);
        assert_eq!(probe.ordinal, 3_000_000_000);
        assert_eq!(probe.send_nanos, u64::MAX);
    }

    #[test]
    fn the_wire_sequence_wraps_while_the_payload_ordinal_does_not() {
        let mut buffer = [0u8; PACKET_LEN];
        // Ordinal past the u16 ceiling: the header sequence wraps, the payload ordinal is intact.
        write_packet(&mut buffer, 1, 0, 65_538, 0).expect("write");
        assert_eq!(&buffer[2..4], &[0x00, 0x02], "wire sequence wrapped to 2");
        let probe = parse_packet(&buffer).expect("parse");
        assert_eq!(probe.ordinal, 65_538, "payload ordinal did not wrap");
    }

    #[test]
    fn fills_the_remaining_payload_so_the_packet_is_a_full_g711_frame() {
        let mut buffer = [0u8; PACKET_LEN];
        write_packet(&mut buffer, 1, 1, 1, 1).expect("write");
        assert!(
            buffer[OFFSET_FILLER..PACKET_LEN]
                .iter()
                .all(|byte| *byte == 0xFF),
            "filler must cover the rest of the 160-byte frame"
        );
        assert_eq!(PACKET_LEN - RTP_HEADER_LEN, PAYLOAD_LEN);
    }

    #[test]
    fn refuses_a_buffer_too_small_to_hold_a_packet() {
        let mut buffer = [0u8; PACKET_LEN - 1];
        assert!(write_packet(&mut buffer, 1, 1, 1, 1).is_none());
    }

    #[test]
    fn rejects_packets_that_are_not_ours() {
        // Truncated.
        assert!(parse_packet(&[0x80, 0x00]).is_none());
        assert!(parse_packet(&[0u8; PACKET_LEN - 1]).is_none());

        // Right length, wrong version — e.g. a STUN binding request landing on the media port.
        let mut wrong_version = [0u8; PACKET_LEN];
        wrong_version[0] = 0x00;
        assert!(parse_packet(&wrong_version).is_none());

        // Right length and version, wrong payload type — an RTCP sender report is PT 200.
        let mut wrong_payload_type = [0u8; PACKET_LEN];
        wrong_payload_type[0] = VERSION_FLAGS;
        wrong_payload_type[1] = 200;
        assert!(parse_packet(&wrong_payload_type).is_none());
    }

    #[test]
    fn accepts_a_packet_longer_than_ours_by_reading_only_the_prefix() {
        // Defensive: a peer or a future relay could pad. We must not reject on length alone.
        let mut buffer = vec![0u8; PACKET_LEN + 32];
        write_packet(&mut buffer, 9, 9, 9, 9).expect("write");
        let probe = parse_packet(&buffer).expect("parse");
        assert_eq!(probe.stream, 9);
        assert_eq!(probe.ordinal, 9);
    }
}
