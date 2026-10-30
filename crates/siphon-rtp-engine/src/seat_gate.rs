//! The per-seat ingress chain every room that terminates its participants' media runs, factored out
//! so the mixing conference and the forwarding room cannot drift on what they admit.
//!
//! A datagram reaching a seat's endpoint passes, in this order (docs/security-and-nat.md §4):
//!
//! 1. layer 2, the signalled-source gate: a source the SDP did not signal is refused;
//! 2. a DTLS-SRTP seat whose handshake has not keyed it, and a full-ICE seat whose agent has not
//!    selected a pair, are refused (media must follow the key and ICE's decision, not race them);
//! 3. SRTP `unprotect` on a secure seat (RFC 3711 §3.3): the auth tag also proves authenticity, so a
//!    forged or replayed packet dies here;
//! 4. layer 3, the constrained SSRC-consistent reply latch (RFC 3550 §8): a new source that cannot
//!    prove it is the seat's stream is refused, an accepted one aims the seat's reply address.
//!
//! [`admit`] returns the cleartext datagram on success, so the caller does its room-specific work
//! (mix, forward) on plaintext only. [`consume_rtcp`] is the other shared piece: what a room reads
//! out of a seat's RTCP before dropping it.

use std::net::SocketAddr;

use siphon_rtp_datapath::{rtp_media_ssrc, RxPacket, SourceFilter};
use siphon_rtp_media::rtcp;
use siphon_rtp_srtp::leg::SecureLeg;

use crate::ingress::{Ingress, Refusal, RefusalContext, RefusalLog};
use crate::reply_latch::{ReplyLatch, SymmetricLatch};

/// The parts of one seat the ingress chain reads or updates.
pub(crate) struct SeatGate<'a> {
    /// The consumer, for the refusal log (`"conference"`, `"forward-room"`).
    pub(crate) component: &'static str,
    /// The room the seat belongs to, for the refusal log.
    pub(crate) room_id: &'a str,
    /// Layer 2: the sources the seat may send from.
    pub(crate) accepted_source: SourceFilter,
    /// A DTLS seat not yet keyed.
    pub(crate) secure_pending: bool,
    /// A full-ICE seat whose agent has not selected a pair.
    pub(crate) ice_pending: bool,
    /// The seat's SRTP state, when it is a secure seat.
    pub(crate) secure: &'a mut Option<SecureLeg>,
    /// Whether to latch the seat's reply address to its observed source (symmetric RTP).
    pub(crate) latch: bool,
    pub(crate) reverse_latch: &'a mut SymmetricLatch,
    pub(crate) refusals: &'a RefusalLog,
    /// Where the room sends to the seat; moved by the latch.
    pub(crate) egress_destination: &'a mut SocketAddr,
}

/// Run the ingress chain on `packet`. `Ok` is the cleartext datagram (borrowed from the packet, or
/// from `clear` for a secure seat); `Err` is the [`Ingress`] to report, which is always a refusal:
/// none of these drops is evidence the path is alive.
pub(crate) fn admit<'p>(
    gate: SeatGate<'_>,
    packet: &'p RxPacket,
    clear: &'p mut Vec<u8>,
) -> Result<&'p [u8], Ingress> {
    let context = RefusalContext {
        component: gate.component,
        call_id: gate.room_id,
        endpoint: packet.endpoint,
        source: packet.source,
        expected: gate.accepted_source,
    };
    // Layer 2 — signalled-source gate (docs/security-and-nat.md §4): an unsignalled source never
    // enters the room.
    if !gate.accepted_source.accepts(packet.source.ip()) {
        gate.refusals.log(Refusal::UnsignalledSource, context);
        return Err(Ingress::Refused);
    }
    // A DTLS seat whose handshake has not keyed it yet: drop. Decoding SRTP as if it were plaintext
    // would put noise into the room. Not activity: the room has never had usable media from it.
    if gate.secure_pending {
        return Err(Ingress::Refused);
    }
    // A full-ICE seat before its agent has selected a pair: drop. Media must follow ICE's decision,
    // not race it (RFC 8445 §7; docs/security-and-nat.md §4 layer 4).
    if gate.ice_pending {
        return Err(Ingress::Refused);
    }
    // SRTP: decrypt a secure seat's packet first (RFC 3711 §3.3). Plain seats pass untouched.
    let data: &[u8] = if let Some(secure) = gate.secure.as_mut() {
        clear.clear();
        if secure.unprotect(&packet.data, clear).is_err() {
            gate.refusals.log(Refusal::NotAuthenticated, context);
            return Err(Ingress::Refused);
        }
        clear
    } else {
        &packet.data
    };
    // Layer 3 — constrained, SSRC-consistent latch (docs/security-and-nat.md §4 layer 3; RFC 3550
    // §8), decided after SRTP unprotect (a forged packet was already dropped) and before the packet
    // is consumed.
    if gate.latch {
        match gate
            .reverse_latch
            .admit(packet.source, rtp_media_ssrc(data))
        {
            ReplyLatch::Reject => {
                gate.refusals.log(Refusal::NewSource, context);
                return Err(Ingress::Refused);
            }
            ReplyLatch::Accept(Some(destination)) => *gate.egress_destination = destination,
            ReplyLatch::Accept(None) => {}
        }
    }
    Ok(data)
}

/// Whether a cleartext datagram is RTCP on an rtcp-mux socket (RFC 5761 §4: payload-type byte
/// 64..=95).
pub(crate) fn is_rtcp(data: &[u8]) -> bool {
    data.len() >= 2 && (64..=95).contains(&(data[1] & 0x7f))
}

/// One thing [`consume_rtcp`] read out of a datagram.
pub(crate) enum RtcpItem<'a> {
    /// The NTP timestamp of a Sender Report.
    SenderReportNtp(u64),
    /// A reception report block, from an SR or an RR.
    Block(&'a rtcp::ReportBlock),
}

/// Read what a room needs out of one seat's RTCP datagram: the NTP timestamp of a leading Sender
/// Report (its middle 32 bits become the LSR of our reception report, RFC 3550 §6.4.1) and every
/// reception report block (in an SR or an RR), which feeds the round-trip estimate when it reports
/// our egress stream. The datagram is consumed by the caller, never relayed.
pub(crate) fn consume_rtcp(data: &[u8], mut consume: impl FnMut(RtcpItem<'_>)) {
    // Sender Report (V=2, PT=200): the 64-bit NTP timestamp sits at offset 8, after the 8-byte
    // header, so the packet must hold at least 16 bytes.
    if data.len() >= 16 && data[0] >> 6 == 2 && data[1] == rtcp::packet_type::SENDER_REPORT {
        if let Ok(ntp_bytes) = <[u8; 8]>::try_from(&data[8..16]) {
            consume(RtcpItem::SenderReportNtp(u64::from_be_bytes(ntp_bytes)));
        }
    }
    if let Ok(packets) = rtcp::parse_compound(data) {
        for packet in &packets {
            let blocks = match packet {
                rtcp::RtcpPacket::SenderReport(report) => report.reports.as_slice(),
                rtcp::RtcpPacket::ReceiverReport(report) => report.reports.as_slice(),
                rtcp::RtcpPacket::Other { .. } => &[],
            };
            for block in blocks {
                consume(RtcpItem::Block(block));
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use bytes::Bytes;
    use siphon_rtp_datapath::EndpointId;
    use siphon_rtp_media::rtp::{write_packet, RtpHeader};

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn rtp(ssrc: u32, sequence: u16) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 96,
            sequence,
            timestamp: 0,
            ssrc,
        };
        let mut buffer = vec![0u8; 16];
        write_packet(&header, &[1, 2, 3, 4], &mut buffer).unwrap();
        buffer
    }

    fn rx(source: &str, data: Vec<u8>) -> RxPacket {
        RxPacket {
            endpoint: EndpointId(1),
            source: address(source),
            arrival: 0,
            data: Bytes::from(data),
        }
    }

    struct Seat {
        secure: Option<SecureLeg>,
        latch: SymmetricLatch,
        refusals: RefusalLog,
        destination: SocketAddr,
    }

    impl Seat {
        fn new() -> Self {
            Self {
                secure: None,
                latch: SymmetricLatch::default(),
                refusals: RefusalLog::default(),
                destination: address("192.0.2.1:4000"),
            }
        }

        fn admit<'p>(
            &mut self,
            accepted: SourceFilter,
            secure_pending: bool,
            ice_pending: bool,
            packet: &'p RxPacket,
            clear: &'p mut Vec<u8>,
        ) -> Result<&'p [u8], Ingress> {
            admit(
                SeatGate {
                    component: "test",
                    room_id: "room",
                    accepted_source: accepted,
                    secure_pending,
                    ice_pending,
                    secure: &mut self.secure,
                    latch: true,
                    reverse_latch: &mut self.latch,
                    refusals: &self.refusals,
                    egress_destination: &mut self.destination,
                },
                packet,
                clear,
            )
        }
    }

    #[test]
    fn admits_the_signalled_source_and_aims_the_reply_at_it() {
        let mut seat = Seat::new();
        let packet = rx("192.0.2.1:4000", rtp(7, 1));
        let mut clear = Vec::new();
        let accepted = SourceFilter::Exact(address("192.0.2.1:4000").ip());
        let data = seat
            .admit(accepted, false, false, &packet, &mut clear)
            .unwrap();
        assert_eq!(data, &packet.data[..]);
        assert_eq!(seat.destination, address("192.0.2.1:4000"));
    }

    #[test]
    fn refuses_an_unsignalled_source() {
        let mut seat = Seat::new();
        let packet = rx("198.51.100.9:4000", rtp(7, 1));
        let mut clear = Vec::new();
        let accepted = SourceFilter::Exact(address("192.0.2.1:4000").ip());
        assert_eq!(
            seat.admit(accepted, false, false, &packet, &mut clear),
            Err(Ingress::Refused)
        );
    }

    #[test]
    fn refuses_a_seat_whose_dtls_key_or_ice_pair_is_still_pending() {
        let mut seat = Seat::new();
        let packet = rx("192.0.2.1:4000", rtp(7, 1));
        let mut clear = Vec::new();
        assert_eq!(
            seat.admit(SourceFilter::Any, true, false, &packet, &mut clear),
            Err(Ingress::Refused)
        );
        assert_eq!(
            seat.admit(SourceFilter::Any, false, true, &packet, &mut clear),
            Err(Ingress::Refused)
        );
    }

    #[test]
    fn refuses_a_new_source_with_another_ssrc_and_keeps_the_reply_address() {
        let mut seat = Seat::new();
        let mut clear = Vec::new();
        let first = rx("192.0.2.1:4000", rtp(7, 1));
        seat.admit(SourceFilter::Any, false, false, &first, &mut clear)
            .unwrap();
        let spray = rx("198.51.100.9:5000", rtp(99, 2));
        assert_eq!(
            seat.admit(SourceFilter::Any, false, false, &spray, &mut clear),
            Err(Ingress::Refused)
        );
        assert_eq!(seat.destination, address("192.0.2.1:4000"));
    }

    #[test]
    fn consume_rtcp_reads_the_sender_report_ntp_and_every_block() {
        let reports = [rtcp::ReceptionReport {
            ssrc: 5,
            fraction_lost: 0,
            cumulative_lost: 0,
            extended_highest_seq: 9,
            jitter: 0,
            last_sr: 0,
            delay_last_sr: 0,
        }];
        let mut buffer = [0u8; 64];
        let length =
            rtcp::write_sender_report(1, 0x0102_0304_0506_0708, 0, 0, 0, &reports, &mut buffer)
                .unwrap();
        let mut ntp = None;
        let mut blocks = 0;
        consume_rtcp(&buffer[..length], |item| match item {
            RtcpItem::SenderReportNtp(value) => ntp = Some(value),
            RtcpItem::Block(_) => blocks += 1,
        });
        assert_eq!(ntp, Some(0x0102_0304_0506_0708));
        assert_eq!(blocks, 1);
        assert!(is_rtcp(&buffer[..length]));
        assert!(!is_rtcp(&rtp(1, 1)));
    }

    #[test]
    fn consume_rtcp_ignores_garbage() {
        consume_rtcp(&[0x80, 200], |_| panic!("nothing to read"));
        consume_rtcp(&[], |_| panic!("nothing to read"));
    }
}
