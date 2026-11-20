//! Lawful interception (ETSI TS 103 221-2 X3) of one room seat.
//!
//! A mixing room decodes every seat and sends each its own mixed-minus-self stream, so the seat's
//! accepted media and what it is sent both exist only inside the room actor, which is therefore
//! where the taps sit. The room is the owner of its seats' taps (single owner, no shared state): the
//! engine posts the interception's own tap factory as a [`SeatControl::SetX3`] and the room builds
//! the pair from it, with the engine address of the seat it already knows. So the delivery
//! connection, the Correlation ID and the PDU sequence counter are the interception's and never the
//! room's.
//!
//! In a room the target is always the seated party (TS 103 221-2 §5.2.6 is target-relative):
//!
//! - **`from_target`**: what the seat sent, taken in [`Conference::ingest`] right after the shared
//!   ingress chain accepted it (source gate, SRTP unprotect), so a secure seat yields plaintext and
//!   a forged datagram yields nothing.
//! - **`to_target`**: what the room sent the seat, taken in `Conference::emit` after the packet was
//!   built and protected successfully and before it is queued, so it is exactly what the seat is
//!   sent: nothing for a pending, blocked or discontinuous-transmission frame, and never another
//!   seat's raw stream.

use siphon_rtp_datapath::EndpointId;
use siphon_rtp_proto::Event;

use super::{Conference, ConferenceRegistry};
use crate::x3::{X3Tap, X3TapFactory};
use siphon_rtp_li::PayloadDirection;

/// The two taps of one intercepted seat, built from the interception's own
/// [`crate::x3::X3TapFactory`] with the engine address the seat talks to.
pub(super) struct X3SeatTaps {
    /// On what the seat sent, delivered as `from_target`.
    pub(super) from_target: X3Tap,
    /// On what the room sent the seat, delivered as `to_target`.
    pub(super) to_target: X3Tap,
}

impl Conference {
    /// Put the interception's taps on a seat, replacing any it had. Returns whether the tag is
    /// seated (and knows the engine address its PDUs are attributed to). A seat still pending
    /// (`conference_seat` before activation) takes them too: it ingests and sends nothing until it
    /// opens, so the first packet it handles is the first one delivered.
    pub fn set_seat_x3(&mut self, tag: &str, factory: &X3TapFactory) -> bool {
        let Some(participant) = self.participants.iter_mut().find(|seat| seat.tag == tag) else {
            return false;
        };
        // TS 103 221-2 §5.3 attributes each PDU to the addresses the packet travelled between, so a
        // seat whose engine address is unknown is refused rather than delivered with a guessed one.
        let Some(local) = participant.telemetry.local else {
            return false;
        };
        participant.call_seat.x3 = Some(Box::new(X3SeatTaps {
            from_target: factory.tap(local, PayloadDirection::FromTarget),
            to_target: factory.tap(local, PayloadDirection::ToTarget),
        }));
        true
    }

    /// Take the interception's taps off a seat. Returns whether the tag is seated; a seat that was
    /// not intercepted is not an error.
    pub fn clear_seat_x3(&mut self, tag: &str) -> bool {
        let Some(participant) = self.participants.iter_mut().find(|seat| seat.tag == tag) else {
            return false;
        };
        participant.call_seat.x3 = None;
        true
    }
}

impl ConferenceRegistry {
    /// The engine endpoint of `tag`'s seat in `conference_id` when that seat **joined** the room
    /// (`conference_join` / `conference_answer`) rather than being a live call's leg
    /// (`conference_seat`), whose interception is its call's. `None` for no such seat.
    #[must_use]
    pub fn joined_seat_endpoint(&self, conference_id: &str, tag: &str) -> Option<EndpointId> {
        let room = self.rooms.get(conference_id)?;
        let member = room.members.iter().find(|member| member.tag == tag)?;
        member.call_id.is_none().then_some(member.endpoint)
    }

    /// The event sink of the client whose join seated `tag`, which is the seat's owner: `None` for
    /// no such seat, `Some(None)` for a seat seated by a client with no sink.
    #[must_use]
    pub fn seat_owner_sink(
        &self,
        conference_id: &str,
        tag: &str,
    ) -> Option<Option<flume::Sender<Event>>> {
        let room = self.rooms.get(conference_id)?;
        let member = room.members.iter().find(|member| member.tag == tag)?;
        Some(member.events.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::Bytes;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_datapath::{RxPacket, SourceFilter};
    use siphon_rtp_li::PayloadDirection;
    use siphon_rtp_proto::ConferenceDtmf;

    use super::*;
    use crate::conference::{ParticipantConfig, SeatControl, SeatTelemetry};
    use crate::x3::{x3_channel, X3Delivery, X3Packet};

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    /// The engine address seat `index` talks to.
    fn engine_address(index: usize) -> SocketAddr {
        address(&format!("198.51.100.1:{}", 20_000 + index))
    }

    /// A G.711 µ-law seat gated to `192.0.2.<index + 1>`, replying to its port 4000.
    fn seat(index: usize) -> ParticipantConfig {
        let octet = index + 1;
        ParticipantConfig {
            tag: format!("seat-{index}"),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            ingress_endpoint: EndpointId(index as u64 + 1),
            egress_endpoint: EndpointId(index as u64 + 1),
            egress_dst: address(&format!("192.0.2.{octet}:4000")),
            accepted_source: SourceFilter::Exact(format!("192.0.2.{octet}").parse().expect("ip")),
            latch: false,
            egress_ssrc: 0xC000_0000 + index as u32,
            egress_payload_type: 0,
            mos_codec: siphon_rtp_hep::mos::Codec::G711,
            telephone_event: None,
            dtmf: ConferenceDtmf::Events,
            secure: None,
            secure_pending: false,
            text: None,
            ice_pending: false,
            routing: Default::default(),
            telemetry: SeatTelemetry {
                local: Some(engine_address(index)),
                sip_call_id: None,
            },
            call: None,
        }
    }

    fn voice(index: usize, sequence: u16) -> RxPacket {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&(0x1000_0000 + index as u32).to_be_bytes());
        packet.extend_from_slice(&[0x40; 160]);
        RxPacket {
            endpoint: EndpointId(index as u64 + 1),
            source: address(&format!("192.0.2.{}:5000", index + 1)),
            arrival: 0,
            data: Bytes::from(packet),
        }
    }

    fn delivered(delivery: &X3Delivery) -> Vec<X3Packet> {
        delivery.packets.try_iter().collect()
    }

    /// Three seats, all talking for `frames` frames; every tick's output is returned.
    fn run(room: &mut Conference, frames: u16) -> Vec<crate::media_pipeline::Outbound> {
        let mut sent = Vec::new();
        for sequence in 0..frames {
            for index in 0..3 {
                room.ingest(&voice(index, sequence));
            }
            room.tick(&mut sent);
        }
        sent
    }

    fn room() -> Conference {
        let mut room = Conference::new("x3-room".into(), 0);
        for index in 0..3 {
            room.add_participant(seat(index)).expect("seat");
        }
        room
    }

    #[test]
    fn taps_on_an_unknown_seat_are_refused_and_clearing_one_says_so_too() {
        let mut room = room();
        let (factory, _delivery) = x3_channel(8);
        assert!(!room.set_seat_x3("nobody", &factory));
        assert!(!room.clear_seat_x3("nobody"));
        assert!(room.set_seat_x3("seat-0", &factory));
        assert!(room.clear_seat_x3("seat-0"));
        assert!(
            room.clear_seat_x3("seat-1"),
            "clearing a seat that was not intercepted is not an error"
        );
    }

    #[test]
    fn a_seat_with_no_known_engine_address_is_refused_not_delivered_with_a_guess() {
        let mut room = Conference::new("x3-no-local".into(), 0);
        room.add_participant(ParticipantConfig {
            telemetry: SeatTelemetry::default(),
            ..seat(0)
        })
        .expect("seat");
        let (factory, _delivery) = x3_channel(8);
        assert!(!room.set_seat_x3("seat-0", &factory));
    }

    #[test]
    fn the_seat_controls_reply_whether_the_seat_exists() {
        let mut room = room();
        let (factory, _delivery) = x3_channel(8);
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        let control = SeatControl::SetX3 {
            tag: "nobody".into(),
            factory: factory.clone(),
            reply: sender,
        };
        assert!(!room.apply_seat_control(control));
        assert_eq!(receiver.try_recv(), Ok(false), "no such seat");

        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        room.apply_seat_control(SeatControl::SetX3 {
            tag: "seat-2".into(),
            factory: factory.clone(),
            reply: sender,
        });
        assert_eq!(receiver.try_recv(), Ok(true));
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        room.apply_seat_control(SeatControl::ClearX3 {
            tag: "nobody".into(),
            reply: sender,
        });
        assert_eq!(receiver.try_recv(), Ok(false), "no such seat");
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        room.apply_seat_control(SeatControl::ClearX3 {
            tag: "seat-2".into(),
            reply: sender,
        });
        assert_eq!(receiver.try_recv(), Ok(true));
    }

    #[test]
    fn an_intercepted_seat_is_delivered_as_the_target_in_both_directions() {
        let mut room = room();
        let (factory, delivery) = x3_channel(4096);
        assert!(room.set_seat_x3("seat-1", &factory));

        let sent = run(&mut room, 10);

        let packets = delivered(&delivery);
        let from_target: Vec<_> = packets
            .iter()
            .filter(|packet| packet.direction == PayloadDirection::FromTarget)
            .collect();
        let to_target: Vec<_> = packets
            .iter()
            .filter(|packet| packet.direction == PayloadDirection::ToTarget)
            .collect();
        assert_eq!(from_target.len(), 10, "every packet the seat sent");
        for packet in &from_target {
            assert_eq!(
                packet.source,
                address("192.0.2.2:5000"),
                "the seat's address"
            );
            assert_eq!(packet.destination, engine_address(1));
            assert_eq!(&packet.payload[8..12], &0x1000_0001u32.to_be_bytes());
        }

        // What the room sent the seat, byte for byte, from the engine address to the seat's address.
        let sent_to_seat: Vec<_> = sent
            .iter()
            .filter(|outbound| outbound.endpoint == EndpointId(2))
            .collect();
        assert!(
            !sent_to_seat.is_empty(),
            "the room sends the seat its stream"
        );
        assert_eq!(to_target.len(), sent_to_seat.len(), "exactly what was sent");
        for (packet, outbound) in to_target.iter().zip(&sent_to_seat) {
            assert_eq!(packet.source, engine_address(1));
            assert_eq!(packet.destination, address("192.0.2.2:4000"));
            assert_eq!(packet.payload.as_slice(), &outbound.data[..]);
            assert_eq!(
                &packet.payload[8..12],
                &0xC000_0001u32.to_be_bytes(),
                "the seat's own egress stream, not another seat's"
            );
        }
    }

    #[test]
    fn the_destination_follows_a_reply_address_that_latched_after_the_tap_went_on() {
        let mut room = room();
        let (factory, delivery) = x3_channel(4096);
        assert!(room.set_seat_x3("seat-1", &factory));
        room.participants[1].egress_dst = address("192.0.2.2:4444");

        run(&mut room, 3);

        let to_target: Vec<_> = delivered(&delivery)
            .into_iter()
            .filter(|packet| packet.direction == PayloadDirection::ToTarget)
            .collect();
        assert!(!to_target.is_empty());
        assert!(to_target
            .iter()
            .all(|packet| packet.destination == address("192.0.2.2:4444")));
    }

    #[test]
    fn a_seat_that_is_not_intercepted_delivers_nothing_and_a_cleared_one_stops() {
        let mut room = room();
        let (factory, delivery) = x3_channel(4096);
        assert!(room.set_seat_x3("seat-1", &factory));
        run(&mut room, 3);
        let before = delivered(&delivery).len();
        assert!(before > 0);

        assert!(room.clear_seat_x3("seat-1"));
        for sequence in 3..6 {
            for index in 0..3 {
                room.ingest(&voice(index, sequence));
            }
            room.tick(&mut Vec::new());
        }
        assert!(
            delivered(&delivery).is_empty(),
            "nothing after the taps came off"
        );
    }

    #[test]
    fn a_pending_seat_delivers_nothing_until_it_opens() {
        let mut room = Conference::new("x3-pending".into(), 0);
        room.add_participant(seat(0)).expect("seat");
        room.add_participant(ParticipantConfig {
            secure_pending: true,
            ..seat(1)
        })
        .expect("pending seat");
        let (factory, delivery) = x3_channel(4096);
        assert!(
            room.set_seat_x3("seat-1", &factory),
            "a pending seat takes the taps, so the first packet it handles is delivered"
        );
        for sequence in 0..5 {
            room.ingest(&voice(0, sequence));
            room.ingest(&voice(1, sequence));
            room.tick(&mut Vec::new());
        }
        assert!(
            delivered(&delivery).is_empty(),
            "a pending seat is neither heard nor sent anything, so nothing is intercepted"
        );
    }

    #[test]
    fn a_datagram_from_the_wrong_source_is_not_delivered() {
        let mut room = room();
        let (factory, delivery) = x3_channel(4096);
        assert!(room.set_seat_x3("seat-1", &factory));
        let mut forged = voice(1, 1);
        forged.source = address("203.0.113.66:5000");
        room.ingest(&forged);
        assert!(
            delivered(&delivery).is_empty(),
            "the source gate decides what was accepted"
        );
    }

    #[test]
    fn a_telephone_event_forwarded_to_an_intercepted_seat_is_delivered_as_to_target() {
        let mut room = Conference::new("x3-dtmf".into(), 0);
        room.add_participant(ParticipantConfig {
            telephone_event: Some(crate::sdp::TelephoneEvent {
                payload_type: 101,
                clock_rate_hz: 8000,
            }),
            dtmf: ConferenceDtmf::Forward,
            ..seat(0)
        })
        .expect("owner");
        room.add_participant(ParticipantConfig {
            telephone_event: Some(crate::sdp::TelephoneEvent {
                payload_type: 101,
                clock_rate_hz: 8000,
            }),
            ..seat(1)
        })
        .expect("target");
        let (factory, delivery) = x3_channel(64);
        assert!(room.set_seat_x3("seat-1", &factory));

        let mut packet = vec![0x80, 101, 0, 1];
        packet.extend_from_slice(&8000u32.to_be_bytes());
        packet.extend_from_slice(&0x2000_0000u32.to_be_bytes());
        packet.extend_from_slice(&[5, 0x80 | 10, 0x01, 0x40]);
        room.ingest(&RxPacket {
            endpoint: EndpointId(1),
            source: address("192.0.2.1:5000"),
            arrival: 0,
            data: Bytes::from(packet),
        });
        let mut forwarded = Vec::new();
        room.drain_forwarded(&mut forwarded);

        assert_eq!(forwarded.len(), 1, "the event is forwarded to the target");
        let packets = delivered(&delivery);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].direction, PayloadDirection::ToTarget);
        assert_eq!(packets[0].payload.as_slice(), &forwarded[0].data[..]);
        assert_eq!(packets[0].destination, address("192.0.2.2:4000"));
    }
}
