//! Unlinking two bridged rooms, and keeping the record of which rooms are linked.
//!
//! [`ConferenceRegistry::bridge`] wires one channel per enabled direction and tells each room's actor
//! which room is on the other end. That name is what this module removes a link by: `unbridge`
//! drops every channel between the two rooms whichever direction it was created in, and a room that
//! is torn down is dropped from its peers the same way, so a surviving room stops paying the bridge's
//! pinned wideband rate and a later room reusing the id is not mistaken for a linked one.

use std::fmt;

use super::{Conference, ConferenceControl, ConferenceInput, ConferenceRegistry};

/// Why two rooms were not unbridged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnbridgeRefusal {
    /// There is no room with this id.
    NoSuchRoom(String),
    /// Both rooms exist and are not bridged with each other.
    NotBridged,
}

impl fmt::Display for UnbridgeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchRoom(conference_id) => {
                write!(formatter, "unknown conference: {conference_id}")
            }
            Self::NotBridged => write!(formatter, "the two conferences are not bridged"),
        }
    }
}

impl Conference {
    /// Drop every bridge channel to or from `peer`, then recompute the room rate: a room left with no
    /// bridge returns to the rate its own membership calls for.
    pub fn remove_bridges_with(&mut self, peer: &str) {
        let before = self.bridge_in.len() + self.bridge_out.len();
        self.bridge_in.retain(|(name, _)| name != peer);
        self.bridge_out.retain(|(name, _)| name != peer);
        if self.bridge_in.len() + self.bridge_out.len() != before {
            self.recompute_room_rate();
        }
    }
}

impl ConferenceRegistry {
    /// Undo [`ConferenceRegistry::bridge`] between two rooms, in both directions.
    pub fn unbridge(&self, room_a: &str, room_b: &str) -> Result<(), UnbridgeRefusal> {
        for room in [room_a, room_b] {
            if !self.rooms.contains_key(room) {
                return Err(UnbridgeRefusal::NoSuchRoom(room.to_string()));
            }
        }
        let linked = self
            .rooms
            .get(room_a)
            .is_some_and(|handle| handle.bridged_with.iter().any(|peer| peer == room_b));
        if !linked {
            return Err(UnbridgeRefusal::NotBridged);
        }
        self.unlink(room_a, room_b);
        self.unlink(room_b, room_a);
        Ok(())
    }

    /// Record that two rooms are bridged, once per pair however many times it is bridged.
    pub(super) fn record_bridge(&self, room_a: &str, room_b: &str) {
        for (room, peer) in [(room_a, room_b), (room_b, room_a)] {
            // One guard at a time: `room_a == room_b` must not take the same shard twice.
            if let Some(mut handle) = self.rooms.get_mut(room) {
                if !handle.bridged_with.iter().any(|linked| linked == peer) {
                    handle.bridged_with.push(peer.to_string());
                }
            }
        }
    }

    /// Drop a torn-down room from every room it was bridged with. Called with the room's own guard
    /// already released.
    pub(super) fn forget_bridges(&self, gone: &str, peers: &[String]) {
        for peer in peers.iter().filter(|peer| peer.as_str() != gone) {
            self.unlink(peer, gone);
        }
    }

    /// Forget `peer` in `room`'s record and have its actor drop the channels to and from it.
    fn unlink(&self, room: &str, peer: &str) {
        if let Some(mut handle) = self.rooms.get_mut(room) {
            handle.bridged_with.retain(|linked| linked != peer);
            let _ =
                handle
                    .mailbox
                    .try_send(ConferenceInput::Control(ConferenceControl::RemoveBridge(
                        peer.to_string(),
                    )));
        }
    }

    /// The rooms `conference_id` is bridged with, for tests and introspection.
    #[must_use]
    pub fn bridged_with(&self, conference_id: &str) -> Vec<String> {
        self.rooms
            .get(conference_id)
            .map(|handle| handle.bridged_with.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ParticipantConfig, Routing, SeatTelemetry, NARROWBAND_RATE_HZ};
    use super::*;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use siphon_rtp_datapath::{EndpointId, SourceFilter};

    /// A G.711 µ-law seat on endpoint `index + 1`.
    fn seat(index: u64) -> ParticipantConfig {
        ParticipantConfig {
            tag: format!("party-{index}"),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            ingress_endpoint: EndpointId(index + 1),
            egress_endpoint: EndpointId(index + 1),
            egress_dst: "192.0.2.10:4000".parse().expect("address"),
            accepted_source: SourceFilter::Exact("192.0.2.10".parse().expect("ip")),
            latch: false,
            egress_ssrc: 0xC000_0000,
            egress_payload_type: 0,
            mos_codec: siphon_rtp_hep::mos::Codec::G711,
            telephone_event_in: None,
            secure: None,
            secure_pending: false,
            text: None,
            ice_pending: false,
            routing: Routing::default(),
            telemetry: SeatTelemetry::default(),
        }
    }

    #[test]
    fn removing_a_peers_bridges_drops_both_directions_and_restores_the_room_rate() {
        let mut room = Conference::new("a".into(), 0);
        room.add_participant(seat(0)).expect("seated");
        assert_eq!(room.room_rate(), NARROWBAND_RATE_HZ);
        let (to_b, _from_a) = flume::bounded(2);
        let (_to_a, from_b) = flume::bounded(2);
        let (to_c, _from_a_at_c) = flume::bounded(2);
        room.add_bridge_out("b".into(), to_b);
        room.add_bridge_in("b".into(), from_b);
        room.add_bridge_out("c".into(), to_c);

        room.remove_bridges_with("b");
        assert!(
            room.bridge_in.is_empty(),
            "the inbound channel from b is gone"
        );
        assert_eq!(room.bridge_out.len(), 1, "the link to c is untouched");
        assert_ne!(room.room_rate(), NARROWBAND_RATE_HZ, "still bridged to c");

        room.remove_bridges_with("c");
        assert!(room.bridge_out.is_empty());
        assert_eq!(
            room.room_rate(),
            NARROWBAND_RATE_HZ,
            "an unbridged all-G.711 room returns to 8 kHz"
        );
    }

    #[test]
    fn removing_a_room_that_was_never_bridged_changes_nothing() {
        let mut room = Conference::new("a".into(), 0);
        room.add_participant(seat(0)).expect("seated");
        room.remove_bridges_with("b");
        assert_eq!(room.room_rate(), NARROWBAND_RATE_HZ);
    }

    async fn registry_with_rooms(rooms: &[&str]) -> ConferenceRegistry {
        let registry = ConferenceRegistry::default();
        let datapath = UdpLoopbackDatapath::new();
        for (index, room) in rooms.iter().enumerate() {
            registry
                .join(room, seat(index as u64), 0, false, datapath.clone(), None)
                .await
                .expect("seated");
        }
        registry
    }

    #[tokio::test]
    async fn unbridge_removes_the_link_whichever_direction_it_was_made() {
        for (a_to_b, b_to_a) in [(true, true), (true, false), (false, true)] {
            let registry = registry_with_rooms(&["a", "b"]).await;
            assert!(registry.bridge("a", "b", a_to_b, b_to_a));
            assert_eq!(registry.bridged_with("a"), ["b"]);
            assert_eq!(registry.bridged_with("b"), ["a"]);
            // Named the other way round from the bridge: still the same link.
            assert_eq!(registry.unbridge("b", "a"), Ok(()));
            assert!(registry.bridged_with("a").is_empty());
            assert!(registry.bridged_with("b").is_empty());
            assert_eq!(
                registry.unbridge("a", "b"),
                Err(UnbridgeRefusal::NotBridged),
                "a second unbridge has nothing to undo"
            );
        }
    }

    #[tokio::test]
    async fn unbridge_refuses_unknown_and_unlinked_rooms() {
        let registry = registry_with_rooms(&["a", "b"]).await;
        assert_eq!(
            registry.unbridge("a", "ghost"),
            Err(UnbridgeRefusal::NoSuchRoom("ghost".into()))
        );
        assert_eq!(
            registry.unbridge("ghost", "b"),
            Err(UnbridgeRefusal::NoSuchRoom("ghost".into()))
        );
        assert_eq!(
            registry.unbridge("a", "b"),
            Err(UnbridgeRefusal::NotBridged)
        );
        assert_eq!(
            UnbridgeRefusal::NoSuchRoom("ghost".into()).to_string(),
            "unknown conference: ghost"
        );
        assert_eq!(
            UnbridgeRefusal::NotBridged.to_string(),
            "the two conferences are not bridged"
        );
    }

    #[tokio::test]
    async fn bridging_a_pair_twice_records_it_once() {
        let registry = registry_with_rooms(&["a", "b"]).await;
        assert!(registry.bridge("a", "b", true, false));
        assert!(registry.bridge("b", "a", true, true));
        assert_eq!(registry.bridged_with("a"), ["b"]);
        assert_eq!(registry.unbridge("a", "b"), Ok(()));
        assert!(registry.bridged_with("b").is_empty());
    }

    #[tokio::test]
    async fn a_room_torn_down_is_forgotten_by_the_room_it_was_bridged_with() {
        let registry = registry_with_rooms(&["a", "b", "c"]).await;
        assert!(registry.bridge("a", "b", true, true));
        assert!(registry.bridge("a", "c", true, true));
        // `b`'s last participant leaves, so the room goes, and `a` no longer lists it.
        assert!(!registry.leave("b", "party-1").is_empty());
        assert_eq!(registry.bridged_with("a"), ["c"]);
        // `c` is torn down whole.
        assert!(!registry.deregister("c").is_empty());
        assert!(registry.bridged_with("a").is_empty());
        // `a` is reaped idle; nothing is left to forget and nothing panics.
        assert!(!registry.reap_idle(10, 1, 0, |_| None).is_empty());
        assert_eq!(registry.room_count(), 0);
    }
}
