//! Lawful interception (ETSI TS 103 221-2 X3) of a **split** call: deliver what is on each wire.
//!
//! On a two-party relay what the target hears *is* the other party's ingress, so the ingress taps of
//! the two directions cover both directions of the call and no egress tap is needed
//! ([`crate::x3::ingress_directions`]). A split breaks that identity: the other party's audio is
//! isolated ([`super::split`]) and the target hears what the bot plays it, rendered on the playout
//! tick and sent from the direction that faces the target. X3 carries content as it crossed the
//! network (TS 103 221-2 §5.3), so while a split holds the call:
//!
//! * `from_target` stays the target's own ingress, untouched;
//! * `to_target` is taken from the **egress** of the direction that faces the target
//!   ([`Direction::push_egress`], the choke point every datagram the target is sent passes, on the
//!   plaintext just sealed): the bot's audio, the silence the playout clock sends when the bot is
//!   quiet or gone, and whatever else the engine puts on that wire; and
//! * the other party's own voice, which the target no longer hears, is **not** delivered as audio the
//!   target heard. It stays in the recordings and on the uplink forks, which are the parties' own
//!   voices and nothing the interception speaks for.
//!
//! The choice between the two sources is a single predicate, `Direction::split` being present, read
//! at both tap sites by the one actor that also flips it ([`MediaCall::attach_split`],
//! [`MediaCall::end_split`], [`MediaCall::begin_split`]). A packet is therefore delivered by exactly
//! one source: none is delivered twice and none is skipped at either boundary, with no message
//! between the isolation and the tap that could land in between.

use std::net::SocketAddr;

use super::{Direction, MediaCall};

impl Direction {
    /// Whether this direction's ingress taps that carry what the target hears give way to its egress
    /// (the split isolates it and a delivery is taking that audio from its egress instead).
    fn x3_ingress_yields_to_egress(&self) -> bool {
        self.split.is_some() && !self.x3_toward.is_empty()
    }

    /// Deliver one accepted ingress datagram to the interception, as `Direction::handle` takes it.
    pub(super) fn deliver_x3_ingress(&self, source: SocketAddr, data: &[u8]) {
        if self.x3.is_empty() {
            return;
        }
        if self.x3_ingress_yields_to_egress() {
            self.x3.deliver_from_target(source, data);
        } else {
            self.x3.deliver(source, data);
        }
    }

    /// Deliver one datagram this direction is sending its party, while the call is split: what the
    /// party hears. A no-op otherwise, when the other party's ingress tap carries it.
    pub(super) fn deliver_x3_toward(&self, plaintext: &[u8]) {
        if self.x3_ingress_yields_to_egress() {
            self.x3_toward.deliver_egress(self.egress_dst, plaintext);
        }
    }
}

impl MediaCall {
    /// Work out each direction's split egress taps from the ingress taps now installed: the
    /// `to_target` taps of a direction's ingress, re-stamped with the engine-local address of the
    /// leg that direction's egress sends from, which is where the other direction's ingress tap of
    /// the same delivery sits. Called wherever the ingress sets change.
    pub(super) fn derive_x3_toward(&mut self) {
        self.a_to_b.x3_toward = self.a_to_b.x3.toward_target_egress(&self.b_to_a.x3);
        self.b_to_a.x3_toward = self.b_to_a.x3.toward_target_egress(&self.a_to_b.x3);
    }
}

#[cfg(test)]
mod tests {
    use super::super::split::SplitAttach;
    use super::super::tests::ulaw_alaw_call;
    use super::*;
    use crate::media_pipeline::Outbound;
    use crate::x3::X3Taps;
    use bytes::Bytes;
    use siphon_rtp_datapath::{EndpointId, RxPacket};
    use siphon_rtp_li::PayloadDirection;
    use siphon_rtp_media::bridge::split::playout;
    use std::sync::Arc;

    const A_SOURCE: &str = "127.0.0.2:5000";
    const B_SOURCE: &str = "127.0.0.3:6000";
    const A_ENGINE: &str = "198.51.100.1:20000";
    const B_ENGINE: &str = "198.51.100.1:20002";

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    fn epoch() -> Arc<std::sync::atomic::AtomicU64> {
        Arc::default()
    }

    fn voice(sequence: u16, byte: u8) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
        packet.extend_from_slice(&[byte; 160]);
        packet
    }

    /// Taps for one delivery, the way `tap_pairs` builds them.
    fn intercept(call: &mut MediaCall, target_is_caller: bool) -> crate::x3::X3Delivery {
        let (factory, delivery) = crate::x3::x3_channel(256);
        let (direction_a, direction_b) = crate::x3::ingress_directions(target_is_caller);
        call.start_x3((
            factory.tap(addr(A_ENGINE), direction_a).into(),
            factory.tap(addr(B_ENGINE), direction_b).into(),
        ));
        delivery
    }

    fn split(call: &mut MediaCall) -> siphon_rtp_media::bridge::PlayoutWriter {
        let (writer, [first, second]) = playout(8_000);
        call.attach_split(SplitAttach {
            toward_a: first,
            toward_b: second,
            wire_rate_hz: 8_000,
            noise_suppression: [false, false],
            epoch: epoch(),
        });
        writer
    }

    fn from(call: &mut MediaCall, source: &str, endpoint: u64, packet: Vec<u8>) -> Vec<Outbound> {
        let mut out = Vec::new();
        call.process(
            &RxPacket {
                endpoint: EndpointId(endpoint),
                source: addr(source),
                arrival: 0,
                data: Bytes::from(packet),
            },
            &mut out,
            &mut Vec::new(),
        );
        out
    }

    fn drained(delivery: &crate::x3::X3Delivery) -> Vec<crate::x3::X3Packet> {
        delivery.packets.try_iter().collect()
    }

    #[test]
    fn an_unsplit_call_delivers_the_two_ingress_taps_and_nothing_from_the_egress() {
        let mut call = ulaw_alaw_call();
        let delivery = intercept(&mut call, true);
        let a = voice(1, 0xD5);
        let b = voice(1, 0x55);
        let _ = from(&mut call, A_SOURCE, 1, a.clone());
        let _ = from(&mut call, B_SOURCE, 2, b.clone());
        let delivered = drained(&delivery);
        assert_eq!(
            delivered.len(),
            2,
            "once each, no egress copy: {delivered:?}"
        );
        assert_eq!(delivered[0].direction, PayloadDirection::FromTarget);
        assert_eq!(delivered[0].payload, a);
        assert_eq!(delivered[1].direction, PayloadDirection::ToTarget);
        assert_eq!(delivered[1].payload, b);
    }

    #[test]
    fn a_split_call_delivers_what_the_target_hears_not_what_the_other_party_says() {
        for target_is_caller in [true, false] {
            let mut call = ulaw_alaw_call();
            let delivery = intercept(&mut call, target_is_caller);
            let mut writer = split(&mut call);
            // The playout of 20 ms of a flat tone for each party: A hears +, B hears -.
            let mut wire = Vec::new();
            for _ in 0..160 {
                wire.extend_from_slice(&8_000i16.to_le_bytes());
                wire.extend_from_slice(&(-8_000i16).to_le_bytes());
            }
            writer.push_wire(&wire);
            let _ = from(&mut call, A_SOURCE, 1, voice(1, 0xD5));
            let _ = from(&mut call, B_SOURCE, 2, voice(1, 0x55));
            let (mut toward_b, mut toward_a) = (Vec::new(), Vec::new());
            call.a_to_b.tick_split(&mut toward_b);
            call.b_to_a.tick_split(&mut toward_a);

            let delivered = drained(&delivery);
            let (heard_by_target, target_engine, target_peer) = if target_is_caller {
                (&toward_a, A_ENGINE, A_SOURCE)
            } else {
                (&toward_b, B_ENGINE, B_SOURCE)
            };
            let own_voice = if target_is_caller { 0xD5 } else { 0x55 };
            let from_target: Vec<_> = delivered
                .iter()
                .filter(|packet| packet.direction == PayloadDirection::FromTarget)
                .collect();
            let to_target: Vec<_> = delivered
                .iter()
                .filter(|packet| packet.direction == PayloadDirection::ToTarget)
                .collect();
            assert_eq!(from_target.len(), 1, "the target's own voice, once");
            assert_eq!(from_target[0].payload[12], own_voice);
            assert_eq!(
                to_target.len(),
                1,
                "exactly the one packet the target was sent (target_is_caller {target_is_caller})"
            );
            assert_eq!(
                to_target[0].payload,
                heard_by_target[0].data.to_vec(),
                "byte for byte what was sent to the target"
            );
            assert_eq!(to_target[0].source, addr(target_engine));
            assert_eq!(to_target[0].destination, addr(target_peer));
            assert_ne!(
                to_target[0].payload[12],
                if target_is_caller { 0x55 } else { 0xD5 },
                "never the other party's own voice"
            );
        }
    }

    #[test]
    fn detaching_the_split_returns_the_other_partys_ingress_with_no_gap_and_no_duplicate() {
        let mut call = ulaw_alaw_call();
        let delivery = intercept(&mut call, true);
        let _writer = split(&mut call);
        let mut toward_a = Vec::new();
        call.b_to_a.tick_split(&mut toward_a);
        let _ = from(&mut call, B_SOURCE, 2, voice(1, 0x55));
        let during = drained(&delivery);
        assert_eq!(
            during
                .iter()
                .filter(|packet| packet.direction == PayloadDirection::ToTarget)
                .count(),
            1,
            "while split: the one playout packet, not B's ingress"
        );
        assert_eq!(
            during
                .iter()
                .find(|packet| packet.direction == PayloadDirection::ToTarget)
                .map(|packet| packet.payload.clone()),
            Some(toward_a[0].data.to_vec()),
            "and it is what was sent to A"
        );

        assert!(matches!(
            call.end_split(0, "split"),
            super::super::split::DetachOutcome::Lifted
        ));
        let relayed = from(&mut call, B_SOURCE, 2, voice(2, 0x55));
        assert_eq!(relayed.len(), 1, "B is relayed to A again");
        let after = drained(&delivery);
        assert_eq!(
            after.len(),
            1,
            "after the detach: B's ingress once, and no egress copy of the relay: {after:?}"
        );
        assert_eq!(after[0].direction, PayloadDirection::ToTarget);
        assert_eq!(after[0].payload[12], 0x55);
        let mut idle = Vec::new();
        call.b_to_a.tick_split(&mut idle);
        assert!(idle.is_empty() && drained(&delivery).is_empty());
    }

    #[test]
    fn every_delivery_gets_its_own_target_side() {
        let mut call = ulaw_alaw_call();
        // Two warrants on one call: one targets the caller, the other the callee.
        let (factory_one, one) = crate::x3::x3_channel(64);
        let (factory_two, two) = crate::x3::x3_channel(64);
        let (one_a, one_b) = crate::x3::ingress_directions(true);
        let (two_a, two_b) = crate::x3::ingress_directions(false);
        call.start_x3((
            X3Taps::new(vec![
                factory_one.tap(addr(A_ENGINE), one_a),
                factory_two.tap(addr(A_ENGINE), two_a),
            ]),
            X3Taps::new(vec![
                factory_one.tap(addr(B_ENGINE), one_b),
                factory_two.tap(addr(B_ENGINE), two_b),
            ]),
        ));
        let _writer = split(&mut call);
        let (mut toward_b, mut toward_a) = (Vec::new(), Vec::new());
        call.a_to_b.tick_split(&mut toward_b);
        call.b_to_a.tick_split(&mut toward_a);
        let one = drained(&one);
        let two = drained(&two);
        assert_eq!(one.len(), 1);
        assert_eq!(
            one[0].payload,
            toward_a[0].data.to_vec(),
            "warrant one hears A's wire"
        );
        assert_eq!(two.len(), 1);
        assert_eq!(
            two[0].payload,
            toward_b[0].data.to_vec(),
            "warrant two hears B's wire"
        );
    }

    #[test]
    fn taps_handed_back_to_a_bridge_and_resumed_from_one_split_the_same_way() {
        use super::super::secure_hold::HeldResume;
        let mut call = ulaw_alaw_call();
        let delivery = intercept(&mut call, false);
        let [held_a, held_b] = call.held_back();
        assert!(!call.is_intercepted(), "the bridge has the taps");
        assert!(call.a_to_b.x3_toward.is_empty() && call.b_to_a.x3_toward.is_empty());

        call.resume_held(HeldResume {
            toward_a: Default::default(),
            toward_b: Default::default(),
            taps_a: held_a.taps,
            taps_b: held_b.taps,
            ungate: true,
        });
        let _writer = split(&mut call);
        let mut toward_b = Vec::new();
        call.a_to_b.tick_split(&mut toward_b);
        let delivered = drained(&delivery);
        assert_eq!(delivered.len(), 1, "target B hears the playout on its wire");
        assert_eq!(delivered[0].payload, toward_b[0].data.to_vec());
        assert_eq!(delivered[0].source, addr(B_ENGINE));
    }
}
