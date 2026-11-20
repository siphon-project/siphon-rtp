//! Lawful interception (ETSI TS 103 221-2 X3) of a single-leg call: an engine-answered caller with
//! no far party.
//!
//! Both directions of such a call face the caller on one endpoint, and [`MediaCall::process`] runs
//! the packet through `a_to_b` alone (the `b_to_a` branch is shadowed), so `a_to_b` is the one
//! direction carrying the caller's ingress and every datagram the engine sends the caller: the
//! prompt, the comfort noise, relayed telephone-events. Both taps therefore sit on `a_to_b`:
//!
//! * the ingress tap in `Direction::handle`, on the decrypted, authenticated slice, and
//! * the egress tap in `Direction::push_egress`, the choke point every egress datagram passes, on the
//!   plaintext slice and only once the datagram is really being sent (not while the leg is unkeyed,
//!   awaiting ICE or not receiving).
//!
//! The engine answering stands in for the callee, so the taps carry the directions the engine chose
//! from the warrant's `target_leg` with [`crate::x3::ingress_directions`] (caller as the target: the
//! ingress tap is `from_target` and the egress tap `to_target`; callee as the target: mirrored).

use super::MediaCall;
use crate::x3::X3Taps;

impl MediaCall {
    /// Begin lawful-interception delivery on a single-leg call (`MediaControl::StartX3SingleLeg`).
    ///
    /// `taps` is `(ingress taps, egress taps)`, one tap per delivery on the call. A call with a far
    /// party keeps its two ingress sets ([`MediaCall::start_x3`]) and gets no egress set, so nothing
    /// is delivered twice. The sets replace whatever was installed.
    pub fn start_x3_single_leg(&mut self, taps: (X3Taps, X3Taps)) {
        let (ingress, egress) = taps;
        self.b_to_a.x3 = X3Taps::default();
        self.a_to_b.x3 = ingress;
        self.a_to_b.x3_egress = egress;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media_pipeline::{DirectionConfig, EchoProfile, Outbound};
    use bytes::Bytes;
    use siphon_rtp_codec::factory::CodecSpec;
    use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
    use siphon_rtp_li::PayloadDirection;
    use std::net::SocketAddr;

    const CALLER: &str = "192.0.2.10:5000";
    const ENGINE: &str = "198.51.100.1:20000";

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    fn direction() -> DirectionConfig {
        let spec = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        DirectionConfig {
            ingress_endpoint: EndpointId(1),
            accepted_source: SourceFilter::Exact(addr(CALLER).ip()),
            egress_endpoint: EndpointId(1),
            egress_dst: addr(CALLER),
            decoder: siphon_rtp_codec::factory::decoder_for(&spec).expect("decoder"),
            encoder: siphon_rtp_codec::factory::encoder_for(&spec).expect("encoder"),
            egress_ssrc: 0xE0E0_0001,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            noise_suppression: false,
            echo: EchoProfile::default(),
            beep_detection: false,
            beep_cadence_guard_ms: None,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        }
    }

    fn single_leg_call() -> MediaCall {
        MediaCall::new("single", "tag-a", None, direction(), direction(), true)
            .with_comfort_idle(None)
    }

    fn voice(sequence: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
        packet.extend_from_slice(&[0xD5; 160]);
        packet
    }

    fn intercept(call: &mut MediaCall) -> crate::x3::X3Delivery {
        let (factory, delivery) = crate::x3::x3_channel(64);
        call.start_x3_single_leg((
            factory
                .tap(addr(ENGINE), PayloadDirection::FromTarget)
                .into(),
            factory.tap(addr(ENGINE), PayloadDirection::ToTarget).into(),
        ));
        delivery
    }

    #[test]
    fn the_callers_packet_is_from_target_and_the_idle_egress_is_to_target() {
        let mut call = single_leg_call();
        let delivery = intercept(&mut call);
        let mut out: Vec<Outbound> = Vec::new();
        let packet = voice(7);
        call.process(
            &RxPacket {
                endpoint: EndpointId(1),
                source: addr(CALLER),
                arrival: 0,
                data: Bytes::from(packet.clone()),
            },
            &mut out,
            &mut Vec::new(),
        );
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "the idle tick sends one comfort frame");

        let first = delivery.packets.try_recv().expect("the caller's packet");
        assert_eq!(first.direction, PayloadDirection::FromTarget);
        assert_eq!(first.payload, packet);
        assert_eq!(first.source, addr(CALLER));
        assert_eq!(first.destination, addr(ENGINE));
        let second = delivery.packets.try_recv().expect("the egress");
        assert_eq!(second.direction, PayloadDirection::ToTarget);
        assert_eq!(
            second.payload,
            out[0].data.to_vec(),
            "exactly what was sent"
        );
        assert_eq!(second.source, addr(ENGINE));
        assert_eq!(second.destination, addr(CALLER));
        assert!(delivery.packets.try_recv().is_err(), "once each");
    }

    #[test]
    fn nothing_is_delivered_toward_a_caller_the_engine_does_not_send_to() {
        let mut call = single_leg_call();
        let delivery = intercept(&mut call);
        call.set_peer_receives(false);
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
        assert!(out.is_empty());
        assert!(
            delivery.packets.try_recv().is_err(),
            "only what is actually sent is delivered"
        );
    }

    #[test]
    fn stopping_the_interception_removes_both_taps_and_a_take_carries_them() {
        let mut call = single_leg_call();
        let _delivery = intercept(&mut call);
        assert!(call.is_intercepted());
        let carried = call.take_attachments();
        assert!(carried.x3.is_none());
        assert!(carried.x3_single_leg.is_some(), "the pair is carried");
        assert!(!call.is_intercepted(), "taken off the old actor");

        let mut call = single_leg_call();
        let _delivery = intercept(&mut call);
        call.stop_x3();
        assert!(!call.is_intercepted());
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
    }
}
