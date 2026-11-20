//! Lawful-interception taps (ETSI TS 103 221-2 X3) of a WebSocket-takeover leg.
//!
//! A takeover call has no media pipeline: the leg's accepted ingress reaches the bridge through
//! [`crate::ws_bridge::WsRegistry::dispatch`] and its only egress is the bridge's drain task. The
//! WebSocket server stands in for the callee, so the two taps are the single-leg pair: the ingress
//! tap sees what the caller sent, the egress tap what the engine sent it.
//!
//! Both read one [`WsTaps`], published through a [`tokio::sync::watch`] like the leg's egress
//! destination. The drain task captures its state at spawn and the ingress path is shared by every
//! packet of the leg, so neither could be handed a new set directly; with the watch each reads the
//! current set with one borrow per packet, never holds the guard across an `.await`, and a replaced
//! set takes effect on the next packet. The set belongs to the leg, not to the connection, so it
//! rides [`crate::ws_bridge::WsEgress`] across a re-point.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::watch;

use crate::ws_bridge::WsSecureLeg;
use crate::x3::X3Taps;

/// The taps of one takeover leg: what it accepts and what it sends. Empty means not intercepted.
#[derive(Debug, Clone, Default)]
pub struct WsTapSet {
    /// Delivered on each accepted ingress packet, in the caller's direction.
    pub ingress: X3Taps,
    /// Delivered on each packet the engine sends the caller, in the engine's direction.
    pub egress: X3Taps,
}

/// The published tap set of a takeover leg. Starts empty; the engine replaces it whole.
#[derive(Debug)]
pub struct WsTaps {
    current: watch::Sender<WsTapSet>,
    /// Whether `current` holds any tap, so the packet paths of an untapped leg (nearly all of them)
    /// pay one relaxed load instead of the watch's lock. Written after the set is published and
    /// before it is withdrawn, so a path that reads `true` finds the set.
    tapped: Arc<AtomicBool>,
}

impl Default for WsTaps {
    fn default() -> Self {
        Self {
            current: watch::Sender::new(WsTapSet::default()),
            tapped: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl WsTaps {
    /// Replace the leg's taps with `set`, whole. Takes effect on the next packet.
    pub fn set(&self, set: WsTapSet) {
        let tapped = !(set.ingress.is_empty() && set.egress.is_empty());
        self.current.send_replace(set);
        self.tapped.store(tapped, Ordering::Release);
    }

    /// Take every tap off the leg. Dropping the set closes each delivery's packet channel only once
    /// no session holds its factory, so a delivery that ends still drains what it buffered.
    pub fn clear(&self) {
        self.tapped.store(false, Ordering::Release);
        self.current.send_replace(WsTapSet::default());
    }

    /// Whether any delivery taps the leg.
    #[must_use]
    pub fn is_tapped(&self) -> bool {
        self.tapped.load(Ordering::Acquire)
    }

    /// Deliver one accepted, decrypted ingress packet to every delivery. One borrow of the watch,
    /// no allocation, never awaits ([`X3Taps::deliver`]).
    pub fn deliver_ingress(&self, source: SocketAddr, data: &[u8]) {
        if !self.tapped.load(Ordering::Relaxed) {
            return;
        }
        let set = self.current.borrow();
        set.ingress.deliver(source, data);
    }

    /// A receiver for the bridge's drain task, which delivers the egress per packet.
    #[must_use]
    pub fn subscribe(&self) -> WsEgressTaps {
        WsEgressTaps {
            current: self.current.subscribe(),
            tapped: self.tapped.clone(),
        }
    }
}

/// The drain task's view of the leg's taps.
#[derive(Debug)]
pub struct WsEgressTaps {
    current: watch::Receiver<WsTapSet>,
    tapped: Arc<AtomicBool>,
}

impl WsEgressTaps {
    /// Deliver one packet the engine sends the caller, toward `destination` ([`X3Taps::deliver_egress`]).
    pub fn deliver(&self, destination: SocketAddr, data: &[u8]) {
        if !self.tapped.load(Ordering::Relaxed) {
            return;
        }
        let set = self.current.borrow();
        set.egress.deliver_egress(destination, data);
    }
}

/// Everything the drain task does to one rendered downlink packet before it goes on the wire:
/// encrypt it on a secure leg (into `sealed`, never sending the clear packet toward a peer that
/// negotiated SRTP), then deliver the **plaintext** to the egress taps, now that the engine has
/// decided to send it. Returns the datagram to send, or `None` when the packet must not be sent
/// (an unkeyed leg or a crypto failure: fail closed, and nothing is delivered for what is not sent).
///
/// One function so the drain and its allocation test and benchmark cannot drift.
pub fn downlink_datagram<'a>(
    packet: &'a [u8],
    secure: Option<&WsSecureLeg>,
    sealed: &'a mut Vec<u8>,
    taps: &WsEgressTaps,
    destination: SocketAddr,
) -> Option<&'a [u8]> {
    let datagram: &[u8] = match secure {
        None => packet,
        Some(secure) => {
            sealed.clear();
            if !secure.protect_egress(packet, sealed) {
                return None;
            }
            sealed
        }
    };
    taps.deliver(destination, packet);
    Some(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3::x3_channel;
    use siphon_rtp_li::PayloadDirection;
    use siphon_rtp_srtp::leg::SecureLeg;
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    fn rtp(sequence: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 0x0A, 0x0A, 0x0A, 0x0A]);
        packet.extend_from_slice(&[0xD5; 160]);
        packet
    }

    fn key(seed: u8) -> SrtpKeyMaterial {
        SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30 bytes")
    }

    /// One delivery's set: ingress `FromTarget`, egress `ToTarget`, as a caller target gets.
    fn one_delivery() -> (WsTapSet, crate::x3::X3Delivery) {
        let (factory, delivery) = x3_channel(16);
        let set = WsTapSet {
            ingress: X3Taps::single(
                factory.tap(address("198.51.100.1:20000"), PayloadDirection::FromTarget),
            ),
            egress: X3Taps::single(
                factory.tap(address("198.51.100.1:20000"), PayloadDirection::ToTarget),
            ),
        };
        (set, delivery)
    }

    #[tokio::test]
    async fn a_fresh_leg_is_untapped_and_delivers_nothing() {
        let taps = WsTaps::default();
        assert!(!taps.is_tapped());
        taps.deliver_ingress(address("192.0.2.1:4000"), &rtp(1));
        let egress = taps.subscribe();
        egress.deliver(address("192.0.2.1:4000"), &rtp(2));
    }

    #[tokio::test]
    async fn a_set_delivers_ingress_and_egress_in_their_own_directions_until_cleared() {
        let taps = WsTaps::default();
        let (set, delivery) = one_delivery();
        taps.set(set);
        assert!(taps.is_tapped());
        let egress = taps.subscribe();

        taps.deliver_ingress(address("192.0.2.1:4000"), &rtp(1));
        egress.deliver(address("192.0.2.1:4000"), &rtp(2));
        let ingress = delivery.packets.try_recv().expect("the ingress packet");
        let sent = delivery.packets.try_recv().expect("the egress packet");
        assert_eq!(ingress.direction, PayloadDirection::FromTarget);
        assert_eq!(ingress.source, address("192.0.2.1:4000"));
        assert_eq!(ingress.destination, address("198.51.100.1:20000"));
        assert_eq!(ingress.payload, rtp(1));
        assert_eq!(sent.direction, PayloadDirection::ToTarget);
        assert_eq!(sent.source, address("198.51.100.1:20000"));
        assert_eq!(sent.destination, address("192.0.2.1:4000"));
        assert_eq!(sent.payload, rtp(2));

        taps.clear();
        assert!(!taps.is_tapped());
        taps.deliver_ingress(address("192.0.2.1:4000"), &rtp(3));
        egress.deliver(address("192.0.2.1:4000"), &rtp(4));
        assert!(delivery.packets.try_recv().is_err(), "nothing after clear");
    }

    #[tokio::test]
    async fn a_replaced_set_reaches_a_receiver_that_already_exists() {
        let taps = WsTaps::default();
        let egress = taps.subscribe();
        let (set, delivery) = one_delivery();
        taps.set(set);
        egress.deliver(address("192.0.2.1:4000"), &rtp(1));
        assert_eq!(
            delivery.packets.try_recv().expect("delivered").payload,
            rtp(1),
            "a drain task spawned before the interception still delivers"
        );
    }

    #[tokio::test]
    async fn the_drain_step_delivers_the_plaintext_it_sent_not_the_ciphertext() {
        let taps = WsTaps::default();
        let (set, delivery) = one_delivery();
        taps.set(set);
        let egress = taps.subscribe();
        let leg = WsSecureLeg::keyed(SecureLeg::new(&key(0x11), &key(0x22)));
        let mut sealed = Vec::new();
        let packet = rtp(7);

        let datagram = downlink_datagram(
            &packet,
            Some(&leg),
            &mut sealed,
            &egress,
            address("192.0.2.1:4000"),
        )
        .expect("a keyed leg sends")
        .to_vec();
        assert_ne!(datagram, packet, "what leaves the socket is encrypted");
        assert_eq!(
            delivery.packets.try_recv().expect("delivered").payload,
            packet,
            "what is delivered is the plaintext the engine sent"
        );

        let mut plain = Vec::new();
        let sent = downlink_datagram(
            &packet,
            None,
            &mut plain,
            &egress,
            address("192.0.2.1:4000"),
        )
        .expect("a plain leg sends");
        assert_eq!(sent, &packet[..]);
        assert_eq!(
            delivery.packets.try_recv().expect("delivered").payload,
            packet
        );
    }

    #[tokio::test]
    async fn an_unkeyed_leg_sends_nothing_and_delivers_nothing() {
        let taps = WsTaps::default();
        let (set, delivery) = one_delivery();
        taps.set(set);
        let egress = taps.subscribe();
        let pending = WsSecureLeg::pending();
        let mut sealed = Vec::new();
        let packet = rtp(1);
        let datagram = downlink_datagram(
            &packet,
            Some(&pending),
            &mut sealed,
            &egress,
            address("192.0.2.1:4000"),
        );
        assert!(datagram.is_none(), "an unkeyed leg fails closed");
        assert!(
            delivery.packets.try_recv().is_err(),
            "content that was never sent is never delivered"
        );
    }
}
