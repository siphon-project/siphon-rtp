//! The userspace RTCP relay of a kernel-relayed call that carries an MCPTT floor stream.
//!
//! A two-party call on the plain in-kernel relay never shows its audio RTCP to the engine, so an
//! RTCP APP packet (a client's floor control riding its audio RTCP, 3GPP TS 24.380 §8) would go
//! unseen. A call that carries a floor stream therefore installs its relay rules with
//! [`ForwardRule::rtcp_to_userspace`](siphon_rtp_datapath::ForwardRule::rtcp_to_userspace): the
//! backend keeps forwarding RTP in-kernel and hands every RTCP datagram it admitted (after the
//! source gate and latch, docs/security-and-nat.md §4) to the redirect stream, which the dispatcher
//! routes here by [`EndpointId`] (muxed RTP/RTCP, RFC 5761 §4, or a companion RTCP port).
//!
//! One actor per call owns the two directions. Per datagram it
//!
//! 1. re-checks the signalled-source gate (the same one the backend applied; RFC 3264),
//! 2. raises an [`Event::RtcpApp`](siphon_rtp_proto::Event::RtcpApp) for each APP packet in the
//!    compound (RFC 3550 §6.7), tagged with the sending party and `stream: audio`,
//! 3. offers the datagram to the telemetry tap, and
//! 4. relays it **unchanged** to the peer (RFC 3550 §6.1: a translator-like relay forwards the
//!    compound as received), toward the peer's latched source when the backend keeps one, else its
//!    signalled RTCP address, exactly as the backend's own `Forward` arm does.
//!
//! The relay is [`RtcpRelay`], the same one the secure-transcode pipeline uses for companion
//! RTCP, here with no secure leg on either side. Only plain (non-SRTP) calls come here: a secure
//! call's RTCP is already userspace.

use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket};
use siphon_rtp_proto::RtcpAppStream;
use tokio::task::JoinHandle;

use crate::app_events::{surface_app_to_queue, AppEventQueue, AppScope};
use crate::ingress::Ingress;
use crate::media_pipeline::{is_rtcp_datagram, send_all, Outbound, RtcpRelay};

/// Datagrams one call's relay actor queues before it sheds the newest. RTCP is a few packets a
/// second per party, so a full mailbox means the actor is wedged, and it is said so.
const MAILBOX_CAPACITY: usize = 1024;

/// One direction of the relay: what a party sends and who the party is.
pub struct RtcpRelayLeg {
    relay: RtcpRelay,
    /// The tag of the party that sends on this direction (the `from_tag` of its APP events).
    sender_tag: String,
}

impl RtcpRelayLeg {
    /// The direction receiving on `relay`'s ingress endpoint from the party `sender_tag`.
    #[must_use]
    pub fn new(relay: RtcpRelay, sender_tag: impl Into<String>) -> Self {
        Self {
            relay,
            sender_tag: sender_tag.into(),
        }
    }
}

/// The state one call's relay actor owns.
pub struct RtcpRelayCall {
    call_id: String,
    legs: Vec<RtcpRelayLeg>,
    queue: Option<AppEventQueue>,
}

impl RtcpRelayCall {
    /// A relay for `call_id` over `legs`, reporting APP packets to `queue`.
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        legs: Vec<RtcpRelayLeg>,
        queue: Option<AppEventQueue>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            legs,
            queue,
        }
    }

    fn endpoints(&self) -> Vec<EndpointId> {
        self.legs
            .iter()
            .map(|leg| leg.relay.ingress_endpoint())
            .collect()
    }

    /// Handle one redirected datagram: gate, report APP packets, tap and relay.
    pub fn process<D: Datapath>(
        &self,
        datapath: &D,
        packet: &RxPacket,
        out: &mut Vec<Outbound>,
    ) -> Ingress {
        let Some(leg) = self
            .legs
            .iter()
            .find(|leg| leg.relay.ingress_endpoint() == packet.endpoint)
        else {
            return Ingress::Refused;
        };
        // The backend redirects only RTCP. A kernel that falls back to userspace for a datagram it
        // cannot forward (no neighbour yet) may also hand up RTP; this actor relays RTCP only, and
        // media is never guessed at here.
        if !is_rtcp_datagram(&packet.data) {
            tracing::trace!(
                call_id = %self.call_id,
                endpoint = ?packet.endpoint,
                "non-RTCP datagram on a floor call's RTCP relay; dropped"
            );
            return Ingress::Refused;
        }
        let destination = datapath
            .latched_source(leg.relay.egress_endpoint())
            .unwrap_or_else(|| leg.relay.egress_dst());
        let verdict = leg
            .relay
            .relay_gated(destination, packet, &self.call_id, out);
        if verdict == Ingress::Accepted {
            // RFC 3550 §6.7: the APP parts of the compound go to the controller. The compound is
            // relayed as received either way: this reads it, it does not consume it.
            surface_app_to_queue(
                AppScope::Call(&self.call_id),
                &leg.sender_tag,
                self.queue.as_ref(),
                RtcpAppStream::Audio,
                &packet.data,
                &mut 0,
                &mut 0,
            );
        }
        verdict
    }
}

/// The running relay of one call.
struct RtcpRelayHandle {
    endpoints: Vec<EndpointId>,
    task: JoinHandle<()>,
}

/// The floor calls' RTCP relays, routed to by endpoint from the redirect dispatcher.
#[derive(Default)]
pub struct RtcpRelayRegistry {
    routes: DashMap<EndpointId, flume::Sender<RxPacket>>,
    calls: DashMap<String, RtcpRelayHandle>,
}

impl RtcpRelayRegistry {
    /// Whether `endpoint` receives its RTCP here (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Whether `call_id` has a relay running.
    #[must_use]
    pub fn has_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Calls with a relay running (a leak check: zero once every call is gone).
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.len()
    }

    /// Route a redirected datagram to its call's actor. Dropped when the mailbox is full or closed,
    /// and said so: an APP packet lost here is a lost floor message.
    pub fn dispatch(&self, packet: RxPacket) {
        let Some(mailbox) = self.routes.get(&packet.endpoint) else {
            return;
        };
        if mailbox.try_send(packet).is_err() {
            tracing::warn!(
                target: "siphon_rtp::media",
                "floor call RTCP relay mailbox full or closed; datagram dropped"
            );
        }
    }

    /// Start (or replace) the relay of `call`, transmitting over `datapath` and publishing the RTCP
    /// it relays to the datapath's telemetry tap.
    pub fn register<D>(&self, call: RtcpRelayCall, datapath: D)
    where
        D: Datapath + Send + 'static,
    {
        let tap = datapath.rtcp_tap();
        let mut call = call;
        call.legs = call
            .legs
            .into_iter()
            .map(|leg| RtcpRelayLeg {
                relay: leg.relay.with_rtcp_tap(tap.clone()),
                sender_tag: leg.sender_tag,
            })
            .collect();
        let call_id = call.call_id.clone();
        let endpoints = call.endpoints();
        // A re-answer replaces the relay: retire the displaced one first so no actor is orphaned.
        self.deregister(&call_id);
        let (mailbox, inbox) = flume::bounded(MAILBOX_CAPACITY);
        for endpoint in &endpoints {
            self.routes.insert(*endpoint, mailbox.clone());
        }
        let task = tokio::spawn(run(call, inbox, datapath));
        self.calls
            .insert(call_id, RtcpRelayHandle { endpoints, task });
    }

    /// Stop `call_id`'s relay and drop its routes. A no-op for a call without one.
    pub fn deregister(&self, call_id: &str) {
        let Some((_, handle)) = self.calls.remove(call_id) else {
            return;
        };
        for endpoint in &handle.endpoints {
            self.routes.remove(endpoint);
        }
        // The actor only ever waits on its mailbox, so there is nothing to drain.
        handle.task.abort();
    }
}

/// The actor: one relayed datagram at a time, until the mailbox closes.
async fn run<D: Datapath>(call: RtcpRelayCall, inbox: flume::Receiver<RxPacket>, datapath: D) {
    let mut outbound: Vec<Outbound> = Vec::with_capacity(1);
    while let Ok(packet) = inbox.recv_async().await {
        outbound.clear();
        call.process(&datapath, &packet, &mut outbound)
            .record(&datapath, packet.endpoint);
        send_all(&datapath, &mut outbound).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use siphon_rtp_datapath::SourceFilter;
    use siphon_rtp_proto::Event;
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// TS 24.380 §8.2.4 Floor Request APP packet.
    const FLOOR_REQUEST: [u8; 16] = [
        0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05,
        0x00,
    ];

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    fn packet(endpoint: EndpointId, source: &str, data: &[u8]) -> RxPacket {
        RxPacket {
            endpoint,
            source: address(source),
            arrival: 0,
            data: Bytes::copy_from_slice(data),
        }
    }

    fn queue() -> AppEventQueue {
        AppEventQueue::new(8, Arc::new(crate::metrics::Metrics::default()))
    }

    fn call(queue: Option<AppEventQueue>) -> RtcpRelayCall {
        let signalled = address("127.0.0.2:5001");
        RtcpRelayCall::new(
            "call-1",
            vec![
                RtcpRelayLeg::new(
                    RtcpRelay::new(
                        EndpointId(1),
                        SourceFilter::Exact(signalled.ip()),
                        EndpointId(2),
                        address("127.0.0.3:5001"),
                    ),
                    "tag-a",
                ),
                RtcpRelayLeg::new(
                    RtcpRelay::new(
                        EndpointId(2),
                        SourceFilter::Exact(address("127.0.0.3:5001").ip()),
                        EndpointId(1),
                        signalled,
                    ),
                    "tag-b",
                ),
            ],
            queue,
        )
    }

    #[test]
    fn a_compound_is_reported_for_the_sender_and_relayed_unchanged_to_the_peer() {
        let queue = queue();
        let events = queue.receiver();
        let relay = call(Some(queue));
        let datapath = UdpLoopbackDatapath::new();
        let mut datagram = vec![0x80, 200, 0x00, 0x06, 0, 0, 0, 1];
        datagram.extend_from_slice(&[0u8; 20]);
        datagram.extend_from_slice(&FLOOR_REQUEST);
        let mut out = Vec::new();

        let verdict = relay.process(
            &datapath,
            &packet(EndpointId(1), "127.0.0.2:5001", &datagram),
            &mut out,
        );

        assert_eq!(verdict, Ingress::Accepted);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].endpoint, EndpointId(2));
        assert_eq!(out[0].dst, address("127.0.0.3:5001"));
        assert_eq!(&out[0].data[..], &datagram[..]);
        let Ok(Event::RtcpApp {
            from_tag,
            stream,
            call_id,
            ..
        }) = events.try_recv()
        else {
            panic!("one rtcp_app event");
        };
        assert_eq!(
            (from_tag.as_str(), stream, call_id.as_deref()),
            ("tag-a", RtcpAppStream::Audio, Some("call-1"))
        );
        assert!(events.try_recv().is_err(), "exactly one");
    }

    #[test]
    fn the_reverse_direction_is_tagged_for_the_other_party() {
        let queue = queue();
        let events = queue.receiver();
        let relay = call(Some(queue));
        let mut out = Vec::new();
        relay.process(
            &UdpLoopbackDatapath::new(),
            &packet(EndpointId(2), "127.0.0.3:5001", &FLOOR_REQUEST),
            &mut out,
        );
        assert_eq!(out[0].endpoint, EndpointId(1));
        let Ok(Event::RtcpApp { from_tag, .. }) = events.try_recv() else {
            panic!("rtcp_app");
        };
        assert_eq!(from_tag, "tag-b");
    }

    #[test]
    fn an_unsignalled_source_is_refused_without_a_report_or_a_relay() {
        let queue = queue();
        let events = queue.receiver();
        let relay = call(Some(queue));
        let mut out = Vec::new();
        let verdict = relay.process(
            &UdpLoopbackDatapath::new(),
            &packet(EndpointId(1), "127.0.0.66:5001", &FLOOR_REQUEST),
            &mut out,
        );
        assert_eq!(verdict, Ingress::Refused);
        assert!(out.is_empty());
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn media_and_unknown_endpoints_are_refused() {
        let relay = call(None);
        let datapath = UdpLoopbackDatapath::new();
        let mut out = Vec::new();
        let mut rtp = vec![0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7];
        rtp.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            relay.process(
                &datapath,
                &packet(EndpointId(1), "127.0.0.2:5001", &rtp),
                &mut out
            ),
            Ingress::Refused,
            "RTP is the relay's, never guessed at here"
        );
        assert_eq!(
            relay.process(
                &datapath,
                &packet(EndpointId(9), "127.0.0.2:5001", &FLOOR_REQUEST),
                &mut out
            ),
            Ingress::Refused
        );
        assert!(out.is_empty());
    }

    #[test]
    fn a_call_without_a_queue_still_relays() {
        let relay = call(None);
        let mut out = Vec::new();
        let verdict = relay.process(
            &UdpLoopbackDatapath::new(),
            &packet(EndpointId(1), "127.0.0.2:5001", &FLOOR_REQUEST),
            &mut out,
        );
        assert_eq!(verdict, Ingress::Accepted);
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn the_registry_routes_by_endpoint_and_drains_to_zero_on_deregister() {
        let registry = RtcpRelayRegistry::default();
        assert!(!registry.owns(EndpointId(1)));
        registry.register(call(None), UdpLoopbackDatapath::new());
        assert!(registry.has_call("call-1"));
        assert!(registry.owns(EndpointId(1)) && registry.owns(EndpointId(2)));
        assert_eq!(registry.call_count(), 1);

        // Re-registering the same call replaces its relay rather than adding one.
        registry.register(call(None), UdpLoopbackDatapath::new());
        assert_eq!(registry.call_count(), 1);

        registry.deregister("call-1");
        assert_eq!(registry.call_count(), 0);
        assert!(!registry.owns(EndpointId(1)) && !registry.owns(EndpointId(2)));
        registry.deregister("call-1");
    }
}
