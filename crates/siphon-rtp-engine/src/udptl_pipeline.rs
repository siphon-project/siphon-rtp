//! The userspace relay for a T.38 fax stream carried over UDPTL (ITU-T T.38 Annex D).
//!
//! # Why this is not a `Forward` flow
//!
//! Every other relayed stream in the engine is RTP, and the datapath's `Forward` fast path is built
//! on that: its layer-1 RFC 7983 demux accepts only first bytes 128..=191, and its layer-3 latch
//! keys a mid-stream re-latch on the RTP SSRC (docs/security-and-nat.md §4 layers 1 and 3). A UDPTL
//! datagram satisfies neither. It has no RTP header at all — its first two octets are a 16-bit
//! sequence number — so its leading byte walks the whole 0..=255 range as the fax progresses and
//! *aliases every demux class*. Installed as a `Forward` flow a fax would be dropped in the datapath
//! for roughly three packets in four, and the quarter that happened to land in the media range would
//! be worse: `rtp_media_ssrc` reads bytes 8..12 and returns `Some(garbage)` rather than `None` for a
//! datagram that merely looks like RTP, pinning the latch to a value that changes every packet.
//!
//! So the flow is installed as [`FlowAction::Redirect`](siphon_rtp_datapath::FlowAction::Redirect)
//! and relayed here. That is the arm the design already sanctions for non-RTP — "a redirected
//! endpoint is entitled to non-RTP" (§4 layer 1) — which leaves the `Forward` path's RTP-only
//! invariant, the RTPBleed fix, exactly as it was. It costs one userspace hop per datagram, which a
//! fax at tens of packets per second will never notice.
//!
//! # What it does, and what it deliberately does not
//!
//! Each direction re-enforces the layer-2 signalled-source gate itself — the UDP backend applies no
//! source gate at all on a non-ICE `Redirect` endpoint, so the consumer must (§4 layer 4, and
//! `text_pipeline` does the same) — then runs the opaque latch and forwards the datagram **byte
//! for byte**.
//!
//! It never parses UDPTL. There is no reason to: a relay does not need the sequence number, the
//! primary IFP packet or the redundancy, and those are a contract between the two fax endpoints. Not
//! parsing it means this module adds no new parser for untrusted bytes, and therefore no new attack
//! surface and no new fuzz target — the bytes that arrive are the bytes that leave.

use bytes::Bytes;
use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use std::net::SocketAddr;

use crate::media_pipeline::Outbound;
use crate::reply_latch::{OpaqueLatch, ReplyLatch};

/// One direction of a relayed fax stream: ingress on one endpoint, egress out the peer's.
struct UdptlDirection {
    /// The endpoint this direction receives on.
    ingress_endpoint: EndpointId,
    /// Layer-2 signalled-source gate (docs/security-and-nat.md §4 layer 2), folded with any
    /// `received-from` hint exactly as the audio and text relays fold theirs.
    accepted_source: SourceFilter,
    /// Layer-3 latch. Address-only and learn-once, because a UDPTL stream carries nothing that could
    /// prove a new source is the same stream — see [`OpaqueLatch`].
    source_latch: OpaqueLatch,
    /// The endpoint this direction transmits from (the peer leg's).
    egress_endpoint: EndpointId,
    /// Where to transmit until the peer's own first accepted datagram moves its latch: the
    /// `(hint IP, signalled port)` pair, or `None` when the peer has not answered yet.
    egress_dst: Option<SocketAddr>,
    /// Datagrams accepted and relayed.
    relayed: u64,
    /// Datagrams dropped by the source gate or the latch.
    dropped: u64,
}

/// How to build one direction of the relay.
pub struct UdptlDirectionConfig {
    /// The endpoint this direction receives on.
    pub ingress_endpoint: EndpointId,
    /// The source gate for that ingress.
    pub accepted_source: SourceFilter,
    /// The endpoint this direction transmits from.
    pub egress_endpoint: EndpointId,
    /// The initial destination (the peer's signalled/hinted address), `None` until it is known.
    pub egress_dst: Option<SocketAddr>,
}

impl UdptlDirection {
    fn new(config: UdptlDirectionConfig) -> Self {
        Self {
            ingress_endpoint: config.ingress_endpoint,
            accepted_source: config.accepted_source,
            source_latch: OpaqueLatch::default(),
            egress_endpoint: config.egress_endpoint,
            egress_dst: config.egress_dst,
            relayed: 0,
            dropped: 0,
        }
    }
}

/// One call's relayed fax stream: the two directions and the call it belongs to.
pub struct UdptlCall {
    call_id: String,
    a_to_b: UdptlDirection,
    b_to_a: UdptlDirection,
}

impl UdptlCall {
    /// Build the relay for one call from its two directions.
    #[must_use]
    pub fn new(
        call_id: String,
        a_to_b: UdptlDirectionConfig,
        b_to_a: UdptlDirectionConfig,
    ) -> Self {
        Self {
            call_id,
            a_to_b: UdptlDirection::new(a_to_b),
            b_to_a: UdptlDirection::new(b_to_a),
        }
    }

    /// The two endpoints this call owns, for the dispatcher's routing table and for teardown.
    #[must_use]
    pub fn endpoints(&self) -> [EndpointId; 2] {
        [self.a_to_b.ingress_endpoint, self.b_to_a.ingress_endpoint]
    }

    /// Relay one redirected datagram, appending what to transmit to `out`.
    ///
    /// Returns whether the datagram was **accepted** — the caller stamps datapath activity only
    /// then, so a spoofed spray can never keep an idle call alive (§4 layer 6).
    pub fn process(&mut self, packet: &RxPacket, out: &mut Vec<Outbound>) -> bool {
        let (direction, peer) = if packet.endpoint == self.a_to_b.ingress_endpoint {
            (&mut self.a_to_b, DirectionLabel::AtoB)
        } else if packet.endpoint == self.b_to_a.ingress_endpoint {
            (&mut self.b_to_a, DirectionLabel::BtoA)
        } else {
            return false;
        };

        // Layer 2 — the signalled-source gate. The `Redirect` arm of the UDP backend applies none of
        // its own on a non-ICE endpoint, so this is the only one there is.
        if !direction.accepted_source.accepts(packet.source.ip()) {
            direction.dropped += 1;
            tracing::trace!(
                target: "siphon_rtp::fax",
                call_id = %self.call_id,
                direction = peer.as_str(),
                "udptl datagram from an unsignalled source dropped"
            );
            return false;
        }

        // Layer 3 — the latch. Drop on reject, exactly as the `Forward` path drops, and before the
        // datagram reaches the peer: declining only to *aim* at it while still relaying it is the
        // shape of the bug §4 layer 3 records as fixed once already for RTP.
        if direction.source_latch.admit(packet.source) == ReplyLatch::Reject {
            direction.dropped += 1;
            tracing::debug!(
                target: "siphon_rtp::fax",
                call_id = %self.call_id,
                direction = peer.as_str(),
                "udptl datagram from a second source dropped; the fax stream is latched"
            );
            return false;
        }

        // The reverse direction now replies to where this one's datagrams actually come from
        // (symmetric relaying, RFC 4961 in spirit — UDPTL has no RTP/RTCP pairing of its own).
        let latched = direction.source_latch.latched();
        let reverse = match peer {
            DirectionLabel::AtoB => &mut self.b_to_a,
            DirectionLabel::BtoA => &mut self.a_to_b,
        };
        if let Some(source) = latched {
            reverse.egress_dst = Some(source);
        }

        let direction = match peer {
            DirectionLabel::AtoB => &mut self.a_to_b,
            DirectionLabel::BtoA => &mut self.b_to_a,
        };
        // Never forward into the void: with no destination resolved the datagram is dropped, not
        // guessed at. It still counts as accepted — it cleared both gates, so it is evidence the
        // call is alive even though there is nowhere to send it yet.
        let Some(dst) = direction.egress_dst else {
            return true;
        };
        direction.relayed += 1;
        out.push(Outbound {
            endpoint: direction.egress_endpoint,
            dst,
            data: Bytes::clone(&packet.data),
        });
        true
    }

    /// The relay's per-direction counters, `(a→b, b→a)` as `(relayed, dropped)`.
    #[must_use]
    pub fn counters(&self) -> [(u64, u64); 2] {
        [
            (self.a_to_b.relayed, self.a_to_b.dropped),
            (self.b_to_a.relayed, self.b_to_a.dropped),
        ]
    }
}

/// Which direction a datagram is travelling, for logging and for picking the reverse direction.
#[derive(Clone, Copy)]
enum DirectionLabel {
    AtoB,
    BtoA,
}

impl DirectionLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::AtoB => "a->b",
            Self::BtoA => "b->a",
        }
    }
}

/// What a running fax-relay actor accepts.
enum UdptlInput {
    Packet(RxPacket),
    Stop,
}

/// The dispatcher's routing table for relayed fax streams, and the per-call handles teardown needs.
/// Mirrors `TextRegistry`, minus everything a fax stream does not have: no recording, no control
/// events, no SRTP legs, no periodic tick.
#[derive(Default)]
pub struct UdptlRegistry {
    /// Image endpoint → the owning actor's mailbox.
    routes: DashMap<EndpointId, flume::Sender<UdptlInput>>,
    /// Call-id → the running actor.
    calls: DashMap<String, UdptlCallHandle>,
}

struct UdptlCallHandle {
    mailbox: flume::Sender<UdptlInput>,
    endpoints: [EndpointId; 2],
    task: tokio::task::JoinHandle<()>,
}

impl UdptlRegistry {
    /// Whether this registry routes datagrams for `endpoint` (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Whether `call_id` has a relayed fax stream.
    #[must_use]
    pub fn is_fax_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Route a redirected fax datagram to its owning actor. A full or closed mailbox drops it: a
    /// bounded mailbox is what stops a spray from growing a queue until the box dies, and late fax
    /// data is no more useful than late audio.
    pub fn dispatch(&self, packet: RxPacket) {
        if let Some(mailbox) = self.routes.get(&packet.endpoint) {
            if mailbox.try_send(UdptlInput::Packet(packet)).is_err() {
                tracing::trace!(
                    target: "siphon_rtp::fax",
                    "fax-relay mailbox full or closed; dropping redirected datagram"
                );
            }
        }
    }

    /// Register a built [`UdptlCall`] and spawn its actor over `datapath`.
    pub fn register<D>(&self, call: UdptlCall, datapath: D)
    where
        D: Datapath + Clone + Send + 'static,
    {
        let call_id = call.call_id.clone();
        let endpoints = call.endpoints();
        let (mailbox, inbox) = flume::bounded(256);
        for endpoint in endpoints {
            self.routes.insert(endpoint, mailbox.clone());
        }
        let task = tokio::spawn(run_udptl_call(call, inbox, datapath));
        self.calls.insert(
            call_id,
            UdptlCallHandle {
                mailbox,
                endpoints,
                task,
            },
        );
    }

    /// Tear a fax relay down: stop the actor, drop its routes, abort the task.
    pub fn deregister(&self, call_id: &str) {
        if let Some((_, handle)) = self.calls.remove(call_id) {
            let _ = handle.mailbox.try_send(UdptlInput::Stop);
            for endpoint in handle.endpoints {
                self.routes.remove(&endpoint);
            }
            handle.task.abort();
        }
    }
}

/// The async actor for one relayed fax stream. No periodic tick — the relay synthesizes nothing, so
/// it does no work between datagrams.
async fn run_udptl_call<D>(mut call: UdptlCall, inbox: flume::Receiver<UdptlInput>, datapath: D)
where
    D: Datapath,
{
    let mut outbound = Vec::new();
    while let Ok(input) = inbox.recv_async().await {
        match input {
            UdptlInput::Packet(packet) => {
                outbound.clear();
                // Stamp activity only for a datagram that cleared both gates: the `Redirect` arm
                // never touches the datapath's own `last_seen`, so without this a fax-only call
                // (which by then carries no audio at all) would be reaped mid-transmission.
                if call.process(&packet, &mut outbound) {
                    datapath.note_activity(packet.endpoint);
                }
                for out in outbound.drain(..) {
                    if let Err(error) = datapath.send(out.endpoint, out.dst, &out.data).await {
                        tracing::debug!(
                            target: "siphon_rtp::fax",
                            %error,
                            "fax-relay forward send failed"
                        );
                    }
                }
            }
            UdptlInput::Stop => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn endpoint(id: u64) -> EndpointId {
        EndpointId(id)
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    /// A UDPTL datagram (T.38 Annex D): the 16-bit sequence number, a one-octet primary IFP packet
    /// carrying the T.30 indicator `no-signal`, and an empty `secondary-ifp-packets` list. A real,
    /// well-formed payload — Wireshark's T.38 dissector reads it with nothing malformed. The
    /// sequence number is what makes the leading byte walk the whole range.
    fn udptl(sequence: u16) -> RxPacket {
        let mut data = Vec::from(sequence.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        RxPacket {
            endpoint: endpoint(1),
            source: address("198.51.100.1:5004"),
            arrival: 0,
            data: Bytes::from(data),
        }
    }

    fn relay() -> UdptlCall {
        UdptlCall::new(
            "fax-call".to_string(),
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(1),
                accepted_source: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                egress_endpoint: endpoint(2),
                egress_dst: Some(address("203.0.113.9:5004")),
            },
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(2),
                accepted_source: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                egress_endpoint: endpoint(1),
                egress_dst: Some(address("198.51.100.1:5004")),
            },
        )
    }

    #[test]
    fn a_udptl_datagram_is_relayed_byte_for_byte() {
        let mut call = relay();
        let mut out = Vec::new();
        let packet = udptl(0);
        assert!(call.process(&packet, &mut out));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].endpoint, endpoint(2));
        assert_eq!(out[0].dst, address("203.0.113.9:5004"));
        assert_eq!(out[0].data, packet.data, "the payload is untouched");
    }

    /// The property that makes a `Forward` flow unusable, asserted directly: a fax's leading byte
    /// walks every RFC 7983 demux class as its sequence number climbs, and the relay must not care.
    #[test]
    fn every_sequence_number_relays_whatever_demux_class_its_first_byte_lands_in() {
        let mut call = relay();
        // 0x0000 reads as STUN, 0x1400 as DTLS, 0x8000 as RTP/RTCP media, 0xC000 as none of them.
        for sequence in [0x0000_u16, 0x1400, 0x4000, 0x8000, 0xbfff, 0xc000, 0xffff] {
            let mut out = Vec::new();
            assert!(
                call.process(&udptl(sequence), &mut out),
                "sequence {sequence:#06x} accepted"
            );
            assert_eq!(out.len(), 1, "sequence {sequence:#06x} relayed");
        }
        assert_eq!(call.counters()[0], (7, 0));
    }

    #[test]
    fn a_datagram_from_an_unsignalled_source_is_dropped_and_never_latches() {
        let mut call = relay();
        let mut out = Vec::new();
        let mut spoofed = udptl(0);
        spoofed.source = address("192.0.2.66:5004");
        assert!(!call.process(&spoofed, &mut out), "gated out");
        assert!(out.is_empty(), "and never relayed");

        // The real peer still latches afterwards: a rejected spray leaves no trace.
        let mut out = Vec::new();
        assert!(call.process(&udptl(0), &mut out));
        assert_eq!(out.len(), 1);
        assert_eq!(call.counters()[0], (1, 1));
    }

    #[test]
    fn a_second_source_inside_the_gate_cannot_take_the_latched_stream() {
        // With `SourceFilter::Any` — what the opt-in `symmetric` flag installs — the latch is the
        // only constraint left, which is exactly where an SSRC-less stream must not go soft.
        let mut call = UdptlCall::new(
            "fax-symmetric".to_string(),
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(1),
                accepted_source: SourceFilter::Any,
                egress_endpoint: endpoint(2),
                egress_dst: Some(address("203.0.113.9:5004")),
            },
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(2),
                accepted_source: SourceFilter::Any,
                egress_endpoint: endpoint(1),
                egress_dst: None,
            },
        );
        let mut out = Vec::new();
        assert!(
            call.process(&udptl(0), &mut out),
            "the first source latches"
        );

        let mut racer = udptl(1);
        racer.source = address("192.0.2.66:5004");
        let mut out = Vec::new();
        assert!(
            !call.process(&racer, &mut out),
            "a racing second source is dropped even with the gate wide open"
        );
        assert!(out.is_empty());
    }

    #[test]
    fn the_first_accepted_datagram_aims_the_reverse_direction() {
        // The b→a direction starts with no destination — B has not answered — and learns it from
        // where A's datagrams actually arrive from.
        let mut call = UdptlCall::new(
            "fax-latch".to_string(),
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(1),
                accepted_source: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                egress_endpoint: endpoint(2),
                egress_dst: Some(address("203.0.113.9:5004")),
            },
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(2),
                accepted_source: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                egress_endpoint: endpoint(1),
                egress_dst: None,
            },
        );
        let mut out = Vec::new();
        assert!(call.process(&udptl(0), &mut out));

        let mut from_b = udptl(0);
        from_b.endpoint = endpoint(2);
        from_b.source = address("203.0.113.9:5004");
        let mut out = Vec::new();
        assert!(call.process(&from_b, &mut out));
        assert_eq!(out.len(), 1, "B's reply now has somewhere to go");
        assert_eq!(
            out[0].dst,
            address("198.51.100.1:5004"),
            "aimed where A's fax actually came from"
        );
    }

    #[test]
    fn a_datagram_with_nowhere_to_go_is_dropped_not_guessed_at() {
        let mut call = UdptlCall::new(
            "fax-void".to_string(),
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(1),
                accepted_source: SourceFilter::Any,
                egress_endpoint: endpoint(2),
                egress_dst: None,
            },
            UdptlDirectionConfig {
                ingress_endpoint: endpoint(2),
                accepted_source: SourceFilter::Any,
                egress_endpoint: endpoint(1),
                egress_dst: None,
            },
        );
        let mut out = Vec::new();
        assert!(
            call.process(&udptl(0), &mut out),
            "accepted — it cleared both gates, so the call is alive"
        );
        assert!(out.is_empty(), "but there is nowhere to forward it");
        assert_eq!(call.counters()[0], (0, 0));
    }

    #[test]
    fn a_datagram_on_an_endpoint_this_call_does_not_own_is_ignored() {
        let mut call = relay();
        let mut out = Vec::new();
        let mut stray = udptl(0);
        stray.endpoint = endpoint(99);
        assert!(!call.process(&stray, &mut out));
        assert!(out.is_empty());
    }
}
