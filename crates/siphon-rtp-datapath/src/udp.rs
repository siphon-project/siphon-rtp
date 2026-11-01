//! The UDP-loopback datapath backend.
//!
//! Every endpoint is a real `tokio` UDP socket bound on loopback; a per-endpoint receive task
//! applies the installed [`FlowAction`]. [`FlowAction::Forward`] re-emits the datagram out the
//! peer endpoint's socket — modelling the XDP_TX rewrite, including symmetric-RTP **latching**
//! (reply to wherever the peer's packets actually arrive from). This backend needs no privileges
//! or NIC, so it is the CI datapath and the behavioural reference the XDP backend must match.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::dscp::Dscp;
use crate::udp_relay::{
    emit, is_data_indication, relay_egress, relay_unwrap, RelayEgress, RelayIngress,
};
use crate::{
    classify, rtp_media_ssrc, signalled_peer_moved, source_latch_verdict, AddressFamily, Datapath,
    DatapathError, Endpoint, EndpointId, EndpointStats, FlowAction, ForwardRule, IceAgentMode,
    IceConfig, IceDatapathEvent, LatchPolicy, ObservedRtcp, PacketClass, RxPacket, SourceLatch,
    SourceLatchVerdict,
};

/// Receive buffer size. RTP/RTCP/STUN/DTLS media datagrams sit well under a 1500-byte MTU; this
/// leaves headroom without paying for jumbo frames the media plane never sees.
const MAX_DATAGRAM: usize = 2048;

/// The logical clock's origin. One rather than zero, because `0` is the value
/// [`StatsAtomic::last_seen`] carries to mean "this endpoint has accepted no packet yet", and a
/// clock starting at zero would let a packet accepted in the very first tick stamp that same value —
/// indistinguishable from never having arrived. The origin itself is arbitrary (nothing reads an
/// absolute tick, only differences), so making it one costs nothing and keeps the sentinel exact.
const FIRST_TICK: u64 = 1;

/// Lock-free per-endpoint counters, mutated from the endpoint's single receive task and snapshotted
/// by `stats`.
struct StatsAtomic {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    packets_dropped: AtomicU64,
    /// Logical-clock tick of the last accepted packet (`0` = none), for the media-timeout sweep.
    last_seen: AtomicU64,
    /// Cumulative RFC 3550 §A.1-style forward-gap loss estimate on this endpoint's **ingress** — the
    /// number of missed inbound RTP media sequence numbers, so a plain relay leg reports network loss
    /// to the CDR. Summable; only ever bumped from the single receive task.
    packets_lost: AtomicU64,
    /// Per-endpoint internal loss-estimator state: the last RTP sequence observed on ingress
    /// ([`RTP_SEQ_NONE`](siphon_rtp_ebpf_common::loss::RTP_SEQ_NONE) before the first packet). Read +
    /// written only by the endpoint's single receive task (`recv_loop` awaits each `dispatch` before
    /// the next `recv_from`), so a plain `Relaxed` load/store carries no read-modify-write race.
    last_rtp_seq: AtomicU64,
}

impl Default for StatsAtomic {
    fn default() -> Self {
        Self {
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            last_seen: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            // No RTP sequence observed yet — the loss estimate establishes its baseline on the first
            // accepted media packet, not on a spurious 0 -> first-seq gap.
            last_rtp_seq: AtomicU64::new(siphon_rtp_ebpf_common::loss::RTP_SEQ_NONE),
        }
    }
}

impl StatsAtomic {
    fn snapshot(&self) -> EndpointStats {
        EndpointStats {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            packets_out: self.packets_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_lost: self.packets_lost.load(Ordering::Relaxed),
        }
    }
}

/// One allocated endpoint: its socket, counters, and receive task.
struct EndpointEntry {
    socket: Arc<UdpSocket>,
    stats: Arc<StatsAtomic>,
    task: JoinHandle<()>,
}

/// A deterministic media-port allocator over a closed `[min, max]` range.
///
/// Unlike OS `:0` ephemeral binding, a port handed out here is drawn from a bounded,
/// operator-configured window — so the media plane can be firewalled to a known range (rtpengine
/// `port-min`/`port-max` parity) and, crucially for HA takeover, a *specific* port can be re-bound
/// on a standby (see [`UdpLoopbackDatapath::alloc_specific`]). Ports are reserved *before* the bind
/// under a lock-free set, so a concurrent allocation never picks the same one; a port that happens
/// to be held by another process on the host is skipped and released.
struct PortAllocator {
    min: u16,
    max: u16,
    /// Round-robin cursor across the range, so successive allocations spread out instead of always
    /// retrying the low end.
    cursor: AtomicUsize,
    /// Ports currently reserved by this backend (reserved before the bind, released on removal).
    reserved: DashSet<u16>,
}

impl PortAllocator {
    fn new(min: u16, max: u16) -> Self {
        Self {
            min,
            max,
            cursor: AtomicUsize::new(0),
            reserved: DashSet::new(),
        }
    }

    /// Inclusive size of the range.
    fn span(&self) -> usize {
        (self.max - self.min) as usize + 1
    }

    /// Reserve the next free port in round-robin order, or `None` when every port in the range is
    /// already reserved. The port is marked used immediately (before the bind) so a concurrent
    /// allocation cannot also pick it.
    fn reserve_next(&self) -> Option<u16> {
        let span = self.span();
        for _ in 0..span {
            let offset = self.cursor.fetch_add(1, Ordering::Relaxed) % span;
            let candidate = self.min + offset as u16;
            if self.reserved.insert(candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Reserve a *specific* port (HA restore — re-bind the exact port the primary used). Returns
    /// `false` when the port is outside `[min, max]` or already reserved.
    fn reserve_exact(&self, port: u16) -> bool {
        if port < self.min || port > self.max {
            return false;
        }
        self.reserved.insert(port)
    }

    /// Return a port to the pool (endpoint removed, or a bind that raced a host process failed).
    fn release(&self, port: u16) {
        self.reserved.remove(&port);
    }
}

/// Verdict of the latch gate for one packet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LatchOutcome {
    /// Forward this packet (and the latch now reflects its source).
    Accept,
    /// Drop this packet — a new source whose SSRC does not match the latched stream (hijack).
    Reject,
}

/// Verdict of the layer-4 ICE gate for one datagram (`docs/security-and-nat.md` §4 layer 4).
#[derive(Clone, Copy, PartialEq, Eq)]
enum IceGate {
    /// The endpoint carries no ICE credentials — layers 2 and 3 apply instead.
    NotIce,
    /// An ICE endpoint whose source a connectivity check validated.
    Accept,
    /// An ICE endpoint, and this is not the validated source (or nothing is validated yet).
    Reject,
}

/// Shared backend state. Held by the public handle (strong) and by receive tasks (weak), so the
/// strong count reaches zero on teardown and [`Drop`] can abort the parked receive tasks.
struct Inner {
    next_id: AtomicU64,
    /// Logical clock (monotonic ticks) for the media-timeout sweep; advanced via `advance_clock`.
    ///
    /// Starts at [`FIRST_TICK`], not at zero, so that the tick an accepted packet stamps can never be
    /// the `0` that [`StatsAtomic::last_seen`] uses to mean "no packet yet". The origin is arbitrary —
    /// only differences between ticks are ever read — but the sentinel is not, and the media-timeout
    /// sweep reasons from it.
    clock: AtomicU64,
    /// Live (reserved) endpoint count, capped at `max_endpoints` to bound port/FD use.
    live: AtomicUsize,
    /// Maximum concurrent media endpoints; `usize::MAX` is unbounded.
    max_endpoints: usize,
    /// The local IP every endpoint socket binds. Loopback by default (the NIC-free CI posture); a
    /// routable IP in production so relay/media sockets are reachable by real peers.
    bind_ip: IpAddr,
    /// Optional deterministic media-port range. `Some` binds each endpoint from the configured
    /// `[min, max]` window (firewallable; re-bindable on a standby); `None` uses OS `:0` ephemeral
    /// ports (the default / CI posture).
    ports: Option<PortAllocator>,
    /// The DSCP (RFC 2474) every media socket is marked with, as a raw 6-bit code point. Read once
    /// per bind (never on the per-packet path), so an atomic costs nothing and lets
    /// [`UdpLoopbackDatapath::with_dscp`] configure the backend after the `Arc` exists.
    dscp: AtomicU8,
    endpoints: DashMap<EndpointId, EndpointEntry>,
    flows: DashMap<EndpointId, FlowAction>,
    /// Per-endpoint latched peer source (address + RTP SSRC), maintained by [`source_latch_verdict`].
    /// A packet from a new source re-latches only with a matching SSRC — the RTPBleed/hijack gate, not
    /// a blind first-source latch.
    latched: DashMap<EndpointId, SourceLatch<SocketAddr>>,
    /// Per-endpoint TURN allocation the leg relays through (RFC 5766 §11 ChannelData). Present only
    /// for a leg whose ICE selected a **relayed** local candidate.
    turn_relay: DashMap<EndpointId, crate::TurnRelay>,
    /// How many endpoints have a [`Self::turn_relay`] entry. The relay-forward path reads this one
    /// relaxed atomic before touching the map, so a node with no TURN allocation (the default)
    /// pays nothing per packet for the egress check.
    turn_relay_count: AtomicUsize,
    /// Per-endpoint ICE-lite credentials; when present, STUN checks are answered and the validated
    /// source is adopted as the media path (RFC 8445).
    ice: DashMap<EndpointId, IceConfig>,
    /// PRIORITY of the nominated pair the ice-lite responder selected per endpoint (RFC 8445
    /// §7.3.1.5): written by a USE-CANDIDATE check that [`crate::nomination_supersedes`] the stored
    /// one, cleared with the credentials (an ICE restart brings new ones, §9.1.1.1).
    ice_nominated: DashMap<EndpointId, u32>,
    /// Per-endpoint **full-agent** STUN forwarding sink. Present only for endpoints promoted via
    /// [`Datapath::set_ice_agent`]; a STUN datagram on such an endpoint is forwarded here (in
    /// addition to the responder answering inbound checks) so the engine's consent checker can
    /// correlate Binding responses — which the responder path drops. Bounded per-sink; a full sink
    /// drops the event (a lost consent response only delays the refresh, never blocks the reactor).
    ice_events: DashMap<EndpointId, flume::Sender<IceDatapathEvent>>,
    /// Endpoints whose STUN the datapath forwards **without answering** — a full RFC 8445 agent owns
    /// request handling there (see [`IceAgentMode::ForwardOnly`]). Absent ⇒ the responder still runs.
    ice_forward_only: DashMap<EndpointId, ()>,
    /// Per-endpoint publisher of the ICE-validated source, created when a consumer subscribes through
    /// [`Datapath::watch_ice_validated`]. Written wherever `latched` is written on an ICE endpoint: the
    /// responder's validated check and [`Datapath::adopt_source`].
    ice_validated: DashMap<EndpointId, tokio::sync::watch::Sender<Option<SocketAddr>>>,
    redirect_tx: flume::Sender<RxPacket>,
    redirect_rx: flume::Receiver<RxPacket>,
    /// Telemetry tap: when enabled, relayed RTCP is copied here (bounded, dropped on backpressure).
    observe_enabled: AtomicBool,
    observe_tx: flume::Sender<ObservedRtcp>,
    observe_rx: flume::Receiver<ObservedRtcp>,
}

impl Inner {
    /// Apply the installed flow to one received datagram. Holds no map guard across an `.await`.
    async fn dispatch(
        &self,
        endpoint: EndpointId,
        source: SocketAddr,
        payload: &[u8],
        in_stats: &StatsAtomic,
    ) {
        let action = match self.flows.get(&endpoint) {
            Some(action) => *action,
            None => {
                in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        match action {
            FlowAction::Forward(rule) => {
                // Layer 1 — RFC 7983 demux: only RTP/RTCP may drive the relay or move the latch;
                // STUN/DTLS/garbage are dropped here. (docs/security-and-nat.md §4 layer 1.)
                if !is_rtp_or_rtcp(payload) {
                    in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                // Layer 4 — ICE supersedes blind latching (docs/security-and-nat.md §4 layer 4;
                // RFC 8445 §7). On an ICE endpoint the signalled-source gate (layer 2) and the SSRC
                // re-latch (layer 3) are subsumed by the authenticated connectivity check.
                match self.ice_gate(endpoint, source) {
                    IceGate::Reject => {
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    IceGate::Accept => {}
                    IceGate::NotIce => {
                        // Layer 2 — signalled-source gate: only the SDP-signalled peer may send here.
                        // This is the RTPBleed fix; an off-path source on another address is dropped
                        // before it can latch or be forwarded. (docs/security-and-nat.md §4 layer 2;
                        // RFC 3264.)
                        if !rule.accepted_source.accepts(source.ip()) {
                            in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        // Layer 3 — SSRC-consistent latch: a new source re-latches only when it
                        // carries the same RTP SSRC (a genuine NAT rebind), never a hijack spray.
                        // (docs/security-and-nat.md §4 layer 3; RFC 3550 §8.)
                        if rule.latch != LatchPolicy::Off
                            && self.update_latch(endpoint, source, rtp_media_ssrc(payload))
                                == LatchOutcome::Reject
                        {
                            in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }

                // The packet is accepted — stamp activity for the media-timeout sweep (§4 layer 6).
                in_stats
                    .last_seen
                    .store(self.clock.load(Ordering::Relaxed), Ordering::Relaxed);

                // RTP forward-gap loss estimate (RFC 3550 §A.1) for a plain userspace relay leg, so its
                // CDR shows inbound network loss even without a transcode actor. RTCP / short datagrams
                // are skipped. Single-task per endpoint (this `recv_loop` drives `dispatch` serially),
                // so a plain Relaxed load/store on `last_rtp_seq` carries no read-modify-write race.
                if rtp_media_ssrc(payload).is_some() {
                    let seq = u16::from_be_bytes([payload[2], payload[3]]);
                    let last = in_stats.last_rtp_seq.load(Ordering::Relaxed);
                    let (updated_last, lost) =
                        siphon_rtp_ebpf_common::loss::rtp_loss_update(last, seq);
                    if lost > 0 {
                        in_stats.packets_lost.fetch_add(lost, Ordering::Relaxed);
                    }
                    in_stats.last_rtp_seq.store(updated_last, Ordering::Relaxed);
                }

                // RFC 3550 §6 / RFC 5761 §4: a rule that asks for it hands the RTCP it admitted to the
                // engine instead of forwarding it, so the engine can read it (an MCPTT floor call's
                // APP packets) and relay it itself. Placed after the gate and the latch above, so an
                // unadmitted source never reaches the consumer; RTP is untouched.
                if rule.rtcp_to_userspace && is_rtcp(payload) {
                    let packet = RxPacket {
                        endpoint,
                        source,
                        arrival: self.clock.load(Ordering::Relaxed).saturating_mul(20_000),
                        data: Bytes::copy_from_slice(payload),
                    };
                    if self.redirect_tx.send(packet).is_err() {
                        tracing::debug!(?endpoint, "redirect stream has no receiver");
                    }
                    return;
                }

                // Forward toward the peer endpoint: prefer its latched source (symmetric RTP) over
                // its configured destination; drop if neither resolves (never forward into the void).
                let destination = self
                    .latched
                    .get(&rule.out_endpoint)
                    .map(|latch| latch.source)
                    .or(rule.out_dst);
                let Some(destination) = destination else {
                    in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let out = match self.endpoints.get(&rule.out_endpoint) {
                    Some(entry) => (entry.socket.clone(), entry.stats.clone()),
                    None => {
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                // RFC 8656 §11.1 / §12: a destination behind the out leg's allocation is reached
                // through the TURN server, so it goes out framed and addressed to the server, the
                // same framing `send` applies. Free when no allocation is installed.
                let egress = if self.turn_relay_count.load(Ordering::Relaxed) == 0 {
                    RelayEgress::Direct
                } else {
                    match self.turn_relay.get(&rule.out_endpoint) {
                        Some(relay) => relay_egress(&relay, destination, payload),
                        None => RelayEgress::Direct,
                    }
                };
                match emit(&out.0, egress, destination, payload).await {
                    Ok(sent) => {
                        out.1.packets_out.fetch_add(1, Ordering::Relaxed);
                        out.1.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        // A stalled TURN stream sheds media instead of queueing it.
                        tracing::debug!(?endpoint, "forward dropped: TURN stream queue full");
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        tracing::warn!(?endpoint, %error, "forward send failed");
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Telemetry tap: copy relayed RTCP to observers (off by default; never blocks relay).
                if self.observe_enabled.load(Ordering::Relaxed) && is_rtcp(payload) {
                    let _ = self.observe_tx.try_send(ObservedRtcp {
                        endpoint,
                        source,
                        destination,
                        payload: Bytes::copy_from_slice(payload),
                    });
                }
            }
            FlowAction::Redirect => {
                // Layer 4 — the same ICE gate the relay path enforces, on the userspace slow path
                // (docs/security-and-nat.md §4 layer 4; RFC 8445 §7). A `Redirect` endpoint is how a
                // conference seat, a promoted call, a WebSocket takeover and the SRTP/DTLS bridges
                // receive their media, and an ICE one of those must be gated on the connectivity
                // check exactly as a `Forward` leg is: the consumer's own signalled-source gate
                // cannot do it, because an ICE leg deliberately runs that gate open — a
                // peer-reflexive check legitimately arrives from a transport the SDP never carried
                // (RFC 8445 §7.3.1.3), so the address is not the discriminator here; the
                // MESSAGE-INTEGRITY the responder verified is.
                //
                // Only the *source* is gated, never the packet class: unlike the relay path there is
                // no layer-1 RFC 7983 demux here, because a redirected endpoint is entitled to
                // non-RTP — a DTLS-SRTP leg's handshake records must reach the bridge (RFC 5764),
                // and a TURN allocation's own STUN must reach its client (RFC 5766 §11). STUN never
                // reaches this arm on an ICE endpoint: `recv_loop` hands it to the responder or the
                // full agent first, which is what lets a check through and lets the latch form.
                if self.ice_gate(endpoint, source) == IceGate::Reject {
                    in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let packet = RxPacket {
                    endpoint,
                    source,
                    // Loopback (CI) backend: derive arrival from the logical tick clock (one tick =
                    // 20 ms) so it stays deterministic and `Instant`-free. Real-time precision is the
                    // XDP backend's job; jitter unit tests stamp `arrival` on the packet directly.
                    arrival: self.clock.load(Ordering::Relaxed).saturating_mul(20_000),
                    data: Bytes::copy_from_slice(payload),
                };
                if self.redirect_tx.send(packet).is_err() {
                    tracing::debug!(?endpoint, "redirect stream has no receiver");
                }
            }
            FlowAction::Drop => {
                in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The layer-4 ICE verdict for one datagram arriving on `endpoint` from `source`
    /// (docs/security-and-nat.md §4 layer 4; RFC 8445 §7).
    ///
    /// On an endpoint carrying ICE credentials the connectivity-check responder ([`handle_stun`]) —
    /// or, for a full RFC 8445 agent, the engine through [`Datapath::adopt_source`] — is the **only**
    /// thing that adopts a media source. Traffic is accepted only from that adopted source: nothing
    /// before a check has validated one, and nothing from a different source afterwards, so an ICE
    /// leg never blind-latches its first sender the way a plain relay's layer 3 may. The signalled
    /// address is deliberately not consulted; a peer-reflexive candidate legitimately sends from a
    /// transport the SDP never carried (RFC 8445 §7.3.1.3).
    ///
    /// One definition, consulted by both delivery paths — the in-kernel-style relay
    /// ([`FlowAction::Forward`]) and the userspace slow path ([`FlowAction::Redirect`]) — so the two
    /// cannot drift on what an ICE leg is allowed to receive.
    fn ice_gate(&self, endpoint: EndpointId, source: SocketAddr) -> IceGate {
        if !self.ice.contains_key(&endpoint) {
            return IceGate::NotIce;
        }
        if self
            .latched
            .get(&endpoint)
            .is_some_and(|latch| latch.source == source)
        {
            IceGate::Accept
        } else {
            IceGate::Reject
        }
    }

    /// Publish `endpoint`'s ICE-validated source to its subscribers, if it has any. The source is read
    /// inside the publisher's own lock, so a check validated while a subscription is being set up can
    /// never be overwritten by an older reading.
    fn publish_ice_validated(&self, endpoint: EndpointId) {
        if let Some(publisher) = self.ice_validated.get(&endpoint) {
            publisher.send_if_modified(|published| {
                let validated = self.latched.get(&endpoint).map(|latch| latch.source);
                if *published == validated {
                    return false;
                }
                *published = validated;
                true
            });
        }
    }

    /// Forget the latches a reinstalled `rule` on `endpoint` has made stale, after the rule is in
    /// place (so its gate already applies to whatever latches next). A re-answer that moves the far
    /// party re-points both directions: the rule on `endpoint` gates a new source, and the rule
    /// toward `rule.out_endpoint` names a new destination. A latch left over from the replaced peer
    /// would reject the new peer's stream (a new source with a new SSRC is exactly what layer 3
    /// refuses) and keep steering the reply to the old transport, so the new peer is let in through
    /// the gate instead (docs/security-and-nat.md §4 layer 3, "re-answer").
    ///
    /// - `endpoint`'s own latch goes when the new gate no longer admits its source: forwarding to a
    ///   source the gate refuses to hear from is never right.
    /// - The peer endpoint's latch goes when the rule toward it moved to a different signalled
    ///   destination ([`signalled_peer_moved`]), which also covers a move to another port on the same
    ///   address that an address-only gate cannot see.
    ///
    /// An ICE endpoint is left alone: there `latched` is the check-validated path, which only a
    /// connectivity check moves (layer 4).
    fn forget_stale_latches(
        &self,
        endpoint: EndpointId,
        previous: Option<FlowAction>,
        rule: &ForwardRule,
    ) {
        if !self.ice.contains_key(&endpoint) {
            self.latched.remove_if(&endpoint, |_, latch| {
                !rule.accepted_source.accepts(latch.source.ip())
            });
        }
        if let Some(FlowAction::Forward(previous)) = previous {
            if previous.out_endpoint == rule.out_endpoint
                && signalled_peer_moved(previous.out_dst, rule.out_dst)
                && !self.ice.contains_key(&rule.out_endpoint)
            {
                self.latched.remove(&rule.out_endpoint);
            }
        }
    }

    /// Apply the SSRC-consistent latch ([`source_latch_verdict`]) to a packet arriving on `endpoint`
    /// from `source`, storing what it learns. Returns [`LatchOutcome::Reject`] for a likely hijack (a
    /// new source that cannot prove it is the latched stream); the caller then drops it.
    /// (docs/security-and-nat.md §4 layer 3.)
    fn update_latch(
        &self,
        endpoint: EndpointId,
        source: SocketAddr,
        ssrc: Option<u32>,
    ) -> LatchOutcome {
        // Copy the current latch out and drop the read guard before any insert (no re-entrant lock).
        let current = self.latched.get(&endpoint).map(|latch| *latch);
        match source_latch_verdict(current, source, ssrc) {
            SourceLatchVerdict::Keep => LatchOutcome::Accept,
            SourceLatchVerdict::Learn(latch) => {
                self.latched.insert(endpoint, latch);
                LatchOutcome::Accept
            }
            SourceLatchVerdict::Reject => LatchOutcome::Reject,
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // The receive tasks hold only a `Weak<Inner>`, so they are parked on `recv_from` with no
        // way to notice teardown — abort them explicitly.
        for entry in self.endpoints.iter() {
            entry.value().task.abort();
        }
    }
}

/// The always-available, NIC-free datapath backend. Cheaply cloned (shares one `Arc<Inner>`).
#[derive(Clone)]
pub struct UdpLoopbackDatapath {
    inner: Arc<Inner>,
}

impl Default for UdpLoopbackDatapath {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpLoopbackDatapath {
    /// Create an empty, unbounded backend (no media-port cap).
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_endpoints(usize::MAX)
    }

    /// Create a backend that allocates at most `max_endpoints` concurrent media endpoints; further
    /// `alloc_endpoint` calls fail with [`DatapathError::PoolExhausted`] until one is freed. This is
    /// the port/FD-exhaustion guard (docs/security-and-nat.md §5). Sockets bind loopback.
    #[must_use]
    pub fn with_max_endpoints(max_endpoints: usize) -> Self {
        Self::build(IpAddr::V4(Ipv4Addr::LOCALHOST), max_endpoints, None)
    }

    /// Create a backend whose endpoint sockets bind `bind_ip` instead of loopback — the production
    /// relay posture, so relay/media sockets are reachable by real peers. Prefer a specific routable
    /// IP (the transmitted source then matches the advertised address); `0.0.0.0` binds every
    /// interface but lets the kernel pick the source per route, so advertise the reachable IP
    /// separately (the TURN server's `--turn-relay-ip`). Unbounded pool.
    #[must_use]
    pub fn with_bind_ip(bind_ip: IpAddr) -> Self {
        Self::build(bind_ip, usize::MAX, None)
    }

    /// As [`with_bind_ip`](Self::with_bind_ip), also bounding the endpoint pool
    /// ([`with_max_endpoints`](Self::with_max_endpoints)).
    #[must_use]
    pub fn with_bind_ip_and_max_endpoints(bind_ip: IpAddr, max_endpoints: usize) -> Self {
        Self::build(bind_ip, max_endpoints, None)
    }

    /// Create a backend that allocates media ports from a deterministic `[port_min, port_max]` range
    /// on `bind_ip`, instead of OS-ephemeral `:0` ports. The range is firewallable (rtpengine
    /// `port-min`/`port-max` parity) and — because a specific port can be re-bound via
    /// [`alloc_specific`](Self::alloc_specific) — is the datapath prerequisite for HA takeover: a
    /// standby behind a floating IP re-binds the exact port a failed primary advertised, so media
    /// survives without a SIP re-INVITE. Unbounded endpoint pool (the range itself bounds ports).
    #[must_use]
    pub fn with_port_range(bind_ip: IpAddr, port_min: u16, port_max: u16) -> Self {
        Self::build(bind_ip, usize::MAX, Some((port_min, port_max)))
    }

    /// Set the DSCP (RFC 2474) applied to every media socket this backend binds — the QoS marking
    /// the network polices voice on. Defaults to [`Dscp::DEFAULT`] (EF, RFC 3246 / RFC 4594 §4.1
    /// Telephony); [`Dscp::BE`] disables marking, leaving the TOS byte untouched.
    ///
    /// Applies to sockets bound *after* this call, which for the daemon is all of them — it is
    /// configured before the first `alloc_endpoint`.
    #[must_use]
    pub fn with_dscp(self, dscp: Dscp) -> Self {
        self.inner.dscp.store(dscp.value(), Ordering::Relaxed);
        self
    }

    /// The DSCP currently applied to newly bound media sockets.
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        // The field only ever holds a value taken from a `Dscp`, so it is always in range.
        Dscp::new(self.inner.dscp.load(Ordering::Relaxed)).unwrap_or(Dscp::BE)
    }

    fn build(bind_ip: IpAddr, max_endpoints: usize, port_range: Option<(u16, u16)>) -> Self {
        let (redirect_tx, redirect_rx) = flume::unbounded();
        let (observe_tx, observe_rx) = flume::bounded(256);
        Self {
            inner: Arc::new(Inner {
                next_id: AtomicU64::new(0),
                clock: AtomicU64::new(FIRST_TICK),
                live: AtomicUsize::new(0),
                max_endpoints,
                bind_ip,
                dscp: AtomicU8::new(Dscp::DEFAULT.value()),
                ports: port_range.map(|(min, max)| PortAllocator::new(min, max)),
                endpoints: DashMap::new(),
                flows: DashMap::new(),
                latched: DashMap::new(),
                ice: DashMap::new(),
                ice_nominated: DashMap::new(),
                turn_relay: DashMap::new(),
                turn_relay_count: AtomicUsize::new(0),
                ice_events: DashMap::new(),
                ice_forward_only: DashMap::new(),
                ice_validated: DashMap::new(),
                redirect_tx,
                redirect_rx,
                observe_enabled: AtomicBool::new(false),
                observe_tx,
                observe_rx,
            }),
        }
    }

    /// Advance the logical clock by `ticks`. The media-timeout sweep compares endpoint activity
    /// against this clock; production advances it ~once per second, while tests advance it
    /// explicitly so timeout behaviour is deterministic (never `Instant::now()`).
    pub fn advance_clock(&self, ticks: u64) {
        self.inner.clock.fetch_add(ticks, Ordering::Relaxed);
    }

    /// Resolve the local IP to bind for a requested address family.
    ///
    /// The configured `bind_ip` is used when it already is of that family. When it is not, there
    /// are two cases and they must not be confused:
    ///
    /// - `bind_ip` is itself loopback. This is the NIC-free test posture, where every peer is on
    ///   this host too, so the loopback of the requested family (`127.0.0.1` / `::1`) is reachable
    ///   by them and is used.
    /// - `bind_ip` is anything else, a routable or wildcard address. The backend then has no
    ///   address in the requested family, and the leg is refused with
    ///   [`DatapathError::NoAddressForFamily`]. Loopback is not a substitute here: the bound
    ///   address is what the rewritten SDP advertises in `c=` (RFC 4566 §5.7), and a remote peer
    ///   told to send to `::1` sends to itself. That call connects and carries nothing, with
    ///   every counter at zero, which is worse than a call that is refused.
    ///
    /// A relay that has to serve both families is given an address in each through named
    /// interfaces, which bind by exact address and never come through here.
    fn bind_ip_for(&self, family: AddressFamily) -> Result<IpAddr, DatapathError> {
        match (self.inner.bind_ip, family) {
            (addr @ IpAddr::V4(_), AddressFamily::V4) => Ok(addr),
            (addr @ IpAddr::V6(_), AddressFamily::V6) => Ok(addr),
            (configured, AddressFamily::V4) if configured.is_loopback() => {
                Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
            }
            (configured, AddressFamily::V6) if configured.is_loopback() => {
                Ok(IpAddr::V6(Ipv6Addr::LOCALHOST))
            }
            (_, family) => Err(DatapathError::NoAddressForFamily { family }),
        }
    }

    /// Allocate and bind a media endpoint on `bind_ip`, starting its receive loop. Shared by
    /// [`alloc_endpoint`](Datapath::alloc_endpoint) (the configured/default family) and
    /// [`alloc_endpoint_for`](Datapath::alloc_endpoint_for) (a requested family).
    async fn alloc_on(&self, bind_ip: IpAddr) -> Result<Endpoint, DatapathError> {
        // Reserve a pool slot up front so a concurrent burst cannot overshoot the cap (port/FD
        // exhaustion guard — docs/security-and-nat.md §5). Release the reservation on any failure.
        let reserved = self.inner.live.fetch_add(1, Ordering::AcqRel) + 1;
        if reserved > self.inner.max_endpoints {
            self.inner.live.fetch_sub(1, Ordering::AcqRel);
            return Err(DatapathError::PoolExhausted {
                limit: self.inner.max_endpoints,
            });
        }
        // Bind from the configured port range, or an OS-ephemeral `:0` port when no range is set.
        let dscp = self.dscp();
        let bound = match &self.inner.ports {
            Some(pool) => Self::bind_in_range(bind_ip, pool, dscp).await,
            None => Self::bind_ephemeral(bind_ip, 0, dscp).await,
        };
        let (socket, local_addr) = match bound {
            Ok(pair) => pair,
            Err(error) => {
                self.inner.live.fetch_sub(1, Ordering::AcqRel);
                return Err(error);
            }
        };
        Ok(self.register_socket(socket, local_addr))
    }

    /// Allocate an endpoint bound to a **specific** port — the HA-restore primitive: a standby
    /// behind a floating IP re-binds the exact port a failed primary advertised, so media survives
    /// without a SIP re-INVITE. With a port range configured the port must lie within it and be
    /// free (else [`DatapathError::PortUnavailable`]); with no range, any bindable port is accepted.
    /// `family` selects the bind IP the same way [`alloc_endpoint_for`](Datapath::alloc_endpoint_for)
    /// does.
    pub async fn alloc_specific(
        &self,
        family: AddressFamily,
        port: u16,
    ) -> Result<Endpoint, DatapathError> {
        self.alloc_specific_on(self.bind_ip_for(family)?, port)
            .await
    }

    /// Allocate an endpoint bound to a **specific local IP and port** — the interface-aware
    /// HA-restore primitive. Like [`alloc_specific`](Self::alloc_specific) but the caller supplies the
    /// exact bind IP (the snapshot's recorded `local_addr.ip()`) rather than selecting it by family, so
    /// a call pinned to a named interface resumes on the same source IP.
    pub async fn alloc_specific_on(
        &self,
        bind_ip: IpAddr,
        port: u16,
    ) -> Result<Endpoint, DatapathError> {
        let reserved = self.inner.live.fetch_add(1, Ordering::AcqRel) + 1;
        if reserved > self.inner.max_endpoints {
            self.inner.live.fetch_sub(1, Ordering::AcqRel);
            return Err(DatapathError::PoolExhausted {
                limit: self.inner.max_endpoints,
            });
        }
        // Reserve the exact port in the range (so a concurrent alloc can't take it) before binding.
        if let Some(pool) = &self.inner.ports {
            if !pool.reserve_exact(port) {
                self.inner.live.fetch_sub(1, Ordering::AcqRel);
                return Err(DatapathError::PortUnavailable { port });
            }
        }
        match Self::bind_ephemeral(bind_ip, port, self.dscp()).await {
            Ok((socket, local_addr)) => Ok(self.register_socket(socket, local_addr)),
            Err(error) => {
                if let Some(pool) = &self.inner.ports {
                    pool.release(port);
                }
                self.inner.live.fetch_sub(1, Ordering::AcqRel);
                Err(error)
            }
        }
    }

    /// Bind a UDP socket on `bind_ip:port` (`port == 0` asks the OS for an ephemeral port), apply
    /// the media DSCP marking, and read back its local address.
    async fn bind_ephemeral(
        bind_ip: IpAddr,
        port: u16,
        dscp: Dscp,
    ) -> Result<(UdpSocket, SocketAddr), DatapathError> {
        let socket = UdpSocket::bind((bind_ip, port))
            .await
            .map_err(DatapathError::Bind)?;
        let local_addr = socket.local_addr().map_err(DatapathError::Bind)?;
        apply_dscp(&socket, local_addr, dscp);
        Ok((socket, local_addr))
    }

    /// Bind an endpoint on the next free port in the configured range. Tries each reservable port
    /// once; a port reservable in our range but held by another process on the host is released and
    /// skipped. `PoolExhausted` when the whole range is taken.
    ///
    /// **Only `EADDRINUSE` is retried.** It is the one failure that is a property of the *port*
    /// rather than of the bind, so another port can still succeed. Every other errno fails for the
    /// whole range — `EMFILE`/`ENFILE` (no descriptors left), `EADDRNOTAVAIL` (the bind address is
    /// not assigned to this host), `ENOBUFS`, `EACCES` — so retrying spends up to `span()` syscalls
    /// to reach the same answer and, worse, reports it as `PoolExhausted`, which names a cause the
    /// operator can act on and is not the real one. The descriptor case is the one that bites: a
    /// container's default 1024 soft limit caps a relay node at roughly 253 calls, and an operator
    /// told the port pool is exhausted widens a range that was never full.
    async fn bind_in_range(
        bind_ip: IpAddr,
        pool: &PortAllocator,
        dscp: Dscp,
    ) -> Result<(UdpSocket, SocketAddr), DatapathError> {
        for _ in 0..pool.span() {
            let Some(port) = pool.reserve_next() else {
                return Err(DatapathError::PoolExhausted { limit: pool.span() });
            };
            match Self::bind_ephemeral(bind_ip, port, dscp).await {
                Ok(bound) => return Ok(bound),
                Err(error) => {
                    pool.release(port);
                    if !is_port_in_use(&error) {
                        return Err(error);
                    }
                }
            }
        }
        Err(DatapathError::PoolExhausted { limit: pool.span() })
    }

    /// Register a freshly bound socket: assign an id, start its receive loop, and record it.
    fn register_socket(&self, socket: UdpSocket, local_addr: SocketAddr) -> Endpoint {
        let socket = Arc::new(socket);
        let id = EndpointId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let stats = Arc::new(StatsAtomic::default());
        let task = tokio::spawn(recv_loop(
            Arc::downgrade(&self.inner),
            id,
            socket.clone(),
            stats.clone(),
        ));
        self.inner.endpoints.insert(
            id,
            EndpointEntry {
                socket,
                stats,
                task,
            },
        );
        Endpoint { id, local_addr }
    }
}

/// Whether a bind failure means "this port is taken" rather than "this bind cannot work".
///
/// `EADDRINUSE` is the only errno for which the next port in the range is worth trying: the port is
/// held by another process on the host (or another instance sharing the range), and nothing about
/// the address, the process's descriptors or its permissions is wrong. See `bind_in_range`.
fn is_port_in_use(error: &DatapathError) -> bool {
    matches!(error, DatapathError::Bind(io) if io.kind() == std::io::ErrorKind::AddrInUse)
}

/// Mark a bound media socket with `dscp` (RFC 2474) so the network can police it as voice.
///
/// The wire field is the IPv4 TOS byte / IPv6 Traffic Class octet, written as `DSCP << 2` with the
/// ECN bits (RFC 3168) left clear — see [`Dscp::to_tos_byte`]. [`Dscp::BE`] is "do not mark": the
/// option is not set at all, so an operator marking upstream (tc, a CNI plugin) is not overwritten
/// with an explicit zero.
///
/// A socket is marked for the family it is bound to. A dual-stack `::` socket also gets `IP_TOS`,
/// because a datagram sent to a v4-mapped destination leaves through the IPv4 output path and takes
/// the IPv4 option; that call is best-effort (some kernels refuse `IPPROTO_IP` options on an
/// `AF_INET6` socket) and its failure is not itself worth a warning.
///
/// **Failure is never fatal.** A sandbox that forbids the option must not take the call down — QoS
/// marking is advisory, so this logs and carries on rather than failing the bind.
fn apply_dscp(socket: &UdpSocket, local_addr: SocketAddr, dscp: Dscp) {
    if !dscp.is_marked() {
        return;
    }
    let tos = u32::from(dscp.to_tos_byte());
    let socket = socket2::SockRef::from(socket);
    let outcome = match local_addr {
        SocketAddr::V4(_) => socket.set_tos_v4(tos),
        SocketAddr::V6(_) => {
            let result = socket.set_tclass_v6(tos);
            // Dual-stack: v4-mapped destinations egress via IPv4 and read IP_TOS, not IPV6_TCLASS.
            let _ = socket.set_tos_v4(tos);
            result
        }
    };
    if let Err(error) = outcome {
        tracing::warn!(
            target: "datapath",
            %local_addr,
            %dscp,
            tos,
            %error,
            "could not set the media DSCP marking on the endpoint socket; media flows unmarked"
        );
    }
}

/// RFC 7983 first-byte demux on a media socket: only RTP/RTCP ([`PacketClass::Media`], 128–191) may
/// drive the relay or move the latch. STUN/DTLS/TURN/garbage are dropped in M-S1 (ICE/DTLS land in
/// M-S3/M-S4). See `docs/security-and-nat.md` §4 layer 1.
fn is_rtp_or_rtcp(payload: &[u8]) -> bool {
    classify(payload) == PacketClass::Media
}

/// Whether `payload` is specifically RTCP: in the RTP/RTCP demux range with an RTCP payload type —
/// the second byte's 7-bit field in 64..=95 (RFC 5761 §4).
fn is_rtcp(payload: &[u8]) -> bool {
    is_rtp_or_rtcp(payload)
        && matches!(payload.get(1), Some(&byte1) if (64..=95).contains(&(byte1 & 0x7F)))
}

/// Answer a STUN connectivity check on an ICE-enabled endpoint: validate the request against our
/// local credentials, adopt the validated source as the media path, and reply with a Binding
/// success response (RFC 8445 §7.3 / RFC 5389). Invalid checks are dropped silently.
async fn handle_stun(
    socket: &UdpSocket,
    endpoint: EndpointId,
    source: SocketAddr,
    datagram: &[u8],
    ice: &IceConfig,
    inner: &Inner,
    stats: &StatsAtomic,
) {
    // The USERNAME must address us (our ufrag first) and MESSAGE-INTEGRITY must verify with our
    // local password — a challenge an off-path attacker cannot forge without the SDP it never saw.
    // Shared with the XDP backend so the two datapaths cannot drift on what authenticates a check.
    let (response, nomination) = match crate::respond_to_stun_check(datagram, ice, source) {
        crate::StunCheckOutcome::Respond {
            response,
            nomination,
        } => (response, nomination),
        crate::StunCheckOutcome::Drop => {
            stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    // Valid check: answered (RFC 8445 §7.3), but a lite agent selects a pair only on a USE-CANDIDATE
    // check (§7.3.1.5 / §6.1.3.2), and among several nominations the highest PRIORITY wins (§8.1.1) —
    // so a browser checking from every interface moves the path only for the pair it nominates, and a
    // lower-priority later nomination never moves an established one.
    if let Some(priority) = nomination {
        let selects = match inner.ice_nominated.entry(endpoint) {
            dashmap::mapref::entry::Entry::Occupied(mut selected) => {
                let supersedes = crate::nomination_supersedes(Some(*selected.get()), priority);
                if supersedes {
                    selected.insert(priority);
                }
                supersedes
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(priority);
                true
            }
        };
        if selects {
            inner
                .latched
                .insert(endpoint, SourceLatch { source, ssrc: None });
            inner.publish_ice_validated(endpoint);
        }
    }
    // The check also counts as activity so the media-timeout sweep treats the path as alive.
    stats
        .last_seen
        .store(inner.clock.load(Ordering::Relaxed), Ordering::Relaxed);
    // The answer to a check that arrived through the allocation goes back through it.
    let egress = match inner.turn_relay.get(&endpoint) {
        Some(relay) => relay_egress(&relay, source, &response),
        None => RelayEgress::Direct,
    };
    match emit(socket, egress, source, &response).await {
        Ok(sent) => {
            stats.packets_out.fetch_add(1, Ordering::Relaxed);
            stats.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
        }
        Err(error) => {
            tracing::debug!(?endpoint, %error, "failed to send STUN response");
        }
    }
}

impl Inner {
    /// Everything a datagram that arrived on `endpoint` goes through after the socket read: the
    /// RFC 8656 de-encapsulation of anything the TURN server relayed, the full-agent STUN seam,
    /// the ICE-lite responder, and the installed flow. Shared by the UDP receive loop and by
    /// [`Datapath::ingest_relayed`], so a datagram that reached us over a TURN stream passes the
    /// same ICE gate, source gate, latch, stats and flows as one that arrived on the socket.
    async fn receive(
        &self,
        endpoint: EndpointId,
        socket: &UdpSocket,
        stats: &StatsAtomic,
        source: SocketAddr,
        buffer: &mut [u8],
        len: usize,
    ) {
        // RFC 5766 §11 de-encapsulation, **before every other layer**. On a leg relaying through a
        // TURN allocation the peer's traffic arrives from the TURN server wrapped in ChannelData, so
        // unwrapping here — and rewriting the source back to the peer the channel belongs to — is
        // what lets the ICE responder, the source gate, the latch and the relay all keep working in
        // terms of the peer's own address, with no idea a relay is in the path.
        //
        // Scoped to datagrams actually from the allocation's server: ChannelData-shaped bytes from
        // anywhere else are left alone, so this can never be used to spoof a peer address.
        let ingress = {
            let relay = self.turn_relay.get(&endpoint);
            relay_unwrap(relay.as_deref(), source, &buffer[..len])
        };
        let (payload_range, source) = match ingress {
            RelayIngress::Direct => (0..len, source),
            RelayIngress::Unwrapped { range, peer } => (range, peer),
            RelayIngress::Indication { payload, peer } => {
                // The DATA is smaller than the datagram it arrived in, so it fits the buffer.
                buffer[..payload.len()].copy_from_slice(&payload);
                (0..payload.len(), peer)
            }
            RelayIngress::Drop => {
                stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        // Shadow the raw datagram with the de-encapsulated view; everything below is unchanged.
        let len = {
            let start = payload_range.start;
            let end = payload_range.end;
            if start > 0 {
                buffer.copy_within(start..end, 0);
            }
            end - start
        };

        // RFC 7983 demux for ICE: STUN (first byte 0..=3) drives connectivity checks on endpoints
        // that carry ICE credentials.
        if classify(&buffer[..len]) == PacketClass::Stun {
            // Full-agent seam (RFC 7675 consent): forward the raw STUN to the engine's checker so it
            // can correlate its own Binding responses — which the responder below otherwise drops.
            // Bounded sink, drop-on-full; forwarded for requests too (the checker ignores those).
            if let Some(sender) = self.ice_events.get(&endpoint).map(|entry| entry.clone()) {
                let _ = sender.try_send(IceDatapathEvent {
                    endpoint,
                    source,
                    arrival_tick: self.clock.load(Ordering::Relaxed),
                    datagram: Bytes::copy_from_slice(&buffer[..len]),
                });
            }
            // A full-agent endpoint answers nothing here: the engine's RFC 8445 agent owns request
            // handling (it needs the role, the checklist, and the nomination state to answer
            // correctly) and is the only thing that may adopt a source. Forwarding above already
            // handed it the datagram; stop, so the responder cannot also answer and latch behind the
            // agent's back.
            if self.ice_forward_only.contains_key(&endpoint) {
                return;
            }
            if let Some(ice) = self.ice.get(&endpoint).map(|config| config.clone()) {
                handle_stun(socket, endpoint, source, &buffer[..len], &ice, self, stats).await;
                return;
            }
            // No ICE credentials: do *not* drop here — fall through to the installed flow. A TURN
            // relay endpoint (`FlowAction::Redirect`, docs/security-and-nat.md §11) must hand
            // whatever the peer sends — including STUN-shaped bytes — to the allocation actor. A
            // media `Forward` endpoint still drops non-RTP inside `dispatch` (the layer-1 demux), so
            // this never lets STUN reach the media latch.
        }
        self.dispatch(endpoint, source, &buffer[..len], stats).await;
    }
}

/// Per-endpoint receive loop: drain the socket and apply the installed flow (which gates the source
/// and latches it per policy — see [`Inner::dispatch`]).
async fn recv_loop(
    inner: Weak<Inner>,
    endpoint: EndpointId,
    socket: Arc<UdpSocket>,
    stats: Arc<StatsAtomic>,
) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, source) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(?endpoint, %error, "endpoint receive loop ending");
                return;
            }
        };
        stats.packets_in.fetch_add(1, Ordering::Relaxed);
        stats.bytes_in.fetch_add(len as u64, Ordering::Relaxed);

        let Some(inner) = inner.upgrade() else {
            return;
        };

        inner
            .receive(endpoint, &socket, &stats, source, &mut buffer, len)
            .await;
    }
}

impl Datapath for UdpLoopbackDatapath {
    async fn alloc_endpoint(&self) -> Result<Endpoint, DatapathError> {
        self.alloc_on(self.inner.bind_ip).await
    }

    async fn alloc_endpoint_for(&self, family: AddressFamily) -> Result<Endpoint, DatapathError> {
        self.alloc_on(self.bind_ip_for(family)?).await
    }

    async fn alloc_endpoint_on_port(
        &self,
        family: AddressFamily,
        port: u16,
    ) -> Result<Endpoint, DatapathError> {
        self.alloc_specific(family, port).await
    }

    async fn alloc_endpoint_on(&self, bind_ip: IpAddr) -> Result<Endpoint, DatapathError> {
        self.alloc_on(bind_ip).await
    }

    async fn alloc_endpoint_on_port_at(
        &self,
        bind_ip: IpAddr,
        port: u16,
    ) -> Result<Endpoint, DatapathError> {
        self.alloc_specific_on(bind_ip, port).await
    }

    fn install_flow(&self, endpoint: EndpointId, action: FlowAction) -> Result<(), DatapathError> {
        if !self.inner.endpoints.contains_key(&endpoint) {
            return Err(DatapathError::UnknownEndpoint(endpoint));
        }
        let previous = self.inner.flows.insert(endpoint, action);
        if let FlowAction::Forward(rule) = action {
            self.inner.forget_stale_latches(endpoint, previous, &rule);
        }
        Ok(())
    }

    fn remove_flow(&self, endpoint: EndpointId) {
        self.inner.flows.remove(&endpoint);
    }

    async fn remove_endpoint(&self, endpoint: EndpointId) {
        if let Some((_, entry)) = self.inner.endpoints.remove(&endpoint) {
            // Release the range port back to the pool (if a range is configured), reading the bound
            // port off the socket before it is dropped, so the port can be re-allocated.
            if let Some(pool) = &self.inner.ports {
                if let Ok(local) = entry.socket.local_addr() {
                    pool.release(local.port());
                }
            }
            // Stop the receive task and wait for it to drop its socket clone, then drop ours, so the
            // OS socket is fully closed before we return. A range port is then immediately
            // re-bindable — needed for a same-port HA restore and for tight port-churn.
            let EndpointEntry { socket, task, .. } = entry;
            task.abort();
            let _ = task.await;
            drop(socket);
            // Release the pool slot only when an endpoint was actually removed (idempotent).
            self.inner.live.fetch_sub(1, Ordering::AcqRel);
        }
        self.inner.flows.remove(&endpoint);
        self.inner.latched.remove(&endpoint);
        self.inner.ice.remove(&endpoint);
        self.inner.ice_nominated.remove(&endpoint);
        self.inner.ice_events.remove(&endpoint);
        self.inner.ice_validated.remove(&endpoint);
        if self.inner.turn_relay.remove(&endpoint).is_some() {
            self.inner.turn_relay_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn send(
        &self,
        endpoint: EndpointId,
        dst: SocketAddr,
        data: &[u8],
    ) -> Result<usize, DatapathError> {
        let (socket, stats) = match self.inner.endpoints.get(&endpoint) {
            Some(entry) => (entry.socket.clone(), entry.stats.clone()),
            None => return Err(DatapathError::UnknownEndpoint(endpoint)),
        };
        // RFC 5766 §11: on a leg relaying through a TURN allocation, traffic to a **bound** peer is
        // wrapped in ChannelData and addressed to the server — the peer is not reachable from here
        // directly, that is the whole reason the allocation exists. A destination with no channel
        // (the server itself, or a peer we reach over a host/srflx candidate) is sent untouched.
        let egress = match self.inner.turn_relay.get(&endpoint) {
            Some(relay) => relay_egress(&relay, dst, data),
            None => RelayEgress::Direct,
        };
        let sent = emit(&socket, egress, dst, data)
            .await
            .map_err(DatapathError::Send)?;
        stats.packets_out.fetch_add(1, Ordering::Relaxed);
        stats.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
        Ok(sent)
    }

    fn stats(&self, endpoint: EndpointId) -> Option<EndpointStats> {
        self.inner
            .endpoints
            .get(&endpoint)
            .map(|e| e.stats.snapshot())
    }

    fn now_ticks(&self) -> u64 {
        self.inner.clock.load(Ordering::Relaxed)
    }

    /// The loopback backend's clock is purely logical, so the media-timeout sweep drives it through
    /// the trait. Delegates to the inherent [`Self::advance_clock`] (which concrete call sites still
    /// resolve to directly, inherent-over-trait), keeping the advance logic in one place.
    fn advance_clock(&self, ticks: u64) {
        UdpLoopbackDatapath::advance_clock(self, ticks);
    }

    fn last_activity(&self, endpoint: EndpointId) -> Option<u64> {
        self.inner
            .endpoints
            .get(&endpoint)
            .map(|entry| entry.stats.last_seen.load(Ordering::Relaxed))
    }

    fn note_dropped(&self, endpoint: EndpointId) {
        if let Some(entry) = self.inner.endpoints.get(&endpoint) {
            entry.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn note_activity(&self, endpoint: EndpointId) {
        if let Some(entry) = self.inner.endpoints.get(&endpoint) {
            entry
                .stats
                .last_seen
                .store(self.inner.clock.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }

    async fn ingest_relayed(&self, endpoint: EndpointId, frame: &[u8]) -> bool {
        // Only the allocation's own stream may deliver here, and only relayed message shapes.
        let Some(first) = frame.first().copied() else {
            return false;
        };
        if !(siphon_rtp_stun::turn::is_channel_data(first) || is_data_indication(frame)) {
            return false;
        }
        let Some(server) = self
            .inner
            .turn_relay
            .get(&endpoint)
            .map(|relay| relay.server)
        else {
            return false;
        };
        let (socket, stats) = match self.inner.endpoints.get(&endpoint) {
            Some(entry) => (entry.socket.clone(), entry.stats.clone()),
            None => return false,
        };
        stats.packets_in.fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_in
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        let mut buffer = frame.to_vec();
        self.inner
            .receive(endpoint, &socket, &stats, server, &mut buffer, frame.len())
            .await;
        true
    }

    fn set_turn_relay(&self, endpoint: EndpointId, relay: Option<crate::TurnRelay>) {
        match relay {
            Some(relay) => {
                if self.inner.turn_relay.insert(endpoint, relay).is_none() {
                    self.inner.turn_relay_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                if self.inner.turn_relay.remove(&endpoint).is_some() {
                    self.inner.turn_relay_count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn turn_relay(&self, endpoint: EndpointId) -> Option<crate::TurnRelay> {
        self.inner
            .turn_relay
            .get(&endpoint)
            .map(|relay| relay.value().clone())
    }

    fn supports_turn_relay(&self) -> bool {
        true
    }

    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>) {
        match config {
            Some(config) => {
                // RFC 8445 §9.1.1.1: new credentials are a new ICE session, so a pair nominated in
                // the old one no longer orders (or blocks) the new session's nominations. The
                // latch itself stays: media continues on the old pair until the new session
                // nominates one (§9.3).
                let restarted = self
                    .inner
                    .ice
                    .get(&endpoint)
                    .is_some_and(|previous| previous.local_ufrag != config.local_ufrag);
                if restarted {
                    self.inner.ice_nominated.remove(&endpoint);
                }
                self.inner.ice.insert(endpoint, config);
            }
            None => {
                self.inner.ice.remove(&endpoint);
                self.inner.ice_nominated.remove(&endpoint);
                self.inner.ice_events.remove(&endpoint);
                self.inner.ice_forward_only.remove(&endpoint);
                self.inner.ice_validated.remove(&endpoint);
            }
        }
    }

    fn set_ice_agent(
        &self,
        endpoint: EndpointId,
        config: IceConfig,
        mode: IceAgentMode,
        events: flume::Sender<IceDatapathEvent>,
    ) {
        // The credentials stay installed either way: they arm the layer-4 media gate, which forwards
        // media only from the adopted source. What `mode` decides is who answers checks (and so who
        // may adopt) — the datapath's ice-lite responder, or the engine's full agent.
        self.inner.ice.insert(endpoint, config);
        self.inner.ice_events.insert(endpoint, events);
        match mode {
            IceAgentMode::RespondAndForward => {
                self.inner.ice_forward_only.remove(&endpoint);
            }
            IceAgentMode::ForwardOnly => {
                self.inner.ice_forward_only.insert(endpoint, ());
            }
        }
    }

    fn adopt_source(&self, endpoint: EndpointId, source: SocketAddr) {
        // Same write the responder performs on a nominating check — relocated to the agent, which on a
        // full-agent endpoint is the only thing entitled to make it.
        self.inner
            .latched
            .insert(endpoint, SourceLatch { source, ssrc: None });
        self.inner.publish_ice_validated(endpoint);
    }

    fn latched_source(&self, endpoint: EndpointId) -> Option<SocketAddr> {
        self.inner.latched.get(&endpoint).map(|latch| latch.source)
    }

    fn latched_ssrc(&self, endpoint: EndpointId) -> Option<u32> {
        self.inner
            .latched
            .get(&endpoint)
            .and_then(|latch| latch.ssrc)
    }

    fn ice_validated_source(&self, endpoint: EndpointId) -> Option<SocketAddr> {
        // Only an ICE endpoint has a *validated* source. On one, `handle_stun` is the sole writer of
        // `latched` — media never creates or moves it (`Inner::dispatch`, layer 4) — so the latch is
        // exactly the check-validated path. On a non-ICE endpoint the same map holds a media latch
        // that no connectivity check ever authenticated; reporting that as validated would let a
        // consent check (and, later, the full agent) treat an unauthenticated source as a selected
        // pair. Gate on the credentials, not on the latch alone.
        if !self.inner.ice.contains_key(&endpoint) {
            return None;
        }
        self.inner.latched.get(&endpoint).map(|latch| latch.source)
    }

    fn watch_ice_validated(
        &self,
        endpoint: EndpointId,
    ) -> Option<tokio::sync::watch::Receiver<Option<SocketAddr>>> {
        // The same credential test as `ice_validated_source`: on a non-ICE endpoint `latched` is a media
        // latch no check authenticated, and nothing gates that endpoint on a check anyway.
        if !self.inner.ice.contains_key(&endpoint) {
            return None;
        }
        let subscription = self
            .inner
            .ice_validated
            .entry(endpoint)
            .or_insert_with(|| tokio::sync::watch::Sender::new(None))
            .subscribe();
        // Catch up with a check validated before this endpoint had a publisher.
        self.inner.publish_ice_validated(endpoint);
        Some(subscription)
    }

    fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp> {
        self.inner.observe_enabled.store(true, Ordering::Relaxed);
        self.inner.observe_rx.clone()
    }

    fn rtcp_tap(&self) -> Option<flume::Sender<ObservedRtcp>> {
        self.inner
            .observe_enabled
            .load(Ordering::Relaxed)
            .then(|| self.inner.observe_tx.clone())
    }

    /// A clone of the shared Redirect stream; all redirected endpoints feed this one MPMC receiver.
    fn rx(&self) -> flume::Receiver<RxPacket> {
        self.inner.redirect_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    // The responder itself now lives in the parent module (shared with the XDP backend), so the STUN
    // codec is only needed here, to build the checks these tests feed it.
    use siphon_rtp_stun as stun;

    use super::*;
    use crate::{ForwardRule, IceConfig, SourceFilter};
    use std::time::Duration;
    use tokio::time::timeout;

    const SHORT: Duration = Duration::from_secs(1);
    const NEGATIVE: Duration = Duration::from_millis(150);

    /// A test "phone": a loopback UDP socket standing in for a SIP endpoint.
    async fn phone() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind phone");
        let addr = socket.local_addr().expect("phone addr");
        (socket, addr)
    }

    /// Read back the kernel's actual TOS byte for an endpoint this backend bound — proof the
    /// marking reached the socket, not just our own copy of the setting.
    fn readback_tos(datapath: &UdpLoopbackDatapath, endpoint: EndpointId) -> u32 {
        let entry = datapath
            .inner
            .endpoints
            .get(&endpoint)
            .expect("endpoint is registered");
        socket2::SockRef::from(entry.socket.as_ref())
            .tos_v4()
            .expect("getsockopt(IP_TOS)")
    }

    #[tokio::test]
    async fn media_sockets_are_marked_expedited_forwarding_by_default() {
        let datapath = UdpLoopbackDatapath::new();
        assert_eq!(datapath.dscp(), Dscp::EF);
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        // DSCP 46 << 2 == 184, the same TOS byte Asterisk writes for `tos_audio=ef`.
        assert_eq!(readback_tos(&datapath, endpoint.id), 184);
    }

    #[tokio::test]
    async fn with_dscp_overrides_the_default_marking() {
        let datapath = UdpLoopbackDatapath::new().with_dscp(Dscp::CS3);
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        assert_eq!(readback_tos(&datapath, endpoint.id), 96);
    }

    #[tokio::test]
    async fn best_effort_leaves_the_tos_byte_untouched() {
        // BE means "do not mark" — the option is never set, so the socket keeps the kernel default
        // (0) rather than being explicitly overwritten. An operator marking upstream survives.
        let datapath = UdpLoopbackDatapath::new().with_dscp(Dscp::BE);
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        assert_eq!(readback_tos(&datapath, endpoint.id), 0);
    }

    #[tokio::test]
    async fn a_port_range_endpoint_is_marked_too() {
        // The HA/firewallable bind path is a different branch from the ephemeral one; both mark.
        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 41000, 41010);
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        assert_eq!(readback_tos(&datapath, endpoint.id), 184);
    }

    #[tokio::test]
    async fn a_restored_specific_port_endpoint_is_marked_too() {
        // `alloc_specific` is the HA-takeover bind; a standby's media must not lose its marking.
        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 41100, 41110);
        let endpoint = datapath
            .alloc_specific(AddressFamily::V4, 41105)
            .await
            .expect("alloc specific");
        assert_eq!(endpoint.local_addr.port(), 41105);
        assert_eq!(readback_tos(&datapath, endpoint.id), 184);
    }

    #[tokio::test]
    async fn an_ipv6_endpoint_is_marked_via_the_traffic_class_octet() {
        let datapath = UdpLoopbackDatapath::with_bind_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let endpoint = datapath
            .alloc_endpoint_for(AddressFamily::V6)
            .await
            .expect("alloc v6");
        let entry = datapath
            .inner
            .endpoints
            .get(&endpoint.id)
            .expect("endpoint is registered");
        let tclass = socket2::SockRef::from(entry.socket.as_ref())
            .tclass_v6()
            .expect("getsockopt(IPV6_TCLASS)");
        assert_eq!(tclass, 184);
    }

    #[tokio::test]
    async fn marking_does_not_disturb_the_relay_path() {
        // The marking is a socket option, not a packet rewrite: a marked endpoint still relays
        // byte-for-byte. Guards against a future "mark by rewriting the datagram" regression.
        let datapath = UdpLoopbackDatapath::new();
        let left = datapath.alloc_endpoint().await.expect("alloc left");
        let right = datapath.alloc_endpoint().await.expect("alloc right");
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        datapath
            .install_flow(
                left.id,
                FlowAction::Forward(ForwardRule::signalled(right.id, Some(addr_b), addr_a.ip())),
            )
            .expect("install flow");
        let packet = [0x80u8, 0x00, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4];
        phone_a
            .send_to(&packet, left.local_addr)
            .await
            .expect("send");
        let (received, _from) = recv(&phone_b).await;
        assert_eq!(received, packet);
    }

    async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0u8; MAX_DATAGRAM];
        let (len, from) = timeout(SHORT, socket.recv_from(&mut buffer))
            .await
            .expect("recv did not time out")
            .expect("recv ok");
        (buffer[..len].to_vec(), from)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relays_in_both_directions() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: Some(addr_b),
                    accepted_source: SourceFilter::Any,
                    latch: LatchPolicy::Off,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow a");
        datapath
            .install_flow(
                leg_b.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_a.id,
                    out_dst: Some(addr_a),
                    accepted_source: SourceFilter::Any,
                    latch: LatchPolicy::Off,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow b");

        // A -> engine(leg_a) -> phone_b, leaving from the engine's B-facing port.
        phone_a
            .send_to(&rtp(0x0A0A_0A0A, 1), leg_a.local_addr)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A, 1));
        assert_eq!(from, leg_b.local_addr);

        // B -> engine(leg_b) -> phone_a, leaving from the engine's A-facing port.
        phone_b
            .send_to(&rtp(0x0B0B_0B0B, 1), leg_b.local_addr)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, rtp(0x0B0B_0B0B, 1));
        assert_eq!(from, leg_a.local_addr);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn latching_resolves_unknown_destination() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // Toward B we know the address; toward A we do not yet — only latching can resolve it.
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(addr_b))),
            )
            .expect("flow a");
        datapath
            .install_flow(
                leg_b.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_a.id, None)),
            )
            .expect("flow b");

        // Before A has spoken, B->A has no destination and must be dropped (not delivered).
        phone_b
            .send_to(&rtp(0x0B0B_0B0B, 1), leg_b.local_addr)
            .await
            .expect("send early");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, phone_a.recv_from(&mut scratch))
                .await
                .is_err(),
            "B->A must not be delivered before A is latched"
        );

        // A speaks: this latches leg_a's source to phone_a, and is forwarded to B.
        phone_a
            .send_to(&rtp(0x0A0A_0A0A, 1), leg_a.local_addr)
            .await
            .expect("send a");
        let (data, _) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A, 1));

        // Now B->A resolves via the latched address even though out_dst was None.
        phone_b
            .send_to(&rtp(0x0B0B_0B0B, 2), leg_b.local_addr)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, rtp(0x0B0B_0B0B, 2));
        assert_eq!(from, leg_a.local_addr);
        let _ = addr_a;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redirect_delivers_to_rx_stream() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (phone, addr) = phone().await;
        datapath
            .install_flow(leg.id, FlowAction::Redirect)
            .expect("redirect flow");
        let rx = datapath.rx();

        phone
            .send_to(b"media-frame", leg.local_addr)
            .await
            .expect("send");
        let packet = timeout(SHORT, rx.recv_async())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(packet.endpoint, leg.id);
        assert_eq!(packet.source, addr);
        assert_eq!(&packet.data[..], b"media-frame");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redirect_delivers_stun_shaped_datagram_raw_without_latching() {
        // A TURN relay endpoint (FlowAction::Redirect, no ICE creds) must hand the allocation actor
        // whatever the peer sends — including a STUN/TURN-shaped datagram (first byte in 0..=3) that
        // a media socket's layer-1 demux would drop — raw, and must never write the media latch.
        // (docs/security-and-nat.md §11.)
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (phone, addr) = phone().await;
        datapath
            .install_flow(leg.id, FlowAction::Redirect)
            .expect("redirect flow");
        let rx = datapath.rx();

        // First byte 0x00: the STUN/TURN band. On a media (Forward) port this is layer-1 dropped.
        let datagram = [0x00u8, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4];
        phone
            .send_to(&datagram, leg.local_addr)
            .await
            .expect("send");
        let packet = timeout(SHORT, rx.recv_async())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(packet.endpoint, leg.id);
        assert_eq!(packet.source, addr);
        assert_eq!(&packet.data[..], &datagram);
        // The latch is never written for a Redirect endpoint — the TURN permission model is the
        // source gate, not symmetric-RTP latching.
        assert!(
            datapath.inner.latched.get(&leg.id).is_none(),
            "a Redirect endpoint must never latch"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_redirect_endpoint_hands_up_media_only_from_a_stun_validated_source() {
        // The `Redirect` counterpart of `ice_forward_leg_forwards_media_only_from_a_stun_validated_source`.
        // A userspace-owned leg (conference seat, promoted relay, SRTP/DTLS bridge) is a `Redirect`
        // endpoint, and an ICE one must be gated by the same layer 4 the relay path enforces: media
        // reaches its consumer only from the source a connectivity check validated, never before one
        // has, and never from a different source afterwards. Without this the consumer's own
        // signalled-source gate is the only thing left — and an ICE leg deliberately runs that gate
        // open, because a peer-reflexive check legitimately arrives from a transport the SDP never
        // carried (RFC 8445 §7.3.1.3). docs/security-and-nat.md §4 layer 4; RFC 8445 §7.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        datapath
            .install_flow(leg.id, FlowAction::Redirect)
            .expect("redirect flow");
        let rx = datapath.rx();

        // Pre-check spray: an attacker's RTP arrives before any connectivity check.
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        attacker
            .send_to(&rtp(0xAAAA_AAAA, 1), leg.local_addr)
            .await
            .expect("attacker send");
        assert!(
            timeout(NEGATIVE, rx.recv_async()).await.is_err(),
            "media before any STUN validation must be dropped, not redirected to the consumer"
        );

        // A valid connectivity check from the real peer adopts its source.
        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let check = nominating_check(&[9u8; 12], NOMINATED_PRIORITY);
        peer.send_to(&check, leg.local_addr)
            .await
            .expect("send check");
        let _ = recv(&peer).await; // await the success response so the adoption has completed

        // The validated peer's media now reaches the consumer.
        peer.send_to(&rtp(0x1234_5678, 1), leg.local_addr)
            .await
            .expect("peer rtp");
        let packet = timeout(SHORT, rx.recv_async())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(packet.source, peer_addr);
        assert_eq!(&packet.data[..], rtp(0x1234_5678, 1).as_slice());

        // A different source spraying after adoption is still rejected — media never creates or
        // moves an ICE endpoint's latch.
        attacker
            .send_to(&rtp(0xBBBB_BBBB, 2), leg.local_addr)
            .await
            .expect("attacker rtp");
        assert!(
            timeout(NEGATIVE, rx.recv_async()).await.is_err(),
            "a different source after adoption must not be redirected (no media re-latch on ICE)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_redirect_endpoint_still_hands_up_non_rtp_from_the_validated_source() {
        // The layer-4 gate on the `Redirect` path is a *source* gate, not the relay path's layer-1
        // RFC 7983 demux. A DTLS-SRTP leg's handshake records (first byte 20..=63) are not RTP and
        // must still reach the DTLS bridge — the handshake keys the pair ICE chose (RFC 5764; RFC
        // 8445 §12), so dropping them would deadlock every secure ICE leg.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        datapath
            .install_flow(leg.id, FlowAction::Redirect)
            .expect("redirect flow");
        let rx = datapath.rx();

        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let check = nominating_check(&[9u8; 12], NOMINATED_PRIORITY);
        peer.send_to(&check, leg.local_addr)
            .await
            .expect("send check");
        let _ = recv(&peer).await;

        // A DTLS handshake record (content type 22, DTLS 1.2 version) from the validated source.
        let record = [0x16u8, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        peer.send_to(&record, leg.local_addr)
            .await
            .expect("peer dtls");
        let packet = timeout(SHORT, rx.recv_async())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(packet.source, peer_addr);
        assert_eq!(&packet.data[..], &record);

        // The same record from an unvalidated source is dropped: DTLS runs *over* the pair ICE chose.
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        attacker
            .send_to(&record, leg.local_addr)
            .await
            .expect("attacker dtls");
        assert!(
            timeout(NEGATIVE, rx.recv_async()).await.is_err(),
            "a DTLS record from an unvalidated source must not reach the handshake"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_action_and_stats_counters() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, _addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: Some(addr_b),
                    accepted_source: SourceFilter::Any,
                    latch: LatchPolicy::Off,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow a");
        datapath
            .install_flow(leg_b.id, FlowAction::Drop)
            .expect("drop flow");

        let forwarded = rtp(0x00C0_FFEE, 1);
        phone_a
            .send_to(&forwarded, leg_a.local_addr)
            .await
            .expect("send a");
        let _ = recv(&phone_b).await;
        // B's datagram is dropped by the Drop flow.
        phone_b
            .send_to(b"dropped", leg_b.local_addr)
            .await
            .expect("send b");

        // Poll until the dropped counter lands (the receive task runs asynchronously).
        let mut dropped = 0;
        for _ in 0..50 {
            dropped = datapath.stats(leg_b.id).expect("stats b").packets_dropped;
            if dropped >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(dropped, 1, "B's datagram should be counted as dropped");

        let stats_a = datapath.stats(leg_a.id).expect("stats a");
        assert_eq!(stats_a.packets_in, 1);
        let stats_b = datapath.stats(leg_b.id).expect("stats b");
        assert_eq!(stats_b.packets_out, 1, "one datagram forwarded out of B");
        assert_eq!(stats_b.bytes_out, forwarded.len() as u64);
    }

    // --- TURN relay seam (RFC 5766 §11) --------------------------------------------------------

    /// A stand-in TURN server socket plus the relay config pointing an endpoint at it.
    async fn turn_relay_for(peer: SocketAddr) -> (UdpSocket, crate::TurnRelay, u16) {
        let (server, server_addr) = phone().await;
        const CHANNEL: u16 = 0x4001;
        let relay = crate::TurnRelay {
            carrier: crate::TurnCarrier::Udp,
            server: server_addr,
            channels: vec![(peer, CHANNEL)],
            permitted: vec![peer],
        };
        (server, relay, CHANNEL)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relayed_egress_is_channel_wrapped_and_sent_to_the_turn_server() {
        // The peer is not reachable from this endpoint directly — that is why the allocation exists
        // — so `send` must address the server and wrap, not send to the peer.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_peer_socket, peer_addr) = phone().await;
        let (server, relay, channel) = turn_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg.id, Some(relay));

        let payload = rtp(0x0A0A_0A0A, 1);
        datapath
            .send(leg.id, peer_addr, &payload)
            .await
            .expect("send");

        let (wire, from) = recv(&server).await;
        assert_eq!(
            from.port(),
            leg.local_addr.port(),
            "sent from the leg's own socket"
        );
        let framed = siphon_rtp_stun::turn::parse_channel_data(&wire).expect("ChannelData");
        assert_eq!(framed.channel, channel);
        assert_eq!(
            framed.data,
            &payload[..],
            "the payload rides the channel intact"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarded_media_toward_a_channel_bound_peer_is_wrapped_for_the_server() {
        // The kernel-style relay path (`FlowAction::Forward`) must honour the out endpoint's
        // allocation exactly as `send` does: a peer behind the allocation is not reachable directly.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (source, _) = phone().await;
        let (_peer_socket, peer_addr) = phone().await;
        let (server, relay, channel) = turn_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_b.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(peer_addr))),
            )
            .expect("flow");

        let payload = rtp(0x1010_1010, 1);
        source
            .send_to(&payload, leg_a.local_addr)
            .await
            .expect("media in");

        let (wire, from) = recv(&server).await;
        assert_eq!(from.port(), leg_b.local_addr.port(), "from the out leg");
        let framed = siphon_rtp_stun::turn::parse_channel_data(&wire).expect("ChannelData");
        assert_eq!(framed.channel, channel);
        assert_eq!(framed.data, &payload[..]);
        let stats = datapath.stats(leg_b.id).expect("stats");
        assert_eq!(stats.packets_out, 1);
        assert_eq!(stats.bytes_out, wire.len() as u64, "counts the wire bytes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarded_media_to_a_peer_without_a_channel_still_goes_direct() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (source, _) = phone().await;
        let (bound_socket, bound_peer) = phone().await;
        let (direct, direct_addr) = phone().await;
        let (_server, relay, _) = turn_relay_for(bound_peer).await;
        drop(bound_socket);
        datapath.set_turn_relay(leg_b.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(direct_addr))),
            )
            .expect("flow");

        let payload = rtp(0x1111_1111, 1);
        source
            .send_to(&payload, leg_a.local_addr)
            .await
            .expect("media in");
        let (wire, _) = recv(&direct).await;
        assert_eq!(wire, payload, "an unbound destination is untouched");
    }

    /// A relay whose only knowledge of `peer` is a permission: no channel is bound.
    async fn permission_only_relay_for(peer: SocketAddr) -> (UdpSocket, crate::TurnRelay) {
        let (server, server_addr) = phone().await;
        let relay = crate::TurnRelay {
            carrier: crate::TurnCarrier::Udp,
            server: server_addr,
            channels: Vec::new(),
            permitted: vec![peer],
        };
        (server, relay)
    }

    fn data_indication(peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
        use siphon_rtp_stun::turn;
        let id = [7u8; 12];
        siphon_rtp_stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_DATA, turn::CLASS_INDICATION),
            &id,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer, &id),
        )
        .attribute(turn::ATTR_DATA, payload)
        .finish(None, false)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_data_indication_from_the_server_is_unwrapped_for_a_permitted_peer() {
        // RFC 8656 §11.4: before ChannelBind completes (or after it failed) a peer's packets reach
        // us as Data indications. They must be attributed to the peer exactly like ChannelData.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (server, relay) = permission_only_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_a.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::signalled(
                    leg_b.id,
                    Some(callee_addr),
                    peer_addr.ip(),
                )),
            )
            .expect("flow");

        let payload = rtp(0x2020_2020, 1);
        server
            .send_to(&data_indication(peer_addr, &payload), leg_a.local_addr)
            .await
            .expect("indication in");

        let (relayed, _) = recv(&callee).await;
        assert_eq!(relayed, payload, "the indication's DATA is the media");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_data_indication_naming_an_unpermitted_peer_is_dropped() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (_stranger_socket, stranger_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (server, relay) = permission_only_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_a.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");

        server
            .send_to(
                &data_indication(stranger_addr, &rtp(0x2121_2121, 1)),
                leg_a.local_addr,
            )
            .await
            .expect("indication in");

        let mut buffer = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut buffer))
                .await
                .is_err(),
            "the server relays only permitted peers, so any other peer address is not trusted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_data_indication_from_anywhere_but_the_allocation_server_is_not_unwrapped() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (attacker, _) = phone().await;
        let (_server, relay) = permission_only_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_a.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::signalled(
                    leg_b.id,
                    Some(callee_addr),
                    peer_addr.ip(),
                )),
            )
            .expect("flow");

        attacker
            .send_to(
                &data_indication(peer_addr, &rtp(0x2222_2222, 1)),
                leg_a.local_addr,
            )
            .await
            .expect("forged");

        let mut buffer = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut buffer))
                .await
                .is_err(),
            "a forged indication must not be attributed to the permitted peer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_malformed_data_indication_is_dropped_not_passed_up() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (server, relay) = permission_only_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_a.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");

        // A Data indication type with a header that claims more attributes than it carries.
        let mut broken = data_indication(peer_addr, &rtp(0x2323_2323, 1));
        broken.truncate(broken.len() - 6);
        server
            .send_to(&broken, leg_a.local_addr)
            .await
            .expect("broken in");

        let mut buffer = [0u8; MAX_DATAGRAM];
        assert!(timeout(NEGATIVE, callee.recv_from(&mut buffer))
            .await
            .is_err());
        assert_eq!(datapath.stats(leg_a.id).expect("stats").packets_dropped, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn egress_to_a_permitted_peer_without_a_channel_is_a_send_indication() {
        // RFC 8656 §11.1: with a permission but no channel, data to the peer goes to the server as
        // a Send indication carrying XOR-PEER-ADDRESS and DATA.
        use siphon_rtp_stun::turn;
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_peer_socket, peer_addr) = phone().await;
        let (server, relay) = permission_only_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg.id, Some(relay));

        let payload = rtp(0x2424_2424, 1);
        datapath
            .send(leg.id, peer_addr, &payload)
            .await
            .expect("send");

        let (wire, from) = recv(&server).await;
        assert_eq!(from.port(), leg.local_addr.port());
        let message = siphon_rtp_stun::parse(&wire).expect("a STUN message");
        assert_eq!(
            message.message_type,
            turn::message_type(turn::METHOD_SEND, turn::CLASS_INDICATION)
        );
        assert_eq!(turn::xor_peer_address(&message), Some(peer_addr));
        assert_eq!(turn::data(&message), Some(&payload[..]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarded_media_to_a_permitted_peer_without_a_channel_is_a_send_indication() {
        use siphon_rtp_stun::turn;
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (source, _) = phone().await;
        let (_peer_socket, peer_addr) = phone().await;
        let (server, relay) = permission_only_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_b.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(peer_addr))),
            )
            .expect("flow");

        let payload = rtp(0x2525_2525, 1);
        source
            .send_to(&payload, leg_a.local_addr)
            .await
            .expect("media in");

        let (wire, _) = recv(&server).await;
        let message = siphon_rtp_stun::parse(&wire).expect("a STUN message");
        assert_eq!(
            message.message_type,
            turn::message_type(turn::METHOD_SEND, turn::CLASS_INDICATION)
        );
        assert_eq!(turn::data(&message), Some(&payload[..]));
    }

    // --- Stream carrier (RFC 8656 §3.1, §12.5) ------------------------------------------------

    fn stream_relay_for(
        peer: SocketAddr,
        depth: usize,
    ) -> (flume::Receiver<Bytes>, crate::TurnRelay, u16) {
        let (sender, receiver) = flume::bounded(depth);
        let relay = crate::TurnRelay {
            carrier: crate::TurnCarrier::Stream(sender),
            server: "192.0.2.1:3478".parse().expect("server"),
            channels: vec![(peer, 0x4001)],
            permitted: vec![peer],
        };
        (receiver, relay, 0x4001)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stream_egress_is_padded_channel_data_queued_on_the_stream() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_peer_socket, peer_addr) = phone().await;
        let (queue, relay, channel) = stream_relay_for(peer_addr, 8);
        datapath.set_turn_relay(leg.id, Some(relay));

        // 13 bytes: the frame is 4 + 13 padded to 20, with the padding outside Length.
        let payload = [0x80u8; 13];
        datapath
            .send(leg.id, peer_addr, &payload)
            .await
            .expect("send");
        let wire = queue.try_recv().expect("queued on the stream");
        assert_eq!(
            wire.len(),
            20,
            "RFC 8656 §12.5: padded to a multiple of four"
        );
        let framed = siphon_rtp_stun::turn::parse_channel_data(&wire).expect("ChannelData");
        assert_eq!(framed.channel, channel);
        assert_eq!(framed.data, &payload[..]);
        assert_eq!(&wire[17..], &[0, 0, 0], "zero padding");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarded_media_toward_a_stream_relay_is_queued_and_a_full_queue_sheds_it() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (source, _) = phone().await;
        let (_peer_socket, peer_addr) = phone().await;
        let (queue, relay, _) = stream_relay_for(peer_addr, 1);
        datapath.set_turn_relay(leg_b.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(peer_addr))),
            )
            .expect("flow");

        for sequence in 1..=3 {
            source
                .send_to(&rtp(0x3030_3030, sequence), leg_a.local_addr)
                .await
                .expect("media in");
        }
        // The queue holds one frame; the others were shed rather than queued without bound.
        let first = timeout(SHORT, queue.recv_async())
            .await
            .expect("a frame is queued")
            .expect("open");
        assert!(siphon_rtp_stun::turn::parse_channel_data(&first).is_some());
        tokio::time::sleep(NEGATIVE).await;
        assert!(queue.len() <= 1, "bounded: late media is dropped");
        let dropped = datapath.stats(leg_a.id).expect("stats").packets_dropped;
        assert!(dropped >= 1, "shed packets are counted, got {dropped}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_channel_data_frame_ingested_from_the_stream_flows_like_a_received_datagram() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (_queue, relay, channel) = stream_relay_for(peer_addr, 8);
        datapath.set_turn_relay(leg_a.id, Some(relay));
        // Gated to the peer: passes only if the ingest rewrote the source to the peer.
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::signalled(
                    leg_b.id,
                    Some(callee_addr),
                    peer_addr.ip(),
                )),
            )
            .expect("flow");

        let payload = rtp(0x3131_3131, 1);
        // The stream pads ChannelData (RFC 8656 §12.5); the padding must not reach the media.
        let mut frame = siphon_rtp_stun::turn::encode_channel_data(channel, &payload, true);
        assert!(datapath.ingest_relayed(leg_a.id, &frame).await);
        let (relayed, _) = recv(&callee).await;
        assert_eq!(relayed, payload);
        let stats = datapath.stats(leg_a.id).expect("stats");
        assert_eq!(stats.packets_in, 1);
        assert_eq!(stats.bytes_in, frame.len() as u64);

        // An unbound channel is dropped, not passed up as the server's.
        frame[1] ^= 0x7F;
        assert!(datapath.ingest_relayed(leg_a.id, &frame).await);
        let mut buffer = [0u8; MAX_DATAGRAM];
        assert!(timeout(NEGATIVE, callee.recv_from(&mut buffer))
            .await
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ingest_refuses_an_endpoint_without_a_relay_and_a_stun_response() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_peer_socket, peer_addr) = phone().await;
        let frame = siphon_rtp_stun::turn::encode_channel_data(0x4001, &rtp(1, 1), true);
        assert!(
            !datapath.ingest_relayed(leg.id, &frame).await,
            "no allocation, nothing to deliver for"
        );
        let (_queue, relay, _) = stream_relay_for(peer_addr, 1);
        datapath.set_turn_relay(leg.id, Some(relay));
        let response = stun::binding_request(&[1u8; 12], "user", b"key");
        assert!(
            !datapath.ingest_relayed(leg.id, &response).await,
            "allocation responses belong to the client, not the media path"
        );
        assert!(!datapath.ingest_relayed(leg.id, &[]).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_ice_answer_to_a_check_that_arrived_over_the_stream_goes_back_through_it() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_peer_socket, peer_addr) = phone().await;
        let (queue, relay, _) = stream_relay_for(peer_addr, 8);
        datapath.set_turn_relay(leg.id, Some(relay));
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "lufrag".into(),
                local_pwd: "localpassword0123456789".into(),
            }),
        );
        let check = stun::binding_request(&[3u8; 12], "lufrag:rufrag", b"localpassword0123456789");
        let frame = siphon_rtp_stun::turn::encode_channel_data(0x4001, &check, true);
        assert!(datapath.ingest_relayed(leg.id, &frame).await);
        let answer = timeout(SHORT, queue.recv_async())
            .await
            .expect("an answer is queued on the stream")
            .expect("open");
        let framed = siphon_rtp_stun::turn::parse_channel_data(&answer).expect("ChannelData");
        let response = stun::parse(framed.data).expect("a STUN response");
        assert_eq!(response.transaction_id, [3u8; 12]);
        assert_eq!(datapath.ice_validated_source(leg.id), Some(peer_addr));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_installed_relay_can_be_read_back_and_clearing_it_removes_it() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_peer_socket, peer_addr) = phone().await;
        assert_eq!(datapath.turn_relay(leg.id), None);
        let (_server, relay) = permission_only_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg.id, Some(relay.clone()));
        assert_eq!(datapath.turn_relay(leg.id), Some(relay));
        datapath.set_turn_relay(leg.id, None);
        assert_eq!(datapath.turn_relay(leg.id), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_destination_with_no_channel_is_sent_directly_and_unwrapped() {
        // The allocation's own requests go to the server as plain STUN, and a peer reached over a
        // host/srflx candidate must not be wrapped. Only bound peers are relayed.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_bound_socket, bound_peer) = phone().await;
        let (direct, direct_addr) = phone().await;
        let (_server, relay, _) = turn_relay_for(bound_peer).await;
        datapath.set_turn_relay(leg.id, Some(relay));

        let payload = rtp(0x0B0B_0B0B, 1);
        datapath
            .send(leg.id, direct_addr, &payload)
            .await
            .expect("send");

        let (wire, _) = recv(&direct).await;
        assert_eq!(wire, payload, "an unbound destination is untouched");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relayed_ingress_is_unwrapped_and_attributed_to_the_peer_not_the_server() {
        // Everything above this layer — the ICE responder, the source gate, the latch — must see the
        // peer's address. If the server's leaked through, a relayed leg could never pass its own
        // signalled-source gate.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (server, relay, channel) = turn_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_a.id, Some(relay));
        // Gate leg A to the *peer* — which only passes if de-encapsulation rewrote the source.
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::signalled(
                    leg_b.id,
                    Some(callee_addr),
                    peer_addr.ip(),
                )),
            )
            .expect("flow");

        let payload = rtp(0x0C0C_0C0C, 1);
        let framed = siphon_rtp_stun::turn::encode_channel_data(channel, &payload, false);
        server
            .send_to(&framed, leg_a.local_addr)
            .await
            .expect("relayed in");

        let (relayed, _) = recv(&callee).await;
        assert_eq!(
            relayed, payload,
            "the peer's media relays through, de-encapsulated"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_data_from_anywhere_but_the_allocation_server_is_left_alone() {
        // Otherwise an off-path sender could wrap a forged payload in ChannelData and have the
        // datapath attribute it to a bound peer — spoofing the source gate through the relay seam.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (attacker, _) = phone().await;
        let (_server, relay, channel) = turn_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_a.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::signalled(
                    leg_b.id,
                    Some(callee_addr),
                    peer_addr.ip(),
                )),
            )
            .expect("flow");

        let framed =
            siphon_rtp_stun::turn::encode_channel_data(channel, &rtp(0x0D0D_0D0D, 1), false);
        attacker
            .send_to(&framed, leg_a.local_addr)
            .await
            .expect("forged");

        let mut buffer = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut buffer))
                .await
                .is_err(),
            "forged ChannelData from an unrelated source must not reach the relay"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_data_on_an_unbound_channel_is_dropped_not_passed_up() {
        // Passing it through would hand the media path a datagram sourced from the TURN server.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (_peer_socket, peer_addr) = phone().await;
        let (callee, callee_addr) = phone().await;
        let (server, relay, channel) = turn_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg_a.id, Some(relay));
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");

        let unbound = channel + 1;
        let framed =
            siphon_rtp_stun::turn::encode_channel_data(unbound, &rtp(0x0E0E_0E0E, 1), false);
        server
            .send_to(&framed, leg_a.local_addr)
            .await
            .expect("send");

        let mut buffer = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut buffer))
                .await
                .is_err(),
            "an unbound channel has no peer to attribute the data to"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stun_from_the_turn_server_still_reaches_the_client_untouched() {
        // The allocation's own responses share the 5-tuple with relayed data; de-encapsulation must
        // not eat them, or the client would never see its Allocate succeed.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (_peer_socket, peer_addr) = phone().await;
        let (server, relay, _) = turn_relay_for(peer_addr).await;
        let server_addr = server.local_addr().expect("addr");
        datapath.set_turn_relay(leg.id, Some(relay));
        datapath
            .install_flow(leg.id, FlowAction::Redirect)
            .expect("flow");
        let redirected = datapath.rx();

        let response = siphon_rtp_stun::binding_success_response(&[7u8; 12], peer_addr, None);
        server
            .send_to(&response, leg.local_addr)
            .await
            .expect("send");

        let packet = timeout(SHORT, redirected.recv_async())
            .await
            .expect("the allocation response is delivered")
            .expect("stream open");
        assert_eq!(&packet.data[..], &response[..], "delivered byte-for-byte");
        assert_eq!(packet.source, server_addr);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clearing_the_relay_puts_the_endpoint_back_on_the_direct_path() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (peer_socket, peer_addr) = phone().await;
        let (_server, relay, _) = turn_relay_for(peer_addr).await;
        datapath.set_turn_relay(leg.id, Some(relay));
        datapath.set_turn_relay(leg.id, None);

        let payload = rtp(0x0F0F_0F0F, 1);
        datapath
            .send(leg.id, peer_addr, &payload)
            .await
            .expect("send");
        let (wire, _) = recv(&peer_socket).await;
        assert_eq!(wire, payload, "unwrapped, straight to the peer");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_injects_from_endpoint() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (phone, addr) = phone().await;

        let sent = datapath
            .send(leg.id, addr, b"injected")
            .await
            .expect("send");
        assert_eq!(sent, b"injected".len());
        let (data, from) = recv(&phone).await;
        assert_eq!(data, b"injected");
        assert_eq!(from, leg.local_addr);
        assert_eq!(datapath.stats(leg.id).expect("stats").packets_out, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_latch_reports_the_ssrc_of_the_stream_it_adopted() {
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let (phone_a, _) = phone().await;
        let (phone_b, addr_b) = phone().await;
        datapath
            .install_flow(
                near.id,
                FlowAction::Forward(ForwardRule::symmetric(far.id, Some(addr_b))),
            )
            .expect("near flow");
        assert_eq!(datapath.latched_ssrc(near.id), None, "nothing latched yet");
        phone_a
            .send_to(&rtp(0x1234_5678, 1), near.local_addr)
            .await
            .expect("send");
        let _ = recv(&phone_b).await;
        assert_eq!(datapath.latched_ssrc(near.id), Some(0x1234_5678));
        assert_eq!(
            datapath.latched_ssrc(far.id),
            None,
            "the far side sent nothing"
        );
    }

    #[tokio::test]
    async fn install_flow_rejects_unknown_endpoint() {
        let datapath = UdpLoopbackDatapath::new();
        let result = datapath.install_flow(EndpointId(999), FlowAction::Drop);
        assert!(matches!(result, Err(DatapathError::UnknownEndpoint(_))));
        let result = datapath
            .send(
                EndpointId(999),
                "127.0.0.1:5000".parse().expect("addr"),
                b"x",
            )
            .await;
        assert!(matches!(result, Err(DatapathError::UnknownEndpoint(_))));
    }

    #[tokio::test]
    async fn remove_endpoint_frees_state() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        assert!(datapath.stats(leg.id).is_some());
        datapath.remove_endpoint(leg.id).await;
        assert!(datapath.stats(leg.id).is_none());
        // Installing a flow on the removed endpoint now fails.
        assert!(matches!(
            datapath.install_flow(leg.id, FlowAction::Drop),
            Err(DatapathError::UnknownEndpoint(_))
        ));
    }

    /// A test phone bound to a specific loopback address (127.0.0.0/8 is all loopback on Linux), so
    /// the source gate — which keys on IP — can be exercised with distinct peers.
    async fn phone_at(ip: Ipv4Addr) -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((ip, 0)).await.expect("bind phone");
        let addr = socket.local_addr().expect("phone addr");
        (socket, addr)
    }

    /// A minimal RTP packet (V=2, PT=0/PCMU) carrying `ssrc` and `sequence` — enough for the latch
    /// to read an SSRC (RFC 3550 §5.1).
    /// PRIORITY a test's nominating check carries unless the test is about ordering.
    const NOMINATED_PRIORITY: u32 = 0x7E00_00FF;

    /// A valid connectivity check for the `ENG` endpoint that nominates its pair (USE-CANDIDATE,
    /// RFC 8445 §7.1.1) with the given PRIORITY.
    fn nominating_check(transaction: &[u8; 12], priority: u32) -> Vec<u8> {
        stun::client::binding_request_ice(
            transaction,
            "ENG:remote",
            b"engpass",
            priority,
            stun::client::IceRole::Controlling(1),
            true,
        )
    }

    /// The same check without USE-CANDIDATE: answered, but it selects nothing.
    fn plain_check(transaction: &[u8; 12], priority: u32) -> Vec<u8> {
        stun::client::binding_request_ice(
            transaction,
            "ENG:remote",
            b"engpass",
            priority,
            stun::client::IceRole::Controlling(1),
            false,
        )
    }

    fn rtp(ssrc: u32, sequence: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"audio");
        packet
    }

    /// A minimal RTCP sender report (V=2, PT=200, RFC 3550 §6.4.1) from `ssrc`.
    fn rtcp_sender_report(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0x00, 0x06];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0u8; 20]);
        packet
    }

    /// Install a near->far relay with `rtcp_to_userspace` set as asked, gated to `addr_near`.
    fn install_relay_with_rtcp_flag(
        datapath: &UdpLoopbackDatapath,
        near: EndpointId,
        far: EndpointId,
        addr_near: SocketAddr,
        addr_far: SocketAddr,
        rtcp_to_userspace: bool,
    ) {
        let mut rule = ForwardRule::signalled(far, Some(addr_far), addr_near.ip());
        rule.rtcp_to_userspace = rtcp_to_userspace;
        datapath
            .install_flow(near, FlowAction::Forward(rule))
            .expect("relay flow");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtcp_goes_to_the_redirect_stream_when_the_rule_asks_and_rtp_is_still_forwarded() {
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        install_relay_with_rtcp_flag(&datapath, near.id, far.id, addr_a, addr_b, true);
        let rx = datapath.rx();

        let report = rtcp_sender_report(0xA0A0_0001);
        phone_a
            .send_to(&report, near.local_addr)
            .await
            .expect("send rtcp");
        let redirected = timeout(SHORT, rx.recv_async())
            .await
            .expect("the RTCP reaches the redirect stream")
            .expect("open");
        assert_eq!(redirected.endpoint, near.id);
        assert_eq!(redirected.source, addr_a);
        assert_eq!(&redirected.data[..], &report[..], "byte-identical");
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(NEGATIVE, phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "the backend does not also forward it: the consumer relays it"
        );

        phone_a
            .send_to(&rtp(0xA0A0_0001, 1), near.local_addr)
            .await
            .expect("send rtp");
        let (data, _) = recv(&phone_b).await;
        assert_eq!(data, rtp(0xA0A0_0001, 1), "RTP is still forwarded");
        assert!(
            timeout(NEGATIVE, rx.recv_async()).await.is_err(),
            "and never redirected"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtcp_is_forwarded_as_before_when_the_rule_does_not_ask() {
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        install_relay_with_rtcp_flag(&datapath, near.id, far.id, addr_a, addr_b, false);
        let rx = datapath.rx();

        let report = rtcp_sender_report(0xA0A0_0001);
        phone_a
            .send_to(&report, near.local_addr)
            .await
            .expect("send rtcp");
        let (data, _) = recv(&phone_b).await;
        assert_eq!(data, report);
        assert!(
            timeout(NEGATIVE, rx.recv_async()).await.is_err(),
            "nothing is redirected"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtcp_from_an_unadmitted_source_is_dropped_not_redirected() {
        // RTPBleed: the gate runs before the redirect decision, so an off-path sender cannot put
        // datagrams in front of the engine's RTCP consumer either.
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let (_phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 66)).await;
        install_relay_with_rtcp_flag(&datapath, near.id, far.id, addr_a, addr_b, true);
        let rx = datapath.rx();

        attacker
            .send_to(&rtcp_sender_report(0xBAD0_0001), near.local_addr)
            .await
            .expect("send rtcp");
        assert!(
            timeout(NEGATIVE, rx.recv_async()).await.is_err(),
            "an unadmitted source's RTCP is not redirected"
        );
        let mut scratch = [0u8; 2048];
        assert!(
            timeout(NEGATIVE, phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "nor forwarded"
        );
        assert_eq!(
            datapath.stats(near.id).expect("stats").packets_dropped,
            1,
            "it is counted as dropped"
        );
    }

    // The three RTPBleed checks below are the backend-agnostic ones from `crate::conformance`, which
    // any other backend runs against its own endpoints; this is the UDP-loopback backend's run.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtpbleed_off_path_source_is_gated_out() {
        crate::conformance::an_off_path_source_is_gated_out(
            &UdpLoopbackDatapath::new(),
            &crate::conformance::Peers::loopback().await,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn symmetric_latch_follows_ssrc_rebind_but_rejects_hijack() {
        crate::conformance::the_latch_follows_a_same_ssrc_rebind_but_rejects_a_hijack(
            &UdpLoopbackDatapath::new(),
            &crate::conformance::Peers::loopback().await,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn re_answer_to_a_new_peer_drops_the_stale_latch() {
        crate::conformance::a_re_answer_that_moves_the_peer_drops_the_stale_latch(
            &UdpLoopbackDatapath::new(),
            &crate::conformance::Peers::loopback().await,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn re_answer_to_another_port_on_the_same_address_drops_the_stale_latch() {
        // The far side moves its media to another port on the same box. The address-only gate admits
        // both, so only the moved destination can tell the latch is stale.
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let (phone_near, addr_near) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (early_peer, addr_early) = phone_at(Ipv4Addr::new(127, 0, 0, 8)).await;
        let (answer_peer, addr_answer) = phone_at(Ipv4Addr::new(127, 0, 0, 8)).await;
        let answer = |far_peer: SocketAddr| {
            datapath
                .install_flow(
                    near.id,
                    FlowAction::Forward(ForwardRule::signalled(
                        far.id,
                        Some(far_peer),
                        addr_near.ip(),
                    )),
                )
                .expect("near flow");
            datapath
                .install_flow(
                    far.id,
                    FlowAction::Forward(ForwardRule::signalled(
                        near.id,
                        Some(addr_near),
                        far_peer.ip(),
                    )),
                )
                .expect("far flow");
        };

        answer(addr_early);
        early_peer
            .send_to(&rtp(0xEA51_0001, 1), far.local_addr)
            .await
            .expect("send early");
        assert_eq!(recv(&phone_near).await.0, rtp(0xEA51_0001, 1));

        answer(addr_answer);
        answer_peer
            .send_to(&rtp(0xF1A1_0002, 1), far.local_addr)
            .await
            .expect("send answer");
        assert_eq!(recv(&phone_near).await.0, rtp(0xF1A1_0002, 1));
        phone_near
            .send_to(&rtp(0x0EA2_0003, 1), near.local_addr)
            .await
            .expect("send near");
        assert_eq!(recv(&answer_peer).await.0, rtp(0x0EA2_0003, 1));
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, early_peer.recv_from(&mut scratch))
                .await
                .is_err(),
            "near media must not go to the port the re-answer replaced"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reinstalling_an_unchanged_answer_keeps_a_natted_latch() {
        // A hold or refresh re-INVITE reinstalls the same rules. A NATed far peer signalled an
        // address it does not send from; its learned source must survive, or the reply falls back
        // to the unroutable signalled address until the peer happens to send again.
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let (phone_near, addr_near) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (natted_peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (signalled_peer, addr_signalled) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;
        let install = || {
            datapath
                .install_flow(
                    near.id,
                    FlowAction::Forward(ForwardRule::signalled(
                        far.id,
                        Some(addr_signalled),
                        addr_near.ip(),
                    )),
                )
                .expect("near flow");
            datapath
                .install_flow(
                    far.id,
                    FlowAction::Forward(ForwardRule::symmetric(near.id, Some(addr_near))),
                )
                .expect("far flow");
        };

        install();
        natted_peer
            .send_to(&rtp(0x0A7E_0001, 1), far.local_addr)
            .await
            .expect("send natted");
        assert_eq!(recv(&phone_near).await.0, rtp(0x0A7E_0001, 1));

        install();
        phone_near
            .send_to(&rtp(0x0EA2_0002, 1), near.local_addr)
            .await
            .expect("send near");
        assert_eq!(recv(&natted_peer).await.0, rtp(0x0EA2_0002, 1));
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, signalled_peer.recv_from(&mut scratch))
                .await
                .is_err(),
            "an unchanged reinstall must keep replying to the learned source"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn demux_drops_non_rtp_without_latching() {
        crate::conformance::a_non_media_datagram_is_dropped_without_latching(
            &UdpLoopbackDatapath::new(),
            &crate::conformance::Peers::loopback().await,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forward_relay_counts_network_loss_from_sequence_gaps() {
        // A plain Forward relay leg (no transcode actor) must still report inbound network loss to the
        // CDR: the datapath folds each accepted RTP sequence into an RFC 3550 §A.1 forward-gap estimate
        // on the ingress endpoint. A deliberate gap in the sequence numbers (nothing dropped by the
        // gate) shows up as `packets_lost`, distinct from `packets_dropped`.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");

        // seq 1 (baseline), 2 (in order), then 5 — 3 and 4 never arrived (two lost) — then 6. One SSRC
        // throughout so the latch stays put. Recv each forwarded datagram before sending the next, so
        // the single receive task has folded packet N's sequence (updating `last_rtp_seq`) before N+1.
        for sequence in [1u16, 2, 5, 6] {
            peer.send_to(&rtp(0x1234_5678, sequence), leg_a.local_addr)
                .await
                .expect("peer send");
            let (data, _) = recv(&callee).await;
            assert_eq!(data, rtp(0x1234_5678, sequence));
        }

        // The two missing sequences (3, 4) are counted as network loss; nothing was gate-dropped.
        let mut lost = 0;
        for _ in 0..50 {
            lost = datapath.stats(leg_a.id).expect("stats").packets_lost;
            if lost >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(lost, 2, "sequence gap 2->5 counts two lost packets");
        assert_eq!(
            datapath.stats(leg_a.id).expect("stats").packets_dropped,
            0,
            "network loss is not an engine-side gate drop"
        );
    }

    #[tokio::test]
    async fn endpoint_pool_is_bounded_and_frees_on_remove() {
        let datapath = UdpLoopbackDatapath::with_max_endpoints(2);
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        // The pool is full — a third allocation fails cleanly, not by exhausting host FDs.
        assert!(matches!(
            datapath.alloc_endpoint().await,
            Err(DatapathError::PoolExhausted { limit: 2 })
        ));
        // Freeing a slot admits a new allocation.
        datapath.remove_endpoint(leg_a.id).await;
        let leg_c = datapath.alloc_endpoint().await.expect("alloc after free");
        let _ = (leg_b, leg_c);
    }

    #[tokio::test]
    async fn port_range_allocates_within_the_configured_window() {
        // Every media port comes from the operator-configured [min, max] window (rtpengine
        // port-min/port-max parity — firewallable), not an arbitrary OS-ephemeral port.
        let (min, max) = (40_000u16, 40_009u16);
        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), min, max);
        for _ in 0..6 {
            let endpoint = datapath.alloc_endpoint().await.expect("alloc in range");
            let port = endpoint.local_addr.port();
            assert!(
                (min..=max).contains(&port),
                "port {port} must be within [{min}, {max}]"
            );
        }
    }

    #[tokio::test]
    async fn a_port_held_by_another_process_is_skipped() {
        // The documented reason `bind_in_range` retries at all: a port reservable in our range but
        // already bound on the host (another process, or another siphon-rtp instance sharing the
        // range) is released and skipped, and the allocation lands on the next one.
        let held = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 43_100))
            .expect("hold the first port of the range");

        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 43_100, 43_101);
        let endpoint = datapath
            .alloc_endpoint()
            .await
            .expect("alloc skips the held port");

        assert_eq!(
            endpoint.local_addr.port(),
            43_101,
            "the held port is skipped, not reported as a failure"
        );
        drop(held);
    }

    #[tokio::test]
    async fn a_bind_error_that_is_not_addr_in_use_is_reported_as_itself() {
        // Every bind failure used to be swallowed and retried, so the loop walked the whole span and
        // renamed the cause `PoolExhausted` — on a range that was entirely free. The failure that
        // matters in production is EMFILE (a container's default 1024-descriptor soft limit caps a
        // relay node at ~253 calls), which no other port can fix. EADDRNOTAVAIL on a TEST-NET-1
        // address (RFC 5737 §3) is the deterministic stand-in: unassigned on any conforming host.
        let datapath = UdpLoopbackDatapath::with_port_range(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            43_200,
            43_209,
        );

        let error = datapath
            .alloc_endpoint()
            .await
            .expect_err("binding an unassigned address cannot succeed");

        match error {
            DatapathError::Bind(io) => assert_eq!(
                io.kind(),
                std::io::ErrorKind::AddrNotAvailable,
                "the operating system's own reason is preserved"
            ),
            other => panic!("expected the bind error itself, got {other:?}"),
        }

        let pool = datapath
            .inner
            .ports
            .as_ref()
            .expect("the range is configured");
        assert!(
            pool.reserved.is_empty(),
            "the attempted port is released, not leaked out of the pool"
        );
    }

    #[tokio::test]
    async fn port_range_exhaustion_is_clean() {
        // A two-port range admits exactly two endpoints; the third fails cleanly (no host-FD spray).
        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 41_000, 41_001);
        let _a = datapath.alloc_endpoint().await.expect("alloc a");
        let _b = datapath.alloc_endpoint().await.expect("alloc b");
        assert!(matches!(
            datapath.alloc_endpoint().await,
            Err(DatapathError::PoolExhausted { limit: 2 })
        ));
    }

    #[tokio::test]
    async fn port_range_releases_the_port_on_remove() {
        // A single-port range: the port is reusable once the endpoint that held it is removed.
        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 42_000, 42_000);
        let first = datapath.alloc_endpoint().await.expect("first alloc");
        assert_eq!(first.local_addr.port(), 42_000);
        assert!(
            matches!(
                datapath.alloc_endpoint().await,
                Err(DatapathError::PoolExhausted { limit: 1 })
            ),
            "the only port is taken"
        );
        datapath.remove_endpoint(first.id).await;
        let reused = datapath.alloc_endpoint().await.expect("alloc after free");
        assert_eq!(reused.local_addr.port(), 42_000, "the freed port is reused");
    }

    #[tokio::test]
    async fn alloc_specific_binds_the_exact_port() {
        // The HA-restore primitive: a standby re-binds the exact port a primary advertised.
        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 43_000, 43_010);
        let endpoint = datapath
            .alloc_specific(AddressFamily::V4, 43_005)
            .await
            .expect("bind the exact port");
        assert_eq!(endpoint.local_addr.port(), 43_005);
        // The reserved port is now unavailable to the range allocator and to a second exact request.
        assert!(matches!(
            datapath.alloc_specific(AddressFamily::V4, 43_005).await,
            Err(DatapathError::PortUnavailable { port: 43_005 })
        ));
    }

    #[tokio::test]
    async fn alloc_specific_rejects_out_of_range_ports() {
        let datapath =
            UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 44_000, 44_002);
        assert!(matches!(
            datapath.alloc_specific(AddressFamily::V4, 50_000).await,
            Err(DatapathError::PortUnavailable { port: 50_000 })
        ));
    }

    #[tokio::test]
    async fn alloc_specific_without_a_range_binds_the_requested_port() {
        // No configured range: the exact port is bound directly (any free OS port is accepted).
        let scratch = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("scratch bind");
        let free_port = scratch.local_addr().expect("addr").port();
        drop(scratch);
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath
            .alloc_specific(AddressFamily::V4, free_port)
            .await
            .expect("bind the requested port without a range");
        assert_eq!(endpoint.local_addr.port(), free_port);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn endpoints_bind_the_configured_ip_and_relay() {
        // The production posture: endpoints bind a chosen, routable IP rather than loopback's
        // default, so the relay is reachable by real peers. 127.0.0.0/8 is entirely loopback on
        // Linux, so a non-default 127.0.0.x address exercises the configurability NIC-free.
        let bind_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
        let datapath = UdpLoopbackDatapath::with_bind_ip(bind_ip);
        let relay = datapath.alloc_endpoint().await.expect("alloc");
        assert_eq!(
            relay.local_addr.ip(),
            bind_ip,
            "the endpoint binds the configured IP, not loopback"
        );

        // It still relays: a Redirect flow delivers a peer datagram raw (the TURN relay path).
        datapath
            .install_flow(relay.id, FlowAction::Redirect)
            .expect("flow");
        let rx = datapath.rx();
        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        peer.send_to(b"peer-media", relay.local_addr)
            .await
            .expect("peer send");
        let packet = timeout(SHORT, rx.recv_async())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(packet.source, peer_addr);
        assert_eq!(&packet.data[..], b"peer-media");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn alloc_endpoint_on_binds_a_per_leg_source_ip_and_emits_from_it() {
        // Named-interface posture: two legs on the *same* datapath bind two *different* source IPs
        // (an `internal` and an `external` address), independent of the datapath's default bind IP.
        // 127.0.0.0/8 is entirely loopback on Linux, so distinct 127.0.0.x addresses exercise per-leg
        // source-IP selection NIC-free.
        let datapath = UdpLoopbackDatapath::new(); // default bind IP = 127.0.0.1
        let internal = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let external = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        let near = datapath
            .alloc_endpoint_on(internal)
            .await
            .expect("alloc internal");
        let far = datapath
            .alloc_endpoint_on(external)
            .await
            .expect("alloc external");
        assert_eq!(
            near.local_addr.ip(),
            internal,
            "near leg binds the internal source IP, not the default loopback"
        );
        assert_eq!(
            far.local_addr.ip(),
            external,
            "far leg binds the external source IP"
        );

        // A -> engine(near) -> phone_b, forwarded out via the `far` endpoint: phone_b must see the
        // datagram arrive *from the external source IP*, proving the far leg emits from its bind IP.
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
        let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;
        datapath
            .install_flow(
                near.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: far.id,
                    out_dst: Some(addr_b),
                    accepted_source: SourceFilter::Exact(addr_a.ip()),
                    latch: LatchPolicy::SignalledOnly,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow");
        phone_a
            .send_to(&rtp(0x0A0A_0A0A, 1), near.local_addr)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A, 1));
        assert_eq!(
            from, far.local_addr,
            "the relayed datagram leaves from the far leg's external source IP"
        );
    }

    #[tokio::test]
    async fn alloc_endpoint_on_port_at_rebinds_a_specific_source_ip_and_port() {
        // Interface-aware HA restore: a standby re-binds the exact (source IP, port) the snapshot
        // recorded, so a call pinned to a named interface resumes on the same source IP.
        let bind_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let scratch = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("scratch bind");
        let free_port = scratch.local_addr().expect("addr").port();
        drop(scratch);
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath
            .alloc_endpoint_on_port_at(bind_ip, free_port)
            .await
            .expect("rebind the exact source IP and port");
        assert_eq!(endpoint.local_addr.ip(), bind_ip);
        assert_eq!(endpoint.local_addr.port(), free_port);
    }

    #[tokio::test]
    async fn a_routable_bind_ip_refuses_a_family_it_has_no_address_for() {
        // A production relay bound to one routable IPv4 address has no IPv6 address to offer. It
        // used to bind `::1` for a `c=IN IP6` leg and advertise it, so the call answered and no
        // packet could ever arrive. RFC 4566 §5.7: the address in `c=` is where media is sent, and
        // a peer cannot reach this host's loopback. Refusing is the only honest answer.
        let routable = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let datapath = UdpLoopbackDatapath::with_bind_ip(routable);

        let refused = datapath.alloc_endpoint_for(AddressFamily::V6).await;
        assert!(
            matches!(
                refused,
                Err(DatapathError::NoAddressForFamily {
                    family: AddressFamily::V6
                })
            ),
            "a v6 endpoint on a v4-only relay is refused, got {refused:?}"
        );
        assert_eq!(
            datapath.inner.live.load(Ordering::Acquire),
            0,
            "a refused allocation holds no pool slot"
        );

        // The HA-restore path selects its bind IP the same way and must refuse the same way.
        let restored = datapath.alloc_specific(AddressFamily::V6, 40_000).await;
        assert!(
            matches!(
                restored,
                Err(DatapathError::NoAddressForFamily {
                    family: AddressFamily::V6
                })
            ),
            "a v6 restore on a v4-only relay is refused, got {restored:?}"
        );
    }

    #[tokio::test]
    async fn a_routable_v6_bind_ip_refuses_ipv4_the_same_way() {
        let routable = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10));
        let datapath = UdpLoopbackDatapath::with_bind_ip(routable);

        let refused = datapath.alloc_endpoint_for(AddressFamily::V4).await;
        assert!(
            matches!(
                refused,
                Err(DatapathError::NoAddressForFamily {
                    family: AddressFamily::V4
                })
            ),
            "a v4 endpoint on a v6-only relay is refused, got {refused:?}"
        );
    }

    #[tokio::test]
    async fn a_wildcard_bind_ip_refuses_the_other_family() {
        // `0.0.0.0` is every IPv4 interface and no IPv6 one. Its v6 counterpart `::` is not an
        // address a peer can be told to send to either, so there is nothing to fall back on.
        let datapath = UdpLoopbackDatapath::with_bind_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let refused = datapath.alloc_endpoint_for(AddressFamily::V6).await;
        assert!(
            matches!(refused, Err(DatapathError::NoAddressForFamily { .. })),
            "got {refused:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn alloc_endpoint_for_v6_binds_loopback_and_round_trips() {
        // A v6-signalled call asks the datapath for a v6 endpoint; it must bind `::1` and relay a
        // datagram between two `::1` sockets (RFC 4566 §5.7 `IN IP6`). The default backend binds
        // loopback v4, so the family is what selects v6 here.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath
            .alloc_endpoint_for(AddressFamily::V6)
            .await
            .expect("alloc v6 a");
        let leg_b = datapath
            .alloc_endpoint_for(AddressFamily::V6)
            .await
            .expect("alloc v6 b");
        assert!(
            leg_a.local_addr.is_ipv6(),
            "v6 endpoint binds an IPv6 address"
        );
        assert_eq!(leg_a.local_addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));

        // Two `::1` phones standing in for the v6 peers.
        let phone_a = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind v6 phone a");
        let addr_a = phone_a.local_addr().expect("v6 addr a");
        let phone_b = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind v6 phone b");
        let addr_b = phone_b.local_addr().expect("v6 addr b");

        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: Some(addr_b),
                    accepted_source: SourceFilter::Exact(addr_a.ip()),
                    latch: LatchPolicy::SignalledOnly,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow a");

        // A -> engine(leg_a) -> phone_b, leaving from the engine's v6 B-facing port.
        phone_a
            .send_to(&rtp(0x0A0A_0A0A, 1), leg_a.local_addr)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, rtp(0x0A0A_0A0A, 1));
        assert_eq!(from, leg_b.local_addr);
    }

    #[tokio::test]
    async fn clock_and_last_activity_track_endpoints() {
        let datapath = UdpLoopbackDatapath::new();
        assert_eq!(datapath.now_ticks(), FIRST_TICK);
        assert_eq!(
            datapath.last_activity(EndpointId(0)),
            None,
            "unknown endpoint"
        );
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        assert_eq!(
            datapath.last_activity(leg.id),
            Some(0),
            "no packets accepted yet"
        );
        datapath.advance_clock(5);
        assert_eq!(datapath.now_ticks(), FIRST_TICK + 5);
    }

    #[test]
    fn the_clock_never_reports_the_no_packet_sentinel() {
        // `last_activity` says "no packet yet" with the tick `0`, and the media-timeout sweep reads
        // that to tell a call whose path died from one still in setup. A clock that could itself
        // report `0` would let a packet accepted in the first tick stamp the sentinel and read back
        // as one that never arrived, so the origin is one — asserted here rather than left to the
        // constant's comment.
        let datapath = UdpLoopbackDatapath::new();
        assert_ne!(
            datapath.now_ticks(),
            0,
            "a fresh backend must already be past the sentinel"
        );
    }

    #[test]
    fn trait_advance_clock_drives_the_logical_clock() {
        // The generic engine runner (`run_with_datapath<D: Datapath>`) advances the sweep clock
        // through the `Datapath` trait method, not the inherent one — prove the trait method moves
        // the loopback backend's logical clock so the media-timeout sweep stays deterministic.
        fn tick_via_trait<D: Datapath>(datapath: &D, ticks: u64) {
            datapath.advance_clock(ticks);
        }
        let datapath = UdpLoopbackDatapath::new();
        assert_eq!(datapath.now_ticks(), FIRST_TICK);
        tick_via_trait(&datapath, 3);
        tick_via_trait(&datapath, 4);
        assert_eq!(datapath.now_ticks(), FIRST_TICK + 7);
    }

    #[test]
    fn default_trait_advance_clock_is_a_noop() {
        // A backend that does not override `advance_clock` (the real-time XDP posture) gets the
        // additive default no-op: the generic sweep call compiles and does nothing to its clock.
        struct RealtimeStub;
        impl Datapath for RealtimeStub {
            async fn alloc_endpoint(&self) -> Result<Endpoint, DatapathError> {
                Err(DatapathError::PortUnavailable { port: 0 })
            }
            fn install_flow(
                &self,
                _endpoint: EndpointId,
                _action: FlowAction,
            ) -> Result<(), DatapathError> {
                Ok(())
            }
            fn remove_flow(&self, _endpoint: EndpointId) {}
            async fn remove_endpoint(&self, _endpoint: EndpointId) {}
            async fn send(
                &self,
                _endpoint: EndpointId,
                _dst: std::net::SocketAddr,
                _data: &[u8],
            ) -> Result<usize, DatapathError> {
                Ok(0)
            }
            fn stats(&self, _endpoint: EndpointId) -> Option<EndpointStats> {
                None
            }
            fn now_ticks(&self) -> u64 {
                42
            }
            fn last_activity(&self, _endpoint: EndpointId) -> Option<u64> {
                None
            }
            fn set_ice(&self, _endpoint: EndpointId, _config: Option<IceConfig>) {}
            fn rx(&self) -> flume::Receiver<RxPacket> {
                flume::unbounded().1
            }
            fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp> {
                flume::unbounded().1
            }
        }
        let stub = RealtimeStub;
        stub.advance_clock(1000);
        assert_eq!(
            stub.now_ticks(),
            42,
            "default no-op must not touch the clock"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_check_is_answered_and_adopts_the_validated_source() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        datapath.set_ice(
            leg_a.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
        // ICE validation gates the source, so the media rule accepts any source and latches.
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");

        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        // A valid connectivity check addressed to us, signed with our password.
        let check = nominating_check(&[9u8; 12], NOMINATED_PRIORITY);
        peer.send_to(&check, leg_a.local_addr)
            .await
            .expect("send check");

        // We answer with a Binding success response, integrity-signed with our password.
        let (response, from) = recv(&peer).await;
        assert_eq!(from, leg_a.local_addr);
        let parsed = stun::parse(&response).expect("parse response");
        assert_eq!(parsed.message_type, stun::BINDING_SUCCESS);
        assert!(stun::verify_message_integrity(&response, b"engpass"));

        // The validated source was adopted: the peer's media now relays to the callee.
        peer.send_to(&rtp(0x1234_5678, 1), leg_a.local_addr)
            .await
            .expect("send rtp");
        let (data, _) = recv(&callee).await;
        assert_eq!(data, rtp(0x1234_5678, 1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_forward_leg_forwards_media_only_from_a_stun_validated_source() {
        // B1 regression: a plaintext-RTP + ICE relay leg must never blind-latch the first RTP
        // sender. Media is forwarded only from a source a STUN connectivity check has validated —
        // never a pre-check spray, and never a different source after adoption (the connectivity
        // check, not "first packet wins", is the path). docs/security-and-nat.md §4 layer 4; RFC 8445.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        datapath.set_ice(
            leg_a.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
        // The engine installs an ICE leg with an open rule (`Any`/`Off`); the datapath's ICE gate —
        // not the rule — decides, so an un-validated source is dropped regardless of the rule.
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: Some(callee_addr),
                    accepted_source: SourceFilter::Any,
                    latch: LatchPolicy::Off,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow");

        // Pre-check spray: an attacker's RTP arrives before any connectivity check. It must be
        // dropped — never blind-latched, never forwarded to the callee.
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        attacker
            .send_to(&rtp(0xAAAA_AAAA, 1), leg_a.local_addr)
            .await
            .expect("attacker send");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut scratch))
                .await
                .is_err(),
            "media before any STUN validation must be dropped, not blind-latched (B1)"
        );

        // A valid connectivity check from the real peer adopts its source.
        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let check = nominating_check(&[9u8; 12], NOMINATED_PRIORITY);
        peer.send_to(&check, leg_a.local_addr)
            .await
            .expect("send check");
        let _ = recv(&peer).await; // await the success response so the adoption has completed

        // The validated peer's media now flows to the callee.
        peer.send_to(&rtp(0x1234_5678, 1), leg_a.local_addr)
            .await
            .expect("peer rtp");
        let (data, from) = recv(&callee).await;
        assert_eq!(data, rtp(0x1234_5678, 1));
        assert_eq!(from, leg_b.local_addr);

        // A different source spraying after adoption is rejected — an ICE path only ever follows a
        // fresh validated check, so a later different-source spray cannot steal it via media.
        attacker
            .send_to(&rtp(0xBBBB_BBBB, 2), leg_a.local_addr)
            .await
            .expect("attacker rtp");
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut scratch))
                .await
                .is_err(),
            "a different source after adoption must not be forwarded (no media re-latch on ICE)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_check_with_bad_integrity_is_dropped() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        // Signed with the wrong password — an off-path forgery; it must not be answered.
        let forged = stun::binding_request(&[0u8; 12], "ENG:remote", b"WRONG");
        peer.send_to(&forged, leg.local_addr)
            .await
            .expect("send forged");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, peer.recv_from(&mut scratch))
                .await
                .is_err(),
            "a check failing MESSAGE-INTEGRITY must be dropped, not answered"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_check_counts_as_activity_for_the_media_timeout_sweep() {
        // Consent (RFC 7675): a valid connectivity check refreshes the endpoint's last-activity, so
        // the media-timeout sweep keeps an ICE path alive while checks flow (and reaps it once they
        // stop).
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        assert_eq!(datapath.last_activity(leg.id), Some(0), "no activity yet");

        datapath.advance_clock(7);
        let check = stun::binding_request(&[1u8; 12], "ENG:remote", b"engpass");
        peer.send_to(&check, leg.local_addr)
            .await
            .expect("send check");
        // Await the response so the check has been fully processed (activity stamped).
        let _ = recv(&peer).await;

        assert_eq!(
            datapath.last_activity(leg.id),
            Some(FIRST_TICK + 7),
            "a valid consent check stamps activity at the current tick"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_validated_source_reports_only_a_check_validated_peer() {
        // The RFC 7675 consent target: the address a MESSAGE-INTEGRITY-verified check adopted
        // (RFC 8445 §7.3) — nothing before that, and nothing a forgery claims.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            None,
            "no check has validated a source yet"
        );

        // A forgery must not become the consent target.
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let forged = stun::binding_request(&[3u8; 12], "ENG:remote", b"WRONG");
        attacker
            .send_to(&forged, leg.local_addr)
            .await
            .expect("send forged");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, attacker.recv_from(&mut scratch))
                .await
                .is_err(),
            "the forged check is dropped"
        );
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            None,
            "a check failing MESSAGE-INTEGRITY never adopts a source"
        );

        // The real peer's valid check does.
        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let check = nominating_check(&[4u8; 12], NOMINATED_PRIORITY);
        peer.send_to(&check, leg.local_addr)
            .await
            .expect("send check");
        let _ = recv(&peer).await;
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            Some(peer_addr),
            "the validated check's source is the selected path"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch_ice_validated_follows_the_nominated_source_until_ice_is_cleared() {
        // The push side of `ice_validated_source`, for a consumer that owns a leg's egress in userspace:
        // RFC 8445 §12.1.1 has an ice-lite leg send nothing before a valid pair, and then send to it.
        // The selected pair is the nominated one (§7.3.1.5), so only a USE-CANDIDATE check publishes.
        let datapath = UdpLoopbackDatapath::new();
        let plain = datapath.alloc_endpoint().await.expect("alloc plain");
        assert!(
            datapath.watch_ice_validated(plain.id).is_none(),
            "an endpoint without ICE credentials has no validated source to follow"
        );
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        let mut validated = datapath
            .watch_ice_validated(leg.id)
            .expect("an ICE endpoint can be followed");
        assert_eq!(
            *validated.borrow_and_update(),
            None,
            "nothing validated yet"
        );

        // A forgery publishes nothing.
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        attacker
            .send_to(
                &stun::binding_request(&[3u8; 12], "ENG:remote", b"WRONG"),
                leg.local_addr,
            )
            .await
            .expect("send forged");
        assert!(
            timeout(NEGATIVE, validated.changed()).await.is_err(),
            "a check failing MESSAGE-INTEGRITY publishes nothing"
        );

        // A valid check without USE-CANDIDATE is answered and publishes nothing (§7.3.1.5).
        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        peer.send_to(&plain_check(&[4u8; 12], 100), leg.local_addr)
            .await
            .expect("send plain check");
        let answer = recv(&peer).await.0;
        assert_eq!(
            stun::parse(&answer).expect("parse").message_type,
            stun::BINDING_SUCCESS
        );
        assert!(
            timeout(NEGATIVE, validated.changed()).await.is_err(),
            "a non-nominating check is answered but selects no pair"
        );

        // The nominating check publishes its source.
        peer.send_to(&nominating_check(&[4u8; 12], 100), leg.local_addr)
            .await
            .expect("send check");
        timeout(std::time::Duration::from_secs(1), validated.changed())
            .await
            .expect("published")
            .expect("publisher alive");
        assert_eq!(*validated.borrow_and_update(), Some(peer_addr));
        let _ = recv(&peer).await;

        // A later subscriber starts at the nominated source instead of waiting for the next check.
        assert_eq!(
            *datapath
                .watch_ice_validated(leg.id)
                .expect("still an ICE endpoint")
                .borrow(),
            Some(peer_addr)
        );

        // A higher-priority nomination from another transport re-points it (§8.1.1).
        let (moved, moved_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
        moved
            .send_to(&nominating_check(&[5u8; 12], 200), leg.local_addr)
            .await
            .expect("send check");
        timeout(std::time::Duration::from_secs(1), validated.changed())
            .await
            .expect("re-published")
            .expect("publisher alive");
        assert_eq!(*validated.borrow_and_update(), Some(moved_addr));

        // Clearing the credentials closes the subscription, so a follower stops instead of waiting.
        datapath.set_ice(leg.id, None);
        assert!(
            timeout(std::time::Duration::from_secs(1), validated.changed())
                .await
                .expect("closed promptly")
                .is_err(),
            "the publisher is dropped with the endpoint's ICE state"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_multi_interface_peer_checking_from_every_address_selects_only_the_nominated_one() {
        // The lab bug: a browser with several interfaces checks from each local address and nominates
        // one. Every check is answered, but the path (latch, validated source, media gate) follows the
        // nominated pair only — not whichever address checked last (RFC 8445 §7.3.1.5).
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        datapath.set_ice(
            leg_a.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");
        let mut validated = datapath.watch_ice_validated(leg_a.id).expect("ice");

        let (first, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (nominated, nominated_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (last, _) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;

        // Before any nomination: answered, nothing selected, media from the checking source dropped.
        first
            .send_to(&plain_check(&[1u8; 12], 300), leg_a.local_addr)
            .await
            .expect("check");
        let _ = recv(&first).await;
        assert_eq!(datapath.ice_validated_source(leg_a.id), None);
        first
            .send_to(&rtp(0x1111_1111, 1), leg_a.local_addr)
            .await
            .expect("rtp");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut scratch))
                .await
                .is_err(),
            "no pair is selected before a nomination, so media is not forwarded"
        );

        // The nominated source checks in the middle of two plain checks from other addresses.
        nominated
            .send_to(&nominating_check(&[2u8; 12], 200), leg_a.local_addr)
            .await
            .expect("nominate");
        let _ = recv(&nominated).await;
        last.send_to(&plain_check(&[3u8; 12], 400), leg_a.local_addr)
            .await
            .expect("check");
        let answer = recv(&last).await.0;
        assert_eq!(
            stun::parse(&answer).expect("parse").message_type,
            stun::BINDING_SUCCESS,
            "a non-nominating check is still answered (RFC 8445 §7.3)"
        );

        assert_eq!(
            datapath.ice_validated_source(leg_a.id),
            Some(nominated_addr),
            "the path follows the nominated pair, not the last check"
        );
        assert_eq!(*validated.borrow_and_update(), Some(nominated_addr));
        nominated
            .send_to(&rtp(0x2222_2222, 1), leg_a.local_addr)
            .await
            .expect("rtp");
        assert_eq!(recv(&callee).await.0, rtp(0x2222_2222, 1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_highest_priority_nomination_wins_and_a_lower_one_never_moves_the_path() {
        // RFC 8445 §8.1.1: with several nominated pairs the highest priority is selected. Equal
        // priority may move (RFC 5245 aggressive nomination sets USE-CANDIDATE on every check).
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        datapath.set_ice(
            leg.id,
            Some(IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            }),
        );
        let (high, high_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (low, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (equal, equal_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;

        high.send_to(&nominating_check(&[1u8; 12], 500), leg.local_addr)
            .await
            .expect("nominate");
        let _ = recv(&high).await;
        assert_eq!(datapath.ice_validated_source(leg.id), Some(high_addr));

        low.send_to(&nominating_check(&[2u8; 12], 100), leg.local_addr)
            .await
            .expect("nominate low");
        let _ = recv(&low).await;
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            Some(high_addr),
            "a lower-priority later nomination must not move an established path"
        );

        equal
            .send_to(&nominating_check(&[3u8; 12], 500), leg.local_addr)
            .await
            .expect("nominate equal");
        let _ = recv(&equal).await;
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            Some(equal_addr),
            "an equal-priority nomination may move the path (aggressive nomination)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ice_restart_clears_the_nomination_so_a_lower_priority_pair_can_be_selected() {
        // RFC 8445 §9.1.1.1: new credentials are a new session; the old session's nomination priority
        // must not block it. Same credentials re-installed (no restart) keep the nomination.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let config = |ufrag: &str| IceConfig {
            local_ufrag: ufrag.into(),
            local_pwd: "engpass".into(),
        };
        datapath.set_ice(leg.id, Some(config("ENG")));
        let (old, old_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (new, new_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        old.send_to(&nominating_check(&[1u8; 12], 500), leg.local_addr)
            .await
            .expect("nominate");
        let _ = recv(&old).await;

        datapath.set_ice(leg.id, Some(config("ENG")));
        new.send_to(&nominating_check(&[2u8; 12], 100), leg.local_addr)
            .await
            .expect("nominate");
        let _ = recv(&new).await;
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            Some(old_addr),
            "re-installing the same credentials is not a restart"
        );

        datapath.set_ice(leg.id, Some(config("ENG2")));
        let restarted = stun::client::binding_request_ice(
            &[3u8; 12],
            "ENG2:remote",
            b"engpass",
            100,
            stun::client::IceRole::Controlling(1),
            true,
        );
        new.send_to(&restarted, leg.local_addr)
            .await
            .expect("nominate after restart");
        let _ = recv(&new).await;
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            Some(new_addr),
            "the restarted session starts with no nomination"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_validated_source_never_reports_a_plain_media_latch() {
        // A non-ICE endpoint latches on media (layer 3). That latch is not authenticated by any
        // connectivity check, so it must never be offered as an ICE-validated path.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, _) = phone().await;
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: None,
                    accepted_source: SourceFilter::Any,
                    latch: LatchPolicy::SignalledOnly,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow a");

        phone_a
            .send_to(&rtp(0x0A0A_0A0A, 1), leg_a.local_addr)
            .await
            .expect("send a");
        // Let the datagram be processed (it latches; with no out_dst resolved it goes nowhere else).
        tokio::time::sleep(NEGATIVE).await;
        assert_eq!(
            datapath.ice_validated_source(leg_a.id),
            None,
            "a media latch on a non-ICE endpoint is not an ICE-validated source"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_agent_forwards_a_stun_response_the_responder_would_drop() {
        // The full-agent seam (RFC 7675 consent) delivers Binding *responses* — which the ice-lite
        // responder drops (they are not requests) — to the engine's checker via the events sink.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (events_tx, events_rx) = flume::bounded(16);
        datapath.set_ice_agent(
            leg.id,
            IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            },
            IceAgentMode::RespondAndForward,
            events_tx,
        );
        datapath.advance_clock(5);

        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let response = stun::binding_success_response(&[7u8; 12], peer_addr, Some(b"engpass"));
        peer.send_to(&response, leg.local_addr)
            .await
            .expect("send response");

        let event = timeout(SHORT, events_rx.recv_async())
            .await
            .expect("an event is delivered")
            .expect("the channel stays open");
        assert_eq!(event.endpoint, leg.id);
        assert_eq!(event.source, peer_addr);
        assert_eq!(
            event.arrival_tick,
            FIRST_TICK + 5,
            "stamped at the current logical tick"
        );
        assert_eq!(event.datagram.as_ref(), response.as_slice());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_agent_still_answers_inbound_checks_and_forwards_them() {
        // A full-agent endpoint keeps the ice-lite responder: an inbound check is still answered,
        // and the request is also forwarded to the checker (visibility for later milestones).
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (events_tx, events_rx) = flume::bounded(16);
        datapath.set_ice_agent(
            leg.id,
            IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            },
            IceAgentMode::RespondAndForward,
            events_tx,
        );

        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let check = nominating_check(&[9u8; 12], NOMINATED_PRIORITY);
        peer.send_to(&check, leg.local_addr)
            .await
            .expect("send check");

        let (response, _) = recv(&peer).await;
        assert_eq!(
            stun::parse(&response).expect("parse").message_type,
            stun::BINDING_SUCCESS,
            "the responder still answers inbound checks"
        );
        let event = timeout(SHORT, events_rx.recv_async())
            .await
            .expect("event")
            .expect("open");
        assert_eq!(event.datagram.as_ref(), check.as_slice());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_forward_only_endpoint_answers_nothing_and_adopts_nothing() {
        // A full RFC 8445 agent owns request handling. If the datapath also answered, it would adopt
        // the source behind the agent's back — the agent could then never keep media on the pair it
        // actually selected.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (events_tx, events_rx) = flume::bounded(16);
        datapath.set_ice_agent(
            leg.id,
            IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            },
            IceAgentMode::ForwardOnly,
            events_tx,
        );

        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        // A perfectly valid check — one the responder would have answered and latched.
        let check = nominating_check(&[9u8; 12], NOMINATED_PRIORITY);
        peer.send_to(&check, leg.local_addr)
            .await
            .expect("send check");

        // It reaches the agent...
        let event = timeout(SHORT, events_rx.recv_async())
            .await
            .expect("forwarded")
            .expect("open");
        assert_eq!(event.datagram.as_ref(), check.as_slice());
        // ...and the datapath itself stays silent and adopts nothing.
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, peer.recv_from(&mut scratch))
                .await
                .is_err(),
            "the datapath must not answer on a forward-only endpoint"
        );
        assert_eq!(
            datapath.ice_validated_source(leg.id),
            None,
            "and must not adopt a source the agent has not selected"
        );

        // The agent's own decision is what opens the path.
        datapath.adopt_source(leg.id, peer_addr);
        assert_eq!(datapath.ice_validated_source(leg.id), Some(peer_addr));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn media_flows_only_after_the_agent_adopts_a_source() {
        // The behavioural consequence of forward-only: until ICE selects a pair, nothing is forwarded
        // — media follows ICE's decision, not the first sender to arrive.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (phone_b, addr_b) = phone().await;
        let (events_tx, _events_rx) = flume::bounded(16);
        datapath.set_ice_agent(
            leg_a.id,
            IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            },
            IceAgentMode::ForwardOnly,
            events_tx,
        );
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: Some(addr_b),
                    accepted_source: SourceFilter::Any,
                    latch: LatchPolicy::Off,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("flow a");

        phone_a
            .send_to(&rtp(0x0A0A_0A0A, 1), leg_a.local_addr)
            .await
            .expect("send a");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, phone_b.recv_from(&mut scratch))
                .await
                .is_err(),
            "no media before ICE selects a pair"
        );

        datapath.adopt_source(leg_a.id, addr_a);
        phone_a
            .send_to(&rtp(0x0A0A_0A0A, 2), leg_a.local_addr)
            .await
            .expect("send a again");
        let (data, _) = recv(&phone_b).await;
        assert_eq!(
            data,
            rtp(0x0A0A_0A0A, 2),
            "media flows on the selected pair"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clearing_ice_removes_the_full_agent_forwarding_sink() {
        // `set_ice(_, None)` tears down both the responder creds and the full-agent sink.
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (events_tx, events_rx) = flume::bounded(16);
        // Keep a sender alive so the channel stays *connected* after the map drops its clone — else
        // `recv_async` would resolve to `Disconnected` and mask "nothing was forwarded".
        let _keepalive = events_tx.clone();
        datapath.set_ice_agent(
            leg.id,
            IceConfig {
                local_ufrag: "ENG".into(),
                local_pwd: "engpass".into(),
            },
            IceAgentMode::RespondAndForward,
            events_tx,
        );
        datapath.set_ice(leg.id, None);

        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let response = stun::binding_success_response(&[7u8; 12], peer_addr, Some(b"engpass"));
        peer.send_to(&response, leg.local_addr)
            .await
            .expect("send response");
        assert!(
            timeout(NEGATIVE, events_rx.recv_async()).await.is_err(),
            "a cleared full-agent sink forwards nothing"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn observes_relayed_rtcp_only() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");
        let observations = datapath.observe_rtcp();

        // An RTP packet relays but is not observed (the tap is RTCP-only).
        peer.send_to(&rtp(0x1234_5678, 1), leg_a.local_addr)
            .await
            .expect("rtp");
        assert_eq!(recv(&callee).await.0, rtp(0x1234_5678, 1));

        // An RTCP SR (second byte 200 → PT 72, in 64..=95) relays and is observed.
        let report = vec![0x80u8, 200, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44];
        peer.send_to(&report, leg_a.local_addr).await.expect("rtcp");
        assert_eq!(recv(&callee).await.0, report);

        // The telemetry tap publishes *after* the forward's `send_to` resolves (see
        // `FlowAction::Forward`), so the callee can hold the datagram before the observation is
        // queued. A non-blocking `try_recv` here races that window and fails under load; wait for
        // the observation instead. The negative assertion below stays non-blocking: the RTP was
        // relayed first, so had the tap observed it, it would already sit ahead of this one.
        let observed = timeout(SHORT, observations.recv_async())
            .await
            .expect("the RTCP was observed")
            .expect("the observation channel stays open");
        assert_eq!(observed.endpoint, leg_a.id);
        assert_eq!(observed.destination, callee_addr);
        assert_eq!(&observed.payload[..], &report[..]);
        assert!(observations.try_recv().is_err(), "the RTP was not observed");
    }

    #[tokio::test]
    async fn a_redirect_consumers_refusal_is_counted_on_the_endpoint() {
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        datapath.note_dropped(endpoint.id);
        datapath.note_dropped(endpoint.id);
        assert_eq!(
            datapath.stats(endpoint.id).expect("stats").packets_dropped,
            2
        );
        // An endpoint already released counts nothing and does not panic.
        datapath.remove_endpoint(endpoint.id).await;
        datapath.note_dropped(endpoint.id);
        assert!(datapath.stats(endpoint.id).is_none());
    }
}
