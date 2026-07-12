//! The UDP-loopback datapath backend.
//!
//! Every endpoint is a real `tokio` UDP socket bound on loopback; a per-endpoint receive task
//! applies the installed [`FlowAction`]. [`FlowAction::Forward`] re-emits the datagram out the
//! peer endpoint's socket — modelling the XDP_TX rewrite, including symmetric-RTP **latching**
//! (reply to wherever the peer's packets actually arrive from). This backend needs no privileges
//! or NIC, so it is the CI datapath and the behavioural reference the XDP backend must match.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use siphon_rtp_stun as stun;

use crate::{
    classify, AddressFamily, Datapath, DatapathError, Endpoint, EndpointId, EndpointStats,
    FlowAction, IceConfig, IceDatapathEvent, LatchPolicy, ObservedRtcp, PacketClass, RxPacket,
};

/// Receive buffer size. RTP/RTCP/STUN/DTLS media datagrams sit well under a 1500-byte MTU; this
/// leaves headroom without paying for jumbo frames the media plane never sees.
const MAX_DATAGRAM: usize = 2048;

/// Lock-free per-endpoint counters, mutated from receive tasks and snapshotted by `stats`.
#[derive(Default)]
struct StatsAtomic {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    packets_dropped: AtomicU64,
    /// Logical-clock tick of the last accepted packet (`0` = none), for the media-timeout sweep.
    last_seen: AtomicU64,
}

impl StatsAtomic {
    fn snapshot(&self) -> EndpointStats {
        EndpointStats {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            packets_out: self.packets_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
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

/// What the relay has learned about an endpoint's peer source: where it sends from and the RTP
/// SSRC it carries (for SSRC-consistent re-latch). See `docs/security-and-nat.md` §4 layer 3.
#[derive(Clone, Copy)]
struct LatchState {
    addr: SocketAddr,
    ssrc: Option<u32>,
}

/// Verdict of the latch gate for one packet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LatchOutcome {
    /// Forward this packet (and the latch now reflects its source).
    Accept,
    /// Drop this packet — a new source whose SSRC does not match the latched stream (hijack).
    Reject,
}

/// Shared backend state. Held by the public handle (strong) and by receive tasks (weak), so the
/// strong count reaches zero on teardown and [`Drop`] can abort the parked receive tasks.
struct Inner {
    next_id: AtomicU64,
    /// Logical clock (monotonic ticks) for the media-timeout sweep; advanced via `advance_clock`.
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
    endpoints: DashMap<EndpointId, EndpointEntry>,
    flows: DashMap<EndpointId, FlowAction>,
    /// Per-endpoint latched peer source (address + RTP SSRC). A packet from a new source re-latches
    /// only with a matching SSRC — the RTPBleed/hijack gate, not a blind first-source latch.
    latched: DashMap<EndpointId, LatchState>,
    /// Per-endpoint ICE-lite credentials; when present, STUN checks are answered and the validated
    /// source is adopted as the media path (RFC 8445).
    ice: DashMap<EndpointId, IceConfig>,
    /// Per-endpoint **full-agent** STUN forwarding sink. Present only for endpoints promoted via
    /// [`Datapath::set_ice_agent`]; a STUN datagram on such an endpoint is forwarded here (in
    /// addition to the responder answering inbound checks) so the engine's consent checker can
    /// correlate Binding responses — which the responder path drops. Bounded per-sink; a full sink
    /// drops the event (a lost consent response only delays the refresh, never blocks the reactor).
    ice_events: DashMap<EndpointId, flume::Sender<IceDatapathEvent>>,
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
                if self.ice.contains_key(&endpoint) {
                    // Layer 4 — ICE supersedes blind latching (docs/security-and-nat.md §4 layer 4;
                    // RFC 8445 §7). On an ICE endpoint the STUN connectivity-check responder
                    // (`handle_stun`) is the *only* thing that adopts a media source: media is
                    // forwarded **only** from the STUN-validated latch, and media never creates or
                    // moves that latch. So drop media that arrives before any check has validated a
                    // source, and drop media whose source is not the adopted one — the leg never
                    // blind-latches the first RTP sender. The signalled-source gate (layer 2) and the
                    // SSRC re-latch (layer 3) are subsumed by the authenticated connectivity check.
                    let validated = self
                        .latched
                        .get(&endpoint)
                        .is_some_and(|state| state.addr == source);
                    if !validated {
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                } else {
                    // Layer 2 — signalled-source gate: only the SDP-signalled peer may send here.
                    // This is the RTPBleed fix; an off-path source on another address is dropped
                    // before it can latch or be forwarded. (docs/security-and-nat.md §4 layer 2; RFC
                    // 3264.)
                    if !rule.accepted_source.accepts(source.ip()) {
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Layer 3 — SSRC-consistent latch: a new source re-latches only when it carries
                    // the same RTP SSRC (a genuine NAT rebind), never a hijack spray.
                    // (docs/security-and-nat.md §4 layer 3; RFC 3550 §8.)
                    if rule.latch != LatchPolicy::Off
                        && self.update_latch(endpoint, source, rtp_ssrc(payload))
                            == LatchOutcome::Reject
                    {
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }

                // The packet is accepted — stamp activity for the media-timeout sweep (§4 layer 6).
                in_stats
                    .last_seen
                    .store(self.clock.load(Ordering::Relaxed), Ordering::Relaxed);

                // Forward toward the peer endpoint: prefer its latched source (symmetric RTP) over
                // its configured destination; drop if neither resolves (never forward into the void).
                let destination = self
                    .latched
                    .get(&rule.out_endpoint)
                    .map(|state| state.addr)
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
                match out.0.send_to(payload, destination).await {
                    Ok(sent) => {
                        out.1.packets_out.fetch_add(1, Ordering::Relaxed);
                        out.1.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
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

    /// Apply the SSRC-consistent latch policy for a packet arriving on `endpoint` from `source`.
    /// Returns [`LatchOutcome::Reject`] for a likely hijack (a new source whose RTP SSRC does not
    /// match the latched stream); the caller then drops it. (docs/security-and-nat.md §4 layer 3.)
    fn update_latch(
        &self,
        endpoint: EndpointId,
        source: SocketAddr,
        ssrc: Option<u32>,
    ) -> LatchOutcome {
        // Copy the current state out and drop the read guard before any insert (no re-entrant lock).
        let current = self.latched.get(&endpoint).map(|state| *state);
        match current {
            None => {
                self.latched
                    .insert(endpoint, LatchState { addr: source, ssrc });
                LatchOutcome::Accept
            }
            Some(state) if state.addr == source => {
                // Same path; record the SSRC the first time we can read one.
                if state.ssrc.is_none() && ssrc.is_some() {
                    self.latched
                        .insert(endpoint, LatchState { addr: source, ssrc });
                }
                LatchOutcome::Accept
            }
            Some(state) => match (state.ssrc, ssrc) {
                // A new source that keeps the SSRC is a genuine NAT rebind — follow it.
                (Some(known), Some(seen)) if known == seen => {
                    self.latched
                        .insert(endpoint, LatchState { addr: source, ssrc });
                    LatchOutcome::Accept
                }
                // A new source with a different/unknown SSRC is a spray/hijack — reject, keep latch.
                _ => LatchOutcome::Reject,
            },
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

    fn build(bind_ip: IpAddr, max_endpoints: usize, port_range: Option<(u16, u16)>) -> Self {
        let (redirect_tx, redirect_rx) = flume::unbounded();
        let (observe_tx, observe_rx) = flume::bounded(256);
        Self {
            inner: Arc::new(Inner {
                next_id: AtomicU64::new(0),
                clock: AtomicU64::new(0),
                live: AtomicUsize::new(0),
                max_endpoints,
                bind_ip,
                ports: port_range.map(|(min, max)| PortAllocator::new(min, max)),
                endpoints: DashMap::new(),
                flows: DashMap::new(),
                latched: DashMap::new(),
                ice: DashMap::new(),
                ice_events: DashMap::new(),
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

    /// Resolve the local IP to bind for a requested address family. When the configured `bind_ip`
    /// already matches the family it is used verbatim (so a production v6 bind IP, or a non-default
    /// loopback v4, is honoured); otherwise the loopback of the requested family is used
    /// (`127.0.0.1` for v4, `::1` for v6) — the NIC-free CI posture for a call signalled in a family
    /// the backend was not configured for.
    fn bind_ip_for(&self, family: AddressFamily) -> IpAddr {
        match (self.inner.bind_ip, family) {
            (addr @ IpAddr::V4(_), AddressFamily::V4) => addr,
            (addr @ IpAddr::V6(_), AddressFamily::V6) => addr,
            (_, AddressFamily::V4) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            (_, AddressFamily::V6) => IpAddr::V6(Ipv6Addr::LOCALHOST),
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
        let bound = match &self.inner.ports {
            Some(pool) => Self::bind_in_range(bind_ip, pool).await,
            None => Self::bind_ephemeral(bind_ip, 0).await,
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
        self.alloc_specific_on(self.bind_ip_for(family), port).await
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
        match Self::bind_ephemeral(bind_ip, port).await {
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

    /// Bind a UDP socket on `bind_ip:port` (`port == 0` asks the OS for an ephemeral port) and read
    /// back its local address.
    async fn bind_ephemeral(
        bind_ip: IpAddr,
        port: u16,
    ) -> Result<(UdpSocket, SocketAddr), DatapathError> {
        let socket = UdpSocket::bind((bind_ip, port))
            .await
            .map_err(DatapathError::Bind)?;
        let local_addr = socket.local_addr().map_err(DatapathError::Bind)?;
        Ok((socket, local_addr))
    }

    /// Bind an endpoint on the next free port in the configured range. Tries each reservable port
    /// once; a port reservable in our range but held by another process on the host is released and
    /// skipped. `PoolExhausted` when the whole range is taken.
    async fn bind_in_range(
        bind_ip: IpAddr,
        pool: &PortAllocator,
    ) -> Result<(UdpSocket, SocketAddr), DatapathError> {
        for _ in 0..pool.span() {
            let Some(port) = pool.reserve_next() else {
                return Err(DatapathError::PoolExhausted { limit: pool.span() });
            };
            match Self::bind_ephemeral(bind_ip, port).await {
                Ok(bound) => return Ok(bound),
                Err(_) => pool.release(port),
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

/// The RTP SSRC (RFC 3550 §5.1, bytes 8–11) for latch identity, or `None` when the datagram is not
/// an RTP media packet (too short, wrong version, or RTCP — RFC 5761: RTCP carries no comparable
/// per-stream SSRC at this offset, so it never drives an SSRC re-latch). A purpose-built reader,
/// not the full media parser, because on a muxed socket RTP and RTCP must be told apart by payload
/// type, which `RtpPacket::parse` does not do.
fn rtp_ssrc(payload: &[u8]) -> Option<u32> {
    if payload.len() < 12 || payload[0] >> 6 != 2 {
        return None;
    }
    let payload_type = payload[1] & 0x7F;
    if (64..=95).contains(&payload_type) {
        return None; // RTCP (RFC 5761 §4)
    }
    Some(u32::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
    ]))
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
    let request = match stun::parse(datagram) {
        Ok(message) if message.is_binding_request() => message,
        _ => {
            stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    // The USERNAME must address us (our ufrag first) and MESSAGE-INTEGRITY must verify with our
    // local password — a challenge an off-path attacker cannot forge without the SDP it never saw.
    let addressed_to_us = request
        .username()
        .and_then(|username| username.split(':').next())
        .is_some_and(|ufrag| ufrag == ice.local_ufrag);
    if !addressed_to_us || !stun::verify_message_integrity(datagram, ice.local_pwd.as_bytes()) {
        stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // Valid check: ICE supersedes blind latching — adopt the validated source, and count the check
    // as activity so the media-timeout sweep treats the path as alive.
    inner.latched.insert(
        endpoint,
        LatchState {
            addr: source,
            ssrc: None,
        },
    );
    stats
        .last_seen
        .store(inner.clock.load(Ordering::Relaxed), Ordering::Relaxed);
    let response = stun::binding_success_response(
        &request.transaction_id,
        source,
        Some(ice.local_pwd.as_bytes()),
    );
    match socket.send_to(&response, source).await {
        Ok(sent) => {
            stats.packets_out.fetch_add(1, Ordering::Relaxed);
            stats.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
        }
        Err(error) => {
            tracing::debug!(?endpoint, %error, "failed to send STUN response");
        }
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
        // RFC 7983 demux for ICE: STUN (first byte 0..=3) drives connectivity checks on endpoints
        // that carry ICE credentials.
        if classify(&buffer[..len]) == PacketClass::Stun {
            // Full-agent seam (RFC 7675 consent): forward the raw STUN to the engine's checker so it
            // can correlate its own Binding responses — which the responder below otherwise drops.
            // Bounded sink, drop-on-full; forwarded for requests too (the checker ignores those).
            if let Some(sender) = inner.ice_events.get(&endpoint).map(|entry| entry.clone()) {
                let _ = sender.try_send(IceDatapathEvent {
                    endpoint,
                    source,
                    arrival_tick: inner.clock.load(Ordering::Relaxed),
                    datagram: Bytes::copy_from_slice(&buffer[..len]),
                });
            }
            if let Some(ice) = inner.ice.get(&endpoint).map(|config| config.clone()) {
                handle_stun(
                    &socket,
                    endpoint,
                    source,
                    &buffer[..len],
                    &ice,
                    &inner,
                    &stats,
                )
                .await;
                continue;
            }
            // No ICE credentials: do *not* drop here — fall through to the installed flow. A TURN
            // relay endpoint (`FlowAction::Redirect`, docs/security-and-nat.md §11) must hand
            // whatever the peer sends — including STUN-shaped bytes — to the allocation actor. A
            // media `Forward` endpoint still drops non-RTP inside `dispatch` (the layer-1 demux), so
            // this never lets STUN reach the media latch.
        }
        inner
            .dispatch(endpoint, source, &buffer[..len], &stats)
            .await;
    }
}

impl Datapath for UdpLoopbackDatapath {
    async fn alloc_endpoint(&self) -> Result<Endpoint, DatapathError> {
        self.alloc_on(self.inner.bind_ip).await
    }

    async fn alloc_endpoint_for(&self, family: AddressFamily) -> Result<Endpoint, DatapathError> {
        self.alloc_on(self.bind_ip_for(family)).await
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
        self.inner.flows.insert(endpoint, action);
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
        self.inner.ice_events.remove(&endpoint);
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
        let sent = socket
            .send_to(data, dst)
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

    fn note_activity(&self, endpoint: EndpointId) {
        if let Some(entry) = self.inner.endpoints.get(&endpoint) {
            entry
                .stats
                .last_seen
                .store(self.inner.clock.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }

    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>) {
        match config {
            Some(config) => {
                self.inner.ice.insert(endpoint, config);
            }
            None => {
                self.inner.ice.remove(&endpoint);
                self.inner.ice_events.remove(&endpoint);
            }
        }
    }

    fn set_ice_agent(
        &self,
        endpoint: EndpointId,
        config: IceConfig,
        events: flume::Sender<IceDatapathEvent>,
    ) {
        // Keep the responder (so inbound checks are still answered) and add the forwarding sink so
        // Binding responses reach the engine's consent checker (RFC 7675).
        self.inner.ice.insert(endpoint, config);
        self.inner.ice_events.insert(endpoint, events);
    }

    fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp> {
        self.inner.observe_enabled.store(true, Ordering::Relaxed);
        self.inner.observe_rx.clone()
    }

    /// A clone of the shared Redirect stream; all redirected endpoints feed this one MPMC receiver.
    fn rx(&self) -> flume::Receiver<RxPacket> {
        self.inner.redirect_rx.clone()
    }
}

#[cfg(test)]
mod tests {
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
    fn rtp(ssrc: u32, sequence: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"audio");
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtpbleed_off_path_source_is_gated_out() {
        // RTPBleed regression: an attacker spraying the media port from another address must never
        // latch or be forwarded — only the SDP-signalled peer's media flows.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (peer, peer_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;

        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::signalled(
                    leg_b.id,
                    Some(callee_addr),
                    peer_addr.ip(),
                )),
            )
            .expect("flow a");

        // Attacker races first — the gate rejects it; nothing reaches the callee.
        attacker
            .send_to(&rtp(0xAAAA_AAAA, 1), leg_a.local_addr)
            .await
            .expect("attacker send");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut scratch))
                .await
                .is_err(),
            "off-path attacker media must not be forwarded (RTPBleed)"
        );

        // The signalled peer's media flows.
        peer.send_to(&rtp(0x1234_5678, 1), leg_a.local_addr)
            .await
            .expect("peer send");
        let (data, from) = recv(&callee).await;
        assert_eq!(data, rtp(0x1234_5678, 1));
        assert_eq!(from, leg_b.local_addr);

        // The rejected datagram is counted as dropped.
        let mut dropped = 0;
        for _ in 0..50 {
            dropped = datapath.stats(leg_a.id).expect("stats").packets_dropped;
            if dropped >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(dropped, 1, "attacker datagram counted as dropped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn symmetric_latch_follows_ssrc_rebind_but_rejects_hijack() {
        // Under a symmetric (any-source) leg, the SSRC separates a NAT rebind from a hijack.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (rebind, _) = phone_at(Ipv4Addr::new(127, 0, 0, 5)).await;
        let (hijacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 6)).await;
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;

        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");

        // First source latches and flows.
        peer.send_to(&rtp(0x1111_1111, 1), leg_a.local_addr)
            .await
            .expect("peer send");
        let (data, _) = recv(&callee).await;
        assert_eq!(data, rtp(0x1111_1111, 1));

        // New source, DIFFERENT SSRC — a hijack attempt; rejected, not forwarded.
        hijacker
            .send_to(&rtp(0x9999_9999, 2), leg_a.local_addr)
            .await
            .expect("hijacker send");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut scratch))
                .await
                .is_err(),
            "a wrong-SSRC source must not hijack the latched stream"
        );

        // New source, SAME SSRC — a genuine NAT rebind; re-latches and flows.
        rebind
            .send_to(&rtp(0x1111_1111, 3), leg_a.local_addr)
            .await
            .expect("rebind send");
        let (data, _) = recv(&callee).await;
        assert_eq!(data, rtp(0x1111_1111, 3));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn demux_drops_non_rtp_without_latching() {
        // A non-RTP datagram (e.g. a STUN binding) on the media port must be dropped by the layer-1
        // demux — never forwarded, never latched — even on a symmetric (any-source) leg.
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (sender, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let (callee, callee_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::symmetric(leg_b.id, Some(callee_addr))),
            )
            .expect("flow");

        // STUN-shaped datagram (first byte 0x00) — dropped, not forwarded.
        sender
            .send_to(
                &[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42],
                leg_a.local_addr,
            )
            .await
            .expect("stun send");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, callee.recv_from(&mut scratch))
                .await
                .is_err(),
            "a non-RTP datagram must not be forwarded"
        );

        // A real RTP packet then flows — proving the STUN packet left no latch behind.
        sender
            .send_to(&rtp(0x2222_2222, 1), leg_a.local_addr)
            .await
            .expect("rtp send");
        let (data, _) = recv(&callee).await;
        assert_eq!(data, rtp(0x2222_2222, 1));
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
        assert_eq!(datapath.now_ticks(), 0);
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
        assert_eq!(datapath.now_ticks(), 5);
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
        assert_eq!(datapath.now_ticks(), 0);
        tick_via_trait(&datapath, 3);
        tick_via_trait(&datapath, 4);
        assert_eq!(datapath.now_ticks(), 7);
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
        let check = stun::binding_request(&[9u8; 12], "ENG:remote", b"engpass");
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
        let check = stun::binding_request(&[9u8; 12], "ENG:remote", b"engpass");
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
            Some(7),
            "a valid consent check stamps activity at the current tick"
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
        assert_eq!(event.arrival_tick, 5, "stamped at the current logical tick");
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
            events_tx,
        );

        let (peer, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let check = stun::binding_request(&[9u8; 12], "ENG:remote", b"engpass");
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

        let observed = observations.try_recv().expect("the RTCP was observed");
        assert_eq!(observed.endpoint, leg_a.id);
        assert_eq!(observed.destination, callee_addr);
        assert_eq!(&observed.payload[..], &report[..]);
        assert!(observations.try_recv().is_err(), "the RTP was not observed");
    }
}
