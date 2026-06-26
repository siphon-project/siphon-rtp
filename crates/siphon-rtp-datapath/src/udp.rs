//! The UDP-loopback datapath backend.
//!
//! Every endpoint is a real `tokio` UDP socket bound on loopback; a per-endpoint receive task
//! applies the installed [`FlowAction`]. [`FlowAction::Forward`] re-emits the datagram out the
//! peer endpoint's socket — modelling the XDP_TX rewrite, including symmetric-RTP **latching**
//! (reply to wherever the peer's packets actually arrive from). This backend needs no privileges
//! or NIC, so it is the CI datapath and the behavioural reference the XDP backend must match.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use siphon_rtp_stun as stun;

use crate::{
    Datapath, DatapathError, Endpoint, EndpointId, EndpointStats, FlowAction, IceConfig, LatchPolicy,
    ObservedRtcp, RxPacket,
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
    endpoints: DashMap<EndpointId, EndpointEntry>,
    flows: DashMap<EndpointId, FlowAction>,
    /// Per-endpoint latched peer source (address + RTP SSRC). A packet from a new source re-latches
    /// only with a matching SSRC — the RTPBleed/hijack gate, not a blind first-source latch.
    latched: DashMap<EndpointId, LatchState>,
    /// Per-endpoint ICE-lite credentials; when present, STUN checks are answered and the validated
    /// source is adopted as the media path (RFC 8445).
    ice: DashMap<EndpointId, IceConfig>,
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
                // Layer 2 — signalled-source gate: only the SDP-signalled peer may send here. This
                // is the RTPBleed fix; an off-path source on another address is dropped before it
                // can latch or be forwarded. (docs/security-and-nat.md §4 layer 2; RFC 3264.)
                if !rule.accepted_source.accepts(source.ip()) {
                    in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                // Layer 3 — SSRC-consistent latch: a new source re-latches only when it carries the
                // same RTP SSRC (a genuine NAT rebind), never a hijack spray.
                // (docs/security-and-nat.md §4 layer 3; RFC 3550 §8.)
                if rule.latch != LatchPolicy::Off
                    && self.update_latch(endpoint, source, rtp_ssrc(payload)) == LatchOutcome::Reject
                {
                    in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
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
                self.latched.insert(endpoint, LatchState { addr: source, ssrc });
                LatchOutcome::Accept
            }
            Some(state) if state.addr == source => {
                // Same path; record the SSRC the first time we can read one.
                if state.ssrc.is_none() && ssrc.is_some() {
                    self.latched.insert(endpoint, LatchState { addr: source, ssrc });
                }
                LatchOutcome::Accept
            }
            Some(state) => match (state.ssrc, ssrc) {
                // A new source that keeps the SSRC is a genuine NAT rebind — follow it.
                (Some(known), Some(seen)) if known == seen => {
                    self.latched.insert(endpoint, LatchState { addr: source, ssrc });
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
    /// the port/FD-exhaustion guard (docs/security-and-nat.md §5).
    #[must_use]
    pub fn with_max_endpoints(max_endpoints: usize) -> Self {
        let (redirect_tx, redirect_rx) = flume::unbounded();
        let (observe_tx, observe_rx) = flume::bounded(256);
        Self {
            inner: Arc::new(Inner {
                next_id: AtomicU64::new(0),
                clock: AtomicU64::new(0),
                live: AtomicUsize::new(0),
                max_endpoints,
                endpoints: DashMap::new(),
                flows: DashMap::new(),
                latched: DashMap::new(),
                ice: DashMap::new(),
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
}

/// RFC 7983 first-byte demux on a media socket: only RTP/RTCP (128–191) may drive the relay or move
/// the latch. STUN/DTLS/TURN/garbage are dropped in M-S1 (ICE/DTLS land in M-S3/M-S4).
/// See `docs/security-and-nat.md` §4 layer 1.
fn is_rtp_or_rtcp(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(&byte0) if (128..=191).contains(&byte0))
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
        payload[8], payload[9], payload[10], payload[11],
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
        if matches!(buffer[..len].first(), Some(&first) if first <= 3) {
            if let Some(ice) = inner.ice.get(&endpoint).map(|config| config.clone()) {
                handle_stun(&socket, endpoint, source, &buffer[..len], &ice, &inner, &stats).await;
                continue;
            }
            // No ICE credentials: do *not* drop here — fall through to the installed flow. A TURN
            // relay endpoint (`FlowAction::Redirect`, docs/security-and-nat.md §11) must hand
            // whatever the peer sends — including STUN-shaped bytes — to the allocation actor. A
            // media `Forward` endpoint still drops non-RTP inside `dispatch` (the layer-1 demux), so
            // this never lets STUN reach the media latch.
        }
        inner.dispatch(endpoint, source, &buffer[..len], &stats).await;
    }
}

impl Datapath for UdpLoopbackDatapath {
    async fn alloc_endpoint(&self) -> Result<Endpoint, DatapathError> {
        // Reserve a pool slot up front so a concurrent burst cannot overshoot the cap (port/FD
        // exhaustion guard — docs/security-and-nat.md §5). Release the reservation on any failure.
        let reserved = self.inner.live.fetch_add(1, Ordering::AcqRel) + 1;
        if reserved > self.inner.max_endpoints {
            self.inner.live.fetch_sub(1, Ordering::AcqRel);
            return Err(DatapathError::PoolExhausted {
                limit: self.inner.max_endpoints,
            });
        }
        let bind = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .and_then(|socket| socket.local_addr().map(|addr| (socket, addr)));
        let (socket, local_addr) = match bind {
            Ok(bound) => bound,
            Err(error) => {
                self.inner.live.fetch_sub(1, Ordering::AcqRel);
                return Err(DatapathError::Bind(error));
            }
        };
        let socket = Arc::new(socket);
        let id = EndpointId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let stats = Arc::new(StatsAtomic::default());
        let task = tokio::spawn(recv_loop(
            Arc::downgrade(&self.inner),
            id,
            socket.clone(),
            stats.clone(),
        ));
        self.inner
            .endpoints
            .insert(id, EndpointEntry { socket, stats, task });
        Ok(Endpoint { id, local_addr })
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
            entry.task.abort();
            // Release the pool slot only when an endpoint was actually removed (idempotent).
            self.inner.live.fetch_sub(1, Ordering::AcqRel);
        }
        self.inner.flows.remove(&endpoint);
        self.inner.latched.remove(&endpoint);
        self.inner.ice.remove(&endpoint);
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
        let sent = socket.send_to(data, dst).await.map_err(DatapathError::Send)?;
        stats.packets_out.fetch_add(1, Ordering::Relaxed);
        stats.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
        Ok(sent)
    }

    fn stats(&self, endpoint: EndpointId) -> Option<EndpointStats> {
        self.inner.endpoints.get(&endpoint).map(|e| e.stats.snapshot())
    }

    fn now_ticks(&self) -> u64 {
        self.inner.clock.load(Ordering::Relaxed)
    }

    fn last_activity(&self, endpoint: EndpointId) -> Option<u64> {
        self.inner
            .endpoints
            .get(&endpoint)
            .map(|entry| entry.stats.last_seen.load(Ordering::Relaxed))
    }

    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>) {
        match config {
            Some(config) => {
                self.inner.ice.insert(endpoint, config);
            }
            None => {
                self.inner.ice.remove(&endpoint);
            }
        }
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

        let sent = datapath.send(leg.id, addr, b"injected").await.expect("send");
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
        let result = datapath.send(EndpointId(999), "127.0.0.1:5000".parse().expect("addr"), b"x").await;
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
    async fn clock_and_last_activity_track_endpoints() {
        let datapath = UdpLoopbackDatapath::new();
        assert_eq!(datapath.now_ticks(), 0);
        assert_eq!(datapath.last_activity(EndpointId(0)), None, "unknown endpoint");
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        assert_eq!(
            datapath.last_activity(leg.id),
            Some(0),
            "no packets accepted yet"
        );
        datapath.advance_clock(5);
        assert_eq!(datapath.now_ticks(), 5);
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
        peer.send_to(&report, leg_a.local_addr)
            .await
            .expect("rtcp");
        assert_eq!(recv(&callee).await.0, report);

        let observed = observations.try_recv().expect("the RTCP was observed");
        assert_eq!(observed.endpoint, leg_a.id);
        assert_eq!(observed.destination, callee_addr);
        assert_eq!(&observed.payload[..], &report[..]);
        assert!(observations.try_recv().is_err(), "the RTP was not observed");
    }
}
