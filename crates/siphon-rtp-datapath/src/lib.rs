//! The datapath seam for siphon-rtp.
//!
//! Media flows are installed against a [`Datapath`] backend that owns the actual sockets and
//! moves packets. Two backends share this trait: the always-available [`udp::UdpLoopbackDatapath`]
//! (real loopback sockets, NIC-free — used by CI and as the semantic reference) and, later, an
//! XDP/AF_XDP backend selected by capability detection. The trait is the only thing the session
//! manager and media pipeline know about, so neither cares which is underneath.
//!
//! A backend hands out [`Endpoint`]s (a bound socket + its [`EndpointId`]) and applies a
//! [`FlowAction`] per endpoint:
//! - [`FlowAction::Forward`] re-emits each received datagram out a peer endpoint — the relay fast
//!   path (the loopback backend models the XDP_TX rewrite, including symmetric-RTP latching).
//! - [`FlowAction::Redirect`] pushes the datagram onto the [`RxPacket`] stream for a userspace
//!   actor (the SRTP/decode/WS slow path).
//! - [`FlowAction::Drop`] discards it (e.g. a blocked or held leg).
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;

pub mod udp;

/// Opaque handle to an allocated endpoint (one bound socket / media port).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct EndpointId(pub u64);

/// An allocated media endpoint: its handle and the local address it is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Handle used to install flows, send, and read stats.
    pub id: EndpointId,
    /// The bound local address (the port advertised in rewritten SDP).
    pub local_addr: SocketAddr,
}

/// The IP address family a media endpoint binds — the family of the peer's signalled `c=` line
/// (RFC 4566 §5.7 `IP4`/`IP6`). The engine asks the datapath for an endpoint of the family that
/// matches the call's signalled media address, so a `c=IN IP6` call gets a v6 engine endpoint (and
/// the rewritten SDP advertises `c=IN IP6`) and a `c=IN IP4` call gets v4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 (`c=IN IP4`).
    V4,
    /// IPv6 (`c=IN IP6`).
    V6,
}

impl AddressFamily {
    /// The address family of an [`IpAddr`].
    #[must_use]
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }
}

/// The class of a datagram arriving on a muxed media socket, decided by its first byte alone per the
/// RFC 7983 §7 demultiplexing table (the scheme RFC 5764 §5.1.2 defines for a DTLS-SRTP + STUN mux on
/// one 5-tuple). The engine splits the redirected stream of a secure WebRTC leg into its STUN,
/// DTLS-handshake, and SRTP-media sub-streams with this; the datapath uses the same table for its
/// in-datapath ICE (STUN) demux and its RFC 7983 layer-1 media gate — one authoritative table, not
/// three scattered byte-range checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketClass {
    /// STUN — first byte `0..=3` (RFC 8489; ICE connectivity checks, RFC 8445).
    Stun,
    /// DTLS — first byte `20..=63` (the DTLS record layer, RFC 9147 / 6347; DTLS-SRTP keying, RFC 5764).
    Dtls,
    /// RTP or RTCP media — first byte `128..=191` (RFC 3550; RTP/RTCP muxed per RFC 5761). On a secure
    /// leg these are SRTP/SRTCP (RFC 3711).
    Media,
    /// Any other first byte — ZRTP, TURN ChannelData (`64..=79`), or garbage. Not demuxed here: the
    /// datapath drops it on the media path and the secure-leg consumer ignores it.
    Other,
}

/// Classify a datagram by its first byte per the RFC 7983 §7 table. An empty datagram is
/// [`PacketClass::Other`]. This is a pure first-byte test — it does not validate the rest of the
/// datagram (a STUN magic cookie, a DTLS record length, an RTP version); that is each sub-stream
/// parser's job. The four ranges are disjoint, so the classification is unambiguous.
#[must_use]
pub fn classify(datagram: &[u8]) -> PacketClass {
    match datagram.first() {
        Some(0..=3) => PacketClass::Stun,
        Some(20..=63) => PacketClass::Dtls,
        Some(128..=191) => PacketClass::Media,
        _ => PacketClass::Other,
    }
}

/// What the backend does with datagrams arriving at an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowAction {
    /// Relay each datagram out a peer endpoint (the in-kernel-style fast path).
    Forward(ForwardRule),
    /// Hand each datagram to a userspace actor via the [`RxPacket`] stream.
    Redirect,
    /// Discard each datagram.
    Drop,
}

/// Which **source address** may send media to an endpoint — the signalled-source gate that closes
/// the RTPBleed first-packet race (RFC 3264: the offer/answer address is the contract).
/// See [`docs/security-and-nat.md`](../../../docs/security-and-nat.md) §4 layer 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFilter {
    /// Only this exact IP may send. The port is never gated — RTP/RTCP split and re-NAT move it.
    Exact(IpAddr),
    /// Any IP inside this CIDR block — carriers that split RTP/RTCP or re-NAT within a prefix.
    Subnet(IpAddr, u8),
    /// Accept any source. For symmetric-NAT legs where the signalled address is genuinely unusable;
    /// opt-in per leg, never a silent default.
    Any,
}

impl SourceFilter {
    /// Whether `source` is permitted by this filter (address only; the port is never gated).
    #[must_use]
    pub fn accepts(&self, source: IpAddr) -> bool {
        match *self {
            SourceFilter::Any => true,
            SourceFilter::Exact(addr) => addr == source,
            SourceFilter::Subnet(network, prefix) => subnet_contains(network, prefix, source),
        }
    }
}

/// How (and whether) an endpoint learns its peer's real source — the latch lifecycle that follows a
/// genuine NAT rebind but resists a hijack spray.
/// See [`docs/security-and-nat.md`](../../../docs/security-and-nat.md) §4 layer 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatchPolicy {
    /// Never latch; forward only to the configured `out_dst`.
    Off,
    /// Latch only sources that pass the [`SourceFilter`]; re-latch a new source **only** if it
    /// carries the same RTP SSRC (RFC 3550 §8) — a real rebind, not a spray. The safe default.
    SignalledOnly,
    /// Accept and latch the first source regardless of address (symmetric NAT); re-latch is still
    /// SSRC-gated. Opt-in per leg via the `symmetric` profile flag.
    Symmetric,
}

/// A relay rule installed on a receiving endpoint: where its datagrams are forwarded, plus the
/// source gate and latch policy applied to the packets arriving on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardRule {
    /// The endpoint to transmit from — the socket facing the party we forward toward.
    pub out_endpoint: EndpointId,
    /// The configured destination (from negotiated SDP). May be `None` until the answer lands; in
    /// that window forwarding falls back to the latched source, or is suppressed if nothing latched.
    pub out_dst: Option<SocketAddr>,
    /// Source-address gate for packets arriving on the endpoint this rule is installed on. Packets
    /// from any other source are dropped before they can latch or be forwarded (RTPBleed defence).
    pub accepted_source: SourceFilter,
    /// Latch lifecycle for this endpoint's incoming source.
    pub latch: LatchPolicy,
}

impl ForwardRule {
    /// The safe default: forward toward `out_endpoint`/`out_dst`, accept only media whose source IP
    /// is `expected` (the SDP-signalled peer), and latch `SignalledOnly`.
    #[must_use]
    pub fn signalled(
        out_endpoint: EndpointId,
        out_dst: Option<SocketAddr>,
        expected: IpAddr,
    ) -> Self {
        Self {
            out_endpoint,
            out_dst,
            accepted_source: SourceFilter::Exact(expected),
            latch: LatchPolicy::SignalledOnly,
        }
    }

    /// A symmetric-NAT leg: accept any source and latch the first (still SSRC-gated on re-latch).
    /// Opt-in — only where the signalled address is unusable.
    #[must_use]
    pub fn symmetric(out_endpoint: EndpointId, out_dst: Option<SocketAddr>) -> Self {
        Self {
            out_endpoint,
            out_dst,
            accepted_source: SourceFilter::Any,
            latch: LatchPolicy::Symmetric,
        }
    }
}

/// Whether `source` falls within the `network`/`prefix` CIDR block (same address family only).
fn subnet_contains(network: IpAddr, prefix: u8, source: IpAddr) -> bool {
    match (network, source) {
        (IpAddr::V4(network), IpAddr::V4(source)) => {
            let prefix = prefix.min(32);
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(network) & mask) == (u32::from(source) & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(source)) => {
            let prefix = prefix.min(128);
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(network) & mask) == (u128::from(source) & mask)
        }
        _ => false,
    }
}

/// A datagram delivered to userspace by a [`FlowAction::Redirect`] flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxPacket {
    /// The endpoint the datagram arrived on.
    pub endpoint: EndpointId,
    /// The observed source address.
    pub source: SocketAddr,
    /// Receive-time clock reading in **microseconds**, stamped the moment the datagram came off the
    /// wire — the arrival time the RTCP interarrival-jitter estimate (RFC 3550 §6.4.1) needs.
    /// Stamped at *receive*, not at actor-ingest, so it reflects network timing rather than queueing
    /// latency. The loopback backend derives it from its logical clock (deterministic); a real-time
    /// backend (XDP) stamps a monotonic microsecond clock.
    pub arrival: u64,
    /// The datagram payload.
    pub data: Bytes,
}

/// Per-endpoint packet/byte counters. Feeds the control protocol's `query` stats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointStats {
    /// Datagrams received on this endpoint.
    pub packets_in: u64,
    /// Datagrams transmitted from this endpoint.
    pub packets_out: u64,
    /// Bytes received on this endpoint.
    pub bytes_in: u64,
    /// Bytes transmitted from this endpoint.
    pub bytes_out: u64,
    /// Datagrams received but discarded (no flow, `Drop`, or no resolvable destination yet).
    pub packets_dropped: u64,
    /// RFC 3550 §A.1-style forward-gap estimate of inbound RTP media packets **lost on the network**
    /// before reaching this endpoint (missed sequence numbers on the ingress stream). Distinct from
    /// `packets_dropped`, which counts engine-side gate / no-destination discards, not network loss.
    /// A plain Forward relay leg (no transcode actor) has no jitter buffer to derive the exact
    /// expected-minus-received figure, so the datapath folds each accepted packet's sequence into this
    /// fast-path counter (see `siphon_rtp_ebpf_common::loss`); the transcode path reports loss from the
    /// actor's jitter buffer instead and leaves this `0`.
    pub packets_lost: u64,
}

/// Errors from a datapath backend.
#[derive(Debug, thiserror::Error)]
pub enum DatapathError {
    /// Binding a new endpoint socket failed.
    #[error("endpoint bind failed: {0}")]
    Bind(#[source] std::io::Error),
    /// A method referenced an endpoint the backend does not know.
    #[error("unknown endpoint {0:?}")]
    UnknownEndpoint(EndpointId),
    /// The media-port pool is full; no new endpoint can be allocated until one is freed. Guards
    /// against port/FD exhaustion (docs/security-and-nat.md §5).
    #[error("media-port pool exhausted (limit {limit})")]
    PoolExhausted {
        /// The configured maximum number of concurrent endpoints.
        limit: usize,
    },
    /// A specific media port was requested (HA restore — re-binding the exact port a failed primary
    /// used) but it is outside the configured range or already reserved on this node.
    #[error("media port {port} is unavailable (out of range or already in use)")]
    PortUnavailable {
        /// The requested port that could not be reserved.
        port: u16,
    },
    /// Transmitting a datagram failed.
    #[error("send failed: {0}")]
    Send(#[source] std::io::Error),
}

/// ICE-lite credentials for an endpoint — the engine's own short-term credential. Lets the datapath
/// answer STUN connectivity checks (RFC 8445 §7.3) and adopt the validated source as the media path,
/// superseding blind latching. See `docs/security-and-nat.md` §4 layer 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceConfig {
    /// The engine's local ICE username fragment; an incoming check's USERNAME must be
    /// `<local_ufrag>:<remote_ufrag>`.
    pub local_ufrag: String,
    /// The engine's local ICE password; incoming `MESSAGE-INTEGRITY` is verified, and responses are
    /// signed, with this.
    pub local_pwd: String,
}

/// Who answers inbound STUN checks on an endpoint promoted via [`Datapath::set_ice_agent`].
///
/// The distinction matters because whoever answers a check also decides whether its source becomes
/// the media path — and there can only be one such decision-maker per endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceAgentMode {
    /// The datapath keeps its ICE-lite responder: it validates and answers inbound checks itself and
    /// adopts the validated source, *and* forwards every STUN datagram to the engine. This is the
    /// posture for a lite agent that additionally wants to see Binding responses — RFC 7675 consent
    /// freshness, which initiates checks but does not run a checklist.
    RespondAndForward,
    /// The datapath **only forwards**: it answers nothing and adopts nothing. A full RFC 8445 agent
    /// must own request handling, because answering correctly requires state the datapath does not
    /// have — the role and tie-breaker for the §7.3.1.1 conflict check, the checklist for
    /// §7.3.1.3 peer-reflexive discovery, and the nomination flag for §7.3.1.5.
    ///
    /// Consequently the media path stays closed until the agent calls
    /// [`adopt_source`](Datapath::adopt_source): under the layer-4 gate an ICE endpoint forwards media
    /// only from the adopted source, so with nothing adopted, nothing flows. That is the intended
    /// behaviour — media follows ICE's decision, not the first packet to arrive.
    ForwardOnly,
}

/// A raw STUN datagram the datapath forwarded to the engine's ICE agent on a **full-agent**
/// endpoint (see [`Datapath::set_ice_agent`]). The ice-lite responder answers inbound checks in the
/// datapath as before; a full-agent endpoint *additionally* forwards every STUN datagram it sees —
/// crucially the Binding **responses** the responder path drops — so the engine's consent checker
/// (RFC 7675) can correlate its own outbound checks. The agent owns all STUN semantics for these.
#[derive(Clone, Debug)]
pub struct IceDatapathEvent {
    /// The endpoint the datagram arrived on (maps back to a call leg / consent state).
    pub endpoint: EndpointId,
    /// The transport source it arrived from.
    pub source: SocketAddr,
    /// The datapath logical tick at arrival (drives consent correlation on the same clock as the
    /// media-timeout sweep — never `Instant::now()`).
    pub arrival_tick: u64,
    /// The raw STUN datagram bytes.
    pub datagram: Bytes,
}

/// A media datapath: allocates endpoints, installs per-endpoint flows, moves packets, reports stats.
///
/// Methods that touch sockets are `async`; the flow-table and stats operations are synchronous
/// (lock-free maps). Implementors are `Send + Sync` so a single instance is shared across the
/// actor runtime.
pub trait Datapath: Send + Sync {
    /// Allocate and bind a new media endpoint, starting its receive loop. The endpoint binds the
    /// backend's configured/default address family (loopback IPv4 on the loopback backend unless a
    /// bind IP was configured).
    fn alloc_endpoint(
        &self,
    ) -> impl std::future::Future<Output = Result<Endpoint, DatapathError>> + Send;

    /// Allocate and bind a new media endpoint of a specific address family — the family of the
    /// peer's signalled `c=` line (RFC 4566 §5.7), so a `c=IN IP6` call gets a v6 engine endpoint
    /// and a `c=IN IP4` call gets v4. The default delegates to [`alloc_endpoint`](Self::alloc_endpoint),
    /// ignoring the family, for single-family backends (the XDP fast path is IPv4-only); backends that
    /// can bind either family (the loopback backend) override this.
    fn alloc_endpoint_for(
        &self,
        _family: AddressFamily,
    ) -> impl std::future::Future<Output = Result<Endpoint, DatapathError>> + Send {
        self.alloc_endpoint()
    }

    /// Allocate and bind an endpoint on a **specific** port — the HA-restore primitive: a standby
    /// behind a floating IP re-binds the exact port a failed primary advertised, so media survives
    /// without a SIP re-INVITE. The default errors with [`DatapathError::PortUnavailable`] (a backend
    /// with no deterministic port allocator cannot honour a specific port); the loopback backend,
    /// which has a port range, overrides this.
    fn alloc_endpoint_on_port(
        &self,
        _family: AddressFamily,
        port: u16,
    ) -> impl std::future::Future<Output = Result<Endpoint, DatapathError>> + Send {
        async move { Err(DatapathError::PortUnavailable { port }) }
    }

    /// Allocate and bind a new media endpoint on a **specific local IP** — the named-interface
    /// primitive. rtpengine-style per-leg interface selection resolves the control `direction` pair to
    /// a bind address (an `internal` 10.x for one leg, an `external` public/private address for the
    /// other) and asks the datapath to source that leg from it. The IP carries its own family, so this
    /// also lets a v6 leg bind the interface's real v6 address rather than a loopback fallback.
    ///
    /// The default derives the family from `bind_ip` and delegates to
    /// [`alloc_endpoint_for`](Self::alloc_endpoint_for), i.e. it honours the family but ignores the
    /// specific IP — keeping every existing backend compiling. Backends that can bind an arbitrary
    /// local IP (the loopback backend; the XDP fast path for source IPs on its attached NIC) override
    /// this to bind `bind_ip` exactly.
    fn alloc_endpoint_on(
        &self,
        bind_ip: IpAddr,
    ) -> impl std::future::Future<Output = Result<Endpoint, DatapathError>> + Send {
        self.alloc_endpoint_for(AddressFamily::of(bind_ip))
    }

    /// Allocate and bind an endpoint on a **specific local IP and port** — the interface-aware
    /// HA-restore primitive. A standby behind a floating IP re-binds the exact `(local_ip, port)` a
    /// failed primary advertised (the snapshot records the full bound `SocketAddr`), so a call that was
    /// pinned to a named interface resumes on the same source IP. The default ignores `bind_ip` and
    /// delegates to [`alloc_endpoint_on_port`](Self::alloc_endpoint_on_port) (so a backend without a
    /// deterministic port allocator still errors [`DatapathError::PortUnavailable`]); the loopback
    /// backend overrides it to bind the given IP.
    fn alloc_endpoint_on_port_at(
        &self,
        bind_ip: IpAddr,
        port: u16,
    ) -> impl std::future::Future<Output = Result<Endpoint, DatapathError>> + Send {
        self.alloc_endpoint_on_port(AddressFamily::of(bind_ip), port)
    }

    /// Install (or replace) the flow action for an endpoint.
    fn install_flow(&self, endpoint: EndpointId, action: FlowAction) -> Result<(), DatapathError>;

    /// Remove an endpoint's flow; subsequent datagrams are dropped until a new flow is installed.
    fn remove_flow(&self, endpoint: EndpointId);

    /// Tear down an endpoint, stopping its receive loop and freeing its socket.
    fn remove_endpoint(&self, endpoint: EndpointId)
        -> impl std::future::Future<Output = ()> + Send;

    /// Transmit a datagram from `endpoint` to `dst` (e.g. injected media / playback).
    fn send(
        &self,
        endpoint: EndpointId,
        dst: SocketAddr,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<usize, DatapathError>> + Send;

    /// Snapshot an endpoint's counters, or `None` if it is unknown.
    fn stats(&self, endpoint: EndpointId) -> Option<EndpointStats>;

    /// The backend's current logical clock (monotonic ticks). Drives the engine's media-timeout
    /// sweep; the loopback backend's clock is advanced explicitly
    /// ([`advance_clock`](Self::advance_clock)) so timeout tests stay deterministic.
    fn now_ticks(&self) -> u64;

    /// Advance the backend's **logical** clock by `ticks`. The daemon's media-timeout sweeper drives
    /// this ~one tick per wall-second so [`now_ticks`](Self::now_ticks) /
    /// [`last_activity`](Self::last_activity) comparisons stay deterministic under test (never
    /// `Instant::now()`).
    ///
    /// Default: **no-op**. Only a backend whose clock is purely *logical* (the UDP-loopback backend)
    /// overrides this to advance it; a real-time backend (the XDP/AF_XDP fast path) derives its clock
    /// from a monotonic kernel source, so the sweep must not drive it. Keeping the method **additive
    /// and defaulted** means every existing backend keeps compiling, and — crucially — lets the
    /// generic engine runner ([`siphon_rtp_engine::run_with_datapath`]) advance the clock through this
    /// trait rather than an external shim trait, which would hit the orphan rule when implemented for
    /// the out-of-crate `XdpDatapath`.
    ///
    /// [`siphon_rtp_engine::run_with_datapath`]: https://docs.rs/siphon-rtp
    fn advance_clock(&self, _ticks: u64) {}

    /// The backend's current clock in **microseconds** — the finer-grained companion to
    /// [`now_ticks`](Self::now_ticks), used for RTCP interarrival jitter / DLSR (RFC 3550 §6.4.1).
    /// The default derives it from the tick clock (one tick = 20 ms), which keeps the loopback
    /// backend deterministic; a real-time backend (XDP) overrides it with a monotonic µs clock.
    fn now_micros(&self) -> u64 {
        self.now_ticks().saturating_mul(20_000)
    }

    /// The tick of the last **accepted** packet on `endpoint` (`0` if none yet), or `None` if the
    /// endpoint is unknown. Feeds the media-timeout / dead-path sweep (docs/security-and-nat.md §4
    /// layer 6).
    fn last_activity(&self, endpoint: EndpointId) -> Option<u64>;

    /// Stamp `endpoint`'s activity at the current logical tick. The `Forward` fast path stamps
    /// activity itself (it sees every accepted packet), but a `Redirect`-path consumer (SRTP bridge,
    /// media actor, conference) accepts packets in userspace, so it calls this after its own
    /// signalled-source gate to keep the media-timeout sweep accurate. Default no-op for backends that
    /// do not track activity.
    fn note_activity(&self, _endpoint: EndpointId) {}

    /// The peer source a backend has learned in-kernel for `endpoint` via symmetric-RTP latching
    /// (RFC 3550 §8), if any. The engine propagates it to the sibling leg's forward destination so a
    /// NATed peer's real source drives the in-kernel relay (docs/security-and-nat.md §4 layer 3).
    /// Default `None`: the loopback backend resolves the latched source inline when forwarding (it owns
    /// both legs), so only a split userspace/kernel backend (XDP) overrides this.
    fn learned_source(&self, _endpoint: EndpointId) -> Option<SocketAddr> {
        None
    }

    /// Install (or clear with `None`) ICE-lite credentials for an endpoint, enabling the datapath to
    /// answer STUN connectivity checks on it and adopt the validated source (RFC 8445, layer 4).
    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>);

    /// Enable **full-agent** ICE on an endpoint: keep answering inbound checks (the ice-lite
    /// responder, exactly as [`set_ice`](Self::set_ice)) **and** forward every STUN datagram seen on
    /// it — including the Binding *responses* the responder drops — to `events`, so the engine's
    /// consent checker (RFC 7675) can correlate its own outbound checks and detect a dead peer.
    ///
    /// Who answers the STUN connectivity checks arriving on a full-agent endpoint.
    ///
    /// This is not a style choice — it decides who owns the ICE state. See [`IceAgentMode`].
    ///
    /// Additive to `set_ice`; clear via `set_ice(endpoint, None)` or [`remove_endpoint`](Self::remove_endpoint).
    /// The **default** installs the responder only (no forwarding) via `set_ice` and **warns**, because
    /// a backend that takes it cannot do consent at all: no Binding response ever reaches the checker,
    /// so the caller silently gets ice-lite behaviour where it asked for a full agent. The warning is
    /// the point — this degradation used to be invisible. A backend without the seam keeps compiling
    /// and keeps answering inbound checks; it just says so.
    fn set_ice_agent(
        &self,
        endpoint: EndpointId,
        config: IceConfig,
        mode: IceAgentMode,
        events: flume::Sender<IceDatapathEvent>,
    ) {
        let _ = (events, mode);
        tracing::warn!(
            target: "siphon_rtp::datapath",
            ?endpoint,
            "datapath backend has no full-agent ICE seam — installing the responder only; RFC 7675 \
             consent freshness is DISABLED on this endpoint (Binding responses cannot be correlated)"
        );
        self.set_ice(endpoint, Some(config));
    }

    /// The peer transport address a **validated** ICE connectivity check adopted for `endpoint`
    /// (RFC 8445 §7.3), or `None` when no check has validated a source yet — or when the endpoint
    /// carries no ICE credentials at all.
    ///
    /// This is the path an RFC 7675 consent check must probe: the address the peer proved it can
    /// receive on by answering a MESSAGE-INTEGRITY-signed check, **never** the signalled `c=` address
    /// (for a NATed peer that is its unusable private address, so probing it would declare live calls
    /// dead). Distinct from [`learned_source`](Self::learned_source), which reports a *media*-latched
    /// source: on an ICE endpoint only an authenticated check ever moves this one.
    ///
    /// Default `None` — a backend with no ICE responder never adopts a source.
    fn ice_validated_source(&self, _endpoint: EndpointId) -> Option<SocketAddr> {
        None
    }

    /// Adopt `source` as `endpoint`'s media path, on the authority of the engine's ICE agent.
    ///
    /// This is the write side of [`ice_validated_source`](Self::ice_validated_source) and the only
    /// way a [`IceAgentMode::ForwardOnly`] endpoint ever gets a path: the agent calls it when ICE
    /// selects a pair (RFC 8445 §8.1.1), and the layer-4 gate then forwards media from that source
    /// and no other.
    ///
    /// Safe by construction: the agent only selects a pair whose check it authenticated with the
    /// negotiated credentials, so this cannot adopt an unvalidated source — it relocates the same
    /// decision from the datapath's responder to the agent that owns the checklist.
    ///
    /// Default: no-op, for a backend with no ICE support at all.
    fn adopt_source(&self, _endpoint: EndpointId, _source: SocketAddr) {}

    /// A receiver for datagrams delivered by [`FlowAction::Redirect`] flows — the userspace slow path
    /// (SRTP/transcode/WS, and the built-in TURN relay, docs/security-and-nat.md §11). Clone-per-
    /// consumer; all redirected endpoints share this single MPMC stream, so a single dispatcher
    /// should own it and route each [`RxPacket`] to the owning subsystem by [`EndpointId`].
    fn rx(&self) -> flume::Receiver<RxPacket>;

    /// Enable observation of **relayed RTCP** and return a receiver of the observed datagrams, for
    /// telemetry export (e.g. HEP to a VoIPmonitor / Homer collector). Bounded — observations are
    /// dropped under backpressure, never blocking the relay. Idempotent; all callers share one stream.
    fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp>;
}

/// A relayed RTCP datagram observed on the datapath, for telemetry export. `source` sent it; the
/// relay forwarded it to `destination`.
#[derive(Clone, Debug)]
pub struct ObservedRtcp {
    /// The endpoint the RTCP arrived on (maps back to a call leg).
    pub endpoint: EndpointId,
    /// The address the RTCP was received from.
    pub source: SocketAddr,
    /// The address the relay forwarded it to.
    pub destination: SocketAddr,
    /// The RTCP datagram bytes.
    pub payload: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn exact_filter_matches_only_that_ip() {
        let filter = SourceFilter::Exact(ip(198, 51, 100, 7));
        assert!(filter.accepts(ip(198, 51, 100, 7)));
        assert!(!filter.accepts(ip(198, 51, 100, 8)));
        assert!(!filter.accepts(ip(203, 0, 113, 7)));
    }

    #[test]
    fn any_filter_accepts_everything() {
        assert!(SourceFilter::Any.accepts(ip(10, 0, 0, 1)));
        assert!(SourceFilter::Any.accepts(ip(203, 0, 113, 9)));
    }

    #[test]
    fn subnet_filter_matches_within_prefix() {
        let filter = SourceFilter::Subnet(ip(198, 51, 100, 0), 24);
        assert!(filter.accepts(ip(198, 51, 100, 1)));
        assert!(filter.accepts(ip(198, 51, 100, 254)));
        assert!(!filter.accepts(ip(198, 51, 101, 1)));
        // A /0 accepts everything; host bits of the network address are ignored.
        assert!(SourceFilter::Subnet(ip(198, 51, 100, 5), 0).accepts(ip(8, 8, 8, 8)));
    }

    #[test]
    fn subnet_rejects_mismatched_address_family() {
        let v4 = SourceFilter::Subnet(ip(10, 0, 0, 0), 8);
        assert!(!v4.accepts(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rule_constructors_set_gate_and_latch() {
        let endpoint = EndpointId(1);
        let dst: SocketAddr = "203.0.113.5:6000".parse().expect("addr");

        let signalled = ForwardRule::signalled(endpoint, Some(dst), ip(198, 51, 100, 1));
        assert_eq!(signalled.latch, LatchPolicy::SignalledOnly);
        assert_eq!(
            signalled.accepted_source,
            SourceFilter::Exact(ip(198, 51, 100, 1))
        );

        let symmetric = ForwardRule::symmetric(endpoint, None);
        assert_eq!(symmetric.latch, LatchPolicy::Symmetric);
        assert_eq!(symmetric.accepted_source, SourceFilter::Any);
    }

    #[test]
    fn classify_matches_the_rfc_7983_boundaries() {
        // The exact edges of the RFC 7983 §7 table — STUN 0..=3, DTLS 20..=63, media 128..=191, and
        // the gaps (which include TURN ChannelData 64..=79 and ZRTP) that are not demuxed here.
        assert_eq!(classify(&[0]), PacketClass::Stun);
        assert_eq!(classify(&[3]), PacketClass::Stun);
        assert_eq!(classify(&[4]), PacketClass::Other);
        assert_eq!(classify(&[19]), PacketClass::Other);
        assert_eq!(classify(&[20]), PacketClass::Dtls);
        assert_eq!(classify(&[63]), PacketClass::Dtls);
        assert_eq!(classify(&[64]), PacketClass::Other);
        assert_eq!(classify(&[127]), PacketClass::Other);
        assert_eq!(classify(&[128]), PacketClass::Media);
        assert_eq!(classify(&[191]), PacketClass::Media);
        assert_eq!(classify(&[192]), PacketClass::Other);
        assert_eq!(classify(&[255]), PacketClass::Other);
    }

    #[test]
    fn classify_ignores_everything_after_the_first_byte() {
        // The first byte alone decides; trailing bytes never change the class.
        assert_eq!(classify(&[20, 0xFF, 0x00, 0x17]), PacketClass::Dtls);
        assert_eq!(classify(&[128, 0x00]), PacketClass::Media);
        assert_eq!(classify(&[0x00; 20]), PacketClass::Stun);
    }

    #[test]
    fn classify_treats_an_empty_datagram_as_other() {
        assert_eq!(classify(&[]), PacketClass::Other);
    }
}
