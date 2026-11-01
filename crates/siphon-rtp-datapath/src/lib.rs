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

#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
pub mod dscp;
pub mod udp;
mod udp_relay;

pub use dscp::{Dscp, DscpParseError};
/// The SSRC-consistent latch state machine (docs/security-and-nat.md §4 layer 3) and the RTP SSRC
/// reader it keys on, re-exported so every userspace latch runs the one definition the in-kernel fast
/// path runs.
pub use siphon_rtp_ebpf_common::rewrite::{
    rtp_media_ssrc, source_latch_verdict, SourceLatch, SourceLatchVerdict,
};

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

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            AddressFamily::V4 => "IPv4",
            AddressFamily::V6 => "IPv6",
        })
    }
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

/// Whether reinstalling a flow re-points it at a **different signalled peer**: a re-answer or
/// re-offer that moved the far party's media to another transport (early media from one media
/// server, the final answer from another). `previous` and `next` are the old and new
/// [`ForwardRule::out_dst`] of a rule toward the same peer endpoint.
///
/// The source that peer endpoint latched belongs to the party the signalling just replaced, so a
/// backend that keeps a latch forgets it on a move: otherwise the stale latch keeps steering the
/// reply to the old transport and, the new peer carrying its own SSRC, rejects every packet the new
/// peer sends (docs/security-and-nat.md §4 layer 3). Forgetting the latch never opens the gate: the
/// new peer still latches only through the rule's signalled-source gate (layer 2).
///
/// A first destination (`None` to `Some`) or an unchanged one is not a move, so a hold or refresh
/// re-INVITE keeps a NATed peer's learned source.
#[must_use]
pub fn signalled_peer_moved(previous: Option<SocketAddr>, next: Option<SocketAddr>) -> bool {
    matches!((previous, next), (Some(previous), Some(next)) if previous != next)
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
    /// Hand the RTCP this endpoint receives to the [`FlowAction::Redirect`] stream instead of
    /// forwarding it, so the engine reads it (RFC 3550 §6) and relays it itself; RTP keeps being
    /// forwarded by the backend. Applies only after the gate and latch above have admitted the
    /// datagram, so traffic from an unadmitted source is never handed up. Works for RTCP on its
    /// own port and muxed with RTP on one (RFC 5761 §4 payload-type demux). Default `false`.
    pub rtcp_to_userspace: bool,
}

impl ForwardRule {
    /// This rule, with RTCP handed to userspace (see [`ForwardRule::rtcp_to_userspace`]).
    #[must_use]
    pub fn with_rtcp_to_userspace(mut self) -> Self {
        self.rtcp_to_userspace = true;
        self
    }

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
            rtcp_to_userspace: false,
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
            rtcp_to_userspace: false,
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
    /// An endpoint was asked for in an address family the backend has no address in: a `c=IN IP6`
    /// leg on a relay configured with an IPv4 address alone, or the reverse. The address in a `c=`
    /// line is where the peer sends its media (RFC 4566 §5.7), so there is no usable substitute
    /// and the leg is refused rather than bound somewhere the peer cannot reach.
    #[error(
        "no {family} media address configured: add an interface address in that family, \
         or bridge the leg to the other one with the `address family` flag"
    )]
    NoAddressForFamily {
        /// The family the leg needed.
        family: AddressFamily,
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

/// What the ice-lite responder decided about one inbound STUN datagram — the outcome of
/// [`respond_to_stun_check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StunCheckOutcome {
    /// Not a valid connectivity check addressed to us: drop it silently. Either it is not a Binding
    /// request, its USERNAME does not lead with our ufrag, or its MESSAGE-INTEGRITY does not verify
    /// with our local password.
    Drop,
    /// A check that authenticated: send `response` back to the datagram's source (RFC 8445 §7.3 —
    /// a lite agent answers every valid check). The source becomes the media path only when
    /// `nomination` is `Some`.
    Respond {
        /// The signed Binding success response.
        response: Vec<u8>,
        /// `Some(priority)` when the check carried USE-CANDIDATE: the controlling agent nominates
        /// the pair this check came in on (RFC 8445 §7.3.1.5 / §6.1.3.2 for a lite agent), and
        /// `priority` is the check's PRIORITY attribute (`0` when absent), the pair priority
        /// that orders several nominations (§8.1.1). `None` for a plain check, which is answered
        /// and selects nothing.
        nomination: Option<u32>,
    },
}

/// Whether a nomination of PRIORITY `candidate` may replace the pair already selected with
/// `current` (`None` = nothing selected yet).
///
/// An ice-lite agent has one host candidate per component, so the pair priority is decided by the
/// remote candidate and the check's PRIORITY attribute orders the pairs (RFC 8445 §6.1.2.3, §8.1.1:
/// the highest-priority nominated pair is selected). A lower-priority later nomination never moves
/// an established path; an equal-or-higher one may, which keeps RFC 5245 aggressive nomination
/// (USE-CANDIDATE on every check) working.
#[must_use]
pub fn nomination_supersedes(current: Option<u32>, candidate: u32) -> bool {
    current.is_none_or(|selected| candidate >= selected)
}

/// The ice-lite STUN responder (RFC 8445 §7.3, RFC 5389), as a pure function of the datagram and the
/// endpoint's credentials — no socket, no state.
///
/// Both backends run *this* code rather than their own copy, so the loopback and XDP datapaths can
/// never drift on what authenticates a check or what nominates. The caller does the side-effects:
/// transmit the response to `source`, and, only when the outcome carries a nomination that
/// [`nomination_supersedes`] the current one, adopt `source` as the media path (RFC 8445 §7.3.1.5).
///
/// The check must be a Binding **request** whose USERNAME leads with our local ufrag (RFC 8445
/// §7.3: `<local>:<remote>`) and whose MESSAGE-INTEGRITY verifies under our local password — a
/// challenge an off-path attacker cannot forge without having seen the SDP.
#[must_use]
pub fn respond_to_stun_check(
    datagram: &[u8],
    ice: &IceConfig,
    source: SocketAddr,
) -> StunCheckOutcome {
    let request = match siphon_rtp_stun::parse(datagram) {
        Ok(message) if message.is_binding_request() => message,
        _ => return StunCheckOutcome::Drop,
    };
    let addressed_to_us = request
        .username()
        .and_then(|username| username.split(':').next())
        .is_some_and(|ufrag| ufrag == ice.local_ufrag);
    if !addressed_to_us
        || !siphon_rtp_stun::verify_message_integrity(datagram, ice.local_pwd.as_bytes())
    {
        return StunCheckOutcome::Drop;
    }
    // RFC 8445 §7.3.1.5 / §6.1.3.2: only USE-CANDIDATE nominates; a lite agent selects the pair of
    // a nominating check and nothing else.
    let nomination = siphon_rtp_stun::client::has_use_candidate(&request)
        .then(|| siphon_rtp_stun::client::priority(&request).unwrap_or(0));
    StunCheckOutcome::Respond {
        response: siphon_rtp_stun::binding_success_response(
            &request.transaction_id,
            source,
            Some(ice.local_pwd.as_bytes()),
        ),
        nomination,
    }
}

/// The transport of the client-to-server leg of a TURN allocation (RFC 8656 §3.1). The leg from the
/// server to peers is always UDP; only this one differs.
#[derive(Clone, Debug, Default)]
pub enum TurnCarrier {
    /// Datagrams to and from the TURN server share the endpoint's own UDP socket (the default).
    #[default]
    Udp,
    /// A TCP or TLS stream the engine owns. Wrapped egress is queued here as already-framed bytes
    /// (ChannelData padded to four bytes, RFC 8656 §12.5) and written by the engine's stream
    /// task. The queue is bounded and drop-on-full: late media is worthless, so a stalled stream
    /// sheds packets instead of growing a queue.
    Stream(flume::Sender<bytes::Bytes>),
}

impl PartialEq for TurnCarrier {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Udp, Self::Udp) => true,
            (Self::Stream(left), Self::Stream(right)) => left.same_channel(right),
            _ => false,
        }
    }
}

impl Eq for TurnCarrier {}

/// A live TURN allocation an endpoint relays through (RFC 5766), installed by
/// [`Datapath::set_turn_relay`].
///
/// This is what makes an ICE **relayed** candidate carry traffic rather than just appear in the SDP.
/// A relayed candidate's transport address lives on the TURN server, not on us, so nothing we send
/// from this endpoint reaches the peer directly: it must be wrapped and addressed to the server,
/// which unwraps it and forwards from the relayed address. Inbound traffic makes the same trip in
/// reverse. Without this the candidate would be advertised, possibly nominated, and then blackhole
/// media — worse than never offering it.
///
/// A bound peer rides **ChannelData** (RFC 8656 §12, 4 bytes of overhead on a 20 ms audio stream).
/// A peer that has a permission but no channel yet (the bind is still in flight, or failed) rides
/// Send and Data indications (§11), the fallback the RFC requires clients to support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnRelay {
    /// How the client-to-server leg is carried: the endpoint's own UDP socket, or a TCP/TLS stream
    /// owned by the engine (RFC 8656 §3.1).
    pub carrier: TurnCarrier,
    /// The TURN server's transport address — where every wrapped datagram is actually sent, and the
    /// only source inbound relayed traffic is accepted from.
    pub server: SocketAddr,
    /// Bound peer → channel number (RFC 5766 §11, `0x4000`..=`0x7FFF`). A destination absent from
    /// this list is **not** relayed: it is sent directly, which is correct for the TURN server itself
    /// (allocation requests) and for a peer we reach over a host or server-reflexive candidate.
    pub channels: Vec<(SocketAddr, u16)>,
    /// Peers the server holds a permission for (RFC 8656 §9), channel-bound or not. Egress to a
    /// permitted peer with no channel goes out as a Send indication, and a Data indication is only
    /// accepted from a permitted peer: the server relays nothing else, so an indication naming any
    /// other peer is not from an allocation we made.
    pub permitted: Vec<SocketAddr>,
}

impl TurnRelay {
    /// Whether the server relays `peer`'s traffic to us: it has a permission, or a bound channel
    /// (a channel binding installs a permission as a side effect, RFC 8656 §12).
    #[must_use]
    pub fn is_permitted(&self, peer: SocketAddr) -> bool {
        self.permitted.contains(&peer) || self.channel_for(peer).is_some()
    }

    /// The channel bound for `peer`, if any — i.e. whether traffic to it must be relay-wrapped.
    #[must_use]
    pub fn channel_for(&self, peer: SocketAddr) -> Option<u16> {
        self.channels
            .iter()
            .find(|(bound, _)| *bound == peer)
            .map(|(_, channel)| *channel)
    }

    /// The peer a bound channel belongs to — how an inbound `ChannelData` message's source is
    /// rewritten back to the peer that actually sent it, so everything above this layer sees the
    /// peer's address and never the TURN server's.
    #[must_use]
    pub fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        self.channels
            .iter()
            .find(|(_, bound)| *bound == channel)
            .map(|(peer, _)| *peer)
    }
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
    ///
    /// `0` is load-bearing, not merely conventional: the sweep distinguishes a call whose media path
    /// *died* from one that has not carried a packet **yet** (still in setup) by whether any of its
    /// endpoints reports a non-zero tick, and gives the two different ceilings. A backend must
    /// therefore never let [`now_ticks`](Self::now_ticks) report `0` while it is running, or a packet
    /// accepted in that first tick stamps the sentinel and reads back as one that never arrived. The
    /// loopback backend starts its logical clock at one for exactly this reason; the cost of getting
    /// it wrong is bounded (one tick of the longer ceiling, self-correcting on the next packet), but
    /// it makes the sweep's reasoning untrue.
    fn last_activity(&self, endpoint: EndpointId) -> Option<u64>;

    /// Stamp `endpoint`'s activity at the current logical tick. The `Forward` fast path stamps
    /// activity itself (it sees every accepted packet), but a `Redirect`-path consumer (SRTP bridge,
    /// media actor, conference) accepts packets in userspace, so it calls this after its own
    /// signalled-source gate to keep the media-timeout sweep accurate. Default no-op for backends that
    /// do not track activity.
    fn note_activity(&self, _endpoint: EndpointId) {}

    /// Count one datagram a `Redirect`-path consumer refused (source gate, failed authentication,
    /// latch rejection) in `endpoint`'s `packets_dropped`. The `Forward` fast path counts its own
    /// drops; a redirected packet was counted as received and is otherwise never counted again, so a
    /// userspace path refusing every packet reads as `packets_in` climbing with nothing dropped and
    /// nothing sent — which is what made a whole direction of a call silently disappear. Default no-op
    /// for a backend with no userspace counters.
    fn note_dropped(&self, _endpoint: EndpointId) {}

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

    /// Follow the source ICE validates for `endpoint`: the push side of
    /// [`ice_validated_source`](Self::ice_validated_source), for a consumer that owns a leg's egress
    /// in userspace and has to aim it at the valid pair without polling. RFC 8445 §12.1.1: a lite
    /// agent "MUST NOT send data until it has a valid list that contains at least one valid pair for
    /// each component", and then sends to that pair's remote candidate. An ice-lite endpoint's valid
    /// pair is the source of the check its responder authenticated, so this is the only signal such a
    /// consumer gets.
    ///
    /// The receiver holds the validated source (`None` until a check validates one) and changes
    /// whenever the responder or [`adopt_source`](Self::adopt_source) adopts a different one. Its
    /// sender is dropped, closing the receiver, when the endpoint's ICE credentials are cleared or the
    /// endpoint is removed.
    ///
    /// `None` for an endpoint that carries no ICE credentials, whose traffic no check gates, and by
    /// default for a backend without the seam, whose consumer then keeps its pre-validation behaviour
    /// rather than waiting forever for a source nothing will publish.
    fn watch_ice_validated(
        &self,
        _endpoint: EndpointId,
    ) -> Option<tokio::sync::watch::Receiver<Option<SocketAddr>>> {
        None
    }

    /// The address `endpoint` is currently **latching** to — the peer's observed source, adopted by
    /// symmetric RTP (docs/security-and-nat.md §4 layer 3) or written by an ICE selection — or
    /// `None` when nothing has been observed yet.
    ///
    /// The read side of what [`LatchPolicy`] maintains, for a caller that has to take a *live* flow
    /// over and keep sending where the peer is actually reachable rather than where its SDP said it
    /// would be. A NATed peer's `c=` port is routinely not the one it sends from (RFC 3264 offers
    /// the signalled address; symmetric RTP is what makes the real one usable), so a takeover that
    /// re-derived the destination from the signalling would break exactly the calls the latch exists
    /// for. Distinct from [`ice_validated_source`](Self::ice_validated_source), which is deliberately
    /// `None` on a non-ICE endpoint because no connectivity check ever authenticated the latch —
    /// this reports the media path as it stands, with no claim about how it was learned, and is
    /// therefore for continuity only, never for a trust decision.
    ///
    /// Default: `None`, for a backend that keeps no latch state.
    fn latched_source(&self, _endpoint: EndpointId) -> Option<SocketAddr> {
        None
    }

    /// The RTP SSRC of the stream `endpoint`'s ingress latch adopted (RFC 3550 §8), when the backend
    /// keeps one: the stream a `Forward` relay has been carrying from that endpoint's peer.
    ///
    /// For continuity only, like [`latched_source`](Self::latched_source). The engine reads it when a
    /// relayed stream is replaced by one the engine originates (a leg moved into a conference room),
    /// so it can say `BYE` for the stream the other party was receiving (RFC 3550 §6.6).
    ///
    /// Default: `None`, for a backend that keeps no per-endpoint SSRC (the XDP kernel latch).
    fn latched_ssrc(&self, _endpoint: EndpointId) -> Option<u32> {
        None
    }

    /// Install (or clear with `None`) the TURN allocation `endpoint` relays through (RFC 5766).
    ///
    /// While installed, traffic to a **bound peer** is wrapped in ChannelData and sent to the TURN
    /// server instead of the peer, and inbound ChannelData from that server is unwrapped with its
    /// source rewritten back to the peer — so every layer above this one, from the ICE agent's
    /// connectivity checks to the media relay, keeps working in terms of the peer's own address and
    /// never learns a relay is in the path.
    ///
    /// A destination **not** in [`TurnRelay::channels`] is sent directly and untouched. That is what
    /// keeps the allocation's own requests (addressed to the server) and any peer reached over a host
    /// or server-reflexive candidate on the direct path.
    ///
    /// Default: a no-op that **warns**, for a backend with no relay seam. The warning is the point —
    /// a backend that silently ignored this would advertise a relayed candidate it cannot carry, and
    /// a peer that nominated it would get a call that connects and then has no audio.
    fn set_turn_relay(&self, endpoint: EndpointId, relay: Option<TurnRelay>) {
        if relay.is_some() {
            tracing::warn!(
                target: "siphon_rtp::datapath",
                ?endpoint,
                "datapath backend has no TURN relay seam — a relayed ICE candidate cannot carry \
                 media on this backend and must not be advertised"
            );
        }
    }

    /// Deliver a datagram the TURN server sent on the allocation's own TCP/TLS stream (a ChannelData
    /// message or a Data indication, RFC 8656 §11.4, §12) as if it had arrived on `endpoint`'s
    /// socket from the server: it is de-encapsulated against the installed [`TurnRelay`] (unbound
    /// channels and unpermitted peers are dropped) and then passes the same ICE gate, STUN
    /// routing, source gate, latch, stats and flows as any received datagram. Returns whether the
    /// datagram was accepted for processing.
    ///
    /// Default: `false`. Only a backend with a TURN relay seam delivers a stream's datagrams.
    fn ingest_relayed(
        &self,
        endpoint: EndpointId,
        frame: &[u8],
    ) -> impl std::future::Future<Output = bool> + Send {
        let _ = (endpoint, frame);
        async { false }
    }

    /// The TURN relay currently installed on `endpoint` by [`Self::set_turn_relay`], if any. A
    /// read-back for tests and diagnostics: which peers are permitted and which have a channel.
    /// Default: `None`.
    fn turn_relay(&self, endpoint: EndpointId) -> Option<TurnRelay> {
        let _ = endpoint;
        None
    }

    /// Whether this backend can actually relay through a TURN allocation ([`Self::set_turn_relay`]).
    ///
    /// Gathering consults this **before** it advertises a relayed candidate: on a backend that
    /// cannot, the candidate is not offered at all, so a peer can never nominate a path that would
    /// blackhole. Default `false` — a backend opts in by implementing the seam.
    fn supports_turn_relay(&self) -> bool {
        false
    }

    /// A receiver for datagrams delivered by [`FlowAction::Redirect`] flows — the userspace slow path
    /// (SRTP/transcode/WS, and the built-in TURN relay, docs/security-and-nat.md §11). Clone-per-
    /// consumer; all redirected endpoints share this single MPMC stream, so a single dispatcher
    /// should own it and route each [`RxPacket`] to the owning subsystem by [`EndpointId`].
    fn rx(&self) -> flume::Receiver<RxPacket>;

    /// Enable observation of **relayed RTCP** and return a receiver of the observed datagrams, for
    /// telemetry export (e.g. HEP to a VoIPmonitor / Homer collector). Bounded — observations are
    /// dropped under backpressure, never blocking the relay. Idempotent; all callers share one stream.
    fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp>;

    /// A sender into the [`Self::observe_rtcp`] stream for a `Redirect`-path consumer. The datapath
    /// only hands a redirected datagram on, so the RTCP of a leg carried in userspace — an SRTP or
    /// DTLS bridge, a transcoded or locally answered call — is seen only by the consumer, after it
    /// decrypts it. The consumer publishes that plaintext here so the leg's reports reach telemetry
    /// the same way a relayed leg's do. `None` while nothing observes, so no consumer copies RTCP
    /// nobody reads. Default `None`, for a backend with no observation stream.
    fn rtcp_tap(&self) -> Option<flume::Sender<ObservedRtcp>> {
        None
    }
}

/// An RTCP datagram observed for telemetry export: relayed by the datapath, or published by a
/// `Redirect`-path consumer through [`Datapath::rtcp_tap`]. `source` sent it; it was forwarded to
/// `destination`. Always plaintext — a consumer publishes what it decrypted.
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

impl ObservedRtcp {
    /// Offer one RTCP datagram to a [`Datapath::rtcp_tap`] sender without blocking: dropped when the
    /// stream is full, because telemetry must never delay media. A no-op without a tap.
    pub fn offer(
        tap: Option<&flume::Sender<ObservedRtcp>>,
        endpoint: EndpointId,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) {
        if let Some(tap) = tap {
            let _ = tap.try_send(Self {
                endpoint,
                source,
                destination,
                payload: Bytes::copy_from_slice(payload),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn signalled_peer_moved_only_when_a_known_destination_changes() {
        let early = SocketAddr::new(ip(192, 0, 2, 10), 37322);
        let answer = SocketAddr::new(ip(198, 51, 100, 20), 21818);
        let same_box_new_port = SocketAddr::new(ip(192, 0, 2, 10), 37324);
        assert!(signalled_peer_moved(Some(early), Some(answer)));
        assert!(signalled_peer_moved(Some(early), Some(same_box_new_port)));
        assert!(!signalled_peer_moved(Some(early), Some(early)));
        assert!(!signalled_peer_moved(None, Some(answer)));
        assert!(!signalled_peer_moved(Some(early), None));
        assert!(!signalled_peer_moved(None, None));
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

    // --- The shared ice-lite responder (both backends run this) ----------------------------------

    fn responder_config() -> IceConfig {
        IceConfig {
            local_ufrag: "engineUfrag".to_string(),
            local_pwd: "enginePasswordThatIsLongEnough".to_string(),
        }
    }

    fn responder_peer() -> SocketAddr {
        "198.51.100.10:5000".parse().expect("addr")
    }

    #[test]
    fn responder_answers_a_check_signed_with_our_password() {
        let config = responder_config();
        let check = siphon_rtp_stun::binding_request(
            &[1u8; 12],
            &format!("{}:peerUfrag", config.local_ufrag),
            config.local_pwd.as_bytes(),
        );
        let StunCheckOutcome::Respond {
            response,
            nomination,
        } = respond_to_stun_check(&check, &config, responder_peer())
        else {
            panic!("a valid check must be answered");
        };
        // A plain check (no USE-CANDIDATE) is answered but nominates nothing (RFC 8445 §7.3.1.5).
        assert_eq!(nomination, None);
        // The response is itself signed, so the peer can authenticate us in turn (RFC 5389 §15.4).
        assert!(siphon_rtp_stun::verify_message_integrity(
            &response,
            config.local_pwd.as_bytes()
        ));
    }

    fn nominating_check(config: &IceConfig, priority: u32, use_candidate: bool) -> Vec<u8> {
        siphon_rtp_stun::client::binding_request_ice(
            &[2u8; 12],
            &format!("{}:peerUfrag", config.local_ufrag),
            config.local_pwd.as_bytes(),
            priority,
            siphon_rtp_stun::client::IceRole::Controlling(7),
            use_candidate,
        )
    }

    #[test]
    fn responder_reports_the_priority_of_a_use_candidate_check() {
        let config = responder_config();
        let check = nominating_check(&config, 0x7E00_01FF, true);
        let StunCheckOutcome::Respond { nomination, .. } =
            respond_to_stun_check(&check, &config, responder_peer())
        else {
            panic!("a valid check must be answered");
        };
        assert_eq!(nomination, Some(0x7E00_01FF));
    }

    #[test]
    fn responder_answers_but_does_not_nominate_a_check_without_use_candidate() {
        let config = responder_config();
        let check = nominating_check(&config, 0x7E00_01FF, false);
        let StunCheckOutcome::Respond { nomination, .. } =
            respond_to_stun_check(&check, &config, responder_peer())
        else {
            panic!("a valid check must be answered");
        };
        assert_eq!(nomination, None, "PRIORITY alone is not a nomination");
    }

    #[test]
    fn a_nomination_supersedes_nothing_lower_and_everything_equal_or_higher() {
        // RFC 8445 §8.1.1: the highest-priority nominated pair wins; equal may move (aggressive
        // nomination re-nominates on every check).
        assert!(nomination_supersedes(None, 0));
        assert!(nomination_supersedes(Some(100), 101));
        assert!(nomination_supersedes(Some(100), 100));
        assert!(!nomination_supersedes(Some(100), 99));
    }

    #[test]
    fn responder_drops_a_check_signed_with_the_wrong_password() {
        // An off-path attacker who never saw the SDP cannot forge MESSAGE-INTEGRITY — this is the
        // gate that makes ICE adoption safe (docs/security-and-nat.md §4 layer 4).
        let config = responder_config();
        let forged = siphon_rtp_stun::binding_request(
            &[1u8; 12],
            &format!("{}:peerUfrag", config.local_ufrag),
            b"not-our-password",
        );
        assert_eq!(
            respond_to_stun_check(&forged, &config, responder_peer()),
            StunCheckOutcome::Drop
        );
    }

    #[test]
    fn responder_drops_a_check_addressed_to_a_different_ufrag() {
        // RFC 8445 §7.3: the USERNAME is `<local>:<remote>`, so a check whose first half is not our
        // ufrag is not addressed to this endpoint even if it somehow verifies.
        let config = responder_config();
        let misaddressed = siphon_rtp_stun::binding_request(
            &[1u8; 12],
            "someoneElse:peerUfrag",
            config.local_pwd.as_bytes(),
        );
        assert_eq!(
            respond_to_stun_check(&misaddressed, &config, responder_peer()),
            StunCheckOutcome::Drop
        );
    }

    #[test]
    fn responder_drops_non_requests_and_garbage() {
        let config = responder_config();
        // A Binding *response* is not a check to answer — answering one would be a reflection loop.
        let response = siphon_rtp_stun::binding_success_response(
            &[1u8; 12],
            responder_peer(),
            Some(config.local_pwd.as_bytes()),
        );
        assert_eq!(
            respond_to_stun_check(&response, &config, responder_peer()),
            StunCheckOutcome::Drop
        );
        // Truncated / non-STUN bytes must not panic.
        assert_eq!(
            respond_to_stun_check(&[], &config, responder_peer()),
            StunCheckOutcome::Drop
        );
        assert_eq!(
            respond_to_stun_check(&[0x00, 0x01, 0xFF], &config, responder_peer()),
            StunCheckOutcome::Drop
        );
    }
}
