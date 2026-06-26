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

/// A media datapath: allocates endpoints, installs per-endpoint flows, moves packets, reports stats.
///
/// Methods that touch sockets are `async`; the flow-table and stats operations are synchronous
/// (lock-free maps). Implementors are `Send + Sync` so a single instance is shared across the
/// actor runtime.
pub trait Datapath: Send + Sync {
    /// Allocate and bind a new media endpoint, starting its receive loop.
    fn alloc_endpoint(
        &self,
    ) -> impl std::future::Future<Output = Result<Endpoint, DatapathError>> + Send;

    /// Install (or replace) the flow action for an endpoint.
    fn install_flow(
        &self,
        endpoint: EndpointId,
        action: FlowAction,
    ) -> Result<(), DatapathError>;

    /// Remove an endpoint's flow; subsequent datagrams are dropped until a new flow is installed.
    fn remove_flow(&self, endpoint: EndpointId);

    /// Tear down an endpoint, stopping its receive loop and freeing its socket.
    fn remove_endpoint(
        &self,
        endpoint: EndpointId,
    ) -> impl std::future::Future<Output = ()> + Send;

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
    /// ([`udp::UdpLoopbackDatapath::advance_clock`]) so timeout tests stay deterministic.
    fn now_ticks(&self) -> u64;

    /// The tick of the last **accepted** packet on `endpoint` (`0` if none yet), or `None` if the
    /// endpoint is unknown. Feeds the media-timeout / dead-path sweep (docs/security-and-nat.md §4
    /// layer 6).
    fn last_activity(&self, endpoint: EndpointId) -> Option<u64>;

    /// Install (or clear with `None`) ICE-lite credentials for an endpoint, enabling the datapath to
    /// answer STUN connectivity checks on it and adopt the validated source (RFC 8445, layer 4).
    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>);
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
        assert_eq!(signalled.accepted_source, SourceFilter::Exact(ip(198, 51, 100, 1)));

        let symmetric = ForwardRule::symmetric(endpoint, None);
        assert_eq!(symmetric.latch, LatchPolicy::Symmetric);
        assert_eq!(symmetric.accepted_source, SourceFilter::Any);
    }
}
