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

use std::net::SocketAddr;

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

/// A relay rule: where forwarded datagrams leave and where they go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardRule {
    /// The endpoint to transmit from — the socket facing the party we forward toward.
    pub out_endpoint: EndpointId,
    /// The configured destination (from negotiated SDP). May be `None` until the answer lands;
    /// in that window forwarding is suppressed unless a latched address is available.
    pub out_dst: Option<SocketAddr>,
    /// When set, prefer the address latched from `out_endpoint`'s observed source over `out_dst`
    /// — symmetric RTP / NAT traversal: reply to wherever the peer's packets actually came from.
    pub allow_latch: bool,
}

impl ForwardRule {
    /// A forward rule toward `out_endpoint`/`out_dst` with latching enabled.
    #[must_use]
    pub fn latching(out_endpoint: EndpointId, out_dst: Option<SocketAddr>) -> Self {
        Self {
            out_endpoint,
            out_dst,
            allow_latch: true,
        }
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
    /// Transmitting a datagram failed.
    #[error("send failed: {0}")]
    Send(#[source] std::io::Error),
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
}
