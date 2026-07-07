//! Kernel routing/neighbour/link queries over rtnetlink, plus the pure extractors that turn the
//! reply messages into the caches' values.
//!
//! Two halves, split so the logic is testable without a NIC:
//! - **pure extractors** ([`next_hop_from_route`], [`neighbour_from_message`],
//!   [`link_mac_from_message`], [`is_usable_nud`]) and the wire-parse helpers
//!   ([`parse_neighbour_message`], [`parse_route_message`]) — no I/O, unit-tested against explicit
//!   netlink byte fixtures;
//! - the **async worker** ([`run_worker`]) that issues `RTM_GETROUTE` / `RTM_GETLINK` /
//!   `RTM_GETNEIGH` on a Tokio netlink socket and writes results into the shared caches, plus the
//!   [`arp_kick`] that primes an unresolved neighbour (RFC 826) without blocking.
//!
//! Message types (`netlink-packet-route`) and the RTM_* request builders (`rtnetlink`) are the same
//! version the worker and the fixtures share, so what the kernel sends and what the tests parse go
//! through one codepath.

use std::net::Ipv4Addr;
use std::sync::Arc;

use futures::TryStreamExt;
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use netlink_packet_route::AddressFamily;
use rtnetlink::{Handle, IpVersion};

use crate::headers::MacAddr;

use super::Shared;

/// The kernel's next-hop decision for a destination: the IPv4 to ARP for and the egress interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NextHop {
    /// The IPv4 whose MAC the frame's destination MAC must be — the destination itself when on-link
    /// (RFC 1122 §3.3.1), else the gateway.
    pub(crate) ip: Ipv4Addr,
    /// The egress interface index (RTA_OIF) — its own MAC becomes the frame's source MAC.
    pub(crate) ifindex: u32,
}

/// A neighbour-table entry reduced to the fields the datapath needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedNeighbour {
    /// The neighbour's IPv4 (NDA_DST).
    pub(crate) ip: Ipv4Addr,
    /// The interface the entry is on (`ndmsg.ndm_ifindex`).
    pub(crate) ifindex: u32,
    /// The link-layer address (NDA_LLADDR), exactly 6 bytes for Ethernet.
    pub(crate) mac: MacAddr,
    /// Whether the NUD state means the `mac` is currently valid to send to.
    pub(crate) usable: bool,
}

/// Errors from querying the kernel over netlink.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NeighborError {
    /// A netlink query round-trip failed.
    #[error("netlink query: {0}")]
    Netlink(String),
}

/// Whether a neighbour-cache NUD state means the entry carries a usable link-layer address.
///
/// Per the kernel neighbour state machine (RFC 826 for ARP; `NUD_*` in `<linux/neighbour.h>`):
/// `REACHABLE`/`STALE`/`DELAY`/`PROBE`/`PERMANENT`/`NOARP` all have a valid `lladdr` (STALE/DELAY/
/// PROBE trigger revalidation but keep sending on the last-known MAC — exactly the kernel's own
/// behaviour). `INCOMPLETE`/`FAILED`/`NONE` do not — the datapath must drop until it resolves.
pub(crate) fn is_usable_nud(state: NeighbourState) -> bool {
    matches!(
        state,
        NeighbourState::Reachable
            | NeighbourState::Stale
            | NeighbourState::Delay
            | NeighbourState::Probe
            | NeighbourState::Permanent
            | NeighbourState::Noarp
    )
}

/// Reduce an `RTM_*ROUTE` reply for `dst` to its next hop, or `None` if it names no egress interface.
///
/// RFC 1122 §3.3.1: a destination with no gateway on its route is **on-link** — the next hop is the
/// destination itself; otherwise the next hop is the route's gateway (RTA_GATEWAY, the default-route
/// gateway in the common case). The egress interface is RTA_OIF.
pub(crate) fn next_hop_from_route(dst: Ipv4Addr, message: &RouteMessage) -> Option<NextHop> {
    let mut gateway: Option<Ipv4Addr> = None;
    let mut oif: Option<u32> = None;
    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(gw)) => gateway = Some(*gw),
            RouteAttribute::Oif(index) => oif = Some(*index),
            _ => {}
        }
    }
    Some(NextHop {
        ip: gateway.unwrap_or(dst),
        ifindex: oif?,
    })
}

/// Reduce an `RTM_*NEIGH` message to `(ip, ifindex, mac, usable)`, or `None` if it is not an IPv4
/// neighbour with a 6-byte Ethernet link-layer address.
pub(crate) fn neighbour_from_message(message: &NeighbourMessage) -> Option<ResolvedNeighbour> {
    let mut ip: Option<Ipv4Addr> = None;
    let mut mac: Option<MacAddr> = None;
    for attribute in &message.attributes {
        match attribute {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) => ip = Some(*addr),
            NeighbourAttribute::LinkLayerAddress(bytes) => mac = mac_from_bytes(bytes),
            _ => {}
        }
    }
    Some(ResolvedNeighbour {
        ip: ip?,
        ifindex: message.header.ifindex,
        mac: mac?,
        usable: is_usable_nud(message.header.state),
    })
}

/// The egress interface's own hardware address (IFLA_ADDRESS) from an `RTM_*LINK` message, or `None`
/// if the interface has no 6-byte Ethernet address (e.g. loopback advertises a 6-byte all-zero one,
/// which is returned as-is; a non-Ethernet L2 with a different length yields `None`).
pub(crate) fn link_mac_from_message(message: &LinkMessage) -> Option<MacAddr> {
    for attribute in &message.attributes {
        if let LinkAttribute::Address(bytes) = attribute {
            if let Some(mac) = mac_from_bytes(bytes) {
                return Some(mac);
            }
        }
    }
    None
}

/// A 6-byte Ethernet MAC from a netlink lladdr payload, or `None` for any other length.
fn mac_from_bytes(bytes: &[u8]) -> Option<MacAddr> {
    let array: [u8; 6] = bytes.try_into().ok()?;
    Some(array)
}

/// Prime the kernel's ARP resolution for `next_hop` without blocking (RFC 826).
///
/// A throwaway UDP datagram addressed to the next hop makes the stack pick the egress route and, if
/// the neighbour is unresolved, kick off ARP — the same way the first real packet to an unresolved
/// neighbour would. We `connect()` (so the kernel routes to `next_hop` and selects its egress) and
/// send one byte to the discard port (RFC 863); the peer drops it. Runs on the resolver worker
/// thread, never the busy-poll datapath thread. All errors are ignored: the kick is best-effort, the
/// next packet retries.
pub(crate) fn arp_kick(next_hop: Ipv4Addr) {
    let Ok(socket) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return;
    };
    // Non-blocking so a full socket buffer can never stall the worker.
    let _ = socket.set_nonblocking(true);
    if socket.connect((next_hop, 9)).is_ok() {
        let _ = socket.send(&[0u8]);
    }
}

/// What one resolve pass produced, so the worker can act (ARP-kick) off the async runtime.
enum WorkerOutcome {
    /// Neighbour resolved and cached — the datapath's next frame to this destination will send.
    Resolved,
    /// Route + link cached, but the neighbour is unresolved; kick ARP for this next hop.
    NeedsArp(Ipv4Addr),
    /// No route to the destination — nothing to cache; the datapath keeps dropping.
    NoRoute,
}

/// Resolve one destination end-to-end and populate the shared caches. Route → egress-link MAC →
/// neighbour MAC. Leaves the neighbour cache empty (and asks for an ARP kick) when the next hop is
/// not yet resolved, so [`super::NeighborResolver::resolve`] keeps returning `Pending` (drop) until
/// it is — the kernel's own first-packet behaviour.
async fn resolve_once(
    handle: &Handle,
    dst: Ipv4Addr,
    shared: &Shared,
) -> Result<WorkerOutcome, NeighborError> {
    let now = shared.now();

    let Some(next_hop) = route_lookup(handle, dst).await? else {
        return Ok(WorkerOutcome::NoRoute);
    };
    shared
        .routes
        .insert(dst, (next_hop.ip, next_hop.ifindex), now);

    // Egress interface MAC (frame source). Re-query only when not already fresh — an interface MAC
    // rarely changes, so this is almost always a cache hit after the first resolve on that link.
    if shared.links.get(&next_hop.ifindex, now).is_none() {
        if let Some(src_mac) = link_mac(handle, next_hop.ifindex).await? {
            shared.links.insert(next_hop.ifindex, src_mac, now);
        }
    }

    match neighbour_mac(handle, next_hop.ifindex, next_hop.ip).await? {
        Some((mac, true)) => {
            shared.neighbors.insert(next_hop.ip, mac, now);
            Ok(WorkerOutcome::Resolved)
        }
        // Absent, or present but INCOMPLETE/FAILED: do not cache a MAC we may not send to.
        Some((_, false)) | None => Ok(WorkerOutcome::NeedsArp(next_hop.ip)),
    }
}

/// `RTM_GETROUTE` for a single destination (kernel FIB lookup, the `ip route get` semantics — the
/// request carries an RTA_DST so rtnetlink omits `NLM_F_DUMP`). Returns the first route that names an
/// egress interface.
async fn route_lookup(handle: &Handle, dst: Ipv4Addr) -> Result<Option<NextHop>, NeighborError> {
    let mut message = RouteMessage::default();
    message.header.address_family = AddressFamily::Inet;
    message.header.destination_prefix_length = 32;
    message
        .attributes
        .push(RouteAttribute::Destination(RouteAddress::Inet(dst)));

    let mut responses = handle.route().get(message).execute();
    while let Some(route) = responses
        .try_next()
        .await
        .map_err(|error| NeighborError::Netlink(error.to_string()))?
    {
        if let Some(next_hop) = next_hop_from_route(dst, &route) {
            return Ok(Some(next_hop));
        }
    }
    Ok(None)
}

/// `RTM_GETLINK` by index — the egress interface's own hardware address (frame source MAC).
async fn link_mac(handle: &Handle, ifindex: u32) -> Result<Option<MacAddr>, NeighborError> {
    let mut responses = handle.link().get().match_index(ifindex).execute();
    while let Some(link) = responses
        .try_next()
        .await
        .map_err(|error| NeighborError::Netlink(error.to_string()))?
    {
        if let Some(mac) = link_mac_from_message(&link) {
            return Ok(Some(mac));
        }
    }
    Ok(None)
}

/// `RTM_GETNEIGH` dump, filtered to the `(ifindex, next_hop)` entry. Returns its `(mac, usable)`, or
/// `None` if the kernel has no entry for that next hop on that interface yet.
async fn neighbour_mac(
    handle: &Handle,
    ifindex: u32,
    next_hop: Ipv4Addr,
) -> Result<Option<(MacAddr, bool)>, NeighborError> {
    let mut responses = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V4)
        .execute();
    while let Some(message) = responses
        .try_next()
        .await
        .map_err(|error| NeighborError::Netlink(error.to_string()))?
    {
        if let Some(neighbour) = neighbour_from_message(&message) {
            if neighbour.ifindex == ifindex && neighbour.ip == next_hop {
                return Ok(Some((neighbour.mac, neighbour.usable)));
            }
        }
    }
    Ok(None)
}

/// The resolver worker thread body: own a single-threaded Tokio runtime + one netlink socket, drain
/// resolution requests, and write answers into the shared caches. Kept off the busy-poll datapath
/// thread and off the engine's shared Tokio reactor — the async netlink I/O lives here alone.
///
/// Exits when the request channel closes (the resolver, hence the only sender, was dropped).
pub(crate) fn run_worker(shared: Arc<Shared>, requests: flume::Receiver<Ipv4Addr>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "neighbor resolver: failed to build runtime; MAC resolution disabled");
            drain_requests(&shared, &requests);
            return;
        }
    };

    let handle = match runtime.block_on(async {
        let (connection, handle, _messages) = rtnetlink::new_connection()?;
        // The connection future services the socket; it progresses on every later `block_on`.
        tokio::spawn(connection);
        Ok::<Handle, std::io::Error>(handle)
    }) {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!(%error, "neighbor resolver: netlink connection failed; MAC resolution disabled");
            drain_requests(&shared, &requests);
            return;
        }
    };

    while let Ok(dst) = requests.recv() {
        match runtime.block_on(resolve_once(&handle, dst, &shared)) {
            Ok(WorkerOutcome::Resolved) => {}
            Ok(WorkerOutcome::NeedsArp(next_hop)) => arp_kick(next_hop),
            Ok(WorkerOutcome::NoRoute) => {
                tracing::debug!(%dst, "neighbor resolver: no route to destination; dropping");
            }
            Err(error) => {
                tracing::warn!(%dst, %error, "neighbor resolver: query failed");
            }
        }
        // Clear the in-flight marker last, so the next datapath miss re-enqueues a fresh attempt
        // (whether this pass resolved it, kicked ARP, or errored).
        shared.clear_in_flight(dst);
    }
}

/// Drain any queued requests (clearing their in-flight markers) when the worker cannot start, so the
/// hot path's in-flight set does not pin a bounded set of destinations forever.
fn drain_requests(shared: &Shared, requests: &flume::Receiver<Ipv4Addr>) {
    while let Ok(dst) = requests.try_recv() {
        shared.clear_in_flight(dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{DecodeError, Parseable};
    use netlink_packet_route::neighbour::NeighbourMessageBuffer;
    use netlink_packet_route::route::RouteMessageBuffer;

    /// Parse raw `ndmsg`+NLA bytes into a [`NeighbourMessage`]; a truncated buffer errors, never
    /// panics. `&bytes` (a `&&[u8]`) so the buffer's referent is the `Sized` `&[u8]` the `Parseable`
    /// impl requires.
    fn parse_neighbour_message(bytes: &[u8]) -> Result<NeighbourMessage, DecodeError> {
        let buffer = NeighbourMessageBuffer::new_checked(&bytes)?;
        NeighbourMessage::parse(&buffer)
    }

    /// Parse raw `rtmsg`+NLA bytes into a [`RouteMessage`]; a truncated buffer errors, never panics.
    fn parse_route_message(bytes: &[u8]) -> Result<RouteMessage, DecodeError> {
        let buffer = RouteMessageBuffer::new_checked(&bytes)?;
        RouteMessage::parse(&buffer)
    }

    // ── Wire fixtures (explicit byte literals, little-endian netlink; never round-tripped) ────────

    /// `ndmsg` + NDA_DST(198.51.100.2) + NDA_LLADDR(02:00:00:00:00:02), state REACHABLE, ifindex 7.
    const NEIGH_REACHABLE: [u8; 32] = [
        // ndmsg: family=AF_INET(2), 3 pad, ifindex=7, state=REACHABLE(0x0002), flags=0, ntype=0
        0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        // NLA NDA_DST: len=8, type=1, value=198.51.100.2
        0x08, 0x00, 0x01, 0x00, 0xc6, 0x33, 0x64, 0x02,
        // NLA NDA_LLADDR: len=10, type=2, value=02:00:00:00:00:02, +2 pad
        0x0a, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    ];

    /// Same neighbour but state INCOMPLETE (0x0001) — a MAC is present but not yet usable.
    const NEIGH_INCOMPLETE: [u8; 32] = [
        0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01,
        0x00, 0xc6, 0x33, 0x64, 0x02, 0x0a, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00,
    ];

    /// `rtmsg` + RTA_OIF(7) + RTA_GATEWAY(198.51.100.1): a route via a gateway.
    const ROUTE_VIA_GATEWAY: [u8; 28] = [
        // rtmsg: af=AF_INET(2), dst_len=0, src_len=0, tos=0, table=254, proto=0, scope=0,
        //        kind=RTN_UNICAST(1), flags=0
        0x02, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // NLA RTA_OIF: len=8, type=4, value=7
        0x08, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00,
        // NLA RTA_GATEWAY: len=8, type=5, value=198.51.100.1
        0x08, 0x00, 0x05, 0x00, 0xc6, 0x33, 0x64, 0x01,
    ];

    /// `rtmsg` + RTA_OIF(7) only: an on-link route (no gateway).
    const ROUTE_ON_LINK: [u8; 20] = [
        0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // NLA RTA_OIF: len=8, type=4, value=7
        0x08, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parses_reachable_neighbour_to_ip_mac_and_usable_state() {
        let message = parse_neighbour_message(&NEIGH_REACHABLE).expect("parse");
        let neighbour = neighbour_from_message(&message).expect("extract");
        assert_eq!(neighbour.ip, Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(neighbour.mac, [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(neighbour.ifindex, 7);
        assert!(neighbour.usable, "REACHABLE carries a usable lladdr");
    }

    #[test]
    fn incomplete_neighbour_parses_but_is_not_usable() {
        let message = parse_neighbour_message(&NEIGH_INCOMPLETE).expect("parse");
        let neighbour = neighbour_from_message(&message).expect("extract");
        assert_eq!(neighbour.ip, Ipv4Addr::new(198, 51, 100, 2));
        assert!(!neighbour.usable, "INCOMPLETE must not be sent to");
    }

    #[test]
    fn truncated_neighbour_bytes_error_never_panic() {
        // Shorter than the 12-byte ndmsg header → new_checked rejects it.
        assert!(parse_neighbour_message(&[0x02, 0x00, 0x00]).is_err());
        // Empty is also an error, not a panic.
        assert!(parse_neighbour_message(&[]).is_err());
    }

    #[test]
    fn route_via_gateway_selects_the_gateway_as_next_hop() {
        let message = parse_route_message(&ROUTE_VIA_GATEWAY).expect("parse");
        let dst = Ipv4Addr::new(203, 0, 113, 5);
        let next_hop = next_hop_from_route(dst, &message).expect("next hop");
        // RFC 1122 §3.3.1: off-link destination → next hop is the gateway, not the destination.
        assert_eq!(next_hop.ip, Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(next_hop.ifindex, 7);
    }

    #[test]
    fn on_link_route_uses_the_destination_as_next_hop() {
        let message = parse_route_message(&ROUTE_ON_LINK).expect("parse");
        let dst = Ipv4Addr::new(198, 51, 100, 42);
        let next_hop = next_hop_from_route(dst, &message).expect("next hop");
        // On-link: next hop is the destination itself (RFC 1122 §3.3.1).
        assert_eq!(next_hop.ip, dst);
        assert_eq!(next_hop.ifindex, 7);
    }

    #[test]
    fn route_without_egress_interface_yields_none() {
        // A route reply carrying no RTA_OIF cannot name an egress → no next hop.
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet;
        message
            .attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(Ipv4Addr::new(
                198, 51, 100, 1,
            ))));
        assert!(next_hop_from_route(Ipv4Addr::new(203, 0, 113, 5), &message).is_none());
    }

    #[test]
    fn truncated_route_bytes_error_never_panic() {
        assert!(parse_route_message(&[0x02, 0x00]).is_err());
    }

    #[test]
    fn nud_usability_matches_the_kernel_state_machine() {
        for usable in [
            NeighbourState::Reachable,
            NeighbourState::Stale,
            NeighbourState::Delay,
            NeighbourState::Probe,
            NeighbourState::Permanent,
            NeighbourState::Noarp,
        ] {
            assert!(is_usable_nud(usable), "{usable:?} should be usable");
        }
        for unusable in [
            NeighbourState::Incomplete,
            NeighbourState::Failed,
            NeighbourState::None,
        ] {
            assert!(
                !is_usable_nud(unusable),
                "{unusable:?} should not be usable"
            );
        }
    }

    #[test]
    fn link_mac_extracts_a_six_byte_hardware_address() {
        let mut message = LinkMessage::default();
        message.header.index = 7;
        message.attributes.push(LinkAttribute::Address(vec![
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        ]));
        assert_eq!(
            link_mac_from_message(&message),
            Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn link_without_six_byte_address_yields_none() {
        let mut message = LinkMessage::default();
        // A 4-byte (non-Ethernet) address is not a MAC.
        message
            .attributes
            .push(LinkAttribute::Address(vec![0x00, 0x00, 0x00, 0x00]));
        assert!(link_mac_from_message(&message).is_none());
    }

    #[test]
    fn arp_kick_does_not_panic_for_a_documentation_range_next_hop() {
        // Sending one throwaway byte toward a TEST-NET-2 next hop must never panic (no route / no
        // permission is swallowed). Deterministic and NIC-free (the datagram goes nowhere).
        arp_kick(Ipv4Addr::new(198, 51, 100, 254));
    }
}
