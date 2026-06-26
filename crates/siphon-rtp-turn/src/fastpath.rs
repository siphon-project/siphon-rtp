//! The kernel TURN channel-relay fast-path seam (M-T8).
//!
//! Once a client binds a channel (RFC 5766 §11) the per-packet relay is a fixed rewrite — peer→client
//! prepends a 4-byte ChannelData header and TX's to the client; client→peer strips it and TX's to the
//! peer — that an XDP datapath can do entirely in-kernel. The allocation actor calls this seam when a
//! channel is bound and when it is torn down (expiry / allocation delete); a real implementation
//! translates each [`ChannelRoute`] into the `TURN_PEERS` / `TURN_CHANNELS` map entries
//! (`siphon-rtp-ebpf-common`). The default [`NoFastPath`] is a no-op: the UDP-loopback backend (and
//! any datapath without an XDP channel-relay program) relays channel data in userspace.
//!
//! Only UDP client legs are accelerable — the kernel rewrites UDP, so the actor installs routes only
//! for UDP allocations; TCP/TLS clients always ride the userspace path.

use std::net::SocketAddr;

/// A bound channel's relay, the unit the kernel fast path installs and removes. It carries both
/// directions: peer→client (prepend `channel`, TX to `client` from `listener`) and client→peer
/// (strip the header, TX to `peer` from `relay`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelRoute {
    /// The bound channel number (`0x4000`–`0x7FFF`).
    pub channel: u16,
    /// The client's transport address.
    pub client: SocketAddr,
    /// The server transport the client allocated on (the TX source toward the client).
    pub listener: SocketAddr,
    /// The remote peer's transport address.
    pub peer: SocketAddr,
    /// The allocation's relay endpoint (the TX source toward the peer).
    pub relay: SocketAddr,
}

/// Programs the in-kernel TURN channel-relay maps. Called by the allocation actor on ChannelBind and
/// on teardown; an XDP datapath implements it by poking the BPF maps.
pub trait TurnFastPath: Send + Sync {
    /// Install (or refresh) both directions of a channel relay in the kernel.
    fn install_channel(&self, route: ChannelRoute);
    /// Remove a channel relay (idempotent — removing an absent route is a no-op).
    fn remove_channel(&self, route: ChannelRoute);
}

/// No kernel fast path: channel data is relayed in userspace. The default for the UDP-loopback
/// backend and any datapath without an XDP channel-relay program.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoFastPath;

impl TurnFastPath for NoFastPath {
    fn install_channel(&self, _route: ChannelRoute) {}
    fn remove_channel(&self, _route: ChannelRoute) {}
}
