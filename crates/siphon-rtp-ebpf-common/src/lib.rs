//! The XDP map ABI: `#[repr(C)]` POD types shared verbatim between the kernel XDP classifier
//! (`siphon-rtp-ebpf`, no_std nightly) and the userspace loader (`siphon-rtp-datapath`,
//! `feature = "xdp"`). The layout **is** the kernel ABI contract, so the size/offset tests below
//! guard it — a field reorder that silently changed the map value would corrupt every flow.
//!
//! It mirrors the userspace security model 1:1: [`FlowAction::kind`] ↔ `FlowAction` (Forward/
//! Redirect/Drop), [`FlowAction::source_kind`] ↔ `SourceFilter` (Any/Exact/Subnet), and
//! [`FlowAction::latch_policy`] ↔ `LatchPolicy` (Off/SignalledOnly/Symmetric). The kernel program
//! enforces the same RTPBleed source-gate and SSRC-consistent latch the loopback backend does.
//!
//! IPv4 only for now (the media plane is IPv4 first); the v6 widening of the key/action is tracked
//! with the multi-interface / IPv4↔IPv6 work.
#![cfg_attr(not(test), no_std)]

/// Pure, `no_std` relay math (RFC 1624 incremental checksum fixup + RFC 3550 §8 SSRC-consistent
/// latch state machine) shared by the in-kernel XDP_TX fast path and its host-side tests/benches.
pub mod rewrite;

/// Flow action discriminants ([`FlowAction::kind`]).
pub mod action {
    /// Discard the datagram.
    pub const DROP: u8 = 0;
    /// Relay out the peer endpoint (XDP_TX fast path).
    pub const FORWARD: u8 = 1;
    /// Redirect to userspace via AF_XDP (the media slow path).
    pub const REDIRECT: u8 = 2;
}

/// Source-gate discriminants ([`FlowAction::source_kind`]) — mirrors `SourceFilter`.
pub mod source {
    /// Accept any source IP (symmetric-NAT opt-in).
    pub const ANY: u8 = 0;
    /// Accept only the exact signalled IP.
    pub const EXACT: u8 = 1;
    /// Accept any IP within the prefix.
    pub const SUBNET: u8 = 2;
}

/// Latch-policy discriminants ([`FlowAction::latch_policy`]) — mirrors `LatchPolicy`.
pub mod latch {
    /// Never latch; forward only to the configured destination.
    pub const OFF: u8 = 0;
    /// Latch only signalled sources; re-latch a new source only on a matching SSRC.
    pub const SIGNALLED: u8 = 1;
    /// Accept and latch the first source (symmetric NAT); re-latch still SSRC-gated.
    pub const SYMMETRIC: u8 = 2;
}

/// Key into the `FLOWS` map: the engine-local IPv4 transport a packet is destined to.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    /// Engine-local IPv4 address (network byte order).
    pub local_ipv4: u32,
    /// Engine-local UDP port (network byte order).
    pub local_port: u16,
    /// Padding to an 8-byte value (keeps the map key layout fixed).
    pub _pad: u16,
}

/// Value in the `FLOWS` map: the relay rule plus its mutable in-kernel latch state.
///
/// The configured fields (`source_*`, `out_*`, policies) are written by the loader; the `latched_*`
/// fields are updated in-kernel as the peer's real source is learned (symmetric RTP).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FlowAction {
    /// One of [`action`].
    pub kind: u8,
    /// One of [`latch`].
    pub latch_policy: u8,
    /// One of [`source`].
    pub source_kind: u8,
    /// Subnet prefix length when `source_kind == source::SUBNET`.
    pub source_prefix: u8,
    /// Accepted source IPv4 (network byte order) for exact/subnet gating.
    pub source_ipv4: u32,
    /// Forward destination IPv4 (network byte order).
    pub out_ipv4: u32,
    /// Engine-local IPv4 to transmit from on XDP_TX (network byte order).
    pub out_local_ipv4: u32,
    /// Forward destination UDP port (network byte order).
    pub out_port: u16,
    /// Engine-local UDP port to transmit from (network byte order).
    pub out_src_port: u16,
    /// Latched peer source IPv4 in **host** order (the kernel writes `from_be_bytes` of the wire
    /// address; see `siphon-rtp-ebpf::forward_in_kernel`). Valid when `latch_valid != 0`.
    pub latched_ipv4: u32,
    /// Latched peer RTP SSRC (host order); the re-latch consistency key.
    pub latched_ssrc: u32,
    /// Latched peer source port in **host** order (the kernel writes `from_be_bytes` of the wire port).
    pub latched_port: u16,
    /// Whether the latch fields hold a learned source.
    pub latch_valid: u8,
    /// Padding.
    pub _pad: u8,
    /// AF_XDP queue index for `action::REDIRECT`.
    pub redirect_queue: u32,
}

// --- TURN channel-relay fast path (docs/security-and-nat.md §11, M-T8) -----------------------
//
// Once a TURN client binds a channel (RFC 5766 §11) the per-packet relay is a fixed rewrite the
// kernel can do without userspace: peer→client prepends a 4-byte ChannelData header and TX's to the
// client; client→peer strips it and TX's to the peer. The userspace TURN server programs these two
// maps on ChannelBind and removes them on teardown; control packets (Allocate/Refresh/permissions,
// Send/Data indications, non-channel data) always go to userspace via `action::REDIRECT`.
//
// IPv4 only, like the rest of the ABI. The kernel rewrite + `XDP_TX` is the hardware-verified half;
// these POD types are the contract both sides build to.

/// Key into the `TURN_PEERS` map (peer→client direction): a peer's transport as observed on a relay
/// endpoint. The relay transport is unique per allocation, so `(relay, peer)` identifies the channel.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TurnPeerKey {
    /// Relay endpoint IPv4 (network byte order) — the datagram's destination.
    pub relay_ipv4: u32,
    /// Peer IPv4 (network byte order) — the datagram's source.
    pub peer_ipv4: u32,
    /// Relay endpoint UDP port (network byte order).
    pub relay_port: u16,
    /// Peer UDP port (network byte order).
    pub peer_port: u16,
}

/// Value in `TURN_PEERS`: how to deliver a peer datagram to the client as ChannelData — prepend the
/// `channel` header and `XDP_TX` to `client` from the server `listener` transport.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TurnClientRoute {
    /// Client IPv4 (network byte order) — the TX destination.
    pub client_ipv4: u32,
    /// Server listener IPv4 the client allocated on (network byte order) — the TX source.
    pub listener_ipv4: u32,
    /// Client UDP port (network byte order).
    pub client_port: u16,
    /// Server listener UDP port (network byte order).
    pub listener_port: u16,
    /// Channel number (host byte order) prepended in the ChannelData header.
    pub channel: u16,
    /// Padding to a fixed 16-byte value.
    pub _pad: u16,
}

/// Key into the `TURN_CHANNELS` map (client→peer direction): a ChannelData stream from a client,
/// identified by the listener it arrived on, the client source, and the channel number.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TurnChannelKey {
    /// Server listener IPv4 (network byte order) — the datagram's destination.
    pub listener_ipv4: u32,
    /// Client IPv4 (network byte order) — the datagram's source.
    pub client_ipv4: u32,
    /// Server listener UDP port (network byte order).
    pub listener_port: u16,
    /// Client UDP port (network byte order).
    pub client_port: u16,
    /// Channel number (host byte order) read from the ChannelData header.
    pub channel: u16,
    /// Padding to a fixed 16-byte key.
    pub _pad: u16,
}

/// Value in `TURN_CHANNELS`: how to relay a client's ChannelData payload — strip the header and
/// `XDP_TX` to `peer` from the allocation's `relay` endpoint.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TurnPeerRoute {
    /// Peer IPv4 (network byte order) — the TX destination.
    pub peer_ipv4: u32,
    /// Relay endpoint IPv4 (network byte order) — the TX source.
    pub relay_ipv4: u32,
    /// Peer UDP port (network byte order).
    pub peer_port: u16,
    /// Relay endpoint UDP port (network byte order).
    pub relay_port: u16,
}

/// Per-CPU counters for a media flow. The same POD is the value of **two** maps:
/// - the program-wide `STATS` `PerCpuArray<FlowStats>` (one entry) — the aggregate over every flow,
///   summed across CPUs by the loader (`last_seen_ns` is not meaningful there and stays `0`);
/// - the per-flow `FLOW_STATS` `PerCpuHashMap<FlowKey, FlowStats>` — one entry per media flow, so the
///   loader reports a single endpoint's real counters instead of the program aggregate.
///
/// The counter fields are **summed** across CPUs by the loader; `last_seen_ns` is a monotonic-clock
/// timestamp, so it is **maxed** across CPUs instead (the most recent accepted packet on any CPU).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FlowStats {
    /// Datagrams received.
    pub packets_in: u64,
    /// Datagrams transmitted.
    pub packets_out: u64,
    /// Bytes received.
    pub bytes_in: u64,
    /// Bytes transmitted.
    pub bytes_out: u64,
    /// Datagrams dropped (gate, no destination, or `action::DROP`).
    pub packets_dropped: u64,
    /// `bpf_ktime_get_ns()` (`CLOCK_MONOTONIC` nanoseconds) of the last **accepted** packet on this
    /// flow, stamped in-kernel for the media-timeout / dead-path sweep (docs/security-and-nat.md §4
    /// layer 6). `0` means no packet has been accepted yet. Per-CPU, so the loader takes the **max**
    /// across CPUs; unused (left `0`) in the program-wide `STATS` aggregate.
    pub last_seen_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    // The kernel ABI contract: these sizes/offsets must not drift. A change here means the kernel
    // program and the loader disagree on the map layout — every flow would be misread.

    #[test]
    fn flow_key_abi_is_stable() {
        assert_eq!(size_of::<FlowKey>(), 8);
        assert_eq!(align_of::<FlowKey>(), 4);
        assert_eq!(offset_of!(FlowKey, local_ipv4), 0);
        assert_eq!(offset_of!(FlowKey, local_port), 4);
    }

    #[test]
    fn flow_action_abi_is_stable() {
        assert_eq!(size_of::<FlowAction>(), 36);
        assert_eq!(align_of::<FlowAction>(), 4);
        assert_eq!(offset_of!(FlowAction, kind), 0);
        assert_eq!(offset_of!(FlowAction, source_ipv4), 4);
        assert_eq!(offset_of!(FlowAction, out_ipv4), 8);
        assert_eq!(offset_of!(FlowAction, out_local_ipv4), 12);
        assert_eq!(offset_of!(FlowAction, out_port), 16);
        assert_eq!(offset_of!(FlowAction, out_src_port), 18);
        assert_eq!(offset_of!(FlowAction, latched_ipv4), 20);
        assert_eq!(offset_of!(FlowAction, latched_ssrc), 24);
        assert_eq!(offset_of!(FlowAction, latched_port), 28);
        assert_eq!(offset_of!(FlowAction, redirect_queue), 32);
    }

    #[test]
    fn flow_stats_abi_is_stable() {
        // Stage 3a widened the per-CPU value with `last_seen_ns` (the in-kernel activity stamp) for
        // the per-flow `FLOW_STATS` map: size 40 -> 48, alignment unchanged (all `u64`), the five
        // counters keep their offsets (0/8/16/24/32) and `last_seen_ns` is appended at offset 40.
        assert_eq!(size_of::<FlowStats>(), 48);
        assert_eq!(align_of::<FlowStats>(), 8);
        assert_eq!(offset_of!(FlowStats, packets_in), 0);
        assert_eq!(offset_of!(FlowStats, packets_out), 8);
        assert_eq!(offset_of!(FlowStats, bytes_in), 16);
        assert_eq!(offset_of!(FlowStats, bytes_out), 24);
        assert_eq!(offset_of!(FlowStats, packets_dropped), 32);
        assert_eq!(offset_of!(FlowStats, last_seen_ns), 40);
    }

    #[test]
    fn turn_channel_relay_abi_is_stable() {
        // The TURN fast-path map ABI — userspace TURN server and the kernel rewrite must agree.
        assert_eq!(size_of::<TurnPeerKey>(), 12);
        assert_eq!(align_of::<TurnPeerKey>(), 4);
        assert_eq!(offset_of!(TurnPeerKey, peer_ipv4), 4);
        assert_eq!(offset_of!(TurnPeerKey, relay_port), 8);
        assert_eq!(offset_of!(TurnPeerKey, peer_port), 10);

        assert_eq!(size_of::<TurnClientRoute>(), 16);
        assert_eq!(align_of::<TurnClientRoute>(), 4);
        assert_eq!(offset_of!(TurnClientRoute, listener_ipv4), 4);
        assert_eq!(offset_of!(TurnClientRoute, channel), 12);

        assert_eq!(size_of::<TurnChannelKey>(), 16);
        assert_eq!(align_of::<TurnChannelKey>(), 4);
        assert_eq!(offset_of!(TurnChannelKey, client_ipv4), 4);
        assert_eq!(offset_of!(TurnChannelKey, channel), 12);

        assert_eq!(size_of::<TurnPeerRoute>(), 12);
        assert_eq!(align_of::<TurnPeerRoute>(), 4);
        assert_eq!(offset_of!(TurnPeerRoute, relay_ipv4), 4);
        assert_eq!(offset_of!(TurnPeerRoute, peer_port), 8);
    }

    #[test]
    fn discriminants_match_the_userspace_model() {
        // Forward/Redirect/Drop, Any/Exact/Subnet, Off/Signalled/Symmetric — same order as the
        // siphon-rtp-datapath enums, so a numeric cast on either side stays in sync.
        assert_eq!((action::DROP, action::FORWARD, action::REDIRECT), (0, 1, 2));
        assert_eq!((source::ANY, source::EXACT, source::SUBNET), (0, 1, 2));
        assert_eq!((latch::OFF, latch::SIGNALLED, latch::SYMMETRIC), (0, 1, 2));
    }
}
