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
    /// Latched peer source IPv4 (network byte order); valid when `latch_valid != 0`.
    pub latched_ipv4: u32,
    /// Latched peer RTP SSRC (host order); the re-latch consistency key.
    pub latched_ssrc: u32,
    /// Latched peer source port (network byte order).
    pub latched_port: u16,
    /// Whether the latch fields hold a learned source.
    pub latch_valid: u8,
    /// Padding.
    pub _pad: u8,
    /// AF_XDP queue index for `action::REDIRECT`.
    pub redirect_queue: u32,
}

/// Per-CPU counters in the `STATS` map (summed across CPUs by the loader).
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
        assert_eq!(size_of::<FlowStats>(), 40);
        assert_eq!(align_of::<FlowStats>(), 8);
        assert_eq!(offset_of!(FlowStats, packets_dropped), 32);
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
