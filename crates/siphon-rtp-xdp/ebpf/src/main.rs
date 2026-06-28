//! The siphon-rtp XDP classifier.
//!
//! For each inbound UDP datagram it builds a [`FlowKey`] from the destination IPv4 transport,
//! looks it up in the `FLOWS` map, and:
//! - **no flow** → `XDP_PASS` (not our media; the kernel stack keeps it),
//! - **Drop** → `XDP_DROP`,
//! - **Forward/Redirect** → enforce the **RTPBleed source-gate** (drop a source the SDP did not
//!   signal) and then `XDP_REDIRECT` to the AF_XDP socket for the owning userspace actor.
//!
//! The in-kernel `XDP_TX` passthrough fast-path (FIB/neighbour lookup + L2/L3/L4 rewrite +
//! checksum fixup) is a later optimisation; until then every matched flow rides the AF_XDP slow
//! path, which is where SRTP/decode/transcode/WS already live. The source-gate runs in-kernel
//! regardless, so spoofed sources are dropped before they ever reach userspace.
//!
//! ## TURN channel-relay fast path (M-T8 — planned, gated on `XDP_TX`)
//!
//! Once a TURN client binds a channel (RFC 5766 §11; docs/security-and-nat.md §11) the per-packet
//! relay is a fixed rewrite the kernel can do without ever touching userspace. The userspace TURN
//! server (`siphon-rtp-turn`) already programs the seam — its `TurnFastPath` installs a `ChannelRoute`
//! on ChannelBind and withdraws it on teardown — and the shared ABI is the
//! [`TurnPeerKey`]→[`TurnClientRoute`] / [`TurnChannelKey`]→[`TurnPeerRoute`] map pairs in
//! `siphon-rtp-ebpf-common`. The kernel dispatch this enables, *checked before the generic `FLOWS`
//! redirect so an established channel bypasses the AF_XDP slow path:*
//!
//! - **peer → client:** dest = a relay endpoint, src = peer ⇒ look up `TURN_PEERS{relay, peer}`; on a
//!   hit, `bpf_xdp_adjust_head(-4)`, write the 4-byte ChannelData header (channel + length), rewrite
//!   L2/L3/L4 to the client from the listener transport, fix checksums, `XDP_TX`.
//! - **client → peer:** dest = a listener, payload is ChannelData (first two bits `01`) ⇒ read the
//!   channel, look up `TURN_CHANNELS{listener, client, channel}`; on a hit, strip the 4-byte header
//!   (`bpf_xdp_adjust_head(+4)`), rewrite to the peer from the relay transport, fix checksums,
//!   `XDP_TX`.
//! - everything else (Allocate/Refresh/CreatePermission/ChannelBind, Send/Data indications,
//!   non-channel data) falls through to `action::REDIRECT` and is handled in userspace.
//!
//! This shares the generic `XDP_TX` rewrite + checksum machinery, so it lands with that work — only
//! the two map lookups and the 4-byte header adjust are TURN-specific. Permission gating is implicit:
//! a route exists only while its channel is bound, and the userspace server enforces every permission
//! on the control path before it ever programs a route.
#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, XskMap},
    programs::XdpContext,
};
use siphon_rtp_ebpf_common::{action, source, FlowAction, FlowKey, FlowStats};

/// Flow table: destination transport → relay rule. Keyed/valued by the shared ABI POD.
#[map]
static FLOWS: HashMap<FlowKey, FlowAction> = HashMap::with_max_entries(65_536, 0);

/// AF_XDP sockets, one per RX queue; `XDP_REDIRECT` targets an entry by queue index.
#[map]
static XSKS: XskMap = XskMap::with_max_entries(64, 0);

/// Per-CPU counters (summed by the loader).
#[map]
static STATS: PerCpuArray<FlowStats> = PerCpuArray::with_max_entries(1, 0);

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

/// A bounds-checked pointer into the packet (the verifier requires every access be proven in-range).
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn load<T: Copy>(ctx: &XdpContext, offset: usize) -> Result<T, ()> {
    Ok(unsafe { *ptr_at::<T>(ctx, offset)? })
}

#[inline(always)]
fn bump(field: impl Fn(&mut FlowStats)) {
    if let Some(stats) = STATS.get_ptr_mut(0) {
        // Single-CPU view (per-CPU array), so a plain read-modify-write is race-free here.
        unsafe { field(&mut *stats) };
    }
}

/// Whether `source_ipv4` (network order) passes the flow's source gate.
#[inline(always)]
fn source_allowed(rule: &FlowAction, source_ipv4: u32) -> bool {
    match rule.source_kind {
        source::ANY => true,
        source::EXACT => rule.source_ipv4 == source_ipv4,
        source::SUBNET => {
            let prefix = rule.source_prefix.min(32);
            if prefix == 0 {
                return true;
            }
            // Addresses are network order; compare in host order so the shift is well-defined.
            let mask = u32::MAX << (32 - prefix);
            (u32::from_be(rule.source_ipv4) & mask) == (u32::from_be(source_ipv4) & mask)
        }
        _ => false,
    }
}

#[xdp]
pub fn siphon_rtp_xdp(ctx: XdpContext) -> u32 {
    match try_classify(&ctx) {
        Ok(verdict) => verdict,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_classify(ctx: &XdpContext) -> Result<u32, ()> {
    // Ethernet: only IPv4 (the media plane is IPv4 first).
    let ethertype: u16 = u16::from_be(load(ctx, 12)?);
    if ethertype != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv4: respect IHL (options), require UDP.
    let version_ihl: u8 = load(ctx, ETH_HDR_LEN)?;
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if ihl < 20 {
        return Ok(xdp_action::XDP_PASS);
    }
    let protocol: u8 = load(ctx, ETH_HDR_LEN + 9)?;
    if protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    let source_ipv4: u32 = load(ctx, ETH_HDR_LEN + 12)?; // network order
    let dest_ipv4: u32 = load(ctx, ETH_HDR_LEN + 16)?;

    // UDP: destination port keys the flow.
    let udp_offset = ETH_HDR_LEN + ihl;
    let dest_port: u16 = load(ctx, udp_offset + 2)?; // network order

    let key = FlowKey {
        local_ipv4: dest_ipv4,
        local_port: dest_port,
        _pad: 0,
    };
    let rule = match unsafe { FLOWS.get(&key) } {
        Some(rule) => rule,
        None => return Ok(xdp_action::XDP_PASS),
    };

    bump(|s| s.packets_in += 1);

    match rule.kind {
        action::DROP => {
            bump(|s| s.packets_dropped += 1);
            Ok(xdp_action::XDP_DROP)
        }
        action::FORWARD | action::REDIRECT => {
            // RTPBleed gate: a source the SDP did not signal never reaches userspace.
            if !source_allowed(rule, source_ipv4) {
                bump(|s| s.packets_dropped += 1);
                return Ok(xdp_action::XDP_DROP);
            }
            // Hand to the owning AF_XDP socket (the userspace actor relays / transcodes).
            match XSKS.redirect(rule.redirect_queue, 0) {
                Ok(redirect) => Ok(redirect),
                Err(_) => {
                    bump(|s| s.packets_dropped += 1);
                    Ok(xdp_action::XDP_DROP)
                }
            }
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
