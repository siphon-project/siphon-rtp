//! The siphon-rtp XDP classifier.
//!
//! For each inbound UDP datagram it builds a [`FlowKey`] from the destination IPv4 transport,
//! looks it up in the `FLOWS` map, and:
//! - **no flow** → `XDP_PASS` (not our media; the kernel stack keeps it),
//! - **Drop** → `XDP_DROP`,
//! - **Redirect** → enforce the **RTPBleed source-gate** (drop a source the SDP did not signal) and
//!   then `XDP_REDIRECT` to the AF_XDP socket for the owning userspace actor (SRTP / decode /
//!   transcode / WS / TURN-control legs live there),
//! - **Forward** → relay the datagram **entirely in the kernel** (the `XDP_TX` fast path): enforce
//!   the source-gate + the SSRC-consistent symmetric-RTP latch (RTPBleed, RFC 3550 §8), rewrite
//!   L3/L4 in place with an incremental checksum fixup (RFC 1624), resolve the next hop with
//!   `bpf_fib_lookup`, rewrite L2, and `XDP_TX` / `bpf_redirect`. A plain `rtp_passthrough` relay
//!   never touches userspace.
//!
//! The correctness-critical arithmetic (the incremental checksum fixup and the latch state machine)
//! lives in the host-testable [`siphon_rtp_ebpf_common::rewrite`] module — proptested against a
//! from-scratch one's-complement recompute and unit-tested exhaustively — so this program only does
//! the bounds-checked packet I/O and the FIB lookup around it.
//!
//! ## TURN channel-relay fast path (M-T8 — planned, gated on this `XDP_TX` work)
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
//! This shares the generic `XDP_TX` rewrite + checksum machinery landed here, so only the two map
//! lookups and the 4-byte header adjust remain TURN-specific.
#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{
        bpf_fib_lookup as bpf_fib_lookup_params, xdp_action, BPF_FIB_LKUP_RET_SUCCESS,
        BPF_FIB_LOOKUP_DIRECT,
    },
    helpers::{bpf_fib_lookup, bpf_ktime_get_ns, bpf_redirect},
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, PerCpuHashMap, XskMap},
    programs::XdpContext,
    EbpfContext,
};
use siphon_rtp_ebpf_common::{
    action, latch,
    loss::{rtp_loss_update, RTP_SEQ_NONE},
    rewrite::{
        ipv4_checksum_after_addr_rewrite, is_rtp_or_rtcp, latch_decision, rtp_media_ssrc,
        udp_checksum_after_rewrite, LatchVerdict, Latched,
    },
    source, FlowAction, FlowKey, FlowStats,
};

/// Flow table: destination transport → relay rule. Keyed/valued by the shared ABI POD.
#[map]
static FLOWS: HashMap<FlowKey, FlowAction> = HashMap::with_max_entries(65_536, 0);

/// AF_XDP sockets, one per RX queue; `XDP_REDIRECT` targets an entry by queue index.
#[map]
static XSKS: XskMap = XskMap::with_max_entries(64, 0);

/// Program-wide per-CPU counters — the aggregate over every flow (summed by the loader).
#[map]
static STATS: PerCpuArray<FlowStats> = PerCpuArray::with_max_entries(1, 0);

/// Per-flow per-CPU counters + last-accepted-packet timestamp, keyed by the same [`FlowKey`] as
/// `FLOWS`, so the loader reports one endpoint's real counters and its `last_activity`
/// (docs/security-and-nat.md §4 layer 6) instead of the program-wide aggregate. Sized to `FLOWS`.
#[map]
static FLOW_STATS: PerCpuHashMap<FlowKey, FlowStats> = PerCpuHashMap::with_max_entries(65_536, 0);

/// A zeroed per-flow stats value for the first-packet insert. A `const` reference so the insert
/// carries no on-stack copy (the eBPF stack budget is 512 bytes; the FIB-lookup params already use it).
const EMPTY_FLOW_STATS: FlowStats = FlowStats {
    packets_in: 0,
    packets_out: 0,
    bytes_in: 0,
    bytes_out: 0,
    packets_dropped: 0,
    last_seen_ns: 0,
    packets_lost: 0,
    last_rtp_seq: RTP_SEQ_NONE,
};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
/// Address family for IPv4 (`AF_INET`; not exported by the aya bindings) — the `bpf_fib_lookup`
/// family selector for an IPv4 route lookup.
const AF_INET: u8 = 2;

/// A bounds-checked const pointer into the packet (the verifier requires every access be in-range).
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// A bounds-checked mutable pointer into the packet (for the in-place L2/L3/L4 rewrite). XDP packet
/// data is writable; the verifier still requires the range be proven in-bounds.
#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

#[inline(always)]
fn load<T: Copy>(ctx: &XdpContext, offset: usize) -> Result<T, ()> {
    Ok(unsafe { *ptr_at::<T>(ctx, offset)? })
}

/// Store `value` at `offset` in the packet buffer (bounds-checked). Used with `[u8; N]` byte arrays
/// so the byte order is explicit (`to_be_bytes` at the call site), never host-endian-dependent.
#[inline(always)]
fn store<T>(ctx: &XdpContext, offset: usize, value: T) -> Result<(), ()> {
    unsafe { *ptr_at_mut::<T>(ctx, offset)? = value };
    Ok(())
}

/// Read a network-order 32-bit field at `offset` as a host-order `u32` (`from_be_bytes`), so the
/// checksum/latch math is byte-order-explicit and portable.
#[inline(always)]
fn load_be_u32(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(load::<[u8; 4]>(ctx, offset)?))
}

/// Read a network-order 16-bit field at `offset` as a host-order `u16`.
#[inline(always)]
fn load_be_u16(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(load::<[u8; 2]>(ctx, offset)?))
}

/// This flow's per-CPU stats entry, creating a zeroed one on first sight. Returns `None` only if the
/// `FLOW_STATS` map is full (65 536 concurrent flows) — then only the program-wide aggregate is
/// bumped, never a panic. Per-CPU, so no cross-CPU race on the entry.
#[inline(always)]
fn flow_stats_entry(key: &FlowKey) -> Option<*mut FlowStats> {
    if let Some(entry) = FLOW_STATS.get_ptr_mut(key) {
        return Some(entry);
    }
    // First packet for this flow on this CPU: insert a zeroed entry (BPF_ANY), then take the pointer.
    let _ = FLOW_STATS.insert(key, &EMPTY_FLOW_STATS, 0);
    FLOW_STATS.get_ptr_mut(key)
}

/// Apply `field` to **both** the program-wide aggregate (`STATS[0]`) and this flow's per-CPU entry,
/// so one counter bump keeps the aggregate and the per-endpoint view in lockstep. Both are per-CPU,
/// so a plain read-modify-write is race-free.
#[inline(always)]
fn account(entry: Option<*mut FlowStats>, field: impl Fn(&mut FlowStats)) {
    if let Some(aggregate) = STATS.get_ptr_mut(0) {
        unsafe { field(&mut *aggregate) };
    }
    if let Some(flow) = entry {
        unsafe { field(&mut *flow) };
    }
}

/// Stamp this flow's last-accepted-packet time (`last_seen_ns`, per-CPU) with a monotonic
/// `bpf_ktime_get_ns()` reading. Only the per-flow entry carries it — the aggregate's `last_seen_ns`
/// is meaningless. Drives the loader's `last_activity` (docs/security-and-nat.md §4 layer 6).
#[inline(always)]
fn stamp_last_seen(entry: Option<*mut FlowStats>, now_ns: u64) {
    if let Some(flow) = entry {
        unsafe { (*flow).last_seen_ns = now_ns };
    }
}

/// Whether `source_ipv4` (native-order read, as the classifier keys/gates on) passes the flow's
/// source gate. Layer 2 of the media-plane design (docs/security-and-nat.md §4; RFC 3264): only the
/// SDP-signalled peer may send here — the RTPBleed fix.
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
    let source_ipv4: u32 = load(ctx, ETH_HDR_LEN + 12)?; // native-order read (classifier gate/key)
    let dest_ipv4: u32 = load(ctx, ETH_HDR_LEN + 16)?;

    // UDP: destination port keys the flow.
    let ip_offset = ETH_HDR_LEN;
    let udp_offset = ETH_HDR_LEN + ihl;
    let dest_port: u16 = load(ctx, udp_offset + 2)?; // network order

    // UDP payload bytes for stats = IP total length (RFC 791) minus the IP header (ihl) and the 8-byte
    // UDP header (RFC 768). This matches the loopback backend's byte accounting (the recv_from /
    // send_to payload length), so both datapaths report the same bytes for the same call. Saturating:
    // a malformed short total-length counts 0 rather than underflowing.
    let ip_total_len = load_be_u16(ctx, ip_offset + 2)? as usize;
    let payload_len = ip_total_len.saturating_sub(ihl + 8) as u64;

    let key = FlowKey {
        local_ipv4: dest_ipv4,
        local_port: dest_port,
        _pad: 0,
    };
    // A mutable value pointer so the Forward fast path can write the learned latch state back.
    let rule_ptr = match FLOWS.get_ptr_mut(&key) {
        Some(rule) => rule,
        None => return Ok(xdp_action::XDP_PASS),
    };
    // A private copy for the read-only fields; the map value is only mutated through `rule_ptr` on
    // a latch learn, so there is no aliasing between the copy and the write.
    let rule = unsafe { *rule_ptr };

    // This flow's per-CPU stats entry (created on first sight); threaded through every bump so the
    // per-endpoint counters track the aggregate.
    let stats_entry = flow_stats_entry(&key);
    account(stats_entry, |s| {
        s.packets_in += 1;
        s.bytes_in += payload_len;
    });

    match rule.kind {
        action::DROP => {
            account(stats_entry, |s| s.packets_dropped += 1);
            Ok(xdp_action::XDP_DROP)
        }
        action::FORWARD => Ok(forward_in_kernel(
            ctx,
            &rule,
            rule_ptr,
            stats_entry,
            source_ipv4,
            payload_len,
            ip_offset,
            udp_offset,
        )
        .unwrap_or_else(|()| {
            // Truncated/malformed datagram: drop (do not XDP_PASS partial media).
            account(stats_entry, |s| s.packets_dropped += 1);
            xdp_action::XDP_DROP
        })),
        action::REDIRECT => {
            // RTPBleed gate: a source the SDP did not signal never reaches userspace.
            if !source_allowed(&rule, source_ipv4) {
                account(stats_entry, |s| s.packets_dropped += 1);
                return Ok(xdp_action::XDP_DROP);
            }
            // Accepted media handed to userspace — stamp activity for the media-timeout sweep (mirrors
            // the loopback backend, which stamps last_seen right after the gate, before the send).
            stamp_last_seen(stats_entry, unsafe { bpf_ktime_get_ns() });
            // Hand to the owning AF_XDP socket (the userspace actor relays / transcodes).
            match XSKS.redirect(rule.redirect_queue, 0) {
                Ok(redirect) => Ok(redirect),
                Err(_) => {
                    account(stats_entry, |s| s.packets_dropped += 1);
                    Ok(xdp_action::XDP_DROP)
                }
            }
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// The in-kernel `XDP_TX` relay for an `action::FORWARD` flow (docs/security-and-nat.md §4).
///
/// Enforces the layered secure symmetric-RTP posture before it forwards a single byte:
/// 1. **layer 1 — demux** (RFC 7983): only RTP/RTCP (first byte 128..=191) drives the relay or moves
///    the latch; STUN/DTLS/garbage on a Forward leg is dropped;
/// 2. **layer 2 — signalled-source gate** (RFC 3264): drop a source the SDP did not signal;
/// 3. **layer 3 — SSRC-consistent latch** (RFC 3550 §8): learn the peer's real source, re-latch a
///    new source only on a matching SSRC (a genuine NAT rebind), drop an SSRC-mismatched spray.
///
/// It then resolves the forward destination (the userspace-maintained `out_*`, rtpengine `dst_addr`
/// parity — never a flow's *own* ingress latch, which would echo), rewrites L3/L4 with the RFC 1624
/// incremental checksum fixup, resolves the next hop with `bpf_fib_lookup` (RFC 1122 §3.3), rewrites
/// L2, and `XDP_TX`s (hairpin) or `bpf_redirect`s (different egress ifindex). A FIB miss / unresolved
/// neighbour falls back to `action::REDIRECT` so userspace (netlink resolve + ARP kick) handles the
/// cold case. Returns the XDP verdict; `Err(())` means a bounds check failed (the caller drops).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn forward_in_kernel(
    ctx: &XdpContext,
    rule: &FlowAction,
    rule_ptr: *mut FlowAction,
    stats_entry: Option<*mut FlowStats>,
    source_ipv4: u32,
    payload_len: u64,
    ip_offset: usize,
    udp_offset: usize,
) -> Result<u32, ()> {
    let payload_offset = udp_offset + 8;

    // --- Layer 1: RFC 7983 first-byte demux (only RTP/RTCP may drive a Forward relay). ----------
    let first_byte: u8 = match load::<u8>(ctx, payload_offset) {
        Ok(byte) => byte,
        // No payload at all — not media on a media flow.
        Err(()) => {
            account(stats_entry, |s| s.packets_dropped += 1);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    if !is_rtp_or_rtcp(&[first_byte]) {
        account(stats_entry, |s| s.packets_dropped += 1);
        return Ok(xdp_action::XDP_DROP);
    }

    // --- Layer 2: signalled-source gate (RTPBleed, RFC 3264). ----------------------------------
    if !source_allowed(rule, source_ipv4) {
        account(stats_entry, |s| s.packets_dropped += 1);
        return Ok(xdp_action::XDP_DROP);
    }

    // The datagram source in host order (used both for the latch and — as old_src — for the
    // checksum fixup below). Kernel-private latch state uses this same representation throughout.
    let src_ip_host = load_be_u32(ctx, ip_offset + 12)?;
    let src_port_host = load_be_u16(ctx, udp_offset)?;

    // --- Layer 3: SSRC-consistent latch (RFC 3550 §8). Only for a latching policy. --------------
    if rule.latch_policy != latch::OFF {
        // The RTP SSRC (bytes 8..12 of the payload), or None for RTCP / a too-short datagram.
        let ssrc = match load::<[u8; 12]>(ctx, payload_offset) {
            Ok(rtp_header) => rtp_media_ssrc(&rtp_header),
            Err(()) => None,
        };
        let current = if rule.latch_valid != 0 {
            Some(Latched {
                ipv4: rule.latched_ipv4,
                port: rule.latched_port,
                ssrc: rule.latched_ssrc,
            })
        } else {
            None
        };
        match latch_decision(current, src_ip_host, src_port_host, ssrc) {
            LatchVerdict::Drop => {
                // A hijack spray (new source, wrong/absent SSRC) — drop, keep the existing latch.
                account(stats_entry, |s| s.packets_dropped += 1);
                return Ok(xdp_action::XDP_DROP);
            }
            LatchVerdict::Learn(learned) => {
                // Learn / re-latch the peer's real source (symmetric RTP, RFC 4961). Written back
                // through the map value pointer; last-writer-wins across CPUs is fine (it converges).
                unsafe {
                    (*rule_ptr).latched_ipv4 = learned.ipv4;
                    (*rule_ptr).latched_port = learned.port;
                    (*rule_ptr).latched_ssrc = learned.ssrc;
                    (*rule_ptr).latch_valid = 1;
                }
            }
            LatchVerdict::Forward => {}
        }
    }

    // The datagram has passed layer 1 (demux) + layer 2 (source gate) + layer 3 (SSRC latch): it is
    // accepted media. Stamp activity now — before the destination is resolved — so even a leg whose
    // answer has not landed yet (no `out_dst`) records that the peer is alive, exactly what the
    // media-timeout / dead-path sweep needs (docs/security-and-nat.md §4 layer 6).
    stamp_last_seen(stats_entry, unsafe { bpf_ktime_get_ns() });

    // In-kernel RTP loss estimate: fold this accepted media packet's sequence into the per-flow
    // forward-gap counter (RFC 3550 §A.1-style) so a kernelized (XDP_TX) relay still reports network
    // loss to the CDR. Skip RTCP (rtp_media_ssrc None) and short/non-RTP datagrams.
    if let Ok(rtp_header) = load::<[u8; 12]>(ctx, payload_offset) {
        if rtp_media_ssrc(&rtp_header).is_some() {
            let seq = u16::from_be_bytes([rtp_header[2], rtp_header[3]]);
            let last = stats_entry.map_or(RTP_SEQ_NONE, |entry| unsafe { (*entry).last_rtp_seq });
            let (updated_last, lost) = rtp_loss_update(last, seq);
            if lost > 0 {
                account(stats_entry, |s| s.packets_lost += lost);
            }
            if let Some(flow) = stats_entry {
                unsafe { (*flow).last_rtp_seq = updated_last };
            }
        }
    }

    // --- Resolve the forward destination. The kernel forwards to the userspace-maintained
    //     destination (rtpengine `dst_addr` parity; the loopback backend's `.or(rule.out_dst)`
    //     primary path). A flow's *own* ingress latch is the RTPBleed source anchor above, not a
    //     destination — forwarding to it would echo. Never forward into the void: no destination →
    //     drop (docs/security-and-nat.md §4; the datapath drops when nothing resolves). -----------
    let new_dst_ip_host = rule.out_ipv4; // loader stores host-order (from_be_bytes)
    let new_dst_port_host = u16::from_be(rule.out_port); // loader stores network-order (to_be)
    if new_dst_ip_host == 0 || new_dst_port_host == 0 {
        account(stats_entry, |s| s.packets_dropped += 1);
        return Ok(xdp_action::XDP_DROP);
    }
    let new_src_ip_host = rule.out_local_ipv4; // host-order
    let new_src_port_host = u16::from_be(rule.out_src_port); // network-order -> host

    // --- Next hop (RFC 1122 §3.3): a FIB lookup on the *rewritten* destination. -----------------
    let ip_total_len_host = load_be_u16(ctx, ip_offset + 2)?;
    let ingress_ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let mut params: bpf_fib_lookup_params = unsafe { mem::zeroed() };
    params.family = AF_INET;
    params.l4_protocol = IPPROTO_UDP;
    params.sport = rule.out_src_port; // already network order (be16)
    params.dport = rule.out_port; // already network order (be16)
    params.ifindex = ingress_ifindex;
    // Writing a union field is safe (only reads are unsafe); these select the IPv4 arms.
    params.__bindgen_anon_1.tot_len = ip_total_len_host;
    params.__bindgen_anon_3.ipv4_src = new_src_ip_host.to_be();
    params.__bindgen_anon_4.ipv4_dst = new_dst_ip_host.to_be();
    let fib_result = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr(),
            &mut params as *mut bpf_fib_lookup_params,
            mem::size_of::<bpf_fib_lookup_params>() as i32,
            BPF_FIB_LOOKUP_DIRECT,
        )
    };
    if fib_result != BPF_FIB_LKUP_RET_SUCCESS as i64 {
        // FIB miss / no neighbour / not forwardable (e.g. BPF_FIB_LKUP_RET_NO_NEIGH): the resolved
        // fast path can't handle it — hand the *original* (un-rewritten) datagram to userspace,
        // which has the netlink resolver + ARP kick (docs/security-and-nat.md; PR #84).
        return match XSKS.redirect(rule.redirect_queue, 0) {
            Ok(redirect) => Ok(redirect),
            Err(_) => {
                account(stats_entry, |s| s.packets_dropped += 1);
                Ok(xdp_action::XDP_DROP)
            }
        };
    }

    // --- FIB hit: commit the rewrite. Only now do we mutate the packet, so a fallback REDIRECT
    //     above always forwards the original bytes. -----------------------------------------------

    // L3/L4 (RFC 1624 incremental fixup): only the two addresses and two ports change; TTL is left
    // untouched — a media relay is not an IP router, so it does not decrement TTL (RFC 1122 §3.3.1.1
    // TTL decrement is a hop/router behaviour; a NAT/relay forwards the datagram, matching rtpengine
    // and the userspace loopback backend, which rewrite addresses only).
    let old_dst_ip_host = load_be_u32(ctx, ip_offset + 16)?;
    let old_ip_checksum = load_be_u16(ctx, ip_offset + 10)?;
    let old_dst_port_host = load_be_u16(ctx, udp_offset + 2)?;
    let old_udp_checksum = load_be_u16(ctx, udp_offset + 6)?;

    let new_ip_checksum = ipv4_checksum_after_addr_rewrite(
        old_ip_checksum,
        src_ip_host,
        new_src_ip_host,
        old_dst_ip_host,
        new_dst_ip_host,
    );
    let new_udp_checksum = udp_checksum_after_rewrite(
        old_udp_checksum,
        src_ip_host,
        new_src_ip_host,
        old_dst_ip_host,
        new_dst_ip_host,
        src_port_host,
        new_src_port_host,
        old_dst_port_host,
        new_dst_port_host,
    );

    store::<[u8; 4]>(ctx, ip_offset + 12, new_src_ip_host.to_be_bytes())?;
    store::<[u8; 4]>(ctx, ip_offset + 16, new_dst_ip_host.to_be_bytes())?;
    store::<[u8; 2]>(ctx, ip_offset + 10, new_ip_checksum.to_be_bytes())?;
    store::<[u8; 2]>(ctx, udp_offset, new_src_port_host.to_be_bytes())?;
    store::<[u8; 2]>(ctx, udp_offset + 2, new_dst_port_host.to_be_bytes())?;
    store::<[u8; 2]>(ctx, udp_offset + 6, new_udp_checksum.to_be_bytes())?;

    // L2: the FIB gave us the egress source MAC and the next-hop destination MAC.
    store::<[u8; 6]>(ctx, 0, params.dmac)?;
    store::<[u8; 6]>(ctx, 6, params.smac)?;

    // Count the UDP payload bytes (not the L2 frame) so bytes_out matches bytes_in and the loopback
    // backend's send_to accounting; the payload is unchanged by the header-only rewrite above.
    account(stats_entry, |s| {
        s.packets_out += 1;
        s.bytes_out += payload_len;
    });

    if params.ifindex == ingress_ifindex {
        // Same NIC — hairpin the frame straight back out.
        Ok(xdp_action::XDP_TX)
    } else {
        // Different egress interface — redirect the (already L2-rewritten) frame to it.
        Ok(unsafe { bpf_redirect(params.ifindex, 0) } as u32)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
