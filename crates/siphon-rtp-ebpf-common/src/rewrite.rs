//! Pure, `no_std`, allocation-free relay math shared by the in-kernel XDP_TX fast path
//! (`siphon-rtp-ebpf`) and its host-side tests/benches (`siphon-rtp-xdp`).
//!
//! eBPF code cannot run under `cargo test`, so the parts that have to be *provably* correct — the
//! RFC 1624 incremental checksum fixup and the RFC 3550 §8 SSRC-consistent latch state machine —
//! live here as ordinary functions. They compile for `bpfel-unknown-none` (the kernel program) and
//! for the host (the proptest that pins the incremental checksum against an independent full
//! recompute, the unit tests, and the criterion bench). The kernel program's `main.rs` only does the
//! bounds-checked packet I/O + the FIB lookup around these functions.
//!
//! ## Why incremental, not recompute
//! A media relay changes exactly the L3 source/destination address and the L4 source/destination
//! port; everything else (the RTP/UDP payload) is untouched. XDP has no `l3/l4_csum_replace` helper
//! (those are TC-only), so the fixup is hand-rolled per **RFC 1624** (`HC' = ~(~HC + ~m + m')`) over
//! just the changed 16-bit words — never a full pass over the datagram. The acceptance test is that,
//! for arbitrary before/after tuples, this equals an independent from-scratch one's-complement sum
//! (RFC 1071) over the whole header — see the proptest below.

// -------------------------------------------------------------------------------------------------
// RFC 1071 / RFC 1624 incremental checksum fixup
// -------------------------------------------------------------------------------------------------

/// IPv4 protocol number for UDP (RFC 790 / IANA) — the pseudo-header protocol byte.
pub const IPPROTO_UDP: u8 = 17;

/// Fold a 32-bit one's-complement accumulator down to 16 bits by carrying the high half back in
/// (RFC 1071 §1). Terminates in at most two iterations for any `u32`.
#[inline(always)]
#[must_use]
pub fn fold16(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// The high 16-bit word of a host-order `u32` (the big-endian *first* word when serialised).
#[inline(always)]
fn word_hi(value: u32) -> u16 {
    (value >> 16) as u16
}

/// The low 16-bit word of a host-order `u32` (the big-endian *second* word when serialised).
#[inline(always)]
fn word_lo(value: u32) -> u16 {
    (value & 0xFFFF) as u16
}

/// Accumulate one RFC 1624 field change `m -> m'` into `sum`: add `~m` (16-bit one's complement of
/// the old word) and `m'` (the new word). `sum` is folded once by the caller.
#[inline(always)]
fn accumulate(sum: &mut u32, old_word: u16, new_word: u16) {
    // `!old_word` is the 16-bit one's complement (`0xFFFF - old_word`); RFC 1624 eqn 3.
    *sum += u32::from(!old_word);
    *sum += u32::from(new_word);
}

/// The RFC 1624 incremental IPv4 **header** checksum after rewriting the source and destination
/// addresses — the only header fields a media relay changes (TTL is deliberately preserved; see
/// `siphon-rtp-ebpf`). `old_checksum` is the current header checksum field (host order); addresses
/// are host-order `u32` (`u32::from_be_bytes(octets)`). Returns the corrected checksum (host order).
///
/// The IPv4 header checksum has no "zero means none" rule (that is UDP-only, RFC 768), so `0x0000`
/// is a legal value here and is returned as-is.
#[inline(always)]
#[must_use]
pub fn ipv4_checksum_after_addr_rewrite(
    old_checksum: u16,
    old_src: u32,
    new_src: u32,
    old_dst: u32,
    new_dst: u32,
) -> u16 {
    // Start from ~HC (RFC 1624 eqn 3), then fold every changed 16-bit word in.
    let mut sum = u32::from(!old_checksum);
    accumulate(&mut sum, word_hi(old_src), word_hi(new_src));
    accumulate(&mut sum, word_lo(old_src), word_lo(new_src));
    accumulate(&mut sum, word_hi(old_dst), word_hi(new_dst));
    accumulate(&mut sum, word_lo(old_dst), word_lo(new_dst));
    !fold16(sum)
}

/// The RFC 1624 incremental IPv4 header checksum after rewriting the **TOS byte** — the DiffServ
/// code point (RFC 2474 §3) the relay stamps on media it forwards, so the in-kernel fast path marks
/// identically to the userspace one.
///
/// The TOS byte shares a 16-bit word with the version/IHL byte at header offset 0, so the caller
/// passes `version_ihl` (unchanged) to reassemble that word; this function owns the assembly so a
/// caller cannot get the byte order wrong.
///
/// Composes with [`ipv4_checksum_after_addr_rewrite`]: feeding this the checksum that returned
/// gives the same result as one combined RFC 1624 sum, because `!fold16` and the leading `!` of the
/// next step cancel. The proptest below pins that composition against a full RFC 1071 recompute.
#[inline(always)]
#[must_use]
pub fn ipv4_checksum_after_tos_rewrite(
    old_checksum: u16,
    version_ihl: u8,
    old_tos: u8,
    new_tos: u8,
) -> u16 {
    if old_tos == new_tos {
        return old_checksum;
    }
    let word = |tos: u8| (u16::from(version_ihl) << 8) | u16::from(tos);
    let mut sum = u32::from(!old_checksum);
    accumulate(&mut sum, word(old_tos), word(new_tos));
    !fold16(sum)
}

/// The RFC 1624 incremental **UDP** checksum after rewriting the source/destination address (the
/// UDP pseudo-header, RFC 768) and the source/destination port (the UDP header). All addresses are
/// host-order `u32`; ports and checksums are host-order `u16`.
///
/// RFC 768 zero rules are honoured:
/// - a stored checksum of `0x0000` means "checksum not computed" on IPv4 — it stays `0x0000` (we
///   never turn a checksum-less datagram into a checksummed one);
/// - a *computed* checksum of `0x0000` is transmitted as `0xFFFF` (so it is never confused with
///   "none").
#[inline(always)]
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn udp_checksum_after_rewrite(
    old_checksum: u16,
    old_src_ip: u32,
    new_src_ip: u32,
    old_dst_ip: u32,
    new_dst_ip: u32,
    old_src_port: u16,
    new_src_port: u16,
    old_dst_port: u16,
    new_dst_port: u16,
) -> u16 {
    // RFC 768: a zero checksum field means the sender did not compute one — leave it off.
    if old_checksum == 0 {
        return 0;
    }
    let mut sum = u32::from(!old_checksum);
    // Pseudo-header addresses (RFC 768): both 16-bit halves of src and dst.
    accumulate(&mut sum, word_hi(old_src_ip), word_hi(new_src_ip));
    accumulate(&mut sum, word_lo(old_src_ip), word_lo(new_src_ip));
    accumulate(&mut sum, word_hi(old_dst_ip), word_hi(new_dst_ip));
    accumulate(&mut sum, word_lo(old_dst_ip), word_lo(new_dst_ip));
    // UDP header ports.
    accumulate(&mut sum, old_src_port, new_src_port);
    accumulate(&mut sum, old_dst_port, new_dst_port);
    let computed = !fold16(sum);
    // RFC 768: a computed 0x0000 is transmitted as 0xFFFF.
    if computed == 0 {
        0xFFFF
    } else {
        computed
    }
}

// -------------------------------------------------------------------------------------------------
// RFC 3550 §8 SSRC-consistent symmetric-RTP latch (RTPBleed defence, docs/security-and-nat.md §4
// layer 3). Mirrors the userspace loopback backend's `update_latch` exactly for RTP media; RTCP and
// short datagrams (no readable SSRC) are gated + forwarded but never move the SSRC latch.
// -------------------------------------------------------------------------------------------------

/// The learned source of a flow's peer: address + port + the RTP SSRC it carries, all in **host**
/// byte order — the kernel reads the wire fields with `from_be_bytes` before comparing/storing, so the
/// whole latch state machine is host-order throughout (equality is order-agnostic; the readback in
/// `siphon-rtp-xdp` reconstructs the peer transport from these host-order values). The SSRC is the
/// re-latch consistency key — a genuine NAT rebind keeps its SSRC, an off-path hijack spray does not
/// (RFC 3550 §8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Latched {
    /// Peer source IPv4 (host byte order).
    pub ipv4: u32,
    /// Peer source UDP port (host byte order).
    pub port: u16,
    /// Peer RTP SSRC (host byte order).
    pub ssrc: u32,
}

/// What the in-kernel latch decides for one datagram already accepted by the source gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LatchVerdict {
    /// Forward the datagram; the latch state is unchanged (same source, or a non-RTP datagram that
    /// carries no SSRC to latch on).
    Forward,
    /// Forward the datagram and write [`Latched`] back into the flow's latch state (first learn, or
    /// a same-SSRC NAT rebind from a new source).
    Learn(Latched),
    /// Drop the datagram — a new source whose SSRC does not match the latched stream (a hijack
    /// spray), or any non-RTP datagram from a new source while latched.
    Drop,
}

/// The RTP SSRC (RFC 3550 §5.1, bytes 8..12 of the RTP header / UDP payload) if `payload` is an RTP
/// **media** packet, else `None`. Returns `None` for a datagram too short to hold the fixed RTP
/// header, a non-RTP version, or an RTCP payload type (64..=95, RFC 5761 §4) — RTCP carries no
/// comparable per-stream SSRC at this offset, so it never drives an SSRC re-latch. Mirrors the
/// loopback backend's `rtp_ssrc`.
#[inline(always)]
#[must_use]
pub fn rtp_media_ssrc(payload: &[u8]) -> Option<u32> {
    if payload.len() < 12 || payload[0] >> 6 != 2 {
        return None;
    }
    let payload_type = payload[1] & 0x7F;
    if (64..=95).contains(&payload_type) {
        return None; // RTCP (RFC 5761 §4)
    }
    Some(u32::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
    ]))
}

/// Whether the RFC 7983 first-byte demux classifies `payload` as RTP/RTCP media (128..=191) — the
/// only class allowed to drive the relay or move the latch (docs/security-and-nat.md §4 layer 1).
/// STUN/DTLS/TURN/garbage on a Forward leg are dropped before any latch write.
#[inline(always)]
#[must_use]
pub fn is_rtp_or_rtcp(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(&byte0) if (128..=191).contains(&byte0))
}

/// Whether the RFC 7983 first-byte demux classifies `payload` as STUN (0..=3) — an ICE connectivity
/// check or its response. On an ICE flow these are redirected to userspace for the RFC 8445 agent
/// instead of being dropped by the layer-1 demux; on every other flow they are still dropped.
#[inline(always)]
#[must_use]
pub fn is_stun(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(&byte0) if byte0 <= 3)
}

/// Layer 4 — whether an **ICE** flow may forward this media datagram (docs/security-and-nat.md §4
/// layer 4; RFC 8445 §7).
///
/// On an ICE endpoint the authenticated connectivity check is the *only* thing that may adopt a
/// media source, so this subsumes both the signalled-source gate (layer 2) and the SSRC re-latch
/// (layer 3): media is forwarded only from the source ICE adopted, and media itself never creates or
/// moves that adoption. Before any check has validated a source (`current == None`) nothing is
/// forwarded at all — an ICE leg that blind-latched the first RTP sender would be exactly the
/// RTPbleed hole ICE exists to close.
///
/// The SSRC field of `current` is deliberately not consulted: on an ICE endpoint the adoption is
/// written by the agent in userspace (`Datapath::adopt_source`), which authenticates with
/// MESSAGE-INTEGRITY rather than SSRC continuity. Mirrors the loopback backend's layer-4 gate.
#[inline(always)]
#[must_use]
pub fn ice_media_allowed(current: Option<Latched>, source_ipv4: u32, source_port: u16) -> bool {
    match current {
        Some(latched) => latched.ipv4 == source_ipv4 && latched.port == source_port,
        None => false,
    }
}

/// Apply the SSRC-consistent latch policy to one datagram that has already passed the RFC 7983 demux
/// (layer 1) and the signalled-source gate (layer 2). `current` is the flow's latch state (`None`
/// when not yet latched), `source_*` is the datagram's L3/L4 source (host order — the kernel reads the
/// wire fields with `from_be_bytes` before calling), and `ssrc` is [`rtp_media_ssrc`] of its payload.
/// Returns the [`LatchVerdict`]. RFC 3550 §8; RFC 4961.
///
/// This is a pure function of `(current, source, ssrc)` — no I/O — so it is exhaustively unit-tested
/// on the host and reused verbatim by the kernel program.
#[inline(always)]
#[must_use]
pub fn latch_decision(
    current: Option<Latched>,
    source_ipv4: u32,
    source_port: u16,
    ssrc: Option<u32>,
) -> LatchVerdict {
    match current {
        // Not yet latched: learn the first source that carries an SSRC. A datagram with no readable
        // SSRC (RTCP / too short) is forwarded but does not pin the media path (stricter than the
        // loopback's latch-on-any-accepted, and never weaker — it only ever narrows the gate).
        None => match ssrc {
            Some(ssrc) => LatchVerdict::Learn(Latched {
                ipv4: source_ipv4,
                port: source_port,
                ssrc,
            }),
            None => LatchVerdict::Forward,
        },
        Some(latched) => {
            if latched.ipv4 == source_ipv4 && latched.port == source_port {
                // Same path — forward; a same-source SSRC change is a legitimate RTP SSRC change
                // (RFC 3550 §8), not a hijack, so we keep forwarding without re-pinning.
                LatchVerdict::Forward
            } else {
                // New source: re-latch only on a matching SSRC (a genuine NAT rebind keeps its
                // SSRC); anything else — a different SSRC, or a non-RTP datagram — is a spray/hijack.
                match ssrc {
                    Some(seen) if seen == latched.ssrc => LatchVerdict::Learn(Latched {
                        ipv4: source_ipv4,
                        port: source_port,
                        ssrc: seen,
                    }),
                    _ => LatchVerdict::Drop,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // --- Independent one's-complement oracle (RFC 1071), mirrored from siphon-rtp-xdp::headers so
    //     the incremental fixup is validated against a from-scratch recompute, not a round-trip. ---

    /// Sum `data` as big-endian 16-bit words into a 32-bit accumulator (odd trailing byte is the high
    /// byte of a word whose low byte is zero, RFC 1071 §1).
    fn sum_be16(data: &[u8]) -> u32 {
        let mut sum = 0u32;
        let (words, remainder) = data.as_chunks::<2>();
        for chunk in words {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let [last] = remainder {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
        sum
    }

    /// Full IPv4 header checksum over a 20-byte header whose checksum field is zeroed (RFC 1071).
    fn full_ipv4_checksum(header: &[u8; 20]) -> u16 {
        !fold16(sum_be16(header))
    }

    /// Full UDP checksum over the pseudo-header + UDP header + payload, in *transmitted* form
    /// (computed 0 -> 0xFFFF, RFC 768).
    fn full_udp_checksum(src_ip: u32, dst_ip: u32, udp_segment: &[u8]) -> u16 {
        let mut sum = 0u32;
        sum += u32::from(word_hi(src_ip));
        sum += u32::from(word_lo(src_ip));
        sum += u32::from(word_hi(dst_ip));
        sum += u32::from(word_lo(dst_ip));
        sum += u32::from(IPPROTO_UDP); // zero byte ‖ protocol
        sum += udp_segment.len() as u32; // UDP length (header + payload)
        sum += sum_be16(udp_segment);
        let computed = !fold16(sum);
        if computed == 0 {
            0xFFFF
        } else {
            computed
        }
    }

    /// Build a 20-byte IPv4 header (checksum field zeroed) with the given fields + addresses.
    fn ipv4_header(total_len: u16, id: u16, ttl: u8, src: u32, dst: u32) -> [u8; 20] {
        ipv4_header_with_tos(total_len, id, ttl, 0, src, dst)
    }

    /// As [`ipv4_header`], with an explicit TOS byte (RFC 2474 DSCP ‖ RFC 3168 ECN).
    fn ipv4_header_with_tos(
        total_len: u16,
        id: u16,
        ttl: u8,
        tos: u8,
        src: u32,
        dst: u32,
    ) -> [u8; 20] {
        let mut header = [0u8; 20];
        header[0] = 0x45; // version 4, IHL 5
        header[1] = tos;
        header[2..4].copy_from_slice(&total_len.to_be_bytes());
        header[4..6].copy_from_slice(&id.to_be_bytes());
        header[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF
        header[8] = ttl;
        header[9] = IPPROTO_UDP;
        // header[10..12] = checksum, left zero for the recompute.
        header[12..16].copy_from_slice(&src.to_be_bytes());
        header[16..20].copy_from_slice(&dst.to_be_bytes());
        header
    }

    #[test]
    fn an_unchanged_tos_leaves_the_checksum_alone() {
        // The common case on an already-marked flow: no write, no fixup, no cost.
        let header = ipv4_header_with_tos(200, 7, 64, 0xB8, 0xC000_0201, 0xC000_0202);
        let checksum = full_ipv4_checksum(&header);
        assert_eq!(
            ipv4_checksum_after_tos_rewrite(checksum, 0x45, 0xB8, 0xB8),
            checksum
        );
    }

    #[test]
    fn marking_an_unmarked_header_expedited_forwarding_keeps_it_valid() {
        // DSCP 46 (EF, RFC 3246) << 2 == 0xB8 — the byte the relay stamps on media.
        let unmarked = ipv4_header_with_tos(200, 7, 64, 0x00, 0xC000_0201, 0xC000_0202);
        let old_checksum = full_ipv4_checksum(&unmarked);
        let marked = ipv4_header_with_tos(200, 7, 64, 0xB8, 0xC000_0201, 0xC000_0202);

        let got = ipv4_checksum_after_tos_rewrite(old_checksum, 0x45, 0x00, 0xB8);
        assert_eq!(got, full_ipv4_checksum(&marked));

        // And the marked header with that checksum written in sums to zero (RFC 1071 §1: a valid
        // header's one's-complement sum including the checksum field is 0xFFFF -> ~ == 0).
        let mut verified = marked;
        verified[10..12].copy_from_slice(&got.to_be_bytes());
        assert_eq!(!fold16(sum_be16(&verified)), 0);
    }

    #[test]
    fn fold16_carries_the_high_half_back_in() {
        assert_eq!(fold16(0x0001_0000), 1);
        // End-around carry: 0xFFFF + 1 = 0x1_0000, fold -> 0x0001 (one's-complement -0 + 1).
        assert_eq!(fold16(0x0001_FFFF), 1);
        assert_eq!(fold16(0xFFFF), 0xFFFF);
        assert_eq!(fold16(0), 0);
    }

    #[test]
    fn ipv4_incremental_validates_at_a_receiver() {
        // Rewrite src/dst on a concrete header; the corrected header (checksum included) must sum to
        // zero at a receiver (RFC 1071 §1).
        let old_src = u32::from_be_bytes([198, 51, 100, 1]);
        let old_dst = u32::from_be_bytes([203, 0, 113, 5]);
        let new_src = u32::from_be_bytes([192, 0, 2, 9]);
        let new_dst = u32::from_be_bytes([198, 51, 100, 42]);

        let mut old_header = ipv4_header(200, 0x1234, 64, old_src, old_dst);
        let old_checksum = full_ipv4_checksum(&old_header);
        old_header[10..12].copy_from_slice(&old_checksum.to_be_bytes());

        let got =
            ipv4_checksum_after_addr_rewrite(old_checksum, old_src, new_src, old_dst, new_dst);

        let mut new_header = ipv4_header(200, 0x1234, 64, new_src, new_dst);
        new_header[10..12].copy_from_slice(&got.to_be_bytes());
        assert_eq!(full_ipv4_checksum(&new_header), 0);
    }

    proptest! {
        /// The RFC 1624 incremental IPv4 checksum equals a full from-scratch RFC 1071 recompute over
        /// the rewritten header, for arbitrary addresses and other header fields. A shared bug in a
        /// round-trip would pass; comparing incremental against an independent recompute cannot.
        #[test]
        fn ipv4_incremental_equals_full_recompute(
            total_len in any::<u16>(),
            id in any::<u16>(),
            ttl in any::<u8>(),
            old_src in any::<u32>(),
            new_src in any::<u32>(),
            old_dst in any::<u32>(),
            new_dst in any::<u32>(),
        ) {
            let old_header = ipv4_header(total_len, id, ttl, old_src, old_dst);
            let old_checksum = full_ipv4_checksum(&old_header);

            let new_header = ipv4_header(total_len, id, ttl, new_src, new_dst);
            let expected = full_ipv4_checksum(&new_header);

            let got = ipv4_checksum_after_addr_rewrite(
                old_checksum, old_src, new_src, old_dst, new_dst,
            );
            prop_assert_eq!(got, expected);
        }

        /// The RFC 1624 incremental IPv4 checksum after a TOS rewrite equals a full RFC 1071
        /// recompute over the re-marked header — the in-kernel DSCP stamp (RFC 2474) must leave the
        /// header checksum valid or every marked packet is dropped by the next hop.
        #[test]
        fn ipv4_tos_incremental_equals_full_recompute(
            total_len in any::<u16>(),
            id in any::<u16>(),
            ttl in any::<u8>(),
            old_tos in any::<u8>(),
            new_tos in any::<u8>(),
            src in any::<u32>(),
            dst in any::<u32>(),
        ) {
            let old_header = ipv4_header_with_tos(total_len, id, ttl, old_tos, src, dst);
            let old_checksum = full_ipv4_checksum(&old_header);

            let new_header = ipv4_header_with_tos(total_len, id, ttl, new_tos, src, dst);
            let expected = full_ipv4_checksum(&new_header);

            let got = ipv4_checksum_after_tos_rewrite(old_checksum, 0x45, old_tos, new_tos);
            prop_assert_eq!(got, expected);
        }

        /// The address fixup and the TOS fixup **compose**: the kernel forward path applies both to
        /// one header, so chaining them must equal a full recompute of the fully-rewritten header.
        #[test]
        fn ipv4_addr_then_tos_composes_to_the_full_recompute(
            total_len in any::<u16>(),
            id in any::<u16>(),
            ttl in any::<u8>(),
            old_tos in any::<u8>(),
            new_tos in any::<u8>(),
            old_src in any::<u32>(),
            new_src in any::<u32>(),
            old_dst in any::<u32>(),
            new_dst in any::<u32>(),
        ) {
            let old_header =
                ipv4_header_with_tos(total_len, id, ttl, old_tos, old_src, old_dst);
            let old_checksum = full_ipv4_checksum(&old_header);

            let new_header =
                ipv4_header_with_tos(total_len, id, ttl, new_tos, new_src, new_dst);
            let expected = full_ipv4_checksum(&new_header);

            let after_addrs = ipv4_checksum_after_addr_rewrite(
                old_checksum, old_src, new_src, old_dst, new_dst,
            );
            let got = ipv4_checksum_after_tos_rewrite(after_addrs, 0x45, old_tos, new_tos);
            prop_assert_eq!(got, expected);
        }

        /// The RFC 1624 incremental UDP checksum equals a full recompute over the rewritten
        /// pseudo-header + UDP header + payload, for arbitrary addresses, ports and payloads.
        #[test]
        fn udp_incremental_equals_full_recompute(
            old_src_ip in any::<u32>(),
            new_src_ip in any::<u32>(),
            old_dst_ip in any::<u32>(),
            new_dst_ip in any::<u32>(),
            old_src_port in any::<u16>(),
            new_src_port in any::<u16>(),
            old_dst_port in any::<u16>(),
            new_dst_port in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            // Build the old UDP segment (8-byte header + payload), checksum field zeroed.
            let udp_len = (8 + payload.len()) as u16;
            let build = |sport: u16, dport: u16| {
                let mut seg = std::vec![0u8; udp_len as usize];
                seg[0..2].copy_from_slice(&sport.to_be_bytes());
                seg[2..4].copy_from_slice(&dport.to_be_bytes());
                seg[4..6].copy_from_slice(&udp_len.to_be_bytes());
                // seg[6..8] checksum = 0
                seg[8..].copy_from_slice(&payload);
                seg
            };
            let old_seg = build(old_src_port, old_dst_port);
            let old_checksum = full_udp_checksum(old_src_ip, old_dst_ip, &old_seg);

            let new_seg = build(new_src_port, new_dst_port);
            let expected = full_udp_checksum(new_src_ip, new_dst_ip, &new_seg);

            let got = udp_checksum_after_rewrite(
                old_checksum,
                old_src_ip, new_src_ip,
                old_dst_ip, new_dst_ip,
                old_src_port, new_src_port,
                old_dst_port, new_dst_port,
            );
            prop_assert_eq!(got, expected);
        }
    }

    #[test]
    fn udp_zero_checksum_stays_off() {
        // RFC 768: a datagram sent without a UDP checksum (field 0) must not gain one on rewrite.
        let got = udp_checksum_after_rewrite(0, 1, 2, 3, 4, 5, 6, 7, 8);
        assert_eq!(got, 0);
    }

    #[test]
    fn udp_transmitted_checksum_is_never_a_bare_zero() {
        // The transmitted form maps a computed 0x0000 to 0xFFFF (RFC 768); the oracle enforces the
        // same, so a real (checksummed) datagram never carries 0x0000.
        let checksum = full_udp_checksum(0, 0, &[0, 0, 0, 8, 0, 8, 0, 0]);
        assert_ne!(checksum, 0);
    }

    // --- Latch state machine (mirrors the loopback backend's update_latch outcomes for RTP). ---

    fn latched(ipv4: u32, port: u16, ssrc: u32) -> Latched {
        Latched { ipv4, port, ssrc }
    }

    #[test]
    fn first_rtp_source_is_learned() {
        let verdict = latch_decision(None, 0x0A00_0001, 5000, Some(0xDEAD_BEEF));
        assert_eq!(
            verdict,
            LatchVerdict::Learn(latched(0x0A00_0001, 5000, 0xDEAD_BEEF))
        );
    }

    #[test]
    fn first_datagram_without_ssrc_forwards_without_latching() {
        // RTCP / too-short before any RTP: forwarded, but does not pin the media path.
        assert_eq!(
            latch_decision(None, 0x0A00_0001, 5000, None),
            LatchVerdict::Forward
        );
    }

    #[test]
    fn same_latched_source_forwards_unchanged() {
        let current = Some(latched(0x0A00_0001, 5000, 0x1111_2222));
        assert_eq!(
            latch_decision(current, 0x0A00_0001, 5000, Some(0x1111_2222)),
            LatchVerdict::Forward
        );
        // A same-source SSRC change is a legitimate RTP SSRC change, not a hijack — still forward.
        assert_eq!(
            latch_decision(current, 0x0A00_0001, 5000, Some(0x9999_9999)),
            LatchVerdict::Forward
        );
    }

    #[test]
    fn new_source_same_ssrc_is_a_nat_rebind_relatch() {
        let current = Some(latched(0x0A00_0001, 5000, 0x1111_2222));
        // A new address that keeps the SSRC: genuine NAT rebind — re-latch to it (RFC 4961).
        assert_eq!(
            latch_decision(current, 0xC000_0209, 6000, Some(0x1111_2222)),
            LatchVerdict::Learn(latched(0xC000_0209, 6000, 0x1111_2222))
        );
    }

    #[test]
    fn new_source_different_ssrc_is_a_hijack_drop() {
        let current = Some(latched(0x0A00_0001, 5000, 0x1111_2222));
        // A new address spraying a *different* SSRC is the RTPBleed hijack primitive — drop, keep
        // the existing latch (RFC 3550 §8).
        assert_eq!(
            latch_decision(current, 0xC000_0209, 6000, Some(0x3333_4444)),
            LatchVerdict::Drop
        );
    }

    #[test]
    fn new_source_without_ssrc_is_dropped_while_latched() {
        let current = Some(latched(0x0A00_0001, 5000, 0x1111_2222));
        // A new-source RTCP / non-RTP datagram cannot prove the SSRC — reject (never re-latch on it).
        assert_eq!(
            latch_decision(current, 0xC000_0209, 6000, None),
            LatchVerdict::Drop
        );
    }

    #[test]
    fn rtp_media_ssrc_reads_the_ssrc_and_rejects_rtcp_and_short() {
        // A minimal RTP media packet: V=2, PT=0 (PCMU), SSRC = 0x11223344.
        let rtp = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB,
        ];
        assert_eq!(rtp_media_ssrc(&rtp), Some(0x1122_3344));
        // RTCP sender report (PT 200) in the muxed range carries no comparable SSRC here.
        let mut rtcp = rtp;
        rtcp[1] = 200;
        assert_eq!(rtp_media_ssrc(&rtcp), None);
        // Too short to hold the fixed 12-byte header.
        assert_eq!(rtp_media_ssrc(&rtp[..8]), None);
        // Wrong RTP version.
        let mut v1 = rtp;
        v1[0] = 0x40;
        assert_eq!(rtp_media_ssrc(&v1), None);
    }

    #[test]
    fn demux_accepts_only_the_rtp_rtcp_range() {
        // First byte 128..=191 (RFC 7983): V=2 for both RTP and RTCP. (The RTCP PT 200 lives in the
        // *second* byte; the first byte of an RTCP SR is 0x80..0x9F.)
        assert!(is_rtp_or_rtcp(&[0x80])); // RTP / RTCP, V=2 RC=0
        assert!(is_rtp_or_rtcp(&[0xBF])); // top of the range
        assert!(!is_rtp_or_rtcp(&[0xC8])); // 200 — out of range as a first byte
        assert!(!is_rtp_or_rtcp(&[0x00])); // STUN
        assert!(!is_rtp_or_rtcp(&[20])); // DTLS
        assert!(!is_rtp_or_rtcp(&[64])); // TURN channel
        assert!(!is_rtp_or_rtcp(&[])); // empty
    }

    #[test]
    fn stun_demux_accepts_only_the_rfc_7983_stun_range() {
        // RFC 7983: STUN is 0..=3. A Binding request's first byte is 0x00, a response's 0x01.
        assert!(is_stun(&[0x00])); // Binding request
        assert!(is_stun(&[0x01])); // Binding response
        assert!(is_stun(&[0x03])); // top of the range
        assert!(!is_stun(&[0x04])); // just past it
        assert!(!is_stun(&[20])); // DTLS
        assert!(!is_stun(&[64])); // TURN channel
        assert!(!is_stun(&[0x80])); // RTP
        assert!(!is_stun(&[])); // empty
    }

    /// The two demux predicates must never both claim a byte, or a datagram's handling would depend
    /// on which is tested first. Exhaustive over the whole byte range.
    #[test]
    fn stun_and_media_demux_ranges_are_disjoint() {
        for byte in 0u8..=255 {
            assert!(
                !(is_stun(&[byte]) && is_rtp_or_rtcp(&[byte])),
                "byte {byte} claimed by both demux classes"
            );
        }
    }

    #[test]
    fn ice_media_gate_forwards_only_the_adopted_source() {
        let adopted = Latched {
            ipv4: 0xC000_0201, // 192.0.2.1
            port: 40000,
            ssrc: 0x1122_3344,
        };
        // The adopted transport, and only it, is forwarded.
        assert!(ice_media_allowed(Some(adopted), 0xC000_0201, 40000));
        // Same address, different port — a different transport, so not the adopted path.
        assert!(!ice_media_allowed(Some(adopted), 0xC000_0201, 40001));
        // Same port, different address.
        assert!(!ice_media_allowed(Some(adopted), 0xC000_0202, 40000));
    }

    #[test]
    fn ice_media_gate_drops_everything_before_a_check_validates_a_source() {
        // The RTPbleed case ICE exists to close: with nothing adopted, the first RTP sender to
        // arrive must NOT become the media path. Nothing is forwarded at all.
        assert!(!ice_media_allowed(None, 0xC000_0201, 40000));
        assert!(!ice_media_allowed(None, 0x0A00_0001, 1));
    }

    /// An SSRC that matches the adopted latch buys a foreign transport nothing on an ICE flow — the
    /// re-latch escape hatch that layer 3 grants a plain relay is deliberately absent here, because
    /// on an ICE endpoint only an authenticated check may move the path (RFC 8445 §7.3).
    #[test]
    fn ice_media_gate_ignores_a_matching_ssrc_from_a_foreign_source() {
        let adopted = Latched {
            ipv4: 0xC000_0201,
            port: 40000,
            ssrc: 0x1122_3344,
        };
        // Layer 3 would re-latch this (same SSRC = a NAT rebind); layer 4 must not.
        assert_eq!(
            latch_decision(Some(adopted), 0xC000_02FF, 50000, Some(0x1122_3344)),
            LatchVerdict::Learn(Latched {
                ipv4: 0xC000_02FF,
                port: 50000,
                ssrc: 0x1122_3344,
            })
        );
        assert!(!ice_media_allowed(Some(adopted), 0xC000_02FF, 50000));
    }
}
