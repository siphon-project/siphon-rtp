# Datapath (UDP default, XDP via a separate daemon)

Where packets actually move. This page describes the datapath architecture as it is: **the UDP
backend is what the default `siphon-rtp` binary runs**, and the XDP/AF_XDP backend is wired into the
separate **`siphon-rtp-xdp-daemon`** binary — the same engine via `run_with_datapath`, choosing the
in-kernel backend when the NIC supports it and falling back to UDP when it does not.

- [The `Datapath` seam](#the-datapath-seam)
- [What happens to a packet](#what-happens-to-a-packet)
- [The UDP backend (shipping)](#the-udp-backend-shipping)
- [The intended two-tier XDP model](#the-intended-two-tier-xdp-model)
- [XDP status](#xdp-status)
- [What this means for capacity planning](#what-this-means-for-capacity-planning)

---

## The `Datapath` seam

Everything above the packet level (session manager, media pipeline, SRTP bridge, conference,
TURN) talks to one trait, `Datapath` (`crates/siphon-rtp-datapath`). A backend hands out
**endpoints** (one endpoint = one bound media socket/port, the thing a rewritten SDP advertises)
and applies one **flow action** per endpoint:

| `FlowAction` | What it does | Who uses it |
|---|---|---|
| `Forward(ForwardRule)` | Re-emit each accepted datagram out a peer endpoint. The relay fast path; this is what an XDP program would do in-kernel as `XDP_TX`. | Plain RTP relay. |
| `Redirect` | Push the datagram onto a shared receive stream for a userspace actor. The slow path. | SRTP bridge, transcode actors, WebSocket bridge, conference mixer, the TURN relay. |
| `Drop` | Discard. | Blocked legs (`block_media`), torn-down endpoints. |

A `ForwardRule` is not just "send it over there". It carries the security policy that makes the
relay safe to expose (see [Security & NAT design](security-and-nat.md) for the threat model):

- **`out_endpoint` / `out_dst`**: the peer-facing socket and the negotiated destination. If no
  destination is resolvable (nothing negotiated, nothing safely latched), the packet is dropped,
  never guessed at.
- **`accepted_source`**: the signalled-source gate, `Exact(ip)` / `Subnet(ip, prefix)` / `Any`.
  Packets from any other source are dropped before they can latch or be forwarded. This closes the
  RTPBleed first-packet race; the offer/answer address is the contract (RFC 3264).
- **`latch`**: the symmetric-RTP lifecycle. `SignalledOnly` (the default) latches only sources
  that pass the gate and re-latches a new source only if it carries the same RTP SSRC (RFC 3550
  §8), a genuine NAT rebind rather than a spray. `Symmetric` (opt-in per leg via the `symmetric`
  flag) accepts and latches the first source for legs whose signalled address is genuinely
  unusable. `Off` never latches.

The trait also provides: family-aware allocation (a `c=IN IP6` call gets a v6 endpoint, RFC 4566
§5.7), **allocation on a specific port** (the HA-restore primitive,
[Scaling, clustering & HA](scaling-and-ha.md#warm-standby-ha)), per-endpoint packet/byte/drop
counters, a logical clock that drives the media-timeout sweep, per-endpoint ICE-lite credentials
so the datapath itself answers STUN Binding checks (RFC 8445 §7.3), and an RTCP observation tee
for HEP export.

One more shared piece: incoming datagrams on a muxed socket are classified by first byte per the
RFC 7983 §7 table (STUN `0..=3`, DTLS `20..=63`, RTP/RTCP `128..=191`, everything else dropped or
ignored). The same table demultiplexes a WebRTC leg's STUN / DTLS handshake / SRTP sub-streams,
so there is exactly one authoritative demux, not three scattered byte checks.

## What happens to a packet

```text
datagram arrives on an endpoint
  -> RFC 7983 first-byte class (STUN answered in-datapath if ICE creds are set)
  -> installed FlowAction:
       Forward: source gate -> latch bookkeeping -> re-emit from the peer endpoint
                to the negotiated destination (or the safely-latched source)
       Redirect: onto the shared rx() stream
                 -> the single redirect dispatcher routes by endpoint id to the
                    SRTP bridge / media actor / WS bridge / conference / TURN relay
       Drop: counted, discarded
```

The redirect stream has exactly one consumer, a dispatcher task the daemon spawns at boot, which
routes each packet to the owning subsystem. Per-leg state (jitter buffer, codec state, SRTP
context) lives in exactly one actor; the datapath never locks per-packet.

## The UDP backend (shipping)

`UdpLoopbackDatapath` is the backend the daemon binds **unconditionally** today. The name
undersells it: every endpoint is a real tokio UDP socket, and it is the same code path in CI, in
the lab, and in production.

- By default endpoints bind loopback (safe, NIC-free, what CI runs). With `--relay-bind-ip` they
  bind a routable address and the engine serves real peers. With `--port-min`/`--port-max` ports
  come from a deterministic, firewallable pool (round-robin cursor, reserve-before-bind, specific
  ports bindable for HA restore) instead of OS-ephemeral.
- Its `Forward` implementation is the behavioural reference for the future in-kernel path: it
  models the XDP_TX rewrite including the source gate and symmetric-RTP latching described above.
  When the XDP backend lands it must match this backend's semantics bit for bit; the loopback
  implementation is the oracle its tests compare against.
- Its clock is logical (explicitly advanced by the daemon's 1 s sweeper, directly settable in
  tests), which is why media-timeout and soak tests are deterministic.

The default `siphon-rtp` binary is UDP-only: it has no `--xdp` flag and no runtime datapath
selection, so if you are running `siphon-rtp` you are running this backend. The separate
`siphon-rtp-xdp-daemon` selects the XDP backend with `--xdp-interface <NAME>` (and `--xdp-queue
<N>`), probing the NIC's capability and falling back to this UDP backend when the host cannot
support XDP.

## QoS marking (DSCP)

Every media datagram the engine emits carries a DiffServ code point (RFC 2474 §3) in the IPv4 TOS
byte / IPv6 Traffic Class octet, so the network can police the media plane as voice. The default is
**EF** (46, RFC 3246 — RFC 4594 §4.1 assigns EF to the Telephony service class), which is TOS byte
`184`: the same value operators already configure as Asterisk's `tos_audio` or rtpengine's `--tos`.
`--media-dscp` (or `media_dscp:` in the config file) takes a name (`EF`, `CS3`, `AF41`, `VA`, `BE`,
…) or a raw `0`–`63`.

**All three egress paths mark identically**, so a call's marking never depends on which datapath
carried it:

| Path | How the byte is set |
| --- | --- |
| Userspace UDP relay | `IP_TOS` / `IPV6_TCLASS` on each bound media socket. A dual-stack `::` socket also gets `IP_TOS`, since a v4-mapped destination egresses through the IPv4 path. |
| AF_XDP TX (the slow path's frame builder) | Written into the IPv4 header it constructs, before the header checksum is computed. |
| In-kernel `XDP_TX` fast path | Rewritten in place alongside the address/port rewrite, with an RFC 1624 incremental header-checksum fixup. The value is a load-time `.rodata` constant (`MEDIA_TOS`, set by the loader), not a per-flow map field — it is node policy, so the flow ABI is unchanged. |

Two deliberate choices:

- **`BE` (or `0`) means "do not mark", not "mark zero".** The option is never set and the byte is
  left as-is, so an operator marking upstream (tc, a CNI plugin, a hypervisor) is not overwritten.
  The in-kernel path likewise skips the write, preserving the sender's byte exactly as it did before
  marking existed.
- **The marking is socket-level, not per-packet.** RTP, RTCP, STUN and DTLS share one socket under
  rtcp-mux, so they all carry the media marking. Giving RTCP its own code point would need an
  `IP_TOS` control message on every `sendmsg` — per-packet cost on the hot path for no real gain.

Only media is marked. The control listeners, the metrics/health HTTP server, the HEP exporter and
the WS bridge are left at best effort. And marking is a request, not a guarantee: an access network
that does not trust DSCP will bleach it at its edge.

## The intended two-tier XDP model

The design goal, stated plainly so the current state below is measurable against it:

1. **Fast path, in-kernel.** An XDP program (aya, pure Rust) attached to the NIC classifies
   ingress datagrams against a kernel `FLOWS` map. A plain-RTP relay flow gets its L2/L3/L4
   headers rewritten and is transmitted straight back out with `XDP_TX`, never leaving the kernel,
   with the same signalled-source gate enforced in-kernel.
2. **Slow path, userspace actors.** Anything that must touch media bytes (SRTP, transcode,
   WebSocket bridging, conference mixing, TURN) is `XDP_REDIRECT`ed to an AF_XDP socket and lands
   in the same per-leg actors that exist today. The `Datapath` trait is the seam that makes the
   two backends interchangeable; the engine above it does not change.

In the default `siphon-rtp` binary both tiers run in userspace: the UDP backend's `Forward` is the
fast path and its `Redirect` stream is the slow path, over ordinary sockets. Under
`siphon-rtp-xdp-daemon` the fast path is an in-kernel `XDP_TX` rewrite and the slow path is an
`XDP_REDIRECT` to an AF_XDP socket.

## XDP status

The XDP backend lives in `crates/siphon-rtp-xdp`, deliberately **excluded from the main
workspace** (the eBPF program crate builds on a pinned nightly via aya-build; the stable workspace
and `cargo test` never touch it). It ships as the separate `siphon-rtp-xdp-daemon` binary, which
depends up into the engine, reuses the whole CLI/TOML surface, and hands its `XdpDatapath` to the
same `siphon_rtp_engine::run_with_datapath` runner the UDP binary uses — so control, TURN,
dispatch, sweep, metrics and NG behave identically over either datapath.

Built, unit-tested, and wired into `siphon-rtp-xdp-daemon`:

- **backend selection and fallback** — `--xdp-interface` / `--xdp-queue`, a capability probe
  (`xdp_supported`), native-then-generic-SKB attach, and a clean fall back to the UDP datapath on
  any missing capability, attach failure, or a non-routable `--relay-bind-ip` (never a hard error);
- the loader and the `FLOWS` / `FLOW_STATS` / `XSKS` map programming over the shared `no_std` ABI
  crate (`siphon-rtp-ebpf-common`);
- an in-house AF_XDP socket implementation (UMEM/ring bookkeeping) and the busy-poll thread that
  drains RX into the redirect stream;
- Ethernet/IPv4/UDP header build/parse and checksums for TX;
- **next-hop MAC resolution** via rtnetlink/ARP (`crates/siphon-rtp-xdp/src/neighbor/`), so TX
  frames egress a real NIC;
- the **in-kernel `XDP_TX` rewrite fast path** (`forward_in_kernel`): a plain-RTP `Forward` flow is
  demuxed (RFC 7983), source-gated, SSRC-latched, L3/L4-rewritten with an RFC 1624 incremental
  checksum fixup, and transmitted straight back out — falling back to `XDP_REDIRECT` only on a
  FIB / neighbour miss;
- **per-flow kernel stats and activity feedback** — the classifier stamps `FlowStats::last_seen_ns`
  per flow, which `Datapath::last_activity` reads to drive the media-timeout sweep;
- an **in-kernel RTCP copy-to-userspace tap** (`RTCP_TAP`), so a kernelized relay's RTCP still
  reaches the HEP QoS export (loss / jitter / RTT for VoIPmonitor / Homer).

Remaining gaps:

- **Single media RX queue.** The classifier redirects to the AF_XDP socket bound on queue 0; there
  is no multi-queue / RSS fan-out across queues yet (`--xdp-queue` selects one queue).

The docker-compose profiles grant the capabilities this needs (`NET_ADMIN`, `BPF`, bpffs, memlock)
([deployment](deployment.md#docker-compose-profiles)).

## What this means for capacity planning

The userspace relay is cheap enough that the missing kernel path is a throughput ceiling concern,
not a per-call latency one. Measured on one core (see the README benchmarks): RTP parse ~1.9 ns,
full parse-rewrite-write ~8 ns per packet, zero per-packet heap. At a typical 50 pps per media
stream, packet processing is nowhere near the bottleneck; syscall overhead and the NIC's pps
budget are what XDP will eventually buy back at very high channel counts. Until then, plan
capacity around transcode CPU (`siphon_rtp_transcode_sessions`, the `load` score) rather than
relay cost.

See also: [Security & NAT design](security-and-nat.md) for why a packet is accepted, latched and
forwarded, [Deployment & operations](deployment.md) for `--relay-bind-ip` and the port pool, and
the [NAT cookbook](cookbook/nat.md) for latching in practice.
