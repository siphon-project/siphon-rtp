# Datapath (UDP today, XDP planned)

Where packets actually move. This page describes the datapath architecture as it is, not as the
roadmap wants it to be: **the UDP backend is the production datapath today**, and the XDP/AF_XDP
backend is built and unit-tested in its own workspace but **not yet wired into the daemon**.

- [The `Datapath` seam](#the-datapath-seam)
- [What happens to a packet](#what-happens-to-a-packet)
- [The UDP backend (shipping)](#the-udp-backend-shipping)
- [The intended two-tier XDP model (planned)](#the-intended-two-tier-xdp-model-planned)
- [XDP status: built vs. wired](#xdp-status-built-vs-wired)
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

There is no `--xdp` flag and no runtime datapath selection today. If you are running siphon-rtp,
you are running this backend.

## The intended two-tier XDP model (planned)

The design goal, stated plainly so the current state below is measurable against it:

1. **Fast path, in-kernel.** An XDP program (aya, pure Rust) attached to the NIC classifies
   ingress datagrams against a kernel `FLOWS` map. A plain-RTP relay flow gets its L2/L3/L4
   headers rewritten and is transmitted straight back out with `XDP_TX`, never leaving the kernel,
   with the same signalled-source gate enforced in-kernel.
2. **Slow path, userspace actors.** Anything that must touch media bytes (SRTP, transcode,
   WebSocket bridging, conference mixing, TURN) is `XDP_REDIRECT`ed to an AF_XDP socket and lands
   in the same per-leg actors that exist today. The `Datapath` trait is the seam that makes the
   two backends interchangeable; the engine above it does not change.

Today, both tiers run in userspace: the UDP backend's `Forward` is the fast path and its
`Redirect` stream is the slow path, over ordinary sockets.

## XDP status: built vs. wired

The XDP backend lives in `crates/siphon-rtp-xdp`, deliberately **excluded from the main
workspace** (the eBPF program crate builds on a pinned nightly via aya-build; the stable workspace
and `cargo test` never touch it).

Built and unit-tested, NIC-free:

- the loader (load the embedded classifier, attach native or SKB/generic mode),
- the `FLOWS` / `STATS` / `XSKS` map programming with a shared no_std ABI crate
  (`siphon-rtp-ebpf-common`),
- an in-house AF_XDP socket implementation (UMEM/ring bookkeeping) and the busy-poll thread that
  drains RX into the redirect stream,
- Ethernet/IPv4/UDP header build/parse and checksums for TX,
- a capability probe (`xdp_supported`) plus an eager AF_XDP bind, so backend selection can fall
  back to the UDP datapath gracefully.

Not wired, and why it is not the production path yet:

- **Not selected by the daemon.** `main.rs` constructs the UDP backend unconditionally; there is
  no flag, feature, or capability probe in the daemon today.
- **No next-hop MAC resolution.** TX frames are built with a zeroed destination MAC; ARP/neighbour
  lookup (rtnetlink) is the missing piece before frames can egress a real NIC.
- **No in-kernel `XDP_TX` yet.** The eBPF classifier currently `XDP_REDIRECT`s every matched flow
  to userspace; the in-kernel rewrite fast path is unimplemented, so even the wired-up backend
  would today be "kernel-bypass receive, userspace relay".
- Aggregate (not per-flow) kernel stats, no per-flow activity feedback for the media-timeout
  sweep, and no RTCP observation on the future fast path. All documented in the crate as gaps.

The docker-compose profiles already grant the capabilities this will need (`NET_ADMIN`, `BPF`,
bpffs, memlock) so the operational wiring is proven ahead of the code
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
