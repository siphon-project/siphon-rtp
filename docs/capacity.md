# Capacity & sizing (relay)

How many concurrent calls one node carries, and which limit you hit first. This page is about
**plain relay** — no transcoding, no SRTP, no conferencing — because that is the cheapest pipeline
and therefore the one where the cost is the datapath itself rather than the codec.

The short version: on a relay-only node the CPU is rarely what runs out first. A **file-descriptor
limit** and a **passive packet capture** both bite earlier than the relay does, and neither shows up
as a CPU graph.

- [What was measured, and how](#what-was-measured-and-how)
- [The numbers](#the-numbers)
- [Where the time actually goes](#where-the-time-actually-goes)
  - [Does batching the syscalls help?](#does-batching-the-syscalls-help)
- [Sizing a node from those numbers](#sizing-a-node-from-those-numbers)
- [The limits that bite before CPU](#the-limits-that-bite-before-cpu)
- [Deriving an honest `--max-sessions`](#deriving-an-honest-max-sessions)
- [What these numbers do not tell you](#what-these-numbers-do-not-tell-you)

---

## What was measured, and how

With `siphon-rtp-loadgen`, a development-only harness in the repository. It boots the real engine on
the real userspace UDP datapath, establishes N plain relay calls through the engine's own control
surface, and drives real RTP through all of them at 50 pps per stream (G.711, 20 ms ptime). Each
relayed call carries two streams, so N calls offer `N × 100` packets per second.

```sh
cargo run --release -p siphon-rtp-loadgen -- --sweep 100,250,500,1000,2000 --duration 20
```

This is **not** the [criterion benchmarks](https://github.com/siphon-project/siphon-rtp#readme),
which measure per-packet *compute* with no socket I/O. The relay's cost is not compute — it is two
syscalls and a handful of map lookups per packet, one packet per ptime on each of two sockets per
call. That only shows up when the whole system runs.

The figure to reason with is **engine CPU microseconds per relayed packet**. The harness shares a
process with the engine and performs comparable syscall work, so CPU is attributed per thread from
`/proc/self/task` and the harness's own share is excluded. A per-packet cost is independent of how
saturated the box got, which is what makes it usable as a sizing input; "N calls ran cleanly" only
says the box was not saturated, not where saturation is.

Measured on one host: **AMD Ryzen AI 9 HX 370**, 12 cores / 24 threads, release build, engine
confined to 4 worker threads. Endpoints and synthetic peers are on loopback.

## The numbers

| Concurrent calls | Relayed | Loss | Engine CPU / packet | Engine cores | In kernel | Latency p50 |
|---|--:|--:|--:|--:|--:|--:|
| 100 | 10 000 pps | 0.13 % | 10.1 µs | 0.10 | 64.8 % | 0.5–1.3 ms |
| 250 | 25 000 pps | 0.10 % | 8.4 µs | 0.21 | 68.9 % | 0.8–0.9 ms |
| 500 | 50 000 pps | 0.03 % | 7.3 µs | 0.37 | 68.2 % | 1.2–1.3 ms |
| 1 000 | 100 000 pps | 0.03 % | 7.5 µs | 0.75 | 69.8 % | 2.3–2.4 ms |
| 2 000 | 200 000 pps | 0.00 % | 7.9 µs | 1.58 | 70.3 % | 4.2–5.7 ms |

Each row is the mean of repeated passes. Run-to-run spread on this host is about **±10 %**, which is
large enough that a single run should not be read as a change; the second host below, which was
quiet, agreed inside ±1 %. Quote a mean of several passes or do not quote a number.

Three things are worth reading off that table.

**Per-packet cost is flat.** It stays inside 7–10 µs across a twentyfold range, so nothing in the
one-socket-and-one-task-per-stream model degrades with scale — 2 000 calls is 4 000 sockets and
4 000 receive tasks, and the cost per packet at that point is the same as at 100 calls. Capacity is
therefore close to linear in cores, and the arithmetic below is sound rather than optimistic. The
higher figure at 100 calls is fixed overhead amortising, not a small-run advantage.

**About 70 % of it is kernel time, and the share grows with load.** That is the syscall bill:
one `recvmsg` and one `sendmsg` per relayed packet. It is the single largest item in the relay's
cost and the reason a kernel-bypass datapath ([XDP](datapath.md)) is on the roadmap at all.

**Latency is scheduling, not queueing.** The p50 climbs from under a millisecond to about 5 ms as
the socket count grows, all of it well inside a 20 ms ptime. The p99 is not tabulated because on a
host with other work on it the tail measures the host, not the engine — it moved between 2 ms and
40 ms across passes at identical load.

### The same measurement on a second host

Because the cost is mostly syscall, it moves with the host by a factor that is worth seeing rather
than assuming. The same harness, same build, same call counts, on a **2 vCPU Skylake-generation
virtualised instance with page-table isolation and IBRS both active** (against the 12-core desktop
part above, which needs neither):

| Concurrent calls | Desktop part | Virtualised, mitigations active | Ratio |
|---|--:|--:|--:|
| 100 | 10.1 µs | 29.4 µs | 2.9× |
| 250 | 8.4 µs | 21.5 µs | 2.6× |

Kernel share is ~65–70 % on both, so the pipeline is the same shape; only the price of a syscall
changed. Three runs per point on the quiet second host agreed inside **±0.6 %** (21.41 / 21.49 /
21.67 µs at 250 calls), so the gap is real and not measurement noise.

**A relay-only node therefore needs roughly 1.1 cores per 500 concurrent calls on the second host
against 0.37 on the first.** Carrying a table across hardware classes would be wrong by a factor of
nearly three, in the direction that matters.

## Where the time actually goes

Profiled with `perf` at 1000 concurrent calls (100 000 pps), sampling only the engine's threads, with
kernel symbols resolved. Buckets are non-overlapping, first match wins, and sum to 100 %:

| Bucket | Share |
|---|--:|
| spinlock acquire / contention | 16.1 % |
| epoll / readiness tracking | 13.1 % |
| **netfilter conntrack / NAT** | **10.6 %** |
| UDP socket layer | 9.6 % |
| long tail (no symbol above 1.2 %) | 8.6 % |
| file-descriptor lookup + refcount | 7.3 % |
| IP layer | 5.5 % |
| generic socket layer | 5.1 % |
| syscall entry / exit | 4.8 % |
| route / dst lookup | 4.6 % |
| netdev transmit | 4.0 % |
| skb alloc / free | 3.9 % |
| copy to/from user | 2.3 % |
| RCU | 1.7 % |
| hardened usercopy checks | 1.6 % |
| scheduler / wakeup | 0.6 % |
| AppArmor LSM | 0.5 % |
| userspace: Tokio | 0.15 % |
| **userspace: siphon-rtp itself** | **0.04 %** |

**The engine's own relay logic is four hundredths of one percent of the cost.** The flow lookup, the
signalled-source gate, the latch check, the RFC 3550 §A.1 loss counter — all of it, together, rounds
to nothing next to the two syscalls that carry the packet. There is no userspace optimisation
available here, and a criterion bench of the packet handling, however fast it gets, cannot move a
capacity number.

Three things in that table are worth acting on.

**`netfilter conntrack / NAT`, at 10.6 %, is the largest avoidable item.** Connection tracking is
loaded on any host running Docker (`xt_conntrack`, `nf_nat`, `nft_ct`, `xt_MASQUERADE` pull it in) and
it then tracks every relayed media packet — for a media relay that is pure overhead, since the
engine's own source gate is what decides whether a packet is accepted, not conntrack's state. Exempt
the media port range in the `raw` table:

```sh
# -j CT --notrack is the supported form; bare -j NOTRACK is deprecated.
iptables -t raw -A PREROUTING -p udp --dport 30000:40000 -j CT --notrack
iptables -t raw -A OUTPUT     -p udp --sport 30000:40000 -j CT --notrack
```

Check `iptables -t raw -L -n -v` first: if something already exempts the range, this is done. Note
this removes the media flows from `conntrack` listings, which is the point, but worth knowing if you
debug with them. The conntrack **table size** is generally not the constraint — at 4 entries per call
a 2000-call node holds ~8000 against a typical `nf_conntrack_max` of 65536 — so this is about CPU,
not about exhaustion.

**`epoll` plus file-descriptor handling is 20.3 % together**, and that is per-syscall readiness and
lookup machinery, not data movement (`copy to/from user` is only 2.3 %). It is tempting to read that
as the share a batched-submission datapath would reclaim. **We measured it, and that reading is
wrong — or rather, it is true only on some hardware.** See
[Does batching the syscalls help?](#does-batching-the-syscalls-help) below.

**`route / dst lookup` at 4.6 % is smaller than it looks worth chasing.** A `connect()`ed UDP socket
would let the kernel cache the destination and skip most of it, but `connect()` also filters the
receive side, which would collide with the source gate and with latching — so it is not a free
change, and 4.6 % does not justify touching that path.

One caveat on the numbers: this profile is over loopback. On a physical interface the `netdev
transmit` and `skb` shares grow with real driver work, so the other percentages shrink
proportionally. The *shape* holds — overhead machinery dominates, data movement does not, and the
engine's own code is invisible.

### Does batching the syscalls help?

`io_uring` removes the syscall boundary: one `io_uring_enter` carries submissions and completions for
many sockets, where `epoll` + `recvfrom`/`sendto` costs a kernel crossing per operation. Since ~70 %
of the relay's CPU is kernel time, that looks like the obvious lever.

It was measured, with a relay that does one receive and one send per packet exactly as the datapath
does, against an `epoll` control arm, at 50 pps per socket — the production cadence. Both arms read
the source address, because a relay needs it for the source gate. **The answer depends entirely on
the host**, and not by a little:

| Host | `epoll` | `io_uring` | Kernel crossings/packet | Result |
|---|--:|--:|--:|---|
| Modern AMD desktop part, no PTI | 2.75 µs | 3.01 µs | 3.03 → 0.038 | `io_uring` **9 % worse** |
| Virtualised Skylake, PTI + IBRS | 17.25 µs | 14.64 µs | 2.95 → 0.17 | `io_uring` **~15 % better** |

Read the crossings column first: `io_uring` cut kernel crossings by **about a thousandfold on both
hosts** — and on one it still lost. That is the finding. The cost of a relayed packet is the work
*inside* the kernel (the UDP and IP layers, socket locks, skb handling, connection tracking), not the
boundary crossing to get there. Where a crossing is cheap, removing it does not pay for the ring
bookkeeping that replaces it. Where speculative-execution mitigations make a crossing expensive, it
does — and the same three syscalls per packet are then worth about 2.6 µs.

Two things follow for anyone planning this work. Batched submission is a **hardware-conditional**
optimisation, so it belongs behind a runtime-selectable backend rather than as a replacement, or it
regresses the hosts where crossings are already cheap. And `epoll` itself is close to free — 2.75 µs
against 2.71 µs for a round-robin loop that never asks about readiness at all — so the 13 % the
profile attributes to readiness tracking is not 13 % of *avoidable* work.

Reproduce with `cargo run --release -p siphon-rtp-loadgen --example uring_vs_syscall`.

## Sizing a node from those numbers

A relayed call is two streams, each one packet per ptime:

```text
packets/second/call  =  2 / ptime          # 100 pps at a 20 ms ptime
engine cores         =  calls x packets/second/call x microseconds-per-packet / 1e6
```

At a 20 ms ptime that gives, with zero headroom:

| Per-packet cost | CPU per call | Calls per core |
|---|--:|--:|
| 7.5 µs (desktop part) | 0.75 ms/s | ~1 300 |
| 21.5 µs (virtualised, mitigations active) | 2.15 ms/s | ~465 |

Size well below whichever applies: a node at its arithmetic ceiling has nothing left for a traffic
spike, a re-INVITE storm, the control plane, or anything else sharing the box.

!!! warning "Syscall cost is host-specific, and this workload is mostly syscall"
    Around 70 % of the per-packet cost is kernel time, so the figure moves with anything that
    changes syscall cost — CPU generation, and especially speculative-execution mitigations. A host
    with page-table isolation and IBRS active pays materially more per syscall than one without, and
    a virtualised NIC adds driver cost that a loopback measurement does not capture. **Re-measure on
    the hardware you will deploy on** rather than carrying this table over; the harness exists so
    that is a twenty-second job.

## The limits that bite before CPU

**File descriptors, almost always first.** Each relay call binds four media endpoints — RTP and
RTCP on each leg — or two with `rtcp-mux` (RFC 5761). Every one is a socket:

| Soft `nofile` | Calls at 4 fds/call | Calls with `rtcp-mux` |
|---|--:|--:|
| 1 024 (a container default) | ~250 | ~500 |
| 65 536 | ~16 000 | ~32 000 |

A container started without an explicit limit commonly gets **1 024**, which caps a relay node at
roughly **250 concurrent calls** and fails as confusing bind errors rather than as anything that
names the real cause. Set it explicitly:

```sh
# docker / podman
docker run --ulimit nofile=65536:65536 ...
```

```ini
# systemd unit
[Service]
LimitNOFILE=65536
```

`rtcp-mux` is worth treating as a capacity lever and not only an interop flag: it halves both the
descriptor count and the number of receive tasks.

**Passive capture is not free, and it scales with your media, not your calls.** A sniffer filtered
on the media port range sees every packet the relay forwards — at 500 concurrent calls that is
100 000 packets per second through `libpcap`, plus whatever per-stream analysis and compression it
does, competing for the same cores as the engine. On a small node this is frequently the largest
consumer on the box. Give it its own cores, narrow its filter, or move it off the media node.

**Ports.** Already covered under
[the port pool](deployment.md#production-posture): up to 4 per call, 2 with `rtcp-mux`.

**Socket buffers.** `net.core.netdev_max_backlog` and `net.core.wmem_max` at distribution defaults
are sized for ordinary traffic, not for tens of thousands of small datagrams per second arriving on
one receive queue. Raise them before concluding a loss figure is the engine's.

## Deriving an honest `--max-sessions`

`--max-sessions` is advertised capacity for the dispatcher's load score; it
[does not cap admission](scaling-and-ha.md#scale-out-the-dispatcher-model). An honest value is one
where `load_permille` reaches 1000 at about the point the node genuinely runs out — so derive it
from whichever limit is lowest on your node, not from CPU alone:

1. Measure per-packet cost on the real hardware with the harness.
2. Compute the CPU ceiling from the arithmetic above, then take a fraction of it as the target —
   half is a reasonable starting point on a node that also runs a capture or a proxy.
3. Compute the descriptor ceiling from the `nofile` limit actually in force.
4. Advertise the **lower** of the two.

If the descriptor ceiling is the lower one, raise the limit rather than advertising the smaller
number — it is a one-line fix, and CPU is the limit you actually want to be sized against.

## What these numbers do not tell you

Stated plainly, because a capacity table invites more confidence than one deserves.

- **Loopback is not a NIC.** Endpoints and synthetic peers share the loopback interface, so the
  driver, NAPI and the device queue are absent. The syscall and scheduling cost is real; treat the
  result as a **lower bound** on cost over a physical interface, and expect a virtualised NIC with a
  single receive queue to add measurably.
- **Relay only.** Transcoding, SRTP, conferencing, ICE and the WebSocket bridge each add their own
  per-packet or per-frame cost, measured separately in the criterion benches. A transcoding node is
  sized around codec CPU instead — see
  [capacity planning on the datapath page](datapath.md#what-this-means-for-capacity-planning).
- **Not a soak.** Per this project's own standard, a synthetic run is not real-traffic production
  soak testing, and nothing here makes a deployment production-ready.
- **One host, one configuration.** Every figure above is from a single machine at a single worker
  count. It is a starting point for arithmetic, not a guarantee.

---

See also: [Deployment & operations](deployment.md) for the port pool and production posture,
[Scaling, clustering & HA](scaling-and-ha.md) for the dispatcher's load score and how nodes are
ranked, and [Datapath](datapath.md) for why the syscall share is what a kernel fast path would buy
back.
