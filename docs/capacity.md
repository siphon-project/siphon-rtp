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
- [Recording to Ogg Opus](#recording-to-ogg-opus)
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

Measured on one host: **AMD Ryzen AI 9 HX 370**, 12 cores / 24 threads, release build, default
relay threads (one per CPU) and the default 100 µs batching window. Endpoints and synthetic peers are
on loopback.

## The numbers

| Concurrent calls | Relayed | Loss | Engine CPU / packet | Engine cores | In kernel | Latency p50 |
|---|--:|--:|--:|--:|--:|--:|
| 100 | 10 000 pps | 0.00 % | 13.6 µs | 0.14 | 85.3 % | 0.4 ms |
| 250 | 25 000 pps | 0.03–0.07 % | 10.3 µs | 0.26 | 85.6 % | 0.7 ms |
| 500 | 50 000 pps | 0.05–0.08 % | 8.8 µs | 0.44 | 86.1 % | 1.2 ms |
| 1 000 | 100 000 pps | 0.05–0.09 % | 8.4 µs | 0.84 | 86.2 % | 1.8–2.0 ms |
| 2 000 | 200 000 pps | 0.03–0.05 % | 8.4 µs | 1.69 | 87.7 % | 3.4–3.6 ms |

Each row is the mean of two passes, which agreed within 3 %. Run-to-run spread on a host with other
work on it can reach **±10 %**, so a single run should not be read as a change. Quote a mean of
several passes or do not quote a number.

An earlier version of this table, measured when every socket had its own Tokio receive task, read
7.3–10.1 µs. That build does not reproduce it: re-run on the same host it costs 10.8–11.5 µs per
packet at 2 000 calls, so compare against that, not against the old table.

Three things are worth reading off the table.

**Per-packet cost is flat above a few hundred calls.** It settles at about 8.4 µs from 1 000 calls
on, so nothing in the relay degrades with scale: 2 000 calls is 8 000 sockets spread over the relay
threads, and the cost per packet is the same as at 1 000. Capacity is therefore close to linear in
cores. The higher figure at 100 calls is a quiet relay thread waking for nearly every packet; as
load grows each wake-up serves more of them.

**Close to 90 % of it is kernel time, and the share grows with load.** That is the syscall bill:
one `recvfrom` and one `sendto` per relayed packet. It is the single largest item in the relay's
cost and the reason a kernel-bypass datapath ([XDP](datapath.md)) is on the roadmap at all.

**Latency is scheduling and the batching window, not queueing.** The p50 climbs from under a
millisecond to about 3.5 ms as the socket count grows, all of it well inside a 20 ms ptime. The p99
is not tabulated because on a host with other work on it the tail measures the host, not the engine.

### The same measurement on a second host

Because the cost is mostly syscall, it moves with the host by a factor that is worth seeing rather
than assuming. The same harness, same build (the earlier, task-per-socket one), same call counts, on a **2 vCPU Skylake-generation
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

Profiled with `perf` under a SIPp G.711 load through a siphon B2BUA at 320 calls per second (3 200
concurrent calls, about 320 000 relayed packets per second), sampling only the engine's threads, with
kernel and Rust symbols resolved. The host is an 11th-generation Intel desktop part in an LXC
container, six relay threads, the generator and the SIP proxy on other cores. Buckets are
non-overlapping, kernel buckets match only kernel symbols and userspace buckets only userspace ones,
first match wins:

| Bucket | Before the relay threads | Now |
|---|--:|--:|
| userspace: Tokio I/O and scheduler | 10.5 % | 0.0 % |
| userspace: siphon-rtp relay logic | 9.9 % | 9.9 % |
| userspace: per-packet map lookups and hashing | 8.2 % | 0.7 % |
| generic socket layer | 8.5 % | 10.7 % |
| UDP socket layer | 8.5 % | 9.5 % |
| security (AppArmor LSM, hardened usercopy) | 6.7 % | 7.2 % |
| **netfilter conntrack / NAT** | 5.5 % | **7.1 %** |
| spinlock acquire / contention | 3.8 % | 6.0 % |
| epoll / readiness tracking | 3.3 % | 5.5 % |
| IP layer | 4.9 % | 5.1 % |
| file-descriptor lookup and refcount | 3.6 % | 4.0 % |
| skb alloc / free | 2.2 % | 3.1 % |
| scheduler / wakeup / futex | 1.1 % | 2.7 % |
| netdev transmit | 2.3 % | 2.4 % |
| syscall entry / exit | 1.5 % | 2.4 % |
| copy to/from user | 2.4 % | 2.0 % |
| RCU, route lookup, timers, allocator | 1.6 % | 2.5 % |
| long tail (no symbol above 1 %) | 15.6 % | 19.1 % |

"Before" is a Tokio task per socket reading until `EAGAIN` and looking its flow up in shared maps on
every packet. "Now" is dedicated relay threads (`--relay-threads`, see [Deployment](deployment.md)): one
level-triggered `epoll` per thread, one `recvfrom` per readiness report, and the flow cached per
socket until a control write changes it. The kernel shares grew because the total shrank, not because the kernel
does more: engine CPU per relayed packet on this host fell from 13.2 µs to 11.8 µs over the same
change.

**Userspace went from about 29 % of the cost to about 11 %.** An earlier version of this page put the
engine's own code at 0.04 %. That figure was wrong: the bucketing matched names such as `udp` against
userspace symbols too, so the receive loop and Tokio's socket calls were counted as kernel time. Read
the userspace row as small but real; what is left of it is the receive loop itself and the
out-leg lookup.

**The kernel is still close to 90 % of a relayed packet.** One receive and one send per packet,
each through the full UDP, IP, LSM and netfilter path. That is the reason a kernel-bypass datapath
([XDP](datapath.md)) is on the roadmap.

Three items in that table are host configuration rather than relay work.

**`netfilter conntrack / NAT`, at 7.1 %, is the largest avoidable item.** Connection tracking is
loaded on any host running Docker (`xt_conntrack`, `nf_nat`, `nft_ct`, `xt_MASQUERADE` pull it in) and
it then tracks every relayed media packet. For a media relay that is pure overhead, since the
engine's own source gate is what decides whether a packet is accepted, not conntrack's state. Exempt
the media port range in the `raw` table:

```sh
# -j CT --notrack is the supported form; bare -j NOTRACK is deprecated.
iptables -t raw -A PREROUTING -p udp --dport 30000:40000 -j CT --notrack
iptables -t raw -A OUTPUT     -p udp --sport 30000:40000 -j CT --notrack
```

Check `iptables -t raw -L -n -v` first: if something already exempts the range, this is done. Note
this removes the media flows from `conntrack` listings, which is the point, but worth knowing if you
debug with them. The conntrack **table size** is generally not the constraint (at 4 entries per call
a 2000-call node holds ~8000 against a typical `nf_conntrack_max` of 65536), so this is about CPU,
not about exhaustion.

**The security bucket is AppArmor checking every `sendmsg`** (`aa_inet_msg_perm` alone is the
largest single kernel symbol, 3.9 %). It is there because the container runs under an AppArmor
profile; a host without one does not pay it.

**`epoll` plus file-descriptor handling is about 9.5 %**, and that is per-syscall readiness and
lookup machinery, not data movement (`copy to/from user` is 2.0 %). It is tempting to read that as
the share a batched-submission datapath would reclaim. **We measured it, and that reading is wrong,
or rather true only on some hardware.** See
[Does batching the syscalls help?](#does-batching-the-syscalls-help) below.

**`route / dst lookup` is under 1 %.** A `connect()`ed UDP socket would let the kernel cache the
destination and skip it, but `connect()` also filters the receive side, which would collide with the
source gate and with latching, so it is not worth touching that path.

One caveat on the numbers: the generator and the engine share a host, so the receive side is
loopback-like. On a physical interface the `netdev transmit` and `skb` shares grow with real driver
work and the other percentages shrink proportionally. The *shape* holds: per-packet kernel machinery
dominates, data movement does not.

### Does batching the syscalls help?

`io_uring` removes the syscall boundary: one `io_uring_enter` carries submissions and completions for
many sockets, where `epoll` + `recvfrom`/`sendto` costs a kernel crossing per operation. Since close to
90 % of the relay's CPU is kernel time, that looks like the obvious lever.

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
| 8.4 µs (desktop part) | 0.84 ms/s | ~1 190 |
| 21.5 µs (virtualised, mitigations active, earlier build) | 2.15 ms/s | ~465 |

Size well below whichever applies: a node at its arithmetic ceiling has nothing left for a traffic
spike, a re-INVITE storm, the control plane, or anything else sharing the box.

!!! warning "Syscall cost is host-specific, and this workload is mostly syscall"
    Close to 90 % of the per-packet cost is kernel time, so the figure moves with anything that
    changes syscall cost — CPU generation, and especially speculative-execution mitigations. A host
    with page-table isolation and IBRS active pays materially more per syscall than one without, and
    a virtualised NIC adds driver cost that a loopback measurement does not capture. **Re-measure on
    the hardware you will deploy on** rather than carrying this table over; the harness exists so
    that is a twenty-second job.

## The limits that bite before CPU

On a relay node, CPU is usually not what runs out first. Two other things do, and neither shows up as
a CPU graph. They are stated here because they belong in a capacity estimate; the fixes are in
[Performance & tuning](performance.md).

| Limit | Where it bites | Fix |
|---|--:|---|
| **File-descriptor ceiling** | ~250 calls on a default 1 024 soft `nofile` (4 sockets per call, 2 with `rtcp-mux`) | [Raise `nofile`](performance.md#host-file-descriptors) |
| **Connection tracking** | 10.6 % of relay CPU, on every packet, deciding nothing | [Exempt the media range](performance.md#host-connection-tracking) |
| **Passive capture** | Scales with your *media*, not your calls: 100 000 pps through libpcap at 500 concurrent calls, on the same cores | [Budget for it](performance.md#passive-capture-is-part-of-the-budget) |
| **Receive queues** | A single-queue virtualised NIC puts all ingress on one CPU, and the count is often not raisable from the guest | [Check `ethtool -l`](performance.md#host-receive-queues-and-interrupts) |
| **Socket buffers** | Distribution defaults assume ordinary traffic, not tens of thousands of small datagrams per second | [Raise backlog and `wmem_max`](performance.md#host-socket-buffers-and-backlog) |

The descriptor ceiling is the one to check first, because it fails as bind errors that name nothing
about descriptors — and because at 4 sockets per call it lands at half of a 500-call target.

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
number — it is [a one-line fix](performance.md#host-file-descriptors), and CPU is the limit you
actually want to be sized against.

## Recording to Ogg Opus

Not a relay cost, but the one recording format that spends real CPU: a `start_recording` with
`format: "ogg_opus"` runs an Opus encoder for every 20 ms of recorded audio. It runs in the
recording's writer task, off the media path, and allocates nothing per frame. A `wav` or `pcap`
recording costs a file write and nothing comparable.

Criterion bench `ogg_opus_bench` (Opus encode plus Ogg paging, default bitrate, a speech-like
signal; Ryzen AI 9 HX 370, one core, box under load so read ±10 %):

| Recording | Per 20 ms frame | Concurrent recordings per core |
|---|--:|--:|
| 8 kHz mono (a G.711 voicemail) | 74 µs | ~270 |
| 8 kHz stereo (a G.711 call, one party per channel) | 151 µs | ~130 |
| 16 kHz mono | 141–154 µs | ~130 |
| 16 kHz stereo (an AMR-WB or G.722 call) | 280–306 µs | ~65 |

The per-core figure is `20 ms / per-frame cost`, with zero headroom. A recording is one encode per
20 ms however many legs feed it, so the cost scales with recordings, not with calls.

The encode stays inline in the writer task rather than moving to a blocking pool. One frame costs
well under a millisecond, the task yields between frames, and the transcoding pipelines already run
an Opus encoder on the same runtime for every Opus leg. What it does compete for is the same worker
threads the media actors use, so count recording cores into the budget alongside transcoding: a node
recording 100 stereo G.711 calls spends about 0.75 of a core on it.

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

See also: [Performance & tuning](performance.md) for the knobs these limits are fixed with,
[Deployment & operations](deployment.md) for the port pool and production posture,
[Scaling, clustering & HA](scaling-and-ha.md) for the dispatcher's load score and how nodes are
ranked, and [Datapath](datapath.md) for why the syscall share is what a kernel fast path would buy
back.
