# Performance & tuning

The knobs, in the order they are worth turning, each with the measurement that justifies it and a way
to confirm it did something. For *how many calls fit on a box* — the measured per-packet costs and the
arithmetic — read [Capacity & sizing](capacity.md) first; this page assumes you have a box and want
more out of it.

One result shapes everything below. Profiled at 100 000 packets per second, **the engine's own relay
logic is 0.04 % of the cost** and Tokio is 0.15 %: the flow lookup, signalled-source gate, latch check
and loss counter together round to nothing. Every figure worth chasing on a relay node is in the
kernel or in the host's configuration, not in this codebase.

- [Before you turn anything](#before-you-turn-anything)
- [Host: file descriptors](#host-file-descriptors)
- [Host: connection tracking](#host-connection-tracking)
- [Host: socket buffers and backlog](#host-socket-buffers-and-backlog)
- [Host: receive queues and interrupts](#host-receive-queues-and-interrupts)
- [Engine: the settings that matter](#engine-the-settings-that-matter)
- [Passive capture is part of the budget](#passive-capture-is-part-of-the-budget)
- [Confirming a change helped](#confirming-a-change-helped)
- [Measured and rejected](#measured-and-rejected)
- [Rules of thumb](#rules-of-thumb)

---

## Before you turn anything

Get a number first. `siphon-rtp-loadgen` in this repository boots the engine on the real UDP datapath,
drives N plain relay calls and reports **engine CPU microseconds per relayed packet**, which is
independent of how saturated the box got:

```sh
cargo run --release -p siphon-rtp-loadgen -- --sweep 100,250,500,1000 --duration 30
```

Two things to know before you read its output. Run-to-run spread is a few per cent on a quiet host and
around ten on a busy one, so **quote the mean of several passes or do not quote a number** — a single
run cannot resolve a 10 % change. And per-packet cost is strongly host-dependent: the same binary
measured 2.6 to 2.9 times more expensive on a virtualised Skylake with page-table isolation and IBRS
active than on a desktop part without them. Numbers from someone else's hardware are a starting point
for arithmetic, never a target.

## Host: file descriptors

**Raise this first. It is the limit that breaks a relay node soonest, and its failure mode names
nothing.**

Every media endpoint is a socket, and a plain relay call binds four of them — RTP and RTCP on each leg
— or two with `rtcp-mux` (RFC 5761):

| Soft `nofile` | Calls at 4 per call | With `rtcp-mux` |
|---|--:|--:|
| 1 024 (common container default) | ~250 | ~500 |
| 65 536 | ~16 000 | ~32 000 |

A container started without an explicit limit commonly gets **1 024**, which caps the node at roughly
**250 concurrent calls**. Past that, `bind` fails with `EMFILE` and surfaces as control-plane errors
that say nothing about descriptors — you will be reading SDP before you think of `ulimit`. The hard
limit is usually already high, so this is an unset knob rather than a privilege problem.

```sh
docker run --ulimit nofile=65536:65536 ...
```

```ini
[Service]
LimitNOFILE=65536
```

Confirm what the running process actually got, not what you configured:

```sh
grep 'Max open files' /proc/$(pidof siphon-rtp)/limits
```

## Host: connection tracking

**Worth about 10 % of the relay's CPU, for two rules and no code — the best ratio on this page.**

Connection tracking is rarely asked for on a media node; it arrives because a container runtime loads
`nf_conntrack` as a side effect of its own rules, and once loaded it tracks every UDP flow on the box,
including all four per relayed call. Profiled at 100 000 pps it is the **third largest consumer on the
relay path at 10.6 %**, behind only spinlocks and `epoll` readiness tracking.

For a relay that work buys nothing. Conntrack exists so a firewall can reason about flow state, but
the engine already decides admission for itself and on stricter grounds — a signalled-source gate that
accepts only the address negotiated in SDP, plus an SSRC-consistent latch that follows a genuine NAT
rebind and rejects a hijack (see [Security & NAT design](security-and-nat.md)). Nothing on the media
path reads conntrack's verdict.

### Check these three things first

!!! warning "On a host whose input policy is `drop`, getting this wrong black-holes all inbound media"
    An exempted packet arrives with `ct state untracked`, which does **not** match
    `ct state established,related`. If a stateful rule is the only thing admitting your media, removing
    tracking removes your media. Verify all three before applying, on every host:

    1. **Media is admitted without reference to conntrack state.** There must be an explicit accept for
       the media port range, not only a stateful one. Check with `nft list ruleset` or
       `iptables-save | grep -i ctstate`.
    2. **No NAT applies to the media.** A relay behind a translation rule needs the tracking that
       implements it. An engine on host networking, sending from the host's own address, does not.
    3. **`ct state invalid drop` will not catch it.** `untracked` and `invalid` are distinct states, so
       such a rule does not match an exempted packet. Confirm on the host with
       `nft -c` against a rule matching `ct state untracked`.

    Re-check all three if the engine ever moves onto a bridge network — container traffic there is
    typically admitted by conntrack state, and these rules would then break it.

### The rules

Exempting has to happen at the `raw` hook (priority −300), ahead of conntrack's own hook at −200, and
in **both** directions, because tracking either one creates the entry. On an `nftables` host, put it in
the file the service loads rather than applying it live:

```
table inet media_notrack {
    chain raw_prerouting {
        type filter hook prerouting priority raw; policy accept;
        udp dport 30000-40000 notrack
    }
    chain raw_output {
        type filter hook output priority raw; policy accept;
        udp sport 30000-40000 notrack
    }
}
```

The `iptables` equivalent, where that is what manages the host — `-j CT --notrack`, since a bare
`-j NOTRACK` is deprecated:

```sh
iptables -t raw -A PREROUTING -p udp --dport 30000:40000 -j CT --notrack
iptables -t raw -A OUTPUT     -p udp --sport 30000:40000 -j CT --notrack
```

Keep the range in step with `--port-min`/`--port-max`. Widen the media pool and the new ports stay
tracked until this moves with it.

### Then check where the accept sits in the chain

Easy to miss, and it gives back part of the gain. If your media currently matches an early
`ct state established,related accept` and the explicit media accept sits at the *end* of the chain,
exempted packets no longer match the early rule and traverse the whole chain to reach the late one —
possibly a dozen or more evaluations where there was one. Move the media accept to the front of the
chain. It widens nothing (the rule and its source set are unchanged; only its position moves) and
exempted media then matches immediately without evaluating the conntrack rules at all.

### Verify

```sh
conntrack -L 2>/dev/null | grep -c ':3[0-9]\{4\}'   # should fall to zero with calls up
cat /proc/sys/net/netfilter/nf_conntrack_count       # should drop ~4 per live call
```

Then place a call and confirm **two-way** audio: a one-way failure is the signature of an admission
rule that no longer matches. The conntrack *table* is usually not the constraint — 4 entries per call
is ~8 000 at 2 000 calls against a typical `nf_conntrack_max` of 65 536 — so this is about CPU.

**It does not affect packet capture.** A sniffer taps via `AF_PACKET`, outside the conntrack hooks, so
exempted packets are still captured in full. Worth stating because the XDP fast path
([Datapath](datapath.md)) *does* make media invisible to libpcap, and the two are easy to conflate.

## Host: socket buffers and backlog

Distribution defaults are sized for ordinary traffic, not for tens of thousands of small datagrams a
second arriving on one receive queue. Raise them before concluding that a loss figure is the engine's:

| Setting | Typical default | Why it matters here |
|---|--:|---|
| `net.core.netdev_max_backlog` | 1 000 | Per-CPU queue between the driver and the stack. At 50 000 pps on one queue, a brief scheduling delay overruns it and the drop is counted nowhere useful. |
| `net.core.rmem_max` | 212 992 | Ceiling for a socket receive buffer. Relevant when a leg is briefly starved of CPU. |
| `net.core.wmem_max` | 212 992 | Send-side ceiling, often left far below `rmem_max`. |

```sh
sysctl -w net.core.netdev_max_backlog=4096
sysctl -w net.core.wmem_max=2097152
```

A socket buffer is a tolerance for jitter, not for a shortfall in throughput. If a node is dropping
because it cannot keep up, a larger buffer converts loss into latency — which for media is not an
improvement. Size the node, then size the buffers.

## Host: receive queues and interrupts

Check how many receive queues the interface actually has before assuming work spreads:

```sh
ethtool -l <interface>
```

On virtualised NICs the answer is frequently **one**, and frequently not raisable from inside the
guest — `ethtool -L` returns `requested channel count exceeds maximum` because the count is set by the
hypervisor. A single queue means all receive processing lands in one softirq context on one CPU, so
adding cores does not spread ingress. If that is the constraint, a larger instance type generally
brings more queues; nothing inside the guest will.

This is also where the XDP path's remaining gap comes from: the classifier redirects to an AF_XDP
socket bound to one queue, with no RSS fan-out across queues yet, so a single-queue NIC additionally
drops `XDP_REDIRECT` into a slower locked transmit mode.

On bare metal with several queues, pin their interrupts to cores that are not also running the engine's
busiest workers, and keep the engine off the cores handling ingress softirqs.

## Engine: the settings that matter

**`rtcp-mux` (RFC 5761) is the one free win.** It halves both the descriptor count and the number of
receive tasks per call. Worth treating as a capacity lever, not only an interop flag.

**A bounded media port range** (`--port-min`/`--port-max`) costs nothing and buys a firewallable media
plane plus the option of warm-standby restore. Size it for concurrency at up to 4 ports per call, 2
with `rtcp-mux`; see [Deployment](deployment.md#production-posture).

**Worker threads default to the host's parallelism**, which is right for a dedicated node. On a node
shared with a proxy or a capture process, the contention is usually better solved by giving those their
own cores than by shrinking the engine's pool.

**Transcoding is a different cost model entirely.** Relay cost is syscalls; transcode cost is codec
CPU, and it is orders of magnitude larger per call. A node doing both should be sized around
`siphon_rtp_transcode_sessions` and the `load` score rather than around packet rate. Leave media in
passthrough wherever the two legs already agree on a codec — the cheapest transcode is the one that
does not happen.

**DSCP marking is not a performance setting.** It requests treatment from the network; it creates no
capacity, and an access network that does not trust it will bleach it at the edge.

## Passive capture is part of the budget

A sniffer filtered on the media port range sees **every packet the relay forwards** — at 500
concurrent calls that is 100 000 packets per second through libpcap, plus whatever per-stream analysis
and compression it performs, competing for the same cores as the engine. On a small node it is
frequently the largest single consumer on the box, and it is invisible in the engine's own metrics.

Options, roughly in order of preference: give it its own cores by sizing the node for both; narrow its
filter to signalling only and keep media analysis off the media node; sample rather than capture
everything; or move it to a mirror port on another host. Whichever you pick, measure it — it is the
component most often left out of a capacity estimate.

## Confirming a change helped

Run the harness before and after at the same call count, several passes each, and compare means. A
change inside the run-to-run spread has not been demonstrated, however plausible the mechanism — two of
the ideas in the section below were plausible and wrong.

Watch these while a change is in flight:

| Signal | What a regression looks like |
|---|---|
| `siphon_rtp_load_permille` | Rising at a flat session count. |
| `siphon_rtp_cpu_permille` | The same, and it is the term that dominates the load score on a relay node with `--max-sessions 0`. |
| Per-call `packets_lost` from `CallSummary` | Network loss, as distinct from engine-side gate drops. |
| `siphon_rtp_jemalloc_allocated_bytes` | Rising at a flat session count is a leak, not load. Gate on this, never on RSS. |

## Measured and rejected

Recorded so the next person does not spend the time again.

**`recvmmsg` / `sendmmsg` — cannot help here.** They batch datagrams on *one* socket, and each media
socket carries one stream at 50 pps: one packet every 20 ms, so there is never a second packet queued
to batch with. It would return a single message per call, identically to `recv_from`, unless you block
waiting for a second one — up to a full packetisation interval of added latency. One socket per
endpoint is forced by SDP, so the traffic cannot be concentrated to make batching work.

**`io_uring` — genuinely hardware-conditional, and it lost on the faster host.** Measured against an
`epoll` control arm at 50 pps per socket, it was about 9 % *more* expensive per packet on a modern
desktop part and 13 to 18 % *cheaper* on a virtualised Skylake with mitigations active. On both hosts
it cut kernel crossings by roughly a **thousandfold**. That is the finding: the cost is the work inside
the kernel, not the boundary crossing to reach it, so removing the crossing only pays where
mitigations have made it expensive. Any implementation therefore belongs behind a runtime-selectable
backend, or it regresses the hosts that needed it least. Reproduce with
`cargo run --release -p siphon-rtp-loadgen --example uring_vs_syscall`.

**`connect()`ing the media sockets to cache the route — not worth it.** Route and destination lookup is
only 4.6 % of the path, and `connect()` on a UDP socket also filters the receive side, which collides
with the source gate and with latching. A small gain for a change on the security-critical path.

**`epoll` is close to free, so do not go looking for it.** A readiness-driven loop measured within about
2 % of one that never asks about readiness at all. The profile attributes 13 % to readiness tracking,
but that is work which has to happen somewhere rather than overhead waiting to be removed.

## Rules of thumb

- Raise `nofile` before anything else, and verify it on the running process rather than in the config.
- Exempt the media range from connection tracking, after checking all three pre-flight conditions.
- Turn on `rtcp-mux` where the peers support it: half the sockets, half the tasks, no downside.
- Count the packet capture as a first-class consumer, or it will surprise you.
- Measure on the hardware you deploy on. Syscall cost varies by nearly 3× across host classes, and
  about 70 % of a relayed packet's cost is kernel time.
- Do not tune the engine's own code. It is 0.04 % of the relay path; the headroom is not there.

---

See also: [Capacity & sizing](capacity.md) for the measured per-packet costs and the sizing arithmetic,
[Deployment & operations](deployment.md#production-posture) for the port pool and production posture,
[Scaling, clustering & HA](scaling-and-ha.md) for the dispatcher's load score, and
[Datapath](datapath.md) for what the kernel fast path does and does not change.
