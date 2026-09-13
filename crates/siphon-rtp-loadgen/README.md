# siphon-rtp-loadgen

Relay capacity harness for [siphon-rtp](https://github.com/siphon-project/siphon-rtp). **A
development tool, not part of the product** — unpublished, and never built into the runtime image.

It answers a question no criterion bench in the tree can: *how many concurrent relay calls does one
node sustain?* The existing benches measure per-packet **compute** (RTP parse, SSRC rewrite, SRTP)
with no socket I/O — and the relay's real cost is not compute. It is two syscalls and a handful of
map lookups per packet, spread one-packet-per-20 ms across one socket per media stream. That is a
property of the running system, so it is measured by running the system.

The harness boots the real engine on the real userspace UDP datapath, establishes N plain relay
calls through the engine's own control surface, and drives real RTP through all of them.

```sh
# one point
cargo run --release -p siphon-rtp-loadgen -- --calls 500 --duration 30

# a sweep, which is the useful thing: one point cannot show where the curve bends
cargo run --release -p siphon-rtp-loadgen -- \
    --sweep 100,250,500,1000,2000 --duration 30 --json results.json
```

## The number to read

**`ENGINE cost per packet`** — engine CPU microseconds per relayed packet.

Not "N calls worked". That a run completed without loss says the box was not saturated; it does not
say where saturation is. The per-packet cost does, and a sizing table for any core count follows
from it by arithmetic.

The generator shares the process with the engine and performs comparable syscall work, so a
whole-process CPU figure would roughly double-count. The engine and the generator get **separate
Tokio runtimes with distinct thread-name prefixes** (`sr-engine`, `sr-loadgen`), and CPU is
attributed per thread from `/proc/self/task`. The generator's own share is printed alongside, as
disclosure rather than as part of the figure.

## What it does not measure

- **The NIC.** Phones and engine endpoints are on loopback, so the driver, NAPI and the device queue
  are absent. The syscall and scheduling cost is real; the packet's path through a real interface is
  not. Treat the result as a **lower bound** on the cost over a physical NIC.
- **Anything but plain relay.** No transcoding, no SRTP, no ICE, no conferencing. Those are separate
  per-packet costs with their own benches.
- **Production soak.** Per the project's own standard, a synthetic run is not real-traffic soak
  testing and does not make anything production-ready.

## Two limits worth knowing before a large run

- **File descriptors.** Each call needs six: four engine endpoints (RTP + RTCP on each leg) and two
  synthetic phones. A default 1024 soft limit is exhausted at 159 calls. The harness reads
  `/proc/self/limits` and warns before it starts rather than failing mid-run with bind errors.
- **CPU resolution.** `/proc` reports CPU in 10 ms ticks per thread, so a small run measures
  quantisation noise rather than cost. Below one CPU-second the report marks the per-packet figure
  `NOT TRUSTWORTHY` instead of printing a number that looks quotable.
- **Harness memory at large call counts.** Each receive task keeps its own latency histogram
  (160 KB), and there is one receive task per socket, so a 2 000-call run spends roughly 640 MB on
  histograms alone. Harmless on a development box, but it means the harness itself needs headroom
  the engine does not. **Follow-up:** group sockets into receive shards (one histogram per shard,
  via `FuturesUnordered`) rather than one per socket. That would also make the generator cheaper,
  which improves the methodology — but it changes the receive concurrency model, so any figures
  recorded before it lands must be re-measured after.

## On the clock

The project bans `Instant::now()` in DSP tests, because a logical sample clock is what makes
jitter/resampler/AEC tests deterministic. This harness uses the wall clock deliberately: throughput
and scheduling latency *are* wall-clock questions, and there is nothing here to make deterministic.

## License

MIT
