<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/eBPF%2FXDP-kernel%20datapath-orange" alt="eBPF/XDP">
  <img src="https://img.shields.io/badge/Tokio-actor%20model-blue" alt="Tokio">
  <img src="https://img.shields.io/badge/codecs-pure%20Rust%2C%20zero%20C-success" alt="Pure Rust codecs">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

<h1 align="center">siphon-rtp</h1>

<p align="center">
  A pure-Rust, kernel-accelerated <b>media engine</b> for
  <a href="https://github.com/siphon-project/siphon-sip">SIPhon</a>.
</p>

<p align="center">
  <a href="#why-siphon-rtp">Why</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#performance">Performance</a> &middot;
  <a href="#install">Install</a> &middot;
  <a href="#control-protocol">Control protocol</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#building--testing">Building &amp; testing</a> &middot;
  <a href="#status">Status</a>
</p>

---

## Why siphon-rtp

SIPhon owns its signaling plane — proxy, B2BUA, IMS — in Rust. Its media plane has been
external **rtpengine** — the last big non-Rust, non-owned dependency in the stack, and the one
piece standing between SIPhon and a fully self-owned media path for PBX and real-time voice-AI.

`siphon-rtp` is the media engine SIPhon owns. The design bets are deliberate:

- **Pure Rust, zero C dependencies.** Every codec is hand-written Rust — no ffmpeg, no libopus,
  no spandsp, no `-sys` crates. The payoff is a single statically-linked binary, clean licensing,
  and (for IMS/VoLTE) **bit-exact AMR** that ships in one artifact instead of an ffmpeg matrix.
- **IMS/VoLTE codecs first.** G.711 for PSTN interconnect, **AMR-NB and AMR-WB** for VoLTE —
  pure-Rust and **bit-exact against the 3GPP reference**, with a strong focus on per-frame
  performance.
- **Kernel-accelerated relay.** Plain-RTP passthrough is forwarded in-kernel via eBPF/XDP
  (pure-Rust `aya`); flows that touch media (SRTP, transcode, WebSocket, mixing) are redirected to
  per-leg actors over AF_XDP. **No rtpengine kernel module** — XDP is our in-kernel path.
- **Bidirectional RTP ↔ WebSocket streaming as a first-class citizen** — real-time audio
  streamed to and from a WebSocket for voice-AI (STT/TTS/agents), bidirectional and pluggable:
  raw WS PCM, OpenAI Realtime, gRPC, and direct WebRTC bridges.
- **Drop-in twice over.** A native JSON-over-TCP control protocol for SIPhon, and an optional
  rtpengine NG/bencode front-end so existing Kamailio / OpenSIPS deployments switch unchanged.

## Features

| Capability | Standard | Status |
|---|---|---|
| **G.711 (µ-law / A-law)** | ITU-T G.711 | Implemented — bit-exact, all-256 round-trip tested |
| **G.722** | ITU-T G.722 | Implemented — bit-exact vs the ITU reference |
| **G.726 (16 / 24 / 32 / 40 kbit/s)** | ITU-T G.726 | Implemented — bit-exact vs the ITU reference |
| **GSM Full Rate** | GSM 06.10 | Implemented — bit-exact vs the ETSI reference |
| **Comfort noise** | RFC 3389 | Implemented — decode / generate |
| **L16 / PCM** | RFC 3551 | Implemented — big-endian, round-trip tested |
| **AMR-WB** | TS 26.171 / .190, RFC 4867 | Implemented (`amr` feature) — decode and encode bit-exact, all 9 modes (6.60–23.85 kbit/s) vs 3GPP TS 26.174 |
| **AMR-NB** | TS 26.071 / .090, RFC 4867 | Implemented (`amr` feature) — decode and encode bit-exact, all 8 modes (4.75–12.2 kbit/s) vs 3GPP TS 26.074; DTX/SID out of scope |
| **Control: native JSON-over-TCP** | — | Implemented — length-prefixed JSON, async events, optional shared-secret auth |
| **Control: rtpengine NG / bencode** | rtpengine NG | Implemented — drop-in for existing Kamailio / OpenSIPS |
| **Datapath: UDP backend** | — | Implemented — the production datapath today (NIC-free, symmetric-RTP latching) |
| **Datapath: eBPF/XDP + AF_XDP** | — | Planned — `aya`, pure Rust; control plane built, not yet wired into the daemon |
| **RTP / RTCP (SR + RR)** | RFC 3550 / 3551 | Implemented — parse and construct |
| **SRTP (SDES)** | RFC 3711 / 4568 | Implemented — AES-CM + HMAC-SHA1, RFC 3711 anti-replay |
| **DTLS-SRTP** | RFC 5764 | Implemented — pure-RustCrypto handshake keying (webrtc-dtls) |
| **ICE / STUN** | RFC 8445 / 5389 | Implemented — ICE-lite + STUN Binding (full ICE state machine planned) |
| **TURN server** | RFC 5766 / 8656 | Implemented — `turn:` / `turns:` (UDP/TCP/TLS), coturn REST credentials |
| **NAT traversal (symmetric RTP, advertised IP, named interfaces)** | RFC 3550 §8 | Implemented — RTPbleed-gated symmetric latch, `--advertise-ip` for a 1:1-NAT / Elastic-IP host, and rtpengine-style `[[interface]]` + `direction` per-leg selection ([docs](docs/security-and-nat.md)) |
| **Jitter buffer + PLC + resampler** | RFC 3550 | Implemented (resampler AVX2, PLC drives decoder concealment) |
| **VAD / noise suppression / echo cancellation** | — | Implemented — energy VAD, single-channel noise suppression, and echo cancellation (AEC wired on the transcode and WebSocket-bridge paths, not on SRTP/DTLS legs) |
| **WebSocket bridge (raw L16 PCM)** | — | Implemented — bidirectional, `ws://` and `wss://` (wss via ring/rustls + webpki-roots) |
| **OpenAI Realtime / gRPC / WebRTC bridges** | — | Planned |
| **Forking (SIPREC raw-RTP tee)** | RFC 7866 | Implemented |
| **Conferencing (MCU: mix-minus-self, active-speaker, whisper/monitor, room bridging)** | — | Implemented — N-party mixer, JSON control |
| **Observability & QoS (Prometheus, RTCP jitter/loss, G.107 MOS, HEP/Homer)** | RFC 3550 / ITU-T G.107 / HEP3 | Implemented — RR + `call_quality` events ([docs](docs/observability.md)) |
| **Recording (runtime raw-RTP pcap)** | — | Implemented |
| **Clustering + warm-standby HA (checkpoint / restore)** | — | Implemented — plain / SDES-SRTP / transcode / secure-transcode restore (WS restore pending) |
| **Opus** | RFC 6716 / RFC 7587 | Decode implemented and wired — transcoding *from* an Opus leg (SILK / CELT / Hybrid, mono + stereo, PLC + in-band FEC), gated on all 12 official vectors plus exact per-packet `final_range`; the encoder is in progress, so transcoding *toward* Opus is not available yet |
| **EVS** | 3GPP TS 26.441 | Planned |

## Performance

Every hot path carries a [criterion](https://github.com/bheisler/criterion.rs) bench and a CI
regression gate (>10 % over the committed baseline fails the build). The numbers below were taken
with `cargo bench` on a **single core** of an **AMD Ryzen AI 9 HX 370**, release build — pure
per-frame / per-packet compute, no socket I/O and no jitter buffer. One frame is **20 ms**;
**× real-time** is the 20 ms frame budget ÷ the measured time, i.e. how many concurrent real-time
streams one core sustains on that operation alone.

- **G.711 is essentially free** — a µ-law frame decodes in **30 ns** (~660,000× real-time).
- **AMR-WB decode is bit-exact *and* fast** — the 12.65 kbit/s VoLTE mode decodes a full 20 ms
  frame in **~28 µs**, i.e. **~720 concurrent VoLTE decodes per core**. The hot kernels (LPC
  synthesis, pitch interpolation, 12.8→16 kHz oversampling) run on runtime-detected **AVX2 SIMD**
  (pure Rust, scalar fallback) — ~1.6× faster than the scalar port, staying byte-exact.
- **The userspace relay rewrite is ~8 ns/packet** (parse → re-originate SSRC/seq → write), with
  zero per-packet heap — the CPU is never the relay bottleneck.
- **A secure (SRTP) leg adds ~0.5 µs of crypto per packet round-trip** over a plaintext leg.

### Codecs — per 20 ms frame

| Codec / mode | Operation | Per frame | × real-time¹ |
|---|---|--:|--:|
| G.711 µ-law | decode | 30 ns | ~660,000× |
| G.711 µ-law | encode | 176 ns | ~114,000× |
| G.711 A-law | encode | 210 ns | ~95,000× |
| AMR-WB 6.60 kbit/s (mode 0) | decode | 32.7 µs | ~610× |
| AMR-WB 8.85 kbit/s (mode 1) | decode | 29.5 µs | ~680× |
| AMR-WB 12.65 kbit/s (mode 2, VoLTE) | decode | 27.7 µs | ~720× |
| AMR-WB 14.25 kbit/s (mode 3) | decode | 28.1 µs | ~710× |
| AMR-WB 15.85 kbit/s (mode 4) | decode | 28.0 µs | ~715× |
| AMR-WB 18.25 kbit/s (mode 5) | decode | 28.4 µs | ~705× |
| AMR-WB 19.85 kbit/s (mode 6) | decode | 30.8 µs | ~650× |
| AMR-WB 23.05 kbit/s (mode 7) | decode | 29.0 µs | ~690× |
| AMR-WB 23.85 kbit/s (mode 8) | decode | 37.0 µs | ~540× |

AMR-WB decode is validated **bit-exact against the 3GPP TS 26.174 reference vectors** (`tst_mN.out`,
all 9 speech modes) before these numbers are taken — the AVX2 kernels are also `proptest`-fuzzed
byte-identical to their scalar oracles. <sup>¹ frame budget ÷ measured time, one core.</sup>

<details>
<summary><b>Relay, SRTP, media building blocks &amp; TURN microbenchmarks</b></summary>

**Userspace relay slow path** — per packet (12-byte header + 160-byte G.711 payload):

| Path | Time | 1-core throughput |
|---|--:|--:|
| RTP parse (RFC 3550 §5) | 1.9 ns | ~520 M pkt/s |
| Parse → SSRC/seq rewrite → write | 8.1 ns | ~124 M pkt/s |

The plain-RTP **fast path never reaches userspace** — it is forwarded in-kernel by XDP. The above is
paid only on the slow path (SRTP / transcode / bridge), and it allocates nothing per packet.

**SRTP / SRTCP** — the per-packet surcharge a secure leg pays (RFC 3711):

| Operation | Time |
|---|--:|
| SRTP protect (AES-CM + HMAC-SHA1-80) | 243 ns |
| SRTP unprotect (verify + decrypt) | 262 ns |
| SRTCP protect | 173 ns |
| SRTCP unprotect | 183 ns |
| Secure-leg protect (incl. RFC 5761 RTP/RTCP demux) | 245 ns |
| Secure-leg unprotect (incl. demux) | 257 ns |
| SRTP context setup (3× KDF derive, per leg) | 151 ns |

**AMR-WB decode kernels** — where the per-frame time goes:

| Kernel | Scope | Time | |
|---|---|--:|---|
| ISP → LP interpolation (`int_isp`) | per frame (4 subframes) | 795 ns | scalar |
| ISP → LP, one set (`isp_az`, Chebyshev) | per call (4×/frame) | 191 ns | scalar |
| LPC synthesis (`syn_filt_32`) | per subframe | 792 ns | **AVX2** (was 1.97 µs) |
| Adaptive codebook (`pred_lt4`) | per subframe | 194 ns | **AVX2** (was 1.83 µs) |
| 12.8 → 16 kHz oversampler | per subframe | 405 ns | **AVX2** (was 2.04 µs) |
| Algebraic codebook 4T64, 36-bit (12.65k) | per subframe | 9.7 ns | scalar (branchy) |
| Algebraic codebook 4T64, 88-bit (23.85k) | per subframe | 40.7 ns | scalar (branchy) |

The three FIR/convolution kernels are vectorized via `siphon-rtp-simd` (runtime-detected AVX2,
scalar fallback, `proptest`-fuzzed byte-identical); the branchy algebraic-codebook search stays
scalar (it doesn't vectorize — the same is true of the C reference).

**DSP** — telephony ↔ voice-AI bridge (`siphon-rtp-dsp`):

| Block | Time | |
|---|--:|---|
| Resampler 8→16 kHz, one 20 ms frame | 3.8 µs | **AVX2 f32** (was 5.6 µs) |
| Energy VAD, 320-sample frame | 22 ns | AVX2 sum-of-squares |

**Media building blocks** — per 20 ms frame:

| Block | Time |
|---|--:|
| WAV player frame pull | 6.7 ns |
| DTMF digit burst, RFC 4733 (8 payloads) | 23.6 ns |
| SIPREC fork: re-encode + packetize + channel handoff | 203 ns |

**TURN relay** — WebRTC NAT traversal:

| Operation | Time | Throughput |
|---|--:|--:|
| ChannelData encode | 13.2 ns | 11.3 GiB/s |
| ChannelData parse | 3.4 ns | 43.9 GiB/s |
| REST credential derivation (HMAC-SHA1 + MD5 key) | 907 ns | per auth |
| Allocate-success build (+ MESSAGE-INTEGRITY) | 786 ns | per request |

Reproduce any of these with `cargo bench`.

</details>

## Install

From crates.io — installs the **`siphon-rtp`** daemon binary. Everything (control protocol,
datapath, codecs, media plane) compiles into the one statically-linkable binary — no rtpengine,
no C libraries:

```sh
cargo install siphon-rtp
siphon-rtp --control 0.0.0.0:8080      # JSON-over-TCP control front-end
```

From source:

```sh
cargo build --release -p siphon-rtp
./target/release/siphon-rtp --control 0.0.0.0:8080
```

In a container — musl/distroless image; the dev/prod XDP profiles live in `docker-compose.yml`:

```sh
docker build -t siphon-rtp .
docker run --rm -p 8080:8080 siphon-rtp
```

## Control protocol

Two front-ends onto one internal engine:

1. **Native JSON-over-TCP** (`siphon-rtp-proto`, shared with SIPhon) — length-prefixed JSON,
   request/response correlated by id, async events pushed back. rtpengine offer/answer semantics,
   no bencode.
2. **rtpengine NG/bencode** (optional, enabled with `--ng`) — the actual rtpengine wire protocol, so
   existing Kamailio / OpenSIPS / `mod_rtpengine` deployments point at siphon-rtp with no signaling
   changes. Control-protocol parity plus siphon-rtp extensions (cluster load, drain, HA
   checkpoint/restore); the in-kernel path is our own XDP, **not** rtpengine's kernel module.

## Architecture

```
   SIPhon ──JSON/TCP──┐   ControlFrontend → one internal Command + engine
                      ├─▶ (session store, port mgr, aya loader, event stream)
  Kamailio/OpenSIPS   │
   ──NG/bencode/UDP───┘                 │
                                        ▼
   NIC ─ XDP (aya) ─ classify ─ FAST PATH: plain RTP → header rewrite → XDP_TX (in-kernel)
                        └ XDP_REDIRECT → AF_XDP → SLOW PATH (per-leg actors):
                            SRTP → depacketize → jitter/PLC → decode→PCM →
                            [VAD/NS/AEC] → fan-out {WS bridge / mixer / RTP fork} →
                            resample → encode → packetize → SRTP → TX
```

That XDP fast/slow split is the **target** datapath. Today the daemon runs the userspace slow path on
the UDP backend (the XDP loader and classifier are built and unit-tested, not yet wired into the
runtime); see the [datapath](https://rtp.siphon-sip.org/datapath/) page.

Crates:

- **`siphon-rtp-proto`** — native JSON control contract (shared with SIPhon).
- **`siphon-rtp-codec`** — pure-Rust codecs (G.711, G.722, G.726, GSM-FR, L16, comfort noise, AMR-NB/WB).
- **`siphon-rtp-simd`** — pure-Rust SIMD DSP primitives (runtime-detected AVX2 + scalar fallback),
  shared by the codec and dsp hot paths.
- `siphon-rtp-dsp` — resampler (SIMD), energy VAD, single-channel noise suppression, and echo cancellation.
- `siphon-rtp-media` — RTP/RTCP, jitter/PLC, leg pipeline, fan-out/fork, the MCU mixer, stream bridges.
- `siphon-rtp-srtp` — SRTP/SRTCP (SDES) with RFC 3711 anti-replay and the secure-leg demux.
- `siphon-rtp-dtls` — DTLS-SRTP (RFC 5764) handshake keying, pure RustCrypto.
- `siphon-rtp-stun` / `siphon-rtp-turn` — STUN plus the built-in TURN server (a coturn replacement).
- `siphon-rtp-hep` — HEP3 / Homer export with G.107 MOS.
- `siphon-rtp-ngcompat` — the rtpengine NG/bencode control front-end.
- `siphon-rtp-datapath` — the `Datapath` trait and the UDP backend (the runtime datapath today).
- `siphon-rtp-xdp` / `siphon-rtp-ebpf-common` — the aya XDP loader + classifier (built, not yet wired in).
- **`siphon-rtp`** — the installable daemon binary (dir `crates/siphon-rtp-engine/`): control
  front-ends, session manager, actor runtime + aya loader.

## Building & testing

```sh
cargo test          # NIC-free: default features use the UDP-loopback datapath backend
cargo bench         # criterion perf gates (codec µs/frame)
cargo clippy --all-targets --all-features -- -D warnings
```

Discipline mirrors siphon-sip: TDD (codecs validated against reference vectors before they're
"done"), `thiserror` errors with no `.unwrap()` in production paths, criterion perf gates, and a
paired perf + memory-leak check before every commit.

## Status

Pre-1.0, but the core is built and wired end-to-end. Shipping today: both control front-ends (native
JSON-over-TCP and rtpengine NG/bencode), the userspace relay on the UDP datapath (with symmetric-RTP
latching), the IMS-priority codecs (G.711, G.722, G.726, GSM-FR, comfort noise, and bit-exact
AMR-NB/AMR-WB behind the `amr` feature), SRTP-SDES and DTLS-SRTP, a built-in TURN server, RTCP with
G.107 MOS plus HEP/Homer export, the jitter buffer / PLC / resampler, energy VAD, single-channel
noise suppression and echo cancellation (on the transcode and WebSocket-bridge paths), SIPREC
forking, the N-party conferencing MCU, the RTP↔WebSocket bridge, runtime pcap recording, and
cluster load / drain with warm-standby checkpoint/restore.

On the forward track: wiring the eBPF/XDP in-kernel fast path into the daemon (the loader and
classifier are built and unit-tested but not yet selected at runtime), the full ICE state machine
(the agent is foundations-only today), the Opus codec, and the OpenAI-Realtime / gRPC /
direct-WebRTC voice-AI adapters. See the [docs](https://rtp.siphon-sip.org/) for the full picture.

## License

MIT — see [LICENSE](LICENSE).
