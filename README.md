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
| **G.711 (µ-law / A-law)** | ITU-T G.711 | Implemented — encode/decode, all-256 round-trip tested |
| **L16 / PCM** | RFC 3551 | Implemented — big-endian, round-trip tested |
| **Fixed-point basic operators** | 3GPP/ITU `basicop2` | Implemented — saturation/rounding unit-tested |
| **AMR-NB / AMR-WB** | TS 26.071 / TS 26.171, RFC 4867 | Foundation: modes + framing tested; ACELP DSP in progress |
| **Control protocol (JSON/TCP)** | — | Implemented — types + length-prefixed framing, round-trip tested |
| **rtpengine NG/bencode front-end** | rtpengine NG | Planned (drop-in for Kamailio/OpenSIPS) |
| **Datapath: UDP-loopback backend** | — | In progress (NIC-free, CI/dev) |
| **Datapath: eBPF/XDP + AF_XDP** | — | Planned (`aya`, pure Rust) |
| **RTP/RTCP + SRTP / DTLS / ICE** | RFC 3550 / 3711, webrtc-rs | Planned |
| **Jitter buffer + PLC + resampler** | — | Planned |
| **WebSocket bridge (raw PCM)** | — | Planned (M1 headline) |
| **OpenAI Realtime / gRPC / WebRTC bridges** | — | Planned |
| **VAD / noise suppression / echo cancellation** | — | Planned (all pure-Rust) |
| **Forking (SIPREC) + conferencing (MCU)** | RFC 7866 | Planned |
| **Opus / G.722 / EVS** | RFC 6716 / G.722 | Planned (codec track) |

## Control protocol

Two front-ends onto one internal engine:

1. **Native JSON-over-TCP** (`siphon-rtp-proto`, shared with SIPhon) — length-prefixed JSON,
   request/response correlated by id, async events pushed back. rtpengine offer/answer semantics,
   no bencode.
2. **rtpengine NG/bencode** (optional, planned) — the actual rtpengine wire protocol, so existing
   Kamailio / OpenSIPS / `mod_rtpengine` deployments point at siphon-rtp with no signaling changes.
   Control-protocol parity only; the in-kernel path is our own XDP, **not** rtpengine's kernel module.

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

Crates:

- **`siphon-rtp-proto`** — JSON control contract (shared with SIPhon).
- **`siphon-rtp-codec`** — pure-Rust codecs (G.711, L16, AMR-NB/WB, …).
- `siphon-rtp-dsp` — VAD / NS / AEC / resampler (planned).
- `siphon-rtp-media` — RTP/SRTP, jitter/PLC, leg pipeline, fan-out, mixer, bridges (planned).
- `siphon-rtp-datapath` — `Datapath` trait + UDP-loopback (CI) + XDP/AF_XDP backends (planned).
- `siphon-rtp-ebpf*` — the aya XDP classifier (planned).
- `siphon-rtpd` — the daemon: control front-ends, actor runtime, aya loader (planned).

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

Early development. The control protocol and the IMS-priority codecs (G.711 + the AMR foundation)
land first; the XDP datapath, SRTP, and the WebSocket/AI bridges layer on top. See the milestone
plan for the platform-track / codec-track structure.

## License

MIT — see [LICENSE](LICENSE).
