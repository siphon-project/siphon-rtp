# Changelog

All notable changes to siphon-rtp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/). Versioning is one number across the whole
workspace, driven by the git tag (see [VERSIONING.md](VERSIONING.md)).

## [Unreleased]

The initial public surface. This becomes `0.1.0` at the first tag.

### Control plane
- **Native JSON-over-TCP control protocol** (`siphon-rtp-proto`) — length-prefixed
  JSON, request/response correlated by id, async events pushed back, optional
  shared-secret authentication. Verbs: offer, answer, delete, query, ping, list,
  statistics, load, node_info, drain/undrain, checkpoint, restore, play_media,
  stop_media, play_dtmf, silence/unsilence_media, block/unblock_media,
  block/unblock_dtmf, echo, start/stop_recording, subscribe_request/answer,
  unsubscribe, conference_join/leave/route/bridge. Events: dtmf, media_timeout,
  active_speaker, call_quality.
- **rtpengine NG/bencode front-end** (`--ng`, `siphon-rtp-ngcompat`) — drop-in for
  existing Kamailio / OpenSIPS + `mod_rtpengine` deployments, plus siphon-rtp
  extensions (cluster load/node-info/drain, HA checkpoint/restore).

### Media plane
- **UDP datapath** with symmetric-RTP latching (the runtime datapath today); the
  eBPF/XDP loader and classifier are built and unit-tested, not yet wired in.
- **Codecs**, pure Rust, bit-exact against the reference vectors: G.711 µ/A-law, L16,
  G.722, G.726 (16/24/32/40 kbit/s), GSM Full Rate, comfort noise (RFC 3389), and,
  behind the `amr` feature, AMR-WB (decode and encode all 9 modes) and AMR-NB
  (decode all 8 modes, encode MR475 + MR122).
- **SRTP-SDES** (RFC 3711 / 4568) with anti-replay, and **DTLS-SRTP** (RFC 5764),
  both pure RustCrypto.
- **ICE-lite + STUN**, and a **built-in TURN server** (RFC 5766 / 8656, coturn REST
  credentials, `turn:` / `turns:` over UDP/TCP/TLS).
- **RTCP** SR/RR (parse and construct), **jitter buffer + PLC**, **resampler** (AVX2),
  and an energy **VAD**.
- **Conferencing MCU** — N-party mixer with mix-minus-self, active-speaker selection,
  whisper/monitor roles, and room bridging.
- **SIPREC forking** (raw-RTP tee) and **runtime pcap recording**.
- **RTP↔WebSocket bridge** (`ws://` / `wss://`, raw L16 PCM) for voice-AI.
- **Advertised media address + named interfaces** — advertise a public IP in SDP
  decoupled from the bound socket (`--advertise-ip`, for a single-homed host behind
  1:1 NAT such as an Elastic IP: bind private, advertise public, same port), and
  rtpengine-style named interfaces (`[[interface]]` + `default_interface`) selected
  per leg by the control `direction` pair (caller-facing vs callee-facing network).
  Emit-only: the advertised IP never affects the socket bind, the source gate, the
  symmetric-RTP latch, or TURN.

### Operations
- **Prometheus `/metrics` + `/healthz` + `/readyz`**, **HEP/Homer export** with G.107
  MOS, cluster **load / node_info / drain** for rolling upgrades, and warm-standby
  **checkpoint / restore** (plain relay, SDES-SRTP bridge, plaintext transcode, and
  secure transcode; only WebSocket restore is not yet covered).

### Supply chain
- Per-release **SBOM** (SPDX 2.3 + CycloneDX 1.4), a scheduled **cargo-deny** advisory
  audit, and a CI ban list enforcing the **zero C library dependency** rule.
