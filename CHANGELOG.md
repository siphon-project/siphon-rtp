# Changelog

All notable changes to siphon-rtp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/). Versioning is one number across the whole
workspace, driven by the git tag (see [VERSIONING.md](VERSIONING.md)).

## [Unreleased]

The initial public surface. The workspace version is `0.1.5` (a single number across
every crate, see [VERSIONING.md](VERSIONING.md)); this is what the first public tag ships.

### Control plane
- **Native JSON-over-TCP control protocol** (`siphon-rtp-proto`) — length-prefixed
  JSON, request/response correlated by id, async events pushed back, optional
  shared-secret authentication. Verbs: offer, answer, delete, query, ping, list,
  statistics, load, node_info, drain/undrain, checkpoint, restore, play_media,
  stop_media, play_dtmf, silence/unsilence_media, block/unblock_media,
  block/unblock_dtmf, echo, start/stop_recording, subscribe_request/answer,
  unsubscribe, conference_join/leave/route/bridge, attach/detach_ws_tee.
  `play_media` accepts immediately with a `play_id` and reports its end
  asynchronously (below). Events: dtmf, media_timeout, play_finished,
  active_speaker, call_quality, call_summary, ws_tee_started, ws_tee_ended.
- **rtpengine NG/bencode front-end** (`--ng`, `siphon-rtp-ngcompat`) — drop-in for
  existing Kamailio / OpenSIPS + `mod_rtpengine` deployments, plus siphon-rtp
  extensions (cluster load/node-info/drain, HA checkpoint/restore).

### Media plane
- **UDP datapath** with symmetric-RTP latching (the runtime datapath today); the
  eBPF/XDP loader and classifier are built and unit-tested, not yet wired in.
- **Codecs**, pure Rust, bit-exact against the reference vectors: G.711 µ/A-law, L16,
  G.722, G.726 (16/24/32/40 kbit/s), GSM Full Rate, comfort noise (RFC 3389), and,
  behind the `amr` feature, AMR-WB (decode and encode all 9 modes) and AMR-NB
  (decode and encode all 8 modes; DTX/SID out of scope).
- **SRTP-SDES** (RFC 3711 / 4568) with anti-replay, and **DTLS-SRTP** (RFC 5764),
  both pure RustCrypto.
- **ICE-lite + STUN**, with opt-in **consent freshness** (RFC 7675, `--ice-consent`:
  probes the validated candidate pair and tears the call down when the peer stops
  answering), and a **built-in TURN server** (RFC 5766 / 8656, coturn REST
  credentials, `turn:` / `turns:` over UDP/TCP/TLS).
- **RTCP** SR/RR (parse and construct), **jitter buffer + PLC**, **resampler** (AVX2),
  an energy **VAD**, single-channel **noise suppression**, and **echo cancellation**
  (wired on the transcode and WebSocket-bridge paths, not on SRTP/DTLS legs).
- **Conferencing MCU** — N-party mixer with mix-minus-self, active-speaker selection,
  whisper/monitor roles, and room bridging.
- **SIPREC forking** (raw-RTP tee) and **runtime pcap recording**.
- **RTP↔WebSocket bridge** (`ws://` / `wss://`, raw L16 PCM) for voice-AI, in two
  modes. **Takeover** (`ws_uri`) makes the WS server leg A's far side (duplex; the
  A↔B path is not wired), with engine-side turn-taking: a local uplink VAD
  (`ws_vad`) emitting `speech_started` / `speech_stopped` control frames, same-tick
  barge-in (`ws_barge_in`), and echo cancellation of the phone's echo of the AI
  (`echo_cancellation`). **Tee** (`ws_tee` / `attach_ws_tee`) streams a call's audio
  send-only *while it keeps relaying* — one leg's monologue, both legs mixed to mono,
  or both interleaved as stereo L16 — for live transcription, monitoring and
  analytics. The tee taps the same post-decode fan-out SIPREC forks from, so a stream
  is decoded once; a stalled consumer drops tee frames and never the call.
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
