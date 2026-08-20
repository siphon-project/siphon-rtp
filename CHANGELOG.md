# Changelog

All notable changes to siphon-rtp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/). Versioning is one number across the whole
workspace, driven by the git tag (see [VERSIONING.md](VERSIONING.md)).

## [Unreleased]

## [0.2.1] — 2026-08-20

### Changed
- Strip the distributed binaries (docker image, `.deb`/`.rpm`, tarballs). The release profile still
  keeps debug symbols for the iai-callgrind perf gate — stripping happens only on the release
  artifacts, shrinking the container image from ~219 MB to ~13 MB (and the packages likewise). No
  code change.

## [0.2.0] — 2026-08-19

The workspace version is `0.2.0` (a single number across every crate, see
[VERSIONING.md](VERSIONING.md)). siphon-rtp is **experimental** — a very large feature surface that
keeps moving and breaking; nothing is production-ready until it has real-traffic soak testing behind
it, and that designation stays through 1.0.0.

### Control plane
- **Native JSON-over-TCP control protocol** (`siphon-rtp-proto`) — length-prefixed
  JSON, request/response correlated by id, async events pushed back, optional
  shared-secret authentication. Verbs: offer, reoffer, ice_candidate, answer,
  answer_local, delete, query, ping, list, statistics, load, node_info,
  drain/undrain, checkpoint, restore, play_media, stop_media, play_dtmf,
  silence/unsilence_media, block/unblock_media, block/unblock_dtmf, echo,
  start/stop_recording, subscribe_request/answer, unsubscribe,
  conference_join/leave/route/bridge, attach/detach_ws_tee. `play_media` accepts
  immediately with a `play_id` and reports its end asynchronously (below). Events:
  dtmf, text, media_timeout, play_finished, active_speaker, call_quality,
  call_summary, ws_tee_started, ws_tee_ended — an unrecognised event tag decodes to
  `Unknown`, so a controller pinned to an older proto never hard-fails against a
  newer engine.
- **rtpengine NG/bencode front-end** (`--ng`, `siphon-rtp-ngcompat`) — drop-in for
  existing Kamailio / OpenSIPS + `mod_rtpengine` deployments, plus siphon-rtp
  extensions (cluster load/node-info/drain, HA checkpoint/restore).

### Media plane
- **UDP datapath** with symmetric-RTP latching — the datapath the default
  `siphon-rtp` binary runs. (The in-kernel XDP datapath ships separately; see the
  XDP entry below.)
- **Codecs**, pure Rust, bit-exact against the reference vectors: G.711 µ/A-law, L16,
  G.722, G.726 (16/24/32/40 kbit/s), GSM Full Rate, comfort noise (RFC 3389), and,
  behind the `amr` feature, AMR-WB (decode and encode all 9 modes) and AMR-NB
  (decode and encode all 8 modes; DTX/SID out of scope).
- **SRTP-SDES** (RFC 3711 / 4568) with anti-replay, and **DTLS-SRTP** (RFC 5764),
  both pure RustCrypto.
- **ICE-lite + STUN** as the default responder posture, with opt-in **consent
  freshness** (RFC 7675, `--ice-consent`: probes the validated candidate pair and
  tears the call down when the peer stops answering), and a **built-in TURN server**
  (RFC 5766 / 8656, coturn REST credentials, `turn:` / `turns:` over UDP/TCP/TLS).
- **Full RFC 8445 ICE agent** behind `--ice-full` (checklists, connectivity checks,
  both roles with 487 role-conflict, peer-reflexive discovery, regular nomination;
  media gated on the selected pair). ICE-lite responder remains the default posture.
  (`siphon-rtp-ice`)
- **Candidate gathering** per leg/component with `--stun-server` (host +
  server-reflexive, RFC 8445 §5.1.1; the built-in TURN server answers Binding,
  RFC 8656 §12).
- **ICE restart** (RFC 8445 §9) via a new `reoffer` control verb — renegotiates on
  the existing media ports (advertised in `node_info` features as `reoffer`).
- **Trickle-ICE receive** (RFC 8838) — new `ice_candidate` control verb;
  `a=ice-options:trickle` / `a=end-of-candidates`. Requires `--ice-full`.
- **RFC 8839 §5.3 ICE-mismatch** detection/signalling.
- **TURN client** (`siphon-rtp-stun/src/turn_client.rs`) for relayed ICE candidates
  (RFC 5766 Allocate/Refresh/CreatePermission/ChannelBind + ChannelData datapath).
  Wired at the engine API level (`Engine::with_turn_server`); not yet exposed as a
  daemon CLI flag.
- **Opus** (RFC 6716 / RFC 7587) — pure-Rust SILK/CELT/Hybrid, decode AND encode
  wired into the codec factory, all five RFC 7587 fmtp parameters honoured,
  advertised in `node_info`. No Cargo feature.
- **DTLS-SRTP media pipeline leg** (`PipelineKind::DtlsMedia`) — a WebRTC/DTLS leg
  can be transcoded, recorded or ws-teed, not only relayed; DTLS-SRTP conference
  participant seating.
- **XDP kernel datapath** shipped as the separate `siphon-rtp-xdp-daemon` binary —
  in-kernel `XDP_TX` fast path, next-hop MAC resolution (rtnetlink/ARP), layer-1..4
  gate enforced in-kernel; plugs into the engine via `run_with_datapath`. Default
  `siphon-rtp` binary stays UDP-only.
- **Real-time text** (RFC 4103 / RFC 9071) — RFC 2198 RED + RFC 4103 T.140
  reassembly; plaintext `m=text` relay and secure SDES-SRTP text; RFC 9071
  multiparty RTT in the conference; text QoS on the HEP wire; text re-anchored on
  the ICE-restart reoffer path.
- **Repeated `offer` on a live call-id hardened** — owner-only, clean replace.
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
  secure transcode; WebSocket and DTLS-SRTP restore are not yet covered).

### Supply chain
- Per-release **SBOM** (SPDX 2.3 + CycloneDX 1.4), a scheduled **cargo-deny** advisory
  audit, and a CI ban list enforcing the **zero C library dependency** rule.

### Dependencies
- rcgen 0.13 → 0.14; base64 0.23 (`siphon-rtp-srtp`); the cargo-minor-patch group
  (tokio, rustls, rustls-pki-types, webpki-roots, futures-util, serde_json,
  thiserror, clap, toml, async-trait); spin unyanked to 0.9.9. Dependabot now
  ignores the aes/ctr 0.9 wave and standalone webrtc-util bumps.
