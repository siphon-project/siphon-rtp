# Changelog

All notable changes to siphon-rtp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/). Versioning is one number across the whole
workspace, driven by the git tag (see [VERSIONING.md](VERSIONING.md)).

## [Unreleased]

### Added
- **Selectable WebSocket wire sample rate.** The L16 rate a WS consumer exchanges is now negotiable
  and independent of the leg's codec rate, on both WS shapes:
  - `sample_rate` on `attach_ws_tee` and `ws_tee_sample_rate` in `ProfileFlags` — every tapped leg is
    resampled into the requested rate before framing, so an 8 kHz G.711 call can be teed at 16 kHz
    and a stereo tee over two different codecs produces one coherent stream. The `start` envelope's
    `media.sampleRate` and the `ws_tee_started` event both report the **negotiated** rate.
  - `ws_sample_rate` in `ProfileFlags` for the `ws_uri` takeover bridge, applied in **both**
    directions (leg → wire on the uplink, wire → leg on the downlink before re-encoding).
  - All three are strictly additive and optional; unset means exactly the previous behaviour (follow
    the leg codec's PCM rate, with no conversion built at all). An unserviceable rate — zero, outside
    8000–48000, or not a multiple of 1000 — is rejected with a typed error at attach/offer/answer
    time, before anything is dialled, promoted or attached, and is never silently clamped.

### Fixed
- **WebSocket takeover downlink was rendered at the wrong rate.** A server sending playout PCM at
  anything other than the leg's codec rate had it encoded sample-for-sample into the leg's codec, so
  the call heard the right samples at the wrong speed and pitch with no error reported anywhere. The
  downlink is now resampled into the leg's rate before the encode.

### Changed
- The WS bridge's uplink noise suppressor and echo canceller now run in the **wire** rate domain —
  the domain the far side hears, and the only one that keeps the canceller's near-end input and
  far-end reference in a single rate and frame length. A wire rate the noise suppressor does not
  support (anything but 8/16 kHz) leaves it off with a `warn`, and never changes the negotiated rate.

### Fixed
- **Security (RTPBleed class): a redirected ICE endpoint had no source gate at all.** The datapath's
  layer-4 ICE gate — media is accepted only from the transport a STUN connectivity check validated
  (RFC 8445 §7) — ran on the in-kernel/relay `Forward` path only. Every userspace consumer receives
  its media as `Redirect` (conference seats, promoted transcode/record/echo/DTMF calls, WebSocket
  takeover legs, the SDES-SRTP and DTLS-SRTP bridges), and each of those re-enforces the layer-2
  *signalled-source* gate itself — which an ICE leg deliberately leaves open (`SourceFilter::Any`),
  because a peer-reflexive check legitimately arrives from a transport the SDP never carried
  (RFC 8445 §7.3.1.3). The two together left an ICE leg on the redirected path with nothing gating
  its source. The sharpest case was an **ice-lite conference seat** — the default posture, no
  `--ice full` — where the room's `ice_pending` gate is never set (it exists for the window before a
  *full* agent selects a pair) so anyone able to reach the seat's UDP port could inject audio into
  the mix every other participant heard. Both datapaths now apply the identical verdict on the
  `Redirect` path (`Inner::ice_gate` in the UDP backend, the `action::REDIRECT` arm of the eBPF
  classifier): an endpoint carrying ICE credentials hands its consumer only the check-validated
  source. Only the *source* is gated — a redirected endpoint is still entitled to non-RTP, so a
  DTLS-SRTP handshake (RFC 5764) and a TURN allocation's own STUN (RFC 5766 §11) are unaffected —
  and STUN itself is exempt so the handshake cannot deadlock. Non-ICE redirected endpoints are
  unchanged. `docs/security-and-nat.md` §4 layers 1/3/4 and 5c/5d updated.

- **Neural voice-activity detection** (`siphon-rtp-dsp`) — the Silero VAD v5 network as a
  hand-written pure-Rust forward pass with its 309 633 parameters embedded in the binary (~1.2 MB,
  MIT, provenance and hashes in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)). No inference
  runtime, no shared library, no extra deployment artifact: siphon-rtp stays one static binary. The
  existing `EnergyVad` is unchanged and stays the default.

  The energy detector answers "is something loud here", so as a *turn* detector it fires on mains
  hum, breathing and fan noise. On synthetic hum and breathing at four times the default energy
  threshold — where the energy gate fires throughout — the network peaks at probability 0.07 and
  0.35. Validated against the published ONNX graph run by `onnxruntime` out of tree: worst
  per-window probability error 1.3e-6 and **100 % decision agreement over 937 windows** (30 s) of
  speech, plus committed hum / breathing / echo / speech-onset cases
  (`crates/siphon-rtp-dsp/tests/vectors/`, regenerated by `reference/silero-vad/`).

  Framing is the model's own 512 samples at 16 kHz (32 ms) run on its own cadence fed from the media
  frame clock, which puts the turn-detection floor at 32 ms plus up to one media frame; a leg at any
  other rate is resampled into the detector. Cost: ~37 µs per 32 ms window; on the WS bridge tick,
  ~27 µs per 20 ms frame on an 8 kHz leg (resample included) against ~83 ns for the energy gate,
  about 0.14 % of one core per call. Zero heap allocation per window and per bridge tick.
- **`ws_vad_engine`** profile flag — `energy` (default, unchanged behaviour) or `neural`, selecting
  the WS voice-AI bridge's uplink detector. A selection the engine cannot build for the leg fails
  the offer with a reason rather than downgrading to the detector the controller was avoiding.
- **`ws_vad_min_speech_ms`** profile flag — a **leading** minimum-speech run: the uplink must read
  as speech continuously for that long before `speech_started` (and barge-in) fires. Previously the
  edge fired on the first speech frame, so a cough, a door or one burst of echo interrupted the
  prompt. Unset ⇒ unchanged behaviour. Works with either detector.

Both flags are `Option`/omitted-when-unset, so existing controller JSON serialises byte-identically.

### Documentation
- [Voice AI cookbook](docs/cookbook/voice-ai.md) gains a detector-choice section: the comparison
  table, the 32 ms framing and its latency floor, the measured cost, the leading-run gate, and the
  measured echo-return-loss curve showing why `echo_cancellation` is not optional under barge-in
  (the network still calls far-end speech "speech" down to about −36 dB of ERL — echo of speech is
  speech, and no VAD can substitute for the canceller).

- **Answering-machine (voicemail beep) detection** — opt-in per call via the new `beep_detection`
  profile flag, reporting the new `beep_detected` event (`call_id`, `from_tag`, `to_tag?`,
  `frequency_hz`, `duration_ms`, `offset_ms`) so a controller can abort an attended transfer instead
  of bridging a caller into a voicemail box. A new pure-Rust `RecordToneDetector`
  (`siphon-rtp-dsp`'s `tone_detect`) runs on the leg's decoded ingress over the same √Hann WOLA STFT
  the noise suppressor uses, and requires a tone to pass *every* discriminator: narrow-band energy
  concentration, no second tone (which is what excludes DTMF, ITU-T Q.24), frequency stability,
  amplitude stability, a 120–1000 ms duration, and — the discriminator that separates a record tone
  from ringback / busy / congestion / the special-information tone — no repeat inside a configurable
  cadence guard (`beep_cadence_guard_ms`, default 4500 ms, which is also the reporting latency).
  Setting the flag promotes a same-codec call from the in-kernel relay to the userspace media
  pipeline exactly as `noise_suppression` does; supported at 8 and 16 kHz, inert elsewhere. Fires
  once per leg per call. Validated against a synthesised corpus (196 must-fire / 240 must-not-fire
  cases across both rates, 0 false negatives and 0 false positives), benched at ≈ 2.1 µs/frame at
  8 kHz and ≈ 4.0 µs at 16 kHz (about a third of the noise suppressor's cost measured on the same
  run) with zero per-frame heap allocation. See
  [docs/control/json.md](docs/control/json.md#answering-machine-beep-detection) for the parameters,
  the operating point and what it cannot do.

- **Overlay playback** — `play_media` with `"overlay": true` mixes audio *under* a leg's live egress
  instead of replacing it: ringback beneath a leg that has not answered, hold music beneath silence,
  a background bed beneath a conversation. Up to **four concurrent overlays per direction**, each
  addressed by its own `play_id` for `stop_media` and `set_play_gain` and each ending with its own
  `play_finished`; a fifth is rejected with an error naming the cap rather than displacing one. An
  overlay rides the live stream when there is one (one overlay frame per emitted egress frame, so it
  adds no packets) and carries the egress itself when there is not — which is what makes ringback
  toward a leg receiving no media work. Mixing accumulates in `i32` and saturates, like the
  conference mix bus. Zero per-tick heap allocation, proven by a counting-allocator test.
- **Playout gain** — `gain_decibels` on `play_media` (overlay *and* superseding), in whole decibels
  over −60 … +12 dB, plus a new `set_play_gain` verb to retune a playback that is already running.
  Better than 0.1 dB accurate across the range; saturating, so a boost clips rather than wraps.
- **Tone generation** — a new `{"source": "tone", "tone": "…"}` playback source. Fourteen cited
  call-progress presets (`ringback_eu`, `busy_na`, `dial_uk`, …) from ETSI ETR 187, Telcordia
  GR-506-CORE and the ITU-T E.180 Supplement 2 national tables, at the −10 dBm0 nominal of ITU-T
  E.180/Q.35 §2 — plus a documented cadence grammar (`425/1000,0/4000*inf`) for anything the table
  does not cover, parsed with typed errors and fuzzed (`tone_spec_fuzz`). Tones render directly at
  the leg's codec rate off a 32-bit phase accumulator, so they are never resampled and allocate
  nothing per frame.
- **Playback from a URL** — a new `{"source": "http", "url": "…"}` source fetched by the engine over
  `http`/`https`. Bounded on every axis (connect, first-byte and overall timeouts, a body-size cap
  enforced against `Content-Length` *and* while reading, a redirect cap), all configurable via
  `--media-fetch-*` / the TOML equivalents. The fetch runs on its own task, so it never touches the
  media path or stalls the control connection: the accept returns a `play_id` immediately and any
  failure resolves the playback with `play_finished` reason `error`. Only `http`/`https` are
  accepted and every redirect hop is re-validated, with an optional `--media-fetch-allow-host`
  allow-list; the SSRF posture is documented in `docs/control/json.md`.
- **`stop_media` can target one playback** — an optional `play_id` stops just that one and leaves the
  rest running. Without it the verb still stops everything on the call, exactly as before.

### Fixed
- `play_media`'s `duration_ms` was parsed and then dropped. It is now the hard playout cap the
  contract always described — and the only bound, short of a stop, on an endless tone.
- A resampled prompt now emits exactly one egress frame per playout tick. Previously it emitted
  whatever the polyphase resampler happened to produce while advancing the RTP timestamp by a fixed
  increment, so a prompt whose source rate differed from the leg's drifted against its own clock.

- **WebSocket takeover on a secure offerer.** A takeover call (`ws_uri`) makes the WS media server
  leg A's far side, which makes the engine A's cryptographic peer when A negotiated SRTP.
  `answer_local` now terminates that: it mints the engine's **own** SDES key (RFC 4568) or advertises
  its own certificate fingerprint plus the complement `a=setup` role (RFC 5763 §5), then decrypts A's
  ingress before the decoder and encrypts the bridge's downlink before it leaves (RFC 3711). DTLS-SRTP
  (RFC 5764) reuses the existing bridge through a new `PipelineTarget::Ws`, so the RFC 7983 demux and
  the handshake stay where they are and the takeover leg is the single owner of the key.
- **Full ICE on a takeover leg.** A takeover leg's egress belongs to the bridge's drain task rather
  than a datapath forward rule, so an RFC 8445 selection is now routed to `WsRegistry::ice_selected`
  as well as to the datapath: it re-points the downlink at the selected pair (§8.1.1) and narrows the
  source gate to it. Nothing crosses the leg before the agent selects (§12).

### Fixed
- **`ws_uri` on a leg the engine cannot bridge is refused instead of accepted.** A secure or ICE
  offerer carrying `ws_uri` used to return `ok` and produce a call that answered and bridged nothing —
  A's SRTP reached the decoder as ciphertext and the downlink left in the clear. Each unsupported
  shape is now refused at **offer** time with a stable leading reason token, before the controller
  commits to the dialog: `ws-takeover-secure-offerer` / `ws-takeover-ice-offerer` on `offer` and
  `answer`, and `secure-offerer-unsupported` / `ws-takeover-unkeyable` /
  `ws-takeover-ice-unsupported` on `answer_local`. See the matrix in
  [docs/cookbook/voice-ai.md](docs/cookbook/voice-ai.md) and Layer 5e of
  [docs/security-and-nat.md](docs/security-and-nat.md).
- **`answer_local` no longer echoes a secure offerer's own keying back at it.** A secure offer to the
  single-leg IVR / echo / announcement pipeline was answered with the caller's own `a=crypto` /
  `a=fingerprint` copied into the answer, which no media path could back. It is refused.
- **`play_media` on a call with no media actor is refused instead of accepted.** On a crypto bridge
  (`Srtp` / `Dtls`) or a WebSocket takeover there is no pipeline to inject into and none is promoted,
  so the injection landed nowhere while the controller got back an accepted `play_id` and waited for a
  `play_finished` that never came. It now errors, as `play_dtmf` and `silence_media` already did and
  as the control reference already documented.

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
