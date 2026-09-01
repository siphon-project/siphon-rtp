# Changelog

All notable changes to siphon-rtp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/). Versioning is one number across the whole
workspace, driven by the git tag (see [VERSIONING.md](VERSIONING.md)).

## [Unreleased]

**Lands as 0.4.0, not a 0.3.x patch.** The workspace version is bumped here rather than at the
release cut, because a controller floating on `^0.3` would otherwise pick this up from an ordinary
dependency bump. The JSON wire stays backward compatible as always — new verbs a peer never sends,
and new event tags an older consumer decodes as `Event::Unknown` — and `Command` / `Event` have been
`#[non_exhaustive]` since 0.3.0, so a downstream `match` keeps compiling. What a minor bump buys is
that picking the change up is a *decision*: the engine's runtime behaviour changes (a takeover bridge
now has a lifecycle, and `block_media` is refused on a call that has one), and that should not arrive
in a consumer's build unannounced.

### Added

- **The WebSocket takeover bridge has a lifecycle.** `ProfileFlags::ws_uri` could only ever create a
  bridge at negotiation and destroy it with the call, so a controller could not attach one to a call
  already up, move one to a different server, or take one off without tearing the call down. Two
  verbs close that:

  - **`attach_ws_bridge`** (`call_id`, `from_tag`, `ws_uri`), following `attach_ws_tee`'s
    replace-on-existing shape, so one verb covers both halves:
    - On a call that **already has** a bridge it **re-points** it — the headline case, moving a live
      call's audio to a different consumer. The leg does not renegotiate: its codec, wire rate,
      uplink VAD / noise suppression / echo cancellation, source gate, SRTP keying and ICE-selected
      egress are all carried across rather than rebuilt, so there is no re-INVITE and nothing
      silently reverts to a default. The outgoing connection is closed and awaited before the
      replacement is registered, so two drain tasks never write to the leg at once.
    - On a call that has **none** it **takes a live two-party relay over**: A's media goes to the WS
      server and the A↔B path is unwired, so leg B hears nothing until the bridge is detached.
  - **`detach_ws_bridge`** (`call_id`, `from_tag`) reinstalls the exact forward rules the takeover
    displaced — gate and latch policy included — and the two parties hear each other again.
    Idempotent on a call with no bridge.

  Both are native JSON verbs; the NG/bencode front-end does not carry them.

- **`ws_bridge_started` / `ws_bridge_ended` events.** A takeover bridge dying used to be **silent**:
  the tee had `ws_tee_ended`, the bridge had nothing at all — and a takeover bridge is leg A's *only*
  far side, so its death is one-way audio on a live call with no signal anywhere. `ws_bridge_ended`
  is emitted exactly once per started bridge with a `WsBridgeEndReason` mirroring the tee's:
  `detached` (a detach, or the close half of a re-point — the only orderly end), `server_closed`,
  `server_stopped`, `call_ended`, `transport_error`. Anything but `detached` is also logged at WARN,
  so a node with no event consumer still leaves a trace. `ws_bridge_started` reports the negotiated
  wire rate and the `stream_id` matching the WS `start` frame, for bridges stood up at negotiation as
  well as at runtime.

- **`siphon_rtp_ws_bridges` gauge** — live takeover bridges, alongside the existing tee gauges (which
  the metrics reference had never listed; it does now).

### Fixed

- **A stream's `*_started` event is now guaranteed to precede its own `*_ended`.** Both the takeover
  bridge and the WebSocket tee spawned their transport task *before* enqueuing the start event, so a
  media server that closes on the handshake could have its end event enqueued first — leaving a
  consumer with an `ws_bridge_ended` / `ws_tee_ended` for a `stream_id` it was never told had
  started. Anything keying per-stream state on the start (the obvious way to consume these) would
  fault or leak on the unknown stream. Both now enqueue the start before the task that can report an
  end exists; the event channel is FIFO and the spawn happens strictly afterwards, so the ordering is
  structural rather than a matter of timing. The contract documents the guarantee on both end events.

  Each half has its own guard, asserting the *sequence* (start first, then an end naming the same
  `stream_id`) rather than that an end arrives eventually — a guard that drains until it finds the
  event it wants cannot see this defect at all, which is how the tee carried it undetected from the
  day it shipped. Both were mutation-checked by reverting only their own reorder and re-running the
  full engine suite: the bridge's guard caught it in 2 of 15 runs, the tee's in 3 of 15. The tee
  needs 512 attach/detach rounds to get there because its window is a single map insert, against a
  watch, a second task spawn and two inserts on the bridge.

  The tee half is a pre-existing defect, not new in this release — the bridge inherited the shape
  from it.

### Changed

- **`block_media` / `unblock_media` are refused on a WebSocket-takeover call.** They already made no
  sense there — a takeover call's wire bytes are not the two-party media, which is why recording,
  SIPREC, the tee and `block_dtmf` all refuse it — and once a bridge can be *attached* to a live
  relay it became unsafe: such a call still holds the displaced relay's forward rules so its detach
  can reinstall them, and `unblock` walks exactly that list, which would have pulled leg A back off
  the bridge with nothing reporting it.

- **An ICE selection on a takeover leg is recorded with `send_replace` rather than `send`.** A
  `watch::Sender::send` fails and leaves the value untouched once every receiver is gone, which is
  what happens the moment a bridge's drain task exits. The watch now outlives that task (a re-point
  reuses it), so a selection landing on a leg whose bridge has died must still be recorded, or the
  replacement bridge would start out aimed at the pre-ICE address.

### Not included, and why

**Detaching a bridge that was negotiated with `ws_uri` is refused** (`ws-bridge-negotiated`), not
performed. That bridge *is* the call's media path: nothing was displaced, a two-leg negotiated
takeover never wired A↔B (leg B's ports exist, but its codec was never negotiated against A's), and a
single-leg `answer_local` takeover has no second party at all. Detaching it would have to *invent* a
media path from state the engine does not hold — and answering `ok` on a call that now has no audio
path is worse than the gap this work package set out to close. The controller keeps both working
options, named in the refusal: re-point the bridge, or `delete` the call. Handing a negotiated
takeover to a real leg B remains the distinct, unimplemented transition it was.

## [0.3.1] — 2026-08-31

A small release, cut so controllers can pick up the control-contract additions:
`siphon-rtp-proto` **0.3.1** carries the lawful-interception verbs and types that
[SIPhon](https://github.com/siphon-project/siphon) compiles against for the X1/X2 side.

### Added

- **Lawful interception — ETSI TS 103 221-2 X3 content delivery.** Intercepted media is framed and
  shipped to a Mediation Function **straight from the media plane**, over its own
  mutually-authenticated TLS connection, instead of being forked through the signalling process.
  Attach it to a live call with `attach_x3` (`delivery`, `xid`, `correlation_id`, `target_leg`) and
  stop it with `detach_x3`; both are additive, so the call keeps relaying, recording and teeing.
  Scope here is X3 content only — X1 provisioning and X2 IRI live in the signalling plane.

  - New crate **`siphon-rtp-li`**: the clause 5 wire format on its own, pure Rust and std only.
    Written against **V1.4.1 (2021-04)** with every constant carrying its clause citation, and
    validated three ways — byte-exact fixtures, a known-answer test against a PDU captured from an
    unrelated implementation, and an independent third-party Wireshark dissector driven through
    `tshark`. Framing costs ~49 ns/packet and allocates nothing per intercepted frame.
  - **Control contract** (`siphon-rtp-proto`): `Command::AttachX3` / `Command::DetachX3`, the `Xid`
    task-identifier type (UUID on the wire, carried opaquely), `X3TargetLeg`, and
    `Event::X3Started` / `Event::X3Loss` / `Event::X3Ended` with `X3EndReason`. Additive —
    `Command` and `Event` are already `#[non_exhaustive]`, so no consumer breaks.
  - **Configuration** (`x3_client_cert`, `x3_client_key`, `x3_ca`, `x3_network_function_id`,
    `x3_interception_point_id`, `x3_buffer_packets`, `x3_keepalive_secs`). All three PEM paths are
    required; a half-provisioned node counts as unprovisioned. **Without them `attach_x3` is
    refused**, never accepted and left inert — an interception that reports success and delivers
    nowhere reads as a served warrant.
  - Delivered content is what the engine **accepted**: after SRTP decryption and after the
    authentication and replay checks, so a secure leg yields plaintext RTP and a forged, replayed or
    not-yet-keyed packet yields nothing. Coverage includes the SDES and DTLS **crypto bridges**,
    which relay without decoding — without that, an ordinary same-codec WebRTC call would have been
    silently uninterceptable.
  - Loss is treated as reportable, not best-effort: the buffer survives a Mediation Function outage
    rather than discarding through it, a full buffer drops the *arriving* packet so what was
    delivered stays a contiguous prefix, and every drop is counted and raised as `Event::X3Loss`.

  See [docs/lawful-interception.md](docs/lawful-interception.md).

### Fixed

- **The WS uplink VAD's trailing hangover was counted in milliseconds, not ptime frames** — a 0.3.0
  regression from the detector-selection refactor, which moved the ms → frames conversion into
  `WsVadConfig` and then called it with a hard-coded 1 ms ptime. `ws_vad_hangover_ms: 300` built an
  energy gate holding speech for 300 *frames* (six seconds at a 20 ms ptime), and the 200 ms default
  held it for four, so `speech_stopped` — the turn endpoint a voice-AI server commits ASR on — never
  arrived inside a normal turn and the next `speech_started` could not fire either. `speech_started`
  and barge-in were unaffected, which is what made it look like turn-taking still worked. The
  detector is now built with the leg's own ptime. The pre-existing unit test only ever covered the
  conversion helper, which was the half that was right, so the guard is a new end-to-end one: it
  offers a leg with `ws_vad` and a 300 ms hangover, talks into it over real RTP, and counts the
  uplink frames a WS server sees between `speech_started` and `speech_stopped` — 15 frames at the
  leg's 20 ms ptime, against the 300 the defect produced.

### Internal

- **The memory-leak soaks now gate on a converged steady state rather than a fixed warmup.** The
  intermittent "overlay playback leaked ~600 KB" was measurement, not a leak: the delta does not
  scale with cycles, and the plateau's height and the cycles needed to reach it both scale with core
  count, so no fixed warmup could be right about it. The new gate churns until ten consecutive
  segments come back flat and then holds the last five to 16 bytes per cycle — 109× tighter than the
  bar it replaces, which passed an injected 64-bytes-per-cycle leak most of the time.
- **Release CI publishes `siphon-rtp-proto` to crates.io on a tag**, authenticated by Trusted
  Publishing rather than a stored token, and reachable by `workflow_dispatch` against an existing tag
  so a release predating the job can still be published.
- Third-party notices now credit the projects the X2/X3 framing was validated against — Wireshark,
  hyavari's `x2x3PduDissector`, and sipgate's MIT-licensed LI reference implementation and simulator,
  whose captured demo PDU established the PDU-format version. None of it is redistributed here.
- Docs: the echo canceller runs in the wire domain, not at the codec's native rate.

## [0.3.0] — 2026-08-21

### Breaking changes

**The JSON wire is backward compatible.** Every new field is `Option` (or a `bool` with
`skip_serializing_if`), the default `ProfileFlags` still serialises to `{}`, and an event tag a
consumer does not recognise still decodes to `Event::Unknown`. An existing controller's frames go
out byte-identical and are understood unchanged. The breaks are in the **Rust API** of
`siphon-rtp-proto` and in **runtime behaviour**.

Rust API:

- **The contract enums are now `#[non_exhaustive]`** — `Command`, `CmdResult`, `Event`,
  `PlayEndReason`, `PlayMediaSource`, `WsTeeEndReason` and `ProtoError`. A downstream `match` on any
  of them now needs a wildcard arm. That is a one-time cost that buys the opposite for every release
  after this one: adding a variant stops being a breaking change. `WsTeeDirection`, `WsVadEngine`,
  `ConferenceRole` and `BridgeDirection` are deliberately left exhaustive — those select engine
  behaviour, and a consumer that swept a new value into a wildcard would silently do the wrong thing
  instead of failing to build. The reasoning is recorded per type in the crate docs.
- **New variants**: `Command::SetPlayGain`, `Event::BeepDetected`, `PlayMediaSource::Tone` and
  `PlayMediaSource::Http`; plus a new `WsVadEngine` enum.
- **New fields on existing struct variants**: `overlay` and `gain_decibels` on `Command::PlayMedia`,
  `play_id` on `Command::StopMedia`, `sample_rate` on `Command::AttachWsTee`, and `beep_detection`,
  `beep_cadence_guard_ms`, `ws_sample_rate`, `ws_vad_engine`, `ws_vad_min_speech_ms` and
  `ws_tee_sample_rate` on `ProfileFlags`. Rust code that constructs these exhaustively (without
  `..Default::default()`) must be updated. Note the limit of what the previous bullet buys:
  `#[non_exhaustive]` at the **enum** level does not make *adding a field to a struct variant*
  additive. Only per-variant `#[non_exhaustive]` would, and that also stops other crates
  constructing the variant at all, so it is deliberately not applied — adding a field to a struct
  variant stays a breaking change.

Behaviour:

- **`play_media`'s `duration_ms` is now enforced.** It was parsed and dropped, so a caller that set
  it heard the whole prompt anyway; it now caps playout exactly as the contract always described. A
  controller that was relying on the field being ignored will see truncated playback.
- **`ws_uri` on a secure or ICE offerer is refused at offer time**, with a stable leading reason
  token, where it used to return `ok` and produce a call that answered and bridged nowhere. A
  controller that read the old `ok` as success now gets an error instead of a silently dead call.
- **`play_media` on a call with no media actor now errors** instead of returning a `play_id` and a
  `play_finished` that never arrived.
- **Media from an unvalidated source on a redirected ICE endpoint is now dropped** (the security fix
  below). Traffic that was reaching a conference seat, a promoted userspace call or a WebSocket
  takeover leg from a transport ICE never validated stops being relayed. That is the point of the
  fix, but it is a behaviour change for anything that was unknowingly relying on the open gate.

### Added

- **Overlay playback.** `play_media` with `"overlay": true` mixes audio *under* a leg's live egress
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

### Changed

- **The published contract enums carry `#[non_exhaustive]`** so that adding a variant is additive
  from here on. See the Breaking changes call-out above for which types, which are deliberately
  exempt, and why.
- The WS bridge's uplink noise suppressor and echo canceller now run in the **wire** rate domain —
  the domain the far side hears, and the only one that keeps the canceller's near-end input and
  far-end reference in a single rate and frame length. A wire rate the noise suppressor does not
  support (anything but 8/16 kHz) leaves it off with a `warn`, and never changes the negotiated rate.

### Fixed

- **WebSocket takeover downlink was rendered at the wrong rate.** A server sending playout PCM at
  anything other than the leg's codec rate had it encoded sample-for-sample into the leg's codec, so
  the call heard the right samples at the wrong speed and pitch with no error reported anywhere. The
  downlink is now resampled into the leg's rate before the encode.
- `play_media`'s `duration_ms` was parsed and then dropped. It is now the hard playout cap the
  contract always described — and the only bound, short of a stop, on an endless tone.
- A resampled prompt now emits exactly one egress frame per playout tick. Previously it emitted
  whatever the polyphase resampler happened to produce while advancing the RTP timestamp by a fixed
  increment, so a prompt whose source rate differed from the leg's drifted against its own clock.
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

### Security

- **RTPBleed class: a redirected ICE endpoint had no source gate at all.** The datapath's
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

### Documentation

- [Voice AI cookbook](docs/cookbook/voice-ai.md) gains a detector-choice section: the comparison
  table, the 32 ms framing and its latency floor, the measured cost, the leading-run gate, and the
  measured echo-return-loss curve showing why `echo_cancellation` is not optional under barge-in
  (the network still calls far-end speech "speech" down to about −36 dB of ERL — echo of speech is
  speech, and no VAD can substitute for the canceller).

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
