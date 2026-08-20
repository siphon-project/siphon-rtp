# Native JSON control protocol

siphon-rtp's native control interface is length-prefixed JSON over a persistent TCP
connection. SIPhon speaks it directly; anything else that can frame JSON can too. The wire
types live in the [`siphon-rtp-proto`](https://crates.io/crates/siphon-rtp-proto) crate,
shared by both ends, so the Rust types *are* the contract.

The daemon listens on `--control` (default `127.0.0.1:8080`). The verb set and session
keying (`call_id` / `from_tag` / `to_tag`) mirror the rtpengine NG semantics, only the
encoding differs. If you need the actual bencode wire format for an existing
Kamailio/OpenSIPS deployment, use the [NG front-end](ng.md) instead.

## Framing

Each frame is a big-endian `u32` byte length followed by a JSON body:

```
+----------------+----------------------------+
| length (4B BE) | JSON body (length bytes)   |
+----------------+----------------------------+
```

- Maximum frame size is 1 MiB. A length prefix beyond that is treated as corruption and
  the connection is closed.
- Requests are processed in order per connection; connections are handled concurrently.
- A request carries a numeric `id`; the matching response echoes it. Asynchronous events
  are server-initiated frames with no `id`.
- Commands are tagged on `"command"`, results on `"result"`, events on `"event"`, all in
  snake_case. Unknown event kinds must be tolerated by clients (the engine reserves the
  right to add more).

A request and its response:

```json
{"id": 1, "command": "ping"}
```

```json
{"id": 1, "result": "pong"}
```

## Authentication

Set `SIPHON_RTP_CONTROL_SECRET` in the daemon's environment to require a shared secret.
When set, the first command on every connection must be:

```json
{"id": 0, "command": "authenticate", "token": "the-shared-secret"}
```

Any other command before a successful `authenticate` is answered
`{"result": "error", "reason": "authentication required"}`. The token comparison is
length-checked and constant-time. With no secret configured, connections start
authenticated; run that posture only on a trusted, private control network.

Two more per-connection guards apply regardless of auth:

- A token-bucket rate cap (`--max-control-rps`, default 200 requests/second, 0 disables).
  A breach is answered `{"result": "error", "reason": "rate limit exceeded"}` before any
  work is done.
- Ownership: a call is private to the connection that created it. `query`, `delete`,
  `checkpoint`, and the media-control verbs on someone else's call answer as if the call
  did not exist, and `list` returns only your own calls. See
  [Security and NAT](../security-and-nat.md) for the threat model.

## Request catalogue

### Session lifecycle

| Verb | Fields | Purpose |
|---|---|---|
| `offer` | `call_id`, `from_tag`, `sdp`, `profile` | SDP offer (A to B). Allocates media ports, rewrites the SDP (RFC 3264 offer/answer), returns the rewritten SDP. |
| `reoffer` | `call_id`, `from_tag`, `sdp`, `profile` | SDP re-offer (SIP re-INVITE, RFC 3264 §8) on a live call: renegotiate **on the existing media ports** instead of replacing the call. A re-offer whose `a=ice-ufrag`/`a=ice-pwd` differ triggers an RFC 8445 §9 ICE restart while media keeps flowing. Owner-only; returns the rewritten SDP on the same ports. |
| `answer` | `call_id`, `from_tag`, `to_tag`, `sdp`, `profile` | SDP answer (B to A). Completes negotiation, returns the rewritten SDP. |
| `answer_local` | `call_id`, `from_tag`, `sdp`, `profile` | Single-leg UAS answer — the engine *is* the far side (IVR / echo / announcement). Picks one encodable codec from the offer, synthesises the RFC 3264 answer, and engages the transcoder now. No `to_tag` (there is no far leg). |
| `ice_candidate` | `call_id`, `from_tag`, `to_tag?`, `candidates`, `end_of_candidates?` | A trickled ICE candidate from a peer (RFC 8838), arriving after its offer/answer. Each `a=candidate:` line is paired and checked as a triggered check. `to_tag` absent ⇒ near (offerer) leg, present ⇒ far (answerer) leg. Owner-only; requires `--ice-full`. |
| `delete` | `call_id`, `from_tag`, `to_tag?` | Tear down the session. |
| `query` | `call_id`, `from_tag`, `to_tag?` | Session statistics: `packets_in/out`, `bytes_in/out`, `packets_lost`. |

The `profile` object is the JSON twin of rtpengine's flag set. Most fields change behaviour; `ice`
and `dtls` override the SDP-derived ICE/DTLS posture on `offer` (below); `direction` selects the
per-leg media interface (below).

| `profile` field | Type | Meaning |
|---|---|---|
| `transport_protocol` | string | Far-leg transport, e.g. `RTP/AVP`, `RTP/SAVP` (SDES-SRTP, RFC 4568), `UDP/TLS/RTP/SAVPF` (DTLS-SRTP, RFC 5764). |
| `ice` | string | Override the SDP-derived ICE posture on the far offer (RFC 8445 / RFC 8839 §5). `force` (and `force-relay`) advertise engine ICE-lite even when the offer carried no ICE; `remove` strips the offerer's ICE and advertises none of ours. Unset ⇒ mirror the offer. `force-relay` is treated as `force` (the relay-only restriction is not honored). The engine advertises its host candidate, a server-reflexive candidate when `--stun-server` answers, and — when a TURN server is configured for the engine to allocate against (`Engine::with_turn_server`, not a daemon flag today) — a relayed candidate; a plain `force` leg offers the same set. |
| `dtls` | string | Override the DTLS-SRTP posture of a secure (`UDP/TLS/RTP/SAVP[F]`) far leg. `off` downgrades it to plaintext `RTP/AVP` (strips `a=fingerprint`/`a=setup`); `passive` / `active` / `actpass` set the offerer `a=setup` role (RFC 4145 §4 / RFC 5763 §5) instead of the default `actpass`. On a non-DTLS far leg the field is a no-op. |
| `replace` | string list | SDP fields to rewrite, e.g. `["origin"]`. |
| `address_family` | string | `IP4` \| `IP6` for the far leg's engine endpoints (v4/v6 interworking). |
| `flags` | string list | Behavioral flags plus the codec directives (`codec-transcode-X`, `codec-mask-X`, `codec-strip-X`, `codec-offer-X`, `codec-except-X`, `ptime=N`, ...). |
| `direction` | string list | Named-interface selection (rtpengine-style). Two interface names: the first for the caller-facing (A / near) leg, the second for the callee-facing (B / far) leg — so an inbound leg lands on `internal` and the outbound leg on `external`. Each interface has a bind IP and an advertised (public) IP (see the daemon `[[interface]]` config). An absent or unknown name falls back to the default interface (logged). With no `[[interface]]` configured, both legs use the single synthesised `default` interface. |
| `record_call`, `record_path` | bool, string | Record this call from setup; output directory. |
| `noise_suppression` | bool | Single-channel noise suppression on this leg's decoded ingress before it is transcoded/relayed (and captured by recording/forks). Engaged only on a userspace-transcoded leg whose codec is 8 or 16 kHz; inert on an in-kernel passthrough or a 48 kHz codec. Setting it forces a same-codec call off the in-kernel fast path onto the media slow path (like `record_call`). Native extension; not set over NG. |
| `echo_cancellation` | bool | Acoustic/line echo cancellation on this leg's send path, using the audio played *toward* that party as the far-end reference (on a WebSocket voice-AI bridge, the AI downlink cancels the phone's echo of the AI). Runs at the codec's native 8 or 16 kHz; a codec at another rate passes through uncancelled. Wired on transcode and WebSocket-bridge legs, **not** on SRTP/DTLS-secured legs. Setting it promotes a same-codec plaintext call to the userspace pipeline. Native extension; not set over NG. |
| `beep_detection` | bool | Watch this call's decoded ingress audio for the short single tone an answering machine plays before it records (the "voicemail beep"), and report it as a `beep_detected` event — the media half of answering-machine detection. Armed on **both** legs of the call; the event's `from_tag` names the leg the tone was heard on. Needs decoded audio, so setting it promotes a same-codec plaintext call to the userspace media pipeline (like `noise_suppression`); inert on a codec whose native rate is neither 8 nor 16 kHz. Fires **once** per leg per call — no mid-call re-arm. See [Answering-machine (beep) detection](#answering-machine-beep-detection). Native extension; not set over NG. |
| `beep_cadence_guard_ms` | int | How long the beep detector waits after a candidate tone to rule out a repeat — the discriminator that keeps a cadenced ringback / busy / congestion / special-information tone from reading as a record tone, and therefore also the detection latency. Unset ⇒ 4500 ms. Inert without `beep_detection`. |
| `ws_uri` | string | Attach leg A to an external WebSocket media server (`ws://` or `wss://`; `wss://` on ring/rustls with webpki-roots trust). A native extension; not available over NG. |
| `ws_vad`, `ws_barge_in` | bool | Voice-AI turn-taking on the `ws_uri` bridge. `ws_vad` runs a local energy-VAD on the uplink and emits `speech_started` / `speech_stopped` WS control frames on the caller's speech edges (turn boundaries without a server-side VAD). `ws_barge_in` additionally flushes the queued downlink playout in the same tick when the caller starts speaking (no server round-trip); it implies `ws_vad`. Both inert without `ws_uri`. |
| `ws_sample_rate` | int | L16 wire sample rate in Hz for the `ws_uri` takeover bridge, independent of the leg's codec rate and applied in **both** directions (uplink is resampled leg→wire, downlink wire→leg before re-encoding). Also the domain the uplink noise suppressor / echo canceller run in; they engage only at 8/16 kHz, so another rate leaves them off without changing the wire rate. Must be a multiple of 1000 within 8000–48000, else the offer/answer is rejected (never clamped). Unset ⇒ the leg codec's own PCM rate, no conversion. Inert without `ws_uri`. |
| `ws_vad_threshold`, `ws_vad_hangover_ms` | int, int | Tune the WS uplink VAD: mean-square energy threshold (`None` ≈ 1_000_000; higher is less sensitive) and trailing hangover in ms before `speech_stopped` fires (`None` ≈ 200 ms). Only meaningful with `ws_vad` / `ws_barge_in`. |

| `ws_vad`, `ws_barge_in` | bool | Voice-AI turn-taking on the `ws_uri` bridge. `ws_vad` runs a local VAD on the uplink (which detector is `ws_vad_engine`, below) and emits `speech_started` / `speech_stopped` WS control frames on the caller's speech edges (turn boundaries without a server-side VAD). `ws_barge_in` additionally flushes the queued downlink playout in the same tick when the caller starts speaking (no server round-trip); it implies `ws_vad`. Both inert without `ws_uri`. |
| `ws_vad_threshold`, `ws_vad_hangover_ms` | int, int | Tune the WS uplink **energy** VAD: mean-square energy threshold (`None` ≈ 1_000_000; higher is less sensitive) and trailing hangover in ms before `speech_stopped` fires (`None` ≈ 200 ms). Only meaningful with `ws_vad` / `ws_barge_in`, and only with `ws_vad_engine: "energy"`. |
| `ws_vad_engine` | string | Which detector the WS uplink VAD runs: `energy` (default — a mean-square threshold with hangover) or `neural` (an embedded speech classifier that does not fire on breathing, hum or fan noise). See [Turn-taking, barge-in, and echo control](../cookbook/voice-ai.md#turn-taking-barge-in-and-echo-control). Only meaningful with `ws_vad` / `ws_barge_in`; an unbuildable selection fails the offer rather than downgrading. The detector runs in the **wire**-rate domain (`ws_sample_rate`), the same domain as the noise suppressor and echo canceller, because the rate conversion happens before the frame reaches them. |
| `ws_vad_min_speech_ms` | int | **Leading** minimum-speech run: how long the uplink must read as speech *continuously* before `speech_started` (and barge-in) fires. Unset ⇒ no leading requirement, i.e. the edge fires on the first speech frame. Rounded up to whole ptime frames and added directly to turn-start latency; 60–120 ms is the useful range. Works with either detector. |
| `received_from` | IP string | The real post-NAT source IP the SIP proxy saw. Tightens the ingress source gate (anti-RTPBleed, see [Security and NAT](../security-and-nat.md)). |
| `rtcp_mux` | string list | rtpengine `rtcp-mux` directives (`offer`, `require`, `demux`, `accept`, `reject`, `remove`) overriding the RFC 5761 mux decision. |
| `text_events` | bool | Emit `text` events for recovered RFC 4103 real-time text on the call's `m=text` stream (routes the text through the userspace text processor). Native extension; not set over NG. |
| `ws_tee` | string | Attach a send-only WebSocket tee at offer time (the `attach_ws_tee` twin): a `ws://` / `wss://` URI the engine streams the call's decoded audio to while it keeps relaying. Native extension; not over NG. |
| `ws_tee_direction` | string | Which leg(s) `ws_tee` streams: `both` (default) / `caller` / `callee`. Inert without `ws_tee`. |
| `ws_tee_channels` | int | Wire channel count for `ws_tee`: `2` = stereo caller/callee, `1` = mixed mono. Unset ⇒ 2 when both legs are teed, 1 for a single leg. Inert without `ws_tee`. |
| `ws_tee_sample_rate` | int | L16 wire sample rate in Hz for `ws_tee`, independent of either leg's codec rate: each tapped leg is resampled into it before framing. Must be a multiple of 1000 within 8000–48000, else the answer is rejected (never clamped). Unset ⇒ the tapped leg's own codec PCM rate. Inert without `ws_tee`. |

### Liveness and census

| Verb | Fields | Result |
|---|---|---|
| `ping` | none | `{"result": "pong"}`. |
| `list` | none | `{"result": "list", "call_ids": [...]}`, scoped to the calling connection. |
| `statistics` | none | Global process counters: `offers_total`, `answers_total`, `deletes_total`, `control_errors_total`, live `sessions`. |

### Cluster placement

| Verb | Fields | Result |
|---|---|---|
| `load` | none | Live load snapshot for a dispatcher: `node_id`, `sessions`, `max_sessions`, `load_permille` (0..=1000), `transcode_sessions`, `cpu_permille?`, `jemalloc_allocated_bytes`, `draining`. |
| `node_info` | none | Static identity: `node_id`, `version`, `media_addresses`, `codecs`, `features`, `max_sessions`, `draining`. Read once and cache; poll `load` instead. |
| `drain` | none | Stop admitting new sessions (`offer` and `conference_join` are rejected); live calls run to completion. Idempotent. |
| `undrain` | none | Resume admitting new sessions. |

### High availability

| Verb | Fields | Result |
|---|---|---|
| `checkpoint` | `call_id`, `from_tag` | `{"result": "checkpoint", "snapshot": "..."}`. An opaque blob; store it verbatim, keyed by call. Ownership-gated. |
| `restore` | `snapshot` | Rebuilds the call on this (standby) node at the snapshot's exact ports, so a floating-IP failover needs no re-INVITE. |

`restore` currently rebuilds four call shapes: a plain passthrough relay, an SDES-SRTP
bridge, a plaintext transcode call, and a secure transcode call (`SrtpMedia`). A
WebSocket-bridged or DTLS-SRTP call keeps live state that a snapshot cannot recover (a running
WS actor, or handshake-derived DTLS keys) and is rejected with
`restore of a ... call is not yet supported`. Restoring a `call_id` that already exists
on the node is also rejected.

### Media control

| Verb | Fields | Purpose |
|---|---|---|
| `play_media` | `call_id`, `from_tag`, `source`, `repeat_times?`, `start_pos_ms?`, `duration_ms?`, `to_tag?` | Inject a WAV prompt toward a leg. `source` is tagged: `{"source": "file", "path": "..."}` or `{"source": "blob", "data": [...]}`. Accepts immediately (accept-on-start) with a `play_id`; the prompt's end is reported later by a matching `play_finished` event carrying the same `play_id`, so a controller correlates the completion without a late response racing the request timeout. |
| `stop_media` | `call_id`, `from_tag` | Stop prompt/DTMF playback. |
| `play_dtmf` | `call_id`, `from_tag`, `code`, `duration_ms?`, `volume_dbm0?`, `pause_ms?`, `to_tag?` | Inject RFC 4733 telephone-events toward a leg. |
| `silence_media` / `unsilence_media` | `call_id`, `from_tag` | Replace egress audio with comfort silence / resume. |
| `block_media` / `unblock_media` | `call_id`, `from_tag` | Drop egress packets entirely / resume. |
| `block_dtmf` / `unblock_dtmf` | `call_id`, `from_tag`, `to_tag?` | Stop relaying one leg's RFC 4733 telephone-events to the peer. The digit is still detected and surfaced as a `dtmf` event; only the relay is suppressed. Drop mode only (no tone/PCM replacement yet). |
| `echo` | `call_id`, `from_tag`, `to_tag?`, `enabled` | Loop a leg's inbound audio back to itself (echo test). `enabled` defaults to `true`; send `false` to stop. |
| `attach_ws_tee` | `call_id`, `from_tag`, `ws_uri`, `direction?`, `channels?`, `sample_rate?` | Attach a send-only WebSocket tee to a live call: stream its decoded audio to `ws_uri` while the call keeps relaying. `direction` is `both` (default) / `caller` / `callee`; `channels` is `2` (stereo caller/callee) or `1` (mono mix), both-legs only. `sample_rate` is the L16 wire rate in Hz, independent of the codec rate (multiple of 1000, 8000–48000; rejected, never clamped) — unset follows the tapped leg's own PCM rate. A plain relay is promoted to the userspace pipeline for the tee's lifetime. Native extension; not over NG. |
| `detach_ws_tee` | `call_id`, `from_tag` | Detach the WebSocket tee and close its stream. Idempotent. |

Media-control honesty, in one place:

- `play_media`, `play_dtmf`, `silence_media`, and `echo` require a media-processing
  (transcoding) call. A plain relay forwards opaque payloads and cannot synthesize into
  them; the error says so.
- `play_media` with `{"source": "db_id"}` is rejected (`db-id media source is not
  supported`). Use `file` or `blob`.
- `block_dtmf` is rejected on a plain SRTP bridge or a WebSocket-bridged call, whose DTMF
  is not carried as clear telephone-events. A secure *transcode* call is fine (the actor
  sees clear RTP).
- `block_media` on an SRTP bridge (non-transcoding) is rejected: the call is not answered
  as a plain relay and has no media actor to gate.

### Recording and forking

| Verb | Fields | Purpose |
|---|---|---|
| `start_recording` | `call_id`, `from_tag`, `recording_dir?` | Record the live call's raw RTP/RTCP byte-for-byte to `{recording_dir}/{call_id}.pcap`. A plain relay is promoted to the userspace pipeline for the tap. |
| `stop_recording` | `call_id`, `from_tag` | Finalize the pcap; the relay demotes back to the fast path if nothing else holds it. |
| `subscribe_request` | `call_id`, `from_tags[]`, `sdp?`, `profile` | SIPREC fork (RFC 7866): the engine *offers* the named legs' media to a recording server, `a=sendonly`. Send `sdp: null`; an SDP-bearing request (SRS offering first) is rejected. Returns the offer SDP and a `to_tag`. |
| `subscribe_answer` | `call_id`, `from_tag`, `to_tag`, `sdp` | Complete the subscription with the SRS's answer; the tee starts. |
| `unsubscribe` | `call_id`, `from_tag`, `to_tag` | Tear down the subscription. |

Both recording and SIPREC copy the source leg's original ingress RTP byte-for-byte (its
negotiated codec, no re-encode), so they work on any codec the engine can relay,
including ones it cannot transcode. Both are rejected on SRTP-bridged and
WebSocket-bridged calls, whose on-the-wire bytes are ciphertext or diverted; decrypting
before recording is a follow-up.

### Conferencing

| Verb | Fields | Purpose |
|---|---|---|
| `conference_join` | `conference_id`, `from_tag`, `sdp`, `role`, `profile` | Join (or lazily create) a mixing conference. The engine answers the SDP; the participant hears the room mixed-minus-self. |
| `conference_leave` | `conference_id`, `from_tag` | Leave; the room tears down when the last participant leaves. |
| `conference_route` | `conference_id`, `from_tag`, `role` | Live-update a participant's routing role. |
| `conference_bridge` | `conference_id_a`, `conference_id_b`, `direction` | Bridge two rooms (`both`, `a_to_b`, `b_to_a`). |

`role` is tagged: `{"role": "talker"}` (default), `"listener"`, `"muted"`,
`{"role": "whisper", "target": "..."}` (supervisor coaching, excluded from the room mix),
or `{"role": "monitor", "target": "...", "whisper_target": "..."}` (listen to one
participant, optionally whispering to another). Rooms are capped at 64 participants.

Conference legs accept plain `RTP/AVP` and SDES `RTP/SAVP` offers. An ICE or DTLS-SRTP
(WebRTC) conference leg is accepted and seated *pending*: the seat opens only once the DTLS
handshake keys it / ICE selects a pair, and until then the room drops its ingress and sends it
nothing. A participant whose codec the engine can decode but not encode is also refused a seat (the
room mix could not be sent back).

## Results

Every response is one of:

| `result` | Payload |
|---|---|
| `ok` | Optional `sdp` (offer/answer/subscribe), `play_id` + `duration_ms` (play_media accept), `to_tag` (subscribe_request), `stats` (query). |
| `pong` | none |
| `list` | `call_ids` |
| `statistics` | `statistics` counter object |
| `load` | `load` snapshot object |
| `node_info` | `node` identity object |
| `checkpoint` | `snapshot` blob |
| `error` | `reason` string |

## Asynchronous events

Events are pushed down the same TCP connection, tagged on `"event"`, with no `id`:

| Event | Fields | When |
|---|---|---|
| `dtmf` | `call_id`, `from_tag`, `to_tag?`, `digit`, `duration_ms`, `volume`, `source?` | An RFC 4733 telephone-event completed on a leg of a media-processing call or a conference participant. Fires even while that leg's DTMF relay is blocked. |
| `media_timeout` | `call_id`, `from_tag` | The call went silent past `--media-timeout-secs` and the engine reaped it. Release your own per-call state. |
| `play_finished` | `call_id`, `from_tag`, `to_tag?`, `play_id`, `reason`, `played_ms?` | A `play_media` prompt ended. `play_id` matches the accept; `reason` is `completed` (drained in full, all repeats / the `duration_ms` cap), `stopped` (`stop_media`), `superseded` (a newer `play_media` on the same leg), or `error` (decode/source error or the leg was torn down mid-play). Only `completed` means the prompt finished on its own. |
| `active_speaker` | `conference_id`, `from_tag?` | The dominant speaker in a conference changed; `from_tag` absent means the floor went silent. |
| `call_quality` | `conference_id?` xor `call_id?`, `from_tag`, `jitter_ms`, `loss_percent`, `mos` | Periodic reception quality: RFC 3550 §6.4.1 interarrival jitter, residual loss, and an ITU-T G.107 E-model MOS estimate (1.0..=4.5). Fires every few seconds per conference participant (keyed by `conference_id`) and per 2-party relay or transcode leg (keyed by `call_id`); exactly one identifier is present. |
| `text` | `call_id`, `from_tag`, `to_tag?`, `text`, `direction?` | Newly-recovered RFC 4103 real-time text (T.140) on a call's `m=text` stream. `text` is the UTF-8 increment this packet delivered (U+FFFD markers preserved where loss occurred, RFC 4103 §5.3); `from_tag` is the sending leg; `direction` is `a_to_b` / `b_to_a`. Requires `text_events`. |
| `beep_detected` | `call_id`, `from_tag`, `to_tag?`, `frequency_hz`, `duration_ms`, `offset_ms` | An answering-machine record tone was heard on a leg armed with `beep_detection`. `from_tag` is the leg that played it; `frequency_hz` / `duration_ms` are what was measured (duration accurate to ≈ ±32 ms); `offset_ms` is how far into that leg's decoded audio the tone *started* — the event itself arrives `beep_cadence_guard_ms` later. Emitted at most once per leg per call. |
| `call_summary` | `call_id`, `reason`, `duration_ms`, `legs[]` | End-of-call CDR, emitted once at teardown (`delete` or media-timeout). Carries per-party byte/packet counters and, for a userspace media call, RFC 3550 loss/jitter + ITU-T G.107 MOS. One `legs` entry per party (a single-leg call has one). |
| `ws_tee_started` | `call_id`, `from_tag`, `stream_id`, `ws_uri`, `direction`, `channels`, `sample_rate` | A WebSocket tee started streaming (`attach_ws_tee` or `ws_tee`): carries the negotiated wire shape (channels, and the L16 `sample_rate` actually negotiated — the requested one when `sample_rate` / `ws_tee_sample_rate` was set, otherwise the tapped leg's codec rate) and the `stream_id` matching the WS `start` frame. |
| `ws_tee_ended` | `call_id`, `from_tag`, `stream_id`, `reason`, `frames_sent?`, `frames_dropped?` | The WebSocket tee stopped (detach, call teardown, or the server ended it). Emitted exactly once per started tee. |

`active_speaker` is conference-scoped. `call_quality` now also fires for ordinary 2-party relay and
transcode calls (keyed by `call_id`), so per-call quality is on the control channel as well as in the
[HEP/Homer export](../observability.md).

## Answering-machine (beep) detection

`beep_detection` turns on a media-only detector for the short single tone an answering machine plays
before it starts recording, so a controller can abort an attended transfer instead of bridging a live
caller into a voicemail box. It is opt-in per call, arms both legs, and reports through the
`beep_detected` event above.

### What it looks for

A record tone is a *lone, sustained, narrow-band tone of stable frequency and stable amplitude, of a
plausible duration, that is not speech*. The one standardised anchor point is ITU-T E.180 / Q.35's
recording warning tone (1400 Hz, 500 ms); deployed voicemail tones sit in the same neighbourhood. Per
16 ms analysis hop the detector requires **all** of:

| Rule | Default | Why this value |
|---|---|---|
| Frequency window | 400 Hz … 2000 Hz | Below 400 Hz lie mains hum harmonics and the 350/425 Hz dial-tone family; above 2 kHz lie the fax answer tone (2100 Hz) and modem signalling. |
| Narrow-band concentration | ≥ 0.60 of the 200–3400 Hz band power in the three bins around the peak | A clean tone scores ≈ 0.99 and the ratio degrades as `SNR/(SNR+1)`; 0.60 holds a tone to ≈ 2 dB in-band SNR while sitting far above anything speech reaches. |
| No second tone | strongest out-of-lobe bin ≥ 12 dB below the peak | DTMF is dual-frequency with at most 8 dB of twist (ITU-T Q.24), so 12 dB rejects every valid DTMF pair with margin; a lone tone's own spectral leakage is ≥ 23 dB down. |
| Frequency stability | peak-to-peak excursion ≤ 30 Hz across the tone | Just under one 31.25 Hz analysis bin — inside a clean tone's measurement error even at low SNR, but well below a formant glide or an instrument vibrato. |
| Amplitude stability | peak-to-peak level swing ≤ 5 dB (ignoring the onset hop) | A tone's envelope is flat to well under a dB; a syllable swings by tens, and two close tones (440+480 Hz ringback) beat. |
| Duration | 120 ms … 1000 ms | Deployed record tones are 200–600 ms with a tail to 1 s. The *upper* bound is what stops a continuous dial or hold tone ever qualifying. |
| Not cadenced | no other qualifying burst within `beep_cadence_guard_ms` (default 4500 ms) either side | Ringback, busy, congestion and the three-segment special-information tone all repeat, and the repeat is the discriminator. 4500 ms clears the 4 s silent interval of the slowest widely deployed ringback cadence. |

Silence and comfort noise never reach the spectral tests: an energy gate (mean-square ≥ 20 000,
≈ −44 dBFS RMS) screens them out first.

### Latency

Because the cadence rule has to see what *follows* the tone, the event is emitted
`beep_cadence_guard_ms` after the tone ends — **≈ 4.5 s with the default**. That is the price of not
reporting a ringback burst as a beep. Lower it if the flow cannot wait; ≈ 1200 ms still covers busy,
congestion, the special-information tone and the UK double-ring inter-burst gap, but a slow-cadence
in-band ringback (1 s on / 4 s off) will then be reported as a beep on its first burst.

### What it cannot do

This is a media-only detector, and it errs toward **missing a beep rather than inventing one** — a
spurious "you reached a machine" tears down a live call, while a missed one just leaves the flow
where it would have been without the feature.

- It detects a *record tone*, not "an answering machine". A machine whose greeting ends without a
  tone, or whose tone is outside the frequency or duration window, is not detected. There is no
  greeting-length or silence-pattern heuristic and no speech recognition.
- Measured operating floor: the tone is still found down to **2 dB** in-band SNR at 8 kHz and
  **0 dB** at 16 kHz (`tone_detect_corpus`'s SNR sweep). Below that it is missed.
- A lone, harmonic-free, perfectly steady instrument note of 120–1000 ms surrounded by several
  seconds of silence is indistinguishable from a record tone by these rules. Real music on hold is
  neither harmonic-free nor surrounded by silence, and is rejected by the second-tone and cadence
  rules — but a synthetic one would fire.
- Duration is quantised to the 16 ms analysis hop and is accurate to about one analysis window
  (±32 ms). The reported frequency is sub-bin accurate (typically within a few Hz).
- Only the 8 kHz and 16 kHz telephony rates are supported. A leg at another native rate (a 48 kHz
  Opus leg) is left unwatched, logged at `warn` — it does not fail the call.
- Not restored by `restore`: a checkpoint does not carry the profile, so re-arm by re-issuing it.

It *is* wired on secure legs, unlike `echo_cancellation`: an SDES-SRTP or DTLS-SRTP call with the
flag set takes the secure media slow path (decrypt → detect → re-encrypt) rather than the cheaper
crypto-only bridge.

### Cost

One forward real FFT per 16 ms hop plus a bin scan. Criterion (`beep_8k_20ms` / `beep_16k_20ms`)
measures **≈ 2.1 µs per 20 ms frame at 8 kHz** and **≈ 4.0 µs at 16 kHz**; the noise suppressor
measured 6.0 µs / 12.3 µs on the same run, so beep detection costs about **a third of what noise
suppression does** on the same path — roughly 0.02 % of the 20 ms budget either way. Zero heap
allocation per frame.

## Worked examples

An offer that bridges a secure access leg to a plaintext core, stripping ICE:

```json
{
  "id": 12,
  "command": "offer",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "sdp": "v=0\r\no=- 1 1 IN IP4 198.51.100.20\r\ns=-\r\nc=IN IP4 198.51.100.20\r\nt=0 0\r\nm=audio 30000 RTP/SAVP 96 101\r\na=rtpmap:96 AMR-WB/16000\r\na=rtpmap:101 telephone-event/8000\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:...\r\n",
  "profile": {
    "transport_protocol": "RTP/AVP",
    "ice": "remove",
    "replace": ["origin"],
    "flags": ["codec-transcode-PCMA", "codec-mask-AMR-WB"]
  }
}
```

```json
{
  "id": 12,
  "result": "ok",
  "sdp": "v=0\r\no=- 1 1 IN IP4 203.0.113.10\r\ns=-\r\nc=IN IP4 203.0.113.10\r\nt=0 0\r\nm=audio 40002 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
}
```

Query the same call mid-flight:

```json
{"id": 13, "command": "query", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f"}
```

```json
{
  "id": 13,
  "result": "ok",
  "stats": {
    "packets_in": 4812,
    "packets_out": 4808,
    "bytes_in": 826464,
    "bytes_out": 812552,
    "packets_lost": 4
  }
}
```

Block a leg's DTMF relay, then observe the digit still arriving as an event:

```json
{"id": 14, "command": "block_dtmf", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f"}
```

```json
{"id": 14, "result": "ok"}
```

```json
{
  "event": "dtmf",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "digit": "5",
  "duration_ms": 120,
  "volume": -8
}
```

## See also

- [NG/bencode front-end](ng.md) for existing rtpengine deployments.
- [Security and NAT](../security-and-nat.md) for control-plane auth, ownership, and the
  media source gate.
- [Codec support](../codecs.md) for what `codec-transcode-X` can actually target.
