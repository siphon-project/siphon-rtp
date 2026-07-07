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
| `answer` | `call_id`, `from_tag`, `to_tag`, `sdp`, `profile` | SDP answer (B to A). Completes negotiation, returns the rewritten SDP. |
| `delete` | `call_id`, `from_tag`, `to_tag?` | Tear down the session. |
| `query` | `call_id`, `from_tag`, `to_tag?` | Session statistics: `packets_in/out`, `bytes_in/out`, `packets_lost`. |

The `profile` object is the JSON twin of rtpengine's flag set. Most fields change behaviour; a few
(`ice`, `dtls`, `direction`) are accepted for rtpengine compatibility but are **not policy inputs
yet**, noted below.

| `profile` field | Type | Meaning |
|---|---|---|
| `transport_protocol` | string | Far-leg transport, e.g. `RTP/AVP`, `RTP/SAVP` (SDES-SRTP, RFC 4568), `UDP/TLS/RTP/SAVPF` (DTLS-SRTP, RFC 5764). |
| `ice` | string | Parsed for compatibility, **currently no-op**. ICE-lite is driven from the SDP (an ICE offer), not this field. |
| `dtls` | string | Parsed for compatibility, **currently no-op**. DTLS-SRTP is selected by `transport_protocol` (`UDP/TLS/RTP/SAVPF`) + the SDP `a=fingerprint` / `a=setup`, not this field. |
| `replace` | string list | SDP fields to rewrite, e.g. `["origin"]`. |
| `address_family` | string | `IP4` \| `IP6` for the far leg's engine endpoints (v4/v6 interworking). |
| `flags` | string list | Behavioral flags plus the codec directives (`codec-transcode-X`, `codec-mask-X`, `codec-strip-X`, `codec-offer-X`, `codec-except-X`, `ptime=N`, ...). |
| `direction` | string list | Parsed for compatibility, **currently no-op** (multi-interface direction routing is planned). |
| `record_call`, `record_path` | bool, string | Record this call from setup; output directory. |
| `ws_uri` | string | Attach leg A to an external WebSocket media server (`ws://` or `wss://`; `wss://` on ring/rustls with webpki-roots trust). A native extension; not available over NG. |
| `received_from` | IP string | The real post-NAT source IP the SIP proxy saw. Tightens the ingress source gate (anti-RTPBleed, see [Security and NAT](../security-and-nat.md)). |
| `rtcp_mux` | string list | rtpengine `rtcp-mux` directives (`offer`, `require`, `demux`, `accept`, `reject`, `remove`) overriding the RFC 5761 mux decision. |

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

`restore` currently rebuilds three call shapes: a plain passthrough relay, an SDES-SRTP
bridge, and a plaintext transcode call. A secure transcode call (`SrtpMedia`) or a
WebSocket-bridged call keeps live state inside its running actor and is rejected with
`restore of a ... call is not yet supported`. Restoring a `call_id` that already exists
on the node is also rejected.

### Media control

| Verb | Fields | Purpose |
|---|---|---|
| `play_media` | `call_id`, `from_tag`, `source`, `repeat_times?`, `start_pos_ms?`, `duration_ms?`, `to_tag?` | Inject a WAV prompt toward a leg. `source` is tagged: `{"source": "file", "path": "..."}` or `{"source": "blob", "data": [...]}`. |
| `stop_media` | `call_id`, `from_tag` | Stop prompt/DTMF playback. |
| `play_dtmf` | `call_id`, `from_tag`, `code`, `duration_ms?`, `volume_dbm0?`, `pause_ms?`, `to_tag?` | Inject RFC 4733 telephone-events toward a leg. |
| `silence_media` / `unsilence_media` | `call_id`, `from_tag` | Replace egress audio with comfort silence / resume. |
| `block_media` / `unblock_media` | `call_id`, `from_tag` | Drop egress packets entirely / resume. |
| `block_dtmf` / `unblock_dtmf` | `call_id`, `from_tag`, `to_tag?` | Stop relaying one leg's RFC 4733 telephone-events to the peer. The digit is still detected and surfaced as a `dtmf` event; only the relay is suppressed. Drop mode only (no tone/PCM replacement yet). |
| `echo` | `call_id`, `from_tag`, `to_tag?`, `enabled` | Loop a leg's inbound audio back to itself (echo test). `enabled` defaults to `true`; send `false` to stop. |

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

Conference legs accept plain `RTP/AVP` and SDES `RTP/SAVP` offers. An ICE / DTLS-SRTP
(WebRTC) conference leg is rejected with a clear error; that is a follow-up. A
participant whose codec the engine can decode but not encode is also refused a seat (the
room mix could not be sent back).

## Results

Every response is one of:

| `result` | Payload |
|---|---|
| `ok` | Optional `sdp` (offer/answer/subscribe), `duration_ms` (play_media), `to_tag` (subscribe_request), `stats` (query). |
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
| `active_speaker` | `conference_id`, `from_tag?` | The dominant speaker in a conference changed; `from_tag` absent means the floor went silent. |
| `call_quality` | `conference_id`, `from_tag`, `jitter_ms`, `loss_percent`, `mos` | Periodic per-participant reception quality: RFC 3550 §6.4.1 interarrival jitter, residual loss, and an ITU-T G.107 E-model MOS estimate (1.0..=4.5). Emitted every few seconds per conference participant. |

`active_speaker` and `call_quality` are conference-scoped today. For per-call quality on
ordinary relayed calls, use [HEP/Homer export](../observability.md) instead.

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
