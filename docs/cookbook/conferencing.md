# Conferencing (MCU)

siphon-rtp ships a built-in N-party audio conference: a clock-driven mixer (MCU) that seats up to
64 participants per room, mixes them every 20 ms, and hands each participant its own
mixed-minus-self stream. You drive it with four native-JSON control verbs: `conference_join`,
`conference_leave`, `conference_route`, and `conference_bridge`.

These verbs exist only on the native JSON-over-TCP control channel. The rtpengine NG/bencode
front-end does not expose `conference_*` (stock rtpengine has no MCU), so a Kamailio/OpenSIPS
deployment talking NG cannot reach them.

## How the room works

A two-party call is packet-driven: one packet in, one packet out. A conference is clock-driven
instead. Every 20 ms (the RFC 3551 default ptime) the room actor pops one frame from every
participant's jitter buffer, decodes and resamples it to the room rate, mixes, then encodes and
sends one frame back to every participant. Each participant keeps its own decoder, encoder,
jitter buffer, and egress SSRC/sequence/timestamp (RFC 3550 §5.1), so the mix leaving the room
is a clean, engine-originated stream per leg.

The mix itself is O(N) mixed-minus-self: the room total is summed once (in i32, so 64 full-scale
i16 frames cannot overflow), each contributing talker hears `saturate(total - own)` so it never
hears itself, and everyone else shares one `saturate(total)` listener frame.

Only participants who are actually speaking contribute. An energy VAD (with hangover to bridge
short pauses) gates each talker in or out per tick, and the mixer can additionally cap the number
of simultaneous contributors to the M loudest (top-M by frame energy, up to 8). A talker gated
out this tick just hears the room like a listener. Rooms are created uncapped today (every
speaking talker contributes); there is no control verb to set the cap yet. The same energy
ranking drives the dominant-speaker detection behind the `active_speaker` event.

### Dynamic room rate

An unbridged room runs at the lowest of three rates — 8 kHz, 16 kHz, 48 kHz — that is at or above
every seated participant's own sample rate, so no leg is ever downsampled on the way into the mix.
An all-narrowband room (G.711, G.726, GSM-FR, ...) stays at 8 kHz, so the common all-G.711/PSTN
conference pays zero resampling. A wideband leg (G.722, AMR-WB) lifts it to 16 kHz; a full-band leg
(Opus, which RFC 7587 §4.1 clocks at 48 kHz) lifts it to 48 kHz, and an all-Opus room therefore
mixes full-band with no resampler in the path at all. Every rate change rebuilds every
participant's resampler pair, mid-call, in either direction. A leg whose rate falls between two
tiers (a 24 kHz Opus `maxplaybackrate`, say) is carried by the tier above it — upsampled, rather
than losing band on the way in.

A bridged room is the exception: it is pinned to 16 kHz regardless of membership. A bridge carries
bare room-rate frames with no rate tag and the two rooms' memberships move independently, so one
fixed rate is the only way both ends can agree without inter-room resampling.

### Packetization intervals that are not 20 ms

The room tick is a fixed 20 ms, but a leg's packetization interval need not be — RFC 7587 §6.1 lets
an Opus leg negotiate anything from 10 ms to 120 ms. Such a leg is drained and re-accumulated at the
room boundary rather than forced onto the tick: a 60 ms decode feeds three ticks instead of being
truncated to its first 20 ms, and the mix is held until a whole 60 ms frame is ready, so the leg
emits one packet every third tick with its RTP timestamp advancing 60 ms at a time. A 10 ms leg is
the mirror: two decodes fill a tick, and two packets leave it. Either way the leg's RTP clock tracks
the wall clock. A 20 ms leg (all of G.711, G.722, G.726, GSM-FR, AMR-NB/WB, and the Opus default)
takes the direct path and allocates neither buffer.

Two things get a leg refused at join. Its decoder and encoder must agree on sample rate,
packetization interval, and channel count: the room works in one frame length per participant, and a
mismatched pair would hand its encoder a wrong-length frame every tick. And its interval must be at
most 120 ms — the interval sizes the leg's ingress carry, its egress accumulator, and its playout
queue, so an unbounded `a=ptime` would buy a peer arbitrary per-participant buffering.

### Shared encode

Every listener (and every non-contributing talker) hears the same frame, so the engine encodes it
once per codec class per tick and fans the payload out with each leg's own RTP header. This works
for stateless codecs (G.711, L16); stateful encoders (G.722, G.726) and active talkers still
encode per leg. Listeners running below the room rate share the resample too — one room-to-8 kHz
and one room-to-16 kHz downsample per tick, not one per listener — so a 48 kHz Opus room with a
G.711 gallery and a 16 kHz gallery pays two downsamples between all of them. A 40-listener G.711
webinar pays one encode per tick, not forty. A listener whose packetization interval is not the room
tick is excluded from the shared class: the shared payload is exactly one tick of the listener mix,
and such a leg's frames straddle tick boundaries at its own phase.

## What a conference leg accepts

Honest limits first:

- Plain `RTP/AVP` and SDES-keyed `RTP/SAVP` (RFC 3711 / RFC 4568, `a=crypto` with
  `AES_CM_128_HMAC_SHA1_80`) legs are supported. An ICE or DTLS-SRTP (WebRTC) offer is accepted and
  the seat is taken *pending*: it joins the mix only once the DTLS handshake keys it or ICE selects a
  pair; until then its ingress is dropped and it hears nothing.
- The participant's codec must be both decodable and encodable by this build, because the engine
  has to encode the mix back. AMR-WB and AMR-NB egress need the `amr` Cargo feature (off by default,
  see [codec licensing](../codec-licensing.md)); without it an AMR join is refused. With `amr`,
  AMR-NB mixes are encoded at MR122 (the SDP `mode-set` is not applied to the mix egress). Opus has
  no encoder, so an Opus participant is refused.
- 64 participants per room, hard cap (the active-speaker set is a u64 bitmask).
- A node in drain mode rejects `conference_join` like it rejects `offer`.

Every participant endpoint is a full inbound surface, so the same RTPBleed defence as the relay
applies: ingress is gated to the SDP-signalled source address (or opened with the `symmetric`
profile flag), the reply address is latched only from a gated source, and a packet from anywhere
else never enters the mix. See [Security & NAT](../security-and-nat.md).

RFC 4733 telephone-events are filtered out of the mix (DTMF would mangle the audio) and surfaced
as `dtmf` events on the control channel instead.

## Joining a room

Rooms are created lazily: the first `conference_join` for a `conference_id` creates it, the last
`conference_leave` tears it down. The participant offers SDP; the engine answers with its own
endpoint, the participant's codec, sendrecv. Frames on the control channel are a big-endian u32
length prefix plus a JSON body; the bodies below omit the prefix.

```json
{
  "id": 1,
  "command": "conference_join",
  "conference_id": "room-1",
  "from_tag": "alice",
  "role": { "role": "talker" },
  "sdp": "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=-\r\nc=IN IP4 198.51.100.10\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
}
```

```json
{ "id": 1, "result": "ok", "sdp": "v=0\r\n... engine address and port, PCMU, sendrecv ...", "to_tag": "alice" }
```

`role` defaults to `talker` when omitted. For a secure participant, offer `RTP/SAVP` with an
`a=crypto` line; the answer comes back `RTP/SAVP` with the engine's own `a=crypto`, and that
leg's ingress is decrypted and egress encrypted (SRTP and SRTCP, RFC 3711).

Leaving frees the participant's endpoint; the room dies with its last member:

```json
{ "id": 2, "command": "conference_leave", "conference_id": "room-1", "from_tag": "alice" }
```

Participants that go silent past the media timeout (`--media-timeout-secs`) are reaped
automatically, and a room left empty is torn down, so an abandoned leg never leaks a room.

## Roles: mute, whisper, monitor

`conference_route` updates a seated participant's role live, no re-INVITE, no rejoin. The roles
form a small call-centre routing matrix:

| role | hears | is heard by |
|---|---|---|
| `talker` | room minus self | everyone (the default) |
| `listener` | the room | no one |
| `muted` | the room | no one (distinct from listener only for UI/state) |
| `whisper` | room minus self | only its `target` (excluded from the public mix) |
| `monitor` | its `target` directly, target unaware | no one (optionally whispers too) |

Mute a participant:

```json
{ "id": 3, "command": "conference_route", "conference_id": "room-1", "from_tag": "bob",
  "role": { "role": "muted" } }
```

Supervisor coaching: the supervisor's audio reaches only the agent, and the customer never hears
it.

```json
{ "id": 4, "command": "conference_route", "conference_id": "room-1", "from_tag": "supervisor",
  "role": { "role": "whisper", "target": "agent-a" } }
```

Silent monitoring, with an optional whisper path to the same agent (listen and coach):

```json
{ "id": 5, "command": "conference_route", "conference_id": "room-1", "from_tag": "supervisor",
  "role": { "role": "monitor", "target": "agent-a", "whisper_target": "agent-a" } }
```

Each replies `{ "id": N, "result": "ok" }`, or `"result": "error"` with a reason if the room or
participant is gone.

## Bridging two rooms

`conference_bridge` links two live rooms so each hears the other's participants, in one or both
directions:

```json
{ "id": 6, "command": "conference_bridge", "conference_id_a": "room-1",
  "conference_id_b": "room-2", "direction": "both" }
```

`direction` is `both` (default), `a_to_b`, or `b_to_a`. The bridge carries one room-rate frame
per tick over a bounded channel, adding one frame of latency; if a room falls behind, stale
frames are skipped rather than queued (late bridge audio is worthless). What crosses the bridge
is the participant-only mix, captured before any bridged audio is summed in, so a bridge can
never echo a room's own audio back to itself. Bridged audio is heard by everyone in
the receiving room but is not a participant: no one is mixed-minus-self against it. Bridging
forces both rooms to 16 kHz.

## Events the room pushes

The engine pushes these asynchronously on the same control connection (no `id`):

```json
{ "event": "active_speaker", "conference_id": "room-1", "from_tag": "alice" }
```

Fires when the dominant (loudest active) speaker changes; `from_tag` is omitted when the floor
goes silent. Drives floor control or speaker highlighting.

```json
{ "event": "dtmf", "call_id": "room-1", "from_tag": "bob", "digit": "5",
  "duration_ms": 120, "volume": -8 }
```

One event per completed RFC 4733 key press. Note the conference id arrives in the `call_id`
field, the same shape as two-party DTMF events.

```json
{ "event": "call_quality", "conference_id": "room-1", "from_tag": "alice",
  "jitter_ms": 1.125, "loss_percent": 0.0, "mos": 4.41 }
```

Per participant, every ~5 s: RFC 3550 interarrival jitter, residual loss, and an ITU-T G.107
E-model MOS. The engine also sends each participant a periodic RTCP Sender Report with a
reception report block (RFC 3550 §6.4.1) on the same muxed endpoint (RFC 5761). See
[Monitoring & QoS](monitoring.md) and [Observability](../observability.md).

## How to verify

- `siphon_rtp_conference_rooms` and `siphon_rtp_conference_participants` gauges on `/metrics`
  track live rooms and seats; `siphon_rtp_conference_joins_total` / `_leaves_total` count the
  verbs. See [Monitoring & QoS](monitoring.md).
- Join two G.711 legs as talkers and send audio into one: the other's socket receives a mixed
  RTP stream from the engine's answered port within a few 20 ms frames, with the engine's own
  SSRC.
- Watch the control connection for `active_speaker` when the louder party starts talking, and
  `call_quality` every ~5 s per seat.
- Leave with both tags and confirm `siphon_rtp_conference_rooms` drops back to 0.
