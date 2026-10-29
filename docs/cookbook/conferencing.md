# Conferencing (MCU)

siphon-rtp ships a built-in N-party audio conference: a clock-driven mixer (MCU) that seats up to
64 participants per room, mixes them every 20 ms, and hands each participant its own
mixed-minus-self stream. You drive it with native-JSON control verbs: `conference_join` (a
participant calls in), `conference_offer` and `conference_answer` (the room calls a participant
out), `conference_leave`, `conference_route`, and `conference_bridge` / `conference_unbridge`.

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

Two things keep a codec from being seated. Its decoder and encoder must agree on sample rate,
packetization interval, and channel count: the room works in one frame length per participant, and a
mismatched pair would hand its encoder a wrong-length frame every tick. And its interval must be at
most 120 ms — the interval sizes the leg's ingress carry, its egress accumulator, and its playout
queue, so an unbounded `a=ptime` would buy a peer arbitrary per-participant buffering. A codec that
fails either is passed over for the next one offered (see [Which codec a seat
gets](#which-codec-a-seat-gets)).

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
  has to encode the mix back. G.711, G.722, G.726, GSM-FR, L16 and Opus always are. AMR-WB and
  AMR-NB need the `amr` Cargo feature (off by default, see [codec licensing](../codec-licensing.md))
  and G.729 the `g729` one; without the feature that codec is passed over, and a join that offered
  nothing else is refused. With `amr`, an AMR seat's mix is encoded in the payload format and
  `mode-set` it offered.
- 64 participants per room, hard cap (the active-speaker set is a u64 bitmask).
- A node in drain mode rejects `conference_join` and `conference_offer` like it rejects `offer`.
  An offer made before the drain can still be answered.

### Which codec a seat gets

The room picks the participant's codec the way `answer_local` picks a single leg's: the offer's own
audio codecs, in offer order, after the profile's codec flags (`codec-strip-X`, `codec-mask-X`,
`codec-consume-X` remove X, `codec-except-X` / `codec-accept-X` keep only the listed codecs,
`codec-offer-X` moves X to the front). The first one the engine can decode, encode and hold in the
room is taken. A VoLTE terminal that offers EVS, AMR-WB and AMR is seated in AMR-WB on a build with
`amr`. The answer names that one codec with the payload type and `a=fmtp` it was offered under
(for AMR, the payload format and `mode-set` as offered), and telephone-event at the same clock rate
when the offer carries one.

A join is answered `ok` only once the room has seated the participant. Otherwise it is an error
that says why, before any media is set up:

| Refusal | `reason` |
|---|---|
| No offered codec qualifies | `conference_join: no offered codec can be seated: <codec>/<rate> payload type <n>: <why>; ...`, every offered codec named with why it was not taken (no decoder or encoder in this build, withheld by the profile's codec flags, or the room cannot hold its frame) |
| The from-tag is already seated | `conference_join: from-tag <tag> is already seated in this room` |
| The room holds 64 seats | `conference_join: the room is full (64 seats)` |
| The room did not answer within 1 s | `conference_join: the room did not seat the participant within 1000 ms` |
| The from-tag has an offered seat awaiting its answer | `conference_join: from-tag <tag> has a conference_offer awaiting its answer` |

Every participant endpoint is a full inbound surface, so the same RTPBleed defence as the relay
applies: ingress is gated to the SDP-signalled source address (or opened with the `symmetric`
profile flag), the reply address is latched only from a gated source, and a packet from anywhere
else never enters the mix. See [Security & NAT](../security-and-nat.md).

RFC 4733 telephone-events are filtered out of the mix (DTMF would mangle the audio) and surfaced
as `dtmf` events on the control channel instead.

## Joining a room

Rooms are created lazily: the first `conference_join` for a `conference_id` creates it, the last
`conference_leave` tears it down. The participant offers SDP; the engine answers with its own
endpoint, the one codec the seat was given, sendrecv. Frames on the control channel are a big-endian u32
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
automatically, and a room left empty is torn down, so an abandoned leg never leaks a room. The
client whose join seated the participant is told: a `media_timeout` with an empty `call_id`, the
room's `conference_id`, and the seat's tag in `from_tag`. (A leg seated with `conference_seat` is
the exception: see below.)

## Calling a participant out

`conference_join` answers a participant who called the room. When the room calls someone instead
(RFC 4579 §5.5: a REFER to the focus naming the user, or 3GPP TS 24.605 CONF's ad-hoc conference),
the focus sends the INVITE, so it needs an **offer** from the engine rather than an answer. That is
two verbs. `conference_offer` allocates the seat's endpoint and returns the offer:

```json
{ "id": 7, "command": "conference_offer", "conference_id": "room-1", "from_tag": "carol",
  "role": { "role": "talker" } }
```

```json
{ "id": 7, "result": "ok", "to_tag": "carol",
  "sdp": "v=0\r\no=- 3141592653 1 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\nt=0 0\r\nm=audio 30212 RTP/AVP 111 9 0 8 102 3 110 101\r\na=rtpmap:111 OPUS/48000/2\r\n... a=sendrecv\r\na=rtcp-mux\r\n" }
```

Put that SDP in the INVITE. When the participant answers, hand the engine its answer:

```json
{ "id": 8, "command": "conference_answer", "conference_id": "room-1", "from_tag": "carol",
  "sdp": "v=0\r\no=- 7 1 IN IP4 198.51.100.30\r\ns=-\r\nc=IN IP4 198.51.100.30\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n" }
```

```json
{ "id": 8, "result": "ok" }
```

From here the seat is exactly a joined one: same source gate and latch, same roles, same events,
left with `conference_leave`. The room is created on its first seat, whichever verb seated it.

What the offer contains:

- One `RTP/AVP` audio stream, `a=sendrecv`, `a=rtcp-mux` (a seat is one muxed endpoint, and the room
  sends its RTCP there whatever the answer says), `a=ptime:20` and `a=maxptime:120`.
- Every codec this build can seat, widest band first: Opus (111), AMR-WB (96 bandwidth-efficient, 97
  octet-aligned) with `amr`, G.722 (9), AMR (98, 99) with `amr`, PCMU (0), PCMA (8), G.729 (18) with
  `g729`, G.726-32 (102), GSM (3). It is the same test a join's codec passes, so nothing is offered
  that the answer could then fail to seat in. The profile's codec flags edit the list with the rules
  a join uses (`codec-strip-X` / `codec-mask-X` remove, `codec-except-X` keeps only, `codec-offer-X`
  moves to the front).
- telephone-event once per clock rate the codecs use: 101 at 8 kHz, 100 at 16 kHz, 110 at 48 kHz.
- The near `direction` interface, IPv4 unless `profile.address_family` is `IP6` (there is no peer
  address yet to take the family from).

What the answer has to be. The seat's codec is the answer's **first** audio format (RFC 3264 §6.1),
and it must be a payload type the offer listed, under the same encoding and clock rate (and, for
AMR, the same `octet-align`). Its telephone-event is used when it is one the offer listed. An
`a=recvonly` or `a=inactive` answer seats the participant held, so the idle sweep does not reap its
silence. A refused answer frees the seat's port:

| Refusal | `reason` |
|---|---|
| No offer is pending for the tag | `conference_answer: no conference_offer for from-tag <tag> awaits an answer in this room` |
| The first audio format was not offered | `conference_answer: the answer chose payload type <n>, which was not offered` |
| The audio stream was rejected | `conference_answer: the answer rejected the audio stream (port 0)` |
| The answer is `RTP/SAVP` or DTLS | `conference_answer: the answer is secure, but the offer was RTP/AVP` |
| The room refuses the seat | as for `conference_join`, under `conference_answer:` |

Limits of an offered seat: it is plain RTP only. SDES and DTLS-SRTP keying and ICE are built around
answering a peer's offer, so a `conference_offer` whose profile asks for them (`transport_protocol`
other than `RTP/AVP`, `dtls` other than `off`, `ice: force`) is refused rather than offered without
anything behind it. A secure or WebRTC participant has to call in with `conference_join`. The offered
seat carries no RFC 9071 text stream either.

A seat that is offered and never answered is not in the room and holds only its port. It ends with
`conference_leave`, or expires on the sweep after `--setup-timeout-secs` (the ceiling an offered
call awaiting its answer gets; the media timeout bounds it when the setup timeout is `0`). A second
`conference_offer` for a tag already pending or seated is refused, and so is a `conference_join` for
a tag whose offer is pending.

## Seating a live call's leg

The two verbs above both bring a party in with a fresh endpoint and an SDP exchange. A three-way
call starts from two calls that are already up: a subscriber talks to X, holds, calls Y, and
merges. X and Y are each anchored on an engine endpoint they already send to; seating either through
`conference_join` or `conference_offer` would mean re-INVITEing them to move their media a few ports
along on the same host. `conference_seat` seats the leg where it stands instead:

```json
{ "id": 9, "command": "conference_seat", "call_id": "c-x@example.com", "from_tag": "x-tag",
  "conference_id": "merge-1", "role": { "role": "talker" } }
```

```json
{ "id": 9, "result": "ok" }
```

`from_tag` names the leg by its tag in the call (the call's `from_tag` or `to_tag`) and is the
seat's tag in the room. The leg keeps everything the far party was told: the engine endpoint (same
local address and port), the latched peer, the negotiated codec and payload types, its SDES-SRTP
contexts (rollover and replay state included) or its DTLS association (the handshake is not
repeated), and its ICE pair. No SDP is exchanged and the reply carries none. A leg relayed in the
kernel (or by XDP) is moved onto the decoding path by the same command; nothing has to be promoted
first. The frame's `scope` applies as it does to every verb naming a `call_id`.

The leg's former peer in that call — the subscriber's leg — is released by the same command, its
endpoint freed. You are ending that dialog anyway, and a half-call left allocated would hold a port
pair until it timed out. The order matters: the seat goes in first, and only then is the peer
released, so a refusal never drops the call.

```
subscriber ──(call X)── engine ──── X        subscriber ── (both dialogs ended)
subscriber ──(call Y)── engine ──── Y   =>   room merge-1: X, Y (+ the subscriber's own join)
```

Merging, end to end: `conference_seat` the X leg of the first call and the Y leg of the second,
then bring the subscriber in with `conference_join` (or `conference_offer`) on a new dialog. All
three hear each other mixed-minus-self.

### What the far party sees

The room originates its own stream toward each seat, so the far party sees a new SSRC, sequence and
timestamp base with no signalling, which RFC 3550 §8 permits. The engine makes the change as easy
to follow as it can: the first packet of the mix carries the marker bit (§5.1), and, where the leg
carries RTCP and the engine knows the SSRC of the stream it had been relaying to the party, an RTCP
`BYE` for that SSRC goes out first (§6.3.7). The SSRC is known for a userspace leg and for the
loopback datapath's relay; the XDP kernel latch does not report it, so a leg moved off the XDP relay
gets no `BYE`. Some border controllers latch on SSRC: that is a property of the far end and has to
be measured per carrier, not assumed.

### Refusals

A refusal leaves the call relaying exactly as it was:

| Refusal | `reason` contains |
|---|---|
| The leg's codec has no encoder (or decoder) in this build | `conference_seat: <codec> payload type <n>: no encoder: …` |
| Decoder and encoder disagree on rate, interval or channels | `the room cannot hold it: decoder (…) and encoder (…) disagree` |
| Packetization interval over 120 ms | `packetization interval <n> ms is outside 1..=120 ms` |
| The room is full | `the room is full (64 seats)` |
| The tag is already seated in the room | `from-tag <tag> is already seated in this room` |
| The node is draining | `node is draining; not accepting new sessions` |
| The call is unanswered, single-leg, a WebSocket takeover, `fax_passthrough`, or carries text or fax | named in the reason |
| The call's SRTP runs end to end and the engine holds no key | `the engine holds no key to decrypt the leg` |
| A DTLS leg whose handshake has not completed | `the leg's DTLS-SRTP handshake has not completed` |
| A pcap recording, WebSocket tee or bridge, interception, subscription, DTMF block or echo mode is attached | `<feature> is attached to the call; stop it first`, naming it |

### The call while it is seated

The call stays in the registry with the seated leg as its one leg, so your view of it holds:

- `delete` takes the seat out of the room, frees the endpoint, and returns the same `call_summary` a
  call always returns. Its packet and byte counts are the endpoint's own, so they span the time
  before and after the move. `siphon_rtp_conference_participants` drops by one.
- Events the seat raises name the call: `dtmf`, `call_quality` and `media_started` carry the
  original `call_id` and `from_tag`, with `conference_id` beside them, and go to the client that owns
  the call.
- `silence_media` gives the seat encoded silence instead of the mix; `block_media` stops the room
  sending it anything (the egress clock keeps running, so it resumes cleanly). Both are undone by
  their reverses.
- `play_media` plays to that seat alone, at its own rate: a plain prompt replaces the mix while it
  plays (a newer one supersedes it), an `overlay` mixes under it. `stop_media` and `set_play_gain`
  work by `play_id`, and each prompt ends with a `play_finished` naming the call, as on a call.
- Recording. A decoded (`wav` or `ogg_opus`) recording that was running on the call when it was
  seated **carries over**: the same `recording_id`, the same file, no gap and no second file. It goes
  on recording that leg's party — what it says, and what the room sends it — so a stereo file stays
  caller-left / callee-right, with the party on its own side and the room's mix on the other.
  `start_recording` on a seated call records the seat the same way (the party left, what it hears
  right). `recording_finished` fires once, when the recording is stopped or the call deleted, with a
  duration spanning the move. A pcap recording is the exception: a seat's packets are the room's, so
  it refuses the seat (and `start_recording` with `pcap` on a seated call).
- Room-wide playback and recording stay on the `conference_*` verbs; the other call verbs are
  refused with a reason naming the room.
- A seated leg that goes silent raises `media_timeout` **for its call**, with the room's
  `conference_id`, under the same reasons and budgets a two-party leg has, measured on that leg's own
  ingress (and on consent or ICE failure, as for a call). The engine does **not** free it: end the
  dialog, then `delete` the call. It is reported once per silence; fresh media re-arms it. The
  room's own idle reap leaves it alone.

### Leaving

`conference_leave` on a seated leg does not free it. The leg goes back to its call as a one-legged
call on the same endpoint, relaying nothing (its media is dropped and counted, and it is judged by
the media-timeout sweep like any call). It keeps its SRTP contexts and DTLS association, so it can
be seated again with `conference_seat`, or deleted. A recording running on it keeps going: the file
stays open (gaining nothing while the leg relays nothing), carries on from the new seat when the leg
is seated again, and ends when it is stopped or the call is deleted. Pairing it back to a new far party (turning the
room back into an ordinary call) has no verb yet.

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

`conference_unbridge` undoes it, in both directions whichever way the bridge was made, and in
either order of the two ids:

```json
{ "id": 9, "command": "conference_unbridge", "conference_id_a": "room-2",
  "conference_id_b": "room-1" }
```

Each room stops hearing the other and returns to the rate its own membership calls for. Unbridging
two rooms that are not bridged, or naming a room that does not exist, is an error
(`conference_unbridge: the two conferences are not bridged`, `conference_unbridge: unknown
conference: <id>`). A bridge also ends when either room is torn down: the surviving room drops it
the same way.

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

One event per completed RFC 4733 key press. For a joined participant the conference id arrives in
the `call_id` field, the same shape as two-party DTMF events, and again in `conference_id`. For a leg
seated with `conference_seat`, `call_id` and `from_tag` are its call's own, with `conference_id`
beside them.

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
  track live rooms and seats; `siphon_rtp_conference_joins_total`, `_offers_total`,
  `_answers_total` and `_leaves_total` count the verbs. See [Monitoring & QoS](monitoring.md).
- Join two G.711 legs as talkers and send audio into one: the other's socket receives a mixed
  RTP stream from the engine's answered port within a few 20 ms frames, with the engine's own
  SSRC.
- Watch the control connection for `active_speaker` when the louder party starts talking, and
  `call_quality` every ~5 s per seat.
- Leave with both tags and confirm `siphon_rtp_conference_rooms` drops back to 0.


## Playing audio into a room

A PBX conference announces joins and leaves, plays music to a lone participant, and says
"this conference is being recorded". None of that is any participant's audio, so it goes in
as a **non-participant source**: everyone hears it, and nobody is mixed-minus-self against
it, which is what stops it being treated as somebody's own voice and subtracted back out.

`play_media` cannot do this — it resolves through the call registry, which a conference never
enters, so a room id answers `unknown call`. Use `conference_play`:

```json
{
  "id": 50,
  "command": "conference_play",
  "conference_id": "bridge-4412",
  "source": {"source": "tone", "tone": "425/200,0/200*2"},
  "gain_decibels": -6
}
```

```json
{"id": 50, "result": "ok", "play_id": 12, "duration_ms": 800}
```

Up to four run at once, each with its own `play_id`, and each ends with its own
`play_finished` — carrying `conference_id`, with `call_id` empty, because a room playback is
not on a call:

```json
{"event": "play_finished", "call_id": "", "conference_id": "bridge-4412", "from_tag": "", "play_id": 12, "reason": "completed", "played_ms": 800}
```

`conference_set_play_gain` retunes a running one (how an announcement ducks under a
conversation rather than burying it) and `conference_stop_play` ends it — by `play_id`, or
all of them when none is given.

**Rate changes are handled for you.** A room mixes at 8 kHz while everyone is narrowband and
moves to 16 kHz when a wideband participant joins or the room is bridged. A playback keeps
rendering at the rate it started at and the room converts, so an announcement is never cut
off mid-word because somebody joined.

## Recording a room

```json
{
  "id": 51,
  "command": "conference_start_recording",
  "conference_id": "bridge-4412",
  "recording_dir": "/var/spool/conferences",
  "max_duration_ms": 7200000
}
```

```json
{"id": 51, "result": "ok", "recording_id": "rec-3"}
```

This records the **listener mix** — what a listener actually hears, including any bridged
room and any room playback — which is the useful definition of "record the conference". (The
participant-only mix, which feeds a bridge, deliberately excludes bridged audio so a bridge
cannot echo a room back to itself.)

It is the same streaming writer a call recording uses, so it produces the same file and the
same completion event, and the same rule applies: **only act on the file when the event
arrives**, because that is emitted after the WAV header is finalized and flushed.

```json
{"event": "recording_finished", "call_id": "", "conference_id": "bridge-4412", "recording_id": "rec-3", "path": "/var/spool/conferences/bridge-4412-rec-3.wav", "duration_ms": 1830000, "reason": "stopped"}
```

The file is pinned to 16 kHz for its lifetime. A room that starts narrowband and goes
wideband mid-recording would otherwise change sample rate inside one WAV, which no player
handles; the room converts into the recording's rate instead.
