# Forwarding rooms (push-to-talk)

A forwarding room is the group-call counterpart of the [mixing conference](conferencing.md). A
push-to-talk call (3GPP TS 24.379) has one talker at a time, so the room does not decode, mix or
encode: it takes the RTP of the one seat you choose and hands it, payload unchanged, to every other
seat. There is no jitter buffer and no 20 ms tick for media. A packet is forwarded when it arrives.

Each receiving seat has its own RTP translator (RFC 3550 §7). Whoever talks, a receiver sees one
stream: a fixed SSRC chosen by the engine, sequence numbers and timestamps that carry on across talker
changes, and the marker bit on the first packet after each change (RFC 3550 §5.1, a talk spurt
start). The talker's own SSRC and CSRCs never reach a receiver.

The verbs exist on the native JSON control channel only, and take no `scope`: put the function in the
`conference_id`. A room id names a forwarding room or a mixing conference, never both.

## The verbs

| Verb | What it does |
|---|---|
| `forward_join` | Seat a member (creating the room on the first join) and answer its SDP |
| `forward_offer` | Dial a member out: offer it a seat, pending until it answers |
| `forward_answer` | Seat the member that answered a `forward_offer` |
| `forward_set_source` | Choose whose audio is forwarded: a `from_tag`, or none |
| `forward_leave` | Unseat a member (or drop its unanswered offer); the room ends with its last member |

```json
{"id":1,"command":"forward_join","conference_id":"group-1","from_tag":"a7c31f","sdp":"v=0\r\n..."}
{"id":2,"command":"forward_join","conference_id":"group-1","from_tag":"b19e02","sdp":"v=0\r\n..."}
{"id":3,"command":"forward_set_source","conference_id":"group-1","from_tag":"a7c31f"}
{"id":4,"command":"forward_set_source","conference_id":"group-1"}
{"id":5,"command":"forward_leave","conference_id":"group-1","from_tag":"b19e02"}
```

`forward_set_source` takes effect on the next packet the room receives. The client that sent it gets
one `forward_source_started` (`conference_id`, `from_tag`) per change, when the new source's first
packet has actually been forwarded. A `from_tag` no seat has is an error. Packets from a seat that is
not the source are counted in that seat's endpoint `packets_dropped` and dropped; the source never
hears itself. If the source leaves, nothing is forwarded until the next `forward_set_source`.

Check `node_info` `features` for `forward_room` first (`forward_dialout` for the offer and answer verbs,
`forward_transcode` for mixed-codec rooms). A draining node refuses `forward_join` and `forward_offer`.

## Dialling a member out

`forward_join` answers a member who called the room. A group call also fans out the other way: the
controller INVITEs each member, so the engine is the offerer (RFC 3264 §5). `forward_offer` allocates
the seat's endpoints and returns the SDP offer; `forward_answer` takes the member's answer and seats it
exactly as `forward_join` would have.

```json
{"id":1,"command":"forward_offer","conference_id":"group-1","from_tag":"b19e02",
 "profile":{"floor_fmtp":"mc_queueing;mc_priority=5;mc_granted"}}
{"id":2,"command":"forward_answer","conference_id":"group-1","from_tag":"b19e02","sdp":"v=0\r\n...",
 "received_from":"203.0.113.9"}
```

The offer is plain `RTP/AVP`, `a=sendrecv`, `a=rtcp-mux`. When the room exists it lists the room's
codec first, with its format parameters (AMR `octet-align` and `mode-set`, G.729 `annexb`), then every
codec the engine can transcode to and from it, then telephone-event per clock rate. When the room does
not exist yet the first seat fixes the codec, so the offer lists every codec a room could carry, widest
band first, edited by the profile's codec flags; AMR and G.729 are listed on any build because
forwarding needs no codec. With `profile.floor_fmtp` the offer carries an anchored
`m=application <port> udp MCPTT` section with `a=fmtp:MCPTT <floor_fmtp>` verbatim, wired like the floor
stream of a `forward_join`: an answer that accepts it (a port) gives the seat a floor stream, port 0
leaves an audio-only seat.

Until it is answered the seat is **pending**: it holds its endpoints but is not in the room, so nothing
is forwarded to or from it. A pending seat ends one of four ways, each freeing its endpoints: answered
(and seated, or refused), `forward_leave`, a refused answer, or the setup-timeout sweep
(`--setup-timeout-secs`, else `--media-timeout-secs`). The answer's first audio format must be one the
offer listed. SDES, DTLS-SRTP and ICE are not offered (`conference_offer` does not either); a profile
asking for them is refused. An id that names a mixing conference is refused, as `conference_offer`
refuses an id that names a forwarding room.

## The codec rule

The first seat fixes the room's codec: the first codec in its offer (RFC 3264 order, after the
profile's codec flags) that the room can carry. A later seat must offer that codec, and is answered
with **its own** payload type for it. "That codec" means the same payload format:

* the same encoding name, clock rate and channel count;
* for AMR and AMR-WB the same `octet-align`. Bandwidth-efficient and octet-aligned payloads put the
  same frames in different bits (RFC 4867 §4.4), so copying one to a seat expecting the other
  delivers garbage. An absent `octet-align` is bandwidth-efficient;
* for G.729 the same `annexb` (RFC 3555 §4.1.13).

The AMR `mode-set` is the room's (the first seat's). A later seat is answered with it (RFC 4867
§8.3.1), so a seat whose own offer excludes a mode the room may send is refused.

A seat that offers another codec is not refused any more: the room **transcodes** for it when the
engine has a decoder and an encoder for both its codec and the room's, and the seat's packetization
interval is the room's (see below). A seat the room can neither forward to nor transcode for is refused
with a reason that names the room's codec and why each offered codec failed, for example
`the room carries AMR-WB/16000 (octet-aligned) and the seat does not offer it: ...; and it cannot be
transcoded to: PCMU/8000 payload type 0: this build lacks AMR transcoding (built without the amr
feature)`. A seat that offers the room's codec as it is always wins over a transcode, whatever the
offer's order, because forwarding it costs nothing.

The room needs no encoder or decoder for its codec, so a codec this build cannot transcode forwards
fine. AMR-WB works without the `amr` feature. Transcoding AMR needs it (patent-licensed, see
`docs/codec-licensing.md`); a build without it forwards an AMR room and refuses a seat in another codec,
saying so.

RFC 4733 telephone-event is forwarded from the source to a receiver that negotiated it at the same
clock rate, under the receiver's own payload type. A receiver that did not is not sent it, which
leaves a gap in that receiver's sequence numbers where the event packets were.

## Seats in another codec

Same-codec seats keep the zero-copy path above, unchanged. A seat in another codec (a PCMU or Opus
member in an AMR-WB room, say) is handled by the room's transcoder, which is built when the first such
seat arrives:

* **Decode once.** The source's packet is decoded once per inbound packet, however many seats need it,
  by one decoder per room. A decoder's state belongs to one stream, so it is rebuilt when the source
  changes.
* **Encode once per codec group.** Seats that share a codec, clock rate, packetization interval and
  payload format parameters form a group, and their payload is byte-identical, so the group's one
  encoder output serves them all. Between the decoder and each group the audio is resampled when the
  rates differ (the same resampler the mixing conference uses). An encoder is shared by its group and
  carries on across a source change.
* **Packetize per seat.** Each seat is sent that payload through its own translator, so it gets its own
  SSRC, sequence numbers and timestamps (on its own codec's RTP clock, RFC 3551 §4.5), a marker on the
  first packet after a source change, and its own payload type.
* **A cross-codec source** is decoded, resampled to the room codec's rate, encoded once in the room
  codec and forwarded to the room-codec seats as if it were a room-codec source. A seat in the source's
  own codec group is sent its packet as it arrived: nothing to transcode. Other groups get the decoded
  audio encoded for them.
* **Telephone-event** reaches every receiver that negotiated it, under its own payload type, with
  timestamps and durations rescaled when its clock differs from the source's (RFC 4733 §2.3). A receiver
  that did not negotiate it is not sent it.

### Lost source packets

Inside one source run the room follows the RTP sequence numbers (RFC 3550 §5.1). When up to 120 ms of
consecutive audio packets are missing and the timestamp advanced by exactly the missing frames, the
decoder fed by the source conceals one frame per missing packet and every transcoded receiver is sent
it, so it hears a concealed frame instead of a gap, with sequence numbers and timestamps continuous on
its own stream. The concealed frame is encoded once per group, like a packet. For a cross-codec source
the room-codec seats are sent it too, because the stream they hear is the transcoder's.

* G.711 conceals with ITU-T G.711 Appendix I: the last pitch period is replayed, at full level for 10 ms,
  then faded by 20 % per 10 ms and muted after 60 ms, and the first good frame is cross-faded in. (The
  Appendix delays its output by 3.75 ms to smooth the start; a relay cannot hold samples back, so the
  start is joined with a fading offset instead.) AMR-WB and Opus use their own concealment.
* **AMR-NB has no concealment** (3GPP TS 26.091 is not ported): its concealed frame is silence.
* A seat that is sent the source's packets as they came is not given a synthesized frame: it sees the
  gap, as a same-codec seat always did, and its own decoder conceals. The same goes for a gap longer than
  120 ms, a talk-spurt start (marker bit) and a silence-suppression gap (the timestamps advanced by more
  than the missing frames); those are left as they are. Late and duplicate packets are not concealed
  around.
* Counted in the transcoder's `concealed` and `conceal_failed`.

### Codec mode requests

A cross-codec AMR or AMR-WB seat's Codec Mode Request (RFC 4867 §4.3.1) is read from the payloads the seat
itself sends, whether or not it is talking, and caps the mode the room encodes for it: CMR 15 withdraws
the request, and a request for a mode outside the seat's negotiated `mode-set` is ignored (§4.3.1), so a
mode the seat did not negotiate is never sent (§8.1). Codec groups are keyed by codec **and** mode
ceiling: seats with the same request share an encoder, a seat whose request changes moves to the group of
its new ceiling (created on demand), and a group its last seat left is dropped. Each group costs one
encode per packet, so a room whose seats ask for `n` different modes pays `n` encodes. A new group's
encoder starts without history, so the seat hears one short re-convergence when its request changes.

A seat that asked for nothing, in the same codec as the talker, is still sent the talker's packets as
they came and so cannot be steered: their mode is the talker's. A seat that asked for a ceiling is
re-encoded instead. Codecs without a mode request (G.711, Opus and the rest) have nothing to read.

Limits, all explicit: the seat's packetization interval must equal the room's, so one inbound packet
maps to one outbound packet (a seat offering another interval is refused with the reason, and a packet
whose decoded length is not the negotiated frame is dropped and counted in the source's
`transcode_dropped`, never re-framed: the room has no jitter buffer). The DSP is a few microseconds per
frame and runs inline; nothing is allocated per packet, concealment included (a counting-allocator test
holds that), except that rebuilding the decoder at a source change allocates once per talk spurt.

## RTCP

A seat's RTCP is consumed (Sender Report to LSR/DLSR, reception report blocks to round-trip time) and
never forwarded. Every 5 s the room sends each seat a Sender Report about the stream that seat
receives: its fixed SSRC, the translator's packet and octet counts, and an RTP timestamp on the same
line as the packets, so the NTP to RTP mapping is consistent. A seat that has sent the room RTP also
gets a reception report block about it (loss, jitter, LSR and DLSR). RTCP APP packets are not
relayed either: they go to the controller, see [Floor control](#floor-control-mcptt).

## Floor control (MCPTT)

Floor control (3GPP TS 24.380) is the controller's: the engine carries the messages and decides
nothing. A seat that offers `m=application <port> udp MCPTT` gets that stream anchored on its own
engine port, answered with the same transport and format and with the parameters you pass in
`profile.floor_fmtp`:

```json
{"command":"forward_join","conference_id":"group-1","from_tag":"a7c31f","sdp":"...",
 "profile":{"floor_fmtp":"mc_queueing;mc_priority=5;mc_granted"}}
```

The answer carries `m=application 30002 udp MCPTT` and `a=fmtp:MCPTT mc_queueing;mc_priority=5;mc_granted`,
exactly as given. The offerer's own `a=fmtp:MCPTT` is not echoed (TS 24.380 §14.3.1 says an answer
states the answerer's capabilities, and must not add parameters the offer lacked: declare only what you
may). Without `floor_fmtp` the section is answered with no fmtp line. A value with a CR or LF is
refused, and the join with it. Any other stream the engine does not carry is declined with port 0,
including a second floor section.

**Receiving.** Every RTCP APP packet that arrives on the floor stream, or inside a seat's audio RTCP,
reaches the controller that seated it as one `rtcp_app` event, in arrival order per seat. Two APP
packets in one datagram (TS 24.380 §8.1.1) are two events. `stream` says which stream it arrived on;
a datagram the engine cannot read is counted and dropped, with no event.

```json
{"event":"rtcp_app","conference_id":"group-1","from_tag":"a7c31f","stream":"floor",
 "ssrc":287454020,"name":"MCPT","subtype":0,"payload":"AAIFAA=="}
```

`rtcp_app` events have a queue of their own (4096 per controller). If a controller stops reading and
it fills, the oldest event is dropped, logged at `error` and counted in
`statistics.rtcp_app_dropped_total`; alert on any increase.

**Sending.** `send_rtcp_app` with `conference_id` and `from_tag` sends to one seat; without `from_tag`
it sends to every seat that has the stream, except those in `except_from_tags` (the talker, for a Floor
Taken):

```json
{"command":"send_rtcp_app","conference_id":"group-1","stream":"floor","except_from_tags":["a7c31f"],
 "name":"MCPT","subtype":17,"payload":"AQIAHg4GEjRWeAAA"}
```

`ok` comes back after the datapath has taken the datagram for every addressed seat. If a seat could
not be sent to (no floor stream, the seat's path not open yet, a send failure) the answer is an error
naming each such seat as `tag (reason)`; the others were still sent. `name` is four ASCII characters,
`subtype` at most 31 (the TS 24.380 acknowledgement bit is the top of the five), and `payload` a
multiple of four bytes, which the engine does not pad. With no `ssrc` the packet carries the engine's
SSRC toward that seat, the same SSRC the seat's forwarded RTP is announced under; pass `ssrc` to
use another (TS 24.380 §8.1.2 wants the SSRC the receiving party learnt at session establishment).
`stream: "audio"` sends on the seat's audio endpoint (SRTCP-protected on a secure seat) instead.

The floor stream is plain in this build: media control security (TS 24.380 §13) is not negotiated.

### A browser dispatcher

A browser cannot send RTCP APP, so a web dispatcher console runs the same floor control over a WebRTC
data channel. TS 24.380 defines no WebRTC binding: **the convention is ours.** Offer audio and a data
channel in one BUNDLE group, DTLS-SRTP on both (what every browser does by default):

```
a=group:BUNDLE 0 1
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=mid:0
...
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
a=mid:1
a=sctp-port:5000
```

`forward_join` answers the second section on the audio's own port with `a=sctp-port:5000` and
`a=max-message-size:65536`. In the page, **open a channel labelled `mcptt-floor`** once the connection is
up (the engine opens none):

```js
const floor = pc.createDataChannel("mcptt-floor");
floor.binaryType = "arraybuffer";
floor.onopen = () => floor.send(floorRequest);   // 16 bytes: 80 CC 00 03 .. 4D 43 50 54 00 02 05 00
floor.onmessage = (event) => handle(new Uint8Array(event.data));
```

Each message is one complete RTCP APP packet, 12-byte header included, in a **binary** message; a string
message is dropped. You get the same `rtcp_app` events (`stream: "floor"`, `conference_id`, `from_tag`)
as from a phone, and answer with the same `send_rtcp_app` (`stream: "floor"`). `send_rtcp_app` to the
browser is an error until it has opened `mcptt-floor`, so wait for your own `onopen`. Check
`node_info` `features` for `webrtc_floor_channel` first.

The browser's audio is Opus (or whatever it negotiated) and crosses codecs like any other seat's; an
Opus seat in an AMR-WB room needs a build with the `amr` feature. The two-party `offer` / `answer` pair
answers the channel for a browser caller toward a plain callee (see the JSON reference). There is no headless browser in this repository: acceptance in a real
browser is yours to run against a controller.

### Two-party calls

A two-party call carries the same stream. When the offerer's SDP has `m=application <port> udp MCPTT`,
`offer` gives each side an engine endpoint for it: the offer B receives carries the far endpoint with
`a=fmtp:MCPTT <profile.floor_fmtp>`, and when B answers with its own floor section the answer A receives
carries the near endpoint, with the `floor_fmtp` of the `answer` command. `answer_local` terminates it
on its one leg. If B answers without a floor section, A's is declined and nothing is served.

The engine **terminates** the stream on each side; it is not relayed. What a party sends arrives as
`rtcp_app` with `call_id` and the `from_tag` of that leg (the call's from-tag for the offerer, the
to-tag for the answerer), and `send_rtcp_app` with `call_id` and a `from_tag` sends to that leg. The
SSRC an unnamed send carries is minted per leg when the call is answered and stays the same.

The floor endpoints are `Redirect`, so this works whatever carries the call's audio. Limits, all
explicit: a re-offer keeps the endpoints and their addresses, and a floor stream added to a call that
had none is declined; a call with a floor stream cannot be checkpointed (`checkpoint` says so); and
APP packets in a party's *audio* RTCP are reported only where the userspace pipeline terminates that
RTCP (a transcoding or recording call), where the compound is still relayed to the other party as
before, never on the plain in-kernel relay.

## Inactivity

A forwarding seat is **never freed for silence** on its own. A listener sends nothing for as long as others
talk, and an RTCP keepalive is optional. Liveness is any accepted RTP or RTCP datagram on the seat's
endpoint. When a seat has been quiet past `--media-timeout-secs`, the sweep sends `forward_seat_inactive`
(`conference_id`, `from_tag`) to the client that seated it, once. The seat stays seated. It is
reported again only after it has been heard from in between. What to do about it is the controller's
call: `forward_leave` frees it.

### The room backstop

A room nobody ended (a controller that crashed, an operator that forgot) must not hold its sockets
forever. `--forward-room-idle-secs` (default 3600, `0` disables) frees a room in which **every** seat
has received nothing at all, no RTP, RTCP or floor packet, for that long. Each seat is reported to the
client that seated it as a `media_timeout` (`no_media`, empty `call_id`, `conference_id` the room, one
event per seat), then the room and every endpoint are freed. A live group cannot trip it: receivers send
RTCP receiver reports (RFC 3550 §6.2), so a room that has heard from none of them for an hour has no
members left. Seats pending their answer are not counted, and a single seat is still never reaped.

## Security and NAT

A dialled-out seat is gated by its answer's signalled source (or `received_from`) and is not offered
SRTP or ICE. A forwarding seat is gated exactly like a conference seat, because the same code gates both: the
source must be the signalled one (or the `received-from` hint, or any source for an ICE or
`symmetric` seat), media from a DTLS seat before its handshake or an ICE seat before its pair is
selected is dropped, SRTP is checked before anything else, and the reply address follows the
constrained SSRC latch. A secure receiver is sent SRTP under its own key. A cross-codec seat is gated
by the same chain; only after the gate does its payload reach a decoder, so an unsigned source never
feeds one. See
[Layer 5c-ii of the security model](../security-and-nat.md). The floor stream is gated the same way
but learns its reply address once and never moves it (there is no SSRC to prove a rebind): Layer 5h.

## How far it goes

The room is one actor. One inbound packet costs one translator rewrite per receiving seat, written
into scratch buffers the room owns: nothing is allocated per packet (a counting-allocator test holds
that at zero). The cap is 1000 seats per room.

Measured with `cargo bench -p siphon-rtp --bench forward_fanout_bench` (release build, one core, no
sockets, a 62-octet AMR-WB payload; the per-datagram `send` is not in these figures):

| Seats | Per inbound packet | Per forwarded packet |
|---|---|---|
| 10 | 196 ns | 22 ns |
| 100 | 1.74 us | 17.5 ns |
| 500 | 8.86 us | 17.8 ns |
| 1000 | 17.8 us | 17.9 ns |

At 50 packets per second (20 ms frames) a 1000-seat room spends under 1 ms of CPU per second in the
fan-out itself. The cost that grows with the room is the datagram send, one per receiver per packet,
which the actor does one after another.

End to end on the UDP-loopback datapath (`tests/forward_500_seats.rs`, release build): 500 phones
seated, one talking for 50 frames at 20 ms. Every one of the 499 listeners received all 50 frames,
24,950 datagrams, byte for byte, in 0.98 s: the talk ran at the pace of the source, with nothing
queued behind it.

## Mixed-codec fan-out cost

`cargo bench -p siphon-rtp --bench forward_transcode_bench` (release build, one core, no sockets): a
100-seat room with one PCMU seat (the room codec), 50 PCMA seats and 49 Opus seats, one 20 ms frame in.

| Source | Per inbound packet | Per forwarded packet |
|---|---|---|
| PCMU (the room codec) | 174 us | 1.76 us |
| PCMA (a cross-codec seat) | 170 us | 1.72 us |

At 50 packets per second that is under 1% of one core, against about 18 ns per forwarded packet when every seat reads the room codec (above).
