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
| `forward_set_reception` | Switch what one seat is sent, per stream (audio, video) |
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

## Manual reception mode

A seat joins receiving the source's audio and video. 3GPP TS 24.581 §6.3.7 keeps, per receiver, the list
of flows actually sent to it, and a client in manual reception mode gets nothing until it asks. The
controller keeps that list; the room enforces it with one verb:

```json
{"id":6,"command":"forward_set_reception","conference_id":"group-1","from_tag":"b19e02","audio":true,"video":false}
```

Both booleans are required, `true` receives. It answers `ok`, or an error for an unknown room or seat,
takes effect on the next packet and is idempotent, so the controller can resend the whole state. Check
`node_info` `features` for `forward_seat_reception`.

- Only what is sent to the seat is gated: audio and video, in translating rooms (also for a seat that is
  transcoded for and for a browser seat's bundled video), in preserving rooms (the talker's RTP only), the
  parameter-set replay and NACK resends. Each withheld packet is counted per seat and stream as
  `reception_off_dropped`, in the seat's stats and its leave log.
- The seat's own media is not touched. An off seat still sends, and may be the source.
- Its control stream is never gated. `send_rtcp_app` (the floor stream, a browser seat's data channel, or
  the audio RTCP) still reaches a seat whose audio and video are both off, so Media Transmission
  Notification and Receive Media Response are delivered. A preserving room's forwarded talker RTCP is
  control too and keeps flowing.
- Switching a stream back on rebases the seat's stream as at a source switch: its SSRC stays, its sequence
  number carries on from the last packet it was sent, and the first packet carries the marker bit (RFC
  3550 §5.1). For video the seat also waits for the source's next keyframe, the same as a seat that
  joins mid-stream, and the room asks the source for one (PLI or FIR); the parameter sets are replayed
  ahead of the picture. A keyframe asked for this way is not a source change, so no `forward_keyframe`
  event is raised.
- Reports follow RFC 3550 §6.4: the room sends a seat's stream a Sender Report only if it sent that
  stream a data packet in the current report interval or the previous one, otherwise a Receiver Report
  from the same SSRC. So a stream that is off (or a room with no source) goes from SR to RR after two
  report intervals, and back to SR once packets flow again. The RR still carries the reception report
  block about the seat's own media (loss, jitter, LSR, DLSR).
- Forwarding rooms are not part of a snapshot (`snapshot`/`restore` carry calls, not rooms), so the flags
  are not checkpointed: a standby does not have the room at all. A controller that rebuilds a room after
  a failover sets the reception of each seat again.

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
* AMR-NB conceals with 3GPP TS 26.091 (bit-exact with the TS 26.073 reference decoder): lag, LSF and
  gains are extrapolated from the last frames and faded by the bad-frame state machine. DTX is not
  implemented, so a lost frame is always concealed as speech.
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
receives (a Receiver Report instead when the room sent that stream no packet in this interval or the
previous one, RFC 3550 §6.4): its fixed SSRC, the translator's packet and octet counts, and an RTP timestamp on the same
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

### MCVideo transmission control

The MCVideo transmission control stream (3GPP TS 24.581 §4.3.3.1) has the same shape under another
token: `m=application <rtcp port> udp MCVideo`, RTCP APP packets only. Accept it with
`profile.transmission_control_formats`:

```json
{"command":"forward_join","conference_id":"group-1","from_tag":"a7c31f","sdp":"...",
 "profile":{"transmission_control_formats":["MCVideo"],
            "floor_fmtp":"mc_queueing;mc_priority=5;mc_granted;mc_transmission_ssrc=12345678"}}
```

The answer carries `m=application 30002 udp MCVideo` and `a=fmtp:MCVideo <floor_fmtp>`. Without the field
only `MCPTT` is accepted, and an `MCVideo` section is declined with port 0 (never passed through). List
both tokens to take either. `forward_offer` writes the first one listed. `rtcp_app` and `send_rtcp_app`
work as for floor control, with `stream: "floor"`. The engine does not read the APP names (`MCV0`,
`MCV1`, `MCV2`, TS 24.581 §9.1.2), the subtypes or the message set: they are yours, and two messages in
one datagram (§9.1.1) are two events. A browser seat opens the data channel named by
`profile.floor_channel_label` (default `mcptt-floor`). Check `node_info` `features` for
`transmission_control` first.

### Video

A seat may carry video beside its audio and the transmission control stream (3GPP TS 24.281 §6.2:
`m=audio`, `m=video`, `m=application ... udp MCVideo`). Ask for it with `profile.video`:

```json
{"id":7,"command":"forward_join","conference_id":"group-1","from_tag":"a7c31f","sdp":"...",
 "profile":{"transmission_control_formats":["MCVideo"],"floor_fmtp":"mc_queueing;mc_granted",
            "video":{"fmtp":"profile-level-id=640c1f;packetization-mode=1","bandwidth_kbps":1200}}}
```
```json
{"id":7,"result":"ok","sdp":"v=0\r\n...","to_tag":"a7c31f","streams":["audio","video","floor"]}
```

Without `profile.video` the `m=video` section is declined with port 0, as before, and the result says
so in `video_declined`.

**The codec rule.** Video is opaque to the engine: it is never transcoded, so every seat speaks the
same H.264 flavour (RFC 6184 §8.1). The first seat with live video fixes the room's
`packetization-mode` (0 or 1; 2, interleaved, is refused) and `profile-level-id`, or
`video.fmtp` does when you set it (3GPP TS 26.281 §4.1.1 makes H.264 mandatory, Constrained High
Profile level 3.1 being `640c1f`). A seat's own `sprop-parameter-sets` are never handed to another
seat. Each seat keeps its own payload type, as audio does.

**Matching a later seat.** RFC 6184 §8.2.2 splits `profile-level-id` in two: the profile part must be
used symmetrically, the level part may change. So a later seat's `H264/90000` payload fits when:

- its `packetization-mode` is the room's;
- its sub-profile is the room's. The spellings RFC 6184 §8.1 Table 5 gives one sub-profile count as one
  (Constrained Baseline is `42e0..`, `42c0..`, `4240..`, `4d80..` and `58c0..` alike), and any other
  combination must be the room's exactly (High `6400..`, Constrained High `640c..`);
- and, when the seat receives video (`sendrecv` or `recvonly`), it decodes the room's level. The
  room's sources never send above it.

The room's level is the first seat's, or the one in `video.fmtp`. The engine answers each seat in the
seat's own profile spelling:

| Seat | Answered level |
|---|---|
| At or above the room's level | The room's (an answer never upgrades a level) |
| Below it, `sendonly` or `inactive` | Its own (every receiver decodes all lower levels, RFC 6184 §8.1) |
| Below it and receiving | Declined: audio only, `video_declined` names both levels |
| Offers `level-asymmetry-allowed=1` | The room's, with `level-asymmetry-allowed=1`; it receives up to its `max-recv-level`, which must reach the room's level |

Other parameters of `video.fmtp` are written as given; only `profile-level-id` changes per seat.
`forward_offer` never offers `level-asymmetry-allowed`, so a member's answer is held to one level both
ways. A seat in another sub-profile, or with a malformed `profile-level-id`, joins with audio only and
`video_declined` says why. `node_info` lists `forward_video_h264` on an engine that matches this way;
one without it requires the exact `profile-level-id`.

**Directions.** The answer is the complement of the offered direction (RFC 3264 §6.1). A `sendrecv`
seat can be the video source and is sent video. A `recvonly` seat is answered `sendonly`, is sent
video and is never a source: whatever it sends is ignored and counted. A `sendonly` seat is answered
`recvonly`, may be the source, and is sent no video. `inactive` is neither.

**One source for both.** `forward_set_source` moves audio and video together, and the client gets one
`forward_source_started` per change. A source with no video sends the receivers none. Each receiver has
its own video translator: a stable SSRC, continuous sequence numbers and a 90 kHz timestamp line (RFC
3550 §5.1, RFC 6184 §8.2.1). The marker bit is the sender's and is never set at a switch: it ends an
access unit (RFC 6184 §5.1), so a switch that lands in the middle of a picture must not mark the first
packet of the new run.

### Keyframes on a switch

H.264 is predictive, so a receiver handed a stream in the middle of a group of pictures shows nothing
usable until the next IDR picture (RFC 6184 §1.1). A source change therefore starts every receiver on a
keyframe (3GPP TS 24.581 treats a transmission grant as the start of a new video transmission, and TS
26.281 wants the video decodable):

1. **Gate.** Each receiver is sent nothing of the new source until a packet begins an IDR slice (a
   single NAL unit of type 5, one inside a STAP-A, or an FU-A start of one, RFC 6184 §5.6 to §5.8).
   Packets held back are counted (`video_dropped_awaiting_keyframe`).
2. **Ask.** The room sends the new source a keyframe request in an RTCP compound (RFC 4585 §3.1: an
   empty report, the source description with the CNAME, then the feedback): a Picture Loss Indication
   first (RFC 4585 §6.3.1), then a Full Intra Request (RFC 5104 §4.3.1) every 500 ms, up to three
   repeats. A repeat of an unanswered FIR keeps its command sequence number; the next request,
   at the next switch, takes the next. A source is sent only what it accepted in its SDP
   (`a=rtcp-fb`, below), and one that accepted none is sent nothing.
3. **Open.** On the IDR the gate opens, after the source's last SPS and PPS, replayed as single NAL
   unit packets (valid in packetization modes 0 and 1) under the sequence numbers right before the IDR
   and its timestamp, so a receiver that missed them can decode the picture; an IDR that carries them
   itself (a STAP-A) is not preceded by a second copy. Anything older than the IDR is dropped.
4. **Give up.** After 2000 ms with no IDR the room forwards anyway, so a source that cannot send a
   keyframe never mutes the room.

The controller hears `forward_keyframe` once per change (`timed_out`, `latency_ms`). A seat that joins
while a source is streaming is held and asked for a keyframe the same way, alone; that is not a source
change and raises no event.

**Feedback negotiation.** The room supports `nack`, `nack pli` and `ccm fir` (RFC 4585 §4.2, RFC 5104
§7). An `RTP/AVPF` video offer is answered with the intersection of what it lists for the chosen payload
type (or `*`) and that set; an `RTP/AVP` offer is answered none, since that profile has no feedback.
`forward_offer` offers `RTP/AVPF` with all three. A source that did not accept `pli` or `fir` is not
sent one, and a receiver's NACK is answered only if it accepted `nack`.

**Receivers' feedback.** A PLI or FIR a receiver sends about the stream the room sends it is passed on to
the source as one request per second however many receivers ask. A Generic NACK (RFC 4585 §6.2.1) is
answered from a history of the source's last 256 video packets (about 384 KiB per room that has a seat
accepting `nack`, allocated once): the packet is sent again through that receiver's translator, under
the sequence number it was lost under. There is no RTX stream (RFC 4588); a NACK for a packet that left
the history, or from before a switch, or for a replayed parameter set, is counted (`nack_missed`) and
the receiver recovers on its own PLI.

The timings are engine constants: a 500 ms retry, three repeats, a 2000 ms limit and a 1000 ms
interval for receivers' requests. Counters per seat, in the log line when a seat leaves (and in
`ForwardRoom::seat_stats` for an embedder): `pli_sent`, `fir_sent`, `keyframes_seen`, `video_dropped_awaiting_keyframe`,
`nack_answered`, `nack_missed`, `keyframe_timeouts`. Check `node_info` `features` for
`forward_video_keyframe`.

**What this does not do yet.** The gate opens on any IDR slice, not only the first slice of a picture,
so a source that sends an IDR as several slices and is joined in the middle of one starts its receivers
one picture late. There is no transcoding or level negotiation beyond the exact match above. Plain `RTP/AVP` and
`RTP/AVPF` seats in a translate room, and browser seats (below): video offered by an SDES seat, by a
browser on a transport of its own is declined with the reason (a `media: preserve` room carries video, see "Video in a preserve room"). One transmission at a time: concurrent video
sources (3GPP TS 24.581 §4.1.1.2) need per-receiver subscriptions and stable seat ids and are a step of
their own. Check `node_info` `features` for `forward_video` first.

**Video on a browser seat.** A WebRTC seat (`UDP/TLS/RTP/SAVPF` audio) carries video bundled with its
audio and data channel on its one ICE/DTLS transport (RFC 8843), so the video has no endpoint of its own.
The answer's video section sits on the audio's port with the audio's ICE credentials, candidates,
fingerprint and `a=setup`, echoes the offered `a=mid`, and the `a=group:BUNDLE` lists it. Of the several
H.264 payload types a browser offers, the one that fits the room's format is answered. Only `nack`,
`nack pli` and `ccm fir` that were offered are answered; `transport-cc` and `goog-remb` are not (the room
does no congestion control), and no `a=extmap` is (the translator strips header extensions). A `recvonly`
browser is a receive seat. Plain and browser seats in one room see each other's video; keyframe gate,
parameter-set replay, NACK and `forward_keyframe` work as on plain seats, with PLI, FIR and NACK resends
sent as SRTCP/SRTP under the seat's key. `forward_offer` with `transport_protocol: UDP/TLS/RTP/SAVPF` and
`profile.video` offers `m=video <audio port> UDP/TLS/RTP/SAVPF 126` in the bundle; the browser's answer
seats it. A video section outside the audio's BUNDLE group is declined (`video_declined` names RFC 8843),
and so is a browser's video in a preserve room (a WebRTC seat is refused there). A declined browser video leaves the answer's BUNDLE
group. Check `node_info` `features` for `forward_video_webrtc`.

The video endpoint is gated exactly like the seat's audio (the signalled source, then the SSRC-consistent
latch, [Layer 5c-ii](../security-and-nat.md)). `forward_offer` with `profile.video` offers
`m=video <port> RTP/AVPF 126` with the same format rules, and `forward_answer` reports `streams` and
`video_declined` too.

### Video in a preserve room

A `media: preserve` room carries video the way it carries audio (3GPP TS 33.180 §7.5.2): the UEs key
their SRTP between themselves, one group key covering audio and video told apart by SSRC, and the engine
hands the source's video datagram on byte for byte. The seat's `m=video` is `RTP/SAVP`, `RTP/SAVPF` or
plain, on an endpoint of its own, with no `a=crypto`, no DTLS and no BUNDLE with the audio, and is
answered in the offered transport with the offered `a=rtcp-fb`; the controller's `key_mgmt` goes on the
video section as on the audio one. Every seat uses the one video payload type the room's first video seat
fixed (another declines with the reason), and `forward_offer` offers that number once it exists (126 for
the first). The source never hears itself, a seat whose video reception is off (`forward_set_reception`)
is sent none, and the room fans out with no per-packet allocation.

The payload is encrypted, so the room sees no keyframe: there is no gate, no SPS/PPS replay and no
`forward_keyframe` event, and the controller relies on the UE sending an IDR when its transmission
starts. The room's own help is one PLI (one FIR when the source accepted only FIR) to a new source and to
a late joiner, sealed under the source's media SRTCP key, then nothing. A source with no
`media_srtcp_keys` is never sent a request (a plaintext one would be refused). Receivers' PLI and FIR
for the source's stream are passed on at most once a second, and a Generic NACK from a seat that accepted
`nack` is answered from the stored original SRTP bytes (counted `nack_answered`, `nack_missed`).

Video RTCP is hop by hop under each seat's key (§9.4.1), the same key as the audio's. A keyed seat's video
RTCP must authenticate on a replay window per sender SSRC (audio and video each count their own SRTCP index; a key tracks 8 sender SSRCs, a ninth is refused),
and the room's one outgoing index per seat serves both, so no IV is reused (RFC 7714 §9.2). Check
`node_info` `features` for `forward_video_preserve`.

### Inviting a browser into the group

A browser can be a pre-arranged member the room calls, not only one that calls the room. Ask
`forward_offer` for a WebRTC offer with the transport in the profile (check `node_info` `features` for
`forward_offer_webrtc`):

```json
{"id":1,"command":"forward_offer","conference_id":"group-1","from_tag":"b19e02",
 "profile":{"transport_protocol":"UDP/TLS/RTP/SAVPF",
            "floor_fmtp":"mc_queueing;mc_priority=5;mc_granted"}}
```

The offer is `UDP/TLS/RTP/SAVPF` with the engine's `a=fingerprint`, `a=setup:actpass`, `a=ice-lite`
with the seat's credentials and candidates, `a=rtcp-mux`, and one `a=group:BUNDLE`. Because the profile
carries `floor_fmtp` the floor control is the bundled `m=application … webrtc-datachannel` section; leave
`floor_fmtp` out for an audio-only seat. Hand the SDP to the page, then send its answer back:

```js
await pc.setRemoteDescription({ type: "offer", sdp: offerFromEngine });
const audio = pc.getTransceivers().find((t) => t.receiver.track.kind === "audio");
audio.direction = "sendrecv";
await audio.sender.replaceTrack(microphoneTrack);
const floor = pc.createDataChannel("mcptt-floor");   // after setRemoteDescription: reuses the offered section
await pc.setLocalDescription(await pc.createAnswer());
// wait for ICE gathering, then send pc.localDescription.sdp to the controller
```

```json
{"id":2,"command":"forward_answer","conference_id":"group-1","from_tag":"b19e02","sdp":"v=0\r\n..."}
```

The answer must keep `UDP/TLS/RTP/SAVPF`, carry the browser's `a=fingerprint`, and pick a DTLS role
(`active` or `passive`; `actpass` is refused). The seat joins the room waiting for its handshake and ICE,
exactly like a browser that called in, and the floor control then runs as in the next section. A
`media: preserve` room refuses a WebRTC offer (the engine would have to terminate the SRTP the room
forwards end to end), and so do `ice: remove` and a pinned `dtls` role. `conference_offer` does not
offer WebRTC. `scripts/check-floor-channel-chrome.sh` drives this direction from headless Chrome too.

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
answers the channel for a browser caller toward a plain callee (see the JSON reference).
`scripts/check-floor-channel-chrome.sh` drives the whole flow from headless Chrome (CI runs it);
acceptance in your own browser and controller is still yours.

### Two-party calls

A two-party call carries the same stream (`udp MCVideo` under `transmission_control_formats`, as above). When the offerer's SDP has `m=application <port> udp MCPTT`,
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

## Preserve rooms (end-to-end SRTP)

MCPTT media is SRTP between the UEs, keyed with PCK/GMK and signalled with `a=key-mgmt:mikey`
(3GPP TS 33.180 §7.5.2 NOTE 3). SRTP authenticates the SSRC and sequence number, so the translator above
would break it. Create the room with `"media": "preserve"` on `forward_join` / `forward_offer` and the
engine hands the talker's datagrams on byte for byte (RFC 3550 §7.1): same SSRC, sequence number,
timestamp, payload and auth tag at every receiver, no translator, no SRTP re-protect, no transcoding.
The first seat fixes the mode; a later join or offer in the other mode is refused.

- Seats are `RTP/SAVP` (or `RTP/AVP`) **without** `a=crypto`; the answer keeps the transport. A seat that
  offers `a=crypto` or DTLS-SRTP (WebRTC) is refused: the engine must not terminate end-to-end media.
- All seats use one codec **and one payload type** (the packets are not rewritten); a mixed-codec seat is
  refused with "preserve rooms forward the talker's packets unchanged".
- Put the keying in the profile: `"key_mgmt": "mikey ..."` is written as `a=key-mgmt:mikey ...` on the
  audio section of every SDP the engine produces (join answers, `forward_offer` offers, and the two-party
  verbs). The engine never copies the offerer's line, never invents one and never drops yours. A
  `forward_offer` into a preserve room with `key_mgmt` offers `RTP/SAVP`, and the member must answer
  `RTP/SAVP` without `a=crypto`. `key_mgmt` is refused in a translate room (the translator would break the end-to-end SRTP it sets up), so a secured group call needs `media: preserve`.
- RTCP: no engine SR, RR or BYE toward any seat, at room start or later. A seat without media keys
  has its audio SRTCP forwarded byte for byte with its RTP when it talks and dropped when it listens
  (`receiver_rtcp_dropped`); the engine cannot read it, so RTCP APP is surfaced from the floor stream
  only. A seat with `profile.media_srtcp_keys` (a few lines down) is a protected hop instead.
- Media SRTCP keys: 3GPP TS 33.180 §9.4.1 protects all RTCP, media RTCP included, between each client
  and the server under that client's own key (§9.4.2, §9.4.6; `AEAD_AES_128_GCM`, §9.4.8), while the
  media stays end to end (§5.2.1). Give a seat `"media_srtcp_keys": [{"mki", "key", "salt"}, ...]` (the
  `floor_keys` shape, at most two) on `forward_join` / `forward_offer`, or set them later with
  `set_floor_keys` and `"stream": "audio"` (replace semantics as for the floor keys). The engine then
  opens that seat's audio RTCP under its key and drops what does not authenticate
  (`media_srtcp_refused`). A keyed talker's RTCP is sealed again for each receiver under that
  receiver's own key; a receiver with no media key is sent nothing of it, never plaintext
  (`media_srtcp_unkeyed_receiver`), so key every seat of a room that has a keyed talker. A keyed
  receiver's RTCP is read and not forwarded. APP parts of the audio RTCP of a keyed seat surface as
  `rtcp_app` events with stream `audio`, and `send_rtcp_app` with `"stream": "audio"` to it is
  protected under its key. Keys are refused in a translate room, in a mixing room and on a two-party
  call. `node_info` lists `forward_preserve_media_srtcp`.
- `forward_set_source`, `forward_source_started` (once per switch), `forward_seat_inactive` and the idle
  backstop behave as in a translating room. `node_info` lists `forward_preserve`.
- Fan-out is a copy-free loop over the receivers. `cargo bench -p siphon-rtp --bench forward_fanout_bench`
  has `per_inbound_packet_preserve` beside `per_inbound_packet`, and `per_inbound_srtcp_preserve` for the
  one `open` plus one `seal` per receiver a keyed talker's RTCP costs (no allocation, same bench).

The engine cannot verify the SRTP tag in a preserve room (it has no key), so the source-address gate and
the controller's choice of source are what bound who can send: see
[the security model](../security-and-nat.md#layer-5c-iii-preserve-rooms-end-to-end-srtp-hop-by-hop-srtcp)
(preserve rooms).

### SRTCP indices, rejoins and failover

An `AEAD_AES_128_GCM` SRTCP packet is encrypted under an IV made of the key's salt, the sender SSRC and
the SRTCP index, so under one key no (SSRC, index) pair may ever go out twice (RFC 7714 §8: a repeat
breaks confidentiality and integrity). The engine therefore keeps **one send-index counter per key**, not
per seat: a seat that leaves and rejoins with its key, one client key seated in two rooms or in a room and
a two-party floor call, a floor stream and a media stream under one key (TS 33.180 §9.4.2 describes one key
per client), and a key unset and set again all carry on from the last index sent under that key. The
counter is lock-free, one compare-and-swap per sealed packet, and stops at index 2^31 - 1 (nothing more is
sent under that key, and an error is logged, until the controller replaces it). `node_info` lists
`srtcp_index_ledger`.

The counters live in the engine's memory and are never dropped unless you set
`srtcp_ledger_retention_secs` (TOML) or `--srtcp-ledger-retention-secs`: only at or above the lifetime your
controller enforces on a client key, since a key reused after its counter was dropped repeats nonces
(`siphon_rtp_srtcp_ledger_entries` counts them).

The ledger is also capped, by `srtcp_ledger_max_entries` (TOML) or `--srtcp-ledger-max-entries`
(default 100000, about 15 MB at roughly 150 bytes an entry). At the cap a **new** key is refused: the
verb that carried it (`forward_join`, `forward_offer`, a dial-out, `offer`, `answer`, `answer_local`,
`set_floor_keys`) fails with a "ledger is full" reason, an error is logged and
`siphon_rtp_srtcp_ledger_install_refused_total` rises. A key the ledger already holds still installs, and
no entry is ever evicted to make room (its key would restart at index 0). A `restore_srtcp_indices` blob
that would take the ledger past the cap is refused whole. Alert on that counter; fix it by raising the
cap or by setting `srtcp_ledger_retention_secs` so keys the controller no longer uses are released.

Failover is fail-closed. The first `checkpoint_srtcp_indices` puts a lease on each counter (its index plus
65536); every later one moves the lease only when you **store its blob and then send
`confirm_srtcp_indices` with the blob's `generation`** (never before the blob is durably stored: a lost
reply must not let the primary send past what the standby holds). The engine raises `srtcp_checkpoint_due` when a counter is half way and refuses to seal at the
lease until the next checkpoint (`siphon_rtp_srtcp_lease_refused_total`), so the primary can never send past
the point a standby would start from. **Checkpoint on the event, and at least every few minutes** (no key may
send 32768 SRTCP packets between two checkpoints). Without any checkpoint there is no lease.

The counters live in the engine's memory. To survive a failover, store the opaque blob of
`checkpoint_srtcp_indices` on your schedule (it names keys by an HMAC under the key and holds no key
bytes) and send it with `restore_srtcp_indices` to the standby **before** rebuilding any room there: each
counter starts 65536 indices past the checkpointed one, because the primary kept sending after the
checkpoint. **If an engine restarts, or fails over with no restored ledger, it knows nothing of what was
sent: issue fresh keys** (a new MIKEY exchange, RFC 7714 §8) rather than reusing the old ones. The forward
rooms themselves are not checkpointed, so a standby rejoins its seats; the ledger is what makes that safe.

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

A video packet (`video_per_inbound_packet`, a 1200-octet FU-A payload on the video endpoint) costs the
same translate per receiver with a larger payload to copy: 321 ns at 10 seats, 3.2 us at 100, 16.6 us
at 500 and 33.7 us at 1000 (`--quick` run, one core).

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
