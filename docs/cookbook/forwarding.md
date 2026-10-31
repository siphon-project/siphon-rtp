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
| `forward_set_source` | Choose whose audio is forwarded: a `from_tag`, or none |
| `forward_leave` | Unseat a member; the room ends with its last member |

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

Check `node_info` `features` for `forward_room` first. A draining node refuses `forward_join`.

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

A seat that cannot is refused with a reason that names the room's codec and what it offered, for
example `the room carries AMR-WB/16000 (octet-aligned) and the seat does not offer it: AMR-WB/16000
payload type 96: bandwidth-efficient where the room is octet-aligned (RFC 4867 §4.4)`. Nothing is
transcoded: a seat that cannot take the room codec as it is does not join.

The room needs no encoder or decoder for its codec, so a codec this build cannot transcode forwards
fine. AMR-WB works without the `amr` feature.

RFC 4733 telephone-event is forwarded from the source to a receiver that negotiated it at the same
clock rate, under the receiver's own payload type. A receiver that did not is not sent it, which
leaves a gap in that receiver's sequence numbers where the event packets were.

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

## Inactivity

A forwarding seat is **never freed for silence**. A listener sends nothing for as long as others
talk, and an RTCP keepalive is optional. Liveness is any accepted RTP or RTCP datagram on the seat's
endpoint. When a seat has been quiet past `--media-timeout-secs`, the sweep sends `forward_seat_inactive`
(`conference_id`, `from_tag`) to the client that seated it, once. The seat stays seated. It is
reported again only after it has been heard from in between. What to do about it is the controller's
call: `forward_leave` frees it.

## Security and NAT

A forwarding seat is gated exactly like a conference seat, because the same code gates both: the
source must be the signalled one (or the `received-from` hint, or any source for an ICE or
`symmetric` seat), media from a DTLS seat before its handshake or an ICE seat before its pair is
selected is dropped, SRTP is checked before anything else, and the reply address follows the
constrained SSRC latch. A secure receiver is sent SRTP under its own key. See
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
