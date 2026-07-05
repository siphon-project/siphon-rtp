# Plain RTP relay (SBC media anchoring)

The bread-and-butter case. SIPhon (or Kamailio/OpenSIPS) proxies the signalling and anchors both
legs' media through siphon-rtp: the engine allocates a local port per leg, rewrites each SDP to
advertise its own address, and forwards RTP between the two legs. No transcoding, no crypto, no
codec ever executed. This is what rtpengine does by default, and it is the fast path here too.

What you get from anchoring alone:

- **Topology hiding.** Each party sees only the engine's address, never the peer's.
- **NAT traversal.** Symmetric-RTP latching (gated, see below) reaches parties behind NAT.
- **Observability and control.** Per-call counters, media-timeout detection, block/silence,
  runtime recording, all without touching the payload.

## Start the engine

```bash
siphon-rtp \
  --control 127.0.0.1:8080 \
  --ng 127.0.0.1:22222 \
  --relay-bind-ip 203.0.113.10 \
  --port-min 40000 --port-max 49999 \
  --metrics-addr 127.0.0.1:9090
```

`--relay-bind-ip` matters: the default bind is loopback (fine for CI, useless for real peers).
The address you bind is the address the rewritten SDP advertises.

## The offer / answer exchange

The lifecycle is rtpengine's, keyed the same way: `call_id` + `from_tag` (+ `to_tag` from the
answer). `offer` when the INVITE arrives, `answer` when the 200 OK comes back, `delete` on BYE
or any failure path.

Party A's original offer:

```
v=0
o=- 3898131234 3898131234 IN IP4 192.0.2.20
s=-
c=IN IP4 192.0.2.20
t=0 0
m=audio 49170 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20
```

### Native JSON (what SIPhon speaks)

Each frame on the TCP control connection is a big-endian `u32` length followed by the JSON body.
Offer:

```json
{
  "id": 1,
  "command": "offer",
  "call_id": "7f3a9c2e@sip.example.net",
  "from_tag": "a1b2c3",
  "sdp": "v=0\r\no=- 3898131234 ... a=ptime:20\r\n",
  "profile": { "replace": ["origin"] }
}
```

Response:

```json
{ "id": 1, "result": "ok", "sdp": "v=0\r\n... (rewritten, see below)" }
```

Answer, once B's 200 OK arrives (note `to_tag` is now required):

```json
{
  "id": 2,
  "command": "answer",
  "call_id": "7f3a9c2e@sip.example.net",
  "from_tag": "a1b2c3",
  "to_tag": "d4e5f6",
  "sdp": "v=0\r\n... B's answer SDP ...",
  "profile": { "replace": ["origin"] }
}
```

Teardown on BYE (or CANCEL, or a failed dialog):

```json
{ "id": 3, "command": "delete", "call_id": "7f3a9c2e@sip.example.net", "from_tag": "a1b2c3" }
```

### rtpengine NG (what Kamailio/OpenSIPS speak)

Point the `rtpengine` module at `udp:127.0.0.1:22222` and the existing dial plan works. On the
wire each datagram is `<cookie><SP><bencode-dict>`; shown decoded here for readability:

```
offer:  { "command": "offer",  "call-id": "7f3a9c2e@sip.example.net",
          "from-tag": "a1b2c3", "sdp": "v=0\r\n...",
          "replace": ["origin"] }

answer: { "command": "answer", "call-id": "7f3a9c2e@sip.example.net",
          "from-tag": "a1b2c3", "to-tag": "d4e5f6", "sdp": "v=0\r\n..." }

delete: { "command": "delete", "call-id": "7f3a9c2e@sip.example.net",
          "from-tag": "a1b2c3" }
```

Responses come back as `{ "result": "ok", "sdp": "..." }` or
`{ "result": "error", "error-reason": "..." }`, cookie echoed verbatim. Both front-ends funnel
into the same engine; a call created over NG can be queried over NG, and vice versa for JSON.

## What the rewritten SDP looks like

The engine allocates one RTP endpoint per leg (plus a companion RTCP endpoint when the stream is
not `rtcp-mux`ed, RFC 5761) and rewrites the audio `c=` line and `m=audio` port to its own
endpoint (RFC 3264 offer/answer, RFC 4566). The rewritten **offer** is what B receives, so it
advertises the B-facing leg; the rewritten **answer** goes back to A and advertises the A-facing
leg. With `replace: ["origin"]` the `o=` line is rewritten too:

```
v=0
o=- 3898131234 3898131234 IN IP4 203.0.113.10
s=-
c=IN IP4 203.0.113.10
t=0 0
m=audio 40002 RTP/AVP 8 0 101
a=rtcp:40003
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20
```

The codec list, ptime, and every attribute the engine has no business touching pass through
byte-for-byte. Both `IN IP4` and `IN IP6` legs are supported, and the two legs may be different
families (see the `address_family` profile field for IPv4/IPv6 interworking).

## Nothing touches the payload

On a plain relay the RTP payload is forwarded unchanged: same payload type, same SSRC, same
sequence numbers and timestamps, same bytes. The engine parses only what the source gate and
latch need (RFC 3550 header fields). Two consequences worth naming:

- **Any codec relays.** AMR, EVS, Opus, anything. Relaying is not implementing: no codec is
  executed, so passthrough carries no codec patent exposure and needs no build feature. Only
  *transcoding* runs a codec (see [Codec licensing](../codec-licensing.md) and
  [Transcoding](transcoding.md)).
- **Passive monitoring keeps working.** Because SSRC and sequence numbers survive the relay, a
  passive capture (VoIPmonitor-style) can still correlate the two legs.

## NAT: symmetric RTP, safely

Each leg's ingress is gated to the source the SDP signalled, and the reply destination latches to
where the peer's packets actually come from (symmetric RTP, RFC 4961). The latch is constrained:
it never adopts an off-path source and never re-latches mid-stream to a new source with a
different SSRC. That combination is the NAT feature and the anti-RTPbleed defence in one
mechanism. The cookbook view, including the `received-from` hint for parties that signal private
addresses, is in [NAT traversal & latching](nat.md); the design and threat model live in
[Security & NAT](../security-and-nat.md).

!!! warning "Always delete"
    An `offer` without a matching `delete` holds two (or four) media ports until the media
    timeout reaps it (`--media-timeout-secs`, default 30 s of no accepted media, after which the
    engine tears the call down and pushes a `media_timeout` event). Handle every teardown path:
    BYE, CANCEL, dialog failure.

## How to verify

**Per call:** `query` returns the session counters.

```json
{ "id": 4, "command": "query", "call_id": "7f3a9c2e@sip.example.net", "from_tag": "a1b2c3" }
```

```json
{ "id": 4, "result": "ok",
  "stats": { "packets_in": 2450, "packets_out": 2448,
             "bytes_in": 421400, "bytes_out": 421056, "packets_lost": 2 } }
```

`packets_in` counts every datagram that reached the call's engine ports, `packets_out` what the
engine forwarded, and `packets_lost` what it refused or could not use (source-gate rejections,
late or malformed packets). `packets_in` climbing while `packets_lost` climbs with it and
`packets_out` stays behind is the classic source-gate symptom; see
[NAT traversal & latching](nat.md). Over NG, `query` is answered but the counters dict is
currently native-JSON-only, so use the JSON control (or `/metrics`) for numbers.

**Engine-wide:** with `--metrics-addr` set, `GET /metrics` exposes `siphon_rtp_sessions` (live
calls), `siphon_rtp_offers_total` / `siphon_rtp_answers_total` / `siphon_rtp_deletes_total`, and
friends. `list` enumerates your live call-ids; `ping` answers `pong`. See
[Observability & call quality](../observability.md).

**On the wire:** capture the media range and check both directions flow through the engine:

```bash
tcpdump -ni any udp portrange 40000-49999 -w media.pcap
```

You should see A's RTP arriving at the A-facing port and leaving the B-facing port toward B
unchanged (same SSRC and payload type), and the reverse. One-directional flow in the pcap means
one leg's gate or destination is wrong; start at [NAT traversal & latching](nat.md).

## See also

- [Transcoding](transcoding.md) when the two legs cannot share a codec.
- [Secure media (SRTP)](secure-srtp.md) when one side is RTP/SAVP.
- [Monitoring](monitoring.md) for metrics, statistics, and HEP export.
