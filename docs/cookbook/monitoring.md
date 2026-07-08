# Monitoring & QoS

You can see what siphon-rtp is doing three ways: a Prometheus/health HTTP endpoint, RTCP on the
wire, and quality events pushed over the native control channel. A fourth surface, HEP export,
ships relayed RTCP to a Homer or VoIPmonitor collector. None of them block the media path. This
page is the operator's view; [Observability & call quality](../observability.md) has the
field-by-field detail behind each number.

## Prometheus metrics + health

Off by default; enable with a flag:

```
siphon-rtp --control 127.0.0.1:8080 --metrics-addr 0.0.0.0:9100
```

Three routes: `GET /metrics` (Prometheus text exposition, `text/plain; version=0.0.4`, no
labels), `GET /healthz` (liveness, always `200` while the process runs), `GET /readyz`
(readiness, `503` while draining so your orchestrator stops routing new calls to a node being
upgraded, while `/healthz` stays `200` and live calls finish).

The full series set:

| series | type | meaning |
|---|---|---|
| `siphon_rtp_sessions` | gauge | live calls in the session registry |
| `siphon_rtp_conference_rooms` | gauge | live conference rooms |
| `siphon_rtp_conference_participants` | gauge | live conference participants across all rooms |
| `siphon_rtp_offers_total` | counter | control `offer` commands accepted |
| `siphon_rtp_answers_total` | counter | control `answer` commands accepted |
| `siphon_rtp_deletes_total` | counter | control `delete` commands accepted |
| `siphon_rtp_control_errors_total` | counter | control commands that returned an error |
| `siphon_rtp_control_rate_limited_total` | counter | control commands rejected by the per-connection rate limiter |
| `siphon_rtp_conference_joins_total` | counter | `conference_join` commands accepted |
| `siphon_rtp_conference_leaves_total` | counter | `conference_leave` commands accepted |
| `siphon_rtp_jemalloc_allocated_bytes` | gauge | live heap, jemalloc `stats.allocated` |
| `siphon_rtp_max_sessions` | gauge | advertised session capacity (0 = unlimited) |
| `siphon_rtp_transcode_sessions` | gauge | the expensive decode/re-encode subset of sessions |
| `siphon_rtp_load_permille` | gauge | normalized node load 0..=1000, max of session utilization and CPU |
| `siphon_rtp_cpu_permille` | gauge | host CPU 0..=1000 (absent until first `/proc/stat` sample) |
| `siphon_rtp_draining` | gauge | 1 while draining, 0 while serving |

Worth alerting on:

| signal | alert when | why |
|---|---|---|
| `siphon_rtp_jemalloc_allocated_bytes` | `rate(...[30m]) > 0` while `siphon_rtp_sessions` is flat | a real leak (jemalloc retains freed pages, so RSS is too noisy) |
| `siphon_rtp_control_errors_total` | sustained `rate() > 0` | the proxy and engine disagree about something |
| `siphon_rtp_load_permille` | near 1000 | node at capacity; the dispatcher should stop placing calls here |
| `siphon_rtp_sessions` | grows under flat completed-call load | sessions not draining (check media-timeout) |

The same numbers are reachable over the control channel for a dispatcher that would rather poll
than scrape: `statistics` (the counters), `query` (per-call packet/byte/loss counters), `load`
(the placement snapshot: sessions, load per-mille, transcode subset, jemalloc bytes, drain
state), and `node_info` (static capabilities, read once).

## RTCP on the wire (RFC 3550)

Where the engine only relays, it forwards the endpoints' own RTCP untouched, and their SR/RR
exchange remains the authoritative quality record; passive probes (VoIPmonitor, Homer capture
agents) see it as they would around any media relay.

Where the engine terminates media itself, today the conference mixer, it originates RTCP: each
participant gets a Sender Report every ~5 s (RFC 3550 §6.2) on its muxed endpoint (RFC 5761),
carrying the NTP↔RTP mapping and sender counts plus a reception report block on that
participant's inbound stream: cumulative loss, extended highest sequence, interarrival jitter
computed from receive-time arrival stamps (§6.4.1, §A.8), and LSR/DLSR echoed from the peer's
last SR so the peer can derive round-trip time. Secure legs get the same reports as SRTCP
(RFC 3711). The full derivation is in [Observability](../observability.md).

## Control-channel events

The engine pushes these asynchronously to the controlling client (no request id):

- `call_quality`, every ~5 s per conference participant and per 2-party relay / transcode leg: RFC 3550 interarrival jitter in ms,
  residual loss percent, and a MOS estimate from the ITU-T G.107 E-model (R-factor mapped per
  Annex B, clamped to 1.0..4.5), with the codec's impairment factors per ITU-T G.113. One-way
  network delay is now measured (from RTT on inbound RRs, conference path) and folded in, so the
  score reflects jitter, loss, codec, and measured one-way delay.
  Conference participants are keyed by `conference_id`; 2-party relay and transcode legs by `call_id`
  (exactly one identifier is present). The transcode path reports on a ~5 s tick; the plain-relay path
  derives it from each endpoint's RTCP reception reports.

  ```json
  { "event": "call_quality", "conference_id": "room-1", "from_tag": "alice",
    "jitter_ms": 1.125, "loss_percent": 0.0, "mos": 4.41 }
  ```

- `dtmf`: one event per completed RFC 4733 key press, with digit, duration, and volume.
- `media_timeout`: a call went silent past `--media-timeout-secs` (default 30) and the engine
  reaped it; release your own per-call state on this.
- `active_speaker`: the dominant speaker in a conference changed (`from_tag` absent when the
  floor went silent).

## HEP export to Homer / VoIPmonitor

Set an environment variable and the engine ships every relayed RTCP datagram to a capture node
as a HEP3 packet over UDP, exactly the wire Homer, heplify-server, and captagent speak:

```
SIPHON_RTP_HEP_COLLECTOR=198.51.100.20:9060 \
SIPHON_RTP_HEP_AGENT_ID=2001 \
siphon-rtp --control 127.0.0.1:8080 --relay-bind-ip 203.0.113.10
```

Each capture carries the transport 5-tuple, a wall-clock timestamp, protocol type 5 (RTCP), the
configured agent id, and the call-id as the HEP correlation id, so the collector groups both
legs of a call. A HEP type-35 QoS/MOS report now ships alongside the type-5 RTCP capture.
Export is fire-and-forget: observations are tapped off the relay fast path into
a bounded queue and dropped under backpressure, and a send failure is logged, never propagated.
Telemetry cannot disturb media.

Scope, honestly: the tap sits on the plain-relay forwarding path, so what reaches the collector
is the endpoints' own relayed RTCP. Legs the engine terminates in userspace (conference, SRTP,
transcode, WS) are not tapped, and the engine's G.107 MOS estimate now travels BOTH on the control
channel as `call_quality` AND in the HEP stream as a type-35 QoS report. If your collector is
VoIPmonitor sniffing passively
instead of ingesting HEP, note the relay preserves the streams it forwards, so correlation by
SSRC keeps working across the relay.

## Putting it together

Scrape `/metrics` and alert on the table above; point liveness at `/healthz` and readiness at
`/readyz` so a draining node leaves rotation cleanly (pair with the `drain` control verb for
rolling upgrades); consume `call_quality` and `media_timeout` from the control channel in the
proxy; and set `SIPHON_RTP_HEP_COLLECTOR` if a Homer/VoIPmonitor node should archive the relayed
RTCP.

## How to verify

```
curl -s http://127.0.0.1:9100/metrics | grep siphon_rtp_sessions
curl -si http://127.0.0.1:9100/readyz
```

Send `drain` on the control channel and `/readyz` flips to `503 draining`; `undrain` flips it
back. Run one relay call with RTCP flowing and a `tcpdump udp port 9060` on the collector host
shows HEP3 packets (they start with the ASCII bytes `HEP3`).

## See also

- [Observability & call quality](../observability.md), the detailed page behind this one.
- [Security & NAT](../security-and-nat.md), why a packet is accepted before it is ever counted.
