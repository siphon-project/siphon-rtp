# Observability & call quality

How to see what the engine is doing and how good the media sounds. Three surfaces: a Prometheus
HTTP endpoint (process/control health), RTCP reception reports (per-stream quality on the wire), and
the native control channel's `call_quality` events (per-leg jitter / loss / MOS, pushed to SIPhon).

## 1. Prometheus / health HTTP endpoint

Enabled with `--metrics-addr <ip:port>`. A hand-rolled HTTP/1.1 server (no hyper/axum), one request
per connection, never blocking the engine. Routes: `GET /metrics`, `GET /healthz`, `GET /readyz`.
`/metrics` is `text/plain; version=0.0.4` — numbers only, no labels, trivially scrapeable.

| series | type | meaning |
|---|---|---|
| `siphon_rtp_sessions` | gauge | live calls in the session registry |
| `siphon_rtp_conference_rooms` | gauge | live conference rooms |
| `siphon_rtp_conference_participants` | gauge | live conference participants across all rooms |
| `siphon_rtp_offers_total` | counter | control `offer` commands accepted |
| `siphon_rtp_answers_total` | counter | control `answer` commands accepted |
| `siphon_rtp_deletes_total` | counter | control `delete` commands accepted |
| `siphon_rtp_conference_joins_total` | counter | conference `join` commands accepted |
| `siphon_rtp_conference_leaves_total` | counter | conference `leave` commands accepted |
| `siphon_rtp_control_errors_total` | counter | control commands that returned an error |
| `siphon_rtp_control_rate_limited_total` | counter | control commands rejected by the rate limiter |
| `siphon_rtp_transcode_sessions` | gauge | live media-processing (transcode / bridge) sessions |
| `siphon_rtp_max_sessions` | gauge | advertised session cap (`--max-sessions`, 0 = unlimited) |
| `siphon_rtp_load_permille` | gauge | cluster load score, 0–1000 (the max of session utilisation and CPU) |
| `siphon_rtp_cpu_permille` | gauge | sampled CPU utilisation, 0–1000 |
| `siphon_rtp_draining` | gauge | 1 when the node is draining (rejecting new sessions), else 0 |
| `siphon_rtp_jemalloc_allocated_bytes` | gauge | live heap (jemalloc `stats.allocated`) |

Gauges are read on demand at scrape time from the live registries (`Metrics::render` takes a
[`LiveGauges`]); counters are monotonic and incremented on the control path. The jemalloc gauge is
the leak signal — in production alert on `rate(siphon_rtp_jemalloc_allocated_bytes[30m]) > 0` while
`siphon_rtp_sessions` is flat (jemalloc retains freed pages, so RSS is too noisy).

## 2. RTCP reception reports (RFC 3550 §6.4.1)

Each conference participant gets a periodic (~5 s) per-leg RTCP **Sender Report** on its rtcp-mux
endpoint (RFC 5761), carrying the NTP↔RTP mapping (lip-sync) + sender counts, plus a **reception
report** block on that participant's inbound stream:

- **cumulative lost** + **extended highest sequence** — packet loss the engine observed.
- **interarrival jitter** — RFC 3550 §A.8, in RTP-clock units. Computed from each datagram's
  *receive-time* arrival (`RxPacket.arrival`, stamped at the datapath, **not** at actor-ingest — so
  it reflects network timing, not queueing latency) versus the packet's RTP timestamp.
- **LSR / DLSR** — middle 32 bits of the last inbound SR's NTP timestamp, and the delay since
  receiving it (1/65536 s), so the peer can derive round-trip time. The engine consumes inbound SRs
  to populate these.

The plain 2-party relay path forwards RTCP untouched — there the endpoints compute their own
statistics; the engine only terminates (and thus measures) RTP where it decodes/mixes (conferences,
transcoding bridges).

## 3. `call_quality` control events (MOS)

Every few seconds the engine pushes one `Event::CallQuality` per active leg to SIPhon over the
JSON control channel, so the control plane sees live quality without parsing RTCP itself. It fires
for conference participants (keyed by `conference_id`) and for ordinary 2-party relay and transcode
legs (keyed by `call_id`); exactly one identifier is present, matching the
[JSON control](control/json.md) and [monitoring](cookbook/monitoring.md) contract:

```json
{ "event": "call_quality", "conference_id": "room-7", "from_tag": "alice",
  "jitter_ms": 1.125, "loss_percent": 0.0, "mos": 4.41 }
```

- **jitter_ms** — the RFC 3550 interarrival jitter, in milliseconds.
- **loss_percent** — residual inbound loss the listener hears (jitter-buffer concealed/discarded
  slots over `expected = highest − base + 1`).
- **mos** — MOS-CQE (1.0–4.5) from the **ITU-T G.107 E-model** in [`siphon-rtp-hep`'s `mos`
  module](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-hep/src/mos.rs) — the one canonical estimator, shared with the HEP
  export path:

  ```text
  R   = 93.2 − Id − Ie-eff       (default Ro−Is = 93.2; A = 0; relay has no echo path)
  MOS = f(R)                      (G.107 Annex B)
  ```

  `Id` is the delay impairment (jitter feeds in via the de-jitter buffer, ≈ 2× jitter, and measured
  one-way network delay now feeds `Id` too), `Ie-eff` the
  codec impairment (G.113 Appendix I `Ie`/`Bpl`) degraded by loss. The conference maps each leg's
  payload type to a `siphon_rtp_hep::mos::Codec` and feeds the measured loss + jitter in.

### Limitations / roadmap

- **One-way network delay is now measured** on the conference path: RTT is derived from inbound
  reception reports (RRs) and folded into the G.107 MOS, so MOS now reflects jitter, loss, codec,
  and measured one-way delay. The plain-relay path still uses delay `0` (only the conference path
  measures RTT).
- **Per-codec impairment** beyond the G.711 default is a small follow-up (the override hook exists).
- **Wideband** codecs (G.722, AMR-WB) want the G.107.1 wideband extension; the narrowband model here
  is an approximation for them.
- **2-party relay and transcode** legs now emit `call_quality` too, keyed by `call_id` (conferences
  by `conference_id`): the transcode path on a ~5 s tick, the plain-relay path from each endpoint's
  RTCP reception reports.
- **HEP3 / Homer** RTCP export ships (enabled by `SIPHON_RTP_HEP_COLLECTOR`, with
  `SIPHON_RTP_HEP_AGENT_ID`), tapping relayed RTCP on the plain-relay path and sending it as HEP3
  captures. The G.107 MOS now rides BOTH the `call_quality` control events AND the exported HEP
  type-35 QoS report (alongside the raw RTCP capture).

## 4. End-of-call CDR (`call_summary` / the `siphon_rtp::cdr` log block)

At teardown — controller `delete` or the media-timeout reap — the engine emits one CDR per call: a
`siphon_rtp::cdr` log block, and its structured twin `Event::CallSummary` on the control channel, so
the SBC merges the media figures with its own SIP record. Both carry the datapath packet/byte counters
plus, where a userspace media actor measured it, the RFC 3550 loss/jitter and the G.107 MOS shape.

**One entry per party, not per socket.** A two-party call has two: the near (offerer, `from_tag`) leg
and the far (answerer, `to_tag`) leg, each with its own counters and its own inbound quality. A
**single-leg** call — one the engine answered itself, with no far party (IVR, announcement, echo, and
every voice-AI call: `answer_local`, or an offer the controller put in its own 200 OK) — has exactly
**one**: the caller. It carries the call's whole packet/byte total and the caller's measured quality.

So a consumer should iterate `legs` and key on `tag`; one that assumes `legs[1]` exists breaks on every
IVR and voice-AI call.

An `answer_local` call binds one socket pair, on the leg the answer advertises — there is no second
party and so no second leg. An *unanswered* `offer` is the one single-leg shape that still holds two:
the offer allocated a B-facing leg in case a B side answered, and none did. Its idle leg contributes
zero to the totals above.

## 5. RFC 4103 Real-Time Text content QoS on HEP

When a call negotiated a plaintext `m=text` (RFC 4103) stream **and** a text-observability feature
promoted it to the userspace processor (recording, or `text_events`), the engine ships that leg's
**text content QoS** to the same HEP collector at **end of call** — the wire complement to the
`CallSummary` event's per-leg `text` field. One report per direction that carried a measured stream:
the near leg is the offerer's A→B stream, the far leg the answerer's B→A stream.

HEP3 has **no** standard field or chunk for Real-Time Text QoS, so rather than invent a vendor chunk
(uningestable, and a collision risk against the generic chunk ids) this rides the **existing**
report-capture transport that the voice MOS report already uses: the **same** `protocol_type` **35**
(`REPORT_JSON`), the **same** `PAYLOAD` chunk (`0x000f`) carrying a JSON document, correlated by the
**same** `CORRELATION_ID` chunk (`0x0011`) = call-id — so a passive collector groups the text report
with the rest of the call, exactly as it does the raw-RTCP and voice-QoS captures. This does not alter
the wire shape of any existing HEP packet; a text report is its own datagram.

Only the **JSON schema** is a siphon-rtp extension, and it self-describes: the first field is a
discriminator `"report":"rtt-text"`, so a collector routes it without a full parse and never confuses
it with the voice report (which has no `report` field and instead carries `mos`/`codec`). The payload:

```json
{"report":"rtt-text","correlation_id":"<call-id>","tag":"<leg-tag>","direction":"a_to_b",
 "packets":7,"characters":21,"missing_markers":1,"recovered_from_redundancy":2}
```

- **direction** — `"a_to_b"` (offerer → answerer) or `"b_to_a"`; **tag** is the tag of the leg that
  *sent* the text (mirrors the CDR's per-direction attribution).
- **packets** — RTP packets accepted on this leg's inbound T.140 stream (post source-gate).
- **characters** — UTF-8 characters delivered after RED depacketization + T.140 reassembly, including
  redundancy-recovered characters and the U+FFFD missing-text markers.
- **missing_markers** — U+FFFD markers inserted for gaps redundancy could not recover (RFC 4103 §5.3):
  the unrecoverable-loss signal.
- **recovered_from_redundancy** — generations recovered from RFC 2198 RED redundancy (RFC 4103 §4.2).

An audio-only call, or a text stream left on the in-kernel relay (never measured), ships no such
report. The exact HEP3 byte layout (magic + total length + every generic TLV chunk) is pinned by a
byte-exact test in [`siphon-rtp-hep`](../crates/siphon-rtp-hep/src/lib.rs); the JSON schema lives in
that crate's [`text_report`](../crates/siphon-rtp-hep/src/text_report.rs) module. To eyeball a capture,
Wireshark's HEP dissector decodes the chunks and shows the JSON payload verbatim.

See also [`security-and-nat.md`](security-and-nat.md) for the relay's accept/latch/forward model.
