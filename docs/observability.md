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

Every ~5 s the conference pushes one `Event::CallQuality` per active participant to SIPhon over the
JSON control channel — so the control plane sees live quality without parsing RTCP itself:

```json
{ "event": "call_quality", "conference_id": "room-7", "from_tag": "alice",
  "jitter_ms": 1.125, "loss_percent": 0.0, "mos": 4.41 }
```

- **jitter_ms** — the RFC 3550 interarrival jitter, in milliseconds.
- **loss_percent** — residual inbound loss the listener hears (jitter-buffer concealed/discarded
  slots over `expected = highest − base + 1`).
- **mos** — MOS-CQE (1.0–4.5) from the **ITU-T G.107 E-model** in [`siphon-rtp-hep`'s `mos`
  module](../crates/siphon-rtp-hep/src/mos.rs) — the one canonical estimator, shared with the HEP
  export path:

  ```text
  R   = 93.2 − Id − Ie-eff       (default Ro−Is = 93.2; A = 0; relay has no echo path)
  MOS = f(R)                      (G.107 Annex B)
  ```

  `Id` is the delay impairment (jitter feeds in via the de-jitter buffer, ≈ 2× jitter), `Ie-eff` the
  codec impairment (G.113 Appendix I `Ie`/`Bpl`) degraded by loss. The conference maps each leg's
  payload type to a `siphon_rtp_hep::mos::Codec` and feeds the measured loss + jitter in.

### Limitations / roadmap

- **One-way network delay is not yet measured** (passed as `0`), so MOS reflects jitter + loss +
  codec but not absolute latency. Deriving it needs RTT from inbound RRs (not yet consumed).
- **Per-codec impairment** beyond the G.711 default is a small follow-up (the override hook exists).
- **Wideband** codecs (G.722, AMR-WB) want the G.107.1 wideband extension; the narrowband model here
  is an approximation for them.
- **2-party / transcoding-bridge** legs don't yet emit `call_quality` (conference-only today).
- A **HEP3/Homer** export of RTCP + MOS is a candidate but lower priority where VoIPmonitor sniffs
  the media passively.

See also [`security-and-nat.md`](security-and-nat.md) for the relay's accept/latch/forward model.
