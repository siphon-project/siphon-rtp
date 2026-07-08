# Scaling, clustering & HA

How to run more than one siphon-rtp node, and what "cluster" honestly means here.

siphon-rtp is a **single-node media engine scaled horizontally by the SIP layer**, the same
operational model as an rtpengine fleet. There is no engine-to-engine mesh, no replication
protocol, no shared session state between running nodes. The SIP proxy (SIPhon, or
Kamailio/OpenSIPS via the NG front-end) is the dispatcher: it picks a node per call, polls each
node's load, drains nodes for upgrades, and, if you run the warm-standby model, carries call
snapshots from an active node to its standby.

What the engine gives that dispatcher:

- **load surfacing**: the `load` and `node_info` control verbs plus matching Prometheus gauges,
- **drain awareness**: `drain` / `undrain` and a drain-aware `/readyz`, for zero-downtime rolling
  upgrades,
- **warm-standby HA**: `checkpoint` / `restore` control verbs plus a deterministic media port
  range, so a standby behind a floating IP rebuilds a call on the exact same ports.

All of it is exposed on both control front-ends. `load`, `node info`, `drain`, `undrain`,
`checkpoint` and `restore` are siphon-rtp *extensions* to the NG protocol; stock rtpengine does not
have them ([rtpengine NG / bencode](control/ng.md)).

---

## Scale-out: the dispatcher model

Each engine is independent. Adding capacity means adding nodes and telling the SIP layer about
them; a call lives on exactly one engine from `offer` to `delete`, so the dispatcher only has to
be sticky per call-id, which every rtpengine-style module already is.

### Ranking nodes: the `load` verb

Poll `load` on each node (native JSON shown; the NG form returns the same fields with hyphenated
keys):

```json
{
  "node_id": "rtp-1",
  "sessions": 812,
  "max_sessions": 4000,
  "load_permille": 247,
  "transcode_sessions": 140,
  "cpu_permille": 247,
  "jemalloc_allocated_bytes": 734003200,
  "draining": false
}
```

- **`load_permille`** is the number to rank by: the higher of session utilization
  (`sessions / max_sessions`) and host CPU, in per-mille (0..=1000). A node that is CPU-bound at a
  low session count (heavy transcoding) still reports busy. With `--max-sessions 0` (unlimited)
  only CPU drives the score.
- **`cpu_permille`** is sampled from `/proc/stat` about once a second; the key is absent until the
  first sample lands.
- **`transcode_sessions`** counts the expensive decode/re-encode subset, useful when you dedicate
  nodes to transcoding.
- **`max_sessions`** is advertised capacity for scoring only. It does not cap admission; the
  per-client quota and the media port pool do that.

### Capability-aware placement: `node_info`

`node_info` returns the static identity: `node_id`, `version`, `media_addresses` (the routable
relay IP from `--relay-bind-ip`), the compiled-in `codecs` and `features` lists, `max_sessions`,
and the live `draining` flag. A dispatcher can use it to, for example, send AMR transcode calls
only to nodes built with the `amr` feature, or to verify a fleet is on the same version before an
HA pairing.

### The same numbers, on Prometheus

Everything a dispatcher polls is also exported on `--metrics-addr` so operators can graph and
alert without touching the control plane: `siphon_rtp_sessions`, `siphon_rtp_max_sessions`,
`siphon_rtp_transcode_sessions`, `siphon_rtp_load_permille`, `siphon_rtp_cpu_permille` (once
sampled), and `siphon_rtp_draining`. See
[Observability & call quality](observability.md) for the full series list.

---

## Rolling upgrades: drain-aware readiness

`drain` puts a node into a refuse-new-work mode without touching live calls:

- `offer` and `conference_join` are rejected with
  `"node is draining; not accepting new sessions"`,
- everything else keeps working: `answer` for calls mid-setup, `delete`, `query`, media control,
  the census and cluster verbs,
- `/readyz` answers `503` (liveness `/healthz` stays `200`), and `siphon_rtp_draining` goes to 1,
- `undrain` reverses it.

So the upgrade loop per node is: `drain`, wait for `siphon_rtp_sessions` to reach zero (calls end
naturally), `SIGTERM` (which itself drains for up to `--shutdown-grace-secs`), replace, start. The
sequencing details and the Kubernetes wiring are in the
[deployment runbook](deployment.md#graceful-drain-and-rolling-upgrades).

---

## Warm-standby HA

Losing a node mid-call normally drops its calls; the endpoints notice via RTP timeout and the
proxy re-INVITEs or the users redial. For deployments where that is not acceptable, siphon-rtp
supports a **proxy-mediated warm-standby** model: the negotiated state of a call can be
checkpointed off the active node and rebuilt on a standby that re-binds the exact same media
ports, so after a floating-IP swing the peers keep sending to the same `ip:port` and media
resumes without any SIP signalling.

### The ingredients

1. **A floating IP** (keepalived/VRRP or your cloud's equivalent) shared by the active/standby
   pair. Both nodes run with `--relay-bind-ip` on that address.
2. **The same `--port-min`/`--port-max` range on both nodes.** Ports in a snapshot are absolute;
   the standby must be able to bind exactly them. Without a configured range the datapath uses
   OS-ephemeral ports and `restore` fails with `PortUnavailable`.
3. **The SIP proxy as the state carrier.** `checkpoint` returns an opaque JSON blob per call; the
   proxy stores it (keyed by call-id) and hands it back to `restore` on the standby at failover.
   The engine owns the blob format and version-guards it, so the proxy never parses it.

### The flow

```text
active node                         proxy                        standby node
    |  <- checkpoint {call-id} ------ |                               |
    |  -- snapshot blob ------------> | (stores blob)                 |
    |                                 |                               |
    X  node dies                      | (VRRP moves the floating IP)  |
                                      | -- restore {snapshot} ------> |
                                      | <- ok ------------------------|
                        peers keep sending to the same ip:port; media flows
```

`checkpoint` is ownership-gated like `query`: only the control client that created the call can
snapshot it. `restore` rejects a blob whose format version it does not understand (keep the pair
on compatible builds; upgrade the standby first), rejects a call-id that already exists on the
target, and rolls back cleanly if any port bind or flow install fails.

### What a snapshot contains, and what it deliberately does not

In: the call identity (call-id, tags), each leg's **local media ports** and the peers' negotiated
remote addresses, the resolved pipeline and codecs (including the AMR-WB `mode-set` egress mode),
ICE-lite credentials, the SDES crypto attributes, the SRTP rollover counters and SRTCP index
(RFC 3711 §3.3.1, not recoverable from the wire), and the installed forward rules with their
source-gate and latch policy.

Out: node-local handles (sockets, actor mailboxes, datapath endpoint ids; re-allocated on
restore) and ephemeral media state (jitter buffers, resampler/codec history, the learned latch).
Those restart fresh on the standby, so expect at most a brief glitch at takeover, not silence.

!!! warning "Snapshots contain key material"
    A secure call's snapshot carries the SRTP master keys and salts (hex-encoded) so the standby
    can re-key the bridge. Treat stored blobs like the keys they contain: authenticated control
    connections (`SIPHON_RTP_CONTROL_SECRET`), encrypted storage, and no logging of snapshot
    bodies.

### Restore coverage, honestly

| Pipeline | Restorable today? | Notes |
|---|---|---|
| Plain relay (passthrough) | **Yes** | Forward rules, source gates and latch policies reinstalled; latch re-learns. |
| SDES-SRTP bridge (RFC 3711/4568) | **Yes** | Bridge rebuilt and re-keyed from the snapshot; per-SSRC ROC and SRTCP index resume, so packets stay decryptable across the swing. |
| Plaintext transcode | **Yes** | Transcode actor rebuilt from the codec snapshots; codec/jitter state starts fresh. |
| Secure transcode (`SrtpMedia`) | **Yes** | Now supported and integration-tested: restore rebuilds the SRTP keys + per-SSRC rollover and the transcode actor. |
| WebSocket bridge (`Ws`) | **No** | Same reason; additionally the WS client connection cannot be resumed. |
| DTLS-SRTP (RFC 5764) | **No** | Cannot even be checkpointed: the keys are derived from the DTLS handshake and cannot be exported into a snapshot. A restored leg would need a full re-handshake, which requires signalling. |
| Conferences | **No** | `checkpoint` operates on calls; conference rooms and participants are not covered. |

Each supported pipeline's takeover is integration-tested end to end (checkpoint, kill the owner,
restore on a second engine bound to the same range, verify media flows), not just unit-tested
serialization.

### What this model is not

It is not state replication and it is not automatic. The engine gives you the two verbs and
deterministic ports; failure detection, the checkpoint cadence (at answer time, periodically, or
both), blob storage, and the failover sequencing all belong to the proxy/orchestration layer.
Media sent during the detection-plus-swing window is lost, bounded by your VRRP timers. And a
standby is warm, not hot: it holds no state until `restore` hands it some.

---

## Rules of thumb

- Scale out with the dispatcher, rank nodes by `load_permille`, and set an honest
  `--max-sessions` so session pressure shows up in the score before CPU does.
- Always run a bounded `--port-min`/`--port-max` in production, HA or not: it makes the media
  plane firewallable and keeps the HA option open.
- Drain before you stop. It costs one control verb and turns an upgrade into a non-event.
- Reserve warm-standby HA for the call types it actually covers today (relay, SDES-SRTP bridge,
  plaintext transcode, secure transcode). For everything else, fast failover of *new* calls via
  the dispatcher is the honest posture.

See also: [Deployment & operations](deployment.md) for the single-node runbook,
[Native JSON-over-TCP](control/json.md) and [rtpengine NG / bencode](control/ng.md) for the verb
reference, [Security & NAT design](security-and-nat.md) for what the reinstalled forward rules
enforce.
