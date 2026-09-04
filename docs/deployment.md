# Deployment & operations

siphon-rtp ships as one statically linkable daemon binary, `siphon-rtp`. Control front-ends,
datapath, codecs, SRTP/DTLS, TURN and the media plane all compile into that one artifact. No
rtpengine, no kernel module to build, no C libraries to package.

This page is the single-node "how": install, the real configuration surface, and the operations
runbook. For multi-node topologies (dispatcher scale-out, drain-aware upgrades, warm-standby HA),
read [Scaling, clustering & HA](scaling-and-ha.md).

- [Install](#install)
- [The CLI](#the-cli)
- [Environment variables](#environment-variables)
- [The config file](#the-config-file)
- [Production posture](#production-posture)
- [docker-compose profiles](#docker-compose-profiles)
- [Operations runbook](#operations-runbook)

---

## Install

From crates.io:

```sh
cargo install siphon-rtp
siphon-rtp --control 127.0.0.1:8080
```

AMR-NB / AMR-WB transcoding is behind the `amr` Cargo feature, off by default for patent posture
(see [Codec licensing & patents](codec-licensing.md)):

```sh
cargo install siphon-rtp --features amr
```

From source:

```sh
git clone https://github.com/siphon-project/siphon-rtp
cd siphon-rtp
cargo build --release -p siphon-rtp          # add --features amr for AMR transcoding
./target/release/siphon-rtp --control 127.0.0.1:8080
```

In a container. The `Dockerfile` builds a fully static musl binary onto a distroless base, so the
runtime image is the binary and nothing else:

```sh
docker build -t siphon-rtp .
docker run --rm -p 8080:8080 siphon-rtp
# with AMR compiled in:
docker build --build-arg CARGO_FEATURES=amr -t siphon-rtp:amr .
```

Tagged releases publish the same image to GHCR (`ghcr.io/siphon-project/siphon-rtp`, semver tags)
and attach binary tarballs for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` to the
GitHub release, alongside an SBOM ([Supply chain & SBOM](supply-chain.md)).

Note that *relaying* a codec never needs the codec: passthrough forwards any payload type without
running codec code. The `amr` feature only matters when the engine transcodes.

## The CLI

The full flag surface of the default `siphon-rtp` binary, verbatim from `siphon-rtp --help`. The
default binary has **no `--xdp` flag** and always runs the UDP datapath ([Datapath](datapath.md));
the XDP datapath ships as the separate `siphon-rtp-xdp-daemon` binary, which adds `--xdp-interface`
(and `--xdp-queue`) on top of this same flag surface.

| Flag | Default | What it does |
|---|---|---|
| `--config <PATH>` | none | Optional TOML config file (rtpengine-style declarative config). Missing or malformed file is a fatal startup error. |
| `--control <ADDR>` | `127.0.0.1:8080` | Native JSON-over-TCP control listener (length-prefixed JSON, async events). |
| `--ng <ADDR>` | off | rtpengine NG/bencode control listener (UDP). Off unless given; rtpengine's conventional port is 22222. |
| `--relay-bind-ip <IP>` | loopback | Bind relay/media sockets to this IP. The production posture; without it media only reaches loopback peers. |
| `--advertise-ip <IP>` | bound IP | Public IP advertised in offer/answer SDP (`c=`/`m=`/`o=`/ICE candidate) instead of the bound IP, for a single-homed host behind 1:1 NAT (e.g. an Elastic IP): bind private with `--relay-bind-ip`, advertise the public IP here, same port. Emit-only (does not affect the bind, the source gate, the latch, or TURN). For a multi-network split use `[[interface]]` + the control `direction` instead. |
| `--port-min <PORT>` / `--port-max <PORT>` | OS-ephemeral | Bounded media port range (rtpengine `port-min`/`port-max` parity). Both-or-neither; a half-set or inverted range is a fatal startup error. Required for HA takeover. |
| `--media-dscp <DSCP>` | `EF` | DiffServ marking (RFC 2474) on outbound media. A name (`EF`, `CS3`, `AF41`, `VA`, `BE`, …) or a raw `0`–`63`. `EF` is TOS byte 184 — Asterisk's `tos_audio`, rtpengine's `--tos`. `BE`/`0` disables marking and leaves the TOS byte untouched. Applies to every egress path (UDP sockets, AF_XDP TX, in-kernel XDP_TX); never to the control, metrics, HEP or WS sockets. |
| `--metrics-addr <ADDR>` | off | Prometheus + health HTTP: `GET /metrics`, `GET /healthz`, `GET /readyz`. |
| `--max-control-rps <N>` | `200` | Per-connection control request cap (requests/second). `0` disables the limit. |
| `--media-timeout-secs <N>` | `30` | Reap a call after N seconds with no accepted media (dead-path detection). |
| `--shutdown-grace-secs <N>` | `25` | Bounded drain of live calls on SIGTERM/SIGINT before exiting. |
| `--node-id <STRING>` | `$HOSTNAME`, else `siphon-rtp` | Stable cluster node id reported by `load` / `node_info`. |
| `--max-sessions <N>` | `0` (unlimited) | Advertised session capacity for cluster load scoring. Does not itself cap admission. |
| `--turn-udp <ADDR>` / `--turn-tcp <ADDR>` / `--turn-tls <ADDR>` | off | Built-in TURN server listeners (`turn:` / `turns:`, RFC 5766/8656). |
| `--turn-tls-cert <PATH>` / `--turn-tls-key <PATH>` | none | PEM certificate chain and private key for the `turns:` listener. |
| `--turn-relay-ip <IP>` | datapath-assigned | Public IP advertised in XOR-RELAYED-ADDRESS when the bound IP is not the reachable one (NAT'd host). |
| `--stun-server <ADDR>` | none | STUN server probed for a server-reflexive ICE candidate (RFC 8445 §5.1.1). Repeatable. |
| `--ice-full` | off | Run the full RFC 8445 ICE agent (checklists, connectivity checks, nomination) instead of ICE-lite responder-only. |
| `--ice-consent` | off | RFC 7675 consent freshness: probe the validated pair and tear the call down on consent loss. |
| `--consent-interval-secs <N>` | — | Consent-check interval; only meaningful together with `--ice-consent`. |
| `--consent-timeout-secs <N>` | `30` | Consent timeout before teardown (RFC 7675 §5.1); only with `--ice-consent`. |

## Environment variables

Secrets are deliberately not flags and not config-file keys, so they never land in argv or a
world-readable file:

| Variable | Effect |
|---|---|
| `SIPHON_RTP_CONTROL_SECRET` | Enables control-plane authentication: a JSON-over-TCP connection must send `authenticate` with this token before any other verb is honoured. The NG front-end is never authenticated (see the runbook). |
| `SIPHON_RTP_TURN_REALM` + `SIPHON_RTP_TURN_SECRET` | Enable the built-in TURN server (coturn `static-auth-secret` REST credential profile). At least one `--turn-*` listener must then be given. |
| `SIPHON_RTP_HEP_COLLECTOR` (+ optional `SIPHON_RTP_HEP_AGENT_ID`) | Export relayed RTCP as HEP3 to a Homer / VoIPmonitor collector (`ip:port`). |
| `RUST_LOG` | `tracing` env-filter directive (e.g. `info,siphon_rtp_engine=debug`). Wins over the config file's `log_filter`. |

## The config file

Everything the CLI can set, the file can set too (`--config /etc/siphon-rtp/config.toml`). Keys
mirror the long flags (`--relay-bind-ip` becomes `relay_bind_ip`). Precedence, highest wins:

1. an explicit CLI flag (something you actually typed),
2. the config file,
3. the built-in default.

Unknown or mistyped keys are a hard parse error, not a silently ignored line. A fully documented
sample ships in the repo as
[`crates/siphon-rtp-engine/config.example.toml`](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-engine/config.example.toml).

```toml
# /etc/siphon-rtp/config.toml
control       = "192.0.2.10:8080"
ng            = "192.0.2.10:22222"
relay_bind_ip = "198.51.100.10"
port_min      = 30000
port_max      = 40000
metrics_addr  = "192.0.2.10:9090"
node_id       = "rtp-1"
max_sessions  = 4000
log_filter    = "info"
```

## Production posture

The defaults are safe for a lab, not useful for production: the control plane binds loopback and,
more importantly, so do the media sockets. A production node looks like this (192.0.2.0/24 as the
management network, 198.51.100.10 as the routable media address):

```sh
export SIPHON_RTP_CONTROL_SECRET="<shared secret>"
siphon-rtp \
  --control 192.0.2.10:8080 \
  --relay-bind-ip 198.51.100.10 \
  --port-min 30000 --port-max 40000 \
  --metrics-addr 192.0.2.10:9090 \
  --node-id rtp-1 \
  --max-sessions 4000
```

Why each of these:

- **`--relay-bind-ip`** is the switch from lab to production. Media endpoints bind this IP and the
  rewritten SDP advertises it (RFC 3264 offer/answer), so real peers can reach the relay. Leave it
  unset and everything still works, but only against loopback peers.
- **`--advertise-ip`** covers the host whose reachable address is not a local one — a cloud host
  behind 1:1 NAT (e.g. an AWS Elastic IP). Bind the private/routable local IP with `--relay-bind-ip`
  (the XDP fast path needs a real local IPv4), and advertise the public IP here; the rewritten SDP
  hands peers the public address while the socket keeps binding private, same port. It is emit-only:
  the source gate and the symmetric-RTP latch still key on the real remote/bound addresses. For a
  host that fronts two networks (a private core side and a public access side), define named
  `[[interface]]` entries in the config file instead and let the control `direction` pair pick the
  interface per leg — the single `--advertise-ip` is the one-interface shorthand.
- **`--port-min` / `--port-max`** pins media to a firewallable UDP window. Size it for your
  concurrency: up to 4 ports per call (RTP + RTCP on each leg), 2 with rtcp-mux (RFC 5761). A pool
  of 30000-40000 comfortably covers ~2,500 calls at the worst case. A deterministic range is also
  the prerequisite for warm-standby HA takeover
  ([Scaling, clustering & HA](scaling-and-ha.md#warm-standby-ha)).
- **`--media-dscp`** is what makes the network treat the media as voice. It defaults to `EF`
  (DSCP 46, RFC 3246 — RFC 4594 §4.1 assigns it the Telephony service class), which is the TOS byte
  184 you already set as `tos_audio` in Asterisk or `tos` in rtpengine, so a node that configures
  nothing still marks correctly. Set it to `BE` only where something upstream marks for you — that
  leaves the TOS byte untouched rather than writing an explicit zero over an existing marking. Note
  that marking is a *request*: an access network that does not trust or honour DSCP will bleach it
  at its edge, and marking alone does not create capacity. It is the media plane only; the control,
  metrics, HEP and WS-bridge sockets are never marked.
- **`--metrics-addr`** on the management interface, never the public one. It serves the readiness
  probe your dispatcher and orchestrator need.
- **Control listeners stay on a trusted network.** Set `SIPHON_RTP_CONTROL_SECRET` for the JSON
  front-end. The NG front-end (`--ng`) is unauthenticated by design, exactly like rtpengine's, so
  it belongs on a private control VLAN or loopback only.
- **`--node-id` / `--max-sessions`** give the SIP dispatcher a stable identity and a capacity
  figure to rank nodes by (`load` / `node_info`).
- Add the `--turn-*` listeners only if you terminate WebRTC and need TURN
  (see the [WebRTC cookbook](cookbook/webrtc.md)).

A minimal systemd unit:

```ini
[Unit]
Description=siphon-rtp media engine
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/siphon-rtp --config /etc/siphon-rtp/config.toml
Environment=RUST_LOG=info
# secrets.env (mode 0600) carries SIPHON_RTP_CONTROL_SECRET and the TURN/HEP variables.
EnvironmentFile=/etc/siphon-rtp/secrets.env
Restart=on-failure
# SIGTERM triggers the bounded drain; give it slightly more than --shutdown-grace-secs.
TimeoutStopSec=30
User=siphon-rtp
AmbientCapabilities=
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

No capabilities are needed: the UDP datapath is plain sockets on unprivileged ports.

## docker-compose profiles

The repo's `docker-compose.yml` carries two profiles:

```sh
docker compose --profile dev up --build     # shell image + veth pair, BPF caps granted
docker compose --profile prod up --build    # distroless, host networking
```

- **dev** builds the `runtime-dev` image (adds `iproute2` and an entrypoint that mounts bpffs and
  creates a `siphon0`/`siphon-peer` veth pair) and grants `NET_ADMIN`/`BPF`/`SYS_ADMIN` plus
  unlimited memlock. Those caps are what running the separate `siphon-rtp-xdp-daemon` needs; the
  default image ships the UDP `siphon-rtp` build, which does not use them.
- **prod** runs the distroless `runtime` image with `network_mode: host` and requires
  `SIPHON_RTP_TURN_REALM` / `SIPHON_RTP_TURN_SECRET` to be set (it refuses to start with them
  unset; the dev profile has insecure defaults). It starts the TURN listeners on 3478.

Two honest caveats:

1. The `CARGO_FEATURES` build arg only toggles `amr` (leave it empty or set it to `amr`). **XDP is a
   separate binary (`siphon-rtp-xdp-daemon`), never a Cargo feature** — there is no `xdp` feature, and
   passing one fails the build. Both profiles run the UDP datapath ([Datapath](datapath.md)).
2. The compose commands do not pass `--relay-bind-ip`, so relayed media stays on loopback. For
   real peers, append `--relay-bind-ip <host IP>` (and a `--port-min`/`--port-max` window) to the
   `command:` list, which is trivial under host networking in the prod profile.

## Operations runbook

### Graceful drain and rolling upgrades

Two mechanisms, used in sequence:

1. **The `drain` control verb** (native JSON and NG; `undrain` reverses it). A draining node
   refuses the two session-creating verbs, `offer` and `conference_join`, with
   `"node is draining; not accepting new sessions"`. Everything else keeps working: `answer` for
   calls already in setup, `delete`, `query`, media control on live calls, and the census verbs.
   `/readyz` flips to `503` and the `siphon_rtp_draining` gauge goes to `1`, so dispatchers and
   orchestrators stop routing to it without being told twice.
2. **SIGTERM / SIGINT.** The daemon immediately stops accepting new control connections, then
   waits up to `--shutdown-grace-secs` (default 25) for the live session count to reach zero
   before exiting. Sessions still live when the grace elapses are torn down abruptly (and logged).

A rolling upgrade is therefore:

```text
1. send `drain`                      # readyz -> 503, no new sessions
2. watch siphon_rtp_sessions -> 0    # existing calls run to completion
3. SIGTERM                           # bounded tail for stragglers
4. replace the binary / image, start # a fresh process starts undrained
```

In Kubernetes: probes on `/healthz` and `/readyz`, a `preStop` hook that issues `drain` and waits,
and `terminationGracePeriodSeconds` comfortably above `--shutdown-grace-secs`.

### Health probes

Served on `--metrics-addr`:

- **Liveness: `GET /healthz`** answers `200` for as long as the process is alive. It does *not*
  flip during drain; a liveness probe that failed mid-drain would make the orchestrator kill the
  node before it finished draining.
- **Readiness: `GET /readyz`** answers `200` normally and `503` while draining, so load balancers
  and Kubernetes pull the node from rotation the moment you issue `drain`.

### Media-timeout reaping

A call that stops receiving media is dead signalling-wise sooner or later, but the engine does not
wait for the proxy to notice: after `--media-timeout-secs` (default 30) with no *accepted* media,
the call is reaped and the owning controller receives a `media_timeout` event on the control
channel. "Accepted" is measured after the source gate, so an attacker spraying packets at a media
port cannot keep a dead call alive (see
[Security & NAT design](security-and-nat.md), layer 6). Conference participants are reaped on the
same sweep and empty rooms are torn down.

### Control-plane protection

- **Rate limiting.** Each control connection gets a token bucket of `--max-control-rps`
  requests/second (default 200, `0` disables). A breaching request is answered
  `Error { "rate limit exceeded" }` before any work is done, and counted in
  `siphon_rtp_control_rate_limited_total`. A legitimate SIPhon controller never gets near the
  default; a flood cannot drive engine work or probe authentication.
- **Authentication.** With `SIPHON_RTP_CONTROL_SECRET` set, a JSON-over-TCP connection must send
  the `authenticate` verb with the matching token before anything else is honoured (the comparison
  is constant-time). The NG/bencode front-end has no authentication, matching rtpengine, so treat
  `--ng` as trusted-network-only.
- **Ownership.** A call is private to the control connection that created it. Another connection
  cannot query, delete, checkpoint or otherwise touch it (it sees `unknown call`), so a
  compromised or misbehaving second controller cannot enumerate calls.

### Metrics and alerting

Scrape `GET /metrics` (Prometheus text exposition). The full series list, RTCP quality reporting
and the G.107 MOS pipeline are documented in
[Observability & call quality](observability.md). The operationally load-bearing alerts:

| Signal | Alert when | Why |
|---|---|---|
| `siphon_rtp_jemalloc_allocated_bytes` | `rate(...[30m]) > 0` while `siphon_rtp_sessions` is flat | A real leak. Gate on jemalloc `allocated`, not RSS (jemalloc retains freed pages). |
| `siphon_rtp_control_errors_total` | sustained rate > 0 | The proxy and the engine disagree about something; read the engine log. |
| `siphon_rtp_control_rate_limited_total` | any increase | Either a misbehaving controller or a flood at the control port. |
| `siphon_rtp_load_permille` | approaching 1000 | Node saturated by sessions or CPU; the dispatcher should already be steering away. |
| `siphon_rtp_draining` | `1` outside a planned upgrade | Someone (or some automation) drained the node. |

### Logs

Structured `tracing` output to stdout/journald. Filter with `RUST_LOG`
(e.g. `RUST_LOG=info,siphon_rtp_engine=debug`); the config file's `log_filter` applies only when
the environment sets nothing.
