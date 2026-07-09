# Migrating from rtpengine

siphon-rtp speaks rtpengine's NG control protocol on the wire: the `<cookie> <bencode-dict>`
datagram format, the same command vocabulary, the same reply shapes. A Kamailio or OpenSIPS
deployment using the `rtpengine` module points its control socket at siphon-rtp and keeps its
routing script unchanged. This page is the practical cutover guide: what maps one-to-one, what
siphon-rtp adds, what it does not expose, and what to validate before you carry production
traffic.

- [The drop-in cutover](#the-drop-in-cutover)
- [NG command parity](#ng-command-parity)
- [Flags and dictionary keys that are honoured](#flags-and-dictionary-keys-that-are-honoured)
- [The differences that matter](#the-differences-that-matter)
- [What to validate after cutover](#what-to-validate-after-cutover)

---

## The drop-in cutover

Start the engine with the NG listener enabled (off by default; 22222 is rtpengine's conventional
port) and a production media posture:

```sh
siphon-rtp \
  --control 127.0.0.1:8080 \
  --ng 192.0.2.10:22222 \
  --relay-bind-ip 198.51.100.10 \
  --port-min 30000 --port-max 40000
```

Kamailio, unchanged apart from the socket address:

```
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:192.0.2.10:22222")
```

OpenSIPS's `rtpengine` module takes the same `rtpengine_sock` parameter. Your existing
`rtpengine_offer()` / `rtpengine_answer()` / `rtpengine_manage()` / `rtpengine_delete()` calls,
including their flag strings, are what the parity below is measured against. The module's normal
keepalive pings tell you immediately whether the engine is reachable: siphon-rtp answers NG
`ping` with `pong` like rtpengine does.

Both control front-ends drive the same engine, so you can migrate signalling to SIPhon's native
JSON-over-TCP protocol later (or run both at once) without touching the media layer. The NG
listener exists precisely so you do not have to do that on day one.

## NG command parity

Supported today, mapped one-to-one onto the engine:

| NG command | Notes |
|---|---|
| `ping` | Answers `pong`. |
| `offer` / `answer` / `delete` | The core lifecycle, with SDP rewriting (RFC 3264). |
| `query` | Returns `result: ok` plus a `totals` dict of per-session counters (packets-in/out, bytes-in/out, packets-lost). rtpengine's fuller per-SSRC breakdown is not replicated; the native JSON `query` (full `SessionStats`) or Prometheus give richer numbers. |
| `list` / `statistics` | Census: call-id list, global counters plus the live session gauge. |
| `block media` / `unblock media` | Whole-call media gate (the leg `from-tag` is accepted but not acted on — block applies to the whole call, both directions). |
| `silence media` / `unsilence media` | Replaces the call's egress audio with synthesized silence. Requires a media-processing (transcoding) call; rejected on a plain passthrough relay, which forwards opaque payloads it cannot synthesize into. |
| `block DTMF` / `unblock DTMF` | Drop-mode only; see the differences below. |
| `play media` / `stop media` | `file` and `blob` sources; `db-id` parses but is rejected by the engine (there is no media database). |
| `play DTMF` | RFC 4733 telephone-event injection (`code`, `duration`, `volume`, `pause`). |
| `start recording` / `stop recording` | Raw-RTP pcap to `recording-dir`; `from-tag` optional, matching what `rtpengine_start_recording()` sends. |
| `subscribe request` / `subscribe answer` / `unsubscribe` | The SIPREC-style fork (RFC 7865/7866); the engine produces the subscriber offer SDP. |

siphon-rtp **extensions** to NG, not present in stock rtpengine (your existing tooling ignores
them; a dispatcher can adopt them incrementally):

| NG command | Purpose |
|---|---|
| `load` / `node info` | Live load score and node identity/capabilities for load-aware placement. |
| `drain` / `undrain` | Refuse new sessions for a rolling upgrade; live calls run to completion. |
| `checkpoint` / `restore` | Warm-standby HA call snapshot and rebuild. |

See [Scaling, clustering & HA](scaling-and-ha.md) for all six.

**Not exposed** over NG. rtpengine commands that siphon-rtp answers with an error
(`unsupported command: ...`), never with silence and never with a crash:

- `pause recording`
- `start forwarding` / `stop forwarding`
- `publish` / `connect`

And in the other direction, siphon-rtp's native-only surface is deliberately absent from NG:
`echo`, the `conference_*` verbs, `authenticate`, and the `ws_uri` WebSocket-bridge key are
[native JSON-over-TCP](control/json.md) only.

## Flags and dictionary keys that are honoured

Within `offer` / `answer` (and where applicable the other verbs), siphon-rtp reads the rtpengine
vocabulary you already send:

- `call-id`, `from-tag`, `to-tag`, `sdp`
- `transport-protocol` (e.g. `RTP/AVP`, `RTP/SAVP` for the SDES-SRTP bridge, RFC 4568)
- `ICE`, `DTLS`, `replace`
- `direction` — the two interface names select the local media interface per leg (caller-facing then
  callee-facing), exactly as rtpengine's `interface=…` + `direction` do. Define the interfaces (bind
  IP + advertised public IP) as `[[interface]]` entries in the config file; with none configured the
  pair falls back to the single default interface. A single-homed host behind 1:1 NAT usually wants
  just `--advertise-ip` (advertise a public IP, keep binding private) — see
  [Deployment](deployment.md).
- `address family` (both the spaced and `address-family` spellings)
- `received-from` / `received from` (`["IP4"|"IP6", "<address>"]`), used as the RTPBleed
  source-gate hint
- `rtcp-mux` directive list (RFC 5761; the dotted `rtcp.mux` spelling is accepted too)
- `flags`, including the codec directives `codec-strip-X`, `codec-mask-X`, `codec-transcode-X`,
  `codec-offer-X`, `codec-accept-X`, `codec-except-X`, plus the `symmetric` latching flag
- the structured `codec` dictionary (normalized to the same directives) and `ptime`
- `record call` / `record-call` and `recording-dir`

Unrecognized keys inside a supported command are ignored, which is also rtpengine's behaviour, so
a flag soup accumulated over years of `rtpengine_manage("...")` does not break the cutover; it
just may not all do something yet. When in doubt, test the specific flag.

## The differences that matter

**The in-kernel path is XDP, not a kernel module, and it ships as a separate daemon.** rtpengine
accelerates forwarding with its out-of-tree `xt_RTPENGINE` kernel module. siphon-rtp's equivalent
is a pure-Rust eBPF/XDP datapath (via aya, no out-of-tree module to build per kernel) that relays
plain-RTP flows entirely in-kernel (`XDP_TX`) behind the same source gate, redirecting anything that
needs byte access (SRTP, transcode, TURN) to the userspace slow path. It ships as a **separate
opt-in binary, `siphon-rtp-xdp-daemon`**, that shares the engine's CLI/config, probes the NIC,
attaches the classifier (native, else generic/SKB), and falls back cleanly to the userspace UDP
datapath when the host cannot support it. The **default `siphon-rtp` binary is userspace-UDP-only**
and never links the XDP toolchain — and even that userspace rewrite costs only ~8 ns/packet, so read
[Datapath](datapath.md) before assuming rtpengine-kernel-module throughput figures carry over either
way. There is no `/proc/rtpengine` interface (siphon-rtp is not a kernel module); stats come from
`query`/`statistics` and [Prometheus](observability.md).

**NG is UDP-only and unauthenticated.** Like rtpengine, the NG protocol has no authentication;
unlike recent rtpengine, siphon-rtp listens for NG on UDP only (no NG-over-TCP). Keep `--ng` on a
trusted control network. The native JSON front-end supports a shared secret
(`SIPHON_RTP_CONTROL_SECRET`) if you want an authenticated control plane.

**Latching is stricter by default.** rtpengine's default posture learns a peer's address from the
first packet that arrives. That first-packet race is the RTPBleed class of vulnerability, and
siphon-rtp deliberately does not reproduce it: by default the engine only accepts and latches
media from the SDP-signalled source (or the `received-from` address when you pass it), and never
re-latches mid-stream to a new source unless it carries the same SSRC (RFC 3550 §8). For a leg
behind symmetric NAT whose signalled address is genuinely unusable, pass the `symmetric` flag for
that leg. If a call pattern had one-way audio "fixed" by rtpengine's permissive latching, it will
surface during validation here; the fix is `received-from` or `symmetric`, not a global
relaxation. Full rationale in [Security & NAT design](security-and-nat.md).

**`block DTMF` is drop-mode only.** Blocked RFC 4733 telephone-events are still detected (they
surface as `dtmf` events on the native control channel) but are not relayed. rtpengine's
DTMF-security substitution modes (replacing digits with silence, tones, or random digits) are not
implemented.

**Recording is raw-RTP pcap, and secure calls refuse it.** `start recording` writes the relayed
RTP as a `.pcap` into `recording-dir`; there is no metadata spool file or separate recording
daemon to run. Recording (like `block`/`silence`/`subscribe`) is rejected on SRTP and WebSocket
calls rather than silently writing ciphertext.

**Transcoding needs the codec compiled in.** Passthrough relays any codec. The transcoder ships
G.711 (µ-law/A-law), L16, G.722, G.726, GSM-FR and comfort noise unconditionally; AMR-NB/AMR-WB
require the `amr` build (`cargo install siphon-rtp --features amr`); Opus and EVS are not
transcodable today. Check the [codec matrix](codecs.md) against your `codec-transcode-*` flags
before cutover.

**Configuration is not `rtpengine.conf`.** The daemon takes CLI flags or an rtpengine-style
declarative TOML file (`--config`), with familiar knobs (`port-min`/`port-max` are the same
concept), but the schema is its own. See
[Deployment & operations](deployment.md#the-config-file); do not copy `rtpengine.conf` across.

## What to validate after cutover

Work through these with test traffic before moving production:

1. **Control reachability.** The proxy's rtpengine keepalives succeed (the module marks the node
   enabled). `kamcmd rtpengine.show all` or your equivalent shows the socket up.
2. **SDP rewriting.** A test call's rewritten SDP advertises `--relay-bind-ip` and ports inside
   your `--port-min`/`--port-max` window, and the firewall passes that UDP range.
3. **Two-way audio through NAT.** Specifically test endpoints behind symmetric NAT and any legs
   that relied on blind latching; add `received-from` or the `symmetric` flag where needed. This
   is the one behavioural difference most likely to show up in the field.
4. **Codec flags.** Each `codec-transcode-*` / `codec-mask-*` combination your script sends
   produces the SDP you expect, and transcoded calls have audio both ways (AMR requires the `amr`
   build).
5. **DTMF.** RFC 4733 events relay end-to-end; `block DTMF` stops relay; `play DTMF` injects.
6. **Recording.** `start recording` produces a growing `.pcap` in `recording-dir`, and your
   procedure accounts for it being refused on SRTP calls.
7. **Operations.** `statistics` and `list` feed your monitoring; Prometheus is scraping
   `--metrics-addr`; a `drain` / `undrain` round-trip behaves as expected for your upgrade
   playbook.
8. **Load.** At expected concurrency, watch `siphon_rtp_sessions` against your port-pool sizing
   (up to 4 ports per call, 2 with rtcp-mux) and `siphon_rtp_load_permille` for headroom.

See also: [rtpengine NG / bencode](control/ng.md) for the wire-level reference,
[Native JSON-over-TCP](control/json.md) for the richer native surface,
[Deployment & operations](deployment.md) for the production posture around the listener.
