# Cookbook

Recipes for the media roles siphon-rtp plays in a real deployment. Each page is a complete,
working starting point: the control exchange (native JSON and, where it applies, rtpengine
NG/bencode), what the rewritten SDP looks like on the wire, and how to verify the result with
`query`, `/metrics`, or a pcap. Nothing here is aspirational; every verb, flag, and field exists
in the shipped engine.

## The recipes

| Recipe | What you build |
|---|---|
| [Plain RTP relay](relay.md) | SBC media anchoring: SIPhon or Kamailio anchors both legs through the engine, RTP forwarded unchanged |
| [Transcoding](transcoding.md) | The VoLTE workhorse: AMR-WB and AMR-NB to G.711, plus the codec-transcode / codec-mask directives |
| [Secure media (SRTP)](secure-srtp.md) | SDES-keyed SRTP legs (RFC 3711/4568): bridge a secure access leg to a plaintext core |
| [WebRTC legs](webrtc.md) | DTLS-SRTP (RFC 5764); ICE-lite by default or the full RFC 8445 agent with `--ice-full` (connectivity checks, nomination, restart, trickle-receive); built-in TURN server plus a TURN client (engine API) for relayed candidates |
| [Voice-AI streaming](voice-ai.md) | Bridge a call leg to a WebSocket media server: decode to L16 uplink, encode the downlink |
| [Conferencing](conferencing.md) | N-party mixed audio rooms (MCU): roles, active speaker, whisper/monitor, room bridging |
| [NAT traversal & latching](nat.md) | Symmetric RTP done safely: gated latching, `received-from`, SDP address rewrite, hairpinning |
| [Recording](recording.md) | Runtime pcap recording, `record-call` WAV capture, SIPREC media forking (RFC 7865/7866) |
| [Monitoring](monitoring.md) | Prometheus `/metrics`, the `statistics`/`load` verbs, RTCP-derived MOS, HEP/Homer export |

## The setup every recipe shares

One daemon binary, `siphon-rtp`. Start it with the control planes you need:

```bash
siphon-rtp \
  --control 127.0.0.1:8080 \
  --ng 127.0.0.1:22222 \
  --relay-bind-ip 203.0.113.10 \
  --port-min 40000 --port-max 49999
```

`--control` is the native JSON-over-TCP control (on by default), `--ng` the optional rtpengine
NG/bencode control (UDP, off unless given), `--relay-bind-ip` binds the media sockets to a
routable IP (the default is loopback), and `--port-min`/`--port-max` draw media ports from a
bounded, firewallable range instead of OS-ephemeral ports.

Two control planes drive the same engine:

- **Native JSON over TCP** (`--control`): length-prefixed JSON frames, request/response correlated
  by `id`, plus async events (DTMF, media timeout, call quality) pushed back. This is what SIPhon
  speaks. Set `SIPHON_RTP_CONTROL_SECRET` to require an `authenticate` handshake per connection.
- **rtpengine NG/bencode over UDP** (`--ng`): the wire protocol Kamailio's and OpenSIPS's
  `rtpengine` modules already speak, so existing dial plans work unchanged. Off unless the flag is
  given; unauthenticated by design (bind it to a private interface).

Every recipe shows both forms where both exist. A few verbs are native-JSON-only (`echo`, the
`conference_*` family, `ws_uri`); the NG front-end covers the rtpengine verb set plus the
siphon-rtp cluster extensions (`load`, `node info`, `drain`, `checkpoint`, `restore`).

## How to verify, in general

Three tools recur on every page:

- `query` (per call): accepted/forwarded packet and byte counters.
- `--metrics-addr 127.0.0.1:9090` then `GET /metrics`: engine-wide gauges and counters
  (`siphon_rtp_sessions`, `siphon_rtp_offers_total`, ...). See
  [Observability & call quality](../observability.md).
- a pcap on the media port range: the ground truth for what actually crossed the wire.

For why the engine accepts, latches, and forwards a packet (the RTPbleed defence, source gating,
the latch lifecycle), the source of truth is [Security & NAT](../security-and-nat.md). For which
codecs the default build will transcode and why, see [Codec licensing](../codec-licensing.md).
