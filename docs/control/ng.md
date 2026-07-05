# rtpengine NG front-end

siphon-rtp ships an optional rtpengine NG/bencode control listener so an existing
Kamailio or OpenSIPS deployment can swap rtpengine for siphon-rtp without touching its
routing script. Enable it with `--ng`:

```bash
siphon-rtp --control 127.0.0.1:8080 --ng 203.0.113.10:22222 --relay-bind-ip 203.0.113.10
```

It is off unless `--ng` is given. rtpengine's default control port is 22222, so a stock
Kamailio config keeps working:

```
modparam("rtpengine", "rtpengine_sock", "udp:203.0.113.10:22222")
```

Every NG command funnels into the same session engine as the
[native JSON protocol](json.md); the two front-ends share one call registry, so a call
created over NG is visible to the same metrics, timeouts, and reaping.

## Wire envelope

One UDP datagram per request: `<cookie><SP><bencode-dict>`, split on the first space.
The cookie is opaque and echoed verbatim on the response so the client can correlate.

```
6f3e8d92 d7:command4:pinge          request
6f3e8d92 d6:result4:ponge           response
```

- A datagram with no cookie separator cannot be correlated and is dropped.
- A malformed dict or an unknown `command` gets a proper
  `{"result": "error", "error-reason": "..."}` reply, never silence and never a crash, so
  the client fails fast instead of sitting in its retransmit timeout.
- Responses fit comfortably in one datagram (the read buffer matches the 64 KiB
  rtpengine client buffer).

The NG listener is **unauthenticated by design**, matching rtpengine. Anyone who can
reach the port controls media sessions. Bind it to a loopback or private control network
and firewall it; if you need authenticated control, use the
[native JSON front-end](json.md) with `SIPHON_RTP_CONTROL_SECRET`.

## Supported commands

Stock rtpengine verbs, with the exact command strings the parser matches:

| NG command | Native verb | Notes |
|---|---|---|
| `ping` | `ping` | Answers `result: pong`. |
| `offer` | `offer` | `call-id`, `from-tag`, `sdp` + the flag surface below. Returns the rewritten SDP. |
| `answer` | `answer` | Adds `to-tag`. |
| `delete` | `delete` | `to-tag` optional. |
| `query` | `query` | Currently answers `result: ok` with no statistics payload (see parity notes). |
| `list` | `list` | Returns the live call-ids under `calls`. |
| `statistics` | `statistics` | Counters under a `statistics` sub-dict: `offers`, `answers`, `deletes`, `errors`, `sessions`. |
| `play media` | `play_media` | Source from `file`, `blob`, or `db-id` (`db-id` parses but the engine rejects it: no media database). `repeat-times`, `start-pos`, `duration`, `to-tag`. |
| `stop media` | `stop_media` | |
| `play DTMF` | `play_dtmf` | `code`, `duration`, `volume`, `pause`, `to-tag` (RFC 4733 injection). |
| `silence media` / `unsilence media` | `silence_media` / `unsilence_media` | Requires a transcoding call. |
| `block media` / `unblock media` | `block_media` / `unblock_media` | |
| `block DTMF` / `unblock DTMF` | `block_dtmf` / `unblock_dtmf` | Drop mode only: the digit is still detected, just not relayed. rtpengine's replace-with-tone/PCM modes are not implemented. Rejected on SRTP/WebSocket calls. |
| `start recording` / `stop recording` | `start_recording` / `stop_recording` | `call-id` alone suffices (Kamailio's `rtpengine_start_recording()` sends only that); `recording-dir` names the pcap directory. Raw-RTP pcap; rejected on SRTP/WebSocket calls. |
| `subscribe request` | `subscribe_request` | SIPREC fork (RFC 7866). `from-tags` list or a single `from-tag`. The engine offers; an SDP in the request is rejected. |
| `subscribe answer` | `subscribe_answer` | |
| `unsubscribe` | `unsubscribe` | |

siphon-rtp extensions, **not** part of stock rtpengine's NG vocabulary. A stock rtpengine
behind the same dispatcher will reject these, so gate them on the node type:

| NG command | Native verb | Notes |
|---|---|---|
| `load` | `load` | Cluster load snapshot under a `load` sub-dict (`node-id`, `sessions`, `max-sessions`, `load-permille`, `transcode-sessions`, `cpu-permille` when sampled, `allocated-bytes`, `draining` as 0/1). |
| `node info` | `node_info` | Static identity under `node` (`node-id`, `version`, `media-addresses`, `codecs`, `features`, `max-sessions`, `draining`). |
| `drain` / `undrain` | `drain` / `undrain` | Stop/resume admitting new sessions for a rolling upgrade. |
| `checkpoint` | `checkpoint` | HA snapshot; the opaque blob comes back under `snapshot`. |
| `restore` | `restore` | Rebuild a checkpointed call on a standby. Same limits as native: passthrough, SDES-SRTP bridge, and plaintext transcode calls only. |

## Codec directives

Transcoding is driven the same two ways rtpengine accepts, and both normalize to one
internal form:

- Flag strings in the `flags` list: `codec-transcode-PCMA`, `codec-mask-AMR-WB`,
  `codec-strip-G722`, `codec-offer-PCMU`, `codec-except-PCMU`, ...
- The structured `codec` dict (`{"transcode": ["PCMA"], "mask": ["AMR-WB"]}` in JSON
  terms), which is flattened to the same `codec-<op>-<NAME>` strings.
- An integer `ptime` key becomes a `ptime=N` directive.

The operations the engine honours on the far-side offer:

| Directive | Effect |
|---|---|
| `codec-strip-X` | Remove X from the offer. |
| `codec-mask-X` / `codec-consume-X` | Remove X from the offer but keep it usable near-side, engaging the transcoder. |
| `codec-transcode-X` | Add X to the offer; transcode engages when the far side selects it. |
| `codec-except-X` / `codec-accept-X` | Keep-list: X survives a `strip`/`mask` sweep. |
| `codec-offer-X` | Whitelist that sets the offered codec order (first flag preferred). |
| `strip`/`mask` with `all` or `full` | Sweep every codec except the keep-list. |

Names are matched case-insensitively. A `codec-transcode` target the engine cannot
encode is skipped rather than failing the call; the targets it can currently add are
`PCMU`, `PCMA`, `G722`, `GSM`, `G726-32`, and (with the `amr` build feature) `AMR-WB`.
See [Codec support](../codecs.md) for the full matrix.

## NAT, transport, and RTCP flags

The rest of the rtpengine flag surface the parser maps:

| Key | Meaning |
|---|---|
| `transport-protocol` | Far-leg transport (`RTP/AVP`, `RTP/SAVP`, `UDP/TLS/RTP/SAVPF`, ...). |
| `ICE` | `remove` \| `force` \| `force-relay`. |
| `DTLS` | `passive` \| `active` \| `off`. |
| `replace` | SDP rewrite list, e.g. `origin`. |
| `direction` | NAT leg pair, e.g. `["external", "internal"]`. |
| `address family` (or `address-family`) | `IP4` \| `IP6` far-leg endpoints for v4/v6 interworking. |
| `record call` (or `record-call`) + `recording-dir` | Record from setup; pcap directory. |
| `received-from` (or `received from`) | `["IP4"\|"IP6", "<address>"]`: the real post-NAT source IP the proxy saw. Tightens the ingress source gate against RTPBleed-class attacks ([Security and NAT](../security-and-nat.md)). A family token that disagrees with the literal is ignored. Only the IP is gated, never the port. |
| `rtcp-mux` (or `rtcp.mux`) | Directive list (`offer`, `require`, `demux`, `accept`, `reject`, `remove`) overriding the RFC 5761 mux decision. |

## Parity notes

Honest differences from stock rtpengine, and from siphon-rtp's own native protocol:

- **Native-JSON-only surface.** NG does not expose `echo`, the `conference_*` verbs,
  `authenticate`, or the `ws_uri` WebSocket bridge. Those need the
  [JSON front-end](json.md).
- **No asynchronous events.** NG is strictly request/response over UDP. DTMF detection,
  media-timeout, and call-quality events are pushed only on native JSON connections.
- **`query` carries no statistics yet.** The engine computes per-session stats (the
  native `query` returns them), but the NG serializer currently answers `result: ok`
  without a stats payload.
- **`block DTMF` is drop-mode only.** No tone/PCM replacement modes.
- **`play media` has no `db-id` backend.** The key parses for compatibility; the engine
  answers with an error.
- **Extensions are extensions.** `load`, `node info`, `drain`, `undrain`, `checkpoint`,
  `restore` are siphon-rtp additions; do not send them to a real rtpengine.
- **Unknown verbs return an error**, never a crash and never silence:
  `{"result": "error", "error-reason": "unsupported command: ..."}`.
- The bencode parser and NG mapper are fuzzed; malformed datagrams from the network
  decode-or-error, they do not panic the daemon.

## How to verify

Ping it by hand (bencode is printable for this case):

```bash
printf '1234 d7:command4:pinge' | nc -u -w1 127.0.0.1 22222
```

Expect `1234 d6:result4:ponge` back. From Kamailio, `kamcmd rtpengine.show all` should
list the socket as enabled after the first successful ping, and a test call through your
usual `rtpengine_manage()` route should show the rewritten `c=` line carrying the
`--relay-bind-ip` address.

## See also

- [Native JSON control protocol](json.md), the richer, authenticated interface.
- [Security and NAT](../security-and-nat.md), why the NG port must be private.
- [Codec support](../codecs.md), what transcoding the directives can actually invoke.
