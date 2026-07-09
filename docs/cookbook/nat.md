# NAT traversal & latching

NAT traversal and media security are one mechanism in siphon-rtp: the relay learns where to send
a party's media by watching where that party's media actually comes from (symmetric RTP,
RFC 4961), and that same learning step is exactly what an attacker abuses in the RTPbleed class
of attacks. This page is the operational view: what to set, and what to check when audio is
one-way. The design, the threat model, and the layer-by-layer rationale live in
[Security & NAT](../security-and-nat.md); read that before changing any of these knobs in
production.

## Symmetric RTP, gated

The default posture, per leg:

- **Source gate.** Ingress is accepted only from the source the SDP signalled (the `c=`/`m=`
  address, RFC 3264). Packets from anywhere else are dropped before they can influence anything.
- **Latch.** The reply destination follows the peer's *accepted* packets, so a party behind NAT
  is answered at its NAT binding, not at the address it advertised.
- **No mid-stream re-latch.** Once latched, a new source is followed only if it carries the same
  RTP SSRC (a genuine NAT rebind keeps its SSRC, RFC 3550 §8); a new source with a different
  SSRC is rejected and counted. An off-path spray never steals the stream.
- **Never into the void.** A flow with no resolved destination drops the packet rather than
  guessing.

That is the anti-RTPbleed posture ([Security & NAT §2 and §4](../security-and-nat.md)). It is
deliberately stricter than rtpengine's default; loosen it per leg, never globally.

Per-leg knobs, passed in `profile.flags` (native JSON) or `flags` (NG):

| Flag | Gate | When |
|---|---|---|
| (default) | exact source IP, signalled (or `received-from`) address | non-NAT and full-cone-NAT peers |
| `subnet-source` | the signalled IP's /24 (IPv4) or /64 (IPv6) | carriers that re-NAT or split RTP/RTCP within a block |
| `symmetric` | any source; first accepted packet latches | symmetric NAT where the signalled address is genuinely unusable and no `received-from` hint is available |

`symmetric` is the weakest gate; before reaching for it, try `received-from` below, which usually
solves the same problem without opening the leg.

## The `received-from` hint

A UA behind NAT advertises its private address in `c=`; its media then arrives from the NAT's
public IP, the exact-source gate never matches, and everything is dropped. But your SIP proxy
already knows the real post-NAT source: the address the request arrived from. Pass it along and
the engine gates the leg to that IP instead. This *tightens* the gate (exact public IP rather
than a fallback to `symmetric`), it does not loosen it.

Native JSON, on the offer (gates the A leg) or the answer (gates the B leg):

```json
{
  "id": 1,
  "command": "offer",
  "call_id": "nat-call-1",
  "from_tag": "a1b2c3",
  "sdp": "v=0\r\n... c=IN IP4 10.0.0.7 ...",
  "profile": { "received_from": "203.0.113.5" }
}
```

NG, rtpengine's own spelling (a `["IP4"|"IP6", "<address>"]` list; the space-separated
`received from` key is accepted too):

```
{ "command": "offer", "call-id": "nat-call-1", "from-tag": "a1b2c3",
  "sdp": "v=0\r\n...",
  "received-from": ["IP4", "203.0.113.5"] }
```

Only the IP is used. The media port differs from the signalling port, so ports are never gated;
the latch handles the port. A family mismatch (an `IP4` token carrying a v6 literal) is ignored
rather than mis-applied. Details: [Security & NAT §4, layer 2](../security-and-nat.md).

## SDP address rewrite

The engine rewrites each leg's `c=` line and `m=audio` port to its own reachable endpoint, so a
UE's private address is never advertised onward and each party sends to the engine regardless of
what the other signalled. Two things must be true for that to work:

- Bind the media sockets to a routable address: `--relay-bind-ip 203.0.113.10`. The default is
  loopback, and a loopback address in the rewritten `c=` line is the single most common "no
  audio anywhere" cause in a fresh deployment.
- Add `replace: ["origin"]` (`"replace": ["origin"]` in JSON) if you also want the `o=` line
  rewritten to the engine's address for topology hiding; the media path does not need it.

## The engine itself is behind NAT (advertise a public IP)

On a cloud host whose only local address is private and whose public address is an Elastic IP (1:1
NAT via the gateway), binding the public IP is not an option — it is not a local address, and the
XDP fast path requires `--relay-bind-ip` to be a routable *local* IPv4. Decouple the advertised
address from the bound one:

```
siphon-rtp --relay-bind-ip 10.0.0.7 --advertise-ip 203.0.113.9 ...
```

The sockets bind and receive on the private `10.0.0.7`; the rewritten SDP hands peers
`c=IN IP4 203.0.113.9` on the **same port** (1:1 NAT preserves it). It is emit-only: the source
gate and the symmetric-RTP latch still key on the real remote/bound addresses, so this does not
touch the anti-RTPbleed posture, and XDP attach/bind are unaffected. `--advertise-ip` only
substitutes when its family matches the leg's, so a v4 EIP never lands on a `c=IN IP6` leg.

For a host that fronts **two** networks (a private core side and a public access side), define
named interfaces in the config file and let the control `direction` pair pick the interface per leg:

```toml
default_interface = "external"

[[interface]]
name = "internal"
address = "10.0.0.7"

[[interface]]
name = "external"
address = "10.0.0.7"          # bind the private/local IP
advertised = "203.0.113.9"    # advertise the public IP
```

`direction = ["external", "internal"]` then anchors the caller-facing leg on `external` (advertising
the EIP) and the callee-facing leg on `internal`. The single `--advertise-ip` is the one-interface
shorthand for this. Full design: [Security & NAT §12](../security-and-nat.md).

## Hairpinning

Two parties behind the same NAT (or two NATed legs of any shape) relay *through* the engine,
always. The engine never signals one party's address to the other and never expects them to go
direct, so the hairpin case needs no configuration: each leg is gated and latched independently,
and media flows UE, engine, UE even when both UEs share one NAT. What it costs is the extra leg
of bandwidth through the engine, which is the price of anchoring.

## ICE legs

When a leg offers ICE, connectivity checks replace latching as the address-learning mechanism:
the engine answers as ICE-lite (RFC 8445), and a STUN Binding check authenticated with the
negotiated credentials adopts the validated source. The gate/latch story above applies to the
plain-RTP legs, which in VoLTE/PSTN work is most of them. See
[Security & NAT §4, layer 4](../security-and-nat.md) and [WebRTC legs](webrtc.md).

## "My media is one-way" checklist

Work through these in order; each one names its check.

1. **Is the engine reachable at what it advertised?** Look at the rewritten SDP's `c=` line. If
   it says `127.0.0.1`, you forgot `--relay-bind-ip`. If it names a private IP the peer cannot
   route and the host is behind 1:1 NAT (a cloud host with an Elastic IP), set `--advertise-ip` to
   the public address. Otherwise fix the bind or the network, not the latch.
2. **Is the gate dropping the sender?** `query` the call while the party sends. `packets_in`
   rising together with `packets_lost`, while `packets_out` lags, means packets reach the engine
   and the source gate rejects them. Compare the arriving source IP (tcpdump) against the leg's
   signalled `c=` address: if the SDP says `10.x`/`192.168.x` and the packets come from a public
   IP, pass `received-from` on that leg's offer or answer. If `packets_in` is flat too, the
   packets never reach the engine at all: routing or firewall, not the gate.
3. **Silence one way only, gate fine?** Check the *other* leg the same way. One-way audio is
   almost always the quiet direction's ingress being dropped or misrouted, not the loud one.
4. **Did the call get reaped?** No accepted media for `--media-timeout-secs` (default 30)
   tears the call down and pushes a `media_timeout` event to the controller. If calls die after
   exactly that interval, the gate was dropping everything from the start.
5. **Carrier splits RTP across addresses?** RTP arrives from one IP, RTCP (or a re-INVITEd
   stream) from a neighbour. That is what `subnet-source` is for.
6. **Still stuck?** Capture both engine ports and both directions
   (`tcpdump -ni any udp portrange 40000-49999`) and match what arrives against what leaves.
   The engine forwards every accepted packet; whatever is missing was either never received or
   never accepted, and the two look identical from the SIP side.

The one thing *not* to do is force `symmetric` everywhere until sound comes out. It usually
will, and you will have re-opened the latch race the default posture exists to close
([Security & NAT §2](../security-and-nat.md)).

## See also

- [Security & NAT](../security-and-nat.md), the source of truth for the gate, the latch
  lifecycle, and the RTPbleed threat model.
- [Plain RTP relay](relay.md) for the surrounding offer/answer plumbing.
- [WebRTC legs](webrtc.md) for ICE and TURN.
