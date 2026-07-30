# WebRTC legs: DTLS-SRTP, ICE, TURN

A WebRTC endpoint keys SRTP with a DTLS handshake (RFC 5764) instead of SDES,
runs ICE connectivity checks (RFC 8445) before media, and often needs a TURN
relay (RFC 5766) to get through NAT at all. siphon-rtp covers all three in pure
Rust, at different levels of maturity. This page says exactly which level.

**Shipped today:**

- DTLS-SRTP termination on a call leg: the offer advertises `a=fingerprint` +
  `a=setup:actpass`, the handshake keys the leg (webrtc-dtls, pure RustCrypto).
- ICE-lite server posture: per-call credentials, `a=ice-lite` plus a gathered
  candidate list in the rewritten SDP (host per component, and a server-reflexive
  candidate per `--stun-server` that answers), and a STUN Binding responder on the
  media port (MESSAGE-INTEGRITY + FINGERPRINT validated and returned).
- A full built-in TURN server, `turn:` and `turns:`, with coturn REST
  credentials. A coturn replacement, not a shim.
- RFC 7675 consent freshness, opt-in with `--ice-consent`: the engine probes the
  validated pair and tears the call down when the peer stops answering.

**Planned, not shipped:** the full ICE state machine (candidate gathering,
candidate pairs, checklists, nomination, acting as a controlling agent);
transcoding on a DTLS leg (today a DTLS leg is bridged as-is, so both sides must
share a codec); HA checkpoint/restore of a DTLS leg; DTLS or ICE legs into a
conference (`conference_join` rejects them, plain `RTP/AVP` or SDES `RTP/SAVP`
only).

## One port, three protocols: the RFC 7983 demux

A WebRTC peer sends STUN checks, DTLS records, and SRTP on the *same* address
pair. The datapath tells them apart by the first byte, exactly the RFC 7983 §7
table:

| First byte | Class | Handled by |
|---|---|---|
| 0 to 3 | STUN | the ICE Binding responder |
| 20 to 63 | DTLS | the handshake task for the leg |
| 128 to 191 | RTP/RTCP | the secure leg (SRTP unprotect) |
| anything else | dropped | |

So a single engine endpoint per WebRTC leg carries the whole stack, and RTCP is
expected muxed on it too (`a=rtcp-mux`, RFC 5761, as WebRTC requires; a
non-muxed DTLS leg's companion RTCP port is a follow-up).

## DTLS-SRTP: offer, answer, handshake

Ask for a DTLS-secured far leg the same way you ask for SDES, just with the
WebRTC transport profile:

```json
{"id": 1, "command": "offer",
 "call_id": "web-7f3a@203.0.113.40", "from_tag": "as8c1f",
 "sdp": "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=-\r\nc=IN IP4 198.51.100.10\r\nt=0 0\r\nm=audio 30000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
 "profile": {"transport_protocol": "UDP/TLS/RTP/SAVPF"}}
```

The rewritten offer toward the WebRTC side forces the transport and advertises
the engine's identity (no keys in the SDP, that is the point of DTLS-SRTP):

```
m=audio 40002 UDP/TLS/RTP/SAVPF 8
a=fingerprint:sha-256 3E:91:0C:2A:7D:55:18:C4:60:B2:8F:04:D1:73:AA:26:5B:E8:39:C7:12:4F:9D:81:06:EE:57:A3:B0:1C:64:F2
a=setup:actpass
```

The fingerprint is the SHA-256 hash of the engine's self-signed certificate
(ECDSA P-256, minted once at daemon start and reused for every leg, RFC 8122).
The offerer is `actpass`; the answerer picks the role (RFC 5763 §5). When the
answer comes back with the peer's `a=fingerprint` and `a=setup`, the engine
takes the complementary role: a `passive` peer makes the engine the DTLS client,
otherwise the engine is the server and waits for the browser's ClientHello.

What the handshake enforces, per spec:

- The peer's certificate must hash to the fingerprint it signalled (RFC 5763
  §5). No CA chain is consulted; a mismatch aborts the leg before any key is
  derived. As server, the engine requires a client certificate for the same
  reason.
- The negotiated protection profile must be `SRTP_AES128_CM_HMAC_SHA1_80`
  (RFC 5764 §4.1.2); anything else is rejected.
- Keys come from the RFC 5764 §4.2 exporter (`EXTRACTOR-dtls_srtp`), split into
  client/server write keys by role. The result is the same secure-leg type the
  SDES path produces, so replay protection and rollover handling behave
  identically (see [Secure media with SRTP](secure-srtp.md)).
- Until the handshake completes there is no key, so media arriving early is
  dropped. Never forwarded, never buffered.

An answer missing `a=fingerprint` is an error. If certificate generation failed
at startup (it is logged), DTLS offers are rejected rather than served unkeyed.

## ICE: what ICE-lite means here

If the peer's SDP carries ICE (`a=ice-ufrag`), the engine mints fresh short-term
credentials for the call (8-char ufrag, 24-char password, within the RFC 8445
§5.4 bounds), strips the peer's ICE attributes, and re-originates:

```
a=ice-lite
a=ice-ufrag:mJq2X9dK
a=ice-pwd:H7f2kQ91bXcR3sT8wLpZv0Ay
a=candidate:1 1 UDP 2130706431 203.0.113.10 40002 typ host
```

The candidate list is **gathered** (RFC 8445 §5.1.1), not hardcoded: a host
candidate per component — RTP, plus RTCP when the leg is not muxed — carrying the
leg's advertised address, so a 1:1-NAT deployment offers its routable IP rather
than the bound private one.

Point `--stun-server` at a STUN server and the engine also probes it from each
media endpoint for a **server-reflexive** candidate:

```
siphon-rtp --stun-server 198.51.100.1:3478
```

The built-in TURN server answers plain Binding requests (RFC 8656 §12), so its
own address works there and you do not need a second service.

Most deployments should leave it unset. On a routable media address the probe
comes back reporting the address already advertised, which is pruned as redundant
(RFC 8445 §5.1.3) — so you would pay a round trip on every call setup to learn
nothing. It earns its keep only when the engine itself sits behind a NAT it cannot
be addressed through.

Gathering runs on the offer/answer path and is bounded: probes retransmit per RFC
8489 §6.2.1, the plan gives up at a deadline, and whatever was gathered is
advertised. A STUN server that is down costs one bounded delay and a host-only
candidate list, logged as a warning. It never fails the call. Both components
gather concurrently, so that delay is paid once per leg.

Since there is no trickle yet, the offer or answer carries the complete list and
says so with `a=end-of-candidates` (RFC 8838 §14).

Incoming Binding requests on the media port are
answered per RFC 8445 §7.3: the USERNAME must address our ufrag and the
MESSAGE-INTEGRITY must verify against our password, then the response carries
XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY, and FINGERPRINT. An invalid check is
dropped silently.

A *validated* check does one more thing: it adopts the check's source address as
the peer's media path. That is deliberate. An ICE check is cryptographically
bound to the SDP exchange, so it is a stronger latch signal than "first packet
wins" ever could be (see [Security & NAT](../security-and-nat.md), layer 4).

## Full ICE (`--ice-full`)

The default above is the responder half of ICE. Turn on the full agent and the
engine runs the other half too:

```
siphon-rtp --ice-full
```

It forms a checklist from both candidate sets (RFC 8445 §6.1.2), sends
connectivity checks paced at `Ta`, resolves a role conflict by tie-breaker with a
487 response (§7.3.1.1), discovers peer-reflexive candidates in both directions
(§7.3.1.3, §7.2.5.3.1), and nominates a pair with USE-CANDIDATE (§8.1.1).

The behaviour change worth planning for: **media does not flow until ICE selects a
pair.** On a full-agent leg the datapath answers nothing and adopts nothing; the
agent adopts the selected pair, and only then does the layer-4 gate let media
through. That is the correct posture — the path is the one ICE chose, not the one
that sent first — but on a leg whose peer never completes ICE, media never starts
and the call is torn down with CDR reason `ice_failed` instead of relaying.

Off by default because ICE-lite is a valid, simpler posture for a server on a
routable address, and it is what the engine advertises in its SDP.

Still the responder half only in one respect: the engine does not yet perform an
ICE restart (§9) or trickle (RFC 8838). If you need the engine to be an ICE
*client* for outbound WebRTC trunking, that is the same agent driven from the
offerer side and is a follow-up.

## Consent freshness (RFC 7675)

A validated pair can go stale: the peer walks out of coverage, its NAT binding
dies, or it simply stops caring. Consent freshness is the ICE-native answer, and
it is opt-in:

```
siphon-rtp --ice-consent --consent-interval-secs 5 --consent-timeout-secs 30
```

With it on, every ICE leg is promoted to the datapath's full-agent seam (the
responder plus forwarding of the Binding *responses* the responder would drop)
and probed once per sweep tick. Checks go to the address the peer proved it can
receive on, never to its signalled `c=` — for a NATed peer that is a private
address, and probing it would kill healthy calls. Each leg is addressed
`<peer-ufrag>:<our-ufrag>` and signed with that peer's password (RFC 8445
§7.1.2), so the two legs of one call use different credentials. After the timeout
with no verified response the call is torn down: CDR reason `consent_failed`, and
the controller gets the same `Event::MediaTimeout` it already handles for a dead
path.

Why off by default: RFC 7675 §4 says an ICE-lite agent responds to consent checks
and does not generate them, and `a=ice-lite` is what the engine advertises. So
initiating them is a deliberate deviation you opt into, not something we do
behind your back. It becomes the default for legs that stop claiming lite.

Two limits worth knowing. A datapath backend without the full-agent seam (the XDP
fast path) logs a warning per endpoint and stays responder-only — no silent
downgrade. And an HA-restored ICE call runs without consent, because the snapshot
carries the engine's own credentials but not the peer's, so no check can be
addressed; it also says so in the log.

Even with consent off, an ICE path that stops receiving checks is still reaped —
a valid inbound check stamps the endpoint's activity, so the media-timeout sweep
catches it. Consent shortens the detection window and makes it active rather than
passive.

## TURN: the built-in relay

WebRTC clients behind symmetric NAT or UDP-blocking firewalls need TURN. The
engine ships a TURN server so you do not have to run coturn next to it. It is
independent of the control plane (clients talk to it directly), but shares the
media port pool and the session clock, so relay allocations are bounded and
firewallable together with everything else.

Enable it with the two environment variables and at least one listener flag:

```bash
SIPHON_RTP_TURN_REALM=example.org \
SIPHON_RTP_TURN_SECRET=change-me-static-auth-secret \
siphon-rtp \
  --control 127.0.0.1:8080 \
  --relay-bind-ip 203.0.113.10 \
  --port-min 30000 --port-max 39998 \
  --turn-udp 0.0.0.0:3478 \
  --turn-tcp 0.0.0.0:3478 \
  --turn-tls 0.0.0.0:5349 \
  --turn-tls-cert /etc/siphon-rtp/turn-cert.pem \
  --turn-tls-key  /etc/siphon-rtp/turn-key.pem \
  --turn-relay-ip 203.0.113.10
```

- `--turn-udp` / `--turn-tcp` serve `turn:` over UDP and TCP; `--turn-tls`
  serves `turns:` and requires the PEM pair (rustls, TLS only, no C).
- `--turn-relay-ip` is what gets advertised in XOR-RELAYED-ADDRESS when the
  bound IP is not the reachable one (wildcard bind, NAT'd host).
- Allocations, permissions, channels, and nonces expire on the engine's clock
  and are reaped by the same sweeper that reaps idle calls (RFC 5766 lifetimes).

The message set is RFC 5766 (RFC 8656 is the current TURN spec; its
MESSAGE-INTEGRITY-SHA256 is not implemented yet, matching what browsers send in
practice). Credentials are the coturn REST profile (`static-auth-secret`) on
the long-term-credential mechanism, so anything that can mint coturn
credentials can mint these. Your API server generates a time-limited
username/password pair per client:

```bash
EXPIRY=$(( $(date +%s) + 3600 ))          # credential valid 1 h
USERNAME="$EXPIRY:alice"
PASSWORD=$(printf %s "$USERNAME" \
  | openssl dgst -sha1 -hmac "$SIPHON_RTP_TURN_SECRET" -binary | base64)
```

and hands them to the browser:

```js
new RTCPeerConnection({
  iceServers: [{
    urls: ["turn:203.0.113.10:3478?transport=udp",
           "turns:turn.example.org:5349?transport=tcp"],
    username: "1767225600:alice",
    credential: "<the computed password>",
  }],
});
```

The server recomputes the password from the username it receives, enforces the
embedded expiry, and verifies MESSAGE-INTEGRITY, so it stores no per-user
secrets and no nonce table (nonces are stateless HMACs, and 438 Stale Nonce
falls out of an age check).

## How to verify

DTLS leg up:

```bash
RUST_LOG=info siphon-rtp --control 127.0.0.1:8080 ...
# after the answer:
# INFO DTLS-SRTP handshake complete; secure leg installed
```

A `chrome://webrtc-internals` (or `about:webrtc`) dump on the browser side must
show the ICE pair to the engine's advertised candidate as `succeeded` and the
DTLS state `connected`. On the wire, `tcpdump -n udp port 40002` shows the RFC
7983 mix on the one port: STUN (first byte `0x00`/`0x01`), then DTLS records
(`0x16` handshake), then SRTP (`0x80`).

TURN up:

```bash
turnutils_uclient -y -u "$USERNAME" -w "$PASSWORD" 203.0.113.10   # coturn's test client works against it
```

or watch the log for `TURN server enabled (coturn replacement)` and the
listener lines. A misconfigured `--turn-tls` without cert/key fails at startup,
loudly, and TURN configured without any listener logs a warning.

If media never flows after a successful handshake, check the source gate first:
the engine only accepts media consistent with the signalled/validated source
(RTPBleed defence), and a peer whose ICE checks came from a different interface
than its media will be gated. The [Security & NAT](../security-and-nat.md) doc
walks the accept path packet by packet.

## See also

- [Secure media with SRTP](secure-srtp.md), the SDES-keyed sibling; the secure
  leg the DTLS handshake installs is the same machinery.
- [Recording & forking](recording.md); recording and SIPREC are not available
  on a DTLS-bridged call, as on any secure bridge (the verbs return errors, the
  engine never records or forks ciphertext).
- [Security & NAT](../security-and-nat.md), layers 4 and 11: ICE as a latch
  signal, and the TURN server's threat model.
