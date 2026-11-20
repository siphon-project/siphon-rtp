# Lawful interception — X3 content delivery (ETSI TS 103 221-2)

siphon-rtp can deliver intercepted media straight from the media plane to a Mediation/Delivery
Function, framed as ETSI TS 103 221-2 **X3** (Content of Communication) PDUs.

Scope here is the media plane only. **X1** provisioning (the Administration Function creating and
activating an interception task) and **X2** Interception Related Information (the signalling
records) live in the signalling process and are configured separately.

## Why the engine delivers it, not the signalling plane

The alternative is to fork the media to the signalling process over SIPREC and have it wrap and
forward. That works, but it routes every intercepted call's media through the process whose whole
purpose is *not* to carry media. At 500 concurrent intercepted channels it is the wrong shape.

The engine already holds the packets, so it frames them and ships them.

## What is delivered

Every RTP packet the engine **accepted** on either leg, on its own mutually-authenticated TLS
connection to the Mediation Function.

"Accepted" is precise and it is the security property that matters:

- **after decryption.** On an SRTP or DTLS-SRTP leg the delivered payload is the plaintext RTP, not
  the wire ciphertext. (The pcap recorder deliberately does the opposite — it captures the wire —
  which is right for debugging and useless to an agency that has no key.)
- **after authentication.** A packet that fails SRTP authentication, is a replay, or arrives before a
  DTLS handshake has keyed the leg, is dropped by the engine and is never delivered. Forged traffic
  is not presented to an agency as the target's media.
- **after the source gate.** A packet from an address the call never signalled is dropped by the
  RTPBleed defence before it reaches the tap (see [Security & NAT](security-and-nat.md)).

RTCP is not delivered: an X3 PDU declares payload format 8, "RTP packet".

## Direction is relative to the target, not to a leg

TS 103 221-2 §5.2.6 defines direction against the intercept **target**: `2` is *sent to the target*,
`3` is *sent from the target*. The engine knows which leg is the caller and which the callee, but
only the warrant knows which one the target is — so `target_leg` is a required parameter.

With the target on the caller leg:

| Leg's ingress | Meaning | Direction |
|---|---|---|
| Caller (A) | what the target sent | 3 (from target) |
| Callee (B) | what the far end sent | 2 (to target) |

Both ingress taps together cover both directions of the call, so there is no egress tap: what leg B
sends *is* what leg A receives.

**On a transcoding call, direction 2 carries the far end's media in its original encoding** — the
media as it appears at the point of interception, not the bytes re-encoded toward the target. For a
plain relay the two are identical. This is a deliberate decision; confirm it with your Mediation
Function partner if their reading differs.

## Configuration

Node-level, because the PKI and the network-element identity belong to the deployment rather than to
any one warrant. Set them in the config file or as CLI flags:

```toml
x3_client_cert          = "/etc/siphon-rtp/li/client.pem"
x3_client_key           = "/etc/siphon-rtp/li/client.key"
x3_ca                   = "/etc/siphon-rtp/li/mdf-ca.pem"
x3_network_function_id  = "siphon-rtp-sbc-01"   # conditional attribute 6
x3_interception_point_id = "media-relay-a"      # conditional attribute 7
x3_buffer_packets       = 20000
x3_keepalive_secs       = 30
```

The three PEM paths are what enable the feature. All three must be present: a node with a client
certificate but no CA is treated as **unprovisioned**, not half-provisioned.

> **Without this configuration, `attach_x3` is refused.** It is not accepted-and-inert. An
> interception that returns success and delivers nothing reads as a served warrant, and that is the
> failure a compliance audit finds long after the warrant expired.

The delivery connection is mutual TLS on the pure-Rust ring/rustls stack, TLS 1.3 preferred and 1.2
accepted. The Mediation Function authenticates the engine by client certificate; the engine verifies
the Mediation Function against the configured private CA (the public Mozilla bundle will not contain
it).

## Control

```json
{"command":"attach_x3","call_id":"…","from_tag":"…",
 "delivery":"mdf.example.net:8090",
 "xid":"8c292fa1-5831-46ec-86be-bd85f2083299",
 "correlation_id":72623859790382856,
 "target_leg":"caller"}
```

```json
{"command":"detach_x3","call_id":"…","from_tag":"…"}
{"command":"detach_x3","call_id":"…","from_tag":"…","xid":"8c292fa1-5831-46ec-86be-bd85f2083299"}
{"command":"detach_x3","call_id":"…","from_tag":"…","xid":"8c292fa1-5831-46ec-86be-bd85f2083299",
 "delivery":"mdf.example.net:8090"}
```

`xid` and `correlation_id` come from X1 provisioning and are copied into every PDU header without
interpretation — the engine stays lawful-interception-agnostic apart from framing.

`correlation_id` must be **non-zero** and must match the value the signalling plane puts on this
session's X2 records (TS 103 221-2 clause 6); a zero correlation is refused. `detach_x3` is
idempotent, and interception ends automatically with the call.

### Several deliveries on one call

A call can be intercepted under several warrants, or by one warrant toward several Mediation
Functions, at once. Each `attach_x3` names a delivery by its (`xid`, `delivery`) pair:

- a pair the call does not carry **adds** a delivery, with its own mutual-TLS connection, its own
  `correlation_id`, its own PDU sequence counter and its own `target_leg`. Two warrants naming
  different legs on one call each get directions relative to their own target (mirrored);
- the **same** pair again replaces only that delivery (its connection is closed with `detached`, a new
  one opens with a fresh sequence counter) and leaves every other delivery untouched.

`detach_x3` ends what its selectors name: no `xid` ends every delivery of the call (the meaning it
always had), an `xid` ends that warrant's deliveries, `xid` and `delivery` end exactly one. A `delivery`
without an `xid` is refused, since two warrants can share one Mediation Function. Each ended
delivery reports exactly one `x3_ended`, and `x3_loss` / `x3_ended` carry the `xid` and `delivery` they
concern (the engine always fills them). The survivors are not interrupted: the taps of the remaining
deliveries are installed again as a whole, so their connections, Correlation IDs and sequence counters
carry straight on.

The deliveries of a call move together. Whatever rebuilds the call's media path (a re-offer and its
answer, `conference_seat`, `offer_far`, a re-answer of the same dialog) installs the taps of **all**
of them in one step, so a carry can never move some deliveries and drop others; if the taps cannot be
put back, every delivery of the call ends with `transport_error`, loudly. The userspace hold an
interception keeps on a plain relay is released only when the last delivery goes. During the hand-over
of a re-answer a `detach_x3` is honoured for the deliveries it names only. A joined conference seat
carries several deliveries in the same way. The call ending ends every delivery (`call_ended`), one
`x3_ended` each. `node_info` lists `x3_multi_delivery` on a node provisioned for X3.

Attaching is **additive**: the call keeps relaying, recording, teeing and transcoding exactly as it
was. A plain in-kernel relay is promoted to the userspace path for the interception's lifetime and
demoted afterwards — relay-only, so an intercepted call is not forced into a transcode it did not
otherwise need.

The interception belongs to the **call**, not to one negotiation of it. A re-offer and its answer (a
hold, a resume, a session refresh carrying SDP) rebuild the call's media path, and the taps are put
back on the new one: same delivery connection, same Correlation ID, sequence counter unbroken, no
`x3_ended`. `x3_ended` with `call_ended` is emitted only when the call is deleted; a controller's
`detach_x3` or a second `attach_x3` of the same delivery ends that delivery with `detached`. Should the taps ever fail
to be re-installed, the interception ends with `transport_error` rather than staying attached and
silent. A re-offer that changes the negotiated codec is refused by the engine, so that case does not
arise.

`attach_x3` is accepted as soon as the call has been offered, before the callee answers: a warrant can
match at the INVITE. The delivery connection opens at once, and the taps go onto the media path the
first answer installs, so early media from a `183` with SDP and the final answer share one connection,
one Correlation ID and one sequence. `target_leg: callee` is resolved then too. A call deleted before
any answer ends the interception with `call_ended` and nothing delivered. A call the engine answered
itself is intercepted too, see [Engine-answered calls](#engine-answered-calls).

### Conference rooms

A target is not lost when its call is merged into a conference room: the same `conference_seat` works
with a warrant attached (the merge must not tell the target it is intercepted), and the interception
carries on from the room on the **same delivery connection, Correlation ID and PDU sequence**. The
room's own taps are put on the seat while it is still pending, before the leg moves, so no packet the
room handles goes undelivered. If the room cannot take them, `conference_seat` is refused and the call
is left exactly as it was, still relaying and still intercepted.

In a room the target is always **the seated party**, whichever leg the warrant named at attach time:

| Room tap | Meaning | Direction |
|---|---|---|
| The seat's ingress, after the source gate and the SRTP unprotect | what the target sent | 3 (from target) |
| What the room sends the seat, in the clear, built and protected successfully | the room's mixed-minus-self stream for the target | 2 (to target) |

Direction 2 is the stream the target actually receives: the room's own SSRC, sequence and timestamp
for that seat, including a telephone-event the room forwards to it, and nothing when the room sends
the seat nothing (a pending, blocked or discontinuous-transmission frame). It is never another seat's
raw stream. Its PDU source is the engine address the seat talks to and its destination is where the
packet was sent, read per packet because a seat's reply address can latch after the attach.

`attach_x3` and `detach_x3` are accepted on a call whose leg is **seated** (not on one that has left
its room: it relays nothing until it is seated again). A seat that **joined** a room with
`conference_join` has no call, so it is intercepted by naming the room as `call_id` and the seat's
tag as `from_tag`; only the control client that seated it can attach to it. Its `x3_started`,
`x3_loss` and `x3_ended` events carry the room id and the tag. It ends with `call_ended` when the seat
leaves (a `conference_leave`, an idle reap or a failed ICE check) and so when its room stops, and
with `detached` on `detach_x3`.

`conference_leave` on a seated **call** does not end its interception: the call lives on, and a move
from one room to another must not break the warrant. The room's taps leave with the seat and a seat in
any room puts them back on the same connection; the interception ends with the call (`call_ended`) or
on `detach_x3`. If the seat fails after the call's old media path was already stopped (a room that
closed mid-move), the call's media is gone and the interception ends loudly with `transport_error`.

Not covered in a room: RFC 4103 real-time text on a seat's `m=text` stream, which is not audio RTP.
`node_info` lists `x3_conference_seat` on a node provisioned for X3.

### Engine-answered calls

A call the engine answered itself (`answer_local`: an IVR, an announcement, a pre-call prompt) has one
RTP party, the caller, and the engine is its far side. `attach_x3` is accepted on it. The engine
answering stands in for the callee, so `target_leg` applies as it does on two parties (TS 103 221-2
§5.2.6, one mapping for both): with the caller as the target its ingress is `from_target` and the
engine's egress `to_target`; with the callee as the target the two mirror. The directions stay the same
when `offer_far`'s party answers and takes the callee side over.

| Tap | Meaning | Direction (`target_leg: caller` / `callee`) |
|---|---|---|
| The caller's ingress in the media pipeline, after the source gate and the SRTP unprotect | what the caller sent | 3 (from target) / 2 (to target) |
| Every datagram the pipeline sends the caller (prompt, comfort noise, telephone-event), in the clear, only once it is really being sent | exactly the RTP that left the engine | 2 (to target) / 3 (from target) |

The egress tap sits in the one place every egress datagram passes, after the leg is keyed, past ICE and
receiving, and after a secure leg's protect succeeded: an unkeyed or `sendonly`-withheld leg delivers
nothing, a secure leg delivers plaintext and never ciphertext, and nothing is delivered that was not
sent. Its PDU source is the engine address the caller talks to and its destination is where the packet
went. Only a call with one party gets an egress tap: a call with two parties keeps its two ingress taps,
so no packet is delivered twice.

The interception survives what changes the call's shape, on the same delivery connection, Correlation
ID and PDU sequence:

- **`offer_far`.** While the far leg is only offered the single-party taps stay on the caller. When the
  far party answers, the call is a two-party relay and the two ingress taps go on it, with the same
  directions as before for the caller. A refused far answer, or a `delete` of
  the far leg, puts the caller back on the local pipeline with its single-party taps.
- **A re-answer of the same dialog** (`answer_local` again with the same `call_id`, `from_tag` and owner)
  replaces the call's pipeline and endpoints. The caller is the same party in the same dialog and the X2
  records the Correlation ID ties the delivery to do not change, so ending the interception there would
  leave the target's content flowing undelivered. The replacement inherits it. A re-answer under another
  `from_tag` or from another client is a different call and ends the interception with `call_ended`;
  one that is a WebSocket takeover (`ws_uri`) cannot carry it and ends it with `transport_error`. The
  hand-over is atomic as far as `detach_x3` can tell: the session stays registered while the old call is
  torn down and the new one is registered, a `detach_x3` that lands meanwhile is accepted and honoured the
  moment the replacement exists (`detached`, one `x3_ended`), and `attach_x3` in that window is refused
  with a retry reason. The first comfort-noise frame a rebuilt pipeline sends can precede its taps by a
  moment; the caller's own media is never missed, because it only arrives after the answer.

Refused, with the reason unchanged: a WebSocket takeover (`ws_uri`), whose media goes to the server and
never through the pipeline, and an echo call. While an interception is attached, `echo` and
`attach_ws_bridge` are refused on the call (`echo` bypasses the tap and a bridge removes the pipeline),
so the call is never left attached and deaf (a behaviour change for two-party calls too: `echo` was accepted on an intercepted call and silenced its delivery). `node_info` lists `x3_single_leg` on a node provisioned for
X3.

### Events

| Event | Meaning |
|---|---|
| `x3_started` | Delivery is attached and content is flowing. |
| `x3_loss` | **Warranted content was dropped.** See below. Names the `xid` and `delivery` that lost it. |
| `x3_ended` | One delivery stopped, with its lifetime `delivered` / `dropped` counts. Names its `xid` and `delivery`. |

### What cannot be intercepted

| Call shape | Behaviour |
|---|---|
| Plain relay, transcoding, SRTP transcode, DTLS transcode | Delivered (media pipeline tap) |
| Same-codec SDES or DTLS-SRTP bridge | Delivered (crypto-bridge tap) |
| WebSocket takeover (`ws_uri`) | **Refused** — the far side is a media server, not a second party |
| Echo test | **Refused** — no second party, and the echo path bypasses the tap |
| Conference seat (`conference_seat`, or joined with `conference_join`) | Delivered (room tap), see [Conference rooms](#conference-rooms) |
| Engine-answered call (`answer_local`), also while `offer_far` grows it | Delivered (ingress and egress taps, the caller is the target), see [Engine-answered calls](#engine-answered-calls) |

Each unsupported shape is refused at the command with a reason, never accepted silently.

## Loss policy, and why it is not the recorder's

The pcap recorder is best-effort and drops on a full queue, because a recording must never
backpressure the media path. **X3 does not inherit that.** Silently discarding warranted content is a
reportable failure, not a degraded recording.

- The buffer is deep (`x3_buffer_packets`, default 20000 — roughly 400 seconds of one direction at a
  20 ms ptime) and **survives a Mediation Function outage** rather than discarding through it. The
  delivery task reconnects with backoff and drains what accumulated.
- When the buffer is genuinely full the engine discards the **arriving** packet, not a buffered one.
  What has been delivered therefore stays a contiguous prefix, so the gap is a single contiguous
  range rather than interleaved holes.
- Every drop is counted and surfaced: a `warn!` on the `siphon_rtp::li` target, and an `x3_loss`
  event so the controller can raise the corresponding destination-level report toward the
  Administration Function. `x3_ended` carries the lifetime totals.
- The media path is never blocked. If the choice is forced, other calls' audio wins — but the loss is
  loud, never silent.

## Operational notes

- The delivery connection is per interception. If your Mediation Function requires X2 and X3 to share
  one connection, that is not possible here by construction: X2 originates in a different process.
- Sequence numbers (conditional attribute 8) are per **connection** and reset on reconnect, as the
  specification defines them.
- Timestamps (attribute 9) are the wall-clock time the tap saw the packet (TS 103 221-2 §5.3), read
  per packet on every datapath backend. The datapath's own receive clock is not used: on the
  UDP-loopback backend it is logical and does not track time. A wall-clock step backwards repeats a
  timestamp rather than reordering the stream.
- Nothing about the intercepted media is ever logged. Log lines carry the call id, the delivery
  address and the task id, which are what an audit needs.

## Conformance

The framing lives in the `siphon-rtp-li` crate, written against **ETSI TS 103 221-2 V1.4.1
(2021-04)**, with every constant carrying its clause citation. It is validated three ways: byte-exact
fixtures built from the specification, a known-answer test against a PDU captured from an unrelated
implementation, and an independent third-party Wireshark dissector driven through `tshark`. See
`reference/x2x3-dissector/`.
