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
```

`xid` and `correlation_id` come from X1 provisioning and are copied into every PDU header without
interpretation — the engine stays lawful-interception-agnostic apart from framing.

`correlation_id` must be **non-zero** and must match the value the signalling plane puts on this
session's X2 records (TS 103 221-2 clause 6); a zero correlation is refused. `detach_x3` is
idempotent, and interception ends automatically with the call.

Attaching is **additive**: the call keeps relaying, recording, teeing and transcoding exactly as it
was. A plain in-kernel relay is promoted to the userspace path for the interception's lifetime and
demoted afterwards — relay-only, so an intercepted call is not forced into a transcode it did not
otherwise need.

### Events

| Event | Meaning |
|---|---|
| `x3_started` | Delivery is attached and content is flowing. |
| `x3_loss` | **Warranted content was dropped.** See below. |
| `x3_ended` | Delivery stopped, with lifetime `delivered` / `dropped` counts. |

### What cannot be intercepted

| Call shape | Behaviour |
|---|---|
| Plain relay, transcoding, SRTP transcode, DTLS transcode | Delivered (media pipeline tap) |
| Same-codec SDES or DTLS-SRTP bridge | Delivered (crypto-bridge tap) |
| WebSocket takeover (`ws_uri`) | **Refused** — the far side is a media server, not a second party |
| Echo test | **Refused** — no second party, and the echo path bypasses the tap |
| Conference participant | **Not covered** — a room seat is a separate media path |

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
- Timestamps (attribute 9) are absolute Unix time. The engine anchors the wall clock once per
  interception and derives the rest from the datapath receive clock, so inter-packet spacing stays
  exact while the timeline is absolute.
- Nothing about the intercepted media is ever logged. Log lines carry the call id, the delivery
  address and the task id, which are what an audit needs.

## Conformance

The framing lives in the `siphon-rtp-li` crate, written against **ETSI TS 103 221-2 V1.4.1
(2021-04)**, with every constant carrying its clause citation. It is validated three ways: byte-exact
fixtures built from the specification, a known-answer test against a PDU captured from an unrelated
implementation, and an independent third-party Wireshark dissector driven through `tshark`. See
`reference/x2x3-dissector/`.
