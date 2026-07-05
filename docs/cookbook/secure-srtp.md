# Secure media with SRTP (SDES)

The SIP-signalled crypto case: one call leg negotiates `RTP/SAVP` with an `a=crypto`
key in the SDP (SDES, RFC 4568), the other stays plain `RTP/AVP`. siphon-rtp
terminates SRTP (RFC 3711) on the secure side and relays or transcodes plaintext on
the other, entirely in pure Rust (RustCrypto, no libsrtp).

This is the classic SBC edge: a secure access or interconnect leg toward a plain
RTP core. For DTLS-keyed SRTP (WebRTC), see [WebRTC legs](webrtc.md).

## What is negotiated

- **Crypto-suites**: `AES_CM_128_HMAC_SHA1_80` (the SIP/VoLTE default, 10-byte
  auth tag) and `AES_CM_128_HMAC_SHA1_32` (4-byte tag). Anything else on an
  `a=crypto` line (AES-256, AEAD-GCM) is not implemented; unsupported lines in a
  peer's SDP are skipped and the first supported one keys the leg.
- **Key material**: the RFC 4568 §9.1 30-byte inline value, `master_key(16) ||
  master_salt(14)`, base64. The engine mints its own keys from the OS CSPRNG and
  never emits MKI or lifetime parameters (both optional); it tolerates
  `|lifetime|MKI` suffixes and session parameters on the peer's line and uses the
  first inline key-param.
- **RTP/RTCP**: both directions get independent SRTP and SRTCP contexts, derived
  from the same master key under the RFC 3711 §4.3 labels. `a=rtcp-mux`
  (RFC 5761) and non-muxed RTCP both work; on a non-muxed leg the companion RTCP
  port carries SRTCP.

## Who is secured: the leg you offer toward

The controller decides per call. Setting `transport_protocol: "RTP/SAVP"` on the
**offer** secures the far leg (the side the engine offers toward):

1. The engine generates a fresh `a=crypto` (tag 1, `AES_CM_128_HMAC_SHA1_80`),
   forces `RTP/SAVP` on the rewritten offer, and strips the offerer's own keying
   lines.
2. The far end answers `RTP/SAVP` with *its* `a=crypto`. That keys the leg: the
   engine encrypts toward the peer with the key it offered, and decrypts what the
   peer sends with the key from the answer. An answer without a usable `a=crypto`
   is an error (`missing a=crypto in the answer`), not a silent plaintext call.
3. The answer relayed back to the offerer is presented as plain `RTP/AVP`, with
   the far side's keying stripped.

If both legs share a codec this is a pure crypto bridge (packets are not decoded).
If the codecs differ, the engine runs the secure transcode path instead: decrypt,
transcode, re-encrypt, with SRTCP handled on the same keys. Both are selected
automatically from the SDP; there is no separate knob.

**Transcrypt is always explicit.** A secure leg bridged to an insecure leg exists
only because the controller asked for exactly that topology on the offer. The
engine never silently downgrades a secure leg to plaintext, and a packet that
fails SRTP authentication is dropped, never forwarded (see
[Security & NAT](../security-and-nat.md)). Terminating SRTP that the *offerer*
signals (a secure caller toward a plain callee) is wired for conference legs
(`conference_join` answers `RTP/SAVP` + `a=crypto`) but not yet for the two-party
offer/answer relay; there the secure side is the answerer's leg.

## Native JSON exchange

Offer (A is plain G.711; the profile secures the B side):

```json
{"id": 1, "command": "offer",
 "call_id": "a84b4c76e66710@198.51.100.10", "from_tag": "as7d900e",
 "sdp": "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=-\r\nc=IN IP4 198.51.100.10\r\nt=0 0\r\nm=audio 30000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
 "profile": {"transport_protocol": "RTP/SAVP", "replace": ["origin"]}}
```

The response carries the rewritten SDP to send onward to B. Note the forced
transport and the engine's freshly minted key:

```
m=audio 40002 RTP/SAVP 8
a=rtpmap:8 PCMA/8000
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywt
```

Answer, with B's SDP (B chose its own key):

```json
{"id": 2, "command": "answer",
 "call_id": "a84b4c76e66710@198.51.100.10", "from_tag": "as7d900e", "to_tag": "b1c2d3",
 "sdp": "v=0\r\no=- 2 2 IN IP4 203.0.113.40\r\ns=-\r\nc=IN IP4 203.0.113.40\r\nt=0 0\r\nm=audio 5004 RTP/SAVP 8\r\na=rtpmap:8 PCMA/8000\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9\r\n"}
```

The response SDP (relayed to A) is back on `RTP/AVP` with no `a=crypto`. Media now
flows: A's plaintext is encrypted toward B, B's SRTP is authenticated, decrypted,
and relayed to A. Tear down with `delete` as usual.

## rtpengine NG exchange

The same call over the NG/bencode front-end (`--ng 127.0.0.1:22222`). The wire is
`<cookie> <bencode-dict>`; logically the offer dict is:

```
command:            offer
call-id:            a84b4c76e66710@198.51.100.10
from-tag:           as7d900e
sdp:                v=0 ... m=audio 30000 RTP/AVP 8 ...
transport-protocol: RTP/SAVP
replace:            [origin]
```

and the answer carries `command: answer`, `to-tag`, and B's `RTP/SAVP` SDP. From
Kamailio/OpenSIPS this is the stock rtpengine module:

```
rtpengine_offer("RTP/SAVP replace-origin");
rtpengine_answer("");
```

From SIPhon, use a media profile whose offer sets
`transport_protocol: "RTP/SAVP"`; the flags are the same ones SIPhon already
sends to rtpengine, so an existing deployment carries over unchanged.

## Anti-replay and packet-index handling

Straight RFC 3711, enforced per SSRC on every secure leg:

- The 48-bit packet index is recovered with the §3.3.1 rollover estimate, so
  streams survive 16-bit sequence wraps in both directions.
- A §3.3.2 sliding replay window (64 packets wide, the RFC minimum) rejects a
  duplicated index and anything too old to prove fresh. The replay check runs
  *before* the HMAC is spent (cheap early reject), but the window is only advanced
  *after* a packet authenticates, so a forged packet can never poison it or lock
  out the genuine one.
- SRTCP carries its explicit 31-bit index in the authenticated trailer (§3.4); the
  receive side applies the same replay window to it, no rollover guessing needed.
- Tag verification is constant-time. `AuthFailed` and `Replayed` packets are
  dropped and never cross to the other leg.

The replay/rollover state is the one piece of SRTP state that cannot be re-derived
from the SDES key, so `checkpoint` carries it and `restore` reseeds it on a
standby (an HA failover does not break a wrapped secure stream).

## What a secure leg costs

Measured per packet on one core (see the [README benchmarks](https://github.com/siphon-project/siphon-rtp#readme)):

| Operation | Time |
|---|--:|
| SRTP protect (AES-CM + HMAC-SHA1-80) | 243 ns |
| SRTP unprotect (verify + decrypt) | 262 ns |
| SRTCP protect / unprotect | 173 / 183 ns |
| Secure-leg protect / unprotect (incl. RFC 5761 demux) | 245 / 257 ns |
| Per-leg context setup (3x KDF derive) | 151 ns |

Roughly half a microsecond of crypto per relayed packet round trip. At 50 pps per
direction that is noise; budget for it only at very high call counts.

## What is rejected on a secure call, honestly

A plain SRTP bridge relays ciphertext without decoding it, so the media verbs
that need to see or synthesize audio are refused with a clear error rather than
half-working:

| Verb | Plain SRTP bridge | Secure transcode | Why |
|---|---|---|---|
| `block_media` / `unblock_media` | rejected | works | the bridge has no actor to gate; a transcoding call does |
| `silence_media` / `unsilence_media` | rejected | works | silence is synthesized in the egress codec, which needs decode/encode |
| `block_dtmf` / `unblock_dtmf` | rejected | works | the bridge never sees clear RFC 4733 telephone-events; the transcode actor does |
| `start_recording` (pcap) | rejected | rejected | the wire bytes are ciphertext; decrypt-then-record is a follow-up |
| `subscribe_request` (SIPREC) | rejected | accepted | the transcode actor decrypts ingress before the fork, so the SRS receives clear RTP; the bridge cannot tap plaintext |
| `play_media` / `play_dtmf` / `echo` | rejected | works | all need the media actor |

"Secure transcode" means the codecs differ across the bridge and the engine is
already decrypting into the media actor. The same rejections apply to
WebSocket-bridged calls. `checkpoint`/`restore` (HA warm standby) work for the
plain SRTP bridge, including the key material and rollover state; restoring a
secure-transcode call is rejected today.

## How to verify

Capture the two legs and check what is actually on the wire:

```bash
tcpdump -n -i any udp portrange 40000-40100 -X -c 4
```

On the secure leg you should see RTP-shaped headers (version 2, the negotiated
payload type still readable, per RFC 3711 the header is authenticated but not
encrypted) with an opaque payload exactly 10 bytes longer than the plain side's
(the 80-bit auth tag). The plain leg shows the same stream as cleartext G.711.
If you need to prove the ciphertext decrypts, feed the capture and the leg's
inline key to an offline SRTP decryption tool; the recovered audio must match the
plain leg.

Negative checks are as important:

- Replay a captured SRTP packet at the engine (e.g. with `tcpreplay`): it must
  not come out the plain side twice.
- Send plaintext RTP at the secure endpoint from the signalled peer address: auth
  fails, nothing is forwarded.
- Send anything from an unsignalled source address: dropped by the source gate
  before crypto is even attempted (the RTPBleed defence, see
  [Security & NAT](../security-and-nat.md)).

`query` on the call shows packet counters moving in both directions while audio
flows.

## See also

- [WebRTC legs](webrtc.md) for DTLS-keyed SRTP (RFC 5764), ICE, and TURN.
- [Recording & forking](recording.md) for what recording verbs do (and refuse to
  do) on secure calls.
- [Security & NAT](../security-and-nat.md) for the full threat model: source
  gating, latching, and why the bridge re-enforces the gate on the redirect path.
