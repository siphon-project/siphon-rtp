# Transcoding

The VoLTE workhorse: an IMS access leg speaks AMR-WB (or AMR-NB) and the far side is a G.711
PSTN gateway or trunk. The engine decodes one leg, resamples where the rates differ (16 kHz
AMR-WB against 8 kHz G.711), and re-encodes for the other, per direction, in a per-call actor.

Transcoding engages by negotiation, not by a switch: when the two legs' negotiated primary codecs
differ in encoding name or clock rate, the call is promoted from the plain relay fast path to the
transcoding media path at `answer` time. The codec directives below exist to *shape what the far
side is offered* so that the negotiation lands where you want it.

## Build posture: the `amr` feature

Relaying any codec is always available and runs no codec code. Transcoding runs the codec, and
AMR is patent-encumbered, so AMR transcoding is gated behind the `amr` Cargo feature, off by
default. Enabling it is your statement that you hold the licences; see
[Codec licensing](../codec-licensing.md).

```bash
cargo build --release --features amr
```

On a default build, a call that would need an AMR encoder or decoder fails cleanly at setup with
an `unsupported` reason; nothing half-works.

What each codec actually does, precisely:

| Codec | Build | Decode | Encode | Validated against |
|---|---|---|---|---|
| G.711 µ-law / A-law (PCMU/PCMA) | always | yes | yes | ITU-T G.711 |
| L16 / PCM | always | yes | yes | RFC 3551 |
| G.722 (64 kbit/s, mode 1) | always | yes | yes | bit-exact, ITU-T test vectors |
| G.726 (16/24/32/40 kbit/s) | always | yes | yes | bit-exact, ITU-T test vectors |
| GSM-FR (GSM 06.10) | always | yes | yes | bit-exact, ETSI vectors |
| Comfort noise (RFC 3389) | always | yes (generator) | no (DTX is a media-path policy) | RFC 3389 |
| AMR-WB (TS 26.171/.190) | `amr` | all 9 modes, 6.60 to 23.85 kbit/s | all 9 modes | bit-exact, 3GPP TS 26.174 vectors |
| AMR-NB (TS 26.071/.090) | `amr` | all 8 modes | **MR475, MR515, MR59, MR122** | bit-exact, 3GPP TS 26.074 vectors |

Be precise about AMR-NB: the decoder covers every mode, the encoder covers four (MR475, MR515,
MR59, MR122). The engine's default AMR-NB egress mode is MR122 (12.2 kbit/s, the GSM-EFR-compatible
mode); the lower-rate modes are implemented and bit-exact but the SDP layer does not currently
select them. AMR-WB egress defaults
to mode 2 (12.65 kbit/s) and is clamped by the peer's `mode-set` (below). Opus is in progress and
not usable yet; EVS is absent. Both still *relay* fine.

## The AMR-WB to G.711 call, end to end

A (VoLTE UE) offers AMR-WB. You want the far offer to also carry PCMA so a G.711-only gateway
can complete the call.

A's offer:

```
v=0
o=- 1 1 IN IP4 192.0.2.20
s=-
c=IN IP4 192.0.2.20
t=0 0
m=audio 49170 RTP/AVP 96 101
a=rtpmap:96 AMR-WB/16000
a=fmtp:96 octet-align=1;mode-set=0,1,2
a=rtpmap:101 telephone-event/8000
a=ptime:20
```

Native JSON offer, with the codec directives carried as `profile.flags` strings:

```json
{
  "id": 1,
  "command": "offer",
  "call_id": "volte-pstn-1",
  "from_tag": "a1b2c3",
  "sdp": "v=0\r\n... A's AMR-WB offer ...",
  "profile": { "flags": ["codec-transcode-PCMA"] }
}
```

The same over NG, either as flat flags:

```
{ "command": "offer", "call-id": "volte-pstn-1", "from-tag": "a1b2c3",
  "sdp": "v=0\r\n...",
  "flags": ["codec-transcode-PCMA"] }
```

or as the structured `codec` dictionary stock rtpengine clients emit (both are normalized into
the same internal form):

```
{ "command": "offer", "call-id": "volte-pstn-1", "from-tag": "a1b2c3",
  "sdp": "v=0\r\n...",
  "codec": { "transcode": ["PCMA"] },
  "ptime": 20 }
```

The offer the engine hands you for B now carries PCMA appended (with a fresh `a=rtpmap:8`).
B answers PCMA only; you pass that answer to the engine:

```json
{ "id": 2, "command": "answer", "call_id": "volte-pstn-1",
  "from_tag": "a1b2c3", "to_tag": "d4e5f6",
  "sdp": "v=0\r\n... B's PCMA answer ..." }
```

Near primary AMR-WB, far primary PCMA: the codecs differ, the transcoder engages. The answer the
engine returns for A is rewritten to advertise **A's own codec** (AMR-WB, plus the negotiated
telephone-event PT), never B's: an answer may only contain formats from the recipient's own offer
(RFC 3264 §6). For AMR-WB it also advertises `octet-align=1` and, when a `mode-set` was
negotiated, the mode the engine will actually send (RFC 4867 §8.1); the engine's AMR-WB egress is
octet-aligned framing (RFC 4867 §4.4).

If the far side is codec-capable and simply *answers* a different codec than A offered, the same
promotion happens with no flags at all. The flags only shape the offer.

## AMR-NB to G.711

Same shape: the NB leg offers `AMR/8000` (RFC 4867), the far side ends up on G.711, and the
differing primaries engage the transcoder. Ingress AMR-NB decodes in all 8 modes; egress toward
the AMR-NB leg encodes MR122.

One asymmetry to know: `codec-transcode-AMR` is **not** an accepted directive target. The engine
only injects codecs it can unconditionally encode into a far offer, and the AMR-NB encoder covers
two modes, so AMR-NB cannot be forced into an offer that never contained it (the directive is
skipped, the call proceeds without it). `codec-transcode-AMR-WB` *is* accepted on `amr` builds.
In practice this costs nothing: the AMR leg is the access leg that offered AMR itself.

## The codec directives

All of them edit the SDP offered to the far side; names are matched case-insensitively.

| Directive | Effect |
|---|---|
| `codec-strip-X` | remove X from the far offer |
| `codec-mask-X` / `codec-consume-X` | remove X from the far offer, keeping it usable on the near leg (same far-offer edit as strip here; the near leg's codec always comes from its own unmodified offer) |
| `codec-transcode-X` | append X to the far offer; the transcoder engages if the far side selects it |
| `codec-except-X` / `codec-accept-X` | keep-list: X survives any strip/mask sweep |
| `codec-offer-X` (repeatable) | whitelist and ordering: only the listed codecs survive, in flag order |
| `codec-strip-all` / `codec-mask-all` (also `full`) | sweep every codec except the keep-list |

Guard rails, deliberately conservative: the engine never empties the audio codec list (masking
the only offered codec leaves it in place, RFC 4566 requires a non-empty format list), never
fails a call over an unknown or not-yet-encodable `transcode` target (the directive is skipped),
and telephone-event (RFC 4733) survives every sweep unless named outright.

Accepted `codec-transcode` targets today: `PCMU`, `PCMA`, `G722`, `GSM`, `G726-32`, and, on
`amr` builds, `AMR-WB`.

## Mode-set, ptime, DTMF

**`mode-set` (AMR-WB).** The peer's `a=fmtp` `mode-set` (RFC 4867 §8.1) is honoured: the egress
encode mode is clamped into the set (default mode 2 when permitted, else the nearest allowed),
and per-frame CMR adaptation stays within it, so the engine never sends a mode the peer
disallowed. An AMR-NB `mode-set` is not yet resolved onto the egress mode; AMR-NB egress is
MR122.

**ptime.** Each leg's packetization follows its own SDP `a=ptime`, defaulting to 20 ms
(RFC 3551); the transcoder builds each leg's codec at that leg's ptime. The NG `ptime=N` option
now re-frames the egress via a repacketizer (decoupling ingress from egress framing) and forces
the egress packetization, updating the answer `a=ptime`. AMR (frame-based) ignores the override
by construction (fixed native frame).

**DTMF.** RFC 4733 telephone-events are not decoded as audio: they are detected, surfaced as
`dtmf` events on the control channel, and repacketized onto the egress stream using the far
leg's negotiated telephone-event payload type.

## How to verify

- **The answer SDP** returned to A must advertise only A's codec (and its telephone-event PT).
  If you see B's codec leaking back to A, you are not looking at a transcoding call.
- **Metrics:** `siphon_rtp_transcode_sessions` on `/metrics` counts live transcoding calls
  separately from plain relays, and the `load` verb reports the same figure as
  `transcode_sessions`, because a transcoding call costs real CPU where a relay does not.
- **On the wire:** a pcap shows different payloads per leg. Toward the G.711 side: PT 8, 160-byte
  payloads (20 ms at 8 kHz, one byte per sample). Toward the AMR-WB side: the dynamic PT with
  octet-aligned AMR-WB frames. The engine re-originates SSRC and sequence numbers on a
  transcoded stream (it is producing new media), unlike a plain relay.
- **Failure mode:** on a default (no `amr`) build, the answer that would engage AMR transcoding
  returns `result: error` with a reason naming the `amr` build feature. That is the intended
  patent posture, not a bug.

## See also

- [Codec licensing](../codec-licensing.md) for the passthrough-is-always-free rule and the
  per-codec patent posture.
- [Plain RTP relay](relay.md) when both sides can share a codec; prefer it, transcoding costs
  CPU and a little quality.
- [Secure media (SRTP)](secure-srtp.md): a secure leg whose codec differs also transcodes
  (decrypt, transcode, encrypt) in the same media path.
