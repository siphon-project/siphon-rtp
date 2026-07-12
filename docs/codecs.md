# Codec support

All codecs are hand-written pure Rust, no C libraries, and each one is accepted only
when it matches its official reference test vectors bit for bit. This page is the matrix
of what the engine can decode and encode today. It is deliberately conservative: if a
codec is not in the table, the engine cannot transcode it (it can still relay it, see
below).

## Passthrough is not transcoding

The relay never executes a codec. On a passthrough call the RTP payload is forwarded
byte-for-byte, so **any** codec relays: EVS, G.729, Opus, anything a peer negotiates
end-to-end. The codec implementations below are only invoked when you ask the engine to
*transcode* (decode + re-encode), inject prompts, mix a conference, or bridge to
WebSocket. That distinction also carries the patent posture: relaying an encumbered
codec is free, running it is not. See [Codec licensing](codec-licensing.md).

## The matrix

| Codec | SDP name (PT) | Decode | Encode | Bit-exact against | Cargo feature |
|---|---|---|---|---|---|
| G.711 µ-law | `PCMU` (0) | yes | yes | ITU-T G.711 companding law, exhaustive over all 256 code words | none (always on) |
| G.711 A-law | `PCMA` (8) | yes | yes | ITU-T G.711 companding law, exhaustive over all 256 code words | none |
| L16 / linear PCM | `L16` (dynamic) | yes | yes | trivial (RFC 3551 §4.5.11) | none |
| G.722 | `G722` (9) | yes | yes | ITU-T G.722 Appendix II conformance sequences, mode 1 (64 kbit/s) | none |
| G.726 16/24/32/40 | `G726-16/-24/-32/-40` (dynamic), `G721` alias | yes | yes | ITU-T STL test sequences, all four rates, both laws | none |
| GSM Full-Rate | `GSM` (3) | yes | yes | ETSI/3GPP TS 06.10 sequences, coder and decoder | none |
| Comfort noise | `CN` (13) | generate only | no | RFC 3389 (a generator, not a codec) | none |
| AMR-WB | `AMR-WB` (dynamic) | all 9 modes | all 9 modes | 3GPP TS 26.174 vectors, per mode | `amr` |
| AMR-NB | `AMR` (dynamic) | all 8 modes | all 8 modes | 3GPP TS 26.074 vectors | `amr` |
| Opus | `OPUS` | in progress | in progress | RFC 6716 test vectors (targeted) | not wired |
| EVS | | no | no | | absent |

The engine resolves a codec from the `a=rtpmap` encoding name (case-insensitive, RFC
4566 §6), falling back to the RFC 3551 §6 static payload-type table (`PCMU` 0, `GSM` 3,
`PCMA` 8, `G722` 9, `CN` 13) when no rtpmap is present. `telephone-event` (RFC 4733
DTMF) is not an audio codec; the media path detects and repacketizes it out of band.

## Per-codec notes

**G.711.** 8 kHz mono, one byte per sample; decode is a 256-entry table lookup. Packet
loss is concealed with comfort silence today; ITU-T G.711 Appendix I waveform
concealment is planned.

**G.722.** Carries 16 kHz audio but the RTP clock stays 8000 by the RFC 3551 §4.5.2
historical quirk; the engine gets this right in both SDP and timestamps. Mode 1
(64 kbit/s) only, which is what SIP deployments use.

**G.726.** All four rates encode and decode, bit-exact against the ITU-T STL test
sequences for every rate and both companding laws, including the 40 kbit/s overload
condition. The fixed-point arithmetic follows the spandsp reference lineage; that
provenance (and its licensing question) is tracked in
[Codec licensing](codec-licensing.md#provenance).

**GSM-FR.** GSM 06.10 full-rate, 13 kbit/s, the 33-byte RTP frame of RFC 3551 §4.5.8.
Both directions validated frame-by-frame against the ETSI sequences with zero tolerance.

**Comfort noise.** RFC 3389 payloads are *decoded* into synthesized noise at the leg's
rate. There is deliberately no CN encoder in the factory: emitting CN is a DTX policy
decision of the media path, not a per-frame codec.

**AMR-WB** (behind `amr`). Decode covers all 9 speech modes, 6.60 through 23.85 kbit/s,
bit-exact against the 3GPP TS 26.174 vectors, including the RFC 4867 payload
un-sorting. Encode is likewise vector-exact for all 9 modes, mode 8's high-band gain
tier included. The egress mode defaults to mode 2 (12.65 kbit/s), honours the SDP
`a=fmtp` `mode-set` (RFC 4867 §8.1), and adapts per frame to the peer's CMR clamped
into that mode-set. This is the VoLTE codec; it is what the `amr` feature exists for.

**AMR-NB** (behind `amr`). Decode and encode both cover all 8 speech modes (4.75 through
12.2 kbit/s), bit-exact against 3GPP TS 26.074: MR475, MR515, MR59, MR67, MR74, MR795
(7.95 kbit/s), MR102 (10.2 kbit/s) and MR122 (12.2 kbit/s, the GSM-EFR-equivalent mode).
MR795 carries an adaptive gain quantizer (a pre-quantizer over three pitch-gain candidates,
a gain adaptor, then a modified codebook-gain search) and is the only mode that sends two
gain indices per subframe. This is a full AMR-NB encoder for G.711 transcoding in both
directions; only DTX/SID (comfort-noise generation) is out of scope.

**Opus.** An implementation is under way with RFC 6716 conformance gating, but it is
**not wired into the codec factory**: a call that requires Opus transcoding fails at
setup with a clean error. Opus passthrough relays fine, like everything else.

**EVS.** Not implemented, and gated by an active patent pool besides; see
[Codec licensing](codec-licensing.md). EVS passthrough relays fine.

## The `amr` feature

`amr` is the only Cargo feature in the workspace and it is **off by default**. AMR-NB
and AMR-WB carry no explicit royalty-free grant, so the default binary does not even
compile their code; the factory returns a clean "requires the `amr` build feature" error
if a call demands AMR transcoding. Build with it only if you hold the licences:

```bash
cargo build --release --features amr
```

Passthrough of AMR in either variant needs no feature and no licence. The reasoning,
and the posture for every other encumbered codec, is in
[Codec licensing](codec-licensing.md).

## How conformance is enforced

Every codec ships its reference-vector test in-tree (ITU-T and 3GPP vectors are
licensed artifacts, so the files themselves are fetched separately; the tests skip with
a loud notice when absent and run bit-exact when present). Round-trip tests are treated
as insufficient on principle: a shared encode/decode bug passes a round-trip, so
acceptance is always against the official vectors. Hostile bitstreams are covered
separately: the RTP parser and frame decoders are fuzzed, and a malformed payload off
the network decodes-or-errors, never panics.
