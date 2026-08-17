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
| Opus | `opus` (dynamic, `opus/48000/2`) | yes — SILK, CELT and Hybrid, mono and stereo, all bandwidths and frame durations, PLC and in-band FEC | yes — SILK, CELT and Hybrid, mono and stereo, VBR / constrained VBR / CBR, LBRR/FEC and DTX | all 12 official RFC 6716 vectors (mono + stereo), plus exact per-packet `final_range`; the encoder against libopus' own decoder over the full configuration matrix | none (royalty-free) |
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

**Opus.** **Both directions are complete and wired into the codec factory**, so an Opus leg
transcodes either way — Opus ↔ G.711 and Opus ↔ AMR-WB, the WebRTC-trunk and voice-AI
cases — end to end, and Opus is advertised in the `node_info` capability list.

*Decode* covers everything RFC 6716 §4 defines: SILK-only, CELT-only and Hybrid including
mid-packet mode switching and redundancy frames, all five bandwidths, every frame duration
from 2.5 ms to a 120 ms multi-frame packet, full stereo, all five output rates, PLC,
in-band FEC (LBRR) and DTX. It is gated on all 12 official RFC 6716 test vectors in both
the mono and the stereo pass, and additionally on exact `final_range` equality for every
packet of every vector — bitstream-exactness, which the §6 `opus_compare` tolerance metric
cannot see.

*Encode* covers the same ground: real mode / bandwidth / channel decisions driven by the
target rate and the signal (not a fixed mode), VBR, constrained VBR and CBR, LBRR/FEC
generation and DTX. It is gated by encoding the configuration matrix and holding the result
up to libopus' own decoder and `opus_compare`.

Three things the negotiated SDP contributes to the decoder, and nothing else does: the
output sample rate (the RFC 7587 §4.1 clock rate, 48 kHz), the ingress channel count (the
peer's `sprop-stereo`, §6.1 — *not* the rtpmap `/2`, which §7 mandates even for mono), and
the nominal frame (the negotiated `ptime`). A packet carrying more than the negotiated
ptime still decodes in full: the media path's decode buffer is sized for the 120 ms
ceiling, which is exactly why a 60 ms Opus sender does not lose audio.

The encoder takes the same three plus the peer's remaining `a=fmtp` limits (below). Its
frame is the negotiated `ptime` **snapped down to a duration Opus can emit** — RFC 6716 §2
defines 2.5/5/10/20/40/60 ms frames and §3.2 extends that to 80/100/120 ms multi-frame
packets, so `a=ptime:30` (legal SDP, and common on G.711 trunks) is sent as 20 ms rather
than failing every encode. RFC 4566 §6 makes `ptime` a recommendation, so this is within
spec; the decode side snaps identically, which keeps both halves of one leg describing the
same frame. (The `a=ptime` the engine *advertises* is still the negotiated value, so on an
off-grid ptime the advertisement rounds up on what is sent — harmless, since a shorter
packet than advertised is always acceptable, but worth knowing when reading a trace.)
The application is `VoIP` (libopus `OPUS_APPLICATION_VOIP`) — every Opus leg the
engine encodes toward is a telephony leg. Egress is mono; Opus is **stateful**, so it never
joins the conference's shared-encode fan-out (each listener gets its own encode).

The rest of the engine surface is in place. The engine parses and honours the RFC 7587
payload format:

- `a=rtpmap:<pt> opus/48000/2` is emitted **unconditionally**, mono included — RFC 7587 §7
  requires the channel count, and it names the RTP channel count, not the audio one. A
  peer that signals a different clock rate or channel count is corrected to 48000/2
  (RFC 7587 §4.1 — Opus clocks RTP at 48 kHz in every mode).
- The `a=fmtp` parameters of RFC 7587 §6.1 are parsed onto the negotiated codec and **every
  one of them is honoured**. An absent or malformed parameter falls back to its RFC default
  and an out-of-range value is clamped into the range the RFC permits; nothing there can
  panic.

  | Parameter | What it drives | Observable on the wire as |
  |---|---|---|
  | `sprop-stereo` | the ingress channel count the decoder is built for | — (it describes the peer's stream) |
  | `maxptime` | caps the leg's egress `ptime` | shorter packets, `a=ptime` in the answer |
  | `maxaveragebitrate` | the encoder's target bitrate (`OPUS_SET_BITRATE`) | packet size, and the mode/bandwidth the rate then selects in the TOC |
  | `maxplaybackrate` | the encoder's maximum bandwidth (`OPUS_SET_MAX_BANDWIDTH`), per the §3.1.1 rate↔bandwidth table | the bandwidth coded in the TOC byte |
  | `cbr` | rate control: CBR vs constrained VBR (`OPUS_SET_VBR`) | every packet padded to one constant length |
  | `useinbandfec` | LBRR generation (`OPUS_SET_INBAND_FEC`) | each SILK/hybrid packet carries a recoverable copy of the previous frame |
  | `usedtx` | discontinuous transmission (`OPUS_SET_DTX`) | a silent run collapses to bare one-byte TOC packets |
  | `stereo` | nothing — it is a *ceiling* (§7.1), and the engine's egress is mono regardless | — |

  One wrinkle worth stating: libopus will not spend bits on an LBRR copy while its packet-loss
  figure is 0 (`decide_fec`, `opus_encoder.c:811`), so `useinbandfec=1` alone would generate no
  FEC at all. The engine therefore also hands the encoder a conservative 5 % loss assumption when
  the peer declares it — 5 % being the highest figure at which libopus will *not* trade audio
  bandwidth away to afford FEC, so the peer keeps the bandwidth its `maxplaybackrate` bought.
  When per-leg RTCP loss feedback reaches the encoder that assumption becomes the measured figure.
- Frame durations up to 120 ms are carried end to end. RFC 7587 §6.1 allows a ptime that
  long and RFC 6716 §3.2 lets a single packet carry 120 ms whatever ptime was negotiated,
  so the media path's frame buffers are sized for 48 kHz × 120 ms × 2 channels.
- Every parameter the engine declares back is its own posture, not an echo of the peer's:
  the answer carries `a=fmtp:<pt> stereo=0;sprop-stereo=0` (the engine's media path is
  mono — see "Channels and PCM layout" below) plus `a=ptime` and `a=maxptime:120`.

Because Opus is royalty-free (RFC 6716 is an IETF royalty-free design), it gets **no Cargo
feature** — see [Codec licensing](codec-licensing.md). It appears in the `node_info`
capability list only when the factory can build a decoder *and* an encoder for it — which it
now can, so a dispatcher may route Opus calls here, and could never have been told about a
transcode this build cannot perform.

## Channels and PCM layout

Every telephony codec here is mono. Opus is the first that need not be (RFC 7587 §6.1
signals mono or stereo through the `stereo` / `sprop-stereo` fmtp parameters), so the
`Decoder`/`Encoder` trait boundary fixes the layout once, for all codecs:

- **PCM is interleaved.** A multi-channel frame is `L, R, L, R, …` — channel-major within a
  sample instant, never planar. That is the layout `opus_decode` produces and the layout
  RIFF/WAVE stores, so no repacking happens at either edge.
- `CodecParams::frame_samples()` is the frame length in **samples per channel** (i.e. in
  time); `CodecParams::frame_values()` is the **`i16` count of one interleaved frame**. A
  buffer is sized by `frame_values`, a duration or RTP-timestamp step by `frame_samples`.
  `Decoder::frame_samples()` / `Encoder::frame_samples()` are the *buffer* contract, so they
  are interleaved counts. For every mono codec the two numbers are identical.
- **The media path itself is mono.** The mixer, resampler, jitter buffer, echo canceller,
  noise suppressor, and RTP timestamp arithmetic are all single-channel. A multi-channel
  decoded frame is therefore folded to mono once, immediately after `decode`, by
  `siphon_rtp_codec::downmix_to_mono` (the arithmetic mean of the channels at each instant),
  and everything downstream — including the recorder, which stays a 1-channel WAV — sees
  mono. The fold is driven by `params().channels`, not by the codec's identity, so it applies
  to any future multi-channel codec without a special case.
- **The engine's own egress is mono**, and it says so: `sprop-stereo=0` on every Opus answer.
  That is spec-clean — RFC 7587 §7.1 makes `stereo` a ceiling ("MUST NOT send stereo" when
  0), never an obligation to use it — and it saves the peer the bitrate of a channel the
  engine would discard. A stereo Opus stream still **relays** untouched, since passthrough
  never runs a codec.

Going genuinely multi-channel end to end (a stereo mixer, a two-channel resampler, a stereo
WAV) is a separate change; nothing in the codec work depends on it.

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
