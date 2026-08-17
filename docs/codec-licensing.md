# Codec licensing & patent posture

> **Source of truth for which codecs siphon-rtp will *transcode* by default, and why.** This sits
> alongside the hard rule in the project conventions: **pure Rust, zero C deps, license-free by
> default.** Some codecs the engine must interoperate with are patent-encumbered; this document is
> how we keep the *default* build clean while still letting an operator who holds the relevant
> licences opt those codecs in.

## The one rule that matters: passthrough is always free

**Relaying (passthrough) a codec is not the same as implementing it.** When the engine relays an
RTP stream — the in-kernel `FlowAction::Forward` fast path, or the userspace relay-only path — it
**never executes the codec**: the RTP payload is forwarded byte-for-byte, exactly as rtpengine does
by default. Forwarding packets you did not decode carries **no codec patent exposure**.

So, for *every* codec — AMR-NB, AMR-WB, G.729, EVS, anything — **passthrough/relay is always
available and always enabled.** No feature flag, no caveat. You only enter patent territory when you
ask the engine to **transcode** (decode + re-encode), because that runs the codec implementation.

```
AMR ──relay──▶ AMR              always available, no patent exposure (no codec executed)
AMR ─transcode▶ G.711           runs the AMR codec → patent-gated (opt-in feature)
```

## How transcoding of encumbered codecs is gated

Patent-encumbered codec **transcoding** is gated behind **off-by-default Cargo features** on
`siphon-rtp-codec`, one per codec. With the feature off, the codec factory returns
`CodecError::Unsupported` for that codec (so a call that *requires* transcoding it fails cleanly at
setup); passthrough is unaffected. The encumbered codec's source is not even compiled into the
default binary.

| Cargo feature | Codecs | Status |
|---|---|---|
| `amr` | AMR-NB (TS 26.071), AMR-WB / G.722.2 (TS 26.171) | implemented, bit-exact (AMR-WB decode + encode, all 9 modes; AMR-NB decode + encode, all 8 speech modes) |
| `g729` *(planned)* | G.729, G.729A/B | not yet implemented |
| `evs` *(planned)* | EVS (TS 26.441…) | not yet implemented (largest effort; post-Opus) |

**Enabling any feature above is an explicit statement that you, the operator, hold the necessary
patent licence(s) for that codec in your jurisdiction.** Build with e.g. `--features amr`.

## Per-codec patent posture

**License-free by patents — no feature flag needed to run them.** The patent column is
the posture; whether the engine can *transcode* one today is the separate implementation
status on the right (passthrough of every codec is always available, per the rule above).

| Codec | Patent basis | Transcode status |
|---|---|---|
| G.711 µ-law / A-law, L16 | patents long expired; trivial | implemented, bit-exact |
| G.722 | ITU-T, patents expired (1988) | implemented, bit-exact |
| G.726 (16/24/32/40k) | ITU-T, patents expired | implemented, bit-exact |
| GSM 06.10 Full-Rate | patents expired; ETSI | implemented, bit-exact |
| CN (RFC 3389) | free | generate/decode only |
| iLBC | royalty-free (Google/WebRTC, BSD) | not implemented (passthrough only) |
| Speex | royalty-free (Xiph, patent-free by design, BSD) | not implemented (passthrough only) |
| Opus | royalty-free (IETF RF by design, RFC 6716) | decode wired into the factory (transcoding *from* Opus works; the encoder is still in progress, so transcoding *toward* Opus declines and passthrough is always available) — and **no Cargo feature**, since it is royalty-free |

**Patent-encumbered — transcoding gated behind an opt-in feature:**

| Codec | Posture |
|---|---|
| AMR-NB / AMR-WB | 3GPP patent pool. Core patents have largely expired (NB ~2019, WB ~2022) but there is **no explicit royalty-free grant** — treat as licence-required. *Mandatory for VoLTE*, so implemented (behind `amr`); the operator carries the licence. |
| G.729 / G.723.1 | Core patents expired (~2015–2017) but, again, **no explicit grant** — a counsel-grade call. Gated behind `g729` when implemented. |
| EVS | **Actively encumbered** — large pool (Fraunhofer/Qualcomm/Nokia/…), filed ~2012–14, **no expiry until ~2032+**. Always gated; only ever compiled in by an explicitly-licensed operator. |

## Excluded outright

Nothing is *technically* excluded — the `evs`/`g729` features mean even the heavily-encumbered
codecs can be compiled in by a licensed operator. The line we hold is: **the default build ships
only license-free codecs**, and **passthrough of everything is always available**.

## Provenance

Patent posture (above) is one axis; **copyright provenance** is a separate one. Several codecs are
pure-Rust *ports* of a reference implementation — a from-scratch translation, but one that follows
a specific upstream's algorithm, block decomposition, and (in places) ROM tables, as the source
headers document function by function. Who each was ported from, and under what terms:

| Codec | Ported from | Upstream terms |
|---|---|---|
| GSM 06.10 Full-Rate | libgsm (Degener/Bormann, TU Berlin) | permissive, attribution-preserving (not public domain, despite the in-tree header) |
| G.726 | spandsp G.726 (Steve Underwood) | LGPL-2.1 |
| AMR-NB (encode + decode) | 3GPP TS 26.073 fixed-point reference C (ANSI-C: TS 26.104) | 3GPP Organizational Partners' reference-software terms + AMR patent pool |
| AMR-WB (encode + decode) | 3GPP TS 26.173 / TS 26.190 reference C (ANSI-C: TS 26.204) | 3GPP Organizational Partners' reference-software terms + AMR patent pool |
| G.722 | ITU-T G.722 reference | ITU-T reference-software terms |
| Opus (decoder complete and factory-wired; encoder in progress) | libopus float build (Xiph.Org) | BSD-3-Clause |

G.711 is a clean-room implementation of the companding law (not a port), validated against the
ITU-T G.191 STL vectors. The full copyright/licence notices for every upstream above are
reproduced in
[`THIRD-PARTY-NOTICES.md`](https://github.com/siphon-project/siphon-rtp/blob/main/THIRD-PARTY-NOTICES.md)
at the repository root.

> **This records lineage; it does not resolve licence compatibility.** Whether a bit-exact Rust
> port of an LGPL-2.1 (spandsp), 3GPP, or ITU-T reference may itself be distributed under
> siphon-rtp's MIT licence is an **open legal-counsel question** owned by the maintainer, not
> settled by the attribution above.
