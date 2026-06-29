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
| `amr` | AMR-NB (TS 26.071), AMR-WB / G.722.2 (TS 26.171) | implemented (AMR-WB decode; encoder WIP) |
| `g729` *(planned)* | G.729, G.729A/B | not yet implemented |
| `evs` *(planned)* | EVS (TS 26.441…) | not yet implemented (largest effort; post-Opus) |

**Enabling any feature above is an explicit statement that you, the operator, hold the necessary
patent licence(s) for that codec in your jurisdiction.** Build with e.g. `--features amr`.

## Per-codec patent posture

**License-free — always on (transcode + passthrough), no flag:**

| Codec | Basis |
|---|---|
| G.711 µ-law / A-law, L16 | patents long expired; trivial |
| G.722 | ITU-T, patents expired (1988) |
| G.726 (16/24/32/40k) | ITU-T, patents expired |
| GSM 06.10 Full-Rate | patents expired; ETSI |
| CN (RFC 3389) | free |
| iLBC | **explicit royalty-free** — Google open-sourced it (BSD) via WebRTC |
| Speex | **explicit royalty-free** — Xiph, patent-free by design (BSD) |
| Opus | **explicit royalty-free** — IETF RF by design (RFC 6716) |

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
