# ITU-T G.729 — reference C and conformance vectors

`fetch.sh` pulls the ITU-T G.729 Release 3 software package from the in-force Recommendation's
electronic attachment, verifies it against a pinned SHA-256, and lays it out as:

| path | what it is |
|---|---|
| `c-code/g729` | base codec, 8 kbit/s CS-ACELP fixed-point reference |
| `c-code/annex-a` | Annex A — reduced complexity, bitstream-interoperable with the base codec |
| `c-code/annex-b` | Annex B — VAD / DTX / CNG, on the base codec (G.729B) |
| `c-code/annex-ba` | Annex B on Annex A (G.729AB) |
| `testv/base` | base-codec test vectors |
| `testv/annexa` | Annex A test vectors |
| `testv/annexb` | Annex B test vectors (both B and AB sequences) |

Nothing in this directory is compiled, packaged, or shipped. The C is read as the algorithm
reference the Rust port follows function by function; the vectors are the acceptance criteria. Both
are gitignored — see the entries in [`../.gitignore`](../.gitignore) for why.

## The acceptance criterion, and why a round trip is not one

Upstream generated every vector with the reference binaries:

```
coder   file.in  file.bit
decoder file.bit file.pst
```

so the vectors pin **both directions independently**:

- encode `*.in` → must equal `*.bit`, byte for byte;
- decode `*.bit` → must equal `*.pst`, byte for byte.

That independence is the whole point. A shared bug in an encoder/decoder pair passes a round trip
and fails here, which is why `decode(encode(x)) == x` is not accepted as evidence for any codec in
this tree.

Some sequences ship `.bit` + `.pst` only, with no `.in`: they are decoder-side robustness cases
(`erasure`, `overflow`, `parity`) whose bitstreams are not the output of encoding anything.

What each base sequence exercises, per upstream's `testv/base/readmetv.txt`:

| sequence | exercises |
|---|---|
| `algthm` | conditional parts of the algorithm |
| `erasure` | frame-erasure recovery |
| `fixed` | fixed (algebraic) codebook search |
| `lsp` | LSP quantization |
| `overflow` | overflow detection in the synthesizer |
| `parity` | parity check |
| `pitch` | pitch search |
| `speech` | generic speech |
| `tame` | the taming procedure |

Upstream is explicit that passing these is a **minimum** requirement rather than a validation
procedure: the set is not exhaustive, and it does not claim to be.

## Provenance

| | |
|---|---|
| Package | ITU-T G.729 (06/2012), electronic attachment `T-REC-G.729-201206-I!!SOFT-ZST-E`, Software Release 3 |
| Archive sha256 | `979680ff3b52b13a5701453178efd32b53e340114638fd330fdb6669eec86620` (18 476 968 bytes, byte-stable across downloads, hence pinned) |
| Reference C copyright | (c) 1995 AT&T, France Telecom, NTT, Université de Sherbrooke — all rights reserved, provided as part of the Recommendation |
| Terms | ITU-T reference-software terms, as recorded for G.722 in [`docs/codec-licensing.md`](../../docs/codec-licensing.md) |

The copyright on the reference software is a separate axis from the patent posture on the codec
itself; both are recorded in [`docs/codec-licensing.md`](../../docs/codec-licensing.md), and the
transcoding path is gated behind the off-by-default `g729` Cargo feature for the second reason, not
the first.

## Re-running

```sh
sh reference/g729/fetch.sh
```

It caches the archive, so a second run re-extracts without re-downloading. If the ITU republishes
the attachment the hash check fails closed: review what changed, then re-pin the hash here and in
`fetch.sh` as a deliberate commit.
