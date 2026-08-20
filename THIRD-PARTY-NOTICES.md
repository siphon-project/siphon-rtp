# Third-party notices

siphon-rtp is pure Rust and links no third-party C libraries. Several of its hand-written
codec implementations were, however, **ported** from an existing reference implementation:
the Rust is a fresh, from-scratch translation, but the algorithm, the block/function
decomposition, and in some cases the ROM constant tables follow a specific upstream, as the
codec source headers spell out function by function. This file attributes those upstreams and
reproduces their copyright and licence notices.

No third-party C source and no codec reference test vectors are committed to this repository. The
reference C is fetched separately and read only as the algorithm reference (it is gitignored,
never compiled, never redistributed); the official 3GPP/ITU-T test vectors are likewise kept
out of git history. What is attributed below is, for the codecs, the *lineage* of the Rust ports,
not any bundled upstream code.

**One upstream artifact is an exception and *is* redistributed here:** the trained parameters of
the neural voice-activity detector, plus the speech recording its conformance vectors are cut
from, both from the MIT-licensed Silero VAD release. See
[Silero VAD (neural voice activity detection)](#silero-vad-neural-voice-activity-detection) below.

> **Important: this is attribution, not a licence-compatibility ruling.** Recording where each
> codec was ported from and under what upstream terms does **not** assert that re-licensing
> those derivations under siphon-rtp's MIT licence is resolved. Whether a bit-exact Rust port
> of an LGPL-2.1 (spandsp), 3GPP, or ITU-T reference implementation may itself be distributed
> under MIT is an **open question for legal counsel**, owned by the maintainer, and is not
> settled by this file. Patent posture is a separate question again, covered in
> [docs/codec-licensing.md](docs/codec-licensing.md).

---

## libgsm (GSM 06.10 Full-Rate)

The `GSM` codec (`crates/siphon-rtp-codec/src/gsm_fr.rs`) is ported from the plain path of
**libgsm** by Jutta Degener and Carsten Bormann (Technische Universität Berlin), which
implements the bit-exact ETSI / 3GPP TS 06.10 full-rate reference. Field and function names in
the Rust follow libgsm so each step maps onto TS 06.10 §4.2/§4.3.

The in-tree source header currently calls libgsm "public-domain"; that is imprecise. libgsm
ships the permissive, attribution-preserving notice below (not a public-domain dedication):

```
Copyright 1992, 1993, 1994 by Jutta Degener and Carsten Bormann,
Technische Universitaet Berlin

Any use of this software is permitted provided that this notice is not
removed and that neither the authors nor the Technische Universitaet Berlin
are deprecated by mentioning them in advertising without prior written
permission.

The authors offer no warranty. If it does not work for you, too bad.
The authors do not accept responsibility for any damage this software
may cause.
```

## spandsp (G.726 ADPCM)

The `G726` codec (`crates/siphon-rtp-codec/src/g726.rs`) follows the fixed-point steps
(`quan` / `fmult` / `predictor` / `update` and the tandem-adjustment logic) of the **spandsp**
G.726 reference by Steve Underwood, which implements ITU-T G.726. spandsp is distributed under
the **GNU Lesser General Public License, version 2.1**.

```
Copyright (C) Steve Underwood <steveu@coppice.org>

spandsp is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License version 2.1, as
published by the Free Software Foundation.

spandsp is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
more details.
```

The full LGPL-2.1 text is at <https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html>. The
LGPL is a copyleft licence; its compatibility with distributing this derived port under MIT is
one of the open counsel questions noted above.

## 3GPP reference software (AMR-NB and AMR-WB)

The AMR codecs (`crates/siphon-rtp-codec/src/amr/`, behind the `amr` feature) are bit-exact
ports of the 3GPP fixed-point reference C:

- **AMR-NB** encode + decode from **3GPP TS 26.073** (fixed-point C; `cod_amr.c`, `sp_enc.c`,
  and the per-function DSP kernels), with the ROM constant tables (`gains.tab`, `window.tab`,
  `lag_wind.tab`, `grid.tab`, …) copied verbatim from the TS 26.073 tables. The ANSI-C variant
  is **TS 26.104**. Decode is validated against the **TS 26.074** conformance vectors.
- **AMR-WB** decode from **3GPP TS 26.173** (`dec_main.c`) and encode from **3GPP TS 26.190 /
  TS 26.173** (`cod_main.c`). The ANSI-C variant is **TS 26.204**; decode is validated against
  the **TS 26.174** conformance vectors.

The 3GPP reference software is © the **3GPP Organizational Partners** (ARIB, ATIS, CCSA, ETSI,
TSDSI, TTA, TTC) and is distributed for the purpose of implementing 3GPP specifications, under
3GPP's terms and subject to the associated third-party IPR (the AMR patent pool; see
[docs/codec-licensing.md](docs/codec-licensing.md) for the patent posture, which is why the
codecs are gated behind an opt-in `amr` feature). Copyright in the underlying specifications
and reference software remains with the 3GPP Organizational Partners.

## ITU-T reference software (G.711 STL, G.722)

- **G.711** (`crates/siphon-rtp-codec/src/g711.rs`) is a clean-room implementation of the ITU-T
  G.711 companding law (256-entry decode table + the CCITT segment search), not a port. It is
  validated bit-exact against the **ITU-T G.191 Software Tools Library (STL)** reference.
- **G.722** (`crates/siphon-rtp-codec/src/g722.rs`) is ported from the **ITU-T G.722** reference:
  each block carries its ITU-T G.722 block name (`QUANTL`, `SCALEL`, `RECONS`, …) and the Rust
  follows the reference arithmetic exactly. It is validated against the ITU-T G.722 Appendix II
  conformance sequences.

The ITU-T G.191 STL and the ITU-T G.722 reference software are © the **International
Telecommunication Union (ITU)** and are distributed under ITU-T's terms for implementing ITU-T
Recommendations. The Recommendation text and reference software copyright remain with the ITU.

## libopus / Xiph.Org (Opus)

The pure-Rust Opus codec (`crates/siphon-rtp-codec/src/opus/`) — decoder and encoder — ports the
float build of **libopus** (Xiph.Org) and conforms to RFC 6716. It is wired into the codec factory
and used for transcoding; it is attributed here because the code in the tree derives from libopus.
libopus is under the **3-clause BSD licence**:

```
Copyright (c) 2001-2011 Xiph.Org, Skype Limited, Octasic,
                        Jean-Marc Valin, Timothy B. Terriberry,
                        CSIRO, Gregory Maxwell, Mark Borgerding,
                        Erik de Castro Lopo

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

- Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

- Neither the name of Internet Society, IETF or IETF Trust, nor the
  names of specific contributors, may be used to endorse or promote
  products derived from this software without specific prior written
  permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Silero VAD (neural voice activity detection)

Unlike everything above, this is **not** a port of an algorithm — it is upstream *content*
redistributed in the binary. `crates/siphon-rtp-dsp/src/vad/neural.rs` is a hand-written pure-Rust
forward pass of the **Silero VAD v5** network, and it runs that network's own trained parameters,
embedded verbatim at `crates/siphon-rtp-dsp/src/vad/silero_vad_v5_16k.f32`. No inference runtime,
no ONNX parser and no C are involved; the file is a flat little-endian `f32` blob read with
`include_bytes!`.

| | |
|---|---|
| Upstream | <https://github.com/snakers4/silero-vad> |
| Release | tag `v5.1.2` |
| Source file | `src/silero_vad/data/silero_vad.onnx`, sha256 `2623a2953f6ff3d2c1e61740c6cdb7168133479b267dfef114a4a3cc5bdd788f` |
| Embedded blob | `silero_vad_v5_16k.f32`, 309 633 `f32` / 1 238 532 bytes, sha256 `b8df2e6e32753b7aa47ab59571b0d9d0b490a223f8dc9118bb388efeaec6f8e3` |
| Content | the 16 kHz branch only (STFT basis, four encoder convolutions, the LSTM, the output convolution) |
| Licence | MIT |

The conformance vectors under `crates/siphon-rtp-dsp/tests/vectors/` are also upstream-derived:
`neural_vad_speech.pcm` and the far-end material in the echo cases are cut from
`tests/data/test.wav` of the same repository (sha256
`89f17d9c94c4b31eb320f424628bcbc920abaddbee6e2760fd868bfb1d9a2e47`), and every `*.f32` is that
release's own ONNX graph run over the matching PCM by `onnxruntime`, out of tree, once. The
extraction and generation scripts are committed at `reference/silero-vad/` so both the blob and the
vectors can be regenerated from the upstream release and byte-compared; neither Python nor
`onnxruntime` is a build or test dependency.

```
MIT License

Copyright (c) 2020-present Silero Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Dependency licences

The above concerns codec *ports*. The full set of Rust dependency crates compiled into a build,
with their SPDX licence identifiers, is in the generated SBOM (SPDX 2.3 + CycloneDX 1.4)
attached to each release; see [docs/supply-chain.md](docs/supply-chain.md). Everything there
resolves to permissive, MIT-compatible terms, the one non-OSI item being `webpki-roots`
(`CDLA-Permissive-2.0`, a permissive data licence for the bundled Mozilla CA set), allow-listed
in `deny.toml`.
