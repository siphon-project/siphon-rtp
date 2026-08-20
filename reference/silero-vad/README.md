# Silero VAD v5 — weight extraction and conformance-vector generation

`crates/siphon-rtp-dsp/src/vad/neural.rs` is a hand-written forward pass of the Silero VAD v5
network. It embeds that network's trained parameters and is validated, per window and per
decision, against the upstream ONNX graph run by `onnxruntime`.

Neither the ONNX graph nor `onnxruntime` is a build or test dependency. **They are the oracle,
not a component.** These two scripts run once, out of tree, on a developer machine; what they
emit is committed, and the build never sees Python again. That is what keeps the validation
independent: the oracle does not share this port's bugs, which is exactly why a round trip or a
self-consistency check would not have counted.

Nothing in this directory is compiled, packaged, or shipped.

## What the scripts produce

| script | output | committed to |
|---|---|---|
| `extract_weights.py` | `silero_vad_v5_16k.f32` — the 16 kHz branch's tensors as a flat little-endian `f32` blob, in ONNX tensor order | `crates/siphon-rtp-dsp/src/vad/` |
| `make_vectors.py` | `neural_vad_*.pcm` (raw i16 LE mono @ 16 kHz) and `neural_vad_*.f32` (the reference speech probability per 512-sample window) | `crates/siphon-rtp-dsp/tests/vectors/` |

The blob keeps the upstream tensor order rather than the kernel's, so it can be regenerated and
byte-compared against the upstream release. The one re-layout the kernels want (transposing each
encoder convolution from `[out][in][tap]` to `[out][tap][in]`) happens once per process in
`vad/weights.rs`, not here.

## Provenance

| | |
|---|---|
| Model | `snakers4/silero-vad`, tag `v5.1.2`, `src/silero_vad/data/silero_vad.onnx` |
| Model sha256 | `2623a2953f6ff3d2c1e61740c6cdb7168133479b267dfef114a4a3cc5bdd788f` |
| Blob sha256 | `b8df2e6e32753b7aa47ab59571b0d9d0b490a223f8dc9118bb388efeaec6f8e3` (309 633 `f32`, 1 238 532 bytes) |
| Speech corpus | the same repository's `tests/data/test.wav` (60 s, 16 kHz mono), sha256 `89f17d9c94c4b31eb320f424628bcbc920abaddbee6e2760fd868bfb1d9a2e47` |
| Licence | MIT — see `THIRD-PARTY-NOTICES.md` |

**A warning, from an hour lost to it.** There is a third-party `safetensors` conversion of "Silero
VAD v5" published on a model hub. Its STFT basis matches the upstream ONNX exactly (that basis is
a deterministic Fourier basis, so it would), but **every trained tensor differs** — encoder
weights by up to 55.0, the LSTM by up to 3.4, and the value multisets do not match either, so it
is not a permutation or a re-layout of the real thing. A port built on it produced plausible-looking
probabilities that disagreed with the reference by up to 0.88. Extract from the upstream ONNX
release and check the hashes; do not trust a convenience conversion.

## Reproducing

```sh
# 1. fetch the upstream release artifacts (not committed)
curl -sSLo silero_vad_v5.1.2.onnx \
  https://github.com/snakers4/silero-vad/raw/v5.1.2/src/silero_vad/data/silero_vad.onnx
curl -sSLo silero_test.wav \
  https://github.com/snakers4/silero-vad/raw/master/tests/data/test.wav
sha256sum silero_vad_v5.1.2.onnx silero_test.wav   # must match the table above

# 2. an out-of-tree environment for the oracle
python3 -m venv .venv
.venv/bin/pip install onnx onnxruntime numpy

# 3. the weight blob
.venv/bin/python extract_weights.py silero_vad_v5.1.2.onnx silero_vad_v5_16k.f32

# 4. the conformance vectors (writes ./vectors/)
.venv/bin/python make_vectors.py
```

Then copy `silero_vad_v5_16k.f32` to `crates/siphon-rtp-dsp/src/vad/` and `vectors/*` to
`crates/siphon-rtp-dsp/tests/vectors/`, and run
`cargo test -p siphon-rtp-dsp --test neural_vad_conformance`.
