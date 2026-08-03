# Contributing to siphon-rtp

Thanks for your interest. siphon-rtp is a pure-Rust, kernel-accelerated media engine (RTP/SRTP
relay, bit-exact VoLTE codecs, transcoding, conferencing, RTP↔WebSocket). This guide covers how to
build it, the test and quality gates a change has to clear, and how to submit it.

By contributing you agree that your contributions are licensed under the project's
[MIT license](LICENSE) (inbound = outbound).

For **security issues, do not open a public issue** — follow [SECURITY.md](SECURITY.md) (private
vulnerability reporting).

## Getting set up

You need a stable Rust toolchain. The minimum supported version (MSRV) is **1.88**; CI checks that
the shippable crates compile on it.

```sh
git clone https://github.com/siphon-project/siphon-rtp
cd siphon-rtp
cargo build --workspace
```

The XDP/eBPF loader (`crates/siphon-rtp-xdp`) is a separate, excluded workspace on its own pinned
nightly and is not built by `cargo build --workspace`. You only need it if you are working on the
kernel datapath; it requires `bpf-linker` and the pinned nightly toolchain.

## Tests

The default feature set uses the UDP-loopback datapath, so the whole suite (including the
integration tests, which are **not** `#[ignore]`d) runs with no NIC and no privileges:

```sh
cargo test --workspace                 # default features (NIC-free)
cargo test --workspace --all-features  # adds the AMR codecs (see "The amr feature")
```

Every module carries inline `#[cfg(test)] mod tests`; cross-crate behaviour lives in each crate's
`tests/`. New code needs tests: happy path, error paths, and edges. Prefer explicit byte-literal
wire fixtures over indented multi-line strings. Deterministic DSP tests are driven by a logical
sample-clock, never `Instant::now()`.

## Codec conformance vectors

Codecs are validated **bit-exact against their official reference vectors**, not just round-trips (a
shared encode/decode bug passes a round-trip). Those vectors are copyrighted and cannot be
redistributed, so they are gitignored; the conformance tests **skip gracefully when the vectors are
absent**, which is why a fresh checkout stays green.

Fetch the vectors from their sources and drop them under `reference/<codec>/testv/`:

| Codec | Source | Directory |
|---|---|---|
| G.722 / G.726 | ITU-T G.191 Software Tool Library (STL) | `reference/g722/testv`, `reference/g726/testv` |
| GSM Full Rate | ETSI / 3GPP TS 06.10 | `reference/gsm-fr/testv` |
| AMR-NB | 3GPP TS 26.074 | `reference/amr-nb/testv` |
| AMR-WB | 3GPP TS 26.174 | `reference/amr-wb/testv` |
| Opus | RFC 6716 official vectors (opus-codec.org) | `reference/opus/opus_testvectors` |
| Opus (CELT layer) | generated locally — see "Opus conformance oracle" below | `reference/opus/celt_only` |
| Opus (SILK layer) | generated locally — see "Opus conformance oracle" below | `reference/opus/silk_only` |
| Opus (SILK encoder analysis) | generated locally — see "Opus conformance oracle" below | `reference/opus/silk_enc` |

(G.711 and L16 need no external vectors: G.711 is validated exhaustively over all 256 code points,
L16 is an exact byte-order transform.)

To make a conformance run **fail loudly instead of silently skipping** when the vectors are missing
(use this once you have them, so you can't be fooled by a silent skip):

```sh
SIPHON_RTP_REQUIRE_VECTORS=1 cargo test --workspace --all-features
```

### Opus conformance oracle

Opus is the one codec whose conformance criterion is **not** bit-exact PCM: RFC 6716 §6 defines it as
a pass of the `opus_compare` perceptual metric, so float and fixed-point decoders both conform. That
tool ships with libopus, which means Opus conformance needs a **locally built, test-only C reference**.
libopus is never a dependency — `deny.toml` bans the `opus` / `audiopus` / `magnum-opus` crates by
name, and CI enforces it. It is an out-of-tree oracle binary, nothing more.

Unpack the libopus source under `reference/opus/opus-1.5.2/`, then:

```sh
cmake -S reference/opus/opus-1.5.2 -B reference/opus/build \
      -DCMAKE_BUILD_TYPE=Release -DOPUS_BUILD_PROGRAMS=ON -DOPUS_BUILD_TESTING=ON
cmake --build reference/opus/build -j
sh reference/opus/gen_celt_only.sh          # writes reference/opus/celt_only/*.bit + *.dec
sh reference/opus/gen_silk_only.sh          # writes reference/opus/silk_only/*.bit + *.dec
sh reference/opus/gen_silk_plc.sh           # adds reference/opus/silk_only/*.plcdec + plc.loss
SIPHON_RTP_OPUS_COMPARE=$PWD/reference/opus/build/opus_compare \
    cargo test -p siphon-rtp-codec --test celt_only_conformance --test silk_only_conformance \
                                   --test silk_plc_conformance --test opus_conformance
```

`gen_celt_only.sh` writes two directories: `celt_only/` (mono) and `celt_only_stereo/`. They are kept
apart because the mono harness globs its directory and rejects a two-channel packet, so a checkout
that only has one of them still works. Note that the **Opus layer above CELT** has its own,
content-adaptive stereo decision and will downmix to mono below its threshold — mid-stream, not just
at the first packet — so the stereo sweep starts at the lowest rate that stays genuinely stereo for
each frame duration (64 kb/s at 2.5 ms, 48 kb/s at 5 ms, 24 kb/s at 10/20 ms). The harness fails
loudly on a mono packet in a stereo vector rather than tolerating it; the fix is to regenerate that
configuration higher, not to relax the check. Stereo streams are scored with `opus_compare -s`, so
both channels are compared instead of a downmix.

`gen_celt_only.sh` uses `opus_demo -e restricted-lowdelay` (which forces `MODE_CELT_ONLY`);
`gen_silk_only.sh` uses `opus_demo -e voip` at a low bitrate with the bandwidth capped at NB/MB/WB,
which keeps the encoder in `MODE_SILK_ONLY`. Neither is taken on trust: both harnesses assert
`toc.mode()` per packet and fail loudly if libopus ever slipped a frame of the other mode in.

`gen_silk_plc.sh` re-decodes the same SILK-only streams with `opus_demo -lossfile`, against a fixed
loss pattern, so `silk_plc_conformance` has an oracle for RFC 6716 §4.4. Concealment and comfort
noise are the only SILK stages that leave **no** trace in the range coder, so nothing else in the
suite can tell a real concealer from one that returns silence.

#### The SILK layer's own gates

`silk_only_conformance` decodes every SILK-only stream end to end and compares against libopus'
`.dec` **sample for sample** before running `opus_compare`. Bit-exactness is the real bar there: the
SILK port is integer-faithful to the reference fixed-point arithmetic all the way through the
resampler, so a rounding difference is a bug, not a tolerance. Two things it does not do, both
deliberate:

- **It does not check whole-packet `final_range`.** For a SILK-only packet with 17 or more spare bits
  libopus reads a redundancy flag and a CELT redundancy frame *after* the SILK layer and folds both
  into the reported range and into the last 2.5 ms of the output (`opus_decoder.c:452-480`). That is
  the top-level decoder's behaviour. The equivalent exact check at this layer's resolution is the
  per-frame `rng`/`tell` assertion in `silk_excitation_conformance`.
- **It excludes those redundancy-bearing packets from the PCM comparison**, on both sides, and
  reports how many (16 of ~75 000). They are not fudged and not silently tolerated — they are simply
  not this layer's output.

`SIPHON_RTP_OPUS_COMPARE` defaults to `/tmp/opus_compare`. Set it explicitly when working in a git
worktree — `reference/` is untracked, so a fresh worktree has no oracle of its own and should point at
a shared build.

Two things about this oracle are worth knowing before you fight it:

- **The reference `.dec` must be the *stereo* decode** (`opus_demo -d 48000 2`). `opus_compare` reads
  its reference file as 2-channel unconditionally and folds it to mono; hand it a mono `.dec` and it
  sees half the samples and exits with "Sample counts do not match". The official vectors are stereo
  for exactly this reason.
- **`opus_compare` is a tolerance metric and can pass a subtly wrong decoder.** Every packet in a
  `.bit` file also carries the encoder's range-coder final value, and a conformant decoder must finish
  the packet on exactly that value (`opus_demo` itself rejects a mismatch). The harnesses assert this
  per packet — it is the exact check, it localises a desync to one packet, and it is what actually
  caught the CELT band-range bug. Prefer it when debugging; treat `opus_compare` as the acceptance
  gate, not the diagnostic.

#### Validating the CELT **encoder**

An encoder has no reference `final_range` to match, so `celt_encode_conformance` stacks four checks
(same oracle build, same env override):

```sh
SIPHON_RTP_OPUS_COMPARE=$PWD/reference/opus/build/opus_compare \
    cargo test -p siphon-rtp-codec --test celt_encode_conformance -- --nocapture
```

1. Our stream is written in `opus_demo`'s `.bit` framing with **our encoder's** `final_range` beside
   every packet, so `opus_demo -d` aborts with "Range coder state mismatch" unless libopus' own
   decoder ends every packet exactly where we said. That is an exact bitstream check.
2. `CeltDecoder` decodes the same packets and must agree on every packet's `final_range` too.
3. libopus encodes the same source at the identical configuration (`opus_demo -e
   restricted-lowdelay -cvbr -bandwidth X -framesize Y`); our segmental SNR must be within 1 dB of
   its. This is the gate that works at *every* rate.
4. `opus_compare` against the original PCM, for fullband at the top of the rate range.

Two traps specific to the encode direction:

- **Compensate the 120-sample codec delay** before scoring. `opus_demo -d` cannot know the encoder's
  lookahead, so its output is shifted; unaligned, even libopus' own 256 kb/s fullband round trip
  scores 0.396 (fail) instead of 0.042 (83 % quality).
- **Do not score a band-limited or low-rate encode against the original PCM.** `opus_compare` measures
  *decoder* deviation. A 12 kb/s narrowband encode is legitimately far outside that tolerance — use
  check 3 there.

#### Validating the SILK **encoder**

An encoder has no reference `final_range` to match, but the SILK layer has something better than the
CELT one did: a **decoder that is already bit-exact against libopus over 64 streams**. Two
independent decoders agreeing on every sample of a stream neither has seen before is a very strong
statement about that stream, and it is what `silk_encode_conformance` asserts:

```sh
SIPHON_RTP_OPUS_COMPARE=$PWD/reference/opus/build/opus_compare \
    cargo test -p siphon-rtp-codec --release --test silk_encode_conformance -- --nocapture
```

1. Our stream is written in `opus_demo`'s `.bit` framing with **our encoder's** `final_range` beside
   every packet, so `opus_demo -d` aborts with "Range coder state mismatch" unless libopus' own
   range decoder finishes each packet exactly where we said. Exact, per packet.
2. `SilkDecoder` decodes the same packets and the two PCM outputs must be identical **sample for
   sample** — no tolerance, both are integer-faithful to the same reference arithmetic.
3. libopus encodes the same source at the identical bandwidth, frame size, bitrate and rate mode;
   our decoded segmental SNR must be within 1 dB of its. This is the gate that works at *every*
   rate and catches an encoder that is legal but bad.
4. `opus_compare` on the two decodes of **our own** stream, which check 2 says must score 100.0 %.

Two `opus_compare` runs are deliberately **not** made. Against the original 48 kHz PCM is
meaningless — SILK is band-limited to at most 8 kHz and the metric measures *decoder* deviation.
Against libopus' decode of libopus' own stream is equally meaningless: two independent encodings of
the same audio score a weighted error around 3 even when both encoders are perfectly good. Check 3
is the right tool for "as good as theirs".

The harness needs `reference/opus/src01.sw` (written by `gen_silk_only.sh`) and the plain
`reference/opus/build` — not `build-trace`. It skips the vector's first 2 s, which are near-silence,
so it is scored on real speech rather than on the DTX path. One thing it does that `SilkEncoder`
does not: it shrinks the range encoder to exactly the bytes SILK used, as `opus_encoder.c` does,
because a SILK-only packet with 17 or more spare bits makes libopus' *top-level* decoder go looking
for a redundancy frame. That belongs to the Opus layer, not to the SILK encoder.

#### Instrumented libopus, for validating a half-finished layer

Both oracles above need the decoder to consume a packet to its end, so neither can say anything about a
layer that is only partly ported — a SILK decoder that stops at the NLSF stage produces no PCM and never
reaches a final range. For that case there is a second, **intermediate-state** oracle: the same libopus
source built with printf dumps of the side info it decoded, diffed field by field against ours.

`reference/opus/silk_trace.patch` adds `#ifdef SILK_TRACE` blocks to the SILK decode path, each line
tagged with the packet index and — for the per-frame groups — a `u=` counter that increments once per
decoded SILK frame (LBRR frames first, then the regular ones), so a stereo or 60 ms packet is
unambiguous:

| File | Field group |
|---|---|
| `silk/dec_API.c` | VAD / LBRR flags, stereo predictors, mid-only flag |
| `silk/decode_indices.c` | frame type, gain indices, NLSF stage-1 + stage-2 indices, interpolation factor, pitch lags, LTP taps, LTP scaling |
| `silk/gain_quant.c` | dequantized Q16 gains |
| `silk/NLSF_decode.c` | dequantized Q10 residual with its unpacked prediction weights and entropy-table indices, the reconstructed NLSFs **before** stabilisation, and the stabilised NLSFs |
| `silk/decode_parameters.c` | the interpolated first-half NLSFs, and both halves' Q12 LPC coefficients |
| `silk/decode_pulses.c` | LCG seed, rate level, per-shell-block pulse counts, LSB blocks |
| `silk/decode_core.c` | the reconstructed excitation, and the range coder's `rng`/`tell` at the end of each frame |

It is purely additive — stripping the guarded blocks gives the original files back byte for byte, and
`patch -R` is verified to restore them exactly — and it is **one shared patch that every sub-phase
extends**, so add a field group rather than replacing the file, rebuild `build-trace` from the union,
and re-dump afterwards. A harness must ignore field groups it does not own; a closed allow-list means
whichever stage extended the patch last breaks every sibling harness. Apply it, build into a
**separate** build directory so the plain oracle above is untouched, dump, then revert:

```sh
patch -d reference/opus/opus-1.5.2 -p0 < reference/opus/silk_trace.patch
cmake -S reference/opus/opus-1.5.2 -B reference/opus/build-trace \
      -DCMAKE_BUILD_TYPE=Release -DOPUS_BUILD_PROGRAMS=ON -DCMAKE_C_FLAGS=-DSILK_TRACE
cmake --build reference/opus/build-trace -j
patch -R -d reference/opus/opus-1.5.2 -p0 < reference/opus/silk_trace.patch   # keep the source pristine
sh reference/opus/dump_silk_trace.sh        # writes reference/opus/silk_only/*.trace
cargo test -p siphon-rtp-codec --test silk_header_conformance \
    --test silk_nlsf_conformance --test silk_excitation_conformance
```

What the dump carries, by group:

| Line | Source | Consumed by |
|---|---|---|
| `HDR`, `LBRRFLAGS`, `STEREO`, `MIDONLY`, `TYPE`, `GAINIDX`, `GAINS` | `dec_API.c`, `decode_indices.c`, `gain_quant.c` | `silk_header_conformance` |
| `NLSFIDX`, `NLSFRES`, `NLSFPRE`, `NLSFPOST`, `NLSFINT`, `LPC` — the NLSF stage end to end (§4.2.7.5) | `decode_indices.c`, `NLSF_decode.c`, `decode_parameters.c` | `silk_nlsf_conformance` |
| `NLSFSYM` — the `(fl, fh)` of every normalized-LSF symbol | `decode_indices.c` | *nothing, since the NLSF stage landed* |
| `PITCH`, `SEED` — LTP indices (§4.2.7.6) and the LCG seed (§4.2.7.7) | `decode_indices.c` | `silk_excitation_conformance` |
| `PULSES`, `RC` — rate level, per-shell-block counts and LSB shifts, the pulse signal's checksum, and the range-coder `rng`/`tell` at the end of the frame | `decode_pulses.c` | `silk_excitation_conformance` |
| `EXC` — the reconstructed Q14 excitation (§4.2.7.8.6), checksummed | `decode_core.c` | `silk_excitation_conformance` |

`NLSFSYM` was what let a half-finished decoder consume a whole packet: replaying the recorded
`(fl, fh)` pairs through the range decoder's `decode`/`dec_update` is *state-equivalent* to
`ec_dec_icdf` at `ftb = 8`, so `silk_excitation_conformance` could reach the LTP stage before the NLSF
tables existed. The NLSF stage has landed and that replay is gone — the harness decodes those symbols
for real. The group stays in the patch because **removing** a field group breaks every sibling harness
the next time the dumps are regenerated; the harnesses ignore groups they do not own.

`RC` deserves a note: it is this layer's own `final_range` check, at **per-frame** rather than
per-packet resolution. Whole-packet `final_range` is not usable here — for a SILK-only packet with
spare bits, libopus reads a redundancy flag and a CELT redundancy frame after the SILK layer and folds
that into the reported value (`opus_decoder.c:452-480`, `rangeFinal = dec.rng ^ redundant_rng`) — so the
trace records `rng` and `ec_tell` at the exact end of each SILK frame instead, which is strictly finer.

The dump is only read, never regenerated, by the tests, so the instrumented build is a one-off. Each
harness ignores field groups it does not consume, and refuses to pass vacuously: it counts what it
scored and asserts the counts are non-trivial, so a stale dump that is missing a group shows up as a
skip rather than a green run. `silk_nlsf_conformance` additionally requires that the run exercised the
interpolation path, the stage-2 saturation extension symbol, frames the stabiliser actually modified,
and both codebook orders — a decode that never took a branch has not tested it.

Prefer the end-to-end gates now that they exist — `silk_only_conformance` and
`silk_plc_conformance` both compare *decoded audio*, which an intermediate-state diff cannot: matching
fields do not prove the packet parses to its end, and nothing in the trace can see the synthesis
filters, the stereo unmixing, the resampler or §4.4 concealment at all. Keep `build-trace` around only
while a stage is being written; it is a diagnostic, not a gate.

#### Validating the SILK **encoder**'s analysis front end

The same instrumented build, but driven in the *encode* direction. There is no `final_range` on this
side at all — RFC 6716 is decoder-normative, so an encoder has no bitstream to match — which makes the
per-kernel diff the primary gate rather than a diagnostic.

`silk_trace.patch` also adds `#ifdef SILK_TRACE` dumps to `silk/float/encode_frame_FLP.c` and
`silk/float/find_pred_coefs_FLP.c`, covering the whole analysis chain:

| Line | Source | What it pins down |
|---|---|---|
| `EIN` / `ESTATE` / `ECFG` | `encode_frame_FLP.c` | the input signal window as raw IEEE-754 bit patterns, the cross-frame state, and every configuration value that moves a threshold |
| `EPITCH` | after `silk_find_pitch_lags_FLP` | voicing, lag index, contour index, per-subframe lags, prediction gain, normalized correlation |
| `ESHAPE` | after `silk_noise_shape_analysis_FLP` | shaping AR coefficients, tilt, harmonic gain, low-frequency shaping, initial gains, input/coding quality, quantisation offset |
| `ELTPCORR` / `ELPC` | inside `silk_find_pred_coefs_FLP` | the LTP correlation matrix/vector (the codebook search's *input*), and the **unquantized** NLSFs plus the prediction-gain ceiling |
| `ELTP` | after `silk_find_pred_coefs_FLP` | LTP codebook and per-subframe indices, taps, scale, NLSF indices, both Q12 LPC halves, residual energies |
| `EGAINS` | after `silk_process_gains_FLP` | gain indices, quantised gains, the rate-distortion lambda, the running gain index |

Because each frame's dump carries its own inputs *and* its own cross-frame state, every frame is
scored in isolation — a mismatch names one kernel in one frame instead of being blamed on drift.

```sh
patch -d reference/opus/opus-1.5.2 -p0 < reference/opus/silk_trace.patch
cmake -S reference/opus/opus-1.5.2 -B reference/opus/build-trace \
      -DCMAKE_BUILD_TYPE=Release -DOPUS_BUILD_PROGRAMS=ON \
      -DOPUS_DISABLE_INTRINSICS=ON -DCMAKE_C_FLAGS=-DSILK_TRACE
cmake --build reference/opus/build-trace -j
patch -R -d reference/opus/opus-1.5.2 -p0 < reference/opus/silk_trace.patch
SILK_ENC_TRACE_MAX_FRAMES=60 sh reference/opus/dump_silk_enc_trace.sh
cargo test -p siphon-rtp-codec --test silk_encoder_analysis_conformance -- --nocapture
```

Three things about this build differ from the decoder recipe and all three matter:

- **`-DOPUS_DISABLE_INTRINSICS=ON`.** `silk/float/x86/inner_product_FLP_avx2.c` accumulates in a
  different order from `silk_inner_product_FLP_c`, which is what the Rust port reproduces; leaving it
  on compares against a third implementation and inflates every tolerance. libopus' fixed-point SSE4.1
  paths are bit-exact, so the decoder dumps are unaffected — use one `build-trace` for both.
- **`SILK_ENC_TRACE_MAX_FRAMES`** (default 8) caps how many frames dump their input window, which is
  the only large field. 60 frames × 36 configurations is ~38 MB and reaches real voiced speech; every
  frame would be gigabytes.
- **Float, so state a tolerance.** GCC's default `-ffp-contract=fast` fuses multiply-adds that Rust
  never fuses, and `libm` differs in the last ulp, so continuous fields carry a per-kernel relative
  tolerance (documented at the top of the harness). Every **discrete** field — a codebook index, a
  pitch lag, a gain index, a voicing verdict — must match exactly; a tolerance on one of those is a
  bug, not a relaxation.

One more oracle is worth knowing about for the tables rather than the decode path:
`silk_nlsf_tables_vs_libopus` re-parses `reference/opus/opus-1.5.2/silk/tables_NLSF_CB_*.c` and diffs
all 2569 ported NLSF codebook entries against the C element by element. It needs only the unpacked
libopus source, not a build.

#### Per-kernel goldens for the CELT stereo kernels

`opus_compare` and `final_range` both score a *whole packet*, so neither can tell you which kernel is
wrong — and a round trip proves nothing at all, because a shared encode/decode bug passes one. The
stereo kernels (`stereo_itheta`, `intensity_stereo`, `stereo_split`, `stereo_merge`,
`compute_channel_weights`, `compute_qn`, the theta gain/bit split, `stereo_analysis`, the `C == 2`
branches of `alloc_trim_analysis` / `dynalloc_analysis` / `patch_transient_decision`) are therefore
pinned to values libopus itself produced, in
[`crates/siphon-rtp-codec/tests/celt_stereo_golden.rs`](crates/siphon-rtp-codec/tests/celt_stereo_golden.rs).

Most of those helpers are file-static in `celt/bands.c` and `celt/celt_encoder.c`, so the generator
`reference/opus/celt_stereo_golden.c` `#include`s those two translation units directly and prints the
literals. The *inputs* are regenerated on the Rust side from the same LCG, so only the outputs are
carried across and the test needs no reference tree — it runs in CI unconditionally. Re-run the
generator only when a kernel's expected behaviour is deliberately changed:

```sh
cd reference/opus
gcc -O2 -DCPU_INFO_BY_ASM -DDISABLE_DEBUG_FLOAT -DENABLE_HARDENING -DHAVE_ALLOCA_H \
    -DHAVE_CONFIG_H -DHAVE_LRINT -DHAVE_LRINTF -DOPUS_BUILD -DOPUS_HAVE_RTCD \
    -DOPUS_X86_MAY_HAVE_AVX2 -DOPUS_X86_MAY_HAVE_SSE -DOPUS_X86_MAY_HAVE_SSE2 \
    -DOPUS_X86_MAY_HAVE_SSE4_1 -DOPUS_X86_PRESUME_SSE -DOPUS_X86_PRESUME_SSE2 -DVAR_ARRAYS \
    -I build -I opus-1.5.2/include -I opus-1.5.2/celt -I opus-1.5.2/silk -I opus-1.5.2 \
    celt_stereo_golden.c build/libopus.a -lm -o build/celt_stereo_golden
./build/celt_stereo_golden
```

## Fuzzing

Every parser that eats untrusted bytes off the network is fuzzed with `cargo-fuzz` (libFuzzer,
nightly). A malformed / hostile datagram or codec bitstream must decode-or-error: never panic, never
read out of bounds, never spin.

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run rtp_parser_fuzz -- -max_total_time=60
```

Targets: `rtp_parser_fuzz`, `sdp_fuzz`, `bencode_fuzz`, `proto_frame_fuzz`, `stun_fuzz`,
`amr_wb_decode_fuzz`, `amr_nb_decode_fuzz` (the AMR targets need the `amr` feature, which
`fuzz/Cargo.toml` already enables). CI runs a short smoke of each; deeper runs are a local /
scheduled concern.

## Performance

siphon-rtp holds itself to a strict performance bar: every hot path is measured, nothing regresses
silently, and there is **zero per-frame heap allocation** on the datapath (a counting-allocator test
enforces it).

Two kinds of benchmark:

- **criterion** (wall-clock µs/frame, the human-facing numbers): `cargo bench`.
- **iai-callgrind** (deterministic *instruction counts*, what CI gates on): the `*_iai` benches.
  These need `valgrind` and the matching runner:

  ```sh
  cargo install iai-callgrind-runner --version 0.16.1
  # establish a baseline, then compare (a >10% instruction regression fails):
  cargo bench --bench codec_iai --bench media_iai --bench srtp_iai -- --save-baseline=main
  cargo bench --bench codec_iai --bench media_iai --bench srtp_iai -- --baseline=main
  ```

If a change legitimately improves a number, re-baseline to lock in the new floor. Never lower a
baseline just to go green — diagnose or roll back. Any new hot path (per-packet / per-frame /
per-session) ships its own bench in the same change.

## The `amr` feature and codec licensing

`amr` is the only Cargo feature, and it is **off by default**. It gates the AMR-NB / AMR-WB
*transcoding* codecs (patent-encumbered). **Relaying/passthrough of any codec is always available and
never runs the codec** (no patent exposure). Enabling `amr` is an explicit statement that you hold
the relevant licence in your jurisdiction. See [docs/codec-licensing.md](docs/codec-licensing.md).

## Pure Rust, zero C library dependencies

A hard rule, enforced in CI by `cargo-deny` (`check bans sources`): no `-sys` codec crates, no
ffmpeg / libopus / spandsp / libsrtp. Codecs are hand-written Rust; SRTP/DTLS ride RustCrypto; the
XDP path rides `aya`. Do not add a C-linking dependency.

## Coding conventions

- **Errors via `thiserror`**, propagated with `?` / `map_err` / `ok_or_else` / `match`. **No
  `.unwrap()` / `.expect()` in production code** — only in `#[cfg(test)]` and `main()`.
- **`tracing` for logs**, never `println!`. Always answer a control request (even on error) rather
  than silently dropping it.
- **Follow the spec.** RFC / 3GPP / ITU-T text is the source of truth. Cite the spec at the point a
  non-obvious protocol decision is enforced (e.g. `// RFC 3550 §5.1`); a deviation must say so and
  why, with the citation.
- **No abbreviated names** (`request`, not `req`). No real subscriber data in code or tests — use the
  3GPP test range (MCC 001 / MNC 01) and RFC 5737 / RFC 1918 addresses for examples.
- If you touch the latch / source-gate / NAT / ICE / SRTP path or the `ForwardRule` model, update
  [docs/security-and-nat.md](docs/security-and-nat.md) in the same change.

## Submitting a change

- **Branch off `main`; open a pull request.** PRs are the only way in; they land via **squash-merge**
  (one commit per change). Keep PRs small and focused (one feature or fix).
- **Conventional Commits** for the subject: `feat(engine): …`, `fix(codec): …`, `docs: …`,
  `test: …`, `chore: …`.
- **Green before you push:** `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D
  warnings`, and the test suite must be clean. CI re-checks fmt, clippy, tests (MSRV + stable), docs
  (`-D warnings`), `cargo-deny`, the SBOM, the fuzz smoke, the docker build, and the iai-callgrind
  perf gate.

Questions or a design you want to sanity-check before building it? Open an issue first.
