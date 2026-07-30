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
SIPHON_RTP_OPUS_COMPARE=$PWD/reference/opus/build/opus_compare \
    cargo test -p siphon-rtp-codec --test celt_only_conformance --test opus_conformance
```

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
