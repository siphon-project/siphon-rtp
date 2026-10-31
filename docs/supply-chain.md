# Supply chain & SBOM

If you run siphon-rtp in carrier infrastructure, security and procurement will ask two questions:
*what is in this binary?* and *how do you know it's not vulnerable?* This page answers both, and
explains the dependency rule that shapes everything else here: **pure Rust, zero C library
dependencies**, enforced mechanically in CI, not by convention.

- [The zero-C rule, enforced](#the-zero-c-rule-enforced)
- [Software Bill of Materials (SBOM)](#software-bill-of-materials-sbom)
- [Consuming the SBOM](#consuming-the-sbom)
- [Generating an SBOM yourself](#generating-an-sbom-yourself)
- [Dependency vulnerability monitoring](#dependency-vulnerability-monitoring)
- [Release integrity](#release-integrity)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Known gaps](#known-gaps)

---

## The zero-C rule, enforced

siphon-rtp links no libopus, no ffmpeg, no spandsp, no libsrtp, no OpenSSL. Codecs are hand-written
Rust validated against the reference vectors; SRTP/DTLS/TLS are RustCrypto/rustls/ring. That is
why one `cargo install` or a distroless container image is the whole deployment, and why the Cargo
dependency graph below is, to a very good approximation, the *complete* inventory of the binary.

The rule is enforced at the dependency-graph level by
[`deny.toml`](https://github.com/siphon-project/siphon-rtp/blob/main/deny.toml): the well-known
C-FFI codec/DSP/TLS/SRTP crates (`openssl`, `openssl-sys`, `native-tls`, `opus`/`audiopus`,
`ffmpeg-sys*`, `spandsp-sys`, `srtp2-sys`, `speexdsp-sys`, `samplerate`, ...) are on a hard ban
list, so none can sneak in transitively. The **`deny` CI job runs
`cargo deny check bans licenses sources` on every pull request**; a PR that pulls a banned crate,
a crate outside the OSI-permissive licence allow-list, or any crate from outside crates.io
(unknown registries and git sources are denied), fails before review.
The workspace carries no git or patched dependency: `rtc-dtls`, `rtc-shared` and `rtc-crypto` come from
crates.io at 0.21.1, which includes the RFC 6347 §4.2.4 last-flight retransmission fix (webrtc-rs/rtc#243).
The former fork pin and its `allow-git` entry are retired.

Two vendored exceptions, stated so the claim stays honest: the jemalloc allocator
(`tikv-jemallocator`, the one accepted `-sys` dependency) and ring's crypto primitives contain
C/assembly compiled into the crate. Both are self-contained, build from vendored source, and add
no system library dependency; the runtime image is still `FROM distroless/static`.

The rule is also why the neural voice-activity detector is a hand-written forward pass rather than
an inference runtime: binding the published ONNX would have dragged a C++ runtime and a shared
library into the deployment, and that is the whole property being defended. Instead the network's
309 633 parameters are a flat little-endian `f32` blob embedded with `include_bytes!`, and the
graph — a strided 1-D convolution, ReLU, one LSTM cell, a sigmoid — is written out against the
crate's own SIMD primitives. It is **the one upstream artifact this repository redistributes**
(MIT; source, hashes and regeneration scripts in
[THIRD-PARTY-NOTICES.md](https://github.com/siphon-project/siphon-rtp/blob/main/THIRD-PARTY-NOTICES.md)
and `reference/silero-vad/`), so an SBOM consumer should know it is in the binary even though it is
not a Cargo dependency and will not appear in the graph below.

### HTTP client (`play_media` from a URL)

`play_media` can fetch a WAV prompt from an `http://` / `https://` URL, which means the engine
carries an HTTP client. The dependency was picked to add as little surface as possible:

| Crate | Why | Licence |
| --- | --- | --- |
| `hyper` (`client`, `http1`) | HTTP/1.1 only. The **low-level `client::conn` API** is driven directly rather than the pooled `Client`, so the socket is one we connected (and timed out) ourselves and the connect / first-byte / overall-deadline bounds and the redirect cap are enforced in our code, not delegated. | MIT |
| `hyper-util` (`tokio`) | Only the tokio↔hyper IO adapter (`TokioIo`). No pool, no connector, no resolver. | MIT |
| `http-body-util` | The body reader the response-size cap is enforced on, frame by frame. | MIT |

TLS is **not** a new dependency: `https://` terminates on the same `tokio-rustls` + `webpki-roots`
stack, on the **ring** provider, that the `wss://` WebSocket bridge already dials with. `reqwest`
was considered and rejected — it would pull a connection pool, its own DNS resolver, cookie/proxy
machinery and a second TLS configuration path, all of which have to be audited and none of which a
one-shot prompt fetch needs. No `native-tls`, no OpenSSL, no C.

The operational bounds and the SSRF posture of that fetch are documented in
[the JSON control reference](control/json.md#playback-from-a-url).

### WebRTC data channels (`mcptt-floor`)

A browser seat cannot send RTCP APP, so its MCPTT floor control rides a WebRTC data channel: SCTP
(RFC 9260) over the leg's DTLS association (RFC 8261) with DCEP (RFC 8832). The pair below is
sans-I/O, owns no socket, clock or task, and is published by the same publisher as `rtc-dtls`
(rainliu, webrtc-rs). Both are `MIT/Apache-2.0`, contain no `unsafe` and no `build.rs`, and are
pinned exactly like `rtc-dtls`.

| Crate | Why | Licence |
| --- | --- | --- |
| `rtc-sctp` `=0.21.1` | The SCTP association (RFC 9260) under the data channel. | MIT/Apache-2.0 |
| `rtc-datachannel` `=0.21.1` | DCEP (RFC 8832) open/ack framing and the data-channel message types. | MIT/Apache-2.0 |
| `crc32c` 0.6.8 | CRC32c checksum of every SCTP packet. Single owner (zowens); its `build.rs` only writes the CRC tables to `OUT_DIR`; the hardware paths use SIMD `unsafe`; last release 2024-06. | MIT/Apache-2.0 |
| `rustc-hash` 2.x | Fast hasher for the association's stream maps (rust-lang), no `unsafe`. | MIT/Apache-2.0 |
| `sansio` 1.0.1 | The sans-I/O trait both crates implement (rainliu + yapprtc), no dependencies, no `unsafe`. | MIT/Apache-2.0 |

The fuzz/ and crates/siphon-rtp-xdp/ lockfiles additionally gain `rustc_version` 0.4.1 (build-time version probe of `crc32c`) and, in fuzz/, `semver` 1.0.28, both already in the root tree.

Rejected alternative: a hand-rolled SCTP (RFC 9260 with the RFC 8831 / RFC 8832 data-channel profile)
is months of work and its own attack surface. The exposure is bounded: SCTP bytes are only parsed
after the DTLS record layer has authenticated them (see
[security-and-nat.md](security-and-nat.md#webrtc-data-channel-floor-control)).

### SRTCP `AEAD_AES_128_GCM` (`siphon-rtp-srtp`)

MCPTT floor control is protected hop by hop with `AEAD_AES_128_GCM` (RFC 7714), which needs a GCM
implementation next to the AES-CM one the crate already has. `aes-gcm` is the RustCrypto AEAD built on the
same `aes` 0.8 / `cipher` 0.4 / `ctr` 0.9 line the crate pins on purpose (see the comment in its
`Cargo.toml`), so the 0.10 series is used and 0.11 is not. `>= 0.10.3` is required: RUSTSEC-2023-0096
(plaintext exposed by `decrypt_in_place_detached` on tag failure) is fixed there. Only the RTCP side is
used, through the `AeadInPlace` detached API on caller-owned buffers. All five are `MIT/Apache-2.0` and
published by the RustCrypto organisation.

| Crate | Why | Review facts |
| --- | --- | --- |
| `aes-gcm` 0.10.3 | The AEAD itself. | 2023-09-21; owners tarcieri and the `github:rustcrypto:aeads` team; `#![deny(unsafe_code)]`; no `build.rs`; RUSTSEC-2023-0096 fixed in 0.10.3. |
| `ghash` 0.5.1 | GCM's GHASH. | 2024-03-03; no `unsafe`; no `build.rs`. |
| `polyval` 0.6.2 | The carry-less multiply under GHASH. | 2024-03-03; `unsafe` only in the CLMUL / PMULL intrinsic backends, selected at run time with `cpufeatures`; no `build.rs`; no assembly. |
| `universal-hash` 0.5.1 | Trait under `ghash` / `polyval`. | 2023-05-19; 3 `unsafe` uses; no `build.rs`. |
| `opaque-debug` 0.3.1 | Debug impl that hides key-dependent state. | 2024-03-01; no `unsafe`. |

`aead` 0.5.2 was already in the tree. The fuzz/ and crates/siphon-rtp-xdp/ lockfiles gain the same four
new crates; `cargo deny check` is green against all three lockfiles.

### Wiping floor keys (`zeroize`)

The floor SRTCP master keys are secrets, so they are overwritten when dropped. `zeroize` 1.x is the RustCrypto
wipe primitive (`MIT/Apache-2.0`, owner tarcieri, `no_std`, no `build.rs`, no dependencies of its own); it was
already in the tree through `rustls` and `rtc-srtp`, so no new package enters any of the three lockfiles, only
the dependency lists of `siphon-rtp-srtp`, `siphon-rtp-proto`, `siphon-rtp`, `aes` and `aes-gcm` change. The
`derive` feature is off (the impls are hand-written, so no proc-macro). The existing `zeroize` features of
`aes` 0.8 (wipes the expanded round keys) and `aes-gcm` 0.10 (wipes the GHASH subkey while it is built) are on.

## Software Bill of Materials (SBOM)

Every tagged release ships a full SBOM in **two industry formats**, generated from the exact
resolved `Cargo.lock` that built the release artifacts and attached to the
[GitHub Release](https://github.com/siphon-project/siphon-rtp/releases):

| Format | Spec version | Asset name |
| --- | --- | --- |
| **SPDX** | SPDX 2.3 (JSON) | `siphon-rtp-vX.Y.Z.spdx.json` |
| **CycloneDX** | CycloneDX 1.4 (JSON) | `siphon-rtp-vX.Y.Z.cdx.json` |

Both are produced by [`cargo-sbom`](https://github.com/psastras/sbom-rs) in the release workflow.
Two formats because tooling differs in what it ingests: SPDX is the ISO/IEC 5962 standard most
license-compliance tools expect; CycloneDX is what vulnerability scanners (Grype, Trivy,
Dependency-Track) consume natively. The regular CI pipeline also generates the same pair on every
run and uploads them as a build artifact, so an unreleased commit has an inspectable inventory too.

!!! note "What the SBOM covers"
    The SBOM enumerates the Rust dependency graph of the workspace. Because of the zero-C rule
    there are no system codec/TLS libraries hiding outside it; the only components not listed
    per-package are the vendored jemalloc and ring sources named above, which appear as their
    wrapping crates.

## Consuming the SBOM

Download the format your tooling prefers from the release assets, then feed it in.

Scan for known vulnerabilities with [Grype](https://github.com/anchore/grype):

```sh
grype sbom:./siphon-rtp-v0.2.0.cdx.json
```

Scan with [Trivy](https://github.com/aquasecurity/trivy):

```sh
trivy sbom ./siphon-rtp-v0.2.0.cdx.json
```

Continuous monitoring with [Dependency-Track](https://dependencytrack.org/): upload the CycloneDX
document to a project via the API or UI; it re-evaluates the component list against new advisories
over time, no re-scan of the binary needed.

License compliance: feed the SPDX document to your compliance tooling, or a plain `jq` over the
license fields. Everything resolves to permissive, MIT-compatible terms (siphon-rtp itself is MIT).
The one non-OSI item is `webpki-roots`, under `CDLA-Permissive-2.0` (a permissive *data* licence
covering the bundled Mozilla CA set, not a code licence); it is allow-listed in `deny.toml` with
that note. Codec *patent* posture is a separate question from copyright licensing and has its own
page: [Codec licensing & patents](codec-licensing.md).

## Generating an SBOM yourself

The release SBOM is reproducible from any checkout, useful for a fork, an unreleased commit, or
verifying a published document:

```sh
cargo install cargo-sbom

cargo sbom --output-format spdx_json_2_3       > siphon-rtp.spdx.json
cargo sbom --output-format cyclone_dx_json_1_4 > siphon-rtp.cdx.json
```

The output derives from `Cargo.lock`, so a checkout of the same tag produces an equivalent
component list to the published asset.

## Dependency vulnerability monitoring

An SBOM is a snapshot; advisories are continuous. A crate that was clean at release time can have
a RustSec advisory filed a week later without a line of code changing. siphon-rtp splits the
[`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) checks accordingly:

- **Per-PR (`ci.yml`, the `deny` job):** `cargo deny check bans licenses sources` on every
  lockfile in the repository: the workspace, the fuzz harness (`fuzz/`) and the excluded XDP
  workspace (`crates/siphon-rtp-xdp/`), all against the one `deny.toml`. The time-invariant
  policy: the zero-C ban list, the OSI-permissive licence allow-list and the crates.io-only source
  rule. All three read only the dependency graph, so their verdict changes only when a PR changes
  that graph — no unrelated PR is ever failed by them.
- **Per-PR advisories (`ci.yml`, the `advisories` job):** `cargo deny check advisories` on the
  same three lockfiles, reported on every PR but left out of the `CI passed` rollup. A new advisory
  against unchanged code never fails a PR, and a vulnerable dependency is still a red check on the
  PR in front of whoever merges it, a release PR included.
- **Scheduled (`audit.yml`):** `cargo deny check advisories` on all three lockfiles runs **daily
  (06:00 UTC)**, on any push to `main` that touches the dependency set (any `Cargo.toml` or
  `Cargo.lock`, or `deny.toml`), and on demand, so a new advisory surfaces within a day.
- **Release gate (`release.yaml`, the `deny` job):** the full `cargo deny check` (bans, licenses,
  sources and advisories) on the workspace lockfile must pass before the contract crate is
  published to crates.io and before any binary, package or image is built.
- **Yanked crates fail the audit** (`yanked = "deny"`).
- **Licence exceptions are per crate.** `libfuzzer-sys`, reached only from the fuzz harness, may
  carry LLVM's NCSA licence; nothing else may, and NCSA is not on the general allow-list.
- **Ignores are explicit and justified in `deny.toml`**, each with the reason and the exit
  condition recorded (currently three unmaintained-crate notices reached transitively:
  `paste` via the jemalloc stats dev-dependency, `bincode` 1.x via the `iai-callgrind` dev-dependency, and
  `proc-macro-error2` via the `iai-callgrind` perf-gate dev-dependency; none is a
  vulnerability and none has an upstream fix yet; see `deny.toml`).

Run the same checks on your own checkout:

```sh
cargo install cargo-deny
cargo deny check bans licenses sources   # the per-PR gate
cargo deny check advisories              # the per-PR report and the daily audit
cargo deny check                         # the release gate: all four
# The other two lockfiles, against the same deny.toml:
cargo deny --manifest-path fuzz/Cargo.toml check --config deny.toml
cargo deny --manifest-path crates/siphon-rtp-xdp/Cargo.toml check --config deny.toml
```

Beyond dependencies, CI also fuzzes the RTP/RTCP parser with `cargo-fuzz` (libFuzzer) on every
run as a smoke pass; the parsers that eat untrusted bytes must decode-or-error, never panic.

## Release integrity

- **The git tag is the single source of truth.** The release workflow refuses to publish if the
  workspace version does not equal the tag, so a stray in-tree bump can never ship a mismatched
  crate or image.
- **crates.io publishing uses OIDC Trusted Publishing**: CI mints a short-lived token via GitHub
  OIDC per release. There is no long-lived registry token to steal.
- **Container images** are built from the repo's own `Dockerfile` (musl, distroless) and pushed to
  `ghcr.io/siphon-project/siphon-rtp` with semver and commit-SHA tags.
- Builds use `--locked` throughout CI and release, so the committed `Cargo.lock`, the tests, the
  SBOM and the shipped binaries all describe the same graph.

## Reporting a vulnerability

Please report security issues **privately**; do not open a public GitHub issue for a suspected
vulnerability. See
[`SECURITY.md`](https://github.com/siphon-project/siphon-rtp/blob/main/SECURITY.md) at the
repository root for the disclosure process: use GitHub's
[private vulnerability reporting](https://github.com/siphon-project/siphon-rtp/security/advisories/new)
on the repository's **Security** tab. You'll get an acknowledgement and a coordinated-disclosure
timeline. Media-plane bugs with security impact (RTPBleed-class latching issues, SRTP handling,
parser crashes on hostile packets) are treated as release-blocking; the threat model they are
measured against is [Security & NAT design](security-and-nat.md).

## Known gaps

Stated plainly, because a supply-chain page that overclaims is worse than none:

- **No container-image SBOM or SLSA provenance yet.** The published SBOM describes the Rust crate
  graph, not image layers. Since the runtime image is distroless-static plus the one binary, the
  crate SBOM covers nearly everything, but scan the image with your registry scanner as usual.
- **No cryptographic signing of release artifacts yet.** Publication goes through GitHub Releases
  and OIDC Trusted Publishing (no stored secrets), but tarballs/SBOMs are not Sigstore-signed.
  Verify by reproducing the SBOM from the corresponding tag.

## See also

- [Deployment & operations](deployment.md), the production runbook these artifacts slot into.
- [Codec licensing & patents](codec-licensing.md), the patent side of shipping codecs.
- [Security & NAT design](security-and-nat.md), the runtime threat model.
