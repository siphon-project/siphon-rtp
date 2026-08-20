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

- **Per-PR (`ci.yml`, the `deny` job):** `cargo deny check bans licenses sources`. The
  time-invariant policy: the zero-C ban list, the OSI-permissive licence allow-list and the
  crates.io-only source rule. All three read only the dependency graph, so their verdict changes
  only when a PR changes that graph — no unrelated PR is ever failed by them.
- **Scheduled (`audit.yml`):** `cargo deny check advisories` runs **weekly (Mondays 06:00 UTC)**,
  on any push that touches the dependency set (`Cargo.toml`, `Cargo.lock`, `deny.toml`), and on
  demand. Time-varying RustSec advisories live here so a new advisory never turns a green PR red
  on unchanged code, but still surfaces within a week.
- **Yanked crates fail the audit** (`yanked = "deny"`).
- **Ignores are explicit and justified in `deny.toml`**, each with the reason and the exit
  condition recorded (currently three unmaintained-crate notices reached transitively:
  `paste` via the jemalloc stats dev-dependency, `bincode` 1.x via `webrtc-dtls`, and
  `proc-macro-error2` via the `iai-callgrind` perf-gate dev-dependency; none is a
  vulnerability and none has an upstream fix yet; see `deny.toml`).

Run the same checks on your own checkout:

```sh
cargo install cargo-deny
cargo deny check bans licenses sources   # the per-PR gate
cargo deny check advisories              # the scheduled audit
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
