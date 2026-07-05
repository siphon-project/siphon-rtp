# Versioning

siphon-rtp follows [Semantic Versioning 2.0.0](https://semver.org/). It is pre-1.0,
so minor releases may still carry breaking changes; read the
[CHANGELOG](CHANGELOG.md) before upgrading.

## One version across the workspace

Every crate in the workspace carries the **same** version. There is a single
`[workspace.package] version` in the root `Cargo.toml`, and each crate inherits it
with `version.workspace = true`. The published library crates
(`siphon-rtp-proto`, `siphon-rtp-codec`, ...), the `siphon-rtp` daemon binary, and
the `ghcr.io/siphon-project/siphon-rtp` container image all ship at that one version.

The **git tag is the source of truth.** It cannot drift, because the release
workflow refuses to publish when the two disagree:

| Surface | How it gets its version |
|---|---|
| crates / binary / image | `[workspace.package] version` in the root `Cargo.toml` |
| guard | `release.yaml`'s `verify-version` job **fails the release** if `Cargo.toml` version ≠ the `vX.Y.Z` tag |

## What a version protects (the public contract)

A bump reflects the highest-severity change across the surfaces operators actually
depend on:

1. **The native JSON-over-TCP control protocol** — the request/response verbs, their
   fields, and the async events (`siphon-rtp-proto`). This is the primary contract:
   SIPhon and any other controller speak it.
2. **The rtpengine NG/bencode front-end** — the supported commands and their
   semantics, including the documented siphon-rtp extensions.
3. **CLI flags and documented runtime behavior** — the `siphon-rtp` daemon surface.
4. **The TOML config schema** — documented keys and their meaning.

The published library crates additionally follow semver on their `pub` Rust API, but
while the project is pre-1.0 that API may change with a minor bump; pin exact
versions if you embed a crate directly.

## Cutting a release

There is no release script to hand-hold: the tag drives everything.

1. Set the version in the root `Cargo.toml` `[workspace.package]`, update
   `CHANGELOG.md` (move `Unreleased` to the new version), and land it via a PR.
2. Tag the merge commit `vX.Y.Z` and push the tag.

The tag push runs `release.yaml`: `verify-version` (tag must equal `Cargo.toml`),
then the multi-arch binary build (`x86_64` + `aarch64`), `cargo publish` to
crates.io via OIDC trusted publishing, the container image to GHCR, the SBOM (SPDX
2.3 + CycloneDX 1.4), and a GitHub Release with generated notes and the artifacts
attached.

**Never hand-edit a per-crate version.** They all inherit the workspace version by
construction, which is what keeps them in lockstep.
