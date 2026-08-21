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

### `#[non_exhaustive]` on the control contract

Since 0.3.0 the enums a controller *observes* — `Event`, `CmdResult`, `PlayEndReason`,
`WsTeeEndReason`, `ProtoError` — plus the two it *sends* that keep growing (`Command`,
`PlayMediaSource`) are `#[non_exhaustive]`, so **adding a variant to them is no longer a
breaking change.** A `match` in your crate needs a wildcard arm; give it real behaviour, because
a silent catch-all turns a new variant into a dropped notification.

Two things it does not cover, both still breaking:

- **Adding a field to an existing struct variant** (`Command::PlayMedia` gaining `overlay`, say).
  Only per-variant `#[non_exhaustive]` would make that additive, and it would also stop you
  constructing the variant at all, so it is deliberately not applied.
- The **selector** enums a controller sends to choose engine behaviour — `WsTeeDirection`,
  `WsVadEngine`, `ConferenceRole`, `BridgeDirection` — are deliberately exhaustive. A new value
  there changes what the engine does, and the broken `match` is the notification.

None of this touches the JSON wire, which is additive on its own terms: optional fields are
omitted when unset, and an unrecognised `event` tag decodes to `Event::Unknown`.

## Cutting a release

There is no release script to hand-hold: the tag drives everything.

1. Set the version in the root `Cargo.toml` `[workspace.package]`, update
   `CHANGELOG.md` (move `Unreleased` to the new version), and land it via a PR.
2. Tag the merge commit `vX.Y.Z` and push the tag.

The tag push runs `release.yaml`: `verify-version` (tag must equal `Cargo.toml`),
then the multi-arch binary build (`x86_64` + `aarch64`), the container image to
GHCR, the SBOM (SPDX 2.3 + CycloneDX 1.4), a GitHub Release with generated notes
and the artifacts attached, and `cargo publish` of **`siphon-rtp-proto` only** to
crates.io via OIDC trusted publishing.

**Only the contract crate is published.** `siphon-rtp-proto` is a library a
controller compiles against, so it has to exist on crates.io at the same version as
the engine that speaks it. Every other workspace member is a daemon or an internal
crate and is distributed as a binary — the `.deb`/`.rpm`, the image and the
tarballs. The publish job names the crate explicitly for that reason; widening it
to `--workspace` would put the rest of the tree on the registry.

Trusted Publishing has to be enabled once, on the crate rather than in this repo:
crates.io → `siphon-rtp-proto` → Settings → Trusted Publishing, for repository
`siphon-project/siphon-rtp` and workflow `release.yaml`. There is no long-lived
token in repository secrets, and the job fails closed if the exchange is refused.

A tag that shipped before the publish job existed can be published after the fact
with `gh workflow run release.yaml --ref vX.Y.Z` — on a manual dispatch only the
version gate and the crates.io job run, so nothing is rebuilt or re-released.

**Never hand-edit a per-crate version.** They all inherit the workspace version by
construction, which is what keeps them in lockstep.
