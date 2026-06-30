# Publishing runbook — siphon-rtp crates → crates.io

**Goal:** make `cargo install siphon-rtp` work for external users by publishing the whole engine
dependency tree to crates.io.

**Status:** only **`siphon-rtp-proto 0.1.0`** is published. Every other crate is already
metadata-ready (README + LICENSE + `description`/`keywords`/`categories`/`readme`), and all internal
path-deps are version-pinned. `cargo build --workspace` is green. Remaining work is the checklist
below.

---

## 0. Hard constraints (read first)
- [ ] **Do NOT push directly to `main` / `origin/main`** — PRs are the only way into main. Land
      version/pin changes via a PR.
- [ ] **Publish only from a CLEAN, COMMITTED tree** — no `--allow-dirty`. `cargo build --workspace`
      **and** `cargo test` must be green first; run `cargo publish --dry-run -p <crate>` before each
      real publish.
- [ ] **crates.io versions are immutable** — a published version can never be re-uploaded or edited
      (only yanked). `siphon-rtp-proto 0.1.0` is already burned.
- [ ] Clippy clean before any commit: `cargo clippy --all-targets --all-features -- -D warnings`.

## 1. Blocker — published `proto 0.1.0` is stale
The published `siphon-rtp-proto 0.1.0` predates the conference/echo API (`Command::Echo`,
`ConferenceRole`, `BridgeDirection`) that `engine`/`ngcompat`/`media` now use. It must be
re-published at a new version *before* the engine tree can publish.

- [ ] **Decide the version strategy.** All members inherit `version = "0.1.0"` from
      `[workspace.package]` in the root `Cargo.toml`. Recommended for a first full release: **bump
      the workspace version to `0.1.1`** (or `0.2.0`) so every crate ships the same version in
      lockstep — proto re-publishes at the new version (with the new API) and all others publish
      fresh at that version.
- [ ] **Bump every internal path-dep `version` pin** from `"0.1.0"` to the chosen version. Pins live
      in: `codec`, `dsp` (→ simd); `datapath` (→ stun); `turn` (→ stun, datapath); `media` (→ codec);
      `ngcompat` (→ proto); `engine` (→ proto, datapath, srtp, turn, hep, ngcompat, codec, media,
      dsp); plus the `siphon-rtp-xdp` workspace (→ datapath, ebpf-common) if ever un-`publish=false`d.
      Grep: `version = "0.1.0"` under `crates/*/Cargo.toml`.
- [ ] Re-run `cargo build --workspace` + `cargo test` after the bump.

## 2. Publish in topological order
A dependency must be live on crates.io before its dependents publish. `cargo publish -p <crate>`
waits for registry availability before returning. Dry-run each first.

1. [ ] `siphon-rtp-proto`   — re-publish at the new version (carries conference/echo API)
2. [ ] `siphon-rtp-simd`
3. [ ] `siphon-rtp-stun`
4. [ ] `siphon-rtp-srtp`
5. [ ] `siphon-rtp-hep`
6. [ ] `siphon-rtp-ebpf-common`
7. [ ] `siphon-rtp-codec`     — needs `simd`
8. [ ] `siphon-rtp-dsp`       — needs `simd`
9. [ ] `siphon-rtp-datapath`  — needs `stun`
10. [ ] `siphon-rtp-ngcompat` — needs `proto`
11. [ ] `siphon-rtp-media`    — needs `codec`
12. [ ] `siphon-rtp-turn`     — needs `stun`, `datapath`
13. [ ] `siphon-rtp` (engine, dir `crates/siphon-rtp-engine/`) — **LAST**; depends on ~all of the above

## 3. Excluded from this run
- [ ] `siphon-rtp-xdp` (loader) + `crates/siphon-rtp-xdp/ebpf` (kernel program) — both
      `publish = false`. The eBPF crate compiles to BPF bytecode (not a registry library) and the
      loader's `build.rs` needs a pinned nightly + `bpf-linker` a plain `cargo install` lacks. Leave
      unpublished unless/until that build is reproducible from a registry install. They are still
      prepped (README/LICENSE/metadata) in case the decision changes.

## 4. Post-publish verification
- [ ] `cargo install siphon-rtp` from a clean machine / empty cargo cache (`CARGO_HOME=$(mktemp -d)`)
      — confirm it resolves entirely from crates.io and the `siphon-rtp` binary runs.
- [ ] Tag the release and confirm `.github/workflows/release.yaml` matches the published versions.

---

_Notes: cross-session context for this work also lives in the project memory note
`project_crates_io_publish.md`. The `siphon-rtp-codec` `amr` feature is patent-gated and OFF by
default — that's fine to publish (default features carry no patent-encumbered transcoding; see
`docs/codec-licensing.md`)._
