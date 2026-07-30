//! A single hard gate over the codec reference-vector conformance suite.
//!
//! The ITU-T (G.191 STL) and 3GPP (TS 26.074 / 26.174) reference vectors cannot be redistributed, so
//! they are gitignored and every codec conformance test skips gracefully when its vector files are
//! absent. That keeps a fresh checkout (and CI without the vectors) green, but it also means a run
//! that skips everything proves nothing about bit-exactness while still reporting "ok".
//!
//! Set `SIPHON_RTP_REQUIRE_VECTORS=1` (on a maintainer box, or a CI job that has provisioned the
//! vectors) to make that silent skip a hard failure: this test then asserts the per-codec vector
//! directories are present and non-empty, so the conformance tests it guards will actually execute
//! their bit-exact assertions instead of returning early. Without the variable it is a no-op, exactly
//! matching the default skip-when-absent behaviour.

use std::path::Path;

/// Per-codec vector directories the conformance tests read from (relative to the crate root).
const REQUIRED_VECTOR_DIRS: &[&str] = &[
    "../../reference/amr-wb/testv",
    "../../reference/amr-nb/testv",
    "../../reference/g722/testv",
    "../../reference/g726/testv",
    "../../reference/gsm-fr/testv",
    // Opus: the official RFC 6716 `testvectorNN.bit`/`.dec` set, plus the locally generated
    // CELT-only oracle streams (`celt_only/`, see CONTRIBUTING.md — they need a local libopus build).
    "../../reference/opus/opus_testvectors",
    "../../reference/opus/celt_only",
];

fn is_present_and_non_empty(dir: &Path) -> bool {
    dir.is_dir()
        && std::fs::read_dir(dir)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false)
}

#[test]
fn reference_vectors_present_when_required() {
    if std::env::var_os("SIPHON_RTP_REQUIRE_VECTORS").is_none() {
        // Opt-in gate. Default builds / CI without the vectors skip conformance as before.
        return;
    }

    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let missing: Vec<&str> = REQUIRED_VECTOR_DIRS
        .iter()
        .copied()
        .filter(|relative| !is_present_and_non_empty(&crate_root.join(relative)))
        .collect();

    assert!(
        missing.is_empty(),
        "SIPHON_RTP_REQUIRE_VECTORS=1 but these reference-vector directories are absent or empty: \
         {missing:?} (relative to {}). The codec conformance tests would silently skip, so \
         bit-exactness is unproven. Provision the vectors or unset the variable.",
        crate_root.display(),
    );
}
