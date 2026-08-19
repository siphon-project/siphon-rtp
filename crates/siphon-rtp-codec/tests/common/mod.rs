//! Shared lookup for the locally built, test-only libopus oracle binaries.
//!
//! `opus_compare` (RFC 6716 §6) and `opus_demo` are C reference tools built out of the gitignored
//! `reference/opus` tree — see CONTRIBUTING. They are deliberately not vendored, so "absent" is a
//! legitimate state: a fresh checkout has neither the vectors nor the build, and the conformance
//! tests skip. What is *not* legitimate is vectors present with the oracle missing, which the
//! conformance tests assert against so they cannot pass vacuously.
//!
//! This module exists because that lookup used to be copy-pasted across six test binaries, five of
//! which defaulted to `/tmp/opus_compare` while `opus_demo` was already resolved from the
//! `reference/` tree. `/tmp` is cleared on reboot, so the gitignored vectors would outlive the
//! oracle and the suite would hard-fail on a machine that had simply been restarted.

#![allow(dead_code)] // Each test binary links its own copy and uses only the helpers it needs.

use std::path::{Path, PathBuf};

/// The gitignored libopus reference tree, if it has been checked out and built.
pub fn reference_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus");
    dir.is_dir().then_some(dir)
}

/// Resolve a test-only oracle binary by name (`opus_compare`, `opus_demo`).
///
/// Order, most specific first:
/// 1. the binary's env override (`$SIPHON_RTP_OPUS_COMPARE` / `$SIPHON_RTP_OPUS_DEMO`) — an
///    explicit path wins outright, so one build can serve every git worktree, and pointing it at
///    a missing file is an error the caller should see rather than a silent fallback;
/// 2. the in-tree `reference/opus/build/<name>` — the path CONTRIBUTING tells you to build, and
///    the one `opus_demo` has always used;
/// 3. `/tmp/<name>` — the historical default, kept so an existing shared build keeps working.
///
/// `/tmp` is deliberately last: it is cleared on reboot, and an oracle that vanishes while the
/// gitignored vectors survive turns the conformance suite red for a reason that has nothing to do
/// with the codec.
pub fn oracle(name: &str) -> Option<PathBuf> {
    if let Some(override_path) = env_override(name) {
        let path = PathBuf::from(override_path);
        return path.is_file().then_some(path);
    }
    if let Some(in_tree) = reference_dir().map(|dir| dir.join("build").join(name)) {
        if in_tree.is_file() {
            return Some(in_tree);
        }
    }
    let legacy = Path::new("/tmp").join(name);
    legacy.is_file().then_some(legacy)
}

/// The env override for an oracle, if that oracle has one.
fn env_override(name: &str) -> Option<std::ffi::OsString> {
    let variable = match name {
        "opus_compare" => "SIPHON_RTP_OPUS_COMPARE",
        "opus_demo" => "SIPHON_RTP_OPUS_DEMO",
        _ => return None,
    };
    std::env::var_os(variable)
}

/// `opus_compare`, or the reason it is unusable — the message every conformance test skips on.
pub fn opus_compare_or_reason() -> Result<PathBuf, String> {
    oracle("opus_compare").ok_or_else(|| {
        "opus_compare not built (test-only C reference; build reference/opus or set \
         SIPHON_RTP_OPUS_COMPARE)"
            .to_string()
    })
}
