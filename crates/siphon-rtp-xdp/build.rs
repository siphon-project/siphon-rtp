//! Compile the eBPF program and embed it for the loader to `include_bytes_aligned!`.
//!
//! We invoke the eBPF build ourselves rather than via `aya_build::build_ebpf`: that helper builds the
//! program into `OUT_DIR/<name>/` (used as cargo's `--target-dir`) and then copies the artifact to
//! `OUT_DIR/<name>` — the *same path* — which fails with "Is a directory" (the destination is the
//! target dir). Every published aya-build 0.1.x shares that collision, so we replicate the helper's
//! `rustup run <toolchain> cargo build … --target bpfel-unknown-none` invocation but build into a
//! distinct target dir and copy the resulting object to `OUT_DIR/siphon-rtp-ebpf` (a file).
//!
//! The eBPF crate is a standalone workspace pinned to its own nightly (`ebpf/rust-toolchain.toml`),
//! built for `bpfel-unknown-none` with `build-std=core` and bpf-linker on PATH (the Dockerfile.xdp
//! toolchain). Keep the toolchain string in lockstep with `ebpf/rust-toolchain.toml` and the
//! Dockerfile.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The pinned nightly that matches bpf-linker's LLVM (see the module docs / Dockerfile.xdp).
const TOOLCHAIN: &str = "nightly-2026-01-15";
/// The eBPF package + binary name (the `[[bin]]` in `ebpf/Cargo.toml`).
const EBPF_PACKAGE: &str = "siphon-rtp-ebpf";
/// The little-endian BPF target the kernel program is built for (host-endian fixups not needed: all
/// our deploy targets are LE; aya defaults to `bpfel` likewise).
const BPF_TARGET: &str = "bpfel-unknown-none";

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let ebpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("ebpf")
        .canonicalize()
        .expect("locate the siphon-rtp-ebpf crate directory");

    // Rebuild the embedded object when any eBPF source changes.
    println!("cargo:rerun-if-changed={}", ebpf_dir.display());

    // A dedicated target dir for the eBPF build, distinct from the copy destination so there is no
    // file/dir collision (the aya-build bug this build.rs works around).
    let ebpf_target = out_dir.join("ebpf-target");

    let status = Command::new("rustup")
        .args([
            "run",
            TOOLCHAIN,
            "cargo",
            "build",
            "--release",
            "--package",
            EBPF_PACKAGE,
            "--bins",
            "-Z",
            "build-std=core",
            "--target",
            BPF_TARGET,
        ])
        .arg("--target-dir")
        .arg(&ebpf_target)
        // Run inside the eBPF crate's own workspace so its pinned toolchain + profile apply.
        .current_dir(&ebpf_dir)
        // aya/bpf-linker requires BTF debuginfo; mirror aya-build's rustflags.
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            "--cfg=bpf_target_arch=\"x86_64\"\u{1f}-Cdebuginfo=2\u{1f}-Clink-arg=--btf",
        )
        // Ensure the eBPF crate's toolchain is selected, not a wrapper from the parent build.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO")
        .status()
        .expect("spawn the eBPF cargo build");
    assert!(status.success(), "eBPF build failed: {status:?}");

    let artifact = ebpf_target
        .join(BPF_TARGET)
        .join("release")
        .join(EBPF_PACKAGE);
    let embed = out_dir.join(EBPF_PACKAGE);
    copy_artifact(&artifact, &embed);
}

/// Copy the built eBPF object to the embed path the loader includes with `include_bytes_aligned!`.
fn copy_artifact(artifact: &Path, embed: &Path) {
    std::fs::copy(artifact, embed).unwrap_or_else(|error| {
        panic!(
            "copy eBPF object {} -> {}: {error}",
            artifact.display(),
            embed.display()
        )
    });
}
