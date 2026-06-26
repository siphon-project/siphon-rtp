//! Compile the eBPF program and embed it via aya-build.
//!
//! aya-build runs `rustup run <toolchain> cargo build --package <name> -Z build-std=core
//! --target bpf{el,eb}-unknown-none` in the eBPF crate's directory, then embeds the object into
//! `OUT_DIR` (the loader pulls it in with `aya::include_bytes_aligned!`). The eBPF crate is a
//! standalone workspace (its own pinned nightly), so we point `root_dir` at it directly.

use std::path::PathBuf;

fn main() {
    let root_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("ebpf")
        .canonicalize()
        .expect("locate the siphon-rtp-ebpf crate directory");
    let root_dir = root_dir.to_str().expect("siphon-rtp-ebpf path is valid UTF-8");

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "siphon-rtp-ebpf",
            root_dir,
            no_default_features: false,
            features: &[],
        }],
        // Pinned nightly (LLVM 21.1.8) — matches bpf-linker's rust-llvm-21; the bleeding-edge
        // nightly's LLVM 22 dlopen-fails with the published bpf-linker. Keep in lockstep with
        // ebpf/rust-toolchain.toml and the Dockerfile.xdp install.
        aya_build::Toolchain::Custom("nightly-2026-01-15"),
    )
    .expect("build the eBPF program");
}
