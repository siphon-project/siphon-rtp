//! Compile the eBPF program and embed it via aya-build.
//!
//! The eBPF crate is a standalone workspace (its own pinned nightly), so we point cargo-metadata at
//! its manifest directly rather than the parent workspace (which excludes it). aya-build invokes
//! the eBPF crate's toolchain (`rust-src` + bpf-linker) and writes the object into `OUT_DIR`, which
//! the loader pulls in with `aya::include_bytes_aligned!`.

use std::path::PathBuf;

fn main() {
    let ebpf_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("siphon-rtp-ebpf")
        .join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", ebpf_manifest.display());

    let metadata = aya_build::cargo_metadata::MetadataCommand::new()
        .manifest_path(&ebpf_manifest)
        .no_deps()
        .exec()
        .expect("read siphon-rtp-ebpf cargo metadata");

    let ebpf_package = metadata
        .packages
        .into_iter()
        .find(|package| package.name == "siphon-rtp-ebpf")
        .expect("siphon-rtp-ebpf package present");

    aya_build::build_ebpf([ebpf_package]).expect("build the eBPF program");
}
