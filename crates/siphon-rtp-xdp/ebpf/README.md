# siphon-rtp-ebpf

The XDP classifier program (`no_std`, kernel-side aya) for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp).

Built for `bpfel-unknown-none` using this crate's own pinned-nightly `rust-toolchain.toml` (driven
by the loader's `build.rs`), so the parent workspace stays on stable. It is its own workspace and is
excluded from the parent — `cargo test` never touches nightly / eBPF.

> **Not published to crates.io** (`publish = false`): an eBPF program compiles to BPF bytecode, not
> a consumable registry library.

## License

MIT
