# siphon-rtp-xdp

The XDP / AF_XDP datapath backend (userspace loader) for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp) — kernel-accelerated RTP relay.

Kept a **separate** crate from `siphon-rtp-datapath` so the kernel-acceleration plumbing never
disturbs the always-available UDP-loopback backend; it implements the same `Datapath` trait. The
userspace code builds on stable, but its `build.rs` compiles the companion eBPF program
([`siphon-rtp-ebpf`](./ebpf)) with a **pinned-nightly toolchain + `bpf-linker`**, so the crate is
excluded from the default workspace and built via the docker XDP toolchain.

> **Not published to crates.io** (`publish = false`). The `build.rs` eBPF compilation needs a
> pinned nightly and `bpf-linker` that a plain `cargo install` would not have, and the path-deps
> (`siphon-rtp-datapath`, `siphon-rtp-ebpf-common`) must be published first. Flip `publish` only
> once that build is reproducible from a registry install.

## License

MIT
