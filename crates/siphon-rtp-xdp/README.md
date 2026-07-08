# siphon-rtp-xdp

The XDP / AF_XDP datapath backend (userspace loader) for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp) — kernel-accelerated RTP relay.

Kept a **separate** crate from `siphon-rtp-datapath` so the kernel-acceleration plumbing never
disturbs the always-available UDP-loopback backend; it implements the same `Datapath` trait. The
userspace code builds on stable, but its `build.rs` compiles the companion eBPF program
([`siphon-rtp-ebpf`](./ebpf)) with a **pinned-nightly toolchain + `bpf-linker`**, so the crate is
excluded from the default workspace and built via the docker XDP toolchain.

## The `siphon-rtp-xdp-daemon` binary (the two-binary datapath model)

The XDP datapath is a **separate binary, not a Cargo feature** on the engine. There are two daemons:

- **`siphon-rtp`** (crate `siphon-rtp`, the default) — **UDP-only**. It never depends on this crate,
  so the stable workspace, `cargo test`, `cargo fmt --all`, and the default Docker image never touch
  the nightly/eBPF toolchain. This is what `cargo install siphon-rtp` and the runtime image ship.
- **`siphon-rtp-xdp-daemon`** (this crate's `src/bin/siphon-rtp-xdp-daemon.rs`) — the
  kernel-accelerated daemon. It depends **up into** the engine (`siphon-rtp`), reuses its entire
  CLI/TOML surface, and adds `--xdp-interface <NAME>` + `--xdp-queue <N>`. At startup it probes XDP
  capability, tries native then generic-SKB attach, and hands the resulting `XdpDatapath` to
  `siphon_rtp_engine::run_with_datapath` — the *same* generic runner the UDP binary uses, so control,
  TURN, dispatch, sweep, metrics, and NG behave identically over either datapath. On any missing
  capability / attach failure, or without a routable IPv4 `--relay-bind-ip`, it logs and falls back
  to the UDP-loopback datapath — never a hard failure.

Build it where the eBPF toolchain exists (this excluded workspace):

```sh
cd crates/siphon-rtp-xdp
cargo build --locked --bin siphon-rtp-xdp-daemon
sudo ./target/debug/siphon-rtp-xdp-daemon --xdp-interface eth0 --relay-bind-ip 203.0.113.7
```

> **Not published to crates.io** (`publish = false`). The `build.rs` eBPF compilation needs a
> pinned nightly and `bpf-linker` that a plain `cargo install` would not have, and the path-deps
> (`siphon-rtp-datapath`, `siphon-rtp-ebpf-common`) must be published first. Flip `publish` only
> once that build is reproducible from a registry install.

## License

MIT
