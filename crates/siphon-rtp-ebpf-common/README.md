# siphon-rtp-ebpf-common

The XDP map ABI shared between [siphon-rtp](https://github.com/siphon-project/siphon-rtp)'s kernel
program (`no_std`, nightly) and its userspace loader.

Pure `#[repr(C)]` POD structs — `no_std`, zero dependencies — so the ABI layout builds on stable and
is unit-tested here. The `aya::Pod` impls are added behind a `user` feature alongside the loader.

```toml
[dependencies]
siphon-rtp-ebpf-common = "0.1"
```

## License

MIT
