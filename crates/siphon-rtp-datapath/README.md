# siphon-rtp-datapath

The datapath seam for [siphon-rtp](https://github.com/siphon-project/siphon-rtp): a
backend-agnostic `Datapath` trait plus the always-available, NIC-free **UDP-loopback** backend used
by CI and as the reference for the XDP / AF_XDP backends.

```toml
[dependencies]
siphon-rtp-datapath = "0.2"
```

## License

MIT
