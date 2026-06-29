# siphon-rtp-codec

Pure-Rust audio codecs for [siphon-rtp](https://github.com/siphon-project/siphon-rtp) — the
pure-Rust, kernel-accelerated media engine for SIPhon.

**Zero C dependencies.** Every codec is hand-written Rust and validated bit-exact against its
reference vectors (ITU-T G.191 STL; 3GPP TS 26.074 / 26.174), with criterion benches on every
encode/decode hot path.

Implemented: G.711 (A-law / µ-law, with PLC), L16 (linear PCM), and the AMR-NB / AMR-WB foundation.

```toml
[dependencies]
siphon-rtp-codec = "0.1"
```

## License

MIT
