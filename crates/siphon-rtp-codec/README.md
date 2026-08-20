# siphon-rtp-codec

Pure-Rust audio codecs for [siphon-rtp](https://github.com/siphon-project/siphon-rtp) — the
pure-Rust, kernel-accelerated media engine for SIPhon.

**Zero C dependencies.** Every codec is hand-written Rust and validated bit-exact against its
reference vectors (ITU-T G.191 STL; 3GPP TS 26.074 / 26.174), with criterion benches on every
encode/decode hot path.

Implemented: G.711 (A-law / µ-law, with PLC), L16 (linear PCM), G.722, G.726 (16/24/32/40 kbit/s), GSM-FR, RFC 3389 comfort noise, and Opus (full RFC 6716, encode + decode). AMR-NB and AMR-WB (encode + decode, bit-exact against the 3GPP vectors) are gated behind the off-by-default `amr` feature (patent-encumbered transcoding; passthrough/relay is always available).

```toml
[dependencies]
siphon-rtp-codec = "0.2"
```

## License

MIT
