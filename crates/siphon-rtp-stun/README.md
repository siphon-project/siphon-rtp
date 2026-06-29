# siphon-rtp-stun

Pure-Rust STUN ([RFC 8489](https://www.rfc-editor.org/rfc/rfc8489)) message codec for ICE
connectivity checks, part of [siphon-rtp](https://github.com/siphon-project/siphon-rtp).

Deliberately dependency-light (only `thiserror`) so the datapath can parse and serialize STUN on
the hot path without pulling in the media plane's heavier dependency tree. Zero C.

```toml
[dependencies]
siphon-rtp-stun = "0.1"
```

## License

MIT
