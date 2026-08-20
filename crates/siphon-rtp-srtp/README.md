# siphon-rtp-srtp

Pure-Rust SRTP / SRTCP ([RFC 3711](https://www.rfc-editor.org/rfc/rfc3711)) for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp)'s SDES bridge legs.

AES-CM + HMAC-SHA1 built on the RustCrypto primitives — **zero C, no libsrtp / OpenSSL.** The crypto
core is validated against the RFC test vectors in isolation from the engine, with criterion benches
on per-packet `protect` / `unprotect`.

```toml
[dependencies]
siphon-rtp-srtp = "0.2"
```

## License

MIT
