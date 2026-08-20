# siphon-rtp-turn

The built-in pure-Rust TURN server ([RFC 5766](https://www.rfc-editor.org/rfc/rfc5766)) for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp) — a drop-in coturn replacement for the
WebRTC voice-AI legs.

Relay ports are drawn from the shared bounded datapath pool; allocation state is a single-owner
actor behind a `flume` mailbox. **Zero C:** the STUN/TURN codec and the MD5 / HMAC-SHA1 long-term
auth are hand-rolled in [`siphon-rtp-stun`](https://crates.io/crates/siphon-rtp-stun).

```toml
[dependencies]
siphon-rtp-turn = "0.2"
```

## License

MIT
