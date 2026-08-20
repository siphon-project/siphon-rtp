# siphon-rtp-stun

Pure-Rust STUN ([RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / RFC 5389) and TURN (RFC 5766)
for [siphon-rtp](https://github.com/siphon-project/siphon-rtp): the message codec, a STUN client for
ICE connectivity checks and RFC 7675 consent freshness, and a TURN client (allocation lifecycle +
ChannelData) for relayed ICE candidates. The TURN message set here also backs the built-in
`siphon-rtp-turn` server.

Deliberately dependency-light (only `thiserror` and `getrandom`) so the datapath can parse and
serialize STUN on the hot path without pulling in the media plane's heavier dependency tree. Zero C.

```toml
[dependencies]
siphon-rtp-stun = "0.2"
```

## License

MIT
