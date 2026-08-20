# siphon-rtp-proto

The control-protocol contract between [SIPhon](https://github.com/siphon-project/siphon-sip)
and [`siphon-rtp`](https://github.com/siphon-project/siphon-rtp) — the pure-Rust,
kernel-accelerated media engine for SIPhon.

This crate is shared by both ends, so the types here *are* the wire contract. The native
transport is **length-prefixed JSON over a persistent TCP connection**: each frame is a
big-endian `u32` byte length followed by a JSON body.

- Requests and responses are correlated by `Request::id`.
- Asynchronous `Event`s are server-initiated and carry no id.
- The verb set and session keying (`call_id` / `from_tag` / `to_tag`) mirror the
  [rtpengine](https://github.com/sipwise/rtpengine) NG semantics SIPhon already speaks —
  only the encoding (JSON, not bencode) differs.

## Usage

```toml
[dependencies]
siphon-rtp-proto = "0.2"
```

```rust
use siphon_rtp_proto::{Command, Request};

let request = Request {
    id: 1,
    command: Command::Offer {
        call_id: "abc123".to_string(),
        from_tag: "from-tag".to_string(),
        sdp: "v=0\r\n...".to_string(),
        profile: Default::default(),
    },
};

let json = serde_json::to_string(&request).unwrap();
```

## License

MIT
