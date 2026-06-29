# siphon-rtp

The [siphon-rtp](https://github.com/siphon-project/siphon-rtp) engine daemon — a pure-Rust,
kernel-accelerated RTP media engine for SIPhon.

It ships a JSON-over-TCP (and rtpengine NG / bencode) control front-end, a session manager, and an
actor runtime over a pluggable datapath — the NIC-free UDP-loopback backend by default, or
XDP / AF_XDP for kernel acceleration. A drop-in for SIPhon's rtpengine integration and for existing
Kamailio / OpenSIPS rtpengine deployments.

## Install

```sh
cargo install siphon-rtp
```

This installs the `siphon-rtp` binary.

## License

MIT
