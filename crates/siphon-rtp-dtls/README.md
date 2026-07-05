# siphon-rtp-dtls

Pure-Rust DTLS-SRTP (RFC 5764) keying for a secure WebRTC leg in [siphon-rtp](https://github.com/siphon-project/siphon-rtp).

The DTLS handshake runs on [`webrtc-dtls`](https://crates.io/crates/webrtc-dtls) — pure RustCrypto,
**zero C** (no ring / aws-lc-rs / OpenSSL) — over a channel-backed transport that bridges the
datapath's `Redirect` path, so no socket is owned here. On completion it:

1. verifies the peer's certificate against the SDP `a=fingerprint` (RFC 5763 §5 — the fingerprint,
   not a CA chain, is the trust anchor);
2. exports RFC 5764 §4.2 keying material and splits it into per-direction SRTP key material;
3. returns a [`siphon-rtp-srtp`](../siphon-rtp-srtp) `SecureLeg` — the *same* secure leg the SDES path
   produces, so relay, HA, and conference handling are shared.

Licensed under MIT.
