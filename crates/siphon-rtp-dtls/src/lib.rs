//! Pure-Rust DTLS-SRTP (RFC 5764) keying for a secure WebRTC leg.
//!
//! The handshake runs on [`webrtc-dtls`](webrtc_dtls) — pure RustCrypto, zero C, so it satisfies the
//! workspace's zero-C rule — over a [`DtlsTransport`] that bridges the datapath's `Redirect` path
//! (inbound `PacketClass::Dtls` datagrams in, outbound DTLS records out) instead of owning a socket.
//! On completion [`handshake`] verifies the peer's certificate against the SDP `a=fingerprint`
//! (RFC 5763 §5 — DTLS-SRTP's trust anchor is the fingerprint, not a CA chain), exports RFC 5764 §4.2
//! keying material, and returns a [`siphon_rtp_srtp::leg::SecureLeg`] keyed for both directions — the
//! same secure leg the SDES path produces, so all downstream media handling is shared.
//!
//! The engine advertises its own certificate's fingerprint (via [`DtlsCertificate::fingerprint`]) in
//! the SDP it offers/answers, and passes the peer's signalled fingerprint to [`handshake`].
#![forbid(unsafe_code)]

mod handshake;
mod identity;
mod transport;

pub use handshake::{handshake, DtlsRole};
pub use identity::{DtlsCertificate, Fingerprint};
pub use transport::{DtlsChannels, DtlsTransport};

/// Errors from DTLS-SRTP keying.
#[derive(Debug, thiserror::Error)]
pub enum DtlsError {
    /// Generating or reading the self-signed certificate failed.
    #[error("certificate error: {0}")]
    Certificate(String),
    /// The DTLS handshake itself failed (timeout, alert, transport closed, …).
    #[error("DTLS handshake failed: {0}")]
    Handshake(String),
    /// The peer completed the handshake without presenting a certificate, so it cannot be
    /// authenticated against the signalled fingerprint (as DTLS server we require a client cert).
    #[error("peer presented no certificate to verify against the fingerprint")]
    MissingPeerCertificate,
    /// The peer's certificate does not hash to the fingerprint it signalled in SDP (RFC 5763 §5) —
    /// the media is not from the negotiated party, so the leg is rejected.
    #[error("peer certificate does not match the signalled fingerprint")]
    FingerprintMismatch,
    /// The DTLS peers did not agree on an SRTP protection profile this engine implements
    /// (`AES_CM_128_HMAC_SHA1_80`).
    #[error("no supported SRTP protection profile was negotiated")]
    UnsupportedProfile,
    /// Exporting or splitting the RFC 5764 §4.2 keying material failed.
    #[error("SRTP key export failed: {0}")]
    KeyExport(String),
}
