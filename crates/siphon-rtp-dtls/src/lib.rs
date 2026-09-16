//! Pure-Rust DTLS-SRTP (RFC 5764) keying for a secure WebRTC leg.
//!
//! The handshake runs on [`rtc-dtls`](rtc_dtls), which is **sans-I/O**: it owns no socket, reads no
//! clock and spawns no task. The caller feeds it inbound datagrams, drains the datagrams it wants
//! sent, and drives its retransmission timer — so the engine keeps the DTLS association on its own
//! datapath `Redirect` path, and the association's lifetime is the caller's to control rather than a
//! detached task's.
//!
//! On completion [`DtlsSession`] verifies the peer's certificate against the SDP `a=fingerprint`
//! (RFC 5763 §5 — DTLS-SRTP's trust anchor is the fingerprint, not a CA chain), exports RFC 5764 §4.2
//! keying material, and yields a [`siphon_rtp_srtp::leg::SecureLeg`] keyed for both directions — the
//! same secure leg the SDES path produces, so all downstream media handling is shared.
//!
//! The engine advertises its own certificate's fingerprint (via [`DtlsCertificate::fingerprint`]) in
//! the SDP it offers/answers, and passes the peer's signalled fingerprint to the session.
//!
//! # Caller contract
//!
//! A session drives exactly **one** association and is addressed by a fixed internal key, so every
//! datagram handed to it is treated as coming from that peer whatever its source address. That is
//! what lets an ICE re-point move the leg without starting a second handshake — and it means the
//! caller **must** apply its source gate and the RFC 7983 demux *before* calling
//! [`DtlsSession::handle_datagram`]. The engine does this in its DTLS bridge (the RTPBleed source
//! check, then `classify(..) == PacketClass::Dtls`). Without it, any source reaching the port could
//! inject handshake records into the association; the fingerprint check still prevents a successful
//! impersonation, but not the denial of service.
#![forbid(unsafe_code)]

mod handshake;
mod identity;
mod session;

pub use handshake::{DtlsRole, SrtpKeying};
pub use identity::{DtlsCertificate, Fingerprint};
pub use session::{DtlsEvent, DtlsSession};

/// Errors from DTLS-SRTP keying.
#[derive(Debug, thiserror::Error)]
pub enum DtlsError {
    /// Generating or reading the self-signed certificate failed.
    #[error("certificate error: {0}")]
    Certificate(String),
    /// The DTLS handshake itself failed (alert, malformed record, transport closed, …).
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
    /// The session already failed, and every later call reports the same thing rather than
    /// re-entering the state machine on a association that is dead.
    #[error("DTLS session is closed")]
    Closed,
}
