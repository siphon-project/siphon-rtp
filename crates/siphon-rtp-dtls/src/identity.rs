//! The DTLS identity of a secure leg: a self-signed certificate plus its fingerprint.
//!
//! DTLS-SRTP does not trust a CA chain — the trust anchor is the certificate **fingerprint** carried
//! in the SDP `a=fingerprint` line (RFC 8122), bound to the signalling (RFC 5763 §5). So the engine
//! generates a self-signed certificate, advertises its SHA-256 fingerprint in SDP, and on the other
//! side checks that the peer's presented certificate hashes to the fingerprint the peer signalled.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::DtlsError;

/// A self-signed DTLS certificate for a secure leg, plus the DER of its leaf certificate (the input to
/// the fingerprint). Cheap to clone (the inner key material is reference-counted by `webrtc-dtls`).
#[derive(Clone)]
pub struct DtlsCertificate {
    inner: webrtc_dtls::crypto::Certificate,
    leaf_der: Vec<u8>,
}

impl DtlsCertificate {
    /// Generate a fresh self-signed certificate (ECDSA P-256, as `webrtc-dtls` mints and WebRTC uses).
    pub fn generate() -> Result<Self, DtlsError> {
        let inner =
            webrtc_dtls::crypto::Certificate::generate_self_signed(vec!["siphon-rtp".to_owned()])
                .map_err(|error| DtlsError::Certificate(error.to_string()))?;
        let leaf_der = inner
            .certificate
            .first()
            .ok_or_else(|| DtlsError::Certificate("empty certificate chain".to_owned()))?
            .as_ref()
            .to_vec();
        Ok(Self { inner, leaf_der })
    }

    /// The SHA-256 fingerprint of the leaf certificate — the value to advertise in `a=fingerprint`.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::sha256_of(&self.leaf_der)
    }

    /// The inner `webrtc-dtls` certificate, for building a handshake `Config`.
    pub(crate) fn webrtc(&self) -> webrtc_dtls::crypto::Certificate {
        self.inner.clone()
    }
}

/// A certificate fingerprint (RFC 8122): a hash-function name plus the certificate's hash bytes. Used
/// both to advertise our own certificate and to verify the peer's against the fingerprint it signalled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The hash-function token, lowercased (RFC 8122 §5: `sha-256`, `sha-1`, `sha-384`, `sha-512`).
    pub hash_function: String,
    /// The certificate-hash bytes.
    pub bytes: Vec<u8>,
}

impl Fingerprint {
    /// The SHA-256 fingerprint of a DER-encoded certificate (the near-universal WebRTC choice).
    #[must_use]
    pub fn sha256_of(certificate_der: &[u8]) -> Self {
        Self {
            hash_function: "sha-256".to_owned(),
            bytes: Sha256::digest(certificate_der).to_vec(),
        }
    }

    /// Build a fingerprint from a signalled `a=fingerprint` (its hash-function token + decoded bytes).
    /// The token is lowercased so comparison is case-insensitive, as RFC 8122 §5 intends.
    #[must_use]
    pub fn new(hash_function: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            hash_function: hash_function.into().to_ascii_lowercase(),
            bytes,
        }
    }

    /// The `HEX:HEX:…` value (uppercase, colon-separated per RFC 8122 §5) for the SDP line's value
    /// after the hash-function token.
    #[must_use]
    pub fn hex(&self) -> String {
        self.bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Does `certificate_der` hash (under this fingerprint's algorithm) to these bytes? The comparison
    /// is what authenticates a DTLS-SRTP peer (RFC 5763 §5). An unsupported algorithm never matches.
    #[must_use]
    pub fn verify(&self, certificate_der: &[u8]) -> bool {
        // Fingerprints are public (they travel in SDP), so a plain equality check is fine — there is
        // no secret to leak by timing.
        match hash_certificate(&self.hash_function, certificate_der) {
            Some(actual) => actual == self.bytes,
            None => false,
        }
    }
}

/// Hash a DER certificate under a RFC 8122 §5 hash-function token, or `None` if it is not one we
/// support. `sha-256` is the WebRTC default; the others are accepted for interop.
fn hash_certificate(hash_function: &str, certificate_der: &[u8]) -> Option<Vec<u8>> {
    match hash_function {
        "sha-256" => Some(Sha256::digest(certificate_der).to_vec()),
        "sha-384" => Some(Sha384::digest(certificate_der).to_vec()),
        "sha-512" => Some(Sha512::digest(certificate_der).to_vec()),
        "sha-1" => Some(Sha1::digest(certificate_der).to_vec()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_certificate_has_a_32_byte_sha256_fingerprint() {
        let certificate = DtlsCertificate::generate().expect("generate");
        let fingerprint = certificate.fingerprint();
        assert_eq!(fingerprint.hash_function, "sha-256");
        assert_eq!(fingerprint.bytes.len(), 32);
        // The hex form is 32 uppercase octets joined by colons.
        assert_eq!(fingerprint.hex().split(':').count(), 32);
    }

    #[test]
    fn fingerprint_verifies_its_own_certificate_and_rejects_others() {
        let a = DtlsCertificate::generate().expect("a");
        let b = DtlsCertificate::generate().expect("b");
        let a_der = a.leaf_der.clone();
        let b_der = b.leaf_der.clone();

        assert!(a.fingerprint().verify(&a_der), "own cert verifies");
        assert!(!a.fingerprint().verify(&b_der), "a different cert does not");
    }

    #[test]
    fn new_lowercases_the_hash_token() {
        let fingerprint = Fingerprint::new("SHA-256", vec![0xAB, 0xCD]);
        assert_eq!(fingerprint.hash_function, "sha-256");
        assert_eq!(fingerprint.hex(), "AB:CD");
    }

    #[test]
    fn an_unsupported_hash_never_matches() {
        let fingerprint = Fingerprint::new("md5", vec![0u8; 16]);
        assert!(!fingerprint.verify(b"anything"));
    }
}
