//! Long-term-credential authentication (coturn REST profile) and stateless nonces.
//!
//! Credentials follow the RFC 5766 §4 / RFC 5389 §10.2 long-term-credential mechanism with the
//! coturn `static-auth-secret` (REST) profile: the client's `username = <unix-expiry>[:id]`, the
//! `password = base64(HMAC-SHA1(static_auth_secret, username))`, and the MESSAGE-INTEGRITY key is
//! `MD5(username:realm:password)`. The server recomputes the password from the username it receives,
//! enforces the embedded expiry, and verifies the integrity — so it stores no per-user secrets.
//!
//! Nonces are **stateless**: `base64(issued_tick ‖ HMAC(secret, issued_tick ‖ client_ip)[..8])`,
//! validated by recomputation and an age check against the datapath logical clock — no per-nonce map
//! to grow or sweep, and 438 Stale Nonce falls out of the age check (RFC 5389 §10.2).

use std::net::{IpAddr, SocketAddr};

use siphon_rtp_stun::{self as stun, turn, StunMessage};

/// The outcome of authenticating a request under the long-term-credential mechanism.
pub(crate) enum AuthResult {
    /// Authenticated; carries the username (for quota keying) and the long-term key to sign the
    /// response's MESSAGE-INTEGRITY.
    Ok {
        /// The credential username.
        username: String,
        /// `MD5(username:realm:password)` — the response integrity key.
        key: [u8; 16],
    },
    /// Missing/invalid credentials → reply 401 with REALM + a fresh NONCE.
    Unauthorized,
    /// Valid credentials but an expired nonce → reply 438 with REALM + a fresh NONCE.
    StaleNonce,
}

/// Verifies long-term credentials under the coturn REST profile.
pub struct CredentialVerifier {
    secret: Vec<u8>,
    realm: String,
}

impl CredentialVerifier {
    /// A verifier for `realm`, keyed by the `static_auth_secret`.
    #[must_use]
    pub fn new(static_auth_secret: Vec<u8>, realm: String) -> Self {
        Self {
            secret: static_auth_secret,
            realm,
        }
    }

    /// Authenticate a parsed request whose wire bytes are `raw`. `unix_now` validates the REST
    /// username's embedded expiry; `now_tick` and `nonce` validate the NONCE; `client` binds the
    /// nonce to the requester. (RFC 5766 §4, RFC 5389 §10.2.2.)
    pub(crate) fn authenticate(
        &self,
        message: &StunMessage,
        raw: &[u8],
        unix_now: u64,
        nonce: &NonceFactory,
        now_tick: u64,
        client: SocketAddr,
    ) -> AuthResult {
        // The long-term mechanism requires USERNAME + REALM + NONCE + MESSAGE-INTEGRITY; any missing
        // ⇒ this is the first (unauthenticated) request — challenge it.
        let (Some(username), Some(realm), Some(nonce_value)) =
            (message.username(), turn::realm(message), turn::nonce(message))
        else {
            return AuthResult::Unauthorized;
        };
        if message.attribute(turn::ATTR_MESSAGE_INTEGRITY).is_none() {
            return AuthResult::Unauthorized;
        }
        if realm != self.realm {
            return AuthResult::Unauthorized;
        }
        match nonce.check(nonce_value, client, now_tick) {
            NonceStatus::Invalid => return AuthResult::Unauthorized,
            NonceStatus::Stale => return AuthResult::StaleNonce,
            NonceStatus::Valid => {}
        }
        // coturn REST profile: username = "<unix-expiry>[:id]"; reject an expired credential.
        let Some(expiry) = username
            .split(':')
            .next()
            .and_then(|field| field.parse::<u64>().ok())
        else {
            return AuthResult::Unauthorized;
        };
        if expiry < unix_now {
            return AuthResult::Unauthorized;
        }
        // password = base64(HMAC-SHA1(secret, username)); key = MD5(username:realm:password).
        let password = turn::base64_encode(&stun::hmac_sha1(&self.secret, username.as_bytes()));
        let key = turn::long_term_key(username, &self.realm, &password);
        if stun::verify_message_integrity(raw, &key) {
            AuthResult::Ok {
                username: username.to_string(),
                key,
            }
        } else {
            AuthResult::Unauthorized
        }
    }
}

/// Verdict of a nonce check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonceStatus {
    /// Authentic and within its lifetime.
    Valid,
    /// Authentic but older than the nonce lifetime → 438.
    Stale,
    /// Forged, malformed, or for a different client → 401.
    Invalid,
}

/// Issues and validates stateless, HMAC-stamped nonces.
pub struct NonceFactory {
    secret: [u8; 32],
    lifetime: u64,
}

impl NonceFactory {
    /// A factory keyed by `secret` (seeded from the OS CSPRNG at startup) with a nonce `lifetime` in
    /// logical ticks.
    #[must_use]
    pub fn new(secret: [u8; 32], lifetime: u64) -> Self {
        Self { secret, lifetime }
    }

    /// Issue a fresh nonce for `client` stamped at `now_tick`.
    #[must_use]
    pub fn issue(&self, client: SocketAddr, now_tick: u64) -> String {
        let payload = now_tick.to_be_bytes();
        let mac = self.stamp(&payload, client);
        let mut raw = Vec::with_capacity(16);
        raw.extend_from_slice(&payload);
        raw.extend_from_slice(&mac[..8]);
        turn::base64_encode(&raw)
    }

    /// Validate a NONCE attribute value (the base64 text we issued) for `client` at `now_tick`.
    pub(crate) fn check(&self, nonce_value: &[u8], client: SocketAddr, now_tick: u64) -> NonceStatus {
        let Ok(text) = std::str::from_utf8(nonce_value) else {
            return NonceStatus::Invalid;
        };
        let Some(raw) = turn::base64_decode(text) else {
            return NonceStatus::Invalid;
        };
        if raw.len() != 16 {
            return NonceStatus::Invalid;
        }
        let Ok(payload) = <[u8; 8]>::try_from(&raw[0..8]) else {
            return NonceStatus::Invalid;
        };
        let expected = self.stamp(&payload, client);
        if !constant_time_eq(&raw[8..16], &expected[..8]) {
            return NonceStatus::Invalid;
        }
        let issued = u64::from_be_bytes(payload);
        if now_tick.saturating_sub(issued) > self.lifetime {
            NonceStatus::Stale
        } else {
            NonceStatus::Valid
        }
    }

    /// The 8-byte truncated HMAC binding `payload` (the issue tick) to the client's IP.
    fn stamp(&self, payload: &[u8; 8], client: SocketAddr) -> [u8; 20] {
        let mut data = Vec::with_capacity(8 + 16);
        data.extend_from_slice(payload);
        match client.ip() {
            IpAddr::V4(ip) => data.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => data.extend_from_slice(&ip.octets()),
        }
        stun::hmac_sha1(&self.secret, &data)
    }
}

/// Length-checked, branch-free byte comparison (no early-exit on the first differing byte).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> SocketAddr {
        "198.51.100.20:40000".parse().expect("addr")
    }

    #[test]
    fn nonce_round_trips_within_lifetime_and_goes_stale() {
        let factory = NonceFactory::new([7u8; 32], 100);
        let nonce = factory.issue(client(), 1_000);
        assert_eq!(factory.check(nonce.as_bytes(), client(), 1_050), NonceStatus::Valid);
        // Past its lifetime → stale (the 438 trigger).
        assert_eq!(factory.check(nonce.as_bytes(), client(), 1_101), NonceStatus::Stale);
    }

    #[test]
    fn nonce_is_bound_to_the_client_and_unforgeable() {
        let factory = NonceFactory::new([3u8; 32], 100);
        let nonce = factory.issue(client(), 10);
        // A different client cannot reuse it.
        let other: SocketAddr = "203.0.113.9:40000".parse().expect("addr");
        assert_eq!(factory.check(nonce.as_bytes(), other, 11), NonceStatus::Invalid);
        // A different secret rejects it (no shared MAC key).
        let attacker = NonceFactory::new([4u8; 32], 100);
        assert_eq!(attacker.check(nonce.as_bytes(), client(), 11), NonceStatus::Invalid);
        // Garbage is rejected, not panicked on.
        assert_eq!(factory.check(b"not-base64!!", client(), 11), NonceStatus::Invalid);
        assert_eq!(factory.check(b"", client(), 11), NonceStatus::Invalid);
    }

    /// Build an authenticated Allocate the way a coturn REST client does, and check the verifier
    /// accepts it — then check that a tampered username (forged expiry) is rejected.
    #[test]
    fn rest_credentials_authenticate_and_reject_forgery() {
        let secret = b"static-auth-secret".to_vec();
        let realm = "siphon.example".to_string();
        let verifier = CredentialVerifier::new(secret.clone(), realm.clone());
        let nonce_factory = NonceFactory::new([9u8; 32], 600);
        let client = client();
        let nonce = nonce_factory.issue(client, 0);

        let username = "2000000000:webrtc";
        let password = turn::base64_encode(&stun::hmac_sha1(&secret, username.as_bytes()));
        let key = turn::long_term_key(username, &realm, &password);

        let request = build_authed_allocate(username, &realm, nonce.as_bytes(), &key);
        let parsed = stun::parse(&request).expect("parse");
        match verifier.authenticate(&parsed, &request, 1_000, &nonce_factory, 1, client) {
            AuthResult::Ok { username: u, key: k } => {
                assert_eq!(u, username);
                assert_eq!(k, key);
            }
            _ => panic!("valid REST credentials must authenticate"),
        }

        // An expired credential (expiry in the past) is rejected.
        let expired = "100:webrtc";
        let pw2 = turn::base64_encode(&stun::hmac_sha1(&secret, expired.as_bytes()));
        let key2 = turn::long_term_key(expired, &realm, &pw2);
        let request2 = build_authed_allocate(expired, &realm, nonce.as_bytes(), &key2);
        let parsed2 = stun::parse(&request2).expect("parse");
        assert!(matches!(
            verifier.authenticate(&parsed2, &request2, 1_000, &nonce_factory, 1, client),
            AuthResult::Unauthorized
        ));

        // A wrong integrity key (attacker without the secret) is rejected.
        let forged = build_authed_allocate(username, &realm, nonce.as_bytes(), &[0u8; 16]);
        let forged_parsed = stun::parse(&forged).expect("parse");
        assert!(matches!(
            verifier.authenticate(&forged_parsed, &forged, 1_000, &nonce_factory, 1, client),
            AuthResult::Unauthorized
        ));
    }

    #[test]
    fn missing_credentials_challenge() {
        let verifier = CredentialVerifier::new(b"s".to_vec(), "r".to_string());
        let nonce_factory = NonceFactory::new([1u8; 32], 600);
        // A bare Allocate with no USERNAME/REALM/NONCE/MI → challenge.
        let bare = stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
            &[1u8; 12],
        )
        .attribute(
            turn::ATTR_REQUESTED_TRANSPORT,
            &turn::requested_transport_value(turn::TRANSPORT_UDP),
        )
        .finish(None, false);
        let parsed = stun::parse(&bare).expect("parse");
        assert!(matches!(
            verifier.authenticate(&parsed, &bare, 1_000, &nonce_factory, 1, client()),
            AuthResult::Unauthorized
        ));
    }

    fn build_authed_allocate(username: &str, realm: &str, nonce: &[u8], key: &[u8]) -> Vec<u8> {
        stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
            &[2u8; 12],
        )
        .attribute(
            turn::ATTR_REQUESTED_TRANSPORT,
            &turn::requested_transport_value(turn::TRANSPORT_UDP),
        )
        .attribute(turn::ATTR_USERNAME, username.as_bytes())
        .attribute(turn::ATTR_REALM, realm.as_bytes())
        .attribute(turn::ATTR_NONCE, nonce)
        .finish(Some(key), false)
    }
}
