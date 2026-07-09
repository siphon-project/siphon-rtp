//! ICE (RFC 8445) support for the engine's **ICE-lite** server posture.
//!
//! For now this is the credential machinery: the engine generates its own short-term credentials
//! (`ice-ufrag` / `ice-pwd`) per ICE call, advertises them in rewritten SDP, and installs them on
//! the datapath endpoints (`Datapath::set_ice`) so the connectivity-check responder can validate
//! and answer incoming checks. The full ICE state machine + consent (RFC 7675) build on this.
//! See `docs/security-and-nat.md` §4 layer 4.
//!
//! The [`consent`] submodule adds the RFC 7675 consent-freshness checker — the initiator side that
//! actively probes an established peer and detects a dead/withdrawn one — built on the STUN client
//! in `siphon-rtp-stun`. Pure, tick-driven logic; the daemon sweeper drives it (wired in a follow-up).

pub mod consent;

/// The engine's short-term ICE credentials for one call (its own identity as the ICE-lite server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCredentials {
    /// The local username fragment (advertised as `a=ice-ufrag`).
    pub ufrag: String,
    /// The local password (advertised as `a=ice-pwd`; signs/validates `MESSAGE-INTEGRITY`).
    pub pwd: String,
}

/// The ICE `ice-char` alphabet (RFC 8445 §5.4 — ALPHA / DIGIT / `+` / `/`). 64 symbols, so a byte
/// modulo 64 is unbiased (256 is an exact multiple of 64).
const ICE_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Generate fresh ICE credentials from the OS CSPRNG: a 8-char ufrag and a 24-char password (both
/// within RFC 8445 §5.4 length bounds — ufrag ≥ 4, pwd ≥ 22). Returns `None` if the OS RNG is
/// unavailable, in which case the caller falls back to non-ICE handling.
#[must_use]
pub fn generate_credentials() -> Option<IceCredentials> {
    Some(IceCredentials {
        ufrag: random_ice_string(8)?,
        pwd: random_ice_string(24)?,
    })
}

fn random_ice_string(len: usize) -> Option<String> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).ok()?;
    Some(
        bytes
            .iter()
            .map(|&byte| ICE_ALPHABET[(byte % 64) as usize] as char)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_meet_rfc8445_shape() {
        let credentials = generate_credentials().expect("OS RNG available");
        assert!(credentials.ufrag.len() >= 4, "ufrag ≥ 4 chars");
        assert!(credentials.pwd.len() >= 22, "pwd ≥ 22 chars");
        // Every character is from the ice-char alphabet.
        let alphabet: Vec<char> = ICE_ALPHABET.iter().map(|&b| b as char).collect();
        for character in credentials.ufrag.chars().chain(credentials.pwd.chars()) {
            assert!(
                alphabet.contains(&character),
                "{character:?} is an ice-char"
            );
        }
    }

    #[test]
    fn credentials_are_fresh_each_call() {
        let first = generate_credentials().expect("rng");
        let second = generate_credentials().expect("rng");
        // A collision on 24 random base64 chars (~144 bits) is astronomically unlikely.
        assert_ne!(
            first.pwd, second.pwd,
            "passwords are unpredictable per call"
        );
    }
}
