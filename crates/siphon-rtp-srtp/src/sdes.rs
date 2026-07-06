//! SDP Security Descriptions for SRTP — the `a=crypto` line (RFC 4568).
//!
//! SDES carries the SRTP master key/salt inline in the SDP. The engine **generates** an
//! `a=crypto` offer on the secure (`RTP/SAVP`) leg and **parses** the peer's `a=crypto` from its
//! answer; the two key materials key the outbound and inbound [`crate::SrtpContext`]s. This module
//! only does the SDP attribute itself — key material in, attribute line out — never touches the
//! datapath.
//!
//! Scope: `AES_CM_128_HMAC_SHA1_80` (the SIP/VoLTE default) and `_32` are recognised; key material
//! is the 30-byte `master_key(16) || master_salt(14)` base64 inline value (RFC 4568 §9.1, no MKI /
//! no lifetime emitted — both optional and widely accepted absent).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::kdf::MASTER_SALT_LEN;
use crate::MASTER_KEY_LEN;

/// Inline key material length: 16-byte master key + 14-byte master salt (RFC 4568 §9.1).
const INLINE_KEY_LEN: usize = MASTER_KEY_LEN + MASTER_SALT_LEN;

/// Errors parsing or generating an `a=crypto` attribute.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SdesError {
    /// The attribute did not start with `crypto:`.
    #[error("not an a=crypto attribute")]
    NotCrypto,
    /// The tag, suite, or key-params field was missing.
    #[error("malformed a=crypto: {0}")]
    Malformed(&'static str),
    /// The crypto-suite is not one this engine implements.
    #[error("unsupported crypto-suite: {0}")]
    UnsupportedSuite(String),
    /// The inline key-params were not `inline:<base64>` or the base64 was invalid.
    #[error("malformed inline key")]
    BadKey,
    /// The decoded key material was not 30 bytes (16 key + 14 salt).
    #[error("wrong key length: {0} bytes (want {INLINE_KEY_LEN})")]
    KeyLength(usize),
    /// The OS CSPRNG failed (key generation).
    #[error("randomness unavailable")]
    Random,
}

/// An SRTP crypto-suite as named on the `a=crypto` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSuite {
    /// `AES_CM_128_HMAC_SHA1_80` — AES-CM-128 + HMAC-SHA1, 80-bit auth tag (the default).
    AesCm128HmacSha1_80,
    /// `AES_CM_128_HMAC_SHA1_32` — as above with a 32-bit auth tag.
    AesCm128HmacSha1_32,
}

impl CryptoSuite {
    /// The IANA crypto-suite name as it appears on the wire.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            CryptoSuite::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            CryptoSuite::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
        }
    }

    /// Parse an IANA crypto-suite name (the inverse of [`Self::name`]); `None` if unrecognised.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "AES_CM_128_HMAC_SHA1_80" => Some(CryptoSuite::AesCm128HmacSha1_80),
            "AES_CM_128_HMAC_SHA1_32" => Some(CryptoSuite::AesCm128HmacSha1_32),
            _ => None,
        }
    }

    /// Authentication-tag length in bytes for this suite (80 → 10, 32 → 4).
    #[must_use]
    pub fn auth_tag_len(self) -> usize {
        match self {
            CryptoSuite::AesCm128HmacSha1_80 => 10,
            CryptoSuite::AesCm128HmacSha1_32 => 4,
        }
    }
}

/// SRTP master key + salt for one direction (the inline value of an `a=crypto`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SrtpKeyMaterial {
    /// 16-byte master key.
    pub master_key: [u8; MASTER_KEY_LEN],
    /// 14-byte master salt.
    pub master_salt: [u8; MASTER_SALT_LEN],
}

impl SrtpKeyMaterial {
    /// Fresh random key material from the OS CSPRNG (the engine's own offered key).
    pub fn generate() -> Result<Self, SdesError> {
        let mut bytes = [0u8; INLINE_KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|_| SdesError::Random)?;
        // `bytes` is exactly `INLINE_KEY_LEN`, so this split is infallible; propagate the `Result`
        // rather than unwrap it (house rule: no `.expect()` in production).
        Self::from_inline_bytes(&bytes)
    }

    /// Split the 30-byte inline value into master key (16) and salt (14).
    pub fn from_inline_bytes(bytes: &[u8]) -> Result<Self, SdesError> {
        if bytes.len() != INLINE_KEY_LEN {
            return Err(SdesError::KeyLength(bytes.len()));
        }
        let mut master_key = [0u8; MASTER_KEY_LEN];
        let mut master_salt = [0u8; MASTER_SALT_LEN];
        master_key.copy_from_slice(&bytes[..MASTER_KEY_LEN]);
        master_salt.copy_from_slice(&bytes[MASTER_KEY_LEN..]);
        Ok(Self {
            master_key,
            master_salt,
        })
    }

    /// The 30-byte inline value: `master_key || master_salt`.
    #[must_use]
    pub fn to_inline_bytes(&self) -> [u8; INLINE_KEY_LEN] {
        let mut bytes = [0u8; INLINE_KEY_LEN];
        bytes[..MASTER_KEY_LEN].copy_from_slice(&self.master_key);
        bytes[MASTER_KEY_LEN..].copy_from_slice(&self.master_salt);
        bytes
    }
}

// Never leak key bytes through Debug (logs).
impl std::fmt::Debug for SrtpKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SrtpKeyMaterial(<redacted>)")
    }
}

/// A parsed or to-be-generated `a=crypto` attribute (one crypto context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoAttribute {
    /// The crypto tag (`a=crypto:<tag>`), matched against the chosen line in the answer.
    pub tag: u32,
    /// The negotiated crypto-suite.
    pub suite: CryptoSuite,
    /// The inline master key/salt.
    pub key: SrtpKeyMaterial,
}

impl CryptoAttribute {
    /// Generate an offered attribute with fresh random key material for `suite` and `tag`.
    pub fn generate(tag: u32, suite: CryptoSuite) -> Result<Self, SdesError> {
        Ok(Self {
            tag,
            suite,
            key: SrtpKeyMaterial::generate()?,
        })
    }

    /// Parse the value of an `a=crypto` line (the text after `a=`, i.e. `crypto:<tag> <suite>
    /// inline:<base64>[|...][ session-params]`). The first inline key-param is used; lifetime/MKI
    /// suffixes and session parameters are ignored.
    pub fn parse(attribute_value: &str) -> Result<Self, SdesError> {
        let body = attribute_value
            .strip_prefix("crypto:")
            .ok_or(SdesError::NotCrypto)?;
        let mut fields = body.split_whitespace();
        let tag = fields
            .next()
            .ok_or(SdesError::Malformed("tag"))?
            .parse::<u32>()
            .map_err(|_| SdesError::Malformed("tag"))?;
        let suite_name = fields.next().ok_or(SdesError::Malformed("suite"))?;
        let suite = CryptoSuite::from_name(suite_name)
            .ok_or_else(|| SdesError::UnsupportedSuite(suite_name.to_string()))?;
        let key_params = fields.next().ok_or(SdesError::Malformed("key-params"))?;

        // First key-param only; strip the `inline:` prefix and any `|lifetime|MKI` suffix.
        let first = key_params.split(';').next().unwrap_or(key_params);
        let inline = first.strip_prefix("inline:").ok_or(SdesError::BadKey)?;
        let encoded = inline.split('|').next().unwrap_or(inline);
        let raw = STANDARD.decode(encoded).map_err(|_| SdesError::BadKey)?;
        let key = SrtpKeyMaterial::from_inline_bytes(&raw)?;
        Ok(Self { tag, suite, key })
    }

    /// Render the SDP attribute value (`crypto:<tag> <suite> inline:<base64>`), without the `a=`.
    #[must_use]
    pub fn to_attribute_value(&self) -> String {
        format!(
            "crypto:{} {} inline:{}",
            self.tag,
            self.suite.name(),
            STANDARD.encode(self.key.to_inline_bytes())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_rfc_style_crypto_line() {
        // RFC 4568 §6.1 example inline key (40 base64 chars = 30 bytes) with a lifetime|MKI suffix.
        let value = "crypto:1 AES_CM_128_HMAC_SHA1_80 \
                     inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:4";
        let attribute = CryptoAttribute::parse(value).expect("parse");
        assert_eq!(attribute.tag, 1);
        assert_eq!(attribute.suite, CryptoSuite::AesCm128HmacSha1_80);
        // The inline value is exactly 30 bytes once decoded.
        assert_eq!(attribute.key.to_inline_bytes().len(), INLINE_KEY_LEN);
    }

    #[test]
    fn round_trips_generate_to_parse() {
        let generated =
            CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let line = generated.to_attribute_value();
        assert!(line.starts_with("crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"));
        let parsed = CryptoAttribute::parse(&line).expect("parse");
        assert_eq!(parsed.tag, generated.tag);
        assert_eq!(parsed.suite, generated.suite);
        assert_eq!(parsed.key, generated.key);
    }

    #[test]
    fn generated_keys_differ() {
        let one = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let two = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        assert_ne!(one.key, two.key, "CSPRNG must not repeat key material");
    }

    #[test]
    fn parses_the_32_bit_suite() {
        let value = "crypto:7 AES_CM_128_HMAC_SHA1_32 \
                     inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR";
        let attribute = CryptoAttribute::parse(value).expect("parse");
        assert_eq!(attribute.tag, 7);
        assert_eq!(attribute.suite, CryptoSuite::AesCm128HmacSha1_32);
        assert_eq!(attribute.suite.auth_tag_len(), 4);
    }

    #[test]
    fn rejects_unknown_suite() {
        let value = "crypto:1 AES_256_CM_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKJQAwxUeDb4Cfg==";
        assert!(matches!(
            CryptoAttribute::parse(value),
            Err(SdesError::UnsupportedSuite(_))
        ));
    }

    #[test]
    fn rejects_non_crypto_and_short_key() {
        assert_eq!(
            CryptoAttribute::parse("rtcp-mux"),
            Err(SdesError::NotCrypto)
        );
        // 20-byte (too short) inline value.
        let short = STANDARD.encode([0u8; 20]);
        let value = format!("crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{short}");
        assert_eq!(
            CryptoAttribute::parse(&value),
            Err(SdesError::KeyLength(20))
        );
    }

    #[test]
    fn debug_does_not_leak_key_bytes() {
        let key = SrtpKeyMaterial::generate().expect("gen");
        assert_eq!(format!("{key:?}"), "SrtpKeyMaterial(<redacted>)");
    }
}
