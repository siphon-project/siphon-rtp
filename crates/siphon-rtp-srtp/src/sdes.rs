//! SDP Security Descriptions for SRTP — the `a=crypto` line (RFC 4568).
//!
//! SDES carries the SRTP master key/salt inline in the SDP. The engine **generates** an
//! `a=crypto` offer on the secure (`RTP/SAVP`) leg and **parses** the peer's `a=crypto` from its
//! answer; the two key materials key the outbound and inbound [`crate::SrtpContext`]s. This module
//! only does the SDP attribute itself — key material in, attribute line out — never touches the
//! datapath.
//!
//! Scope: `AES_CM_128_HMAC_SHA1_80` (the SIP/VoLTE default) and `_32` are recognised; key material
//! is the 30-byte `master_key(16) || master_salt(14)` base64 inline value (RFC 4568 §9.1). The engine
//! emits no MKI and no lifetime on its own keys (both optional), but a peer's MKI is parsed and kept
//! on its [`SrtpKeyMaterial`]: RFC 3711 §3.1 puts the MKI in *every* packet under that key, so a
//! context that ignored it would authenticate over the wrong bytes and drop the whole stream.

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
    /// The `|<value>:<length>` MKI of a key-param was malformed, zero or over 128 bytes long, or
    /// named a value that does not fit its length (RFC 4568 §6.1).
    #[error("malformed MKI")]
    BadMki,
}

/// A master key identifier (RFC 3711 §3.1), signalled on a key-param as `|<value>:<length>`
/// (RFC 4568 §6.1): `length` bytes carrying `value` big-endian, present in every SRTP and SRTCP
/// packet under that key, after the encrypted portion and before the authentication tag. It is
/// neither encrypted nor authenticated.
///
/// The value is held as a `u64`. RFC 4568 allows up to 128 bytes of length, and a longer field is
/// represented with leading zero bytes; a *value* past 64 bits is refused as [`SdesError::BadMki`],
/// which makes the line unkeyable rather than keyed wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mki {
    value: u64,
    length: u8,
}

impl Mki {
    /// The longest MKI RFC 4568 §6.1 admits, in bytes.
    pub const MAX_LENGTH: usize = 128;

    /// An MKI of `length` bytes carrying `value`. Refuses a zero or over-long length and a value
    /// that does not fit in `length` bytes.
    pub fn new(value: u64, length: usize) -> Result<Self, SdesError> {
        let length_fits = (1..=Self::MAX_LENGTH).contains(&length);
        let value_fits = length >= 8 || value >> (8 * length) == 0;
        if !length_fits || !value_fits {
            return Err(SdesError::BadMki);
        }
        let length = u8::try_from(length).map_err(|_| SdesError::BadMki)?;
        Ok(Self { value, length })
    }

    /// The integer the MKI field carries.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    /// The MKI field's length on the wire, in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.length)
    }

    /// Always `false`: an MKI is at least one byte (RFC 4568 §6.1). Present for the `len` pairing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The field's byte at `position` (0 = first on the wire), big-endian and zero-padded.
    fn byte(&self, position: usize) -> u8 {
        let from_right = self.len() - 1 - position;
        if from_right < 8 {
            self.value.to_be_bytes()[7 - from_right]
        } else {
            0
        }
    }

    /// Whether `field` is exactly this MKI as it appears on the wire.
    #[must_use]
    pub fn matches(&self, field: &[u8]) -> bool {
        field.len() == self.len()
            && field
                .iter()
                .enumerate()
                .all(|(position, byte)| *byte == self.byte(position))
    }

    /// Append the MKI field to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend((0..self.len()).map(|position| self.byte(position)));
    }

    /// Parse the `<value>:<length>` text of a key-param's MKI (both decimal, RFC 4568 §6.1).
    fn parse(text: &str) -> Result<Self, SdesError> {
        let (value, length) = text.split_once(':').ok_or(SdesError::BadMki)?;
        let decimal = |digits: &str| {
            digits
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| digits.parse::<u64>().ok())
                .flatten()
                .ok_or(SdesError::BadMki)
        };
        let length = usize::try_from(decimal(length)?).map_err(|_| SdesError::BadMki)?;
        Self::new(decimal(value)?, length)
    }
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
    /// The master key identifier every packet under this key carries, when its key-param signalled
    /// one (RFC 3711 §3.1). `None` for the engine's own keys and for DTLS-exported ones.
    pub mki: Option<Mki>,
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
            mki: None,
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

    /// The answerer's attribute for an accepted offer line: fresh key material under the offered
    /// line's tag and suite. RFC 4568 §5.1.2 makes the answer's tag the identifier of the offer line
    /// it accepted and requires the same crypto-suite, so neither is the answerer's to renumber.
    pub fn answer_to(offered: &Self) -> Result<Self, SdesError> {
        Self::generate(offered.tag, offered.suite)
    }

    /// Whether [`crate::SrtpContext`] can run this line's suite. The context authenticates with the
    /// 80-bit tag only ([`crate::AUTH_TAG_LEN`]), so a `_32` line is recognised but cannot be keyed;
    /// an answerer must skip it and select a later line (RFC 4568 §7.1.1) rather than answer a suite
    /// it does not run.
    #[must_use]
    pub fn is_keyable(&self) -> bool {
        self.suite.auth_tag_len() == crate::AUTH_TAG_LEN
    }

    /// Parse the value of an `a=crypto` line (the text after `a=`, i.e. `crypto:<tag> <suite>
    /// inline:<base64>[|lifetime][|MKI:length][ session-params]`). The first inline key-param is
    /// used, with its MKI; the lifetime and any session parameters are ignored.
    ///
    /// Only the first key-param is keyed. A peer listing several keys under different MKIs to roll
    /// between them (RFC 4568 §6.1) is therefore heard until it switches, after which its packets
    /// name an MKI this key does not carry and fail as [`crate::SrtpError::UnknownMki`].
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

        // First key-param only: `inline:<key>[|<lifetime>][|<MKI>:<length>]` (RFC 4568 §6.1). The
        // lifetime and the MKI are told apart by the colon only the MKI has.
        let first = key_params.split(';').next().unwrap_or(key_params);
        let inline = first.strip_prefix("inline:").ok_or(SdesError::BadKey)?;
        let mut parts = inline.split('|');
        let encoded = parts.next().unwrap_or(inline);
        let raw = STANDARD.decode(encoded).map_err(|_| SdesError::BadKey)?;
        let mut key = SrtpKeyMaterial::from_inline_bytes(&raw)?;
        for part in parts {
            if part.contains(':') {
                if key.mki.is_some() {
                    return Err(SdesError::BadMki);
                }
                key.mki = Some(Mki::parse(part)?);
            }
        }
        Ok(Self { tag, suite, key })
    }

    /// [`Self::parse`], keeping only a line [`Self::is_keyable`]: `None` for one the engine cannot
    /// parse or whose suite the SRTP context does not run. An answerer skips any line it does not
    /// support (RFC 4568 §7.1.1), so selecting such a line would answer a suite never applied.
    #[must_use]
    pub fn parse_keyable(attribute_value: &str) -> Option<Self> {
        Self::parse(attribute_value).ok().filter(Self::is_keyable)
    }

    /// Render the SDP attribute value (`crypto:<tag> <suite> inline:<base64>[|<MKI>:<length>]`),
    /// without the `a=`.
    #[must_use]
    pub fn to_attribute_value(&self) -> String {
        let mki = self
            .key
            .mki
            .map(|mki| format!("|{}:{}", mki.value(), mki.len()))
            .unwrap_or_default();
        format!(
            "crypto:{} {} inline:{}{mki}",
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
        // `1:4` is MKI value 1 in a 4-byte field, which every packet under this key carries.
        assert_eq!(attribute.key.mki, Some(Mki::new(1, 4).expect("mki")));
    }

    #[test]
    fn an_mki_is_kept_with_or_without_a_lifetime_ahead_of_it() {
        // RFC 4568 §6.1: both `|lifetime` and `|MKI:length` are optional and independent.
        let key = "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR";
        let with = |suffix: &str| {
            CryptoAttribute::parse(&format!("crypto:2 AES_CM_128_HMAC_SHA1_80 {key}{suffix}"))
                .expect("parse")
                .key
                .mki
        };
        assert_eq!(with("|2^31|1:1"), Some(Mki::new(1, 1).expect("mki")));
        assert_eq!(with("|7:2"), Some(Mki::new(7, 2).expect("mki")));
        assert_eq!(with("|2^31"), None);
        assert_eq!(with(""), None);
    }

    #[test]
    fn a_malformed_mki_makes_the_line_unparseable_rather_than_keyed_without_it() {
        let key = "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR";
        for suffix in ["|1:0", "|1:129", "|256:1", "|x:1", "|1:", "|:1", "|1:1|2:1"] {
            assert_eq!(
                CryptoAttribute::parse(&format!("crypto:1 AES_CM_128_HMAC_SHA1_80 {key}{suffix}")),
                Err(SdesError::BadMki),
                "{suffix}"
            );
        }
    }

    #[test]
    fn an_mki_is_its_value_big_endian_in_its_signalled_length() {
        let mut field = Vec::new();
        Mki::new(0x0102, 4).expect("mki").write_to(&mut field);
        assert_eq!(field, [0, 0, 1, 2]);
        let wide = Mki::new(u64::MAX, 10).expect("a field wider than the value");
        let mut field = Vec::new();
        wide.write_to(&mut field);
        assert_eq!(
            field,
            [0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert!(wide.matches(&field));
        assert!(
            !wide.matches(&field[1..]),
            "the length is part of the identity"
        );
        assert!(!Mki::new(1, 1).expect("mki").matches(&[2]));
    }

    #[test]
    fn an_mki_round_trips_through_the_attribute_line() {
        let mut attribute =
            CryptoAttribute::generate(3, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        attribute.key.mki = Some(Mki::new(5, 2).expect("mki"));
        let line = attribute.to_attribute_value();
        assert!(line.ends_with("|5:2"), "{line}");
        assert_eq!(CryptoAttribute::parse(&line).expect("parse"), attribute);
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
    fn an_answer_keeps_the_accepted_lines_tag_and_suite_under_a_fresh_key() {
        // RFC 4568 §5.1.2: the answer's tag names the offer line it accepted and its suite is that
        // line's suite. A caller whose first offered line the engine cannot key accepts tag 2, so
        // an answer numbered from 1 would claim a line that was never accepted.
        let offered = CryptoAttribute::parse(
            "crypto:2 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR",
        )
        .expect("parse");
        let answer = CryptoAttribute::answer_to(&offered).expect("answer");
        assert_eq!(answer.tag, 2);
        assert_eq!(answer.suite, CryptoSuite::AesCm128HmacSha1_80);
        assert_ne!(answer.key, offered.key, "the answerer's key is its own");
        assert!(answer
            .to_attribute_value()
            .starts_with("crypto:2 AES_CM_128_HMAC_SHA1_80 inline:"));
    }

    #[test]
    fn only_a_suite_the_srtp_context_implements_is_keyable() {
        // The context authenticates with the 80-bit tag only (`AUTH_TAG_LEN`), so a `_32` line
        // parses but cannot be keyed: accepting it would answer a suite the engine does not run.
        let eighty = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
        let thirty_two =
            CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_32).expect("gen");
        assert!(eighty.is_keyable());
        assert!(!thirty_two.is_keyable());
        assert!(CryptoAttribute::parse_keyable(&eighty.to_attribute_value()).is_some());
        assert!(CryptoAttribute::parse_keyable(&thirty_two.to_attribute_value()).is_none());
        assert!(CryptoAttribute::parse_keyable("crypto:1 AEAD_AES_128_GCM inline:AAAA").is_none());
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
