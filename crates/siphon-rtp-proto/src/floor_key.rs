//! The SRTCP floor keys a profile or `set_floor_keys` carries (3GPP TS 33.180 §9.4), their wire form
//! and why one is refused. Re-exported from the crate root.

use serde::{Deserialize, Serialize};

use crate::{base64, MAX_FLOOR_CHANNEL_LABEL_LEN};

/// The octets of an SRTCP master key for AEAD_AES_128_GCM (RFC 7714 §12.1).
pub const FLOOR_KEY_LEN: usize = 16;
/// The octets of the 96-bit SRTCP master salt of AEAD_AES_128_GCM (RFC 7714 §12).
pub const FLOOR_SALT_LEN: usize = 12;
/// The octets of the 112-bit SRTP master salt (RFC 3711 §4.3.1), the other length a MIKEY SP
/// policy can negotiate.
pub const FLOOR_SALT_LEN_LONG: usize = 14;
/// The most floor keys a seat holds at once ([`crate::ProfileFlags::floor_keys`], [`crate::Command::SetFloorKeys`]).
pub const MAX_FLOOR_KEYS: usize = 2;

/// Why a [`FloorKey`] or [`crate::ProfileFlags`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorKeyError {
    /// The master key is not [`FLOOR_KEY_LEN`] octets.
    KeyLength(usize),
    /// The master salt is neither [`FLOOR_SALT_LEN`] nor [`FLOOR_SALT_LEN_LONG`] octets.
    SaltLength(usize),
    /// More than [`MAX_FLOOR_KEYS`] keys in a profile.
    TooMany(usize),
    /// `key_mgmt` contains a CR or LF; it is written into an SDP line verbatim.
    KeyMgmtLineBreak,
    /// `floor_channel_label` is empty, longer than [`MAX_FLOOR_CHANNEL_LABEL_LEN`] octets, or holds
    /// a control character.
    ChannelLabel,
}

impl std::fmt::Display for FloorKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyLength(length) => write!(
                formatter,
                "floor key must be {FLOOR_KEY_LEN} octets, got {length}"
            ),
            Self::SaltLength(length) => write!(
                formatter,
                "floor salt must be {FLOOR_SALT_LEN} or {FLOOR_SALT_LEN_LONG} octets, got {length}"
            ),
            Self::TooMany(count) => write!(
                formatter,
                "at most {MAX_FLOOR_KEYS} floor keys are allowed in a profile, got {count}"
            ),
            Self::KeyMgmtLineBreak => formatter.write_str("key_mgmt must not contain a line break"),
            Self::ChannelLabel => write!(
                formatter,
                "floor_channel_label must be 1 to {MAX_FLOOR_CHANNEL_LABEL_LEN} octets with no control character"
            ),
        }
    }
}

impl std::error::Error for FloorKeyError {}

/// One SRTCP master key and salt for floor control (3GPP TS 33.180 §9.4.6 and §9.4.8).
///
/// The cipher is AEAD_AES_128_GCM (RFC 7714) with key derivation rate 0. `mki` is the 32-bit
/// KFC-ID the controller signalled, carried as the SRTCP MKI. `key` and `salt` are base64 on the
/// wire (RFC 4648 §4) and exactly [`FLOOR_KEY_LEN`] octets and [`FLOOR_SALT_LEN`] (RFC 7714 §12, 96 bits) or
/// [`FLOOR_SALT_LEN_LONG`] (RFC 3711, 112 bits) octets, since the MIKEY SP policy can negotiate either. A
/// 12-octet salt is zero-extended on the right to 112 bits before the RFC 3711 AES-CM PRF, which is
/// libsrtp's behaviour. Any other length
/// is refused when the frame is read. [`std::fmt::Debug`] redacts both: key material never reaches a log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FloorKeyWire")]
pub struct FloorKey {
    pub mki: u32,
    #[serde(with = "base64::strict")]
    pub key: Vec<u8>,
    #[serde(with = "base64::strict")]
    pub salt: Vec<u8>,
}

impl std::fmt::Debug for FloorKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FloorKey")
            .field("mki", &self.mki)
            .field("key", &"<redacted>")
            .field("salt", &"<redacted>")
            .finish()
    }
}

impl zeroize::Zeroize for FloorKey {
    /// Overwrite the key and salt octets in place (length kept). The MKI is wire data and stays.
    fn zeroize(&mut self) {
        self.key.as_mut_slice().zeroize();
        self.salt.as_mut_slice().zeroize();
    }
}

/// The controller-derived key (3GPP TS 33.180 §9.4) must not linger in freed memory.
impl Drop for FloorKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl FloorKey {
    /// Check the key and salt lengths (for a key built in code rather than read from the wire).
    ///
    /// # Errors
    /// [`FloorKeyError::KeyLength`] or [`FloorKeyError::SaltLength`].
    pub fn validate(&self) -> Result<(), FloorKeyError> {
        if self.key.len() != FLOOR_KEY_LEN {
            return Err(FloorKeyError::KeyLength(self.key.len()));
        }
        if self.salt.len() != FLOOR_SALT_LEN && self.salt.len() != FLOOR_SALT_LEN_LONG {
            return Err(FloorKeyError::SaltLength(self.salt.len()));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub(crate) struct FloorKeyWire {
    pub(crate) mki: u32,
    #[serde(with = "base64::strict")]
    pub(crate) key: Vec<u8>,
    #[serde(with = "base64::strict")]
    pub(crate) salt: Vec<u8>,
}

impl FloorKeyWire {
    /// Move the decoded key and salt out, leaving the wire form empty.
    pub(crate) fn take_secrets(&mut self) -> (Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut self.key),
            std::mem::take(&mut self.salt),
        )
    }
}

/// A frame whose key fails validation must not leave the decoded octets behind.
impl Drop for FloorKeyWire {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self.key.as_mut_slice());
        zeroize::Zeroize::zeroize(self.salt.as_mut_slice());
    }
}

impl TryFrom<FloorKeyWire> for FloorKey {
    type Error = FloorKeyError;

    fn try_from(mut wire: FloorKeyWire) -> Result<Self, Self::Error> {
        let (key, salt) = wire.take_secrets();
        // A failing key is dropped here, and `Drop for FloorKey` wipes it.
        let key = Self {
            mki: wire.mki,
            key,
            salt,
        };
        key.validate()?;
        Ok(key)
    }
}

pub(crate) fn deserialize_floor_keys<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<FloorKey>, D::Error> {
    let keys = Vec::<FloorKey>::deserialize(deserializer)?;
    if keys.len() > MAX_FLOOR_KEYS {
        return Err(serde::de::Error::custom(FloorKeyError::TooMany(keys.len())));
    }
    Ok(keys)
}
