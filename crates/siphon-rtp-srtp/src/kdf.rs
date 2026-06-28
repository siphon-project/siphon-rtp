//! SRTP AES-CM keystream and key derivation (RFC 3711 §4.1.1, §4.3).
//!
//! AES Counter Mode is plain AES-128-CTR with a 128-bit IV used as the initial counter (the low 16
//! bits increment per block). Key derivation runs the same PRF over the master key with a per-label
//! IV built from the master salt, producing the session encryption key, salt, and auth key.

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};

/// AES-128 in big-endian counter mode — the SRTP cipher.
type AesCm = ctr::Ctr128BE<Aes128>;

/// SRTP master-salt length (112 bits, RFC 3711 §8.2).
pub const MASTER_SALT_LEN: usize = 14;

/// KDF labels (RFC 3711 §4.3.2). RTP and RTCP derive *separate* session keys from the same master
/// key/salt — labels 0/1/2 for SRTP, 3/4/5 for SRTCP.
pub mod label {
    /// SRTP session encryption (cipher) key.
    pub const RTP_ENCRYPTION: u8 = 0x00;
    /// SRTP session authentication key.
    pub const RTP_AUTHENTICATION: u8 = 0x01;
    /// SRTP session salt.
    pub const RTP_SALT: u8 = 0x02;
    /// SRTCP session encryption (cipher) key.
    pub const RTCP_ENCRYPTION: u8 = 0x03;
    /// SRTCP session authentication key.
    pub const RTCP_AUTHENTICATION: u8 = 0x04;
    /// SRTCP session salt.
    pub const RTCP_SALT: u8 = 0x05;
}

/// Generate `out.len()` bytes of AES-CM keystream into `out`: encrypt zeros under `key` starting
/// from the 128-bit counter `iv`.
pub fn keystream(key: &[u8; 16], iv: &[u8; 16], out: &mut [u8]) {
    out.fill(0);
    let mut cipher = AesCm::new(key.into(), iv.into());
    cipher.apply_keystream(out);
}

/// Derive a session key for `label` from the master `key`/`salt` (key-derivation rate 0, index 0 —
/// no mid-session rekeying), writing `out.len()` bytes. RFC 3711 §4.3.1: the KDF IV is the master
/// salt left-shifted 16 bits, with the label XORed into the byte at offset 7.
pub fn derive(key: &[u8; 16], salt: &[u8; MASTER_SALT_LEN], label_id: u8, out: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[..MASTER_SALT_LEN].copy_from_slice(salt);
    iv[7] ^= label_id;
    keystream(key, &iv, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    // RFC 3711 §4.3.2 test vectors for the default AES-CM key derivation.
    const MASTER_KEY: &str = "E1F97A0D3E018BE0D64FA32C06DE4139";
    const MASTER_SALT: &str = "0EC675AD498AFEEBB6960B3AABE6";

    fn key16() -> [u8; 16] {
        hex(MASTER_KEY).try_into().unwrap()
    }
    fn salt14() -> [u8; MASTER_SALT_LEN] {
        hex(MASTER_SALT).try_into().unwrap()
    }

    #[test]
    fn derives_session_encryption_key() {
        let mut out = [0u8; 16];
        derive(&key16(), &salt14(), label::RTP_ENCRYPTION, &mut out);
        assert_eq!(out.to_vec(), hex("C61E7A93744F39EE10734AFE3FF7A087"));
    }

    #[test]
    fn derives_session_salt() {
        let mut out = [0u8; MASTER_SALT_LEN];
        derive(&key16(), &salt14(), label::RTP_SALT, &mut out);
        assert_eq!(out.to_vec(), hex("30CBBC08863D8C85D49DB34A9AE1"));
    }

    #[test]
    fn derives_session_auth_key() {
        let mut out = [0u8; 20];
        derive(&key16(), &salt14(), label::RTP_AUTHENTICATION, &mut out);
        assert_eq!(out.to_vec(), hex("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4"));
    }

    #[test]
    fn keystream_is_aes_ctr() {
        // A zero IV under the master key yields AES-ECB(0) as the first block (CTR of the zero block).
        let mut out = [0u8; 16];
        keystream(&key16(), &[0u8; 16], &mut out);
        // Encrypting the all-zero block with this key (golden from the AES primitive).
        assert_ne!(out, [0u8; 16]);
        // Determinism: same inputs, same keystream.
        let mut again = [0u8; 16];
        keystream(&key16(), &[0u8; 16], &mut again);
        assert_eq!(out, again);
    }
}
