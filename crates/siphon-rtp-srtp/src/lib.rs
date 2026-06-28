//! Pure-Rust SRTP (RFC 3711) for the SDES bridge legs — `AES_CM_128_HMAC_SHA1_80`.
//!
//! [`SrtpContext`] holds the session keys derived from a master key/salt and protects/unprotects
//! RTP packets: AES Counter-Mode encrypts the payload (header in the clear), HMAC-SHA1 truncated to
//! 80 bits authenticates `header || ciphertext || ROC`. The 48-bit packet index (ROC·2¹⁶ + seq) is
//! tracked per SSRC with the RFC 3711 §3.3.1 rollover estimation. Crypto is RustCrypto (pure Rust,
//! zero C). Anti-replay is a later hardening layer; today this is the confidentiality+integrity core.
#![forbid(unsafe_code)]

use std::collections::HashMap;

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub mod kdf;
pub mod sdes;

use kdf::MASTER_SALT_LEN;
use sdes::SrtpKeyMaterial;

type AesCm = ctr::Ctr128BE<Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// HMAC-SHA1-80 authentication tag length (RFC 3711, the default profile).
pub const AUTH_TAG_LEN: usize = 10;
/// Master key length for `AES_CM_128_HMAC_SHA1_80`.
pub const MASTER_KEY_LEN: usize = 16;

/// Errors from SRTP protect/unprotect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SrtpError {
    /// The packet is shorter than a 12-byte RTP header (+ auth tag, for unprotect).
    #[error("packet too short")]
    TooShort,
    /// The RTP version field was not 2.
    #[error("unsupported RTP version")]
    BadVersion,
    /// The authentication tag did not verify (forged/corrupt/wrong key).
    #[error("authentication failed")]
    AuthFailed,
}

/// Per-SSRC rollover state.
#[derive(Default, Clone, Copy)]
struct StreamState {
    roc: u32,
    highest_seq: Option<u16>,
}

impl StreamState {
    /// The 48-bit packet index for `seq` and the 32-bit ROC to authenticate with (RFC 3711 §3.3.1),
    /// advancing the rollover state for in-order/wrapping packets.
    fn index_for(&mut self, seq: u16) -> (u64, u32) {
        let Some(highest) = self.highest_seq else {
            self.highest_seq = Some(seq);
            return (u64::from(seq), self.roc);
        };
        let roc = self.roc;
        let v = if highest < 32_768 {
            if i32::from(seq) - i32::from(highest) > 32_768 {
                roc.wrapping_sub(1) // old packet from before the previous wrap
            } else {
                roc
            }
        } else if i32::from(highest) - i32::from(seq) > 32_768 {
            roc.wrapping_add(1) // seq wrapped forward
        } else {
            roc
        };
        // Advance state only for the current-or-next rollover (never for an old packet).
        if v == roc && seq > highest {
            self.highest_seq = Some(seq);
        } else if v == roc.wrapping_add(1) {
            self.roc = v;
            self.highest_seq = Some(seq);
        }
        ((u64::from(v) << 16) | u64::from(seq), v)
    }
}

/// An SRTP session: the derived session keys plus per-SSRC rollover state.
pub struct SrtpContext {
    session_key: [u8; 16],
    session_salt: [u8; MASTER_SALT_LEN],
    session_auth: [u8; 20],
    streams: HashMap<u32, StreamState>,
}

impl SrtpContext {
    /// Build a context for `AES_CM_128_HMAC_SHA1_80` from a 16-byte master key and 14-byte master
    /// salt (as carried in an SDES `a=crypto` inline key, after base64-decoding: 16 + 14 = 30 bytes).
    #[must_use]
    pub fn new(master_key: &[u8; MASTER_KEY_LEN], master_salt: &[u8; MASTER_SALT_LEN]) -> Self {
        let mut session_key = [0u8; 16];
        let mut session_salt = [0u8; MASTER_SALT_LEN];
        let mut session_auth = [0u8; 20];
        kdf::derive(master_key, master_salt, kdf::label::RTP_ENCRYPTION, &mut session_key);
        kdf::derive(master_key, master_salt, kdf::label::RTP_SALT, &mut session_salt);
        kdf::derive(master_key, master_salt, kdf::label::RTP_AUTHENTICATION, &mut session_auth);
        Self {
            session_key,
            session_salt,
            session_auth,
            streams: HashMap::new(),
        }
    }

    /// Build a context from SDES [`SrtpKeyMaterial`] (a parsed/generated `a=crypto` inline key).
    #[must_use]
    pub fn from_key_material(material: &SrtpKeyMaterial) -> Self {
        Self::new(&material.master_key, &material.master_salt)
    }

    /// Encrypt + authenticate an RTP packet into `out` (cleared first): `header || AES-CM(payload) ||
    /// HMAC-SHA1-80`.
    pub fn protect(&mut self, rtp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        let (header_len, ssrc, seq) = parse_rtp_header(rtp)?;
        let (index, roc) = self.streams.entry(ssrc).or_default().index_for(seq);

        out.clear();
        out.extend_from_slice(rtp);
        let iv = cipher_iv(&self.session_salt, ssrc, index);
        AesCm::new(&self.session_key.into(), &iv.into()).apply_keystream(&mut out[header_len..]);

        let tag = auth_tag(&self.session_auth, out, roc);
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Verify the tag and decrypt an SRTP packet into `out` (cleared first), yielding the plain RTP.
    pub fn unprotect(&mut self, srtp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        if srtp.len() < 12 + AUTH_TAG_LEN {
            return Err(SrtpError::TooShort);
        }
        let (authenticated, tag) = srtp.split_at(srtp.len() - AUTH_TAG_LEN);
        let (header_len, ssrc, seq) = parse_rtp_header(authenticated)?;

        // Estimate the index on a *copy* of the stream state so a failed auth never advances it.
        let mut state = self.streams.get(&ssrc).copied().unwrap_or_default();
        let (index, roc) = state.index_for(seq);

        let expected = auth_tag(&self.session_auth, authenticated, roc);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(SrtpError::AuthFailed);
        }
        self.streams.insert(ssrc, state); // commit rollover only after auth succeeds

        out.clear();
        out.extend_from_slice(authenticated);
        let iv = cipher_iv(&self.session_salt, ssrc, index);
        AesCm::new(&self.session_key.into(), &iv.into()).apply_keystream(&mut out[header_len..]);
        Ok(())
    }
}

/// The AES-CM IV for one packet (RFC 3711 §4.1.1): `session_salt·2¹⁶ ⊕ SSRC·2⁶⁴ ⊕ index·2¹⁶`.
fn cipher_iv(salt: &[u8; MASTER_SALT_LEN], ssrc: u32, index: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..MASTER_SALT_LEN].copy_from_slice(salt);
    for (offset, byte) in ssrc.to_be_bytes().iter().enumerate() {
        iv[4 + offset] ^= byte;
    }
    let index_bytes = (index & 0xFFFF_FFFF_FFFF).to_be_bytes(); // low 48 bits in bytes 2..8
    for offset in 0..6 {
        iv[8 + offset] ^= index_bytes[2 + offset];
    }
    iv
}

/// HMAC-SHA1 over `data || ROC`, truncated to 80 bits.
fn auth_tag(key: &[u8; 20], data: &[u8], roc: u32) -> [u8; AUTH_TAG_LEN] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.update(&roc.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&full[..AUTH_TAG_LEN]);
    tag
}

/// Parse just enough of an RTP header to find the encrypted-payload offset, SSRC, and sequence.
fn parse_rtp_header(packet: &[u8]) -> Result<(usize, u32, u16), SrtpError> {
    if packet.len() < 12 {
        return Err(SrtpError::TooShort);
    }
    if packet[0] >> 6 != 2 {
        return Err(SrtpError::BadVersion);
    }
    let csrc_count = (packet[0] & 0x0F) as usize;
    let seq = u16::from_be_bytes([packet[2], packet[3]]);
    let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

    let mut header_len = 12 + 4 * csrc_count;
    if packet[0] & 0x10 != 0 {
        // Extension: 4-byte header (profile + length-in-words) then length·4 bytes.
        if packet.len() < header_len + 4 {
            return Err(SrtpError::TooShort);
        }
        let words = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]) as usize;
        header_len += 4 + words * 4;
    }
    if packet.len() < header_len {
        return Err(SrtpError::TooShort);
    }
    Ok((header_len, ssrc, seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> SrtpContext {
        let key = [0x11u8; 16];
        let salt = [0x22u8; MASTER_SALT_LEN];
        SrtpContext::new(&key, &salt)
    }

    /// A G.711-ish RTP packet: V2, PT0, given seq/ssrc, 16-byte payload.
    fn rtp(seq: u16, ssrc: u32, payload: u8) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]); // timestamp
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[payload; 16]);
        packet
    }

    #[test]
    fn protect_then_unprotect_recovers_the_packet() {
        let mut sender = context();
        let mut receiver = context();
        let plain = rtp(1000, 0xDEAD_BEEF, 0xAB);

        let mut srtp = Vec::new();
        sender.protect(&plain, &mut srtp).expect("protect");
        // Encrypted + 10-byte tag, header preserved, payload hidden.
        assert_eq!(srtp.len(), plain.len() + AUTH_TAG_LEN);
        assert_eq!(&srtp[..12], &plain[..12], "header in the clear");
        assert_ne!(&srtp[12..28], &plain[12..28], "payload encrypted");

        let mut recovered = Vec::new();
        receiver.unprotect(&srtp, &mut recovered).expect("unprotect");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn tampering_is_rejected() {
        let mut sender = context();
        let mut receiver = context();
        let mut srtp = Vec::new();
        sender.protect(&rtp(1, 0x1234, 0x55), &mut srtp).expect("protect");

        // Flip a ciphertext byte → auth must fail.
        let mut forged = srtp.clone();
        forged[14] ^= 0x01;
        let mut out = Vec::new();
        assert_eq!(receiver.unprotect(&forged, &mut out), Err(SrtpError::AuthFailed));

        // Flip a tag byte → auth must fail.
        let mut bad_tag = srtp.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 0x80;
        assert_eq!(receiver.unprotect(&bad_tag, &mut out), Err(SrtpError::AuthFailed));
    }

    #[test]
    fn wrong_key_fails_auth() {
        let mut sender = context();
        let mut receiver = SrtpContext::new(&[0x99u8; 16], &[0x88u8; MASTER_SALT_LEN]);
        let mut srtp = Vec::new();
        sender.protect(&rtp(5, 0xAAAA, 0x10), &mut srtp).expect("protect");
        let mut out = Vec::new();
        assert_eq!(receiver.unprotect(&srtp, &mut out), Err(SrtpError::AuthFailed));
    }

    #[test]
    fn sequence_rollover_keeps_decryptable() {
        let mut sender = context();
        let mut receiver = context();
        // Cross the 16-bit sequence wrap (65534, 65535, 0, 1) on one SSRC.
        for seq in [65_534u16, 65_535, 0, 1] {
            let plain = rtp(seq, 0xC0FFEE, seq as u8);
            let mut srtp = Vec::new();
            sender.protect(&plain, &mut srtp).expect("protect");
            let mut recovered = Vec::new();
            receiver.unprotect(&srtp, &mut recovered).expect("unprotect across wrap");
            assert_eq!(recovered, plain, "seq {seq}");
        }
    }

    #[test]
    fn distinct_ssrcs_are_independent() {
        let mut sender = context();
        let mut receiver = context();
        for ssrc in [0x1111_1111u32, 0x2222_2222] {
            let plain = rtp(7, ssrc, 0x33);
            let mut srtp = Vec::new();
            sender.protect(&plain, &mut srtp).expect("protect");
            let mut recovered = Vec::new();
            receiver.unprotect(&srtp, &mut recovered).expect("unprotect");
            assert_eq!(recovered, plain);
        }
    }

    #[test]
    fn rejects_short_and_bad_version() {
        let mut context = context();
        let mut out = Vec::new();
        assert_eq!(context.protect(&[0u8; 8], &mut out), Err(SrtpError::TooShort));
        let mut bad = rtp(1, 1, 1);
        bad[0] = 0x40; // version 1
        assert_eq!(context.protect(&bad, &mut out), Err(SrtpError::BadVersion));
    }
}
