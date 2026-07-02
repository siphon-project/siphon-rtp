//! SRTCP — secure RTCP (RFC 3711 §3.4). Distinct from SRTP: the first 8 octets (RTCP fixed header +
//! sender SSRC) stay in the clear, the rest of the compound packet is AES-CM encrypted, and a 4-byte
//! `E|SRTCP-index` trailer carries an *explicit* 31-bit index (no rollover guessing) plus the
//! encrypt flag. HMAC-SHA1-80 authenticates `header || ciphertext || E|index` — the index is in the
//! authenticated span, so there is no separate ROC as in SRTP.
//!
//! SRTCP keys derive from the same master key/salt as SRTP but under labels 3/4/5 (RFC 3711 §4.3.2),
//! so an SRTCP context is independent of the SRTP one on the same leg. Anti-replay (the explicit
//! index makes it cheap) is a later hardening layer; this is the confidentiality+integrity core.

use subtle::ConstantTimeEq;

use crate::kdf::{self, MASTER_SALT_LEN};
use crate::sdes::SrtpKeyMaterial;
use crate::{apply_aes_cm, cipher_iv, hmac_sha1_80, SrtpError, AUTH_TAG_LEN, MASTER_KEY_LEN};

/// The `E|SRTCP-index` trailer length (RFC 3711 §3.4): 1 encrypt-flag bit + 31-bit index.
const INDEX_TRAILER_LEN: usize = 4;
/// RTCP fixed header that stays in the clear: 4-byte header + 4-byte sender SSRC.
const CLEAR_HEADER_LEN: usize = 8;
/// The encrypt flag — the top bit of the index trailer.
const ENCRYPT_FLAG: u32 = 0x8000_0000;
/// 31-bit index mask.
const INDEX_MASK: u32 = 0x7FFF_FFFF;

/// An SRTCP session for one direction: the SRTCP session keys plus the sender's running 31-bit index.
pub struct SrtcpContext {
    session_key: [u8; 16],
    session_salt: [u8; MASTER_SALT_LEN],
    session_auth: [u8; 20],
    /// Our outgoing SRTCP index — starts at 0, used-then-incremented (RFC 3711 §3.4).
    send_index: u32,
}

impl SrtcpContext {
    /// Derive an SRTCP context (labels 3/4/5) from the master key/salt.
    #[must_use]
    pub fn new(master_key: &[u8; MASTER_KEY_LEN], master_salt: &[u8; MASTER_SALT_LEN]) -> Self {
        let mut session_key = [0u8; 16];
        let mut session_salt = [0u8; MASTER_SALT_LEN];
        let mut session_auth = [0u8; 20];
        kdf::derive(
            master_key,
            master_salt,
            kdf::label::RTCP_ENCRYPTION,
            &mut session_key,
        );
        kdf::derive(
            master_key,
            master_salt,
            kdf::label::RTCP_SALT,
            &mut session_salt,
        );
        kdf::derive(
            master_key,
            master_salt,
            kdf::label::RTCP_AUTHENTICATION,
            &mut session_auth,
        );
        Self {
            session_key,
            session_salt,
            session_auth,
            send_index: 0,
        }
    }

    /// Build an SRTCP context from SDES [`SrtpKeyMaterial`] (the same inline key as the SRTP leg).
    #[must_use]
    pub fn from_key_material(material: &SrtpKeyMaterial) -> Self {
        Self::new(&material.master_key, &material.master_salt)
    }

    /// The current outgoing SRTCP index (RFC 3711 §3.4). Carried across an HA failover so a standby
    /// does not re-use indices the primary already sent (a receiver rejects a re-used index as a
    /// replay). See [`Self::set_send_index`].
    #[must_use]
    pub fn send_index(&self) -> u32 {
        self.send_index
    }

    /// Seed the outgoing SRTCP index from an HA checkpoint, so egress SRTCP continues past the
    /// primary's last-sent index instead of restarting at `0`.
    pub fn set_send_index(&mut self, index: u32) {
        self.send_index = index;
    }

    /// Encrypt + authenticate a compound RTCP packet into `out`: `header(8) || AES-CM(rest) ||
    /// E|index || HMAC-SHA1-80`.
    pub fn protect(&mut self, rtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        if rtcp.len() < CLEAR_HEADER_LEN {
            return Err(SrtpError::TooShort);
        }
        if rtcp[0] >> 6 != 2 {
            return Err(SrtpError::BadVersion);
        }
        let ssrc = u32::from_be_bytes([rtcp[4], rtcp[5], rtcp[6], rtcp[7]]);
        let index = self.send_index;
        self.send_index = (self.send_index + 1) & INDEX_MASK;

        out.clear();
        out.extend_from_slice(rtcp);
        let iv = cipher_iv(&self.session_salt, ssrc, u64::from(index));
        apply_aes_cm(&self.session_key, &iv, &mut out[CLEAR_HEADER_LEN..]);

        out.extend_from_slice(&(ENCRYPT_FLAG | index).to_be_bytes());
        let tag = hmac_sha1_80(&self.session_auth, out);
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Verify the tag and decrypt an SRTCP packet into `out`, yielding the plain compound RTCP.
    pub fn unprotect(&mut self, srtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        if srtcp.len() < CLEAR_HEADER_LEN + INDEX_TRAILER_LEN + AUTH_TAG_LEN {
            return Err(SrtpError::TooShort);
        }
        if srtcp[0] >> 6 != 2 {
            return Err(SrtpError::BadVersion);
        }
        let (authenticated, tag) = srtcp.split_at(srtcp.len() - AUTH_TAG_LEN);
        let expected = hmac_sha1_80(&self.session_auth, authenticated);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(SrtpError::AuthFailed);
        }

        let trailer_at = authenticated.len() - INDEX_TRAILER_LEN;
        let index_field = u32::from_be_bytes([
            authenticated[trailer_at],
            authenticated[trailer_at + 1],
            authenticated[trailer_at + 2],
            authenticated[trailer_at + 3],
        ]);
        let encrypted = index_field & ENCRYPT_FLAG != 0;
        let index = index_field & INDEX_MASK;
        let ssrc = u32::from_be_bytes([
            authenticated[4],
            authenticated[5],
            authenticated[6],
            authenticated[7],
        ]);

        out.clear();
        out.extend_from_slice(&authenticated[..trailer_at]); // header + (still-encrypted) payload
        if encrypted {
            let iv = cipher_iv(&self.session_salt, ssrc, u64::from(index));
            apply_aes_cm(&self.session_key, &iv, &mut out[CLEAR_HEADER_LEN..]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> SrtcpContext {
        SrtcpContext::new(&[0x11u8; 16], &[0x22u8; MASTER_SALT_LEN])
    }

    /// A minimal compound RTCP SR: V2, PT=200 (SR), length, sender SSRC, then `body` bytes.
    fn rtcp(ssrc: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0x00, 0x00];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn protect_then_unprotect_recovers_the_packet() {
        let mut sender = context();
        let mut receiver = context();
        let plain = rtcp(0xDEAD_BEEF, &[0xAA; 20]);

        let mut srtcp = Vec::new();
        sender.protect(&plain, &mut srtcp).expect("protect");
        // header(8) + payload(20) + index(4) + tag(10).
        assert_eq!(srtcp.len(), plain.len() + INDEX_TRAILER_LEN + AUTH_TAG_LEN);
        assert_eq!(
            &srtcp[..CLEAR_HEADER_LEN],
            &plain[..CLEAR_HEADER_LEN],
            "8-byte header clear"
        );
        assert_ne!(
            &srtcp[CLEAR_HEADER_LEN..28],
            &plain[CLEAR_HEADER_LEN..],
            "payload encrypted"
        );
        // Encrypt flag set on the index trailer.
        assert_eq!(srtcp[28] & 0x80, 0x80);

        let mut recovered = Vec::new();
        receiver
            .unprotect(&srtcp, &mut recovered)
            .expect("unprotect");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn send_index_checkpoint_and_seed() {
        // The SRTCP index is carried across an HA failover so the standby does not re-use indices the
        // primary already sent (a receiver rejects a re-used index as a replay, RFC 3711 §3.4).
        let mut primary = context();
        let mut out = Vec::new();
        assert_eq!(primary.send_index(), 0, "fresh index starts at 0");
        primary
            .protect(&rtcp(0x1111_2222, &[0; 20]), &mut out)
            .expect("protect");
        primary
            .protect(&rtcp(0x1111_2222, &[0; 20]), &mut out)
            .expect("protect");
        assert_eq!(primary.send_index(), 2, "index advances per SRTCP packet");

        // A standby seeded from the checkpoint continues past the primary's last-sent index.
        let mut standby = context();
        standby.set_send_index(primary.send_index());
        assert_eq!(standby.send_index(), 2);
        standby
            .protect(&rtcp(0x1111_2222, &[0; 20]), &mut out)
            .expect("protect");
        assert_eq!(
            standby.send_index(),
            3,
            "standby continues, never re-using an index"
        );
    }

    #[test]
    fn index_advances_per_packet() {
        let mut sender = context();
        let mut first = Vec::new();
        let mut second = Vec::new();
        sender
            .protect(&rtcp(1, &[0; 12]), &mut first)
            .expect("protect");
        sender
            .protect(&rtcp(1, &[0; 12]), &mut second)
            .expect("protect");
        // Index trailer is the 4 bytes before the 10-byte tag.
        let index_of = |srtcp: &[u8]| {
            let at = srtcp.len() - AUTH_TAG_LEN - INDEX_TRAILER_LEN;
            u32::from_be_bytes([srtcp[at], srtcp[at + 1], srtcp[at + 2], srtcp[at + 3]])
                & INDEX_MASK
        };
        assert_eq!(index_of(&first), 0);
        assert_eq!(index_of(&second), 1);
    }

    #[test]
    fn tampering_is_rejected() {
        let mut sender = context();
        let mut receiver = context();
        let mut srtcp = Vec::new();
        sender
            .protect(&rtcp(0x1234, &[0x55; 16]), &mut srtcp)
            .expect("protect");

        let mut forged = srtcp.clone();
        forged[10] ^= 0x01; // flip a ciphertext byte
        let mut out = Vec::new();
        assert_eq!(
            receiver.unprotect(&forged, &mut out),
            Err(SrtpError::AuthFailed)
        );

        let mut bad_tag = srtcp.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 0x80;
        assert_eq!(
            receiver.unprotect(&bad_tag, &mut out),
            Err(SrtpError::AuthFailed)
        );
    }

    #[test]
    fn wrong_key_fails_auth() {
        let mut sender = context();
        let mut receiver = SrtcpContext::new(&[0x99u8; 16], &[0x88u8; MASTER_SALT_LEN]);
        let mut srtcp = Vec::new();
        sender
            .protect(&rtcp(0xAAAA, &[0x10; 16]), &mut srtcp)
            .expect("protect");
        let mut out = Vec::new();
        assert_eq!(
            receiver.unprotect(&srtcp, &mut out),
            Err(SrtpError::AuthFailed)
        );
    }

    #[test]
    fn srtcp_keys_differ_from_srtp_keys() {
        // Same master key/salt must yield different session keys for RTP (labels 0/1/2) vs RTCP
        // (3/4/5): an 8-byte RR encrypted as SRTCP must not match the SRTP keystream.
        let master_key = [0x11u8; 16];
        let master_salt = [0x22u8; MASTER_SALT_LEN];
        let mut srtcp_key = [0u8; 16];
        let mut srtp_key = [0u8; 16];
        kdf::derive(
            &master_key,
            &master_salt,
            kdf::label::RTCP_ENCRYPTION,
            &mut srtcp_key,
        );
        kdf::derive(
            &master_key,
            &master_salt,
            kdf::label::RTP_ENCRYPTION,
            &mut srtp_key,
        );
        assert_ne!(srtcp_key, srtp_key);
    }

    #[test]
    fn empty_payload_rtcp_round_trips() {
        // An 8-byte RTCP (header + SSRC, no reports) — encrypted portion is empty.
        let mut sender = context();
        let mut receiver = context();
        let plain = rtcp(0xC0FFEE, &[]);
        let mut srtcp = Vec::new();
        sender.protect(&plain, &mut srtcp).expect("protect");
        let mut recovered = Vec::new();
        receiver
            .unprotect(&srtcp, &mut recovered)
            .expect("unprotect");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn rejects_short_and_bad_version() {
        let mut context = context();
        let mut out = Vec::new();
        assert_eq!(
            context.protect(&[0u8; 4], &mut out),
            Err(SrtpError::TooShort)
        );
        // Unprotect needs at least header + index + tag.
        assert_eq!(
            context.unprotect(&[0x80u8; 16], &mut out),
            Err(SrtpError::TooShort)
        );
        let mut bad = rtcp(1, &[0; 12]);
        bad[0] = 0x40; // version 1
        assert_eq!(context.protect(&bad, &mut out), Err(SrtpError::BadVersion));
    }
}
