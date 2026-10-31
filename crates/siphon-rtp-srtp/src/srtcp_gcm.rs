//! SRTCP with `AEAD_AES_128_GCM` (RFC 7714 §9), the profile 3GPP TS 33.180 §9.4.8 mandates for MCPTT
//! floor control (hop by hop). Distinct from [`crate::srtcp`] (AES-CM + HMAC-SHA1): GCM has no
//! separate authentication tag field and the 16-octet tag sits *before* the trailer.
//!
//! Wire layout (RFC 7714 §9.2, §9.3, §17):
//!
//! ```text
//! E=1:  header(8) || AES-GCM ciphertext || tag(16) || E|index(4) || MKI(4)
//! E=0:  header(8) || rest of compound RTCP (clear) || tag(16) || E|index(4) || MKI(4)
//! ```
//!
//! * The first 8 octets (V/P/RC, PT, length, sender SSRC) always stay in the clear and are AAD.
//! * AAD with E=1 is `header(8) || E|index(4)`; with E=0 it is the whole compound packet followed
//!   by `E|index` (§9.3), and there is no plaintext, so the cipher is the tag alone.
//! * IV (§9.1): `00 00 || SSRC(4) || 00 00 || 0|index(31 bits)` XOR the 12-octet session salt.
//! * The MKI (the KFC-ID in TS 33.180 §9.4.7) is raw data: it is neither encrypted nor authenticated
//!   (§9.2), so it is only used to select the key; a wrong MKI at worst selects a key whose tag then
//!   fails.
//! * Session key (16) and salt (12) come from the RFC 3711 §4.3 AES-CM PRF at key derivation
//!   rate 0 with the SRTCP labels (RFC 7714 §11; TS 33.180 §9.4.8).
//! * Anti-replay (RFC 3711 §3.3.2) over the explicit 31-bit index, recorded only after the tag
//!   verified. The send index never wraps: RFC 7714 §9.4 forbids reusing an IV under one key, so at
//!   `2^31 - 1` protect refuses until the keys are replaced or the index is reseeded.

use aes::Aes128;
use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::AesGcm;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::kdf::{self, MASTER_SALT_LEN};
use crate::{ReplayWindow, SrtpError, MASTER_KEY_LEN};

/// `AEAD_AES_128_GCM` with the 12-octet IV and 16-octet tag RFC 7714 §5 fixes.
type Aes128Gcm = AesGcm<Aes128, U12, U16>;

/// RTCP fixed header that stays in the clear: 4-octet header + 4-octet sender SSRC (RFC 3550 §6.1).
const CLEAR_HEADER_LEN: usize = 8;
/// AEAD authentication tag length (RFC 7714 §5, Table 1).
pub const GCM_TAG_LEN: usize = 16;
/// The `E|SRTCP-index` word length (RFC 7714 §9.2 "ESRTCP word").
const ESRTCP_LEN: usize = 4;
/// The MKI length TS 33.180 §9.4.7 fixes for floor control (the KFC-ID).
pub const MKI_LEN: usize = 4;
/// GCM session salt length (RFC 7714 §12, Table 1: 96 bits).
const SESSION_SALT_LEN: usize = 12;
/// Encrypt flag, the top bit of the ESRTCP word.
const ENCRYPT_FLAG: u32 = 0x8000_0000;
/// 31-bit SRTCP index mask.
const INDEX_MASK: u32 = 0x7FFF_FFFF;
/// The last index a sender may use: the index must not cycle back (RFC 7714 §9.4), so `2^31 - 1`
/// is the final value and the counter then stops instead of wrapping.
const LAST_INDEX: u32 = INDEX_MASK;
/// The largest SRTCP index a sender may use (RFC 7714 §9.4: the 31-bit index never wraps).
pub const MAX_SEND_INDEX: u32 = LAST_INDEX;
/// Keys held at once: the current one plus its predecessor for rekey overlap.
pub const MAX_KEYS: usize = 2;
/// Smallest valid packet: header, tag, ESRTCP word, MKI (empty plaintext).
const MIN_PACKET_LEN: usize = CLEAR_HEADER_LEN + GCM_TAG_LEN + ESRTCP_LEN + MKI_LEN;

/// A floor-control master key as distributed for a key id (TS 33.180 §9.4.6): the MKI that
/// names it on the wire plus the RFC 3711 master key and master salt the session keys derive from.
#[derive(Clone, PartialEq, Eq)]
pub struct FloorMasterKey {
    /// The 4-octet MKI (KFC-ID) carried after the ESRTCP word.
    pub mki: u32,
    /// 128-bit master key.
    pub master_key: [u8; MASTER_KEY_LEN],
    /// 112-bit master salt (RFC 3711 §4.3.1), as carried by MIKEY.
    pub master_salt: [u8; MASTER_SALT_LEN],
}

impl FloorMasterKey {
    /// Build a key from a 96-bit master salt (RFC 7714 §12, Table 1), zero-extended on the right to
    /// the 112 bits the RFC 3711 §4.3.1 PRF IV is defined over.
    #[must_use]
    pub fn from_salt_96(
        mki: u32,
        master_key: [u8; MASTER_KEY_LEN],
        master_salt: &[u8; SESSION_SALT_LEN],
    ) -> Self {
        let mut padded = [0u8; MASTER_SALT_LEN];
        padded[..SESSION_SALT_LEN].copy_from_slice(master_salt);
        Self {
            mki,
            master_key,
            master_salt: padded,
        }
    }
}

impl Zeroize for FloorMasterKey {
    /// Overwrite the master key and salt with zeros. The MKI is wire data (RFC 3711 §3.1) and stays.
    fn zeroize(&mut self) {
        self.master_key.zeroize();
        self.master_salt.zeroize();
    }
}

/// A master key never outlives its owner in memory (3GPP TS 33.180 §9.4: the keys are
/// controller-derived secrets). Every clone wipes itself.
impl Drop for FloorMasterKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for FloorMasterKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        formatter
            .debug_struct("FloorMasterKey")
            .field("mki", &self.mki)
            .finish_non_exhaustive()
    }
}

/// One GCM session: the expanded cipher plus the session salt. MKI-free; the key ring adds and
/// strips the MKI.
///
/// Wiping: the `aes` crate's `zeroize` feature (enabled in this crate's manifest) makes the expanded
/// AES round keys inside `cipher` wipe themselves on drop, and the GHASH subkey is zeroized while the
/// `aes-gcm` `zeroize` feature builds the cipher. The session salt is wiped by the `Drop` below.
struct GcmSession {
    cipher: Aes128Gcm,
    salt: [u8; SESSION_SALT_LEN],
}

impl Zeroize for GcmSession {
    /// Wipe the session salt. The cipher wipes itself on drop (see the type docs).
    fn zeroize(&mut self) {
        self.salt.zeroize();
    }
}

impl Drop for GcmSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GcmSession {
    fn from_session_keys(key: &[u8; 16], salt: &[u8; SESSION_SALT_LEN]) -> Self {
        Self {
            cipher: Aes128Gcm::new(GenericArray::from_slice(key)),
            salt: *salt,
        }
    }

    /// RFC 3711 §4.3 PRF at rate 0, SRTCP labels 3 (key) and 5 (salt).
    fn derive(master: &FloorMasterKey) -> Self {
        let mut key = [0u8; 16];
        let mut salt = [0u8; SESSION_SALT_LEN];
        kdf::derive(
            &master.master_key,
            &master.master_salt,
            kdf::label::RTCP_ENCRYPTION,
            &mut key,
        );
        kdf::derive(
            &master.master_key,
            &master.master_salt,
            kdf::label::RTCP_SALT,
            &mut salt,
        );
        let session = Self::from_session_keys(&key, &salt);
        // The derived session key and salt are copied into the session; wipe the temporaries.
        key.zeroize();
        salt.zeroize();
        session
    }

    /// RFC 7714 §9.1 IV.
    fn iv(&self, ssrc: u32, index: u32) -> [u8; 12] {
        let mut iv = self.salt;
        for (offset, byte) in ssrc.to_be_bytes().iter().enumerate() {
            iv[2 + offset] ^= byte;
        }
        for (offset, byte) in (index & INDEX_MASK).to_be_bytes().iter().enumerate() {
            iv[8 + offset] ^= byte;
        }
        iv
    }

    /// Protect `rtcp` into `out` as `header || cipher || tag || ESRTCP` (RFC 7714 §9.2 / §9.3).
    /// The caller has checked `rtcp.len() >= 8`.
    fn seal(
        &self,
        rtcp: &[u8],
        encrypt: bool,
        index: u32,
        out: &mut Vec<u8>,
    ) -> Result<(), SrtpError> {
        let ssrc = u32::from_be_bytes([rtcp[4], rtcp[5], rtcp[6], rtcp[7]]);
        let mut iv = self.iv(ssrc, index);
        let nonce = GenericArray::from_slice(&iv);
        let word = if encrypt { ENCRYPT_FLAG } else { 0 } | index;
        out.clear();
        out.extend_from_slice(rtcp);
        let tag = if encrypt {
            let mut aad = [0u8; CLEAR_HEADER_LEN + ESRTCP_LEN];
            aad[..CLEAR_HEADER_LEN].copy_from_slice(&rtcp[..CLEAR_HEADER_LEN]);
            aad[CLEAR_HEADER_LEN..].copy_from_slice(&word.to_be_bytes());
            self.cipher
                .encrypt_in_place_detached(nonce, &aad, &mut out[CLEAR_HEADER_LEN..])
                .map_err(|_| SrtpError::AuthFailed)
        } else {
            // §9.3: everything, then the ESRTCP word, is AAD; there is no plaintext.
            out.extend_from_slice(&word.to_be_bytes());
            let tag = self
                .cipher
                .encrypt_in_place_detached(nonce, out, &mut [])
                .map_err(|_| SrtpError::AuthFailed);
            out.truncate(out.len() - ESRTCP_LEN);
            tag
        };
        // The IV is the session salt XOR public fields, so it reveals the salt: wipe it, on the
        // error path too.
        iv.zeroize();
        let tag = tag?;
        out.extend_from_slice(&tag);
        out.extend_from_slice(&word.to_be_bytes());
        Ok(())
    }

    /// Verify and (when E=1) decrypt `body` = `header || cipher || tag || ESRTCP` into `out`.
    /// `replay` is consulted before the tag and recorded only after it verifies. The caller has
    /// checked `body.len() >= 8 + 16 + 4`.
    fn open(
        &self,
        body: &[u8],
        replay: &mut ReplayWindow,
        out: &mut Vec<u8>,
    ) -> Result<(), SrtpError> {
        let word_at = body.len() - ESRTCP_LEN;
        let word = u32::from_be_bytes([
            body[word_at],
            body[word_at + 1],
            body[word_at + 2],
            body[word_at + 3],
        ]);
        let encrypted = word & ENCRYPT_FLAG != 0;
        let index = word & INDEX_MASK;
        if replay.is_replay(u64::from(index)) {
            return Err(SrtpError::Replayed);
        }
        let tag_at = word_at - GCM_TAG_LEN;
        let tag = GenericArray::from_slice(&body[tag_at..word_at]);
        let ssrc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let mut iv = self.iv(ssrc, index);
        let nonce = GenericArray::from_slice(&iv);

        out.clear();
        out.extend_from_slice(&body[..tag_at]);
        let verified = if encrypted {
            let mut aad = [0u8; CLEAR_HEADER_LEN + ESRTCP_LEN];
            aad[..CLEAR_HEADER_LEN].copy_from_slice(&body[..CLEAR_HEADER_LEN]);
            aad[CLEAR_HEADER_LEN..].copy_from_slice(&word.to_be_bytes());
            self.cipher
                .decrypt_in_place_detached(nonce, &aad, &mut out[CLEAR_HEADER_LEN..], tag)
        } else {
            out.extend_from_slice(&word.to_be_bytes());
            let result = self
                .cipher
                .decrypt_in_place_detached(nonce, out, &mut [], tag);
            out.truncate(out.len() - ESRTCP_LEN);
            result
        };
        // The IV is the session salt XOR public fields, so it reveals the salt: wipe it.
        iv.zeroize();
        if verified.is_err() {
            out.clear();
            return Err(SrtpError::AuthFailed);
        }
        replay.record(u64::from(index));
        Ok(())
    }
}

struct KeyEntry {
    master: FloorMasterKey,
    session: GcmSession,
    replay: ReplayWindow,
}

impl Zeroize for KeyEntry {
    /// Wipe both stored copies of the key: the master key and salt, and the derived session salt.
    fn zeroize(&mut self) {
        self.master.zeroize();
        self.session.zeroize();
    }
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        let mki = self.master.mki;
        self.zeroize();
        #[cfg(test)]
        record_wiped(mki, self);
        #[cfg(not(test))]
        let _ = mki;
    }
}

// Test hook: the MKI of every `KeyEntry` dropped on this thread, with whether all of its stored
// secrets were zero after the wipe. Freed memory cannot be inspected, so the drop reports it.
#[cfg(test)]
thread_local! {
    static WIPED: std::cell::RefCell<Vec<(u32, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_wiped(mki: u32, entry: &KeyEntry) {
    let all_zero = entry.master.master_key == [0u8; 16]
        && entry.master.master_salt == [0u8; MASTER_SALT_LEN]
        && entry.session.salt == [0u8; SESSION_SALT_LEN];
    WIPED.with(|log| log.borrow_mut().push((mki, all_zero)));
}

impl KeyEntry {
    fn new(master: FloorMasterKey) -> Self {
        Self {
            session: GcmSession::derive(&master),
            master,
            replay: ReplayWindow::default(),
        }
    }

    /// Same MKI and same key material: the entry (and its replay state) may be kept.
    fn is_same_key(&self, other: &FloorMasterKey) -> bool {
        let material_equal = self.master.master_key.ct_eq(&other.master_key).unwrap_u8()
            & self
                .master
                .master_salt
                .ct_eq(&other.master_salt)
                .unwrap_u8();
        self.master.mki == other.mki && material_equal == 1
    }
}

/// An SRTCP `AEAD_AES_128_GCM` endpoint: a set of at most [`MAX_KEYS`] master keys selected by MKI
/// for receiving, the newest of which protects outgoing packets, plus the 31-bit send index.
pub struct SrtcpGcmContext {
    /// Oldest first; the last entry is the sending key.
    keys: Vec<KeyEntry>,
    send_index: u32,
    /// True once the final index was used; protect refuses until it is reseeded (RFC 7714 §9.4).
    exhausted: bool,
}

impl SrtcpGcmContext {
    /// Build a context from `keys`; the last one protects outgoing packets. More than
    /// [`MAX_KEYS`] keeps the last [`MAX_KEYS`]. Errors with [`SrtpError::NoKeys`] for an empty
    /// slice and [`SrtpError::DuplicateMki`] when two keys share an MKI.
    pub fn new(keys: &[FloorMasterKey]) -> Result<Self, SrtpError> {
        let mut context = Self {
            keys: Vec::with_capacity(MAX_KEYS),
            send_index: 0,
            exhausted: false,
        };
        context.replace_keys(keys)?;
        Ok(context)
    }

    /// Replace the whole key set (same rules as [`Self::new`]). Keys that were already present with
    /// identical material keep their replay state; every other prior key is dropped together with
    /// its replay state. The send index is kept: it only ever moves forward, so a new key never
    /// sees a reused (key, index) pair either. On error the existing set is untouched.
    pub fn replace_keys(&mut self, keys: &[FloorMasterKey]) -> Result<(), SrtpError> {
        let kept = &keys[keys.len().saturating_sub(MAX_KEYS)..];
        if kept.is_empty() {
            return Err(SrtpError::NoKeys);
        }
        if kept.len() == 2 && kept[0].mki == kept[1].mki {
            return Err(SrtpError::DuplicateMki);
        }
        let mut next = Vec::with_capacity(MAX_KEYS);
        for master in kept {
            match self.keys.iter().position(|entry| entry.is_same_key(master)) {
                Some(position) => next.push(self.keys.swap_remove(position)),
                None => next.push(KeyEntry::new(master.clone())),
            }
        }
        self.keys = next;
        Ok(())
    }

    /// The MKI of the key that protects outgoing packets.
    #[must_use]
    pub fn sending_mki(&self) -> Option<u32> {
        self.keys.last().map(|entry| entry.master.mki)
    }

    /// The next outgoing SRTCP index. Carry it in an HA checkpoint so a standby never reuses an
    /// index (a reused (key, index) pair reuses the GCM IV, RFC 7714 §9.4).
    #[must_use]
    pub fn send_index(&self) -> u32 {
        self.send_index
    }

    /// The highest SRTCP index that authenticated under each held key, as `(mki, index)`, for an HA
    /// checkpoint. A key nothing has authenticated under is absent.
    #[must_use]
    pub fn received_indices(&self) -> Vec<(u32, u32)> {
        self.keys
            .iter()
            .filter_map(|entry| {
                let highest = u32::try_from(entry.replay.highest()?).ok()?;
                Some((entry.master.mki, highest))
            })
            .collect()
    }

    /// Resume the anti-replay state of the key `mki` from a checkpoint: `index` and everything
    /// below it count as received (RFC 3711 §3.3.2), so the standby does not accept the phone's
    /// last packets a second time. A key this context does not hold is ignored.
    pub fn resume_received(&mut self, mki: u32, index: u32) {
        if let Some(entry) = self.keys.iter_mut().find(|entry| entry.master.mki == mki) {
            entry.replay.close_at(u64::from(index & INDEX_MASK));
        }
    }

    /// Resume the outgoing index from a checkpoint (masked to 31 bits). Callers pass the value
    /// [`Self::send_index`] returned, plus any safety margin they want.
    pub fn set_send_index(&mut self, index: u32) {
        self.send_index = index & INDEX_MASK;
        self.exhausted = false;
    }

    /// Protect a compound RTCP packet with the sending key into `out`
    /// (`header || cipher || tag || E|index || MKI`). `encrypt = false` selects the
    /// authenticated-only form (E=0, RFC 7714 §9.3).
    pub fn protect(
        &mut self,
        rtcp: &[u8],
        encrypt: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), SrtpError> {
        if rtcp.len() < CLEAR_HEADER_LEN {
            return Err(SrtpError::TooShort);
        }
        if rtcp[0] >> 6 != 2 {
            return Err(SrtpError::BadVersion);
        }
        if self.exhausted {
            return Err(SrtpError::IndexExhausted);
        }
        let Some(entry) = self.keys.last() else {
            return Err(SrtpError::NoKeys);
        };
        let index = self.send_index;
        entry.session.seal(rtcp, encrypt, index, out)?;
        out.extend_from_slice(&entry.master.mki.to_be_bytes());
        if index == LAST_INDEX {
            self.exhausted = true;
        } else {
            self.send_index = index + 1;
        }
        Ok(())
    }

    /// Verify and decrypt an SRTCP packet into `out` (the plain compound RTCP). Errors:
    /// [`SrtpError::TooShort`], [`SrtpError::BadVersion`], [`SrtpError::UnknownMki`],
    /// [`SrtpError::Replayed`], [`SrtpError::AuthFailed`]. `out` is empty on error.
    pub fn unprotect(&mut self, srtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        out.clear();
        if srtcp.len() < MIN_PACKET_LEN {
            return Err(SrtpError::TooShort);
        }
        if srtcp[0] >> 6 != 2 {
            return Err(SrtpError::BadVersion);
        }
        let (body, mki_field) = srtcp.split_at(srtcp.len() - MKI_LEN);
        let mki = u32::from_be_bytes([mki_field[0], mki_field[1], mki_field[2], mki_field[3]]);
        let entry = self
            .keys
            .iter_mut()
            .find(|entry| entry.master.mki == mki)
            .ok_or(SrtpError::UnknownMki)?;
        entry.session.open(body, &mut entry.replay, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ascii");
                u8::from_str_radix(text, 16).expect("hex")
            })
            .collect()
    }

    // RFC 7714 §17 / §17.1 / §17.3 session key and salt (the vectors give them directly).
    const KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const SALT: &str = "517569642070726f2071756f";

    const PLAIN: &str = "81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61 \
                         deadbeef deadbeef deadbeef deadbeef deadbeef";
    // RFC 7714 §17.1 encrypted and tagged packet (index 0x5d4, E=1).
    const ENCRYPTED: &str =
        "81c8000d 4d617273 63e94885 dcdab67c a727d766 2f6b7e99 7ff5c0f7 6c06f32d \
         c676a5f1 730d6fda 4ce09b46 86303ded 0bb9275b c84aa458 96cf4d2f c5abf872 \
         45d9eade 800005d4";
    // RFC 7714 §17.3 tagged-only packet (index 0x5d4, E=0).
    const TAGGED: &str = "81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61 \
                          deadbeef deadbeef deadbeef deadbeef deadbeef 841dd968 3dd78ec9 2ae58790 \
                          125f62b3 000005d4";

    fn wiped() -> Vec<(u32, bool)> {
        WIPED.with(|log| log.borrow().clone())
    }

    fn clear_wiped() {
        WIPED.with(|log| log.borrow_mut().clear());
    }

    fn kat_session() -> GcmSession {
        let key: [u8; 16] = hex(KEY).try_into().expect("16");
        let salt: [u8; 12] = hex(SALT).try_into().expect("12");
        GcmSession::from_session_keys(&key, &salt)
    }

    #[test]
    fn iv_matches_rfc7714_section_17() {
        // salt XOR (00 00 SSRC 00 00 0+index) = 51 75 24 05 52 03 72 6f 20 71 70 bb
        let iv = kat_session().iv(0x4d61_7273, 0x5d4);
        assert_eq!(iv.to_vec(), hex("517524055203726f207170bb"));
    }

    #[test]
    fn seal_encrypted_matches_rfc7714_17_1() {
        let mut out = Vec::new();
        kat_session()
            .seal(&hex(PLAIN), true, 0x5d4, &mut out)
            .expect("seal");
        assert_eq!(out, hex(ENCRYPTED));
    }

    #[test]
    fn open_encrypted_matches_rfc7714_17_1() {
        let mut out = Vec::new();
        let mut replay = ReplayWindow::default();
        kat_session()
            .open(&hex(ENCRYPTED), &mut replay, &mut out)
            .expect("open");
        assert_eq!(out, hex(PLAIN));
    }

    #[test]
    fn seal_tag_only_matches_rfc7714_17_3() {
        let mut out = Vec::new();
        kat_session()
            .seal(&hex(PLAIN), false, 0x5d4, &mut out)
            .expect("seal");
        assert_eq!(out, hex(TAGGED));
    }

    #[test]
    fn open_tag_only_matches_rfc7714_17_3() {
        let mut out = Vec::new();
        let mut replay = ReplayWindow::default();
        kat_session()
            .open(&hex(TAGGED), &mut replay, &mut out)
            .expect("open");
        assert_eq!(out, hex(PLAIN));
    }

    #[test]
    fn open_rejects_tampered_tag_and_ciphertext_and_index() {
        let session = kat_session();
        for position in [10, 40, 45, 49] {
            let mut packet = hex(ENCRYPTED);
            packet[position] ^= 0x01;
            let mut out = vec![1, 2, 3];
            let mut replay = ReplayWindow::default();
            assert_eq!(
                session.open(&packet, &mut replay, &mut out),
                Err(SrtpError::AuthFailed),
                "byte {position}"
            );
            assert!(out.is_empty(), "no plaintext released on failure");
            assert!(!replay.is_replay(0x5d4), "forgery must not be recorded");
        }
        let mut packet = hex(TAGGED);
        packet[12] ^= 0x80;
        assert_eq!(
            session.open(&packet, &mut ReplayWindow::default(), &mut Vec::new()),
            Err(SrtpError::AuthFailed)
        );
    }

    #[test]
    fn open_flipping_the_encrypt_flag_fails_auth() {
        let mut packet = hex(ENCRYPTED);
        let at = packet.len() - 4;
        packet[at] &= 0x7f;
        assert_eq!(
            kat_session().open(&packet, &mut ReplayWindow::default(), &mut Vec::new()),
            Err(SrtpError::AuthFailed)
        );
    }

    // ----- key wiping -----

    #[test]
    fn zeroize_clears_master_key_and_salt() {
        let mut key = master(7, 0x11);
        key.zeroize();
        assert_eq!(key.master_key, [0u8; 16]);
        assert_eq!(key.master_salt, [0u8; MASTER_SALT_LEN]);
        assert_eq!(key.mki, 7, "the MKI is public wire data");
    }

    #[test]
    fn zeroize_clears_the_session_salt() {
        let mut session = GcmSession::derive(&master(1, 0x11));
        assert_ne!(session.salt, [0u8; SESSION_SALT_LEN]);
        session.zeroize();
        assert_eq!(session.salt, [0u8; SESSION_SALT_LEN]);
    }

    #[test]
    fn zeroize_clears_every_stored_copy_in_a_key_entry() {
        let mut entry = KeyEntry::new(master(1, 0x11));
        entry.zeroize();
        assert_eq!(entry.master.master_key, [0u8; 16]);
        assert_eq!(entry.master.master_salt, [0u8; MASTER_SALT_LEN]);
        assert_eq!(entry.session.salt, [0u8; SESSION_SALT_LEN]);
    }

    #[test]
    fn dropping_a_key_entry_wipes_it_first() {
        clear_wiped();
        drop(KeyEntry::new(master(0x42, 0x11)));
        assert_eq!(wiped(), vec![(0x42, true)]);
    }

    #[test]
    fn replace_keys_past_the_cap_wipes_the_evicted_key() {
        let mut context = SrtcpGcmContext::new(&[master(1, 0x11), master(2, 0x22)]).expect("ctx");
        clear_wiped();
        context
            .replace_keys(&[master(1, 0x11), master(2, 0x22), master(3, 0x33)])
            .expect("replace");
        // Three offered, newest two kept: key 1 is evicted and wiped, key 2 survives as is.
        assert_eq!(wiped(), vec![(1, true)]);
        assert_eq!(context.sending_mki(), Some(3));
        clear_wiped();
        context
            .replace_keys(&[master(3, 0x33), master(4, 0x44)])
            .expect("replace");
        assert_eq!(wiped(), vec![(2, true)]);
    }

    #[test]
    fn dropping_a_context_wipes_every_key() {
        let context = SrtcpGcmContext::new(&[master(1, 0x11), master(2, 0x22)]).expect("ctx");
        clear_wiped();
        drop(context);
        let mut log = wiped();
        log.sort_unstable();
        assert_eq!(log, vec![(1, true), (2, true)]);
    }

    #[test]
    fn debug_still_redacts_key_material() {
        let text = format!("{:?}", master(5, 0xAB));
        assert!(text.contains("mki"));
        assert!(!text.contains("171"), "0xAB as decimal must not appear");
        assert!(!text.to_lowercase().contains("ab, ab"));
        assert!(!text.contains("master_key"));
        assert!(!text.contains("master_salt"));
    }

    // ----- key ring -----

    fn master(mki: u32, seed: u8) -> FloorMasterKey {
        FloorMasterKey {
            mki,
            master_key: [seed; 16],
            master_salt: [seed ^ 0x5a; MASTER_SALT_LEN],
        }
    }

    fn rtcp(ssrc: u32) -> Vec<u8> {
        let mut packet = hex("81c8000d");
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0xAB; 24]);
        packet
    }

    #[test]
    fn derivation_uses_the_srtcp_labels() {
        let key = master(1, 0x11);
        let session = GcmSession::derive(&key);
        let mut expected_key = [0u8; 16];
        kdf::derive(&key.master_key, &key.master_salt, 0x03, &mut expected_key);
        let mut expected_salt = [0u8; 12];
        kdf::derive(&key.master_key, &key.master_salt, 0x05, &mut expected_salt);
        assert_eq!(session.salt, expected_salt);
        let reference = GcmSession::from_session_keys(&expected_key, &expected_salt);
        let (mut left, mut right) = (Vec::new(), Vec::new());
        session.seal(&rtcp(7), true, 3, &mut left).expect("seal");
        reference.seal(&rtcp(7), true, 3, &mut right).expect("seal");
        assert_eq!(left, right);
    }

    #[test]
    fn ring_roundtrips_encrypted_and_tag_only_with_mki_on_the_wire() {
        let mut sender = SrtcpGcmContext::new(&[master(0xCAFE_0001, 0x11)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(0xCAFE_0001, 0x11)]).expect("ctx");
        let plain = rtcp(0x0102_0304);
        for encrypt in [true, false] {
            let (mut wire, mut out) = (Vec::new(), Vec::new());
            sender.protect(&plain, encrypt, &mut wire).expect("protect");
            assert_eq!(wire.len(), plain.len() + 16 + 4 + 4);
            assert_eq!(wire[wire.len() - 4..], 0xCAFE_0001u32.to_be_bytes());
            assert_eq!(wire[plain.len() + 16] & 0x80 != 0, encrypt);
            assert_eq!(wire[..8], plain[..8]);
            assert_eq!(wire[8..plain.len()] == plain[8..], !encrypt);
            receiver.unprotect(&wire, &mut out).expect("unprotect");
            assert_eq!(out, plain);
        }
        assert_eq!(sender.send_index(), 2);
    }

    #[test]
    fn ring_wire_equals_session_output_plus_mki() {
        let key = master(9, 0x33);
        let mut context = SrtcpGcmContext::new(std::slice::from_ref(&key)).expect("ctx");
        let (mut wire, mut inner) = (Vec::new(), Vec::new());
        context.protect(&rtcp(5), true, &mut wire).expect("protect");
        GcmSession::derive(&key)
            .seal(&rtcp(5), true, 0, &mut inner)
            .expect("seal");
        inner.extend_from_slice(&9u32.to_be_bytes());
        assert_eq!(wire, inner);
    }

    #[test]
    fn rejects_replay_wrong_mki_truncation_and_bad_version() {
        let mut sender = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender.protect(&rtcp(1), true, &mut wire).expect("protect");
        receiver.unprotect(&wire, &mut out).expect("first");
        assert_eq!(
            receiver.unprotect(&wire, &mut out),
            Err(SrtpError::Replayed)
        );

        let mut other_mki = wire.clone();
        let last = other_mki.len() - 1;
        other_mki[last] ^= 0xFF;
        assert_eq!(
            receiver.unprotect(&other_mki, &mut out),
            Err(SrtpError::UnknownMki)
        );

        for length in [0, 7, 8, 31, MIN_PACKET_LEN - 1] {
            assert_eq!(
                receiver.unprotect(&wire[..length], &mut out),
                Err(SrtpError::TooShort)
            );
        }
        let mut bad_version = wire.clone();
        bad_version[0] = 0x40;
        assert_eq!(
            receiver.unprotect(&bad_version, &mut out),
            Err(SrtpError::BadVersion)
        );
        // Truncated by one byte: the MKI/ESRTCP alignment shifts, which must fail, not panic.
        assert!(receiver
            .unprotect(&wire[..wire.len() - 1], &mut out)
            .is_err());
    }

    #[test]
    fn forged_packet_does_not_advance_the_replay_window() {
        let mut sender = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender.protect(&rtcp(1), true, &mut wire).expect("protect");
        let mut forged = wire.clone();
        forged[10] ^= 1;
        assert_eq!(
            receiver.unprotect(&forged, &mut out),
            Err(SrtpError::AuthFailed)
        );
        receiver
            .unprotect(&wire, &mut out)
            .expect("genuine after forgery");
    }

    #[test]
    fn a_resumed_receiver_refuses_the_indices_the_checkpoint_had_seen() {
        let mut sender = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        let mut primary = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        let (mut out, mut plain) = (Vec::new(), Vec::new());
        let mut wires = Vec::new();
        for _ in 0..3 {
            sender.protect(&rtcp(1), true, &mut out).expect("protect");
            wires.push(out.clone());
        }
        // Only the first and the third arrive: the second stays a gap below the highest.
        primary.unprotect(&wires[0], &mut plain).expect("first");
        primary.unprotect(&wires[2], &mut plain).expect("third");
        assert_eq!(primary.received_indices(), vec![(1, 2)]);

        let mut standby = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        for (mki, index) in primary.received_indices() {
            standby.resume_received(mki, index);
        }
        standby.resume_received(99, 7); // a key it does not hold is ignored
        for wire in &wires {
            assert_eq!(
                standby.unprotect(wire, &mut plain),
                Err(SrtpError::Replayed),
                "nothing at or below the checkpointed highest is accepted again"
            );
        }
        sender.protect(&rtcp(1), true, &mut out).expect("fourth");
        standby.unprotect(&out, &mut plain).expect("a newer index");
    }

    #[test]
    fn wrong_key_fails_auth() {
        let mut sender = SrtcpGcmContext::new(&[master(1, 0x11)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(1, 0x12)]).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender.protect(&rtcp(1), true, &mut wire).expect("protect");
        assert_eq!(
            receiver.unprotect(&wire, &mut out),
            Err(SrtpError::AuthFailed)
        );
    }

    #[test]
    fn rekey_keeps_previous_key_and_drops_the_oldest_on_the_third() {
        let (one, two, three) = (master(1, 0x11), master(2, 0x22), master(3, 0x33));
        let mut old_sender = SrtcpGcmContext::new(std::slice::from_ref(&one)).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(std::slice::from_ref(&one)).expect("ctx");
        let (mut wire_one, mut out) = (Vec::new(), Vec::new());
        old_sender
            .protect(&rtcp(1), true, &mut wire_one)
            .expect("protect");

        receiver
            .replace_keys(&[one.clone(), two.clone()])
            .expect("rekey");
        assert_eq!(receiver.sending_mki(), Some(2));
        receiver
            .unprotect(&wire_one, &mut out)
            .expect("old MKI still decrypts");

        let mut new_sender = SrtcpGcmContext::new(std::slice::from_ref(&two)).expect("ctx");
        let mut wire_two = Vec::new();
        new_sender
            .protect(&rtcp(1), true, &mut wire_two)
            .expect("protect");
        receiver
            .unprotect(&wire_two, &mut out)
            .expect("new MKI decrypts");

        receiver
            .replace_keys(&[two.clone(), three.clone()])
            .expect("rekey again");
        let mut late = Vec::new();
        old_sender
            .protect(&rtcp(1), true, &mut late)
            .expect("protect");
        assert_eq!(
            receiver.unprotect(&late, &mut out),
            Err(SrtpError::UnknownMki)
        );
        // Replay state of the retained key survived the replace.
        assert_eq!(
            receiver.unprotect(&wire_two, &mut out),
            Err(SrtpError::Replayed)
        );
    }

    #[test]
    fn replace_keys_keeps_only_the_newest_two_and_protects_with_the_last() {
        let keys = [master(1, 1), master(2, 2), master(3, 3)];
        let mut context = SrtcpGcmContext::new(&keys).expect("ctx");
        assert_eq!(context.sending_mki(), Some(3));
        let mut wire = Vec::new();
        context.protect(&rtcp(1), true, &mut wire).expect("protect");
        let mut one = SrtcpGcmContext::new(&keys[..1]).expect("ctx");
        assert_eq!(
            one.unprotect(&wire, &mut Vec::new()),
            Err(SrtpError::UnknownMki)
        );
        let mut two = SrtcpGcmContext::new(&keys[1..2]).expect("ctx");
        assert_eq!(
            two.unprotect(&wire, &mut Vec::new()),
            Err(SrtpError::UnknownMki)
        );
        let mut newest = SrtcpGcmContext::new(&keys[2..]).expect("ctx");
        newest.unprotect(&wire, &mut Vec::new()).expect("newest");
        // Both of the kept two are accepted on receive.
        let mut second_newest = Vec::new();
        SrtcpGcmContext::new(&keys[1..2])
            .expect("ctx")
            .protect(&rtcp(1), true, &mut second_newest)
            .expect("protect");
        context
            .unprotect(&second_newest, &mut Vec::new())
            .expect("second newest");
    }

    #[test]
    fn replaced_key_loses_its_replay_state() {
        let key = master(1, 0x11);
        let mut sender = SrtcpGcmContext::new(std::slice::from_ref(&key)).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(std::slice::from_ref(&key)).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender.protect(&rtcp(1), true, &mut wire).expect("protect");
        receiver.unprotect(&wire, &mut out).expect("first");
        let fresh = master(1, 0x44); // same MKI, new material
        receiver.replace_keys(&[fresh]).expect("replace");
        assert_eq!(
            receiver.unprotect(&wire, &mut out),
            Err(SrtpError::AuthFailed)
        );
    }

    #[test]
    fn empty_and_duplicate_key_sets_are_rejected_and_leave_state_intact() {
        assert_eq!(SrtcpGcmContext::new(&[]).err(), Some(SrtpError::NoKeys));
        let mut context = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        assert_eq!(context.replace_keys(&[]), Err(SrtpError::NoKeys));
        assert_eq!(
            context.replace_keys(&[master(5, 1), master(5, 2)]),
            Err(SrtpError::DuplicateMki)
        );
        assert_eq!(context.sending_mki(), Some(1));
    }

    #[test]
    fn send_index_is_monotonic_settable_and_never_wraps() {
        let mut context = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut wire = Vec::new();
        context.protect(&rtcp(1), true, &mut wire).expect("protect");
        assert_eq!(context.send_index(), 1);
        context.set_send_index(0xFFFF_FFFF); // masked to 31 bits
        assert_eq!(context.send_index(), 0x7FFF_FFFF);
        context
            .protect(&rtcp(1), true, &mut wire)
            .expect("last index");
        assert_eq!(
            context.protect(&rtcp(1), true, &mut wire),
            Err(SrtpError::IndexExhausted)
        );
        context.set_send_index(10);
        context.protect(&rtcp(1), true, &mut wire).expect("resumed");
        assert_eq!(context.send_index(), 11);
    }

    #[test]
    fn protect_rejects_short_and_non_v2_input() {
        let mut context = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut wire = Vec::new();
        assert_eq!(
            context.protect(&[0x80; 7], true, &mut wire),
            Err(SrtpError::TooShort)
        );
        let mut bad = rtcp(1);
        bad[0] = 0x00;
        assert_eq!(
            context.protect(&bad, true, &mut wire),
            Err(SrtpError::BadVersion)
        );
        assert_eq!(context.send_index(), 0, "refused packets burn no index");
    }

    #[test]
    fn header_only_packet_roundtrips_as_tag_only_cipher() {
        // §9.2: even with an empty plaintext the cipher is the tag.
        let mut sender = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let header = hex("81c80000 11223344");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender.protect(&header, true, &mut wire).expect("protect");
        assert_eq!(wire.len(), MIN_PACKET_LEN);
        receiver.unprotect(&wire, &mut out).expect("unprotect");
        assert_eq!(out, header);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let text = format!("{:?}", master(1, 0xAB));
        assert!(text.contains("mki") && !text.contains("171") && !text.contains("ab"));
    }

    #[test]
    fn salt_96_is_zero_extended() {
        let key = FloorMasterKey::from_salt_96(1, [0; 16], &[0xEE; 12]);
        assert_eq!(key.master_salt[..12], [0xEE; 12]);
        assert_eq!(key.master_salt[12..], [0, 0]);
    }

    /// Writes a protected packet (derived keys, 4-octet MKI) as a hex dump for text2pcap. Driven
    /// by `scripts/check-srtcp-gcm-tshark.sh`; `#[ignore]` because it needs an output path.
    #[test]
    #[ignore = "driven by scripts/check-srtcp-gcm-tshark.sh"]
    fn emit_protected_packet_hex_for_tshark() {
        let path = std::env::var("SRTCP_GCM_HEX_OUT").expect("SRTCP_GCM_HEX_OUT");
        let mut sender = SrtcpGcmContext::new(&[master(0xCAFE_0001, 0x11)]).expect("ctx");
        let mut wire = Vec::new();
        sender
            .protect(&rtcp(0x4d61_7273), true, &mut wire)
            .expect("protect");
        let mut dump = String::from("000000 ");
        for byte in &wire {
            dump.push_str(&format!("{byte:02x} "));
        }
        std::fs::write(path, dump + "\n").expect("write");
    }
}
