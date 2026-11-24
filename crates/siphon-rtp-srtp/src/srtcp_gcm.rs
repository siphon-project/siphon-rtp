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
//! * Anti-replay (RFC 3711 §3.3.2) over the explicit 31-bit index, one window per sender SSRC under
//!   each key (§3.2.3, §3.4: the SRTCP index and the replay list belong to the SSRC's cryptographic
//!   context), recorded only after the tag verified. The windows live in a fixed table of
//!   [`MAX_REPLAY_SSRCS`] slots per key, claimed only by an authenticated packet; a packet of a further
//!   SSRC is refused ([`SrtpError::ReplayTableFull`]), never given a window another SSRC shares. The send index never wraps: RFC 7714 §9.4 forbids reusing an IV under one key, so at
//!   `2^31 - 1` protect refuses until the keys are replaced or the index is reseeded.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
/// Sender SSRCs whose SRTCP replay state one key tracks (RFC 3711 §3.2.3: a context per SSRC). A seat
/// sends RTCP for its audio, its video and the odd restart of either, so eight is generous; a ninth
/// SSRC is refused rather than sharing a window.
pub const MAX_REPLAY_SSRCS: usize = 8;

/// Why [`SendIndex::take`] gave no index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRefused {
    /// The last index (`2^31 - 1`) has been taken (RFC 7714 §9.4: the index never wraps).
    Exhausted,
    /// The index reached the lease: nothing more is sent under the key until the lease is extended.
    LeaseReached,
}

/// No lease: the `limit` half of the packed state while the counter is unleased. Above the index space
/// (`2^31`), so it can never be reached or mistaken for a lease.
const NO_LEASE: u32 = u32::MAX;

/// The next SRTCP index to send under one key, shared by everything that sends under it.
///
/// A GCM IV is the session salt XOR (SSRC, index) (RFC 7714 §9.1), so under one key an index must
/// never go out twice for one SSRC (§8, §9.4). The counter therefore belongs to the key, not to the
/// context that happens to hold it: every context sending under the key draws from one `SendIndex`,
/// whichever stream, seat or room it serves. It only moves forward, lock-free, and stops at
/// `2^31 - 1` instead of wrapping.
///
/// It can also carry a **lease**: an index it may not reach. A standby seeded from a checkpoint starts
/// a margin past the checkpointed index; a primary that sends further than that margin before it
/// fails would be overtaken, so once a checkpoint exists the counter refuses at the margin until the
/// next checkpoint extends the lease. Without a lease nothing changes.
///
/// The index and the lease are **one** atomic word (`limit << 32 | next`) and every change is a
/// compare-and-swap of that whole word. That is what makes the lease safe: a take that read the state
/// before a checkpoint set the lease cannot commit afterwards (its swap fails and it reads the lease),
/// and a checkpoint reads the index and sets the lease from it in one step, so no index can be handed
/// out between the index a checkpoint exports and the lease it grants. A refused take changes nothing.
#[derive(Debug, Clone)]
pub struct SendIndex(Arc<AtomicU64>);

impl Default for SendIndex {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(pack(0, NO_LEASE))))
    }
}

const fn pack(next: u32, limit: u32) -> u64 {
    ((limit as u64) << 32) | next as u64
}

const fn unpack(state: u64) -> (u32, u32) {
    (state as u32, (state >> 32) as u32)
}

/// A state read, to be committed by [`SendIndex::commit_take`]. Public only so that the two steps of
/// a take can be interleaved with a checkpoint deterministically in tests.
#[derive(Debug, Clone, Copy)]
pub struct TakeSnapshot(u64);

impl SendIndex {
    /// A counter at index 0, for a key nothing has sent under.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The word, with the lease clamped to the end of the index space for comparison.
    fn bound(limit: u32) -> u32 {
        limit.min(LAST_INDEX + 1)
    }

    /// Take the next index, or say why there is none. One compare-and-swap in the common case, no
    /// lock, no allocation. A refused take changes nothing.
    ///
    /// # Errors
    /// [`SendRefused::Exhausted`] past the last index, [`SendRefused::LeaseReached`] at the lease.
    pub fn take(&self) -> Result<u32, SendRefused> {
        loop {
            match self.commit_take(self.snapshot()) {
                Ok(Some(index)) => return Ok(index),
                Ok(None) => {}
                Err(refused) => return Err(refused),
            }
        }
    }

    /// Step one of a take: read the state.
    #[must_use]
    pub fn snapshot(&self) -> TakeSnapshot {
        TakeSnapshot(self.0.load(Ordering::Acquire))
    }

    /// Step two: decide on `snapshot` and try to commit it. `Ok(Some(index))` took it, `Ok(None)` means
    /// the state moved since the snapshot (a take, a checkpoint) and nothing was taken, and the caller
    /// reads again; `Err` is a refusal under the state that was read.
    ///
    /// # Errors
    /// [`SendRefused::Exhausted`] or [`SendRefused::LeaseReached`], decided on the snapshot.
    pub fn commit_take(&self, snapshot: TakeSnapshot) -> Result<Option<u32>, SendRefused> {
        let (next, limit) = unpack(snapshot.0);
        if next >= Self::bound(limit) {
            return Err(if limit <= LAST_INDEX {
                SendRefused::LeaseReached
            } else {
                SendRefused::Exhausted
            });
        }
        Ok(self
            .0
            .compare_exchange_weak(
                snapshot.0,
                pack(next + 1, limit),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            .then_some(next))
    }

    /// Change the state with `change` (old `(next, limit)` to new), atomically, and return the old
    /// pair. `change` may run more than once.
    fn update(&self, change: impl Fn(u32, u32) -> (u32, u32)) -> (u32, u32) {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, limit) = unpack(state);
            let (new_next, new_limit) = change(next, limit);
            match self.0.compare_exchange_weak(
                state,
                pack(new_next, new_limit),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return (next, limit),
                Err(observed) => state = observed,
            }
        }
    }

    /// The next index that [`Self::take`] will return (`2^31` once exhausted).
    #[must_use]
    pub fn next(&self) -> u32 {
        unpack(self.0.load(Ordering::Acquire)).0
    }

    /// Raise the counter to `index` (clamped to the end of the index space). It never lowers: an
    /// index that went out is never offered again, whatever a checkpoint or a caller says.
    pub fn raise_to(&self, index: u32) {
        self.update(|next, limit| (next.max(index.min(LAST_INDEX + 1)), limit));
    }

    /// Lease to `index`: nothing at or past it is sent. A counter with no lease takes it; one that has a
    /// lease keeps the longer of the two, so a lease never shortens. `2^31` or more is the whole index
    /// space.
    pub fn lease_to(&self, index: u32) {
        let target = index.min(LAST_INDEX + 1);
        self.update(|next, limit| {
            (
                next,
                if limit == NO_LEASE {
                    target
                } else {
                    limit.max(target)
                },
            )
        });
    }

    /// A checkpoint of this counter, in one step: read the next index and lease the counter to that
    /// index plus `margin`. Returns the index read. Nothing can be handed out between the index read
    /// and the lease set, so a standby that starts `margin` past the returned index cannot be reached.
    #[must_use]
    pub fn checkpoint(&self, margin: u32) -> u32 {
        let target = |next: u32| next.saturating_add(margin).min(LAST_INDEX + 1);
        self.update(|next, limit| {
            (
                next,
                if limit == NO_LEASE {
                    target(next)
                } else {
                    limit.max(target(next))
                },
            )
        })
        .0
    }

    /// Seed from a checkpoint, in one step: raise the counter to `start` and lease it to `lease` (never
    /// shortening an existing lease, never lowering the counter).
    pub fn seed(&self, start: u32, lease: u32) {
        let (start, lease) = (start.min(LAST_INDEX + 1), lease.min(LAST_INDEX + 1));
        self.update(|next, limit| {
            (
                next.max(start),
                if limit == NO_LEASE {
                    lease
                } else {
                    limit.max(lease)
                },
            )
        });
    }

    /// Raise the counter to at least `floor` and close the send window, **in one step**: the new
    /// counter and the lease are the same index, so nothing is sent until a later lease (a confirmed
    /// checkpoint) reopens it. A restore uses it for a key whose sends nothing durable yet bounds. It
    /// must be one compare-and-swap: a raise followed by a separate close would let a concurrent
    /// sender take the raised index in between, and a later standby that restores the same blob would
    /// send it again (RFC 7714 §8). Unlike every other lease change it **shortens** a lease, which is
    /// always safe for nonce uniqueness (it only sends less). Never lowers the counter.
    pub fn raise_and_close(&self, floor: u32) {
        let floor = floor.min(LAST_INDEX + 1);
        self.update(|next, _| {
            let raised = next.max(floor);
            (raised, raised)
        });
    }

    /// The lease, or `None` when the counter has none.
    #[must_use]
    pub fn lease(&self) -> Option<u32> {
        let (_, limit) = unpack(self.0.load(Ordering::Acquire));
        (limit <= LAST_INDEX).then_some(limit)
    }

    /// How many handles share this counter (the ledger's own included).
    #[must_use]
    pub fn holders(&self) -> usize {
        Arc::strong_count(&self.0)
    }
}

/// The replay windows of one key, one per sender SSRC, in a table of fixed size.
struct ReplaySlots {
    slots: [Option<(u32, ReplayWindow)>; MAX_REPLAY_SSRCS],
    /// After an HA restore: windows of SSRCs first seen later start closed at this index.
    resumed: Option<u64>,
}

impl ReplaySlots {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_REPLAY_SSRCS],
            resumed: None,
        }
    }

    /// The window of `ssrc` as it stands, or `None` when the table has no window for it and no free
    /// slot to give it: the caller refuses the packet.
    fn window_of(&self, ssrc: u32) -> Option<ReplayWindow> {
        if let Some((_, window)) = self
            .slots
            .iter()
            .flatten()
            .find(|(known, _)| *known == ssrc)
        {
            return Some(*window);
        }
        if self.slots.iter().any(Option::is_none) {
            let mut fresh = ReplayWindow::default();
            if let Some(index) = self.resumed {
                fresh.close_at(index);
            }
            return Some(fresh);
        }
        None
    }

    /// Keep `window` as the state of `ssrc`, after a packet authenticated. The slot was checked to be
    /// there by [`Self::window_of`].
    fn store(&mut self, ssrc: u32, window: ReplayWindow) {
        let position = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|(known, _)| known == ssrc))
            .or_else(|| self.slots.iter().position(Option::is_none));
        if let Some(position) = position {
            self.slots[position] = Some((ssrc, window));
        }
    }

    /// The highest index recorded under any SSRC, for an HA checkpoint.
    fn highest(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .filter_map(|(_, window)| window.highest())
            .max()
    }

    /// Resume from a checkpoint: `index` and below count as received under every SSRC, known or not
    /// yet seen (the checkpoint does not say which stream it came from).
    fn close_at(&mut self, index: u64) {
        for (_, window) in self.slots.iter_mut().flatten() {
            window.close_at(index);
        }
        self.resumed = Some(index);
    }
}
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

impl FloorMasterKey {
    /// A fingerprint of the key material that names its send counter and reveals nothing of it: the
    /// HMAC-SHA1 (RFC 2104) of a fixed label and the master salt, keyed by the master key.
    ///
    /// The GCM IV is derived from the master key and salt alone (RFC 7714 §11: the session salt comes
    /// from them), so two keys with that material share an IV space whatever their MKIs say; the MKI is
    /// therefore not part of it. Being a function of the key, it is the same on every node, so an HA
    /// standby recognises a checkpointed counter without any secret being distributed; being an HMAC
    /// under the key, it cannot be used to recover or test guesses at the key short of knowing it.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        use hmac::{Hmac, Mac};
        // RFC 2104 zero-pads a key shorter than the block: the 64-octet key below is the same HMAC key
        // as the 16 octets, and the fixed-size constructor cannot fail.
        let mut block = GenericArray::<u8, aes_gcm::aead::consts::U64>::default();
        block[..MASTER_KEY_LEN].copy_from_slice(&self.master_key);
        let mut mac = <Hmac<sha1::Sha1> as Mac>::new(&block);
        block.zeroize();
        mac.update(b"siphon-rtp srtcp send index v1");
        mac.update(&self.master_salt);
        mac.finalize().into_bytes().into()
    }
}

/// The length of [`FloorMasterKey::fingerprint`].
pub const FINGERPRINT_LEN: usize = 20;

/// The length of an [`origin_tag`].
pub const ORIGIN_TAG_LEN: usize = 20;

/// The length of the secret an [`origin_tag`] is keyed with.
pub const ORIGIN_SECRET_LEN: usize = 32;

/// `HMAC-SHA1(secret, message)` (RFC 2104, RFC 2202): a process proves it produced `message` by
/// keying the tag with a secret only it holds. HMAC does not rest on the collision resistance of the
/// hash, so SHA-1 is sound for a tag. It is used rather than HMAC-SHA-256 because `sha1` and `hmac` are
/// already dependencies here (for [`FloorMasterKey::fingerprint`]) and SHA-256 is not: a new edge in
/// the dependency graph buys nothing for a tag under a secret.
/// The secret is zero-padded to the block, which RFC 2104 defines as the same HMAC key.
#[must_use]
pub fn origin_tag(secret: &[u8; ORIGIN_SECRET_LEN], message: &[u8]) -> [u8; ORIGIN_TAG_LEN] {
    use hmac::{Hmac, Mac};
    let mut block = GenericArray::<u8, aes_gcm::aead::consts::U64>::default();
    block[..ORIGIN_SECRET_LEN].copy_from_slice(secret);
    let mut mac = <Hmac<sha1::Sha1> as Mac>::new(&block);
    block.zeroize();
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Whether `tag` is the [`origin_tag`] of `message` under `secret`, compared in constant time (the
/// `hmac` crate's `verify_slice`).
#[must_use]
pub fn origin_tag_verifies(secret: &[u8; ORIGIN_SECRET_LEN], message: &[u8], tag: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    let mut block = GenericArray::<u8, aes_gcm::aead::consts::U64>::default();
    block[..ORIGIN_SECRET_LEN].copy_from_slice(secret);
    let mut mac = <Hmac<sha1::Sha1> as Mac>::new(&block);
    block.zeroize();
    mac.update(message);
    mac.verify_slice(tag).is_ok()
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
    replay: ReplaySlots,
    /// The send counter of this key (shared with every other holder of it).
    counter: SendIndex,
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

/// Whether two master keys are the same key material (key and salt), in constant time.
fn same_material(a: &FloorMasterKey, b: &FloorMasterKey) -> bool {
    (a.master_key.ct_eq(&b.master_key).unwrap_u8()
        & a.master_salt.ct_eq(&b.master_salt).unwrap_u8())
        == 1
}

impl KeyEntry {
    fn new(master: FloorMasterKey, counter: SendIndex) -> Self {
        Self {
            session: GcmSession::derive(&master),
            master,
            replay: ReplaySlots::new(),
            counter,
        }
    }

    /// Same key material, whatever the MKI: the entry (its replay state and its send counter) is the
    /// key's. The MKI only selects a master key on the wire (RFC 3711 §3.2.1) and is not covered by
    /// the tag, so state belongs to the material, never to the label.
    fn is_same_key(&self, other: &FloorMasterKey) -> bool {
        same_material(&self.master, other)
    }
}

/// An SRTCP `AEAD_AES_128_GCM` endpoint: a set of at most [`MAX_KEYS`] master keys selected by MKI
/// for receiving, the newest of which protects outgoing packets, plus the 31-bit send index.
pub struct SrtcpGcmContext {
    /// Oldest first; the last entry is the sending key.
    keys: Vec<KeyEntry>,
}

impl SrtcpGcmContext {
    /// Build a context from `keys`; the last one protects outgoing packets. More than
    /// [`MAX_KEYS`] keeps the last [`MAX_KEYS`]. Errors with [`SrtpError::NoKeys`] for an empty
    /// slice, [`SrtpError::DuplicateMki`] when two keys share an MKI and
    /// [`SrtpError::DuplicateKeyMaterial`] when two keys are one key under two MKIs.
    pub fn new(keys: &[FloorMasterKey]) -> Result<Self, SrtpError> {
        Self::with_counters(keys, |_| SendIndex::new())
    }

    /// [`Self::new`] with the send counter of each key supplied by `counter_of`, so that every
    /// context sending under one key draws its indices from one [`SendIndex`] (RFC 7714 §8).
    pub fn with_counters(
        keys: &[FloorMasterKey],
        counter_of: impl FnMut(&FloorMasterKey) -> SendIndex,
    ) -> Result<Self, SrtpError> {
        let mut context = Self {
            keys: Vec::with_capacity(MAX_KEYS),
        };
        context.replace_keys_with(keys, counter_of)?;
        Ok(context)
    }

    /// Replace the whole key set (same rules as [`Self::new`]). Keys that were already present with
    /// identical material keep their replay state; every other prior key is dropped together with
    /// its replay state. A key that is new starts at the index its own counter holds (0 for a key
    /// nothing has sent under); the IV is per key, so another key's index is no constraint. On error
    /// the existing set is untouched.
    pub fn replace_keys(&mut self, keys: &[FloorMasterKey]) -> Result<(), SrtpError> {
        self.replace_keys_with(keys, |_| SendIndex::new())
    }

    /// [`Self::replace_keys`] with the send counter of each key that is new to the context supplied by
    /// `counter_of`; a key already held keeps its own.
    pub fn replace_keys_with(
        &mut self,
        keys: &[FloorMasterKey],
        mut counter_of: impl FnMut(&FloorMasterKey) -> SendIndex,
    ) -> Result<(), SrtpError> {
        let kept = &keys[keys.len().saturating_sub(MAX_KEYS)..];
        if kept.is_empty() {
            return Err(SrtpError::NoKeys);
        }
        if kept.len() == 2 && kept[0].mki == kept[1].mki {
            return Err(SrtpError::DuplicateMki);
        }
        if kept.len() == 2 && same_material(&kept[0], &kept[1]) {
            return Err(SrtpError::DuplicateKeyMaterial);
        }
        let mut next = Vec::with_capacity(MAX_KEYS);
        for master in kept {
            match self.keys.iter().position(|entry| entry.is_same_key(master)) {
                Some(position) => {
                    // The same key, possibly renamed: it keeps its state under the new MKI.
                    let mut entry = self.keys.swap_remove(position);
                    entry.master.mki = master.mki;
                    next.push(entry);
                }
                None => next.push(KeyEntry::new(master.clone(), counter_of(master))),
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
        self.keys.last().map_or(0, |entry| entry.counter.next())
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

    /// Raise the sending key's outgoing index to a checkpoint's (masked to 31 bits); it never lowers,
    /// because an index already sent must not be sent again (RFC 7714 §9.4). Callers pass the value
    /// [`Self::send_index`] returned, plus any safety margin they want.
    pub fn set_send_index(&mut self, index: u32) {
        if let Some(entry) = self.keys.last() {
            entry.counter.raise_to(index & INDEX_MASK);
        }
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
        let Some(entry) = self.keys.last() else {
            return Err(SrtpError::NoKeys);
        };
        // RFC 7714 §9.4: the last index is the last; the counter stops there.
        let index = entry.counter.take().map_err(|refused| match refused {
            SendRefused::Exhausted => SrtpError::IndexExhausted,
            SendRefused::LeaseReached => SrtpError::SendLeaseReached,
        })?;
        entry.session.seal(rtcp, encrypt, index, out)?;
        out.extend_from_slice(&entry.master.mki.to_be_bytes());
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
        // RFC 3711 §3.2.3, §3.3.2: the replay list is the SSRC's. The SSRC is read before the tag is
        // checked, so it only selects a window to test against; a window is claimed after the tag
        // verified. A further SSRC than the table holds is refused, not given a shared window.
        let ssrc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let mut window = entry
            .replay
            .window_of(ssrc)
            .ok_or(SrtpError::ReplayTableFull)?;
        entry.session.open(body, &mut window, out)?;
        entry.replay.store(ssrc, window);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_origin_tag_matches_the_rfc_2202_hmac_sha1_vector_and_detects_any_change() {
        // RFC 2202 test case 1: key 0x0b x 20, data "Hi There". The 20 octet key zero-padded to 32 is
        // the same HMAC key (RFC 2104 section 2).
        let mut secret = [0u8; ORIGIN_SECRET_LEN];
        secret[..20].fill(0x0b);
        let tag = origin_tag(&secret, b"Hi There");
        assert_eq!(
            tag,
            [
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
                0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
            ]
        );
        assert!(origin_tag_verifies(&secret, b"Hi There", &tag));
        assert!(!origin_tag_verifies(&secret, b"Hi there", &tag));
        assert!(!origin_tag_verifies(
            &[0u8; ORIGIN_SECRET_LEN],
            b"Hi There",
            &tag
        ));
        assert!(!origin_tag_verifies(&secret, b"Hi There", &tag[..19]));
    }

    #[test]
    fn raise_and_close_is_one_step_so_no_take_can_slip_between_the_raise_and_the_close() {
        let counter = SendIndex::new();
        counter.seed(10, 500);
        assert_eq!(counter.take(), Ok(10));
        // A taker that read the state before the restore cannot commit after it.
        let paused = counter.snapshot();
        counter.raise_and_close(65_536);
        assert_eq!(counter.commit_take(paused), Ok(None), "the state moved");
        assert_eq!(counter.next(), 65_536);
        assert_eq!(counter.lease(), Some(65_536), "a longer lease is not kept");
        assert_eq!(counter.take(), Err(SendRefused::LeaseReached));
        // Never lowers the counter, and a later lease reopens it.
        counter.raise_and_close(100);
        assert_eq!(counter.next(), 65_536);
        counter.lease_to(65_600);
        assert_eq!(counter.take(), Ok(65_536));
        // An unleased counter is closed too, and the last index is the end (RFC 7714 section 9.4).
        let unleased = SendIndex::new();
        unleased.raise_and_close(7);
        assert_eq!(unleased.take(), Err(SendRefused::LeaseReached));
        let ending = SendIndex::new();
        ending.raise_and_close(u32::MAX);
        assert_eq!(ending.take(), Err(SendRefused::Exhausted));
    }

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
        let mut entry = KeyEntry::new(master(1, 0x11), SendIndex::new());
        entry.zeroize();
        assert_eq!(entry.master.master_key, [0u8; 16]);
        assert_eq!(entry.master.master_salt, [0u8; MASTER_SALT_LEN]);
        assert_eq!(entry.session.salt, [0u8; SESSION_SALT_LEN]);
    }

    #[test]
    fn dropping_a_key_entry_wipes_it_first() {
        clear_wiped();
        drop(KeyEntry::new(master(0x42, 0x11), SendIndex::new()));
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
    fn send_index_is_monotonic_raise_only_and_never_wraps() {
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
        // An index that went out is never offered again: a checkpoint cannot lower the counter.
        context.set_send_index(10);
        assert_eq!(
            context.protect(&rtcp(1), true, &mut wire),
            Err(SrtpError::IndexExhausted)
        );
        let mut fresh = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        fresh.set_send_index(10);
        fresh.set_send_index(4);
        fresh.protect(&rtcp(1), true, &mut wire).expect("resumed");
        assert_eq!(fresh.send_index(), 11);
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

    /// The index a sealed packet carries (the `E|index` word before the MKI).
    fn index_of(wire: &[u8]) -> u32 {
        let at = wire.len() - MKI_LEN - ESRTCP_LEN;
        u32::from_be_bytes([wire[at], wire[at + 1], wire[at + 2], wire[at + 3]]) & INDEX_MASK
    }

    #[test]
    fn contexts_sharing_a_counter_never_send_one_index_twice() {
        let shared = SendIndex::new();
        let key = master(1, 1);
        let mut first =
            SrtcpGcmContext::with_counters(std::slice::from_ref(&key), |_| shared.clone())
                .expect("ctx");
        let mut second =
            SrtcpGcmContext::with_counters(std::slice::from_ref(&key), |_| shared.clone())
                .expect("ctx");
        let mut wire = Vec::new();
        let mut seen = Vec::new();
        for _ in 0..4 {
            first.protect(&rtcp(7), true, &mut wire).expect("protect");
            seen.push(index_of(&wire));
            second.protect(&rtcp(7), true, &mut wire).expect("protect");
            seen.push(index_of(&wire));
        }
        assert_eq!(seen, (0..8).collect::<Vec<_>>());
        assert_eq!(first.send_index(), 8);
        assert_eq!(shared.holders(), 3);
    }

    #[test]
    fn a_new_key_draws_from_its_own_counter_and_a_kept_key_keeps_its_own() {
        let (one, two) = (master(1, 1), master(2, 2));
        let mut context = SrtcpGcmContext::new(std::slice::from_ref(&one)).expect("ctx");
        let mut wire = Vec::new();
        context.protect(&rtcp(1), true, &mut wire).expect("protect");
        context.protect(&rtcp(1), true, &mut wire).expect("protect");
        context.replace_keys(&[one.clone(), two]).expect("rekey");
        context.protect(&rtcp(1), true, &mut wire).expect("protect");
        assert_eq!(
            index_of(&wire),
            0,
            "the IV is per key: the new key starts at its own 0"
        );
        context.replace_keys(&[one]).expect("back");
        context.protect(&rtcp(1), true, &mut wire).expect("protect");
        assert_eq!(index_of(&wire), 2, "the first key goes on where it stopped");
    }

    #[test]
    fn replay_windows_are_per_sender_ssrc() {
        let mut sender = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut other = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let (mut audio, mut video, mut out) = (Vec::new(), Vec::new(), Vec::new());
        // Audio and video of one client are both at index 0 of their own SSRC (RFC 3711 §3.2.3).
        sender.protect(&rtcp(0xA), true, &mut audio).expect("audio");
        other.protect(&rtcp(0xB), true, &mut video).expect("video");
        receiver.unprotect(&audio, &mut out).expect("audio");
        receiver
            .unprotect(&video, &mut out)
            .expect("the video index 0 is not a replay of the audio's");
        // Each is a replay on its own window.
        assert_eq!(
            receiver.unprotect(&audio, &mut out),
            Err(SrtpError::Replayed)
        );
        assert_eq!(
            receiver.unprotect(&video, &mut out),
            Err(SrtpError::Replayed)
        );
    }

    #[test]
    fn a_high_index_of_one_ssrc_does_not_move_another_ssrcs_window() {
        let mut sender = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut other = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        sender.set_send_index(100_000);
        let (mut audio, mut video, mut out) = (Vec::new(), Vec::new(), Vec::new());
        sender.protect(&rtcp(0xA), true, &mut audio).expect("audio");
        receiver
            .unprotect(&audio, &mut out)
            .expect("audio at 100000");
        // With one shared window the video at index 3 would now be older than the window: refused.
        for _ in 0..3 {
            other.protect(&rtcp(0xB), true, &mut video).expect("video");
        }
        receiver
            .unprotect(&video, &mut out)
            .expect("video at 2, far below the audio's index");
    }

    #[test]
    fn an_audio_packet_replayed_as_another_ssrcs_is_still_a_replay_of_its_own() {
        // The packet is the same bytes: its SSRC is in the authenticated header, so it can only ever be
        // checked on the window of the SSRC it names.
        let mut sender = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender.protect(&rtcp(0xA), true, &mut wire).expect("audio");
        receiver.unprotect(&wire, &mut out).expect("first");
        assert_eq!(
            receiver.unprotect(&wire, &mut out),
            Err(SrtpError::Replayed)
        );
        let mut forged = wire.clone();
        forged[4..8].copy_from_slice(&0xBu32.to_be_bytes());
        assert_eq!(
            receiver.unprotect(&forged, &mut out),
            Err(SrtpError::AuthFailed),
            "a rewritten SSRC fails the tag; it never gets a fresh window"
        );
    }

    #[test]
    fn a_ninth_ssrc_is_refused_without_sharing_a_window_and_only_authenticated_ones_take_a_slot() {
        let mut receiver = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        // Forged packets of many SSRCs claim nothing.
        for ssrc in 0..64u32 {
            let mut senders = SrtcpGcmContext::new(&[master(1, 9)]).expect("ctx");
            senders
                .protect(&rtcp(ssrc), true, &mut wire)
                .expect("protect");
            assert_eq!(
                receiver.unprotect(&wire, &mut out),
                Err(SrtpError::AuthFailed)
            );
        }
        for ssrc in 0..MAX_REPLAY_SSRCS as u32 {
            let mut sender = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
            sender
                .protect(&rtcp(100 + ssrc), true, &mut wire)
                .expect("protect");
            receiver.unprotect(&wire, &mut out).expect("a slot each");
        }
        let mut late = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        late.protect(&rtcp(999), true, &mut wire).expect("protect");
        assert_eq!(
            receiver.unprotect(&wire, &mut out),
            Err(SrtpError::ReplayTableFull)
        );
        assert!(out.is_empty());
        // The held ones are unaffected.
        let mut known = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        known.set_send_index(5);
        known.protect(&rtcp(100), true, &mut wire).expect("protect");
        receiver
            .unprotect(&wire, &mut out)
            .expect("a known SSRC still passes");
    }

    #[test]
    fn a_restored_replay_anchor_applies_to_ssrcs_seen_later_too() {
        let mut receiver = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        receiver.resume_received(1, 10);
        let mut sender = SrtcpGcmContext::new(&[master(1, 1)]).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender
            .protect(&rtcp(0xA), true, &mut wire)
            .expect("index 0");
        assert_eq!(
            receiver.unprotect(&wire, &mut out),
            Err(SrtpError::Replayed)
        );
        sender.set_send_index(11);
        sender
            .protect(&rtcp(0xA), true, &mut wire)
            .expect("index 11");
        receiver
            .unprotect(&wire, &mut out)
            .expect("beyond the anchor");
        assert_eq!(receiver.received_indices(), vec![(1, 11)]);
    }

    #[test]
    fn the_fingerprint_names_the_key_material_and_not_its_mki_and_reveals_no_key_bytes() {
        let key = master(1, 0x41);
        let print = key.fingerprint();
        assert_eq!(
            print,
            master(1, 0x41).fingerprint(),
            "stable: the same on every node"
        );
        let mut renamed = master(1, 0x41);
        renamed.mki = 99;
        assert_eq!(
            print,
            renamed.fingerprint(),
            "one IV space whatever the MKI says"
        );
        assert_ne!(print, master(1, 0x42).fingerprint());
        let mut salted = master(1, 0x41);
        salted.master_salt[0] ^= 1;
        assert_ne!(print, salted.fingerprint());
        assert!(!print
            .windows(4)
            .any(|window| key.master_key.windows(4).any(|part| part == window)));
        assert_eq!(print.len(), FINGERPRINT_LEN);
    }

    #[test]
    fn one_key_under_two_mkis_in_a_set_is_refused() {
        let key = master(1, 0x41);
        let mut alias = master(1, 0x41);
        alias.mki = 2;
        assert!(matches!(
            SrtcpGcmContext::new(&[key.clone(), alias.clone()]),
            Err(SrtpError::DuplicateKeyMaterial)
        ));
        let mut context = SrtcpGcmContext::new(std::slice::from_ref(&key)).expect("ctx");
        assert_eq!(
            context.replace_keys(&[key, alias]),
            Err(SrtpError::DuplicateKeyMaterial)
        );
        assert_eq!(context.sending_mki(), Some(1), "the held set is untouched");
    }

    #[test]
    fn a_captured_packet_resent_under_an_alias_mki_is_a_replay() {
        // The MKI is not authenticated (RFC 7714 §9.2): rewriting it must not give the key a second
        // replay table. The key is renamed to MKI 2 by a rekey (the same material), and the packet
        // captured under MKI 1 comes back with the new MKI.
        let key = master(1, 0x41);
        let mut renamed = master(1, 0x41);
        renamed.mki = 2;
        let mut sender = SrtcpGcmContext::new(std::slice::from_ref(&key)).expect("ctx");
        let mut receiver = SrtcpGcmContext::new(std::slice::from_ref(&key)).expect("ctx");
        let (mut wire, mut out) = (Vec::new(), Vec::new());
        sender
            .protect(&rtcp(0xA), true, &mut wire)
            .expect("protect");
        receiver.unprotect(&wire, &mut out).expect("first");
        receiver
            .replace_keys(std::slice::from_ref(&renamed))
            .expect("the same material, renamed");
        let mut aliased = wire.clone();
        let at = aliased.len() - MKI_LEN;
        aliased[at..].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            receiver.unprotect(&aliased, &mut out),
            Err(SrtpError::Replayed)
        );
        assert_eq!(
            receiver.unprotect(&wire, &mut out),
            Err(SrtpError::UnknownMki)
        );
    }

    #[test]
    fn a_counter_with_a_lease_stops_at_it_until_the_lease_is_extended() {
        let counter = SendIndex::new();
        assert_eq!(counter.lease(), None, "no lease until one is given");
        counter.lease_to(3);
        assert_eq!(counter.lease(), Some(3));
        assert_eq!(
            (counter.take(), counter.take(), counter.take()),
            (Ok(0), Ok(1), Ok(2))
        );
        let at_lease = counter.snapshot().0;
        for _ in 0..1000 {
            assert_eq!(counter.take(), Err(SendRefused::LeaseReached));
        }
        assert_eq!(
            counter.snapshot().0,
            at_lease,
            "a refused take changes nothing"
        );
        counter.lease_to(5);
        assert_eq!(counter.take(), Ok(3));
        assert_eq!(counter.take(), Ok(4));
        assert_eq!(counter.take(), Err(SendRefused::LeaseReached));
        // A lease never shortens.
        counter.lease_to(4);
        assert_eq!(counter.lease(), Some(5));
    }

    #[test]
    fn a_take_that_read_the_state_before_a_checkpoint_cannot_commit_after_it() {
        // The race, forced: a taker reads the unleased state and pauses; a checkpoint reads index 5 and
        // leases to 5 + 10; the senders use the window up; the paused taker then tries to commit. With
        // separate index and limit it would hand out 15, the standby's first index.
        let counter = SendIndex::new();
        counter.raise_to(5);
        let paused = counter.snapshot();
        assert_eq!(counter.checkpoint(10), 5);
        for expected in 5..15 {
            assert_eq!(counter.take(), Ok(expected));
        }
        assert_eq!(
            counter.commit_take(paused),
            Ok(None),
            "the stale swap fails"
        );
        assert_eq!(counter.take(), Err(SendRefused::LeaseReached));
        assert_eq!(
            counter.next(),
            15,
            "nothing was handed out at or past the lease"
        );
    }

    #[test]
    fn a_checkpoint_reads_the_index_and_sets_the_lease_in_one_step() {
        // Whatever the counter holds when the checkpoint runs, the lease is exactly that plus margin.
        let counter = SendIndex::new();
        for _ in 0..7 {
            counter.take().unwrap();
        }
        let exported = counter.checkpoint(100);
        assert_eq!(exported, 7);
        assert_eq!(counter.lease(), Some(107));
        // Taking after the checkpoint never gets past what it granted, however many threads race it.
        let counter = std::sync::Arc::new(counter);
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let counter = counter.clone();
                std::thread::spawn(move || {
                    (0..200)
                        .filter_map(|_| counter.take().ok())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut all: Vec<u32> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all.sort_unstable();
        assert_eq!(
            all,
            (7..107).collect::<Vec<_>>(),
            "exactly the leased window, once each"
        );
    }

    #[test]
    fn seeding_raises_and_leases_in_one_step_and_never_lowers() {
        let counter = SendIndex::new();
        counter.seed(100, 150);
        assert_eq!((counter.next(), counter.lease()), (100, Some(150)));
        counter.seed(10, 20);
        assert_eq!((counter.next(), counter.lease()), (100, Some(150)));
    }

    #[test]
    fn a_leased_context_refuses_to_seal_at_the_bound_and_goes_on_when_extended() {
        let shared = SendIndex::new();
        shared.lease_to(2);
        let mut context =
            SrtcpGcmContext::with_counters(&[master(1, 1)], |_| shared.clone()).expect("ctx");
        let mut wire = Vec::new();
        context.protect(&rtcp(1), true, &mut wire).expect("0");
        context.protect(&rtcp(1), true, &mut wire).expect("1");
        assert_eq!(
            context.protect(&rtcp(1), true, &mut wire),
            Err(SrtpError::SendLeaseReached)
        );
        shared.lease_to(10);
        context.protect(&rtcp(1), true, &mut wire).expect("2");
        assert_eq!(index_of(&wire), 2);
    }

    #[test]
    fn a_counter_that_is_hammered_past_the_end_never_wraps_to_zero() {
        let counter = SendIndex::new();
        counter.raise_to(MAX_SEND_INDEX);
        assert_eq!(counter.take(), Ok(MAX_SEND_INDEX));
        for _ in 0..100_000 {
            assert_eq!(counter.take(), Err(SendRefused::Exhausted));
        }
        assert_eq!(counter.next(), MAX_SEND_INDEX + 1);
    }
}
