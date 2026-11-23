//! The engine-wide ledger of SRTCP send indices (RFC 7714 §8, §9.1, §9.4; 3GPP TS 33.180 §9.4).
//!
//! An `AEAD_AES_128_GCM` SRTCP packet is encrypted under an IV of the session salt XOR (sender SSRC,
//! SRTCP index). Under one key the pair must never repeat, or two packets share a keystream and a
//! GHASH subkey stream: confidentiality and integrity are both lost (RFC 7714 §8). The index is a
//! counter, and a counter that belongs to one seat, leg or room restarts at 0 whenever that owner
//! does: a seat that leaves and rejoins, one client key seated in two rooms, a floor stream and a
//! media stream under one key, a key removed and given again. Resealed talker RTCP keeps the talker's
//! SSRC, so no per-seat randomness separates those packets.
//!
//! So the counter belongs to the **key**. The ledger maps a fingerprint of the key material
//! ([`FloorMasterKey::fingerprint`]: an HMAC under the key, never the key itself, the same on every
//! node, independent of the MKI because the IV is not) to one [`SendIndex`]. Every
//! `FloorProtection` (floor_srtcp.rs) sending under the key, in any forward room, floor leg,
//! stream or seat, draws from it with one compare-and-swap: lock-free, allocation-free, monotonic,
//! stopping at `2^31 - 1` rather than wrapping (RFC 7714 §9.4).
//!
//! **Retention.** An entry is the high-water mark of its key, and it is **never dropped by default**:
//! the engine cannot see a controller replace a key, and a key that comes back after its entry was
//! dropped would start at index 0 and repeat nonces (RFC 7714 §8). Retention is an opt-in setting
//! (`srtcp_ledger_retention_secs`): an entry that nothing has held for that long is dropped, which is
//! safe only at or above the lifetime the controller enforces on a client key (CSK, TS 33.180 §9.4.2).
//! An entry that is held is never dropped, nor one whose index is exhausted. Memory is one small entry
//! per distinct key material seen since start (or within the retention window).
//!
//! **Entry cap.** Retention is opt-in, so by default nothing drops an entry, and a controller that
//! keeps issuing new keys would grow the ledger without bound. [`SrtcpLedger::set_max_entries`] caps
//! it ([`DEFAULT_MAX_ENTRIES`]). At the cap a **new** key is refused, loudly: the verb that carried it
//! fails, `siphon_rtp_srtcp_ledger_install_refused_total` counts it, and an error is logged. A key the
//! ledger already holds still installs (it adds no entry), and **no live or retained entry is ever
//! evicted to make room**: its counter is the only record of how far the key has sent, and evicting it
//! would let the key restart at index 0 and repeat nonces (RFC 7714 §8). The check runs under the
//! install mutex, on the control path only. A restore whose blob would take the ledger past the cap is
//! refused whole: importing part of it would leave the rest of its keys with no floor under them.
//!
//! **HA.** [`SrtcpLedger::checkpoint`] and [`SrtcpLedger::import`] carry the counters across a failover
//! (the `checkpoint_srtcp_indices` and `restore_srtcp_indices` verbs). Every entry is exported,
//! including a key that is installed and has sent nothing. The primary keeps sending after the
//! checkpoint, so a standby starts a margin past it, and that is only sound if the primary never sends
//! that far: so **once a checkpoint has been taken each entry has a lease**, its checkpointed index plus
//! the margin. A counter that has used half of its window since the checkpoint is *due*
//! ([`SrtcpLedger::take_due`], reported as the `srtcp_checkpoint_due` event), and a counter that reaches
//! the lease refuses to seal until the next checkpoint extends it. A key installed after the first
//! checkpoint is leased from index 0, since no checkpoint knows it. Before any checkpoint there is no
//! lease and nothing is refused. A standby that imports a ledger leases from the counter it seeded.
//! With no restored ledger a standby knows nothing of what the primary sent: the controller must issue
//! fresh keys (RFC 7714 §8).
//!
//! **Keys the checkpoint does not list.** The primary caps every key installed after its first
//! checkpoint at index 0 plus the margin (it leases it from creation), so a key absent from a blob has
//! sent below `unlisted_ceiling` (the margin, or what the last standby seeded). A standby that restores
//! a blob therefore raises every key it already holds that the blob does not list to that ceiling, and
//! seeds every key installed later at it with a lease a margin above. The blob carries the ceiling so
//! that a chain of failovers stays sound.
//!
//! **Concurrency.** The per-packet path is the counter alone (`SendIndex`: index and lease in one
//! atomic word). Installing a key and taking or restoring a checkpoint are control-path operations and
//! are serialised by one ledger-wide `std::sync::Mutex` held for a few non-awaiting steps and never
//! across an `.await`, so a key installed during a checkpoint is either in it or leased from its first
//! index, never published unleased and missing.

use dashmap::DashMap;
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SendIndex, FINGERPRINT_LEN, MAX_SEND_INDEX};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The default cap on entries: one per distinct key material. An entry costs about 150 bytes: the
/// map slot (20 byte fingerprint padded to 24, the 24 byte `Entry`, hashbrown control byte and
/// load-factor slack, about 90 bytes) plus the 32 byte allocation behind the shared `SendIndex` (an
/// `Arc` of two counts and one `AtomicU64`). 100 000 entries is therefore about 15 MB, far below any
/// realistic count of live client keys (a seat holds one or two), and a full checkpoint of it is
/// about 3.5 MB. A deployment with more simultaneous keys raises it (`srtcp_ledger_max_entries`).
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// A key's install was refused because the ledger holds its maximum number of entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerFull {
    /// Entries the ledger holds.
    pub entries: usize,
    /// The cap (`srtcp_ledger_max_entries`).
    pub max_entries: usize,
}

impl std::fmt::Display for LedgerFull {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the SRTCP send-index ledger is full ({} of {} entries): a new key cannot be installed, and no existing entry is evicted to make room (raise srtcp_ledger_max_entries, or let retention release keys the controller no longer uses)",
            self.entries, self.max_entries
        )
    }
}

impl std::error::Error for LedgerFull {}

/// One key's counter and what the ledger tracks about it.
struct Entry {
    counter: SendIndex,
    /// The index the counter held at the last checkpoint (or restore): where its lease window starts.
    checkpointed: AtomicU32,
    /// The checkpoint-due event for this window was raised.
    notified: AtomicBool,
    /// The second retention first saw nothing holding the entry; 0 while held or unseen.
    unheld_since: AtomicU64,
}

impl Entry {
    fn new() -> Self {
        Self {
            counter: SendIndex::new(),
            checkpointed: AtomicU32::new(0),
            notified: AtomicBool::new(false),
            unheld_since: AtomicU64::new(0),
        }
    }
}

/// One exported counter: a key fingerprint and the next index its key will send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub fingerprint: [u8; FINGERPRINT_LEN],
    pub next_index: u32,
}

/// A checkpoint of the ledger: every counter, and the ceiling below which any key it does not list has
/// sent (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerCheckpoint {
    /// Which checkpoint this is: the controller confirms it by this number once it has stored it.
    /// An opaque token naming this checkpoint, unique across nodes and processes (a random epoch of
    /// this process and a counter): a confirmation must name a checkpoint this node exported.
    pub generation: String,
    pub entries: Vec<LedgerEntry>,
    pub unlisted_ceiling: u32,
}

/// The send-index counters of every key the engine sends SRTCP under.
pub struct SrtcpLedger {
    entries: DashMap<[u8; FINGERPRINT_LEN], Entry>,
    /// Serialises installing a key with taking or restoring a checkpoint. Control path only; the
    /// per-packet take never touches it. A `std` mutex, held for a few non-awaiting steps.
    control: Mutex<()>,
    /// Drop an entry unheld for this many seconds; 0, the default, never drops one.
    retention_secs: AtomicU64,
    /// The lease margin once a checkpoint has been taken or restored; 0 before (no lease anywhere).
    lease_margin: AtomicU32,
    /// Where a key installed from now on starts: 0 on a primary, the restored ceiling on a standby.
    new_key_start: AtomicU32,
    /// The client that took the last checkpoint, which the due event goes to; `u64::MAX` for none.
    owner: AtomicU64,
    /// The generation of the last checkpoint taken, and of the last one whose lease is in force
    /// (the first takes effect at export; later ones only when confirmed). Under the control lock.
    generations: Mutex<Generations>,
    /// Seals refused because a counter reached its lease.
    lease_refused: AtomicU64,
    /// The most entries the ledger holds; a new key past it is refused.
    max_entries: AtomicUsize,
    /// New keys (or whole restores) refused at the cap.
    install_refused: AtomicU64,
}

/// Which checkpoints exist and which of them bounds the leases.
struct Generations {
    /// A random number of this process: part of every token, so that a token from another node (whose
    /// own counter may coincide) can never be taken for this node's.
    epoch: u64,
    taken: u32,
    confirmed: u32,
    /// This node restored a ledger: it has no send window at all until one of its own exports is
    /// confirmed (no checkpoint of its own has told a later standby how far it may go).
    restored: bool,
    /// One of its own exports has been confirmed since the restore: its window is open.
    window_open: bool,
    /// The counters of the recent checkpoints not yet superseded by a confirmation, by generation.
    exports: Vec<(u32, Vec<LedgerEntry>)>,
}

impl Default for Generations {
    fn default() -> Self {
        let mut bytes = [0u8; 8];
        if getrandom::fill(&mut bytes).is_err() {
            // Only uniqueness matters, not secrecy: the clock and the address of a local will do.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos() as u64);
            bytes = (nanos ^ u64::from(std::process::id()).rotate_left(32)).to_be_bytes();
        }
        Self {
            epoch: u64::from_be_bytes(bytes),
            taken: 0,
            confirmed: 0,
            restored: false,
            window_open: false,
            exports: Vec::new(),
        }
    }
}

impl Generations {
    fn token(&self, number: u32) -> String {
        format!("{:016x}-{number}", self.epoch)
    }
}

/// How many unconfirmed checkpoints are remembered for a confirmation to find.
const REMEMBERED_EXPORTS: usize = 8;

impl Default for SrtcpLedger {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            control: Mutex::new(()),
            retention_secs: AtomicU64::new(0),
            lease_margin: AtomicU32::new(0),
            new_key_start: AtomicU32::new(0),
            owner: AtomicU64::new(u64::MAX),
            generations: Mutex::new(Generations::default()),
            lease_refused: AtomicU64::new(0),
            max_entries: AtomicUsize::new(DEFAULT_MAX_ENTRIES),
            install_refused: AtomicU64::new(0),
        }
    }
}

impl SrtcpLedger {
    fn control(&self) -> MutexGuard<'_, ()> {
        // The guarded state is the atomics themselves, so a panic elsewhere leaves nothing to repair.
        self.control.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hold the control lock (tests interleave operations around it).
    #[cfg(test)]
    fn hold_control(&self) -> MutexGuard<'_, ()> {
        self.control()
    }

    /// Drop entries that nothing has held for `secs` seconds; `0` (the default) never drops one. Only
    /// safe at or above the controller's enforced key lifetime: a key reused after its entry is
    /// dropped repeats nonces (RFC 7714 §8).
    pub fn set_retention_secs(&self, secs: u64) {
        self.retention_secs.store(secs, Ordering::Relaxed);
    }

    /// Cap the ledger at `max_entries` entries (see the module docs). Lowering it below the current
    /// count evicts nothing: it only refuses new keys until retention has released enough.
    pub fn set_max_entries(&self, max_entries: usize) {
        self.max_entries.store(max_entries, Ordering::Relaxed);
    }

    /// The cap on entries.
    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries.load(Ordering::Relaxed)
    }

    /// Installs refused at the cap since start.
    #[must_use]
    pub fn install_refused(&self) -> u64 {
        self.install_refused.load(Ordering::Relaxed)
    }

    /// Count and log a refusal at the cap. Called with the control lock held.
    fn refuse(&self, what: &str) -> LedgerFull {
        let refused = LedgerFull {
            entries: self.entries.len(),
            max_entries: self.max_entries(),
        };
        self.install_refused.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            target: "siphon_rtp::media",
            entries = refused.entries,
            max_entries = refused.max_entries,
            "SRTCP send-index ledger is full: {what} refused; no entry is evicted (RFC 7714 section 8)"
        );
        refused
    }

    /// Install `keys`: give each one a counter, creating the entries of keys the ledger has not seen.
    /// This is the admission point of every verb that carries SRTCP keys, so it runs before the keys
    /// reach a room, a seat or a floor leg. A key already held adds no entry and so always installs; if
    /// the new keys would take the ledger past its cap, **none** is created and the whole set is
    /// refused ([`LedgerFull`]). Never evicts (RFC 7714 §8). Control path only; serialised with
    /// checkpoints by the install mutex.
    ///
    /// # Errors
    /// [`LedgerFull`] when the set holds more new keys than the cap leaves room for.
    pub fn reserve(&self, keys: &[FloorMasterKey]) -> Result<(), LedgerFull> {
        let _control = self.control();
        let mut fresh: Vec<[u8; FINGERPRINT_LEN]> = Vec::new();
        for key in keys {
            let fingerprint = key.fingerprint();
            if !self.entries.contains_key(&fingerprint) && !fresh.contains(&fingerprint) {
                fresh.push(fingerprint);
            }
        }
        if self.entries.len().saturating_add(fresh.len()) > self.max_entries() {
            return Err(self.refuse("a new key install"));
        }
        for fingerprint in fresh {
            self.entries.insert(fingerprint, self.new_entry());
        }
        for key in keys {
            if let Some(entry) = self.entries.get(&key.fingerprint()) {
                entry.unheld_since.store(0, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// A new entry: starts where a key installed now must (0 on a primary), and under a lease regime
    /// is leased from its first index. Called with the control lock held.
    fn new_entry(&self) -> Entry {
        let entry = Entry::new();
        let margin = self.lease_margin.load(Ordering::Acquire);
        if margin > 0 {
            let start = self.new_key_start.load(Ordering::Acquire);
            // A node that restored a ledger has no window until one of its own exports is confirmed.
            let window = if self.window_closed() { 0 } else { margin };
            entry.counter.seed(start, start.saturating_add(window));
            entry.checkpointed.store(start, Ordering::Relaxed);
        }
        entry
    }

    /// Whether this node restored a ledger and none of its own exports has been confirmed since.
    fn window_closed(&self) -> bool {
        let generations = self
            .generations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        generations.restored && !generations.window_open
    }

    /// The counter of `key`, created for a key not seen before. Called when a protection takes a key (a
    /// join, a rekey), never per packet, and serialised with checkpoints: under a lease regime the new
    /// counter is leased before it is published, so no checkpoint can miss a key that then sends
    /// unbounded. An installed key has an entry, and a checkpoint carries it, before it sends anything.
    ///
    /// Every verb reserves its keys first ([`Self::reserve`]), so a key arriving here has an entry. One
    /// that does not, and would exceed the cap, gets a counter that is **already exhausted and not
    /// stored**: it can never seal, so it can never repeat a nonce, and the refusal is counted and
    /// logged (fail closed: never an unbounded entry, never a counter that restarts at 0).
    #[must_use]
    pub fn counter_for(&self, key: &FloorMasterKey) -> SendIndex {
        let _control = self.control();
        let fingerprint = key.fingerprint();
        if !self.entries.contains_key(&fingerprint) && self.entries.len() >= self.max_entries() {
            self.refuse("a key that was not reserved");
            let counter = SendIndex::new();
            counter.raise_to(u32::MAX);
            return counter;
        }
        let entry = self
            .entries
            .entry(fingerprint)
            .or_insert_with(|| self.new_entry());
        entry.unheld_since.store(0, Ordering::Relaxed);
        entry.counter.clone()
    }

    /// Take a checkpoint: every counter, sent under or not, each read in one atomic step, numbered by a
    /// new generation. **The lease only follows what the controller has stored**: the first checkpoint's
    /// lease (each counter's index plus `margin`) takes effect at export, since a standby holds that
    /// blob or nothing at all (and nothing is the fresh-keys case); a later checkpoint does not move
    /// any lease until [`Self::confirm`] says the controller stored it, so that a lost reply leaves the
    /// primary capped at the blob the standby actually has. `owner` is the client the checkpoint-due
    /// event is for.
    #[must_use]
    pub fn checkpoint(&self, margin: u32, owner: Option<u64>) -> LedgerCheckpoint {
        let _control = self.control();
        let mut generations = self
            .generations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The first checkpoint's lease applies at export only for a node that never restored a ledger:
        // a restored node has no window until one of its own exports is confirmed.
        let first = generations.taken == 0 && !generations.restored;
        generations.taken += 1;
        let number = generations.taken;
        let generation = generations.token(number);
        self.lease_margin.store(margin.max(1), Ordering::Release);
        if let Some(owner) = owner {
            self.owner.store(owner, Ordering::Relaxed);
        }
        let mut entries: Vec<LedgerEntry> = self
            .entries
            .iter()
            .map(|entry| {
                let next = if first {
                    let next = entry.counter.checkpoint(margin);
                    entry.checkpointed.store(next, Ordering::Relaxed);
                    entry.notified.store(false, Ordering::Relaxed);
                    next
                } else {
                    entry.counter.next()
                };
                LedgerEntry {
                    fingerprint: *entry.key(),
                    next_index: next,
                }
            })
            .collect();
        entries.sort_by_key(|entry| entry.fingerprint);
        if first {
            generations.confirmed = number;
        } else {
            generations.exports.push((number, entries.clone()));
            if generations.exports.len() > REMEMBERED_EXPORTS {
                generations.exports.remove(0);
            }
        }
        LedgerCheckpoint {
            generation,
            entries,
            unlisted_ceiling: self
                .new_key_start
                .load(Ordering::Acquire)
                .saturating_add(margin),
        }
    }

    /// The controller has durably stored checkpoint `generation`: every counter in it is now leased to
    /// its index in that checkpoint plus `margin`, and its window starts there. A generation older than
    /// the last confirmed one is ignored (a lease never shortens, and the newer blob is at or above it).
    /// Returns whether it was applied.
    ///
    /// # Errors
    /// A generation that was never taken, or whose export is no longer remembered.
    pub fn confirm(&self, token: &str, margin: u32) -> Result<bool, String> {
        let _control = self.control();
        let mut generations = self
            .generations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let generation = token
            .split_once('-')
            .filter(|(epoch, _)| *epoch == format!("{:016x}", generations.epoch))
            .and_then(|(_, number)| number.parse::<u32>().ok())
            .ok_or_else(|| {
                format!("SRTCP index checkpoint {token:?} was not exported by this engine")
            })?;
        if generation <= generations.confirmed {
            return Ok(false);
        }
        let Some(position) = generations
            .exports
            .iter()
            .position(|(known, _)| *known == generation)
        else {
            return Err(format!("no SRTCP index checkpoint {token:?} is pending"));
        };
        let (_, exported) = generations.exports.swap_remove(position);
        for entry in &exported {
            if let Some(slot) = self.entries.get(&entry.fingerprint) {
                slot.counter
                    .lease_to(entry.next_index.saturating_add(margin));
                slot.checkpointed
                    .fetch_max(entry.next_index, Ordering::Relaxed);
                slot.notified.store(false, Ordering::Relaxed);
            }
        }
        generations.confirmed = generation;
        generations.window_open |= generations.restored;
        generations.exports.retain(|(known, _)| *known > generation);
        Ok(true)
    }

    /// Seed from a checkpoint: each listed counter `margin` past its index and leased a further
    /// `margin`; each key already held but not listed raised to the checkpoint's `unlisted_ceiling`
    /// (the primary capped any key installed after its first checkpoint below it) and leased a margin
    /// above; and every key installed later starts at the ceiling with the same lease. A counter never
    /// lowers, so importing is safe at any time and in any order. A margin that would pass the last
    /// index leaves the key exhausted: it sends nothing until the controller replaces it (RFC 7714
    /// §9.4). Returns how many listed entries were applied.
    ///
    /// # Errors
    /// [`LedgerFull`] when the blob lists more keys the ledger does not hold than the cap leaves room
    /// for. The **whole** blob is then refused and nothing is changed: importing part of it would
    /// leave the rest of its keys without the floor the standby needs for them (RFC 7714 §8).
    pub fn import(&self, checkpoint: &LedgerCheckpoint, margin: u32) -> Result<usize, LedgerFull> {
        let _control = self.control();
        let fresh = checkpoint
            .entries
            .iter()
            .map(|entry| entry.fingerprint)
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|fingerprint| !self.entries.contains_key(fingerprint))
            .count();
        if self.entries.len().saturating_add(fresh) > self.max_entries() {
            return Err(self.refuse("a restore"));
        }
        self.lease_margin.store(margin.max(1), Ordering::Release);
        {
            // A standby may restore the last confirmed blob or a newer unconfirmed one: both are at or
            // above what the primary was capped at, so either is safe to seed from. But it seeds a
            // counter and *no send window*: every lease equals the seeded counter until one of this
            // node's own exports is confirmed, because nothing yet tells a later standby how far
            // this node went (two standbys restoring one blob would otherwise both send from it).
            let mut generations = self
                .generations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            generations.restored = true;
            generations.window_open = false;
        }
        let ceiling = checkpoint.unlisted_ceiling;
        self.new_key_start.fetch_max(ceiling, Ordering::AcqRel);
        let listed: HashSet<[u8; FINGERPRINT_LEN]> = checkpoint
            .entries
            .iter()
            .map(|entry| entry.fingerprint)
            .collect();
        for entry in &checkpoint.entries {
            let slot = self
                .entries
                .entry(entry.fingerprint)
                .or_insert_with(Entry::new);
            let start = entry.next_index.saturating_add(margin);
            slot.counter.seed(start, start);
            slot.checkpointed.fetch_max(start, Ordering::Relaxed);
            slot.notified.store(false, Ordering::Relaxed);
        }
        for slot in self
            .entries
            .iter()
            .filter(|slot| !listed.contains(slot.key()))
        {
            slot.counter.seed(ceiling, ceiling);
            slot.checkpointed.fetch_max(ceiling, Ordering::Relaxed);
            slot.notified.store(false, Ordering::Relaxed);
        }
        Ok(checkpoint.entries.len())
    }

    /// How many counters have used half of their lease window since the checkpoint and have not been
    /// reported: each is reported once per window (the next checkpoint opens a new one). The engine
    /// turns a non-zero count into the `srtcp_checkpoint_due` event.
    pub fn take_due(&self) -> usize {
        let margin = self.lease_margin.load(Ordering::Acquire);
        if margin == 0 {
            return 0;
        }
        let half = margin / 2;
        self.entries
            .iter()
            .filter(|entry| {
                entry
                    .counter
                    .next()
                    .saturating_sub(entry.checkpointed.load(Ordering::Relaxed))
                    >= half
                    && !entry.notified.swap(true, Ordering::Relaxed)
            })
            .count()
    }

    /// The client that took the last checkpoint.
    #[must_use]
    pub fn owner(&self) -> Option<u64> {
        let owner = self.owner.load(Ordering::Relaxed);
        (owner != u64::MAX).then_some(owner)
    }

    /// Count a seal refused at a lease.
    pub fn note_lease_refused(&self) {
        self.lease_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Seals refused at a lease since start.
    #[must_use]
    pub fn lease_refused(&self) -> u64 {
        self.lease_refused.load(Ordering::Relaxed)
    }

    /// Run the opt-in retention clock at `now_secs`: drop an entry nothing has held for the configured
    /// time, unless its index is exhausted. With retention 0 (the default) nothing is ever dropped.
    /// Returns how many were dropped.
    pub fn sweep(&self, now_secs: u64) -> usize {
        let retention = self.retention_secs.load(Ordering::Relaxed);
        if retention == 0 {
            return 0;
        }
        let _control = self.control();
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            // The ledger's own handle is one holder; a protection holds another.
            if entry.counter.holders() > 1 || entry.counter.next() > MAX_SEND_INDEX {
                entry.unheld_since.store(0, Ordering::Relaxed);
                return true;
            }
            let since = entry.unheld_since.load(Ordering::Relaxed);
            if since == 0 {
                entry.unheld_since.store(now_secs.max(1), Ordering::Relaxed);
                return true;
            }
            now_secs.saturating_sub(since) < retention
        });
        before.saturating_sub(self.entries.len())
    }

    /// Keys with a counter.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no key has a counter.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use siphon_rtp_srtp::srtcp_gcm::SendRefused;
    use std::sync::Arc;

    const MARGIN: u32 = 1000;

    fn key(mki: u32, seed: u8) -> FloorMasterKey {
        FloorMasterKey::from_salt_96(mki, [seed; 16], &[seed ^ 0x5A; 12])
    }

    fn drain(counter: &SendIndex, count: u32) {
        for _ in 0..count {
            counter.take().unwrap();
        }
    }

    fn listed(checkpoint: &LedgerCheckpoint, key: &FloorMasterKey) -> Option<u32> {
        checkpoint
            .entries
            .iter()
            .find(|entry| entry.fingerprint == key.fingerprint())
            .map(|entry| entry.next_index)
    }

    #[test]
    fn one_key_has_one_counter_whoever_asks_and_whatever_its_mki() {
        let ledger = SrtcpLedger::default();
        let first = ledger.counter_for(&key(1, 7));
        let second = ledger.counter_for(&key(99, 7));
        assert_eq!(first.take(), Ok(0));
        assert_eq!(second.take(), Ok(1), "the IV does not know the MKI");
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.counter_for(&key(1, 8)).take(),
            Ok(0),
            "another key, another space"
        );
    }

    #[test]
    fn a_key_that_is_installed_and_has_sent_nothing_is_still_checkpointed_and_restored() {
        let primary = SrtcpLedger::default();
        let installed = primary.counter_for(&key(1, 7));
        let sent = primary.counter_for(&key(2, 9));
        drain(&sent, 5);
        let exported = primary.checkpoint(MARGIN, Some(1));
        assert_eq!(
            listed(&exported, &key(1, 7)),
            Some(0),
            "the unused key is in it"
        );
        // The key then sends once on the primary, which fails: the standby knows only the checkpoint.
        installed.take().unwrap();
        let standby = SrtcpLedger::default();
        standby.import(&exported, MARGIN).unwrap();
        assert_eq!(
            standby.counter_for(&key(1, 7)).next(),
            MARGIN,
            "0 + margin, not 0"
        );
        assert_eq!(standby.counter_for(&key(2, 9)).next(), 5 + MARGIN);
    }

    #[test]
    fn import_seeds_each_key_with_no_send_window_and_never_lowers_a_counter() {
        let primary = SrtcpLedger::default();
        drain(&primary.counter_for(&key(1, 7)), 5);
        let exported = primary.checkpoint(MARGIN, None);
        let standby = SrtcpLedger::default();
        assert_eq!(standby.import(&exported, MARGIN), Ok(1));
        let counter = standby.counter_for(&key(1, 7));
        assert_eq!(counter.next(), 5 + MARGIN);
        assert_eq!(
            counter.lease(),
            Some(5 + MARGIN),
            "no window: the lease is the seeded counter"
        );
        assert_eq!(counter.take(), Err(SendRefused::LeaseReached));
        // An older checkpoint, or the same one twice, lowers nothing.
        standby.import(&exported, 0).unwrap();
        standby.import(&exported, 10).unwrap();
        assert_eq!(counter.next(), 5 + MARGIN);
        // Past the last index the key is exhausted, never wrapped.
        let near_end = LedgerCheckpoint {
            generation: "x-1".to_string(),
            entries: vec![LedgerEntry {
                fingerprint: key(3, 3).fingerprint(),
                next_index: MAX_SEND_INDEX - 3,
            }],
            unlisted_ceiling: 0,
        };
        standby.import(&near_end, 1 << 16).unwrap();
        assert_eq!(
            standby.counter_for(&key(3, 3)).take(),
            Err(SendRefused::Exhausted)
        );
    }

    #[test]
    fn there_is_no_lease_until_a_checkpoint_is_taken() {
        let ledger = SrtcpLedger::default();
        let counter = ledger.counter_for(&key(1, 1));
        assert_eq!(counter.lease(), None);
        drain(&counter, 10_000);
        assert_eq!(ledger.take_due(), 0, "nothing is due with no checkpoint");
        assert_eq!(counter.take(), Ok(10_000), "HA unused: today's behaviour");
    }

    #[test]
    fn a_counter_that_reaches_its_lease_refuses_until_the_next_checkpoint_extends_it() {
        let ledger = SrtcpLedger::default();
        let counter = ledger.counter_for(&key(1, 1));
        drain(&counter, 10);
        let _ = ledger.checkpoint(MARGIN, Some(3));
        assert_eq!(counter.lease(), Some(10 + MARGIN));
        drain(&counter, MARGIN);
        assert_eq!(
            counter.take(),
            Err(SendRefused::LeaseReached),
            "never past the lease"
        );
        assert_eq!(counter.next(), 10 + MARGIN);
        let exported = ledger.checkpoint(MARGIN, None);
        assert_eq!(listed(&exported, &key(1, 1)), Some(10 + MARGIN));
        assert_eq!(
            counter.take(),
            Err(SendRefused::LeaseReached),
            "an export alone extends nothing: the controller may not have stored it"
        );
        assert_eq!(ledger.confirm(&exported.generation, MARGIN), Ok(true));
        assert_eq!(counter.lease(), Some(10 + 2 * MARGIN));
        assert_eq!(counter.take(), Ok(10 + MARGIN));
        assert_eq!(
            ledger.owner(),
            Some(3),
            "a checkpoint without an owner keeps the last one"
        );
    }

    #[test]
    fn a_counter_is_due_once_at_half_its_window_and_again_only_after_a_checkpoint() {
        let ledger = SrtcpLedger::default();
        let busy = ledger.counter_for(&key(1, 1));
        let idle = ledger.counter_for(&key(2, 2));
        let _ = ledger.checkpoint(MARGIN, Some(1));
        drain(&busy, MARGIN / 2 - 1);
        assert_eq!(ledger.take_due(), 0);
        drain(&busy, 1);
        assert_eq!(ledger.take_due(), 1, "the busy key crossed half its window");
        assert_eq!(ledger.take_due(), 0, "once per crossing");
        drain(&busy, 100);
        assert_eq!(ledger.take_due(), 0);
        let second = ledger.checkpoint(MARGIN, None);
        ledger.confirm(&second.generation, MARGIN).unwrap();
        drain(&busy, MARGIN / 2);
        drain(&idle, MARGIN / 2);
        assert_eq!(ledger.take_due(), 2, "a new window, two keys");
    }

    #[test]
    fn the_first_checkpoints_lease_takes_effect_at_export() {
        // A standby holds that blob or nothing: so the primary is capped at it from the start.
        let ledger = SrtcpLedger::default();
        let counter = ledger.counter_for(&key(1, 1));
        drain(&counter, 4);
        let first = ledger.checkpoint(MARGIN, Some(1));
        assert!(first.generation.ends_with("-1"));
        assert_eq!(counter.lease(), Some(4 + MARGIN));
    }

    #[test]
    fn a_later_export_moves_no_lease_until_it_is_confirmed_and_a_stale_confirm_is_ignored() {
        let ledger = SrtcpLedger::default();
        let counter = ledger.counter_for(&key(1, 1));
        drain(&counter, 4);
        let g1 = ledger.checkpoint(MARGIN, Some(1));
        drain(&counter, 100);
        let g2 = ledger.checkpoint(MARGIN, None);
        assert!(g1.generation.ends_with("-1") && g2.generation.ends_with("-2"));
        assert_eq!(
            counter.lease(),
            Some(4 + MARGIN),
            "g2 exported, not confirmed: g1 still bounds"
        );
        drain(&counter, MARGIN - 100);
        assert_eq!(
            counter.take(),
            Err(SendRefused::LeaseReached),
            "refused at g1 + margin"
        );
        assert_eq!(ledger.confirm(&g2.generation, MARGIN), Ok(true));
        assert_eq!(
            counter.lease(),
            Some(104 + MARGIN),
            "g2's index plus margin"
        );
        assert_eq!(counter.take(), Ok(4 + MARGIN));
        // The controller's late confirmation of the older generation changes nothing.
        assert_eq!(ledger.confirm(&g1.generation, MARGIN), Ok(false));
        assert_eq!(counter.lease(), Some(104 + MARGIN));
        assert_eq!(
            ledger.confirm(&g2.generation, MARGIN),
            Ok(false),
            "and a repeat is idempotent"
        );
        let epoch = g1.generation.split_once('-').unwrap().0;
        assert!(
            ledger.confirm(&format!("{epoch}-9"), MARGIN).is_err(),
            "a generation never taken is an error"
        );
        assert!(ledger.confirm("garbage", MARGIN).is_err());
    }

    #[test]
    fn a_checkpoint_whose_reply_was_lost_never_lets_the_primary_past_what_the_standby_holds() {
        // The standby holds g1 (key at 0). g2 is exported but the controller never stores it, so it is
        // never confirmed; the primary sends until it is refused and then fails.
        let primary = SrtcpLedger::default();
        let on_primary = primary.counter_for(&key(1, 1));
        let g1 = primary.checkpoint(MARGIN, Some(1));
        drain(&on_primary, 300);
        let _g2_lost = primary.checkpoint(MARGIN, None);
        let mut issued = Vec::new();
        while let Ok(index) = on_primary.take() {
            issued.push(index);
        }
        let highest = *issued.last().unwrap();
        assert_eq!(highest, MARGIN - 1, "capped at g1 + margin");
        // The standby restores g1 and starts sending.
        let standby = SrtcpLedger::default();
        standby.import(&g1, MARGIN).unwrap();
        let on_standby = standby.counter_for(&key(1, 1));
        assert!(
            on_standby.next() > highest,
            "{} repeats an index the primary sent",
            on_standby.next()
        );
        assert_eq!(
            on_standby.take(),
            Err(SendRefused::LeaseReached),
            "and it may not send yet"
        );
    }

    #[test]
    fn a_standby_may_restore_a_newer_unconfirmed_blob_and_stays_above_the_primary() {
        let primary = SrtcpLedger::default();
        let counter = primary.counter_for(&key(1, 1));
        let _g1 = primary.checkpoint(MARGIN, Some(1));
        drain(&counter, 700);
        let g2 = primary.checkpoint(MARGIN, None);
        let mut highest = 0;
        while let Ok(index) = counter.take() {
            highest = index;
        }
        let standby = SrtcpLedger::default();
        standby.import(&g2, MARGIN).unwrap();
        assert!(standby.counter_for(&key(1, 1)).next() > highest);
    }

    #[test]
    fn a_key_installed_after_the_first_checkpoint_is_leased_from_the_margin() {
        let ledger = SrtcpLedger::default();
        let _ = ledger.checkpoint(MARGIN, Some(1));
        let late = ledger.counter_for(&key(5, 5));
        assert_eq!(late.lease(), Some(MARGIN), "no checkpoint knows it yet");
        drain(&late, MARGIN);
        assert_eq!(late.take(), Err(SendRefused::LeaseReached));
    }

    #[test]
    fn a_standby_seeds_a_key_the_blob_does_not_list_at_the_margin_not_at_zero() {
        // The primary checkpoints, installs K and sends index 0, then fails. The blob does not list K.
        let primary = SrtcpLedger::default();
        let blob = primary.checkpoint(MARGIN, Some(1));
        let late = primary.counter_for(&key(9, 9));
        assert_eq!(late.take(), Ok(0));
        assert_eq!(blob.unlisted_ceiling, MARGIN);
        // A fresh standby: K is installed after the restore.
        let standby = SrtcpLedger::default();
        standby.import(&blob, MARGIN).unwrap();
        let on_standby = standby.counter_for(&key(9, 9));
        assert_eq!(
            on_standby.next(),
            MARGIN,
            "0 + margin: past anything the primary could send"
        );
        assert_eq!(
            on_standby.lease(),
            Some(MARGIN),
            "and no send window until its own export is confirmed"
        );
        // A standby that already held K when the blob arrives: raised, not left untouched.
        let early = SrtcpLedger::default();
        let held = early.counter_for(&key(9, 9));
        assert_eq!(held.next(), 0);
        early.import(&blob, MARGIN).unwrap();
        assert_eq!(held.next(), MARGIN);
        assert_eq!(held.lease(), Some(MARGIN));
    }

    #[test]
    fn a_chain_of_failovers_keeps_the_unlisted_ceiling_above_what_the_last_standby_issued() {
        let primary = SrtcpLedger::default();
        let first = primary.checkpoint(MARGIN, Some(1));
        let standby = SrtcpLedger::default();
        standby.import(&first, MARGIN).unwrap();
        // The standby opens its window with a checkpoint of its own that the controller stored.
        let own = standby.checkpoint(MARGIN, Some(1));
        standby.confirm(&own.generation, MARGIN).unwrap();
        // A key installed now starts at the ceiling and may send up to a margin above it.
        let new_key = standby.counter_for(&key(4, 4));
        drain(&new_key, MARGIN);
        let second = standby.checkpoint(MARGIN, Some(1));
        assert_eq!(
            second.unlisted_ceiling,
            2 * MARGIN,
            "above the first standby's lease on new keys"
        );
        let next_standby = SrtcpLedger::default();
        next_standby.import(&second, MARGIN).unwrap();
        assert_eq!(next_standby.counter_for(&key(8, 8)).next(), 2 * MARGIN);
    }

    #[test]
    fn a_node_that_restored_a_ledger_cannot_send_until_its_own_export_is_confirmed() {
        // A holds the key and checkpointed G1 (index 0). B restores G1, then C restores after B.
        let a = SrtcpLedger::default();
        let on_a = a.counter_for(&key(1, 1));
        let g1 = a.checkpoint(MARGIN, Some(1));
        drain(&on_a, 10);
        let b = SrtcpLedger::default();
        b.import(&g1, MARGIN).unwrap();
        let on_b = b.counter_for(&key(1, 1));
        assert_eq!((on_b.next(), on_b.lease()), (MARGIN, Some(MARGIN)));
        assert_eq!(
            on_b.take(),
            Err(SendRefused::LeaseReached),
            "restored: no window"
        );
        // Its own export, not confirmed: still no window.
        let b_export = b.checkpoint(MARGIN, Some(1));
        assert_eq!(
            on_b.take(),
            Err(SendRefused::LeaseReached),
            "an unconfirmed export opens nothing"
        );
        // Confirmed: the window is its export plus the margin.
        assert_eq!(b.confirm(&b_export.generation, MARGIN), Ok(true));
        assert_eq!(on_b.lease(), Some(2 * MARGIN));
        let mut sent_by_b = Vec::new();
        while let Ok(index) = on_b.take() {
            sent_by_b.push(index);
        }
        assert_eq!(
            (sent_by_b[0], *sent_by_b.last().unwrap()),
            (MARGIN, 2 * MARGIN - 1)
        );
        // B fails. C restores B's confirmed blob, the newest stored: it starts above everything B sent.
        let c = SrtcpLedger::default();
        c.import(&b_export, MARGIN).unwrap();
        assert!(c.counter_for(&key(1, 1)).next() > *sent_by_b.last().unwrap());
        // Had B never opened its window, C restoring G1 repeats nothing: B sent nothing.
        let never = SrtcpLedger::default();
        never.import(&g1, MARGIN).unwrap();
        assert_eq!(
            never.counter_for(&key(1, 1)).take(),
            Err(SendRefused::LeaseReached)
        );
    }

    #[test]
    fn a_restored_node_gives_a_key_it_installs_later_no_window_either_until_its_export_is_confirmed(
    ) {
        let a = SrtcpLedger::default();
        let g1 = a.checkpoint(MARGIN, Some(1));
        let b = SrtcpLedger::default();
        b.import(&g1, MARGIN).unwrap();
        let late = b.counter_for(&key(9, 9));
        assert_eq!((late.next(), late.lease()), (MARGIN, Some(MARGIN)));
        assert_eq!(late.take(), Err(SendRefused::LeaseReached));
        let export = b.checkpoint(MARGIN, None);
        b.confirm(&export.generation, MARGIN).unwrap();
        assert_eq!(
            late.lease(),
            Some(2 * MARGIN),
            "the confirmed export listed it"
        );
        assert_eq!(late.take(), Ok(MARGIN));
        // A key installed after the window opened is leased from the ceiling as on a primary.
        let after = b.counter_for(&key(10, 10));
        assert_eq!((after.next(), after.lease()), (MARGIN, Some(2 * MARGIN)));
    }

    #[test]
    fn a_confirmation_from_another_node_is_refused_even_when_the_counters_coincide() {
        // A exports G2 and fails before it is confirmed. B restores G1 and exports its own second
        // checkpoint. A's delayed confirmation reaches B.
        let a = SrtcpLedger::default();
        let on_a = a.counter_for(&key(1, 1));
        let g1 = a.checkpoint(MARGIN, Some(1));
        drain(&on_a, 40);
        let a_g2 = a.checkpoint(MARGIN, None);
        let b = SrtcpLedger::default();
        b.import(&g1, MARGIN).unwrap();
        let b_first = b.checkpoint(MARGIN, Some(1));
        b.confirm(&b_first.generation, MARGIN).unwrap();
        let b_second = b.checkpoint(MARGIN, None);
        let number = |token: &str| token.split_once('-').unwrap().1.to_string();
        assert_eq!(
            number(&a_g2.generation),
            number(&b_second.generation),
            "the counters coincide"
        );
        assert_ne!(a_g2.generation, b_second.generation, "the tokens do not");
        let lease_before = b.counter_for(&key(1, 1)).lease();
        let refused = b.confirm(&a_g2.generation, MARGIN);
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(
            b.counter_for(&key(1, 1)).lease(),
            lease_before,
            "nothing moved"
        );
        assert_eq!(b.confirm(&b_second.generation, MARGIN), Ok(true));
    }

    #[test]
    fn a_take_racing_the_first_lease_cannot_hand_out_the_standbys_first_index() {
        // The race the lease must survive, forced step by step: a taker reads the unleased state and
        // pauses, the checkpoint exports N and leases to N + margin, the senders use the window up,
        // and the paused taker commits.
        let ledger = SrtcpLedger::default();
        let counter = ledger.counter_for(&key(1, 1));
        drain(&counter, 5);
        let paused = counter.snapshot();
        let exported = ledger.checkpoint(MARGIN, Some(1));
        let n = listed(&exported, &key(1, 1)).unwrap();
        drain(&counter, MARGIN);
        assert_eq!(
            counter.commit_take(paused),
            Ok(None),
            "its swap fails: the state moved"
        );
        assert_eq!(counter.take(), Err(SendRefused::LeaseReached));
        assert_eq!(
            counter.next(),
            n + MARGIN,
            "the standby's first index was never issued"
        );
    }

    #[test]
    fn an_install_racing_a_checkpoint_is_either_in_the_blob_or_leased_from_its_first_index() {
        // Forced: the ledger is held (a checkpoint in progress) while a key is installed on another
        // thread. The install waits; when the checkpoint is done it sees the lease regime.
        let ledger = Arc::new(SrtcpLedger::default());
        let guard = ledger.hold_control();
        let (sender, receiver) = std::sync::mpsc::channel();
        let installing = {
            let ledger = ledger.clone();
            std::thread::spawn(move || {
                let counter = ledger.counter_for(&key(6, 6));
                sender.send(counter.lease()).unwrap();
            })
        };
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "the install does not run while a checkpoint holds the ledger"
        );
        // The checkpoint's step under the lock: it sets the regime. Release it, as it would on return.
        ledger.lease_margin.store(MARGIN, Ordering::Release);
        drop(guard);
        let lease = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        installing.join().unwrap();
        assert_eq!(
            lease,
            Some(MARGIN),
            "installed under the regime: leased before it was published"
        );
    }

    #[test]
    fn a_checkpoint_waits_for_an_install_in_progress_and_then_lists_the_key() {
        let ledger = Arc::new(SrtcpLedger::default());
        let guard = ledger.hold_control();
        let (sender, receiver) = std::sync::mpsc::channel();
        let checkpointing = {
            let ledger = ledger.clone();
            std::thread::spawn(move || sender.send(ledger.checkpoint(MARGIN, Some(1))).unwrap())
        };
        assert!(receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        let _ = ledger
            .entries
            .entry(key(7, 7).fingerprint())
            .or_insert_with(Entry::new);
        drop(guard);
        let blob = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        checkpointing.join().unwrap();
        assert_eq!(listed(&blob, &key(7, 7)), Some(0));
    }

    #[test]
    fn by_default_nothing_is_ever_evicted() {
        let ledger = SrtcpLedger::default();
        drop(ledger.counter_for(&key(1, 1)));
        let mut now = 1_000;
        for _ in 0..1000 {
            now += 86_400;
            assert_eq!(ledger.sweep(now), 0);
        }
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn a_configured_retention_evicts_only_unheld_entries_older_than_it() {
        let ledger = SrtcpLedger::default();
        ledger.set_retention_secs(3600);
        let held = ledger.counter_for(&key(1, 1));
        drain(&held, 1);
        drop(ledger.counter_for(&key(2, 2)));
        assert_eq!(ledger.sweep(10_000), 0, "first sighting starts the clock");
        assert_eq!(ledger.sweep(10_000 + 3599), 0, "younger than the retention");
        assert_eq!(
            ledger.sweep(10_000 + 3600),
            1,
            "the unheld one, at the retention"
        );
        assert_eq!(ledger.len(), 1);
        assert_eq!(held.next(), 1);
        assert_eq!(ledger.sweep(10_000 + 100_000), 0, "a held entry stays");
        drop(held);
        ledger.sweep(200_000);
        drop(ledger.counter_for(&key(1, 1)));
        assert_eq!(ledger.sweep(200_000 + 3600), 0);
    }

    #[test]
    fn an_exhausted_entry_is_never_evicted() {
        let ledger = SrtcpLedger::default();
        ledger.set_retention_secs(10);
        let counter = ledger.counter_for(&key(1, 1));
        counter.raise_to(u32::MAX);
        drop(counter);
        ledger.sweep(1);
        assert_eq!(
            ledger.sweep(1_000_000),
            0,
            "dropping it would start the key over at index 0"
        );
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn the_counter_is_lock_free_and_unique_across_threads() {
        let ledger = Arc::new(SrtcpLedger::default());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let counter = ledger.counter_for(&key(1, 1));
            handles.push(std::thread::spawn(move || {
                (0..1000)
                    .filter_map(|_| counter.take().ok())
                    .collect::<Vec<_>>()
            }));
        }
        let mut all: Vec<u32> = handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect();
        all.sort_unstable();
        assert_eq!(
            all,
            (0..4000).collect::<Vec<_>>(),
            "no index twice, none skipped"
        );
    }

    #[test]
    fn installs_succeed_up_to_the_cap_and_the_next_new_key_is_refused_and_counted() {
        let ledger = SrtcpLedger::default();
        ledger.set_max_entries(3);
        for seed in 1..=3 {
            ledger.reserve(&[key(1, seed)]).unwrap();
        }
        assert_eq!(ledger.len(), 3);
        let refused = ledger.reserve(&[key(1, 4)]).unwrap_err();
        assert_eq!(refused.max_entries, 3);
        assert_eq!(ledger.len(), 3, "the refused key took no entry");
        assert_eq!(ledger.install_refused(), 1);
    }

    #[test]
    fn a_key_already_in_the_ledger_installs_at_the_cap_and_keeps_its_counter() {
        let ledger = SrtcpLedger::default();
        ledger.set_max_entries(1);
        let counter = ledger.counter_for(&key(1, 1));
        drain(&counter, 5);
        ledger.reserve(&[key(9, 1)]).unwrap();
        assert_eq!(
            ledger.counter_for(&key(9, 1)).next(),
            5,
            "same material, same counter"
        );
        assert_eq!(ledger.install_refused(), 0);
    }

    #[test]
    fn a_set_with_one_new_key_too_many_is_refused_whole_and_creates_nothing() {
        let ledger = SrtcpLedger::default();
        ledger.set_max_entries(2);
        ledger.reserve(&[key(1, 1)]).unwrap();
        assert!(ledger.reserve(&[key(1, 2), key(2, 3)]).is_err());
        assert_eq!(ledger.len(), 1, "no partial install");
    }

    #[test]
    fn a_full_ledger_never_evicts_a_live_entry_to_make_room() {
        let ledger = SrtcpLedger::default();
        ledger.set_max_entries(1);
        ledger.set_retention_secs(10);
        let held = ledger.counter_for(&key(1, 1));
        drain(&held, 7);
        assert!(ledger.reserve(&[key(1, 2)]).is_err());
        assert_eq!(held.next(), 7);
        assert_eq!(
            ledger.counter_for(&key(1, 1)).next(),
            7,
            "the held key did not restart at 0 (RFC 7714 section 8)"
        );
    }

    #[test]
    fn a_counter_asked_for_past_the_cap_fails_closed_and_is_not_stored() {
        let ledger = SrtcpLedger::default();
        ledger.set_max_entries(1);
        let _first = ledger.counter_for(&key(1, 1));
        let beyond = ledger.counter_for(&key(1, 2));
        assert_eq!(beyond.take(), Err(SendRefused::Exhausted), "it never seals");
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.install_refused(), 1);
    }

    #[test]
    fn a_restore_of_an_over_cap_blob_is_refused_whole() {
        let source = SrtcpLedger::default();
        for seed in 1..=3 {
            drain(&source.counter_for(&key(1, seed)), 4);
        }
        let blob = source.checkpoint(MARGIN, None);
        let standby = SrtcpLedger::default();
        standby.set_max_entries(2);
        standby.reserve(&[key(1, 1)]).unwrap();
        let refused = standby.import(&blob, MARGIN).unwrap_err();
        assert_eq!(refused.max_entries, 2);
        assert_eq!(standby.len(), 1, "nothing was imported");
        assert_eq!(
            standby.counter_for(&key(1, 1)).next(),
            0,
            "the entry it already held was not raised either"
        );
        assert_eq!(standby.install_refused(), 1);
        standby.set_max_entries(3);
        assert_eq!(standby.import(&blob, MARGIN), Ok(3));
    }

    #[test]
    fn a_restore_counts_only_keys_the_ledger_does_not_already_hold() {
        let source = SrtcpLedger::default();
        for seed in 1..=2 {
            drain(&source.counter_for(&key(1, seed)), 4);
        }
        let blob = source.checkpoint(MARGIN, None);
        let standby = SrtcpLedger::default();
        standby.set_max_entries(2);
        standby.reserve(&[key(1, 1), key(1, 2)]).unwrap();
        assert_eq!(standby.import(&blob, MARGIN), Ok(2));
    }

    #[test]
    fn the_default_cap_is_the_documented_constant() {
        assert_eq!(SrtcpLedger::default().max_entries(), DEFAULT_MAX_ENTRIES);
    }
}
