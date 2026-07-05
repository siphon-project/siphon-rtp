//! Pure-Rust SRTP (RFC 3711) for the SDES bridge legs — `AES_CM_128_HMAC_SHA1_80`.
//!
//! [`SrtpContext`] holds the session keys derived from a master key/salt and protects/unprotects
//! RTP packets: AES Counter-Mode encrypts the payload (header in the clear), HMAC-SHA1 truncated to
//! 80 bits authenticates `header || ciphertext || ROC`. The 48-bit packet index (ROC·2¹⁶ + seq) is
//! tracked per SSRC with the RFC 3711 §3.3.1 rollover estimation, and a per-SSRC RFC 3711 §3.3.2
//! sliding-window replay filter rejects a duplicated or too-old index — updated only *after* a packet
//! authenticates, so a forgery can never poison it. Crypto is RustCrypto (pure Rust, zero C).
#![forbid(unsafe_code)]

use std::collections::HashMap;

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub mod kdf;
pub mod leg;
pub mod sdes;
pub mod srtcp;

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
    /// The packet index was already received, or is too old to prove fresh — the RFC 3711 §3.3.2
    /// replay filter discards it. The packet authenticated (or was rejected before auth as an obvious
    /// replay); either way the caller drops it and never forwards it.
    #[error("replayed packet")]
    Replayed,
}

/// The RFC 3711 §3.3.2 replay-window width, in packets. The RFC mandates a receiver window of at
/// least 64; we use exactly 64 so the window is a single `u64` bitmap, keeping the per-packet replay
/// check a handful of branchless integer ops on the hot path.
pub(crate) const REPLAY_WINDOW: u64 = 64;

/// A sliding-window replay filter over a monotone packet index (RFC 3711 §3.3.2), shared by SRTP (the
/// estimated 48-bit index) and SRTCP (the explicit 31-bit index). Bit `j` of `mask` records that the
/// index `top - j` has been received — bit 0 is `top` itself. `seen` stays false until the first index
/// is recorded, so a fresh stream never rejects its own opening packet.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayWindow {
    top: u64,
    mask: u64,
    seen: bool,
}

impl ReplayWindow {
    /// Would `index` be a replay — already recorded, or so old it has fallen out of the window and can
    /// no longer be proven fresh? RFC 3711 §3.3.2 requires both cases to be discarded. Read-only: call
    /// it *before* authenticating (a cheap early reject), then [`record`](Self::record) only *after*
    /// the packet authenticates.
    pub(crate) fn is_replay(&self, index: u64) -> bool {
        if !self.seen || index > self.top {
            return false; // first packet, or strictly newer than anything seen — not a replay
        }
        let delta = self.top - index;
        // Below the window we cannot prove non-replay → discard; inside it, replay iff its bit is set.
        delta >= REPLAY_WINDOW || (self.mask & (1u64 << delta)) != 0
    }

    /// Record `index` as received and slide the window up to it. RFC 3711 §3.3.2: MUST be called only
    /// after the packet authenticates, so a forgery can never advance `top` or set a bit.
    pub(crate) fn record(&mut self, index: u64) {
        if !self.seen {
            *self = Self {
                top: index,
                mask: 1,
                seen: true,
            };
            return;
        }
        if index > self.top {
            let shift = index - self.top;
            self.mask = if shift >= REPLAY_WINDOW {
                1 // the window jumped clear of all prior history
            } else {
                (self.mask << shift) | 1
            };
            self.top = index;
        } else {
            // Older than `top` but inside the window (is_replay rejected anything below it): set its bit.
            self.mask |= 1u64 << (self.top - index);
        }
    }

    /// Anchor the window at `index` with only that index marked received. Used when an HA standby seeds
    /// its replay state from the rollover anchor carried in a checkpoint (RFC 3711 §3.3.1): the
    /// per-index history below the anchor is not carried across the failover, only its top.
    pub(crate) fn anchor(&mut self, index: u64) {
        *self = Self {
            top: index,
            mask: 1,
            seen: true,
        };
    }
}

/// Per-SSRC rollover state.
#[derive(Default, Clone, Copy)]
struct StreamState {
    roc: u32,
    highest_seq: Option<u16>,
    /// RFC 3711 §3.3.2 replay filter over this stream's 48-bit packet index, committed post-auth.
    replay: ReplayWindow,
}

/// A per-SSRC SRTP rollover checkpoint (RFC 3711 §3.3.1): the receiver/sender rollover state that is
/// *estimated from observed packets*, not signalled, and so must be carried across an HA failover.
/// Exported by [`SrtpContext::rollover_state`] and re-applied by [`SrtpContext::seed_stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRollover {
    /// The stream's synchronization source (RFC 3550 §5.1).
    pub ssrc: u32,
    /// The 32-bit rollover counter — how many times the 16-bit RTP sequence has wrapped.
    pub roc: u32,
    /// The highest RTP sequence number processed so far (the rollover anchor), or `None` if no packet
    /// has been seen for this SSRC yet.
    pub highest_seq: Option<u16>,
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
        kdf::derive(
            master_key,
            master_salt,
            kdf::label::RTP_ENCRYPTION,
            &mut session_key,
        );
        kdf::derive(
            master_key,
            master_salt,
            kdf::label::RTP_SALT,
            &mut session_salt,
        );
        kdf::derive(
            master_key,
            master_salt,
            kdf::label::RTP_AUTHENTICATION,
            &mut session_auth,
        );
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

    /// Export the per-SSRC rollover state for an HA checkpoint (order unspecified). This is the only
    /// SRTP state that cannot be recovered by observing packets — everything else re-derives from the
    /// SDES master key — so a warm standby must carry it (RFC 3711 §3.3.1). See [`Self::seed_stream`].
    #[must_use]
    pub fn rollover_state(&self) -> Vec<StreamRollover> {
        self.streams
            .iter()
            .map(|(&ssrc, state)| StreamRollover {
                ssrc,
                roc: state.roc,
                highest_seq: state.highest_seq,
            })
            .collect()
    }

    /// Seed a stream's rollover state from an HA checkpoint, so a standby continues a live stream's
    /// SRTP packet index instead of resetting to `0` — which would compute the wrong ROC (and fail
    /// authentication) once the sequence has wrapped. Overwrites any existing state for the SSRC.
    pub fn seed_stream(&mut self, rollover: StreamRollover) {
        let mut state = StreamState {
            roc: rollover.roc,
            highest_seq: rollover.highest_seq,
            replay: ReplayWindow::default(),
        };
        // Anchor the replay filter at the carried index so the standby immediately rejects a replay of
        // the primary's last-seen packet (RFC 3711 §3.3.2). Only the anchor's top is carried across the
        // failover — the per-index bitmap below it is not — so at most a `REPLAY_WINDOW`-wide span may
        // be re-accepted once after a takeover, which is bounded, receiver-local soft state.
        if let Some(seq) = rollover.highest_seq {
            state
                .replay
                .anchor((u64::from(rollover.roc) << 16) | u64::from(seq));
        }
        self.streams.insert(rollover.ssrc, state);
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

    /// Reject replays, verify the tag, and decrypt an SRTP packet into `out` (cleared first), yielding
    /// the plain RTP. Returns [`SrtpError::Replayed`] for a duplicated/too-old index (RFC 3711 §3.3.2)
    /// and [`SrtpError::AuthFailed`] for a forged/corrupt tag; neither advances the stream state.
    pub fn unprotect(&mut self, srtp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        if srtp.len() < 12 + AUTH_TAG_LEN {
            return Err(SrtpError::TooShort);
        }
        let (authenticated, tag) = srtp.split_at(srtp.len() - AUTH_TAG_LEN);
        let (header_len, ssrc, seq) = parse_rtp_header(authenticated)?;

        // Estimate the index on a *copy* of the stream state so a failed auth never advances it.
        let mut state = self.streams.get(&ssrc).copied().unwrap_or_default();
        let (index, roc) = state.index_for(seq);

        // Replay filter before spending the HMAC: a duplicated or too-old index is discarded without
        // authenticating it (RFC 3711 §3.3.2, in the receiver step order of §3.3). The window itself is
        // recorded only *after* auth (below), so a forged packet can never advance or poison it.
        if state.replay.is_replay(index) {
            return Err(SrtpError::Replayed);
        }

        let expected = auth_tag(&self.session_auth, authenticated, roc);
        if expected.ct_eq(tag).unwrap_u8() != 1 {
            return Err(SrtpError::AuthFailed);
        }
        state.replay.record(index); // mark the index received — only now, post-authentication
        self.streams.insert(ssrc, state); // commit rollover + replay window only after auth succeeds

        out.clear();
        out.extend_from_slice(authenticated);
        let iv = cipher_iv(&self.session_salt, ssrc, index);
        AesCm::new(&self.session_key.into(), &iv.into()).apply_keystream(&mut out[header_len..]);
        Ok(())
    }
}

/// The AES-CM IV for one packet (RFC 3711 §4.1.1): `session_salt·2¹⁶ ⊕ SSRC·2⁶⁴ ⊕ index·2¹⁶`.
pub(crate) fn cipher_iv(salt: &[u8; MASTER_SALT_LEN], ssrc: u32, index: u64) -> [u8; 16] {
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

/// AES-CM encrypt/decrypt `buf` in place under `key` from counter `iv` (the cipher is its own
/// inverse). Shared by SRTP and SRTCP.
pub(crate) fn apply_aes_cm(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    AesCm::new(key.into(), iv.into()).apply_keystream(buf);
}

/// HMAC-SHA1 over `data`, truncated to 80 bits. Shared by SRTP (which passes `header||cipher||ROC`)
/// and SRTCP (which passes the authenticated portion through the SRTCP-index field).
pub(crate) fn hmac_sha1_80(key: &[u8; 20], data: &[u8]) -> [u8; AUTH_TAG_LEN] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; AUTH_TAG_LEN];
    tag.copy_from_slice(&full[..AUTH_TAG_LEN]);
    tag
}

/// HMAC-SHA1-80 over `data || ROC` — the SRTP authentication input (RFC 3711 §4.2).
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
        receiver
            .unprotect(&srtp, &mut recovered)
            .expect("unprotect");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn rollover_state_carries_across_a_context_rebuild() {
        // The HA-failover invariant: after the RTP sequence has wrapped, a standby that rebuilds the
        // SRTP context from the SDES key alone (rollover reset to 0) computes the wrong ROC and fails
        // authentication; seeding it with the exported rollover state keeps the stream decryptable.
        let ssrc = 0xCAFE_1234;
        let mut sender = context();
        let mut scratch = Vec::new();
        // Drive the sequence past a wrap (…65534, 65535, 0) so the rollover counter reaches 1.
        for seq in [65534u16, 65535, 0] {
            sender
                .protect(&rtp(seq, ssrc, 0x11), &mut scratch)
                .expect("protect");
        }
        let state = sender.rollover_state();
        assert_eq!(state.len(), 1);
        let checkpoint = state[0];
        assert_eq!(checkpoint.ssrc, ssrc);
        assert_eq!(checkpoint.roc, 1, "the sequence wrapped once");
        assert_eq!(checkpoint.highest_seq, Some(0));

        // The next packet the primary emits is protected at ROC = 1.
        let mut wire = Vec::new();
        sender
            .protect(&rtp(1, ssrc, 0x11), &mut wire)
            .expect("protect next");

        // A standby seeded with the checkpoint continues the stream…
        let mut seeded = context();
        seeded.seed_stream(checkpoint);
        let mut recovered = Vec::new();
        seeded
            .unprotect(&wire, &mut recovered)
            .expect("seeded standby continues the stream");
        assert_eq!(recovered, rtp(1, ssrc, 0x11));

        // …while a cold rebuild (ROC reset to 0) breaks authentication after the wrap.
        let mut cold = context();
        let mut discard = Vec::new();
        assert_eq!(
            cold.unprotect(&wire, &mut discard),
            Err(SrtpError::AuthFailed),
            "resetting rollover state to zero fails SRTP auth once the sequence has wrapped"
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let mut sender = context();
        let mut receiver = context();
        let mut srtp = Vec::new();
        sender
            .protect(&rtp(1, 0x1234, 0x55), &mut srtp)
            .expect("protect");

        // Flip a ciphertext byte → auth must fail.
        let mut forged = srtp.clone();
        forged[14] ^= 0x01;
        let mut out = Vec::new();
        assert_eq!(
            receiver.unprotect(&forged, &mut out),
            Err(SrtpError::AuthFailed)
        );

        // Flip a tag byte → auth must fail.
        let mut bad_tag = srtp.clone();
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
        let mut receiver = SrtpContext::new(&[0x99u8; 16], &[0x88u8; MASTER_SALT_LEN]);
        let mut srtp = Vec::new();
        sender
            .protect(&rtp(5, 0xAAAA, 0x10), &mut srtp)
            .expect("protect");
        let mut out = Vec::new();
        assert_eq!(
            receiver.unprotect(&srtp, &mut out),
            Err(SrtpError::AuthFailed)
        );
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
            receiver
                .unprotect(&srtp, &mut recovered)
                .expect("unprotect across wrap");
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
            receiver
                .unprotect(&srtp, &mut recovered)
                .expect("unprotect");
            assert_eq!(recovered, plain);
        }
    }

    #[test]
    fn rejects_short_and_bad_version() {
        let mut context = context();
        let mut out = Vec::new();
        assert_eq!(
            context.protect(&[0u8; 8], &mut out),
            Err(SrtpError::TooShort)
        );
        let mut bad = rtp(1, 1, 1);
        bad[0] = 0x40; // version 1
        assert_eq!(context.protect(&bad, &mut out), Err(SrtpError::BadVersion));
    }

    /// Seal one RTP packet with `sender` and return the SRTP bytes — a helper for the replay tests.
    fn seal(sender: &mut SrtpContext, seq: u16, ssrc: u32) -> Vec<u8> {
        let mut wire = Vec::new();
        sender
            .protect(&rtp(seq, ssrc, seq as u8), &mut wire)
            .expect("protect");
        wire
    }

    #[test]
    fn replaying_a_captured_packet_is_rejected() {
        // RFC 3711 §3.3.2: an attacker who re-injects a validly-authenticated packet must be dropped.
        let mut sender = context();
        let mut receiver = context();
        let srtp = seal(&mut sender, 100, 0xFEED);

        let mut out = Vec::new();
        receiver
            .unprotect(&srtp, &mut out)
            .expect("first delivery accepted");
        assert_eq!(
            receiver.unprotect(&srtp, &mut out),
            Err(SrtpError::Replayed),
            "the identical, already-seen packet is a replay"
        );
    }

    #[test]
    fn reordered_packet_within_the_window_is_accepted_once_then_replayed() {
        let mut sender = context();
        let mut receiver = context();
        let ssrc = 0x1357_9BDF;
        let p1 = seal(&mut sender, 1, ssrc);
        let p2 = seal(&mut sender, 2, ssrc);
        let p3 = seal(&mut sender, 3, ssrc);

        let mut out = Vec::new();
        receiver.unprotect(&p1, &mut out).expect("1");
        receiver.unprotect(&p3, &mut out).expect("3 ahead of 2");
        receiver
            .unprotect(&p2, &mut out)
            .expect("the delayed 2 is still inside the window");
        assert_eq!(
            receiver.unprotect(&p2, &mut out),
            Err(SrtpError::Replayed),
            "but a second copy of 2 is a replay"
        );
    }

    #[test]
    fn a_packet_older_than_the_window_is_rejected() {
        let mut sender = context();
        let mut receiver = context();
        let ssrc = 0x2468_ACE0;
        let old = seal(&mut sender, 10, ssrc);

        // Advance the receiver's window well past `old` (more than REPLAY_WINDOW ahead).
        let mut out = Vec::new();
        for seq in 11..=80 {
            let wire = seal(&mut sender, seq, ssrc);
            receiver
                .unprotect(&wire, &mut out)
                .expect("in-order accepted");
        }
        // `old` (index 10) is now 70 behind the top (80) — below the window, so it cannot be proven
        // fresh and MUST be discarded, even though it was never actually delivered.
        assert_eq!(receiver.unprotect(&old, &mut out), Err(SrtpError::Replayed));
    }

    #[test]
    fn a_forgery_does_not_poison_the_replay_window() {
        // The window is recorded only after authentication, so a forged packet cannot pre-claim an
        // index and lock out the genuine one.
        let mut sender = context();
        let mut receiver = context();
        let ssrc = 0xF0F0_F0F0;
        let genuine = seal(&mut sender, 50, ssrc);

        let mut forged = genuine.clone();
        forged[20] ^= 0xFF; // corrupt a ciphertext byte → auth fails
        let mut out = Vec::new();
        assert_eq!(
            receiver.unprotect(&forged, &mut out),
            Err(SrtpError::AuthFailed)
        );
        receiver
            .unprotect(&genuine, &mut out)
            .expect("the genuine packet is still accepted after the forgery");
        assert_eq!(out, rtp(50, ssrc, 50));
    }

    #[test]
    fn replay_state_is_independent_per_ssrc() {
        let mut sender_a = context();
        let mut sender_b = context();
        let mut receiver = context();
        let a = seal(&mut sender_a, 7, 0xAAAA_0000);
        let b = seal(&mut sender_b, 7, 0xBBBB_0000);

        let mut out = Vec::new();
        receiver.unprotect(&a, &mut out).expect("ssrc A seq 7");
        receiver
            .unprotect(&b, &mut out)
            .expect("ssrc B seq 7 is a distinct stream, not a replay");
        assert_eq!(
            receiver.unprotect(&a, &mut out),
            Err(SrtpError::Replayed),
            "but replaying A's seq 7 is still rejected"
        );
    }

    #[test]
    fn the_window_slides_forward_and_evicts_old_indices() {
        let mut sender = context();
        let mut receiver = context();
        let ssrc = 0x9999_9999;
        let first = seal(&mut sender, 1, ssrc);
        let jump = seal(&mut sender, 1 + REPLAY_WINDOW as u16 + 5, ssrc);

        let mut out = Vec::new();
        receiver.unprotect(&first, &mut out).expect("seq 1");
        receiver
            .unprotect(&jump, &mut out)
            .expect("a jump forward slides the window");
        assert_eq!(
            receiver.unprotect(&first, &mut out),
            Err(SrtpError::Replayed),
            "seq 1 is now evicted below the window"
        );
    }

    #[test]
    fn seeding_a_standby_anchors_the_replay_window() {
        // HA takeover: a standby seeded from the primary's rollover rejects a replay of the primary's
        // last-seen packet, yet accepts the next genuine one (RFC 3711 §3.3.1 / §3.3.2).
        let ssrc = 0x0BAD_F00D;
        let mut sender = context();
        let last = seal(&mut sender, 500, ssrc);
        let checkpoint = sender
            .rollover_state()
            .into_iter()
            .find(|state| state.ssrc == ssrc)
            .expect("rollover state for the ssrc");
        assert_eq!(checkpoint.highest_seq, Some(500));

        let mut standby = context();
        standby.seed_stream(checkpoint);
        let mut out = Vec::new();
        assert_eq!(
            standby.unprotect(&last, &mut out),
            Err(SrtpError::Replayed),
            "the primary's last packet, re-delivered to the standby, is a replay"
        );
        let next = seal(&mut sender, 501, ssrc);
        standby
            .unprotect(&next, &mut out)
            .expect("the standby continues the live stream");
        assert_eq!(out, rtp(501, ssrc, 501u16 as u8));
    }

    #[test]
    fn replay_window_boundary_is_exactly_the_width() {
        let mut window = ReplayWindow::default();
        assert!(!window.is_replay(1000), "first index establishes the top");
        window.record(1000);
        assert!(window.is_replay(1000), "the top itself is now a replay");

        // Exactly REPLAY_WINDOW-1 below the top is still inside the window (never seen → fresh)…
        let edge = 1000 - (REPLAY_WINDOW - 1);
        assert!(!window.is_replay(edge));
        // …and one further back has fallen out of the window → too old.
        assert!(window.is_replay(edge - 1));
    }

    #[test]
    fn replay_window_records_slides_and_forgets() {
        let mut window = ReplayWindow::default();
        window.record(10);
        window.record(11);
        window.record(12);
        // A jump clear of the window resets the mask to just the new top.
        window.record(12 + REPLAY_WINDOW + 100);
        assert!(window.is_replay(12), "12 is now far below the window");
        assert!(
            !window.is_replay(12 + REPLAY_WINDOW + 101),
            "a newer index is fresh"
        );
    }
}
