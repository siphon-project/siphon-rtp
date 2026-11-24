//! A secure (`RTP/SAVP`) bridge leg: the four SRTP/SRTCP contexts one SDES leg needs, plus RTP/RTCP
//! demux, so the engine's bridge adapter is delivery-mechanism-agnostic glue.
//!
//! **Key direction is the footgun this type exists to pin down.** On the secure leg the engine
//! offers its *own* `a=crypto` (the **local** key) — the peer decrypts what the engine sends with
//! it, so the engine **encrypts outbound with the local key**. The peer's answer carries *its*
//! `a=crypto` (the **remote** key) — the peer encrypts with it, so the engine **decrypts inbound
//! with the remote key**. Swapping the two yields a leg that authenticates against itself in tests
//! but silently fails against a real peer; [`SecureLeg::new`] fixes the mapping and the tests lock it.
//!
//! RTP vs RTCP on one (possibly muxed) leg is demuxed by the RFC 5761 §4 rule — the unencrypted
//! header byte's packet type in 64–95 marks RTCP — which holds for SRTP/SRTCP too since both leave
//! the header in the clear. It is also correct on a non-muxed leg (RTP on the RTP port still
//! demuxes as RTP), so one path serves both.

use crate::sdes::SrtpKeyMaterial;
use crate::srtcp::SrtcpContext;
use crate::{SrtpContext, SrtpError, StreamRollover};

/// Which media a packet carries, as resolved by [`is_rtcp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// An RTP / SRTP packet (media).
    Rtp,
    /// An RTCP / SRTCP packet (control).
    Rtcp,
}

/// Distinguish RTP from RTCP by the RFC 5761 §4 rule: the packet type (second byte masked with the
/// RTP marker bit) in 64–95 marks RTCP. Works on encrypted packets too — both SRTP and SRTCP leave
/// the relevant header byte in the clear. A packet too short to classify is treated as RTP.
#[must_use]
pub fn is_rtcp(packet: &[u8]) -> bool {
    packet.len() >= 2 && matches!(packet[1] & 0x7F, 64..=95)
}

/// One secure leg's crypto state: inbound (decrypt from peer) and outbound (encrypt to peer)
/// contexts for both RTP and RTCP.
pub struct SecureLeg {
    inbound_rtp: SrtpContext,
    outbound_rtp: SrtpContext,
    inbound_rtcp: SrtcpContext,
    outbound_rtcp: SrtcpContext,
    /// The leg's own output buffer for [`Self::protect_buffered`]: grown once, then reused, so
    /// sealing a packet for a caller that needs no buffer of its own allocates nothing.
    sealed: Vec<u8>,
}

/// The non-recoverable rollover state of a [`SecureLeg`], for an HA checkpoint. Everything else on a
/// leg re-derives from the two SDES keys; only these SRTP rollover counters and the outbound SRTCP
/// index are estimated from observed packets and so must move to a standby (RFC 3711 §3.3.1 / §3.4).
///
/// The **inbound** SRTP rollover keeps decryption of the peer's stream authenticating past a sequence
/// wrap; the **outbound** SRTP rollover keeps our encryption continuous for the far side; the
/// **outbound SRTCP index** stops the standby re-using an index (a replay). Inbound SRTCP needs no
/// state — its index is explicit in each packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecureLegRollover {
    /// Per-SSRC rollover of the inbound (from-peer) SRTP context.
    pub inbound_rtp: Vec<StreamRollover>,
    /// Per-SSRC rollover of the outbound (to-peer) SRTP context.
    pub outbound_rtp: Vec<StreamRollover>,
    /// The outbound SRTCP index to continue from.
    pub outbound_rtcp_index: u32,
}

impl SecureLeg {
    /// Build the leg from the engine's own offered key (`local`) and the peer's answered key
    /// (`remote`). Outbound (to-peer) encrypts with `local`; inbound (from-peer) decrypts with
    /// `remote` — see the module note.
    #[must_use]
    pub fn new(local: &SrtpKeyMaterial, remote: &SrtpKeyMaterial) -> Self {
        Self {
            inbound_rtp: SrtpContext::from_key_material(remote),
            outbound_rtp: SrtpContext::from_key_material(local),
            inbound_rtcp: SrtcpContext::from_key_material(remote),
            outbound_rtcp: SrtcpContext::from_key_material(local),
            sealed: Vec::new(),
        }
    }

    /// Replace the key of only the side(s) that changed, in place: `local` is the new key this leg
    /// **sends** under, `remote` the new key it **receives** under, and `None` leaves a side as it is,
    /// send history included. A side that is rebuilt carries its counters over (the per-SSRC rollover,
    /// and for SRTCP the send index), because a new key does not restart a stream's numbering.
    ///
    /// Keeping the outbound context whenever the sending key is unchanged is what keeps its send
    /// window: a re-offer that changes only the peer's key must not forget which indices this leg
    /// already sent under the key it still uses (RFC 3711 §9.1).
    pub fn rekey(&mut self, local: Option<&SrtpKeyMaterial>, remote: Option<&SrtpKeyMaterial>) {
        if let Some(local) = local {
            let mut outbound = SrtpContext::from_key_material(local);
            for stream in self.outbound_rtp.rollover_state() {
                outbound.seed_stream(stream);
            }
            let mut rtcp = SrtcpContext::from_key_material(local);
            rtcp.set_send_index(self.outbound_rtcp.send_index());
            self.outbound_rtp = outbound;
            self.outbound_rtcp = rtcp;
        }
        if let Some(remote) = remote {
            let mut inbound = SrtpContext::from_key_material(remote);
            for stream in self.inbound_rtp.rollover_state() {
                inbound.seed_stream(stream);
            }
            self.inbound_rtp = inbound;
            self.inbound_rtcp = SrtcpContext::from_key_material(remote);
        }
    }

    /// The highest sequence number this leg has sent for `ssrc`, which is the authority on where that
    /// stream's SRTP index stands.
    #[must_use]
    pub fn highest_sent(&self, ssrc: u32) -> Option<u16> {
        self.outbound_rtp.highest_sequence(ssrc)
    }

    /// Re-key the sides whose key actually changed and leave the others untouched, so a re-offer that
    /// repeats a key keeps the live context (its send window and replay state: RFC 3711 §3.3.2, §9.1)
    /// instead of rebuilding it and forgetting what was sent.
    ///
    /// The key is its master key and salt: a side whose MKI alone changed keeps its context, send
    /// window included, and only the MKI it emits or expects is replaced (RFC 3711 §3.4).
    pub fn adopt(&mut self, local: Option<&SrtpKeyMaterial>, remote: Option<&SrtpKeyMaterial>) {
        if let Some(material) = local.filter(|material| self.outbound_rtp.same_key(material)) {
            self.outbound_rtp.set_mki(material.mki);
            self.outbound_rtcp.set_mki(material.mki);
        }
        if let Some(material) = remote.filter(|material| self.inbound_rtp.same_key(material)) {
            self.inbound_rtp.set_mki(material.mki);
            self.inbound_rtcp.set_mki(material.mki);
        }
        let local = local.filter(|material| !self.outbound_rtp.same_key(material));
        let remote = remote.filter(|material| !self.inbound_rtp.same_key(material));
        self.rekey(local, remote);
    }

    /// Decrypt a packet arriving **from** the secure peer (SRTP or SRTCP, auto-demuxed) into `out`,
    /// returning which it was.
    pub fn unprotect(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<PacketKind, SrtpError> {
        if is_rtcp(packet) {
            self.inbound_rtcp.unprotect(packet, out)?;
            Ok(PacketKind::Rtcp)
        } else {
            self.inbound_rtp.unprotect(packet, out)?;
            Ok(PacketKind::Rtp)
        }
    }

    /// [`Self::protect`] into the leg's own reusable buffer, returned borrowed: the caller copies what
    /// it must own (one allocation of the exact size) and the sealing itself allocates nothing once
    /// the buffer has grown to the largest packet.
    pub fn protect_buffered(&mut self, packet: &[u8]) -> Result<&[u8], SrtpError> {
        let mut sealed = std::mem::take(&mut self.sealed);
        let result = self.protect(packet, &mut sealed);
        self.sealed = sealed;
        result.map(|_| self.sealed.as_slice())
    }

    /// Encrypt a plaintext RTP/RTCP packet going **to** the secure peer into `out`, returning which
    /// it was.
    pub fn protect(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<PacketKind, SrtpError> {
        if is_rtcp(packet) {
            self.outbound_rtcp.protect(packet, out)?;
            Ok(PacketKind::Rtcp)
        } else {
            self.outbound_rtp.protect(packet, out)?;
            Ok(PacketKind::Rtp)
        }
    }

    /// How many packets this leg refused to send because sending them would reuse a keystream: an
    /// RTP `(SSRC, index)` already sent or a sequence jump it cannot number (RFC 3711 §3.3.1, §9.1),
    /// or an SRTCP index space used up (§3.4, §9.2).
    #[must_use]
    pub fn reuse_refusals(&self) -> u64 {
        self.outbound_rtp
            .reuse_refusals()
            .saturating_add(self.outbound_rtcp.exhausted_refusals())
    }

    /// Export the leg's rollover state for an HA checkpoint. See [`SecureLegRollover`].
    #[must_use]
    pub fn rollover_snapshot(&self) -> SecureLegRollover {
        SecureLegRollover {
            inbound_rtp: self.inbound_rtp.rollover_state(),
            outbound_rtp: self.outbound_rtp.rollover_state(),
            outbound_rtcp_index: self.outbound_rtcp.send_index(),
        }
    }

    /// Seed the leg's rollover state from an HA checkpoint (after rebuilding it from the two SDES
    /// keys), so a standby continues both directions' SRTP index instead of resetting to `0`.
    pub fn seed_rollover(&mut self, rollover: &SecureLegRollover) {
        for stream in &rollover.inbound_rtp {
            self.inbound_rtp.seed_stream(*stream);
        }
        for stream in &rollover.outbound_rtp {
            self.outbound_rtp.seed_outbound_stream(*stream);
        }
        self.outbound_rtcp
            .set_send_index(rollover.outbound_rtcp_index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srtcp::SrtcpContext;

    fn key(seed: u8) -> SrtpKeyMaterial {
        SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30 bytes")
    }

    fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x77; 16]);
        packet
    }

    #[test]
    fn adopting_an_unchanged_key_keeps_the_send_window() {
        let mut leg = SecureLeg::new(&key(1), &key(2));
        let mut out = Vec::new();
        leg.protect(&rtp(100, 7), &mut out).expect("sent");
        leg.adopt(Some(&key(1)), Some(&key(9)));
        assert_eq!(
            leg.protect(&rtp(100, 7), &mut out),
            Err(SrtpError::IndexReused)
        );
        leg.protect(&rtp(101, 7), &mut out).expect("next");
    }

    #[test]
    fn adopting_a_change_of_mki_alone_keeps_the_send_window() {
        let mut leg = SecureLeg::new(&key(1), &key(2));
        let mut out = Vec::new();
        leg.protect(&rtp(100, 7), &mut out).expect("sent");
        let mut with_mki = key(1);
        with_mki.mki = Some(crate::sdes::Mki::new(5, 2).expect("mki"));
        leg.adopt(Some(&with_mki), None);
        assert_eq!(
            leg.protect(&rtp(100, 7), &mut out),
            Err(SrtpError::IndexReused)
        );
        leg.protect(&rtp(101, 7), &mut out).expect("next");
        assert_eq!(
            &out[out.len() - 12..out.len() - 10],
            &[0, 5],
            "the MKI now emitted sits before the tag (RFC 3711 §3.4)"
        );
    }

    #[test]
    fn seeding_the_outbound_rollover_closes_what_was_already_sent() {
        let mut live = SecureLeg::new(&key(1), &key(2));
        let mut out = Vec::new();
        for seq in [99u16, 100] {
            live.protect(&rtp(seq, 7), &mut out).expect("sent");
        }
        let snapshot = live.rollover_snapshot();
        let mut rebuilt = SecureLeg::new(&key(1), &key(2));
        rebuilt.seed_rollover(&snapshot);
        assert_eq!(
            rebuilt.protect(&rtp(99, 7), &mut out),
            Err(SrtpError::IndexReused)
        );
        rebuilt.protect(&rtp(101, 7), &mut out).expect("next");
    }

    fn rtcp(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0x00, 0x00];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x33; 16]);
        packet
    }

    #[test]
    fn demux_classifies_rtp_and_rtcp() {
        assert!(!is_rtcp(&rtp(1, 1))); // PT 0
        assert!(is_rtcp(&rtcp(1))); // PT 200 → &0x7F = 72
                                    // PT 206 (PSFB) → &0x7F = 78, still RTCP; an RTP marker+PT 96 → &0x7F = 96, RTP.
        assert!(is_rtcp(&[0x80, 206]));
        assert!(!is_rtcp(&[0x80, 0x80 | 96]));
        assert!(!is_rtcp(&[0x80])); // too short → RTP
    }

    #[test]
    fn rollover_snapshot_lets_a_standby_leg_continue_a_wrapped_stream() {
        // HA-failover invariant at the leg level: after the outbound sequence wraps, a standby that
        // rebuilds the leg from the two SDES keys alone (rollover reset) fails the far peer's auth;
        // seeding it with the exported rollover keeps the peer decrypting.
        let (local, remote) = (key(0xAA), key(0xBB));
        let mut leg = SecureLeg::new(&local, &remote);
        // The far peer decrypts our outbound with the *local* key (see the module note).
        let mut peer = SrtpContext::from_key_material(&local);
        let ssrc = 0x1234_5678;
        let mut wire = Vec::new();
        let mut plain = Vec::new();

        // Drive the outbound RTP sequence past a wrap (…65534, 65535, 0); the peer follows the ROC.
        for seq in [65534u16, 65535, 0] {
            leg.protect(&rtp(seq, ssrc), &mut wire).expect("protect");
            peer.unprotect(&wire, &mut plain)
                .expect("peer decrypts pre-failover");
        }
        let snapshot = leg.rollover_snapshot();
        assert_eq!(
            snapshot
                .outbound_rtp
                .iter()
                .find(|stream| stream.ssrc == ssrc)
                .map(|stream| stream.roc),
            Some(1),
            "the outbound rollover reflects the wrap"
        );

        // Failover: a standby rebuilt from the same keys and seeded keeps the peer decrypting.
        let mut standby = SecureLeg::new(&local, &remote);
        standby.seed_rollover(&snapshot);
        standby
            .protect(&rtp(1, ssrc), &mut wire)
            .expect("standby protect");
        peer.unprotect(&wire, &mut plain)
            .expect("seeded standby continues the stream");

        // A cold rebuild (rollover reset to 0) fails the peer's auth after the wrap.
        let mut cold = SecureLeg::new(&local, &remote);
        cold.protect(&rtp(2, ssrc), &mut wire)
            .expect("cold protect");
        assert_eq!(
            peer.unprotect(&wire, &mut plain),
            Err(SrtpError::AuthFailed),
            "a rollover reset breaks the peer's SRTP auth once the sequence has wrapped"
        );
    }

    #[test]
    fn seed_rollover_round_trips_the_outbound_srtcp_index() {
        let (local, remote) = (key(0x11), key(0x22));
        let mut leg = SecureLeg::new(&local, &remote);
        let mut out = Vec::new();
        leg.protect(&rtcp(0xABCD), &mut out).expect("srtcp protect");
        leg.protect(&rtcp(0xABCD), &mut out).expect("srtcp protect");
        let snapshot = leg.rollover_snapshot();
        assert_eq!(snapshot.outbound_rtcp_index, 2);

        let mut standby = SecureLeg::new(&local, &remote);
        standby.seed_rollover(&snapshot);
        // The standby's next SRTCP packet uses index 2, not a re-used 0.
        standby
            .protect(&rtcp(0xABCD), &mut out)
            .expect("srtcp protect");
        assert_eq!(standby.rollover_snapshot().outbound_rtcp_index, 3);
    }

    #[test]
    fn engine_outbound_decrypts_at_a_peer_holding_the_local_key() {
        // The engine offered `local`; the peer decrypts engine→peer media with it.
        let local = key(0xAA);
        let remote = key(0xBB);
        let mut leg = SecureLeg::new(&local, &remote);

        let plain = rtp(1000, 0x1111_1111);
        let mut srtp = Vec::new();
        assert_eq!(
            leg.protect(&plain, &mut srtp).expect("protect"),
            PacketKind::Rtp
        );

        // A peer keyed with `local` (the engine's offered key) as its decrypt key recovers it.
        let mut peer_decrypt = SrtpContext::from_key_material(&local);
        let mut recovered = Vec::new();
        peer_decrypt
            .unprotect(&srtp, &mut recovered)
            .expect("peer unprotect");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn engine_inbound_decrypts_what_a_peer_encrypts_with_the_remote_key() {
        // The peer answered `remote`; it encrypts peer→engine media with it.
        let local = key(0xAA);
        let remote = key(0xBB);
        let mut leg = SecureLeg::new(&local, &remote);

        let plain = rtp(2000, 0x2222_2222);
        let mut peer_encrypt = SrtpContext::from_key_material(&remote);
        let mut srtp = Vec::new();
        peer_encrypt
            .protect(&plain, &mut srtp)
            .expect("peer protect");

        let mut recovered = Vec::new();
        assert_eq!(
            leg.unprotect(&srtp, &mut recovered).expect("unprotect"),
            PacketKind::Rtp
        );
        assert_eq!(recovered, plain);
    }

    #[test]
    fn rtcp_routes_through_the_srtcp_contexts() {
        let local = key(0xAA);
        let remote = key(0xBB);
        let mut leg = SecureLeg::new(&local, &remote);

        // Outbound RTCP is SRTCP under the local key.
        let plain = rtcp(0x3333_3333);
        let mut srtcp = Vec::new();
        assert_eq!(
            leg.protect(&plain, &mut srtcp).expect("protect"),
            PacketKind::Rtcp
        );
        let mut peer = SrtcpContext::from_key_material(&local);
        let mut recovered = Vec::new();
        peer.unprotect(&srtcp, &mut recovered)
            .expect("peer unprotect");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn mismatched_keys_fail_inbound_auth() {
        // A leg whose remote key does not match the peer's encrypt key must reject the packet.
        let mut leg = SecureLeg::new(&key(0xAA), &key(0xBB));
        let mut peer_encrypt = SrtpContext::from_key_material(&key(0xCC)); // wrong key
        let mut srtp = Vec::new();
        peer_encrypt
            .protect(&rtp(1, 1), &mut srtp)
            .expect("peer protect");
        let mut out = Vec::new();
        assert_eq!(leg.unprotect(&srtp, &mut out), Err(SrtpError::AuthFailed));
    }

    #[test]
    fn a_replayed_inbound_packet_is_dropped_at_the_leg() {
        // The RFC 3711 §3.3.2 replay filter surfaces through the leg's demux: a captured inbound SRTP
        // packet re-injected by an attacker is rejected, so the bridge drops it instead of forwarding.
        let (local, remote) = (key(0xAA), key(0xBB));
        let mut leg = SecureLeg::new(&local, &remote);
        let mut peer_encrypt = SrtpContext::from_key_material(&remote);
        let mut srtp = Vec::new();
        peer_encrypt
            .protect(&rtp(9, 0x00AB_CDEF), &mut srtp)
            .expect("peer protect");

        let mut out = Vec::new();
        assert_eq!(
            leg.unprotect(&srtp, &mut out)
                .expect("first delivery accepted"),
            PacketKind::Rtp
        );
        assert_eq!(
            leg.unprotect(&srtp, &mut out),
            Err(SrtpError::Replayed),
            "the replay is dropped at the leg"
        );
    }
    #[test]
    fn changing_only_the_peers_key_keeps_the_send_history() {
        let local = key(1);
        let remote = key(2);
        let mut leg = SecureLeg::new(&local, &remote);
        let mut wire = Vec::new();
        for seq in [99u16, 100] {
            leg.protect(&rtp(seq, 7), &mut wire).expect("sent");
        }
        leg.rekey(None, Some(&key(3)));
        // The key this leg sends under did not change, so 99 and 100 are still sent.
        let mut different = rtp(99, 7);
        different[13] ^= 0xFF;
        assert_eq!(
            leg.protect(&different, &mut wire),
            Err(SrtpError::IndexReused),
            "different bytes at an index already sent under the same key"
        );
        leg.protect(&rtp(101, 7), &mut wire)
            .expect("the stream goes on");
        // And what the peer now sends is read under its new key.
        let mut peer = SecureLeg::new(&key(3), &local);
        let mut sealed = Vec::new();
        peer.protect(&rtp(5, 9), &mut sealed)
            .expect("peer protects");
        let mut plain = Vec::new();
        leg.unprotect(&sealed, &mut plain)
            .expect("read under the new key");
    }

    #[test]
    fn changing_the_sending_key_carries_the_numbering_over() {
        let mut leg = SecureLeg::new(&key(1), &key(2));
        let mut wire = Vec::new();
        for seq in [65_534u16, 65_535, 0] {
            leg.protect(&rtp(seq, 7), &mut wire).expect("sent");
        }
        leg.protect(&rtcp(0xAB), &mut wire).expect("an SRTCP");
        leg.rekey(Some(&key(4)), None);
        let snapshot = leg.rollover_snapshot();
        assert_eq!(
            snapshot.outbound_rtp[0].roc, 1,
            "the rollover is not restarted"
        );
        assert_eq!(snapshot.outbound_rtcp_index, 1, "nor is the SRTCP index");
        leg.protect(&rtp(1, 7), &mut wire)
            .expect("under the new key");
    }
}
