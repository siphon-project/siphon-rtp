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
        }
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
            self.outbound_rtp.seed_stream(*stream);
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
            leg.unprotect(&srtp, &mut out).expect("first delivery accepted"),
            PacketKind::Rtp
        );
        assert_eq!(
            leg.unprotect(&srtp, &mut out),
            Err(SrtpError::Replayed),
            "the replay is dropped at the leg"
        );
    }
}
