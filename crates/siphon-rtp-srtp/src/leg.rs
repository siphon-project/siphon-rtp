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
use crate::{SrtpContext, SrtpError};

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
    fn engine_outbound_decrypts_at_a_peer_holding_the_local_key() {
        // The engine offered `local`; the peer decrypts engine→peer media with it.
        let local = key(0xAA);
        let remote = key(0xBB);
        let mut leg = SecureLeg::new(&local, &remote);

        let plain = rtp(1000, 0x1111_1111);
        let mut srtp = Vec::new();
        assert_eq!(leg.protect(&plain, &mut srtp).expect("protect"), PacketKind::Rtp);

        // A peer keyed with `local` (the engine's offered key) as its decrypt key recovers it.
        let mut peer_decrypt = SrtpContext::from_key_material(&local);
        let mut recovered = Vec::new();
        peer_decrypt.unprotect(&srtp, &mut recovered).expect("peer unprotect");
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
        peer_encrypt.protect(&plain, &mut srtp).expect("peer protect");

        let mut recovered = Vec::new();
        assert_eq!(leg.unprotect(&srtp, &mut recovered).expect("unprotect"), PacketKind::Rtp);
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
        assert_eq!(leg.protect(&plain, &mut srtcp).expect("protect"), PacketKind::Rtcp);
        let mut peer = SrtcpContext::from_key_material(&local);
        let mut recovered = Vec::new();
        peer.unprotect(&srtcp, &mut recovered).expect("peer unprotect");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn mismatched_keys_fail_inbound_auth() {
        // A leg whose remote key does not match the peer's encrypt key must reject the packet.
        let mut leg = SecureLeg::new(&key(0xAA), &key(0xBB));
        let mut peer_encrypt = SrtpContext::from_key_material(&key(0xCC)); // wrong key
        let mut srtp = Vec::new();
        peer_encrypt.protect(&rtp(1, 1), &mut srtp).expect("peer protect");
        let mut out = Vec::new();
        assert_eq!(leg.unprotect(&srtp, &mut out), Err(SrtpError::AuthFailed));
    }
}
