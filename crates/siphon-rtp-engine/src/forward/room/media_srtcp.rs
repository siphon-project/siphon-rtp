//! Media SRTCP of a preserving room: the audio RTCP of a seat that holds media keys.
//!
//! 3GPP TS 33.180 §9.4.1 protects every RTCP packet of a call hop by hop under each client's key,
//! the media RTCP ("MCPTT/MCVideo media signalling") included; §9.4.2 says whose key that is,
//! §9.4.6 how the key is derived and §9.4.8 gives the profile (AEAD_AES_128_GCM SRTCP, 32-bit MKI,
//! RFC 7714). The end-to-end protection of §5.2.1 covers the media, not its RTCP, so the room
//! terminates this hop: it opens a keyed talker's RTCP under the talker's key, and seals the
//! plaintext again for each receiver under the receiver's own key (RFC 7714 §9.2: a fresh index per
//! datagram and receiver, so no IV is ever reused).
//!
//! A seat without media keys is untouched: its RTCP is forwarded byte for byte as it always was
//! (docs/security-and-nat.md, "Preserve rooms"). A keyed receiver is never sent plaintext, and an
//! unkeyed one is sent nothing of a keyed talker's RTCP.

use std::net::SocketAddr;

use siphon_rtp_datapath::{EndpointId, RxPacket};
use siphon_rtp_srtp::srtcp_gcm::FloorMasterKey;

use super::app::{self, FloorKeysError};
use super::{ForwardRoom, Plan, Seat, Verbatim};
use crate::floor_srtcp::FloorProtection;
use crate::ingress::{Ingress, Refusal, RefusalContext};
use crate::seat_gate::{self, RtcpItem};

/// Read the reports of a seat's plaintext audio RTCP: the APP parts go to the controller, the
/// sender report's time becomes our LSR, and reception report blocks about our egress stream feed
/// the seat's statistics (RFC 3550 §6.4).
pub(super) fn consume_audio_rtcp(room_id: &str, seat: &mut Seat, data: &[u8], arrival: u64) {
    let egress_ssrc = seat.translator.egress_ssrc();
    app::surface_audio_apps(room_id, seat, data);
    seat_gate::consume_rtcp(data, |item| match item {
        RtcpItem::SenderReportNtp(ntp) => {
            seat.last_sender_report_ntp_middle = ((ntp >> 16) & 0xFFFF_FFFF) as u32;
            seat.last_sender_report_arrival = Some(arrival);
        }
        RtcpItem::Block(block) => {
            seat.stats
                .record_reception_report(egress_ssrc, block, arrival);
        }
    });
}

impl ForwardRoom {
    /// Ingress for the audio RTCP of a preserving room, after the shared gate. `plan` is armed for
    /// the talker's RTCP and handed on untouched unless the seat holds media keys.
    ///
    /// A keyed seat's datagram must authenticate (TS 33.180 §9.4.1): plaintext, an unknown MKI, a
    /// failed tag and a replay are dropped and counted in `media_srtcp_refused`. What authenticated
    /// is read like a translating room reads RTCP, and, from the talker, armed to be resealed for
    /// each receiver. A keyed receiver's RTCP is consumed and not forwarded.
    pub(super) fn ingest_preserved_rtcp(
        &mut self,
        index: usize,
        packet: &RxPacket,
        mut plan: Plan,
    ) -> Ingress {
        let is_source = self.source == Some(index);
        let seat = &mut self.seats[index];
        let Some(protection) = seat.media_srtcp.as_mut() else {
            if !is_source {
                seat.counters.receiver_rtcp_dropped += 1;
                return Ingress::DroppedFromPeer;
            }
            self.plan = Some(plan);
            return Ingress::Accepted;
        };
        match protection.open(&packet.data) {
            // The room's own buffer holds the plaintext from here: it outlives the seat's borrow and
            // is what each receiver's seal reads.
            Ok(plain) => {
                self.clear_in.clear();
                self.clear_in.extend_from_slice(plain);
            }
            Err(error) => {
                seat.counters.media_srtcp_refused += 1;
                match Refusal::of_unprotect(&error) {
                    Some(refusal) => seat.refusals.log(
                        refusal,
                        RefusalContext {
                            component: "forward-room-media-srtcp",
                            call_id: &self.room_id,
                            endpoint: packet.endpoint,
                            source: packet.source,
                            expected: seat.accepted_source,
                        },
                    ),
                    // A replay is routine (a duplicated datagram): trace only.
                    None => tracing::debug!(
                        target: "siphon_rtp::media", room = %self.room_id, tag = %seat.tag, %error,
                        "media SRTCP datagram dropped"
                    ),
                }
                return Ingress::Refused;
            }
        }
        consume_audio_rtcp(&self.room_id, seat, &self.clear_in, packet.arrival);
        if !is_source {
            seat.counters.receiver_rtcp_dropped += 1;
            return Ingress::DroppedFromPeer;
        }
        plan.verbatim = Verbatim::ResealRtcp;
        self.plan = Some(plan);
        Ingress::Accepted
    }

    /// The next receiver of a keyed talker's RTCP: the plaintext in the room's buffer sealed under
    /// the receiver's media key into `secure_out`. A reachable receiver with no media key is sent
    /// nothing, never the plaintext. `None` once every seat was considered.
    pub(super) fn next_resealed(
        &mut self,
        mut plan: Plan,
    ) -> Option<(EndpointId, SocketAddr, &[u8])> {
        loop {
            let index = plan.cursor;
            if index >= self.seats.len() {
                self.plan = None;
                return None;
            }
            plan.cursor += 1;
            self.plan = Some(plan);
            if index == plan.source {
                continue; // the source never hears itself
            }
            let receiver = &mut self.seats[index];
            if !receiver.reachable() {
                continue;
            }
            let Some(protection) = receiver.media_srtcp.as_mut() else {
                receiver.counters.media_srtcp_unkeyed_receiver += 1;
                continue;
            };
            if let Err(error) = protection.seal(&self.clear_in, &mut self.secure_out) {
                tracing::warn!(
                    target: "siphon_rtp::media", room = %self.room_id, tag = %receiver.tag, %error,
                    "media SRTCP could not be protected for a receiver"
                );
                continue;
            }
            return Some((
                receiver.endpoint,
                receiver.egress_destination,
                &self.secure_out,
            ));
        }
    }

    /// Replace the media SRTCP keys of seat `tag` (the newest two are kept, outbound uses the last).
    /// An unkeyed seat becomes keyed; an empty set removes the keys. Takes effect for the next
    /// datagram in either direction.
    ///
    /// # Errors
    /// [`FloorKeysError`]; the seat's keys are then unchanged. A translating room has no media
    /// SRTCP to protect ([`FloorKeysError::NotPreserving`]).
    pub fn set_media_srtcp_keys(
        &mut self,
        tag: &str,
        keys: &[FloorMasterKey],
    ) -> Result<(), FloorKeysError> {
        let index = self
            .index_of(tag)
            .ok_or_else(|| FloorKeysError::UnknownSeat(tag.to_string()))?;
        if self.codec.media() != siphon_rtp_proto::ForwardMedia::Preserve {
            return Err(FloorKeysError::NotPreserving);
        }
        let slot = &mut self.seats[index].media_srtcp;
        if keys.is_empty() {
            *slot = None;
            return Ok(());
        }
        match slot.as_mut() {
            Some(protection) => protection.replace_keys(keys),
            None => FloorProtection::new(keys)
                .map(|protection| *slot = Some(protection))
                .ok_or(siphon_rtp_srtp::SrtpError::NoKeys),
        }
        .map_err(|error| FloorKeysError::Keys(error.to_string()))
    }

    /// The SRTCP state of seat `tag`'s media keys: the key set in force (oldest first) and the next
    /// outgoing index. `None` for an unkeyed or unknown seat.
    #[must_use]
    pub fn media_srtcp_key_state(&self, tag: &str) -> Option<(Vec<FloorMasterKey>, u32)> {
        let protection = self.seats[self.index_of(tag)?].media_srtcp.as_ref()?;
        Some((protection.keys().to_vec(), protection.send_index()))
    }
}
