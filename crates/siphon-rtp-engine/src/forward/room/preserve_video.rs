//! Video in a preserving room (`media: preserve`; 3GPP TS 24.281 §6.2, TS 33.180).
//!
//! The room is not an endpoint of the video, as it is not of the audio. The UEs key their SRTP
//! between themselves (TS 33.180 §5.2.1, §7.5.2 NOTE 3; one GMK keys audio and video, told apart by
//! SSRC, §7.5), and SRTP authenticates the SSRC and sequence number (RFC 3711 §3.3), so the source's
//! video datagram is lent out byte for byte to every reachable seat that receives video. Nothing is
//! rewritten, protected or allocated per packet, and the source never hears itself.
//!
//! * **Never bundled.** A video that shares the seat's audio transport (RFC 8843) would need the
//!   engine's own keys; a preserving room is never given one (`engine::forward_video`).
//! * **No keyframe gate.** The payload is encrypted, so an IDR picture is invisible and a receiver
//!   cannot be held back until one: every receiver is sent what arrives, no SPS or PPS is replayed
//!   and no `forward_keyframe` event is raised. A receiver that needs a picture asks for one.
//! * **RTCP is hop by hop** (§9.4.1, §9.4.2: one key per client covers its audio and its video
//!   RTCP). A seat with media keys has its video RTCP opened with the audio's context, on a replay
//!   window per sender SSRC (RFC 3711 §3.2.3, §3.3.2) and a refusal is counted in
//!   `media_srtcp_refused`. The source's is sealed again for each keyed receiver under that
//!   receiver's key, on the seat's one outgoing index shared with its audio (RFC 7714 §9.2: no
//!   (SSRC, index) IV is ever reused under a key). A seat without keys is untouched: the source's
//!   RTCP is forwarded as it came and a receiver's is dropped, exactly as for audio.
//! * **Feedback is the room's own.** A keyed receiver's PLI or FIR, addressed to the source's media
//!   SSRC, is aggregated at most once a second into one request toward the source, sealed under the
//!   source's key, and only what the source accepted in its SDP (`keyframe.rs`). A Generic NACK
//!   (RFC 4585 §6.2.1) from a receiver that accepted `nack` is answered with the stored original
//!   SRTP bytes: the receiver never saw that packet, so its replay check passes. An unkeyed source is
//!   never sent a request: a plaintext one would be refused.
//! * **Unkeyed seats.** TS 33.180 §9.4.1 protects every RTCP packet hop by hop under the client's
//!   key, so a seat the controller gave no media keys is outside that protection: the room neither
//!   reads nor writes its RTCP. Its RTCP as a source is forwarded as it came (opaque, as for audio:
//!   a receiver that holds the right key can still use it, and none is sent anything the room
//!   wrote), and its RTCP as a receiver is dropped and counted, because nothing it says can be
//!   authenticated or answered.
//! * **Reception.** A receiver whose video was switched off (`forward_set_reception`) is sent
//!   neither the source's packets nor a resend, and each is counted in `reception_off_dropped_video`;
//!   its RTCP is control and is never gated.

use std::net::SocketAddr;

use siphon_rtp_datapath::{EndpointId, RxPacket};
use siphon_rtp_media::rtcp::Feedback;
use siphon_rtp_media::rtp::RtpPacket;
use siphon_rtp_proto::{Event, ForwardMedia};

use super::keyframe::KeyframePlan;
use super::video::video_plan;
use super::{ForwardRoom, Plan, Stream, StreamPoint, Verbatim};
use crate::ingress::{Ingress, Refusal, RefusalContext};
use crate::seat_gate;

impl ForwardRoom {
    /// Whether the room forwards the talker's packets unchanged.
    pub(super) fn preserving(&self) -> bool {
        self.codec.media() == ForwardMedia::Preserve
    }

    /// Whether a request the room writes to the source can be sent: always in a translating room,
    /// and in a preserving one only when the source holds media keys to seal it under.
    pub(super) fn source_can_be_written_to(&self) -> bool {
        !self.preserving()
            || self
                .source
                .is_some_and(|source| self.seats[source].media_srtcp.is_some())
    }

    /// Ingress for the video endpoint of a preserving room, after the shared gate. RTP from the
    /// source is armed to be handed on as it came; everything else is counted and dropped.
    pub(super) fn ingest_preserved_video(&mut self, index: usize, packet: &RxPacket) -> Ingress {
        let data: &[u8] = &packet.data;
        if seat_gate::is_rtcp(data) {
            return self.ingest_preserved_video_rtcp(index, packet);
        }
        let is_source = self.source == Some(index);
        let seat = &mut self.seats[index];
        let Some(video) = seat.video.as_mut() else {
            return Ingress::Refused;
        };
        let Ok(parsed) = RtpPacket::parse_clear_header(data) else {
            return Ingress::Accepted;
        };
        // What a request to this seat names should it be the source: its own stream, whoever is now.
        if parsed.payload_type == video.payload_type {
            video.keyframe_media.ssrc = Some(parsed.ssrc);
        }
        if !is_source {
            seat.counters.video_not_source_dropped += 1;
            return Ingress::DroppedFromPeer;
        }
        // RFC 3264 §6.1: a seat that offered recvonly (or inactive) video said it sends none.
        if !video.sends {
            seat.counters.video_receive_only_dropped += 1;
            return Ingress::DroppedFromPeer;
        }
        // The payload type is in the clear (RFC 3711 §3.1) and is the one every seat was admitted
        // under: the room hands the packet on unchanged.
        if parsed.payload_type != video.payload_type {
            seat.counters.video_unknown_payload_type += 1;
            return Ingress::DroppedFromPeer;
        }
        // The ring keeps the bytes a receiver's NACK will be answered with.
        self.keyframes
            .source_packet(false, parsed.ssrc, parsed.sequence, data);
        let mut plan = video_plan(
            index,
            StreamPoint {
                ssrc: parsed.ssrc,
                sequence: parsed.sequence,
                timestamp: parsed.timestamp,
                marker: parsed.marker,
            },
            packet.arrival,
            false,
            KeyframePlan::default(),
        );
        plan.verbatim = Verbatim::Rtp;
        self.plan = Some(plan);
        Ingress::Accepted
    }

    /// Ingress for the video RTCP of a preserving room. A keyed seat's datagram must authenticate
    /// (TS 33.180 §9.4.1); the source's is armed to be sealed again for each keyed receiver, a
    /// receiver's is read for its feedback and consumed. An unkeyed seat's is forwarded (source) or
    /// dropped (receiver) without being read.
    fn ingest_preserved_video_rtcp(&mut self, index: usize, packet: &RxPacket) -> Ingress {
        let is_source = self.source == Some(index);
        let mut plan = video_plan(
            index,
            StreamPoint::default(),
            packet.arrival,
            false,
            KeyframePlan::default(),
        );
        plan.verbatim = Verbatim::Rtcp;
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
            // The room's own buffer holds the plaintext from here: it is what each receiver's seal
            // and the feedback reader use.
            Ok(plain) => {
                self.clear_in.clear();
                self.clear_in.extend_from_slice(plain);
            }
            Err(error) => {
                seat.counters.media_srtcp_refused += 1;
                if let Some(video) = seat.video.as_ref() {
                    match Refusal::of_unprotect(&error) {
                        Some(refusal) => video.refusals.log(
                            refusal,
                            RefusalContext {
                                component: "forward-room-video-media-srtcp",
                                call_id: &self.room_id,
                                endpoint: packet.endpoint,
                                source: packet.source,
                                expected: video.accepted_source,
                            },
                        ),
                        // A replay is routine (a duplicated datagram): trace only.
                        None if error == siphon_rtp_srtp::SrtpError::ReplayTableFull => {
                            tracing::warn!(
                                target: "siphon_rtp::media", room = %self.room_id, tag = %seat.tag,
                                "media SRTCP from one more sender SSRC than the key tracks; refused"
                            );
                        }
                        None => tracing::debug!(
                            target: "siphon_rtp::media", room = %self.room_id, tag = %seat.tag, %error,
                            "media SRTCP video datagram dropped"
                        ),
                    }
                }
                return Ingress::Refused;
            }
        }
        if is_source {
            plan.verbatim = Verbatim::ResealRtcp;
            self.plan = Some(plan);
            return Ingress::Accepted;
        }
        self.read_receiver_feedback(index);
        if self.keyframes.retransmissions_pending() {
            // The packets its NACK asked for are sent again by `next_datagram`, to this seat only.
            plan.stream = Stream::Retransmit;
            plan.verbatim = Verbatim::No;
            self.plan = Some(plan);
            return Ingress::Accepted;
        }
        self.seats[index].counters.receiver_rtcp_dropped += 1;
        Ingress::DroppedFromPeer
    }

    /// Read the feedback in the plaintext of seat `index`'s video RTCP (in the room's buffer): a
    /// PLI or FIR for the source's own video stream asks for a keyframe, a Generic NACK for it, from
    /// a seat that accepted `nack`, asks for stored packets.
    fn read_receiver_feedback(&mut self, index: usize) {
        let source_ssrc = self
            .source
            .and_then(|source| self.seats[source].video.as_ref())
            .and_then(|video| video.keyframe_media.ssrc);
        // A request toward an unkeyed source would be refused by it: never made, never kept waiting.
        let askable = self.source_can_be_written_to();
        self.keyframes.start_feedback(index);
        let seat = &mut self.seats[index];
        let nack_accepted = seat.video.as_ref().is_some_and(|video| video.feedback.nack);
        let (keyframes, counters) = (&mut self.keyframes, &mut seat.counters);
        let Some(source_ssrc) = source_ssrc else {
            return;
        };
        seat_gate::consume_feedback(&self.clear_in, |feedback| match feedback {
            Feedback::Pli { media_ssrc, .. } if media_ssrc == source_ssrc && askable => {
                keyframes.wanted();
            }
            Feedback::Fir { mut entries, .. } => {
                if askable && entries.any(|entry| entry.ssrc == source_ssrc) {
                    keyframes.wanted();
                }
            }
            Feedback::GenericNack {
                media_ssrc,
                pid,
                blp,
                ..
            } if media_ssrc == source_ssrc && nack_accepted => {
                let lost = std::iter::once(pid).chain(
                    (0..16u16)
                        .filter(|bit| blp & (1 << bit) != 0)
                        .map(|bit| pid.wrapping_add(bit + 1)),
                );
                for sequence in lost {
                    if !keyframes.queue_stored_resend(source_ssrc, sequence) {
                        counters.nack_missed += 1;
                    }
                }
            }
            _ => {}
        });
    }

    /// The next receiver of a preserving room's armed video datagram: the very buffer that arrived,
    /// lent out again for each reachable seat that receives video; or, for a keyed source's RTCP,
    /// the plaintext sealed under the receiver's own key.
    pub(super) fn next_preserved_video<'a>(
        &'a mut self,
        packet: &'a RxPacket,
        mut plan: Plan,
    ) -> Option<(EndpointId, SocketAddr, &'a [u8])> {
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
            if receiver.secure_pending || receiver.ice_pending {
                continue;
            }
            let Some(video) = receiver.video.as_ref() else {
                continue;
            };
            if !video.receives || !video.reachable() {
                continue;
            }
            // Only the RTP is gated: the source's RTCP is the seat's control stream.
            if plan.verbatim == Verbatim::Rtp && !receiver.reception.video {
                receiver.counters.reception_off_dropped_video += 1;
                continue;
            }
            let (endpoint, destination) = (video.endpoint, video.destination);
            match plan.verbatim {
                Verbatim::ResealRtcp => {
                    // A keyed talker's RTCP is never relayed as it came, and never in the clear.
                    let Some(protection) = receiver.media_srtcp.as_mut() else {
                        receiver.counters.media_srtcp_unkeyed_receiver += 1;
                        continue;
                    };
                    if let Err(error) = protection.seal(&self.clear_in, &mut self.secure_out) {
                        tracing::warn!(
                            target: "siphon_rtp::media", room = %self.room_id, tag = %receiver.tag, %error,
                            "media SRTCP could not be protected for a video receiver"
                        );
                        continue;
                    }
                    return Some((endpoint, destination, &self.secure_out));
                }
                Verbatim::Rtp => {
                    receiver.counters.video_forwarded_packets =
                        receiver.counters.video_forwarded_packets.wrapping_add(1);
                    receiver.counters.video_forwarded_octets = receiver
                        .counters
                        .video_forwarded_octets
                        .wrapping_add(packet.data.len() as u32);
                    if self.announce_pending {
                        self.announce_pending = false;
                        self.events.push(Event::ForwardSourceStarted {
                            conference_id: self.room_id.clone(),
                            from_tag: self.seats[plan.source].tag.clone(),
                        });
                    }
                }
                _ => {}
            }
            return Some((endpoint, destination, &packet.data[..]));
        }
    }

    /// The next packet a keyed receiver's NACK asked for: the stored original bytes, sent to that
    /// receiver again. A packet that left the ring is counted as missed; one for a receiver that
    /// cannot be sent video now (its video is off, unreachable or not keyed yet) is dropped.
    pub(super) fn next_preserved_resend(&mut self) -> Option<(EndpointId, SocketAddr, &[u8])> {
        let ssrc = self
            .source
            .and_then(|source| self.seats[source].video.as_ref())
            .and_then(|video| video.keyframe_media.ssrc);
        let (endpoint, destination, sequence) = loop {
            let Some((index, sequence)) = self.keyframes.take_queued_resend() else {
                self.plan = None;
                return None;
            };
            let held = ssrc.is_some_and(|ssrc| self.keyframes.stored(ssrc, sequence).is_some());
            let Some(receiver) = self.seats.get_mut(index) else {
                continue;
            };
            if receiver.secure_pending || receiver.ice_pending {
                continue;
            }
            let Some(video) = receiver.video.as_ref() else {
                continue;
            };
            if !video.receives || !video.reachable() {
                continue;
            }
            if !receiver.reception.video {
                receiver.counters.reception_off_dropped_video += 1;
                continue;
            }
            if !held {
                receiver.counters.nack_missed += 1;
                continue;
            }
            let (endpoint, destination) = (video.endpoint, video.destination);
            receiver.counters.nack_answered += 1;
            break (endpoint, destination, sequence);
        };
        ssrc.and_then(|ssrc| self.keyframes.stored(ssrc, sequence))
            .map(|bytes| (endpoint, destination, bytes))
    }
}
