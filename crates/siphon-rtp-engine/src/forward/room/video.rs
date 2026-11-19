//! The video stream of a forwarding-room seat (3GPP TS 24.281 §6.2: `m=video` beside the audio).
//!
//! Video is opaque to the room: no transcoder, no jitter buffer, no feed selection. A source's
//! packet is handed through each receiver's video [`Translator`] (RFC 3550 §7) and sent to the
//! receiver's video endpoint under its own payload type and SSRC, exactly as audio is for a seat in
//! the room's codec. Two things differ:
//!
//! * The marker bit is the sender's, never set for a rebase (RFC 6184 §5.1: it ends an access unit,
//!   so a switch that lands mid access unit must not mark the first packet of the new run).
//! * The clock is 90 kHz (RFC 3551 §5, RFC 6184 §8.2.1) whatever the audio codec is.
//!
//! Which seat is the source is the room's one choice, shared with audio, so a source change moves
//! audio and video together. A seat whose offer was receive-only is never forwarded from, and one
//! whose offer was send-only is never sent video (RFC 3264 §6.1; the answer was the complement).
//!
//! A source change starts every receiver on a keyframe (`keyframe.rs`): a receiver's packets are held
//! back until one begins an IDR picture, and the source is asked for one.
//!
//! The endpoint is gated like the seat's audio: the signalled source (layer 2) and the
//! SSRC-consistent reply latch (layer 3), docs/security-and-nat.md §4 layer 5c-ii.

use std::net::SocketAddr;

use bytes::Bytes;

use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_media::h264;
use siphon_rtp_media::ingress::IngressStats;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::RtpPacket;
use siphon_rtp_media::translator::{Forwarded, Translator};
use siphon_rtp_proto::Event;
use siphon_rtp_srtp::leg::SecureLeg;

use super::super::transcode::StreamPoint;
use super::keyframe::{
    Admission, KeyframePlan, Keyframes, ReceiverKeyframe, SourceMedia, STEP_NONE, STEP_PACKET,
    STEP_PPS, STEP_SPS,
};
use super::{
    reception_block, ticks, ForwardRoom, ForwardSeatStats, Plan, PlanKind, Seat, Stream, Verbatim,
};
use crate::ingress::{Ingress, RefusalLog};
use crate::media_pipeline::Outbound;
use crate::reply_latch::SymmetricLatch;
use crate::sdp::video::{RoomVideoFormat, VideoFeedback, VIDEO_CLOCK_RATE_HZ};
use crate::sdp::MediaDirection;
use crate::seat_gate::{self, RtcpItem, SeatGate};

/// The video endpoint of a seat, as the engine resolves it from the offer.
#[derive(Clone)]
pub struct VideoConfig {
    /// The engine socket the seat's video RTP and RTCP arrive on and the room sends from.
    pub endpoint: EndpointId,
    /// Where the room sends the seat's video until the first gated datagram latches the source: the
    /// video m-line's signalled address, or the `received_from` hint with its port.
    pub destination: SocketAddr,
    /// Layer 2: the sources the video stream may come from.
    pub accepted_source: SourceFilter,
    /// The seat's own payload type for the room's video format.
    pub payload_type: u8,
    /// The direction the seat declared for its video (its offer, or its answer to ours): it is the
    /// source of video only when it sends, and is sent video only when it receives.
    pub direction: MediaDirection,
    /// The seat's video egress stream, chosen by the caller so tests are deterministic (RFC 3550
    /// §5.1: random initial sequence number and timestamp).
    pub egress_ssrc: u32,
    pub initial_sequence: u16,
    pub initial_timestamp: u32,
    /// The room's video format this seat was admitted under; the first seat with video fixes it.
    pub format: RoomVideoFormat,
    /// The RTCP feedback the seat accepted in its SDP (RFC 4585 §4.2): a keyframe request is sent to
    /// a source only as a PLI or FIR it accepted, and a NACK is answered only for a seat that
    /// accepted `nack`.
    pub feedback: VideoFeedback,
    /// The CNAME of the seat's streams (RFC 3550 §6.5.1), written in the source description of the
    /// compound a keyframe request travels in (RFC 4585 §3.1).
    pub cname: String,
    /// The video is bundled with the seat's audio on one transport (RFC 8843): it has no endpoint,
    /// latch, key or destination of its own. `endpoint` is the seat's own, and what the video leaves
    /// and arrives through is the seat's gate, its latched destination and its `SecureLeg`.
    pub bundled: bool,
}

pub(super) struct VideoStream {
    pub(super) endpoint: EndpointId,
    pub(super) destination: SocketAddr,
    accepted_source: SourceFilter,
    latch: SymmetricLatch,
    refusals: RefusalLog,
    pub(super) payload_type: u8,
    pub(super) sends: bool,
    pub(super) receives: bool,
    pub(super) translator: Translator,
    stats: IngressStats,
    last_sender_report_ntp_middle: u32,
    last_sender_report_arrival: Option<u64>,
    pub(super) last_forward_clock: u32,
    /// What the seat accepted of RTCP feedback, and the CNAME of its streams.
    pub(super) feedback: VideoFeedback,
    pub(super) cname: Box<str>,
    /// Whether this receiver is held back until a keyframe.
    pub(super) keyframe: ReceiverKeyframe,
    /// What the seat sends, kept for starting receivers on it when it is the source.
    pub(super) keyframe_media: SourceMedia,
    /// See [`VideoConfig::bundled`].
    pub(super) bundled: bool,
}

impl VideoStream {
    pub(super) fn new(config: VideoConfig, anchor: u32) -> Self {
        Self {
            endpoint: config.endpoint,
            destination: config.destination,
            accepted_source: config.accepted_source,
            latch: SymmetricLatch::default(),
            refusals: RefusalLog::default(),
            payload_type: config.payload_type,
            sends: config.direction.peer_sends(),
            receives: config.direction.receives(),
            translator: Translator::new(
                config.egress_ssrc,
                config.initial_sequence,
                config.initial_timestamp,
            )
            .with_preserved_marker(),
            stats: IngressStats::new(VIDEO_CLOCK_RATE_HZ),
            last_sender_report_ntp_middle: 0,
            last_sender_report_arrival: None,
            last_forward_clock: anchor,
            feedback: config.feedback,
            cname: config.cname.into_boxed_str(),
            keyframe: ReceiverKeyframe::new(),
            keyframe_media: SourceMedia::default(),
            bundled: config.bundled,
        }
    }

    /// A talker change: the next packet starts a new run.
    pub(super) fn switch_source(&mut self) {
        self.translator.switch_source();
    }

    pub(super) fn packets_sent(&self) -> u32 {
        self.translator.packets_sent()
    }

    pub(super) fn octets_sent(&self) -> u32 {
        self.translator.octets_sent()
    }
}

impl VideoStream {
    /// Whether the room may send this stream anything: it has a resolved destination (the room never
    /// forwards into the void, docs/security-and-nat.md §4).
    pub(super) fn reachable(&self) -> bool {
        !self.destination.ip().is_unspecified() && self.destination.port() != 0
    }
}

impl Seat {
    /// Whether the room may send this seat's video anything: its destination is resolved (the room
    /// never forwards into the void, docs/security-and-nat.md §4), and for a bundled video the seat's
    /// own key and ICE pair have settled, since it travels on the seat's transport.
    pub(super) fn video_reachable(&self) -> bool {
        match &self.video {
            Some(video) if video.bundled => self.reachable(),
            Some(video) => video.reachable(),
            None => false,
        }
    }

    /// The endpoint the seat's video leaves from and the destination it goes to: its own, or for a
    /// bundled video the seat's (RFC 8843 §8), which follows the seat's latch and ICE selection.
    pub(super) fn video_route(&self) -> Option<(EndpointId, SocketAddr)> {
        let video = self.video.as_ref()?;
        let destination = if video.bundled {
            self.egress_destination
        } else {
            video.destination
        };
        Some((video.endpoint, destination))
    }
}

/// Protect a video datagram for the wire: `Some(false)` when it goes as it is (a video on an endpoint
/// of its own, plain RTP), `Some(true)` when its protection under the seat's `SecureLeg` is in `sealed`
/// (a bundled one: RFC 3711 §3.3 for RTP, §3.4 for RTCP; each SSRC has its own context under the one
/// key, §3.2.3). `None` when it cannot be protected: a bundled video is never sent in the clear.
pub(super) fn seal(
    bundled: bool,
    secure: Option<&mut SecureLeg>,
    plain: &[u8],
    sealed: &mut Vec<u8>,
) -> Option<bool> {
    if !bundled {
        return Some(false);
    }
    sealed.clear();
    secure?.protect(plain, sealed).ok()?;
    Some(true)
}

/// Whether a cleartext datagram that arrived on a seat's endpoint is that seat's bundled video, not
/// its audio (RFC 8843 §9.2): RTP carries the video payload type, which no other section of the
/// bundle uses; RTCP is told apart by the streams it speaks of, since an RTCP packet has no payload
/// type of the section.
pub(super) fn is_bundled_video(video: &VideoStream, data: &[u8]) -> bool {
    if !video.bundled {
        return false;
    }
    if seat_gate::is_rtcp(data) {
        return rtcp_is_about_video(
            data,
            video.translator.egress_ssrc(),
            video.keyframe_media.ssrc,
        );
    }
    data.len() >= 2 && data[1] & 0x7F == video.payload_type
}

/// Whether an RTCP datagram concerns the room's video stream, see [`seat_gate::rtcp_is_about_video`].
pub(super) fn rtcp_is_about_video(data: &[u8], egress: u32, sender: Option<u32>) -> bool {
    seat_gate::rtcp_is_about_video(data, Some(egress), sender)
}

/// Read a seat's video RTCP: the sender report's time becomes our LSR, reception report blocks about
/// our video egress stream feed the seat's statistics (RFC 3550 §6.4), and its feedback (RFC 4585
/// PLI and Generic NACK, RFC 5104 FIR) about that stream is passed to the keyframe state.
fn consume_video_rtcp(
    video: &mut VideoStream,
    keyframes: &mut Keyframes,
    counters: &mut ForwardSeatStats,
    data: &[u8],
    arrival: u64,
) {
    let egress_ssrc = video.translator.egress_ssrc();
    seat_gate::consume_rtcp(data, |item| match item {
        RtcpItem::SenderReportNtp(ntp) => {
            video.last_sender_report_ntp_middle = ((ntp >> 16) & 0xFFFF_FFFF) as u32;
            video.last_sender_report_arrival = Some(arrival);
        }
        RtcpItem::Block(block) => {
            video
                .stats
                .record_reception_report(egress_ssrc, block, arrival);
        }
    });
    seat_gate::consume_feedback(data, |feedback| {
        keyframes.receiver_feedback(video, feedback, counters);
    });
}

/// The fan-out of one video packet, or of the packets a receiver's NACK asked for.
fn video_plan(
    source: usize,
    point: StreamPoint,
    arrival: u64,
    in_clear_buffer: bool,
    keyframe: KeyframePlan,
) -> Plan {
    Plan {
        stream: Stream::Video,
        verbatim: Verbatim::No,
        source,
        // Unused for video: there is no event or concealment to tell apart.
        kind: PlanKind::Audio,
        in_clear_buffer,
        domain_len: None,
        source_group: None,
        point,
        cursor: 0,
        arrival,
        dropped_before: 0,
        fill: None,
        uplink_pending: false,
        keyframe,
    }
}

impl ForwardRoom {
    /// Ingress one datagram that arrived on the video endpoint of seat `index`.
    ///
    /// The endpoint passes the same gate as the seat's audio (layer 2, the signalled source; a seat
    /// whose key or ICE pair is pending is refused; layer 3, the SSRC-consistent latch). Then RTCP is
    /// consumed for the seat's statistics and never forwarded, and RTP from the chosen source, when
    /// the seat sends video, arms the fan-out ([`Self::next_datagram`]). RTP from any other seat is
    /// counted and dropped after the gate: [`Ingress::DroppedFromPeer`], which still proves the seat
    /// is alive.
    pub(super) fn ingest_video(&mut self, index: usize, packet: &RxPacket) -> Ingress {
        // The decrypt buffer is lent to the gate and handed back, so the packet it returns can be
        // read while the room's other state is changed.
        let mut clear = std::mem::take(&mut self.clear_in);
        let outcome = self.gate_video(index, packet, &mut clear);
        self.clear_in = clear;
        outcome
    }

    fn gate_video(&mut self, index: usize, packet: &RxPacket, clear: &mut Vec<u8>) -> Ingress {
        let seat = &mut self.seats[index];
        let Some(video) = seat.video.as_mut() else {
            return Ingress::Refused;
        };
        // A video stream on an endpoint of its own is plain RTP: the engine declines secure video
        // there (a bundled one is gated and unprotected with the seat's audio).
        let mut unkeyed: Option<SecureLeg> = None;
        let data = match seat_gate::admit(
            SeatGate {
                component: "forward-room-video",
                room_id: &self.room_id,
                accepted_source: video.accepted_source,
                secure_pending: seat.secure_pending,
                ice_pending: seat.ice_pending,
                secure: &mut unkeyed,
                latch: true,
                reverse_latch: &mut video.latch,
                refusals: &video.refusals,
                egress_destination: &mut video.destination,
            },
            packet,
            clear,
        ) {
            Ok(data) => data,
            Err(refused) => return refused,
        };
        self.video_after_gate(index, data, packet.arrival, false)
    }

    /// Ingress a datagram of a seat's bundled video (RFC 8843): the seat's own gate, latch and
    /// `SecureLeg` already ran on the audio path, so the cleartext is read as video from here.
    /// `in_clear_buffer` says the cleartext is the room's decrypt buffer rather than the datagram.
    pub(super) fn ingest_bundled_video(
        &mut self,
        index: usize,
        packet: &RxPacket,
        in_clear_buffer: bool,
    ) -> Ingress {
        let clear = std::mem::take(&mut self.clear_in);
        let data: &[u8] = if in_clear_buffer {
            &clear
        } else {
            &packet.data
        };
        let outcome = self.video_after_gate(index, data, packet.arrival, in_clear_buffer);
        self.clear_in = clear;
        outcome
    }

    /// What follows the gate for a video datagram: `data` is its cleartext.
    fn video_after_gate(
        &mut self,
        index: usize,
        data: &[u8],
        arrival: u64,
        in_clear_buffer: bool,
    ) -> Ingress {
        let seat = &mut self.seats[index];
        let Some(video) = seat.video.as_mut() else {
            return Ingress::Refused;
        };
        if data.len() < 2 {
            return Ingress::Accepted; // gated in; too short to be media, but the path is alive
        }
        // RFC 5761 demux, as for audio: the room terminates the seat's RTCP.
        if seat_gate::is_rtcp(data) {
            self.keyframes.start_feedback(index);
            consume_video_rtcp(
                video,
                &mut self.keyframes,
                &mut seat.counters,
                data,
                arrival,
            );
            if self.keyframes.retransmissions_pending() {
                // The packets its NACK asked for are sent again by `next_datagram`, to this seat only.
                self.plan = Some(Plan {
                    stream: Stream::Retransmit,
                    ..video_plan(
                        index,
                        StreamPoint::default(),
                        arrival,
                        false,
                        KeyframePlan::default(),
                    )
                });
            }
            return Ingress::Accepted;
        }
        let Ok(parsed) = RtpPacket::parse(data) else {
            return Ingress::Accepted;
        };
        video
            .stats
            .on_rtp(parsed.ssrc, parsed.sequence, parsed.timestamp);
        video.stats.observe_arrival(arrival);
        // What a keyframe request to this seat names, and the parameter sets to replay, should it
        // become the source: kept whoever is the source now.
        video.keyframe_media.ssrc = Some(parsed.ssrc);
        let found = if parsed.payload_type == video.payload_type {
            h264::scan(parsed.payload)
        } else {
            h264::Scan::default()
        };
        video.keyframe_media.note(&found);
        if self.source != Some(index) {
            seat.counters.video_not_source_dropped += 1;
            return Ingress::DroppedFromPeer;
        }
        // RFC 3264 §6.1: a seat that offered recvonly (or inactive) video said it sends none.
        if !video.sends {
            seat.counters.video_receive_only_dropped += 1;
            return Ingress::DroppedFromPeer;
        }
        if parsed.payload_type != video.payload_type {
            seat.counters.video_unknown_payload_type += 1;
            return Ingress::DroppedFromPeer;
        }
        if found.keyframe_start {
            seat.counters.keyframes_seen += 1;
        }
        self.keyframes
            .source_packet(found.keyframe_start, parsed.ssrc, parsed.sequence, data);
        self.plan = Some(video_plan(
            index,
            StreamPoint {
                ssrc: parsed.ssrc,
                sequence: parsed.sequence,
                timestamp: parsed.timestamp,
                marker: parsed.marker,
            },
            arrival,
            in_clear_buffer,
            KeyframePlan {
                start: found.keyframe_start,
                has_sps: found.sps.is_some(),
                has_pps: found.pps.is_some(),
                ..KeyframePlan::default()
            },
        ));
        Ingress::Accepted
    }

    /// The next receiver of the armed video packet: each reachable seat that receives video is sent
    /// the packet through its own video translator, on its video endpoint, under its own payload
    /// type. The source, a seat with no video stream and a seat that offered send-only video are
    /// skipped; so is a packet the translator drops as a late one of the previous source.
    ///
    /// A receiver that is waiting for a keyframe (`keyframe.rs`) is sent nothing until the packet
    /// begins an IDR slice; that packet is then preceded by the source's SPS and PPS, which are two
    /// more datagrams to the same receiver before the walk moves on.
    pub(super) fn next_video<'a>(
        &'a mut self,
        packet: &'a RxPacket,
        mut plan: Plan,
    ) -> Option<(EndpointId, SocketAddr, &'a [u8])> {
        loop {
            let (index, mut step) = if plan.keyframe.step == STEP_NONE {
                let index = plan.cursor;
                if index >= self.seats.len() {
                    self.plan = None;
                    return None;
                }
                plan.cursor += 1;
                (index, STEP_NONE)
            } else {
                (plan.keyframe.receiver, plan.keyframe.step)
            };
            plan.keyframe.step = STEP_NONE;
            self.plan = Some(plan);
            if index == plan.source {
                continue; // the source never hears itself
            }
            let receiver = &mut self.seats[index];
            if receiver.secure_pending || receiver.ice_pending {
                continue;
            }
            let reachable = receiver.video_reachable();
            let Some(video) = receiver.video.as_mut() else {
                continue;
            };
            if !video.receives || !reachable {
                continue;
            }
            if step == STEP_NONE {
                match video.keyframe.admit(&plan.keyframe, plan.point.sequence) {
                    Admission::Dropped => {
                        receiver.counters.video_dropped_awaiting_keyframe += 1;
                        continue;
                    }
                    Admission::Forward => step = STEP_PACKET,
                    Admission::Opened => {
                        self.plan_replay(&mut plan.keyframe, plan.source);
                        step = STEP_SPS;
                    }
                }
            }
            // The parameter sets come first, then the packet itself.
            let mut replayed = None;
            while step < STEP_PACKET && replayed.is_none() {
                let sps = step == STEP_SPS;
                if sps && plan.keyframe.replay_sps || !sps && plan.keyframe.replay_pps {
                    replayed =
                        self.translate_replay(index, &plan.keyframe, sps, plan.point, plan.arrival);
                }
                step = if step == STEP_SPS {
                    STEP_PPS
                } else {
                    STEP_PACKET
                };
            }
            let length = match replayed {
                Some(length) => {
                    // More of this receiver's keyframe follows.
                    plan.keyframe.step = step;
                    plan.keyframe.receiver = index;
                    self.plan = Some(plan);
                    length
                }
                None => {
                    let Some(video) = self.seats[index].video.as_mut() else {
                        continue;
                    };
                    // The translator's clock is the video RTP clock, 90 kHz (RFC 3550 §5.1).
                    let clock = ticks(plan.arrival, VIDEO_CLOCK_RATE_HZ);
                    // A secure source's packet was unprotected into the room's buffer.
                    let inbound: &[u8] = if plan.in_clear_buffer {
                        &self.clear_in
                    } else {
                        &packet.data
                    };
                    let length = match video.translator.translate(
                        inbound,
                        video.payload_type,
                        clock,
                        &mut self.scratch,
                    ) {
                        Ok(Forwarded::Packet { length, .. }) => length,
                        Ok(Forwarded::DroppedStale) => continue,
                        Err(error) => {
                            tracing::debug!(
                                target: "siphon_rtp::media", room = %self.room_id, %error,
                                "forwarding room could not translate a video packet"
                            );
                            continue;
                        }
                    };
                    video.last_forward_clock = clock;
                    length
                }
            };
            if self.announce_pending {
                self.announce_pending = false;
                self.events.push(Event::ForwardSourceStarted {
                    conference_id: self.room_id.clone(),
                    from_tag: self.seats[plan.source].tag.clone(),
                });
            }
            let receiver = &mut self.seats[index];
            let (endpoint, destination) = receiver.video_route()?;
            let bundled = receiver.video.as_ref().is_some_and(|video| video.bundled);
            let Some(sealed) = seal(
                bundled,
                receiver.secure.as_mut(),
                &self.scratch[..length],
                &mut self.secure_out,
            ) else {
                continue;
            };
            let wire = if sealed {
                &self.secure_out[..]
            } else {
                &self.scratch[..length]
            };
            return Some((endpoint, destination, wire));
        }
    }

    /// One RTCP Sender Report per video seat, about the video stream it is sent (RFC 3550 §6.4.1),
    /// built like the audio one: the translator's counts under its video egress SSRC, an RTP
    /// timestamp on the 90 kHz line of the packets, and a reception report block about the seat's
    /// own video once it has sent any. A seat whose video is inactive is sent none.
    pub(super) fn build_video_reports(
        &mut self,
        ntp_timestamp: u64,
        now_micros: u64,
        out: &mut Vec<Outbound>,
    ) {
        let mut buffer = [0u8; rtcp::SENDER_REPORT_LEN + rtcp::RECEPTION_REPORT_LEN];
        for seat in &mut self.seats {
            if seat.secure_pending || seat.ice_pending {
                continue;
            }
            let reachable = seat.video_reachable();
            let Some((endpoint, destination)) = seat.video_route() else {
                continue;
            };
            let Some(video) = seat.video.as_mut() else {
                continue;
            };
            if !reachable || !(video.sends || video.receives) {
                continue;
            }
            let block = reception_block(
                &mut video.stats,
                video.last_sender_report_ntp_middle,
                video.last_sender_report_arrival,
                now_micros,
            );
            let now_clock = ticks(now_micros, VIDEO_CLOCK_RATE_HZ);
            let rtp_timestamp = video
                .translator
                .last_timestamp()
                .wrapping_add(now_clock.wrapping_sub(video.last_forward_clock));
            let Some(length) = rtcp::write_sender_report(
                video.translator.egress_ssrc(),
                ntp_timestamp,
                rtp_timestamp,
                video.translator.packets_sent(),
                video.translator.octets_sent(),
                block.as_slice(),
                &mut buffer,
            ) else {
                continue;
            };
            // SRTCP under the seat's key for a bundled video (RFC 3711 §3.4), the datagram as it is
            // otherwise.
            let Some(sealed) = seal(
                video.bundled,
                seat.secure.as_mut(),
                &buffer[..length],
                &mut self.secure_out,
            ) else {
                continue;
            };
            let wire = if sealed {
                &self.secure_out[..]
            } else {
                &buffer[..length]
            };
            out.push(Outbound {
                endpoint,
                dst: destination,
                data: Bytes::copy_from_slice(wire),
            });
            video.stats.record_sent_report(ntp_timestamp, now_micros);
        }
    }
}
