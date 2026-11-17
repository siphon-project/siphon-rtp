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
//! The endpoint is gated like the seat's audio: the signalled source (layer 2) and the
//! SSRC-consistent reply latch (layer 3), docs/security-and-nat.md §4 layer 5c-ii.

use std::net::SocketAddr;

use bytes::Bytes;

use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_media::ingress::IngressStats;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::RtpPacket;
use siphon_rtp_media::translator::{Forwarded, Translator};
use siphon_rtp_proto::Event;
use siphon_rtp_srtp::leg::SecureLeg;

use super::super::transcode::StreamPoint;
use super::{reception_block, ticks, ForwardRoom, Plan, PlanKind, Stream, Verbatim};
use crate::ingress::{Ingress, RefusalLog};
use crate::media_pipeline::Outbound;
use crate::reply_latch::SymmetricLatch;
use crate::sdp::video::{RoomVideoFormat, VIDEO_CLOCK_RATE_HZ};
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
}

pub(super) struct VideoStream {
    pub(super) endpoint: EndpointId,
    destination: SocketAddr,
    accepted_source: SourceFilter,
    latch: SymmetricLatch,
    refusals: RefusalLog,
    payload_type: u8,
    sends: bool,
    receives: bool,
    translator: Translator,
    stats: IngressStats,
    last_sender_report_ntp_middle: u32,
    last_sender_report_arrival: Option<u64>,
    last_forward_clock: u32,
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
    fn reachable(&self) -> bool {
        !self.destination.ip().is_unspecified() && self.destination.port() != 0
    }
}

/// Read the reports of a seat's video RTCP: the sender report's time becomes our LSR, and reception
/// report blocks about our video egress stream feed the seat's statistics (RFC 3550 §6.4). Keyframe
/// requests (RFC 4585 PLI, RFC 5104 FIR) are not acted on yet, so they are consumed and dropped.
fn consume_video_rtcp(video: &mut VideoStream, data: &[u8], arrival: u64) {
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
        let seat = &mut self.seats[index];
        let Some(video) = seat.video.as_mut() else {
            return Ingress::Refused;
        };
        // A video stream is plain RTP: the engine declines secure video (steps 5 and 6).
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
            &mut self.clear_in,
        ) {
            Ok(data) => data,
            Err(refused) => return refused,
        };
        if data.len() < 2 {
            return Ingress::Accepted; // gated in; too short to be media, but the path is alive
        }
        // RFC 5761 demux, as for audio: the room terminates the seat's RTCP.
        if seat_gate::is_rtcp(data) {
            consume_video_rtcp(video, data, packet.arrival);
            return Ingress::Accepted;
        }
        let Ok(parsed) = RtpPacket::parse(data) else {
            return Ingress::Accepted;
        };
        video
            .stats
            .on_rtp(parsed.ssrc, parsed.sequence, parsed.timestamp);
        video.stats.observe_arrival(packet.arrival);
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
        self.plan = Some(Plan {
            stream: Stream::Video,
            verbatim: Verbatim::No,
            source: index,
            // Unused for video: there is no event or concealment to tell apart.
            kind: PlanKind::Audio,
            in_clear_buffer: false,
            domain_len: None,
            source_group: None,
            point: StreamPoint {
                ssrc: parsed.ssrc,
                sequence: parsed.sequence,
                timestamp: parsed.timestamp,
                marker: parsed.marker,
            },
            cursor: 0,
            arrival: packet.arrival,
            dropped_before: 0,
            fill: None,
            uplink_pending: false,
        });
        Ingress::Accepted
    }

    /// The next receiver of the armed video packet: each reachable seat that receives video is sent
    /// the packet through its own video translator, on its video endpoint, under its own payload
    /// type. The source, a seat with no video stream and a seat that offered send-only video are
    /// skipped; so is a packet the translator drops as a late one of the previous source.
    pub(super) fn next_video<'a>(
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
            let Some(video) = receiver.video.as_mut() else {
                continue;
            };
            if !video.receives || !video.reachable() {
                continue;
            }
            // The translator's clock is the video RTP clock, 90 kHz (RFC 3550 §5.1).
            let clock = ticks(plan.arrival, VIDEO_CLOCK_RATE_HZ);
            let length = match video.translator.translate(
                &packet.data,
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
            if self.announce_pending {
                self.announce_pending = false;
                self.events.push(Event::ForwardSourceStarted {
                    conference_id: self.room_id.clone(),
                    from_tag: self.seats[plan.source].tag.clone(),
                });
            }
            let video = self.seats[index].video.as_ref()?;
            return Some((video.endpoint, video.destination, &self.scratch[..length]));
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
            let Some(video) = seat.video.as_mut() else {
                continue;
            };
            if !video.reachable() || !(video.sends || video.receives) {
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
            out.push(Outbound {
                endpoint: video.endpoint,
                dst: video.destination,
                data: Bytes::copy_from_slice(&buffer[..length]),
            });
            video.stats.record_sent_report(ntp_timestamp, now_micros);
        }
    }
}
