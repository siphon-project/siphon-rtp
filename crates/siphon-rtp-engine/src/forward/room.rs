//! The synchronous core of a forwarding room: seats, the chosen source, and the fan-out.
//!
//! No sockets, no tasks, no wall clock. The actor in [`super::registry`] feeds it datagrams and
//! sends what it hands back; the unit tests and the bench drive it directly. Every time reading is
//! a caller-supplied microsecond value (the datapath's receive-time stamp), never `Instant::now()`.
//!
//! # The fan-out
//! [`ForwardRoom::ingest`] runs the shared ingress chain on a datagram ([`crate::seat_gate`]),
//! consumes RTCP, and, when the datagram is RTP from the chosen source, arms a *plan*. The actor then
//! calls [`ForwardRoom::next_datagram`] until it returns `None`: each call rewrites the packet for
//! the next receiving seat through that seat's [`Translator`] (RFC 3550 §7), SRTP-protects it for a
//! secure seat, and lends the bytes out of the room's own scratch buffers. Nothing is allocated per
//! packet, and the source is never a receiver.
//!
//! # What a seat is sent
//! Only a seat that can be reached: its DTLS key and ICE pair settled (an unkeyed seat would be sent
//! plaintext RTP where it expects SRTP), and a resolved destination (the room never forwards into
//! the void, docs/security-and-nat.md §4).

use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_media::ingress::IngressStats;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::RtpPacket;
use siphon_rtp_media::translator::{Forwarded, Translator};
use siphon_rtp_proto::Event;
use siphon_rtp_srtp::leg::SecureLeg;

use super::codec::RoomCodec;
use super::transcode::{EventSource, SeatLeg, StreamPoint, TranscodeStats, Transcoder};
use crate::app_events::AppEventQueue;
use crate::floor_channel::FloorChannelHandle;
use crate::ingress::{Ingress, RefusalLog};
use crate::media_pipeline::Outbound;
use crate::reply_latch::SymmetricLatch;
use crate::sdp::TelephoneEvent;
use crate::seat_gate::{self, RtcpItem, SeatGate};

mod app;

pub(crate) use app::push_failure;
use app::FloorStream;
pub use app::{AppRequest, AppSendError, AppTarget, FloorConfig};

/// The most seats one forwarding room holds. A group call's fan-out is one translate per receiver
/// per packet, so the cap is a statement of what one actor is benchmarked to carry
/// (`docs/cookbook/forwarding.md`), not an arbitrary round number.
pub const MAX_SEATS: usize = 1000;

/// The largest datagram the room builds: an RTP packet inside one Ethernet MTU.
const MAX_DATAGRAM: usize = 1500;

/// Why the room refused a change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    /// The room already holds [`MAX_SEATS`] seats.
    #[error("the room is full ({MAX_SEATS} seats)")]
    RoomFull,
    /// A seat with this from-tag is already in the room.
    #[error("from-tag {0} is already seated in this room")]
    DuplicateTag(String),
    /// No seat has this from-tag.
    #[error("no seat {0} in this room")]
    UnknownTag(String),
    /// The seat's codec cannot be transcoded to and from the room's.
    #[error("{0}")]
    Transcode(String),
}

/// Everything the engine resolves from a seat's SDP to seat it.
pub struct ForwardSeatConfig {
    /// The leg tag (SIP From/To tag): the seat's stable id for routing and events.
    pub tag: String,
    /// The engine socket the seat's RTP and RTCP arrive on and the room sends from (rtcp-mux,
    /// RFC 5761: a forwarding seat is one muxed endpoint).
    pub endpoint: EndpointId,
    /// Where the room sends to the seat; follows the constrained latch when `latch`.
    pub egress_destination: SocketAddr,
    /// Layer 2: the sources the seat may send from.
    pub accepted_source: SourceFilter,
    /// Whether to latch the reply address to the seat's observed source (symmetric RTP).
    pub latch: bool,
    /// The seat's own payload type for the room codec.
    pub audio_payload_type: u8,
    /// The seat's RFC 4733 telephone-event payload type, when it negotiated one.
    pub telephone_event: Option<TelephoneEvent>,
    /// SDES-SRTP state of a secure seat.
    pub secure: Option<SecureLeg>,
    /// A DTLS seat whose handshake has not keyed it yet.
    pub secure_pending: bool,
    /// A full-ICE seat whose agent has not selected a pair yet.
    pub ice_pending: bool,
    /// The seat's egress stream, chosen by the caller so tests are deterministic: a fixed SSRC
    /// and random initial sequence number and timestamp (RFC 3550 §5.1).
    pub egress_ssrc: u32,
    pub initial_sequence: u16,
    pub initial_timestamp: u32,
    /// The seat's MCPTT floor-control stream, when it offered one and the engine anchored it.
    pub floor: Option<FloorConfig>,
    /// Where the seat's RTCP APP events go: the queue of the controller that seated it.
    pub app_events: Option<AppEventQueue>,
}

/// What the room counted about one seat, for logs and stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardSeatStats {
    /// RTP packets the seat sent while it was not the source: counted and dropped.
    pub not_source_dropped: u64,
    /// RTP packets from the seat with a payload type it did not negotiate: dropped.
    pub unknown_payload_type: u64,
    /// Packets the room forwarded to the seat.
    pub forwarded_packets: u32,
    /// Payload octets the room forwarded to the seat.
    pub forwarded_octets: u32,
    /// RTCP APP packets read from the seat (floor stream and audio RTCP), each raised as an event.
    pub app_events: u64,
    /// Datagrams with APP-bearing RTCP the room could not read to the end: counted, no event.
    pub malformed_app: u64,
    /// Packets from the seat, while it was the source, that could not be transcoded for the
    /// cross-codec seats (a payload the decoder refused, or a frame of another length than the
    /// negotiated one). Same-codec seats were still sent them.
    pub transcode_dropped: u64,
}

struct Seat {
    tag: String,
    endpoint: EndpointId,
    egress_destination: SocketAddr,
    accepted_source: SourceFilter,
    latch: bool,
    audio_payload_type: u8,
    telephone_event: Option<TelephoneEvent>,
    secure: Option<SecureLeg>,
    secure_pending: bool,
    ice_pending: bool,
    reverse_latch: SymmetricLatch,
    refusals: RefusalLog,
    translator: Translator,
    /// The seat's codec when it is not the room's: its decoder, and the codec group it is sent in.
    cross: Option<SeatLeg>,
    /// The RTP clock of the audio the seat sends and is sent: the room codec's, or the cross-codec
    /// seat's own (RFC 3551 §4.5).
    clock_rate_hz: u32,
    /// The MCPTT floor-control stream, when the seat has one.
    floor: Option<FloorStream>,
    /// Where this seat's RTCP APP events go.
    app_events: Option<AppEventQueue>,
    /// The seat's floor data channel (a browser seat, docs/control/json.md), when it negotiated one
    /// and has no UDP floor stream. Floor control to the seat is one binary message on it.
    floor_channel: Option<FloorChannelHandle>,
    /// Reception statistics of the seat's own inbound stream, for the reception report block.
    stats: IngressStats,
    /// Middle 32 bits of the NTP timestamp of the seat's last Sender Report (our LSR), and when it
    /// arrived (our DLSR); RFC 3550 §6.4.1.
    last_sender_report_ntp_middle: u32,
    last_sender_report_arrival: Option<u64>,
    /// The room clock, in RTP timestamp units, when the translator last sent this seat a packet (or
    /// when it was seated): maps the SR's NTP time onto the egress timestamp line.
    last_forward_clock: u32,
    counters: ForwardSeatStats,
}

impl Seat {
    /// Whether the room may send this seat anything.
    fn reachable(&self) -> bool {
        !self.secure_pending
            && !self.ice_pending
            && !self.egress_destination.ip().is_unspecified()
            && self.egress_destination.port() != 0
    }
}

/// Which of a seat's endpoints a datagram arrived on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Port {
    /// The audio endpoint (RTP and RTCP muxed).
    Audio,
    /// The MCPTT floor-control endpoint (RTCP APP only).
    Floor,
}

/// What kind of RTP the armed plan forwards.
#[derive(Clone, Copy)]
enum PlanKind {
    Audio,
    /// A telephone-event packet. `original_rate` is the event clock of the source's own packet;
    /// `domain_rate` that of the room-domain packet, which differs only for a cross-codec source
    /// (its events are rescaled to the room codec's clock).
    Event {
        original_rate: u32,
        domain_rate: u32,
    },
}

/// The fan-out of one inbound packet, walked by [`ForwardRoom::next_datagram`].
#[derive(Clone, Copy)]
struct Plan {
    source: usize,
    kind: PlanKind,
    /// The cleartext packet is in the room's decrypt buffer rather than in the datagram.
    in_clear_buffer: bool,
    /// The length of the room-domain packet a cross-codec source's packet became, in the
    /// transcoder's buffer; `None` for a source in the room codec (its own packet is the room-domain
    /// packet).
    domain_len: Option<usize>,
    /// The codec group of a cross-codec source: seats in it are sent the source's packet as it came.
    source_group: Option<usize>,
    /// The header of the room-domain packet.
    point: StreamPoint,
    /// The next seat to consider.
    cursor: usize,
    /// The arrival, in microseconds.
    arrival: u64,
    /// The transcoder's drop count when the plan was armed, to see whether this packet added one.
    dropped_before: u64,
}

/// Which packet a receiver's translator reads.
#[derive(Clone, Copy)]
enum Feed {
    /// The packet as it arrived.
    Original,
    /// The cross-codec source's room-domain packet.
    Domain(usize),
    /// A packet built for a cross-codec receiver.
    Synthesized(usize),
}

/// `micros` of the monotonic clock as ticks of an RTP clock of `rate_hz` (RFC 3550 §5.1).
fn ticks(micros: u64, rate_hz: u32) -> u32 {
    ((u128::from(micros) * u128::from(rate_hz)) / 1_000_000) as u32
}

/// A forwarding room.
pub struct ForwardRoom {
    room_id: String,
    codec: RoomCodec,
    seats: Vec<Seat>,
    by_endpoint: HashMap<EndpointId, (usize, Port)>,
    /// Index of the seat being forwarded, or `None`.
    source: Option<usize>,
    /// The transcoder, once a seat in another codec than the room's has been seated.
    transcoder: Option<Transcoder>,
    /// A source change is waiting for its first forwarded packet to be announced.
    announce_pending: bool,
    plan: Option<Plan>,
    events: Vec<Event>,
    /// Decrypted inbound packet of a secure source, the translator's input.
    clear_in: Vec<u8>,
    /// The translated packet, before SRTP.
    scratch: Vec<u8>,
    /// Floor sends queued for seats' data channels, awaiting their verdicts (see `app.rs`).
    pending_channel: Vec<(String, crate::floor_channel::PendingSend)>,
    /// The SRTP-protected packet.
    secure_out: Vec<u8>,
}

impl ForwardRoom {
    /// An empty room carrying `codec`.
    #[must_use]
    pub fn new(room_id: String, codec: RoomCodec) -> Self {
        Self {
            room_id,
            codec,
            seats: Vec::new(),
            by_endpoint: HashMap::new(),
            source: None,
            transcoder: None,
            announce_pending: false,
            plan: None,
            events: Vec::new(),
            clear_in: Vec::with_capacity(MAX_DATAGRAM),
            scratch: vec![0; MAX_DATAGRAM],
            pending_channel: Vec::new(),
            secure_out: Vec::with_capacity(MAX_DATAGRAM),
        }
    }

    /// The room's codec.
    #[must_use]
    pub fn codec(&self) -> &RoomCodec {
        &self.codec
    }

    /// The room's id.
    #[must_use]
    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// Seats in the room.
    #[must_use]
    pub fn seat_count(&self) -> usize {
        self.seats.len()
    }

    /// Whether the room has no seat left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seats.is_empty()
    }

    /// The tag of the seat being forwarded.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.map(|index| self.seats[index].tag.as_str())
    }

    /// The tag of the seat that owns `endpoint` (its audio or its floor endpoint).
    #[must_use]
    pub fn tag_at(&self, endpoint: EndpointId) -> Option<&str> {
        let &(index, _) = self.by_endpoint.get(&endpoint)?;
        Some(self.seats[index].tag.as_str())
    }

    fn index_of(&self, tag: &str) -> Option<usize> {
        self.seats.iter().position(|seat| seat.tag == tag)
    }

    /// Seat a member in the room's codec. `now_micros` anchors the seat's egress timestamp line.
    ///
    /// # Errors
    /// [`ForwardError::RoomFull`] or [`ForwardError::DuplicateTag`].
    pub fn add_seat(
        &mut self,
        config: ForwardSeatConfig,
        now_micros: u64,
    ) -> Result<(), ForwardError> {
        self.check_vacancy(&config.tag)?;
        let clock_rate_hz = self.codec.clock_rate_hz();
        self.insert_seat(config, None, clock_rate_hz, now_micros);
        Ok(())
    }

    /// Seat a member whose codec `spec` is not the room's. The room decodes the source once per
    /// packet and encodes once per codec group (see [`super::transcode`]); the seat is sent its own
    /// stream in `spec`, under `config.audio_payload_type`. Nothing is seated when the codec cannot
    /// be transcoded.
    ///
    /// # Errors
    /// [`ForwardError::RoomFull`], [`ForwardError::DuplicateTag`], or [`ForwardError::Transcode`]
    /// with the reason the codec cannot be transcoded to and from the room's.
    pub fn add_cross_codec_seat(
        &mut self,
        config: ForwardSeatConfig,
        spec: CodecSpec,
        now_micros: u64,
    ) -> Result<(), ForwardError> {
        self.check_vacancy(&config.tag)?;
        let transcoder = match self.transcoder.as_mut() {
            Some(transcoder) => transcoder,
            None => self
                .transcoder
                .insert(Transcoder::new(self.codec.spec()).map_err(ForwardError::Transcode)?),
        };
        let leg = transcoder
            .seat_leg(&spec)
            .map_err(ForwardError::Transcode)?;
        self.insert_seat(config, Some(leg), spec.clock_rate_hz, now_micros);
        Ok(())
    }

    /// What the transcoder has done: all zero in a room with no cross-codec seat.
    #[must_use]
    pub fn transcode_stats(&self) -> TranscodeStats {
        self.transcoder
            .as_ref()
            .map(Transcoder::stats)
            .unwrap_or_default()
    }

    fn check_vacancy(&self, tag: &str) -> Result<(), ForwardError> {
        if self.seats.len() >= MAX_SEATS {
            return Err(ForwardError::RoomFull);
        }
        if self.index_of(tag).is_some() {
            return Err(ForwardError::DuplicateTag(tag.to_string()));
        }
        Ok(())
    }

    fn insert_seat(
        &mut self,
        config: ForwardSeatConfig,
        cross: Option<SeatLeg>,
        clock_rate_hz: u32,
        now_micros: u64,
    ) {
        let anchor = ticks(now_micros, clock_rate_hz);
        self.by_endpoint
            .insert(config.endpoint, (self.seats.len(), Port::Audio));
        if let Some(floor) = &config.floor {
            self.by_endpoint
                .insert(floor.endpoint, (self.seats.len(), Port::Floor));
        }
        self.seats.push(Seat {
            tag: config.tag,
            endpoint: config.endpoint,
            egress_destination: config.egress_destination,
            accepted_source: config.accepted_source,
            latch: config.latch,
            audio_payload_type: config.audio_payload_type,
            telephone_event: config.telephone_event,
            secure: config.secure,
            secure_pending: config.secure_pending,
            ice_pending: config.ice_pending,
            reverse_latch: SymmetricLatch::default(),
            refusals: RefusalLog::default(),
            translator: Translator::new(
                config.egress_ssrc,
                config.initial_sequence,
                config.initial_timestamp,
            ),
            cross,
            clock_rate_hz,
            floor: config.floor.map(FloorStream::new),
            app_events: config.app_events,
            floor_channel: None,
            stats: IngressStats::new(clock_rate_hz),
            last_sender_report_ntp_middle: 0,
            last_sender_report_arrival: None,
            last_forward_clock: anchor,
            counters: ForwardSeatStats::default(),
        });
    }

    /// Unseat a member. Returns whether it was seated. If it was the source, nothing is forwarded
    /// until the next [`Self::set_source`].
    pub fn remove_seat(&mut self, tag: &str) -> bool {
        let Some(index) = self.index_of(tag) else {
            return false;
        };
        let seat = self.seats.remove(index);
        tracing::info!(
            target: "siphon_rtp::media",
            room = %self.room_id,
            tag,
            not_source_dropped = seat.counters.not_source_dropped,
            unknown_payload_type = seat.counters.unknown_payload_type,
            forwarded_packets = seat.translator.packets_sent(),
            "forwarding room seat left"
        );
        self.by_endpoint.clear();
        for (position, seat) in self.seats.iter().enumerate() {
            self.by_endpoint
                .insert(seat.endpoint, (position, Port::Audio));
            if let Some(floor) = &seat.floor {
                self.by_endpoint
                    .insert(floor.endpoint, (position, Port::Floor));
            }
        }
        self.plan = None;
        match self.source {
            Some(source) if source == index => {
                self.source = None;
                self.announce_pending = false;
                self.switch_every_translator();
                self.end_transcode_run();
            }
            Some(source) if source > index => self.source = Some(source - 1),
            _ => {}
        }
        true
    }

    /// Choose whose audio the room forwards: the seat `tag`, or nobody. A change tells every
    /// receiver's translator to start a new run (RFC 3550 §5.1, marker bit), and arms one
    /// [`Event::ForwardSourceStarted`] for the first packet of the new source that is forwarded.
    /// Choosing the source already chosen changes nothing.
    ///
    /// # Errors
    /// [`ForwardError::UnknownTag`] for a tag no seat has.
    pub fn set_source(&mut self, tag: Option<&str>) -> Result<(), ForwardError> {
        let chosen = match tag {
            Some(tag) => Some(
                self.index_of(tag)
                    .ok_or_else(|| ForwardError::UnknownTag(tag.to_string()))?,
            ),
            None => None,
        };
        if chosen == self.source {
            return Ok(());
        }
        self.source = chosen;
        self.announce_pending = chosen.is_some();
        self.plan = None;
        self.switch_every_translator();
        self.end_transcode_run();
        Ok(())
    }

    /// A new talker is a new stream to the transcoder: its decoder and resamplers start clean.
    fn end_transcode_run(&mut self) {
        if let Some(transcoder) = self.transcoder.as_mut() {
            transcoder.end_run();
        }
    }

    fn switch_every_translator(&mut self) {
        for seat in &mut self.seats {
            seat.translator.switch_source();
        }
    }

    /// Give seat `tag` its floor data channel. `false` when the seat already left.
    pub fn attach_floor_channel(&mut self, tag: &str, channel: FloorChannelHandle) -> bool {
        let Some(index) = self.index_of(tag) else {
            return false;
        };
        self.seats[index].floor_channel = Some(channel);
        true
    }

    /// Install a DTLS seat's key and let the room reach it.
    pub fn attach_secure_leg(&mut self, tag: &str, leg: SecureLeg) {
        let Some(index) = self.index_of(tag) else {
            tracing::warn!(
                room = %self.room_id, tag,
                "DTLS handshake completed for a seat that already left; key discarded"
            );
            return;
        };
        let seat = &mut self.seats[index];
        seat.secure = Some(leg);
        seat.secure_pending = false;
        tracing::info!(
            target: "siphon_rtp::media", room = %self.room_id, tag,
            "DTLS-SRTP handshake complete; forwarding seat keyed"
        );
    }

    /// Open a seat's media path on the pair its ICE agent selected (RFC 8445 §8.1.1): the selected
    /// remote becomes the reply address and the narrowed source gate.
    pub fn ice_selected(&mut self, tag: &str, remote: SocketAddr) {
        let Some(index) = self.index_of(tag) else {
            return;
        };
        let seat = &mut self.seats[index];
        seat.egress_destination = remote;
        seat.accepted_source = SourceFilter::Exact(remote.ip());
        seat.reverse_latch = SymmetricLatch::default();
        seat.refusals = RefusalLog::default();
        seat.ice_pending = false;
        if let Some(floor) = seat.floor.as_mut() {
            floor.ice_selected(remote);
        }
        tracing::info!(
            target: "siphon_rtp::media", room = %self.room_id, tag, %remote,
            "ICE selected a candidate pair for a forwarding seat; media path open"
        );
    }

    /// What the room counted about one seat.
    #[must_use]
    pub fn seat_stats(&self, tag: &str) -> Option<ForwardSeatStats> {
        let seat = &self.seats[self.index_of(tag)?];
        Some(ForwardSeatStats {
            forwarded_packets: seat.translator.packets_sent(),
            forwarded_octets: seat.translator.octets_sent(),
            ..seat.counters
        })
    }

    /// Events staged since the last call.
    pub fn drain_events(&mut self) -> std::vec::Drain<'_, Event> {
        self.events.drain(..)
    }

    /// Ingress one datagram from a seat's endpoint.
    ///
    /// RTCP is consumed here and never forwarded. RTP from the chosen source arms the fan-out
    /// ([`Self::next_datagram`]); RTP from any other seat is counted and dropped after the gate, which
    /// is [`Ingress::DroppedFromPeer`]: it counts in the endpoint's `packets_dropped` and still
    /// stamps liveness, because the seat is alive and merely not talking.
    pub fn ingest(&mut self, packet: &RxPacket) -> Ingress {
        self.plan = None;
        let Some(&(index, port)) = self.by_endpoint.get(&packet.endpoint) else {
            return Ingress::Refused;
        };
        if port == Port::Floor {
            return self.ingest_floor(index, packet);
        }
        let seat = &mut self.seats[index];
        let data = match seat_gate::admit(
            SeatGate {
                component: "forward-room",
                room_id: &self.room_id,
                accepted_source: seat.accepted_source,
                secure_pending: seat.secure_pending,
                ice_pending: seat.ice_pending,
                secure: &mut seat.secure,
                latch: seat.latch,
                reverse_latch: &mut seat.reverse_latch,
                refusals: &seat.refusals,
                egress_destination: &mut seat.egress_destination,
            },
            packet,
            &mut self.clear_in,
        ) {
            Ok(data) => data,
            Err(refused) => return refused,
        };
        let in_clear_buffer = seat.secure.is_some();
        if data.len() < 2 {
            return Ingress::Accepted; // gated in; too short to be media, but the path is alive
        }
        // RFC 5761 demux. The room terminates RTCP: it reads the seat's reports and drops the
        // datagram. Relaying one seat's reports to the others would describe streams the receivers
        // never saw (RFC 3550 §7.3: a translator rewrites reports, it does not echo them).
        if seat_gate::is_rtcp(data) {
            let egress_ssrc = seat.translator.egress_ssrc();
            // APP parts (an MCPTT client may put floor control in its audio RTCP) go to the
            // controller; the reports stay here.
            app::surface_audio_apps(&self.room_id, seat, data);
            seat_gate::consume_rtcp(data, |item| match item {
                RtcpItem::SenderReportNtp(ntp) => {
                    seat.last_sender_report_ntp_middle = ((ntp >> 16) & 0xFFFF_FFFF) as u32;
                    seat.last_sender_report_arrival = Some(packet.arrival);
                }
                RtcpItem::Block(block) => {
                    seat.stats
                        .record_reception_report(egress_ssrc, block, packet.arrival);
                }
            });
            return Ingress::Accepted;
        }
        let Ok(parsed) = RtpPacket::parse(data) else {
            return Ingress::Accepted;
        };
        seat.stats
            .on_rtp(parsed.ssrc, parsed.sequence, parsed.timestamp);
        seat.stats.observe_arrival(packet.arrival);
        if self.source != Some(index) {
            seat.counters.not_source_dropped += 1;
            return Ingress::DroppedFromPeer;
        }
        let kind = if parsed.payload_type == seat.audio_payload_type {
            PlanKind::Audio
        } else if let Some(event) = seat
            .telephone_event
            .filter(|event| event.payload_type == parsed.payload_type)
        {
            PlanKind::Event {
                original_rate: event.clock_rate_hz,
                domain_rate: event.clock_rate_hz,
            }
        } else {
            seat.counters.unknown_payload_type += 1;
            return Ingress::DroppedFromPeer;
        };
        let mut plan = Plan {
            source: index,
            kind,
            in_clear_buffer,
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
        };
        if let Some(transcoder) = self.transcoder.as_mut() {
            plan.dropped_before = transcoder.stats().dropped;
            transcoder.begin_packet();
            let new_run = transcoder.begin_run(parsed.ssrc, parsed.timestamp, seat.cross.is_some());
            if let Some(leg) = seat.cross.as_mut() {
                // A source in another codec is brought into the room codec first (see
                // `transcode`); from here it is forwarded like any other.
                if new_run {
                    leg.restart();
                }
                let converted = match kind {
                    PlanKind::Audio => {
                        transcoder.uplink_audio(leg, plan.point, seat.clock_rate_hz, parsed.payload)
                    }
                    PlanKind::Event { original_rate, .. } => transcoder.uplink_event(
                        plan.point,
                        seat.clock_rate_hz,
                        original_rate,
                        parsed.payload,
                    ),
                };
                let Some(length) = converted else {
                    seat.counters.transcode_dropped += 1;
                    return Ingress::Accepted;
                };
                let Ok(domain) = RtpPacket::parse(transcoder.domain(length)) else {
                    return Ingress::Accepted;
                };
                plan.point.timestamp = domain.timestamp;
                plan.domain_len = Some(length);
                plan.source_group = Some(leg.group());
                if let PlanKind::Event { original_rate, .. } = kind {
                    plan.kind = PlanKind::Event {
                        original_rate,
                        domain_rate: self.codec.clock_rate_hz(),
                    };
                }
            }
        }
        self.plan = Some(plan);
        Ingress::Accepted
    }

    /// The next datagram of the fan-out [`Self::ingest`] armed: the receiving seat's endpoint, its
    /// destination, and the bytes, borrowed from the room's scratch. `packet` must be the datagram
    /// that was just ingested. `None` when every seat has been considered.
    ///
    /// A seat is skipped, silently, when it is the source, cannot be reached, has no
    /// telephone-event payload type at the source's clock rate for an event packet (RFC 4733 §2.1),
    /// cannot be sent the audio in its codec (a drop the source's `transcode_dropped` counts), or the
    /// translator drops the packet as a late one of the previous source.
    pub fn next_datagram<'a>(
        &'a mut self,
        packet: &'a RxPacket,
    ) -> Option<(EndpointId, SocketAddr, &'a [u8])> {
        let mut plan = self.plan?;
        loop {
            let index = plan.cursor;
            if index >= self.seats.len() {
                self.plan = None;
                self.count_transcode_drop(&plan);
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
            let original: &[u8] = if plan.in_clear_buffer {
                &self.clear_in
            } else {
                &packet.data
            };
            let Some((feed, payload_type)) =
                select_feed(&plan, receiver, original, &mut self.transcoder)
            else {
                continue;
            };
            let inbound: &[u8] = match (feed, self.transcoder.as_ref()) {
                (Feed::Original, _) => original,
                (Feed::Domain(length), Some(transcoder)) => transcoder.domain(length),
                (Feed::Synthesized(length), Some(transcoder)) => transcoder.synthesized(length),
                (_, None) => continue,
            };
            // The translator's clock is the receiver's own RTP clock (RFC 3550 §5.1).
            let clock = ticks(plan.arrival, receiver.clock_rate_hz);
            let length =
                match receiver
                    .translator
                    .translate(inbound, payload_type, clock, &mut self.scratch)
                {
                    Ok(Forwarded::Packet { length, .. }) => length,
                    Ok(Forwarded::DroppedStale) => continue,
                    Err(error) => {
                        tracing::debug!(
                            target: "siphon_rtp::media", room = %self.room_id, %error,
                            "forwarding room could not translate a packet"
                        );
                        continue;
                    }
                };
            receiver.last_forward_clock = clock;
            if self.announce_pending {
                self.announce_pending = false;
                self.events.push(Event::ForwardSourceStarted {
                    conference_id: self.room_id.clone(),
                    from_tag: self.seats[plan.source].tag.clone(),
                });
            }
            let receiver = &mut self.seats[index];
            let wire: &[u8] = match receiver.secure.as_mut() {
                Some(secure) => {
                    self.secure_out.clear();
                    if secure
                        .protect(&self.scratch[..length], &mut self.secure_out)
                        .is_err()
                    {
                        continue;
                    }
                    &self.secure_out
                }
                None => &self.scratch[..length],
            };
            return Some((receiver.endpoint, receiver.egress_destination, wire));
        }
    }

    /// Count, once per inbound packet, that the cross-codec seats could not be sent it.
    fn count_transcode_drop(&mut self, plan: &Plan) {
        let dropped = self.transcoder.as_ref().map_or(0, |t| t.stats().dropped);
        if dropped > plan.dropped_before {
            self.seats[plan.source].counters.transcode_dropped += 1;
        }
    }

    /// Build one RTCP Sender Report per reachable seat about the stream it is sent, for NTP
    /// wall-clock `ntp_timestamp` and monotonic `now_micros` (RFC 3550 §6.4.1). The SR carries the
    /// translator's packet and octet counts under its egress SSRC, and an RTP timestamp that sits on
    /// the same line as the packets (the last timestamp sent plus the clock elapsed since), so the NTP
    /// to RTP mapping is consistent. A seat that has sent the room RTP also gets a reception report
    /// block about that stream: loss, jitter, and the LSR/DLSR the seat measures its round trip with.
    pub fn build_reports(&mut self, ntp_timestamp: u64, now_micros: u64, out: &mut Vec<Outbound>) {
        let mut buffer = [0u8; rtcp::SENDER_REPORT_LEN + rtcp::RECEPTION_REPORT_LEN];
        for seat in &mut self.seats {
            if !seat.reachable() {
                continue;
            }
            let block;
            let reports: &[rtcp::ReceptionReport] = if let Some(ssrc) = seat.stats.ssrc() {
                let fraction_lost = seat.stats.fraction_lost_since_last_report();
                block = rtcp::ReceptionReport {
                    ssrc,
                    fraction_lost,
                    cumulative_lost: seat.stats.cumulative_lost(),
                    extended_highest_seq: seat.stats.extended_highest_sequence(),
                    jitter: seat.stats.jitter_rtp_units(),
                    last_sr: seat.last_sender_report_ntp_middle,
                    delay_last_sr: delay_since(seat.last_sender_report_arrival, now_micros),
                };
                std::slice::from_ref(&block)
            } else {
                &[]
            };
            // On the seat's own RTP clock: a cross-codec seat's differs from the room codec's.
            let now_clock = ticks(now_micros, seat.clock_rate_hz);
            let rtp_timestamp = seat
                .translator
                .last_timestamp()
                .wrapping_add(now_clock.wrapping_sub(seat.last_forward_clock));
            let Some(length) = rtcp::write_sender_report(
                seat.translator.egress_ssrc(),
                ntp_timestamp,
                rtp_timestamp,
                seat.translator.packets_sent(),
                seat.translator.octets_sent(),
                reports,
                &mut buffer,
            ) else {
                continue;
            };
            // SRTCP-encrypt the report for a secure seat (RFC 3711 §3.4); plain seats send it as is.
            let wire: &[u8] = match seat.secure.as_mut() {
                Some(secure) => {
                    self.secure_out.clear();
                    if secure
                        .protect(&buffer[..length], &mut self.secure_out)
                        .is_err()
                    {
                        continue;
                    }
                    &self.secure_out
                }
                None => &buffer[..length],
            };
            out.push(Outbound {
                endpoint: seat.endpoint,
                dst: seat.egress_destination,
                data: Bytes::copy_from_slice(wire),
            });
            // Remember the SR so a later reception report about it yields a round trip.
            seat.stats.record_sent_report(ntp_timestamp, now_micros);
        }
    }

    /// The round-trip time the last reception report from `tag` measured, in microseconds.
    #[must_use]
    pub fn round_trip_micros(&self, tag: &str) -> Option<u64> {
        self.seats[self.index_of(tag)?].stats.rtt_micros()
    }
}

/// The room-codec payload of an RTP packet, empty when it does not parse.
fn payload_of(packet: &[u8]) -> &[u8] {
    RtpPacket::parse(packet).map_or(&[], |parsed| parsed.payload)
}

/// Decide what `receiver` is sent for the armed `plan`, and under which payload type, preparing the
/// transcoder's output when the receiver is in another codec group than the source. `None` skips it.
///
/// * A seat in the room codec reads the room-domain packet (the source's own, or a cross-codec
///   source's transcoded one).
/// * A cross-codec seat in the source's own codec group reads the source's packet as it arrived: the
///   payload format is the same, so there is nothing to transcode.
/// * Any other cross-codec seat reads its group's encode of the audio (see [`super::transcode`]).
fn select_feed(
    plan: &Plan,
    receiver: &Seat,
    original: &[u8],
    transcoder: &mut Option<Transcoder>,
) -> Option<(Feed, u8)> {
    let group = receiver.cross.as_ref().map(SeatLeg::group);
    let room_codec_feed = match plan.domain_len {
        Some(length) => Feed::Domain(length),
        None => Feed::Original,
    };
    let Some(group) = group else {
        return match plan.kind {
            PlanKind::Audio => Some((room_codec_feed, receiver.audio_payload_type)),
            PlanKind::Event { domain_rate, .. } => {
                let event = receiver
                    .telephone_event
                    .filter(|event| event.clock_rate_hz == domain_rate)?;
                Some((room_codec_feed, event.payload_type))
            }
        };
    };
    if plan.source_group == Some(group) {
        return match plan.kind {
            PlanKind::Audio => Some((Feed::Original, receiver.audio_payload_type)),
            PlanKind::Event { original_rate, .. } => {
                let event = receiver
                    .telephone_event
                    .filter(|event| event.clock_rate_hz == original_rate)?;
                Some((Feed::Original, event.payload_type))
            }
        };
    }
    let transcoder = transcoder.as_mut()?;
    match plan.kind {
        PlanKind::Audio => {
            if !transcoder.prepare_group(group, || payload_of(original)) {
                return None;
            }
            let length = transcoder.synthesize_audio(group, plan.point, receiver.clock_rate_hz)?;
            Some((Feed::Synthesized(length), receiver.audio_payload_type))
        }
        PlanKind::Event { domain_rate, .. } => {
            let event = receiver.telephone_event?;
            let source = match plan.domain_len {
                Some(length) => EventSource::Domain(length),
                None => EventSource::Original(payload_of(original)),
            };
            let length = transcoder.synthesize_event(
                plan.point,
                source,
                domain_rate,
                event.clock_rate_hz,
                receiver.clock_rate_hz,
            )?;
            Some((Feed::Synthesized(length), event.payload_type))
        }
    }
}

/// DLSR (RFC 3550 §6.4.1): the time since the last SR arrived, in 1/65536 s; zero before any.
fn delay_since(arrival: Option<u64>, now_micros: u64) -> u32 {
    match arrival {
        Some(arrival) => {
            let delay = u128::from(now_micros.saturating_sub(arrival));
            ((delay * 65_536) / 1_000_000).min(u128::from(u32::MAX)) as u32
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests;
