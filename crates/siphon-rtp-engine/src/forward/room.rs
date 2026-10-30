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

use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_media::ingress::IngressStats;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::RtpPacket;
use siphon_rtp_media::translator::{Forwarded, Translator};
use siphon_rtp_proto::Event;
use siphon_rtp_srtp::leg::SecureLeg;

use super::codec::RoomCodec;
use crate::app_events::AppEventQueue;
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
    /// The MCPTT floor-control stream, when the seat has one.
    floor: Option<FloorStream>,
    /// Where this seat's RTCP APP events go.
    app_events: Option<AppEventQueue>,
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
    /// A telephone-event packet at this clock rate.
    TelephoneEvent(u32),
}

/// The fan-out of one inbound packet, walked by [`ForwardRoom::next_datagram`].
#[derive(Clone, Copy)]
struct Plan {
    source: usize,
    kind: PlanKind,
    /// The cleartext packet is in the room's decrypt buffer rather than in the datagram.
    in_clear_buffer: bool,
    /// The next seat to consider.
    cursor: usize,
    /// The arrival, in RTP timestamp units of the room codec.
    clock: u32,
}

/// A forwarding room.
pub struct ForwardRoom {
    room_id: String,
    codec: RoomCodec,
    seats: Vec<Seat>,
    by_endpoint: HashMap<EndpointId, (usize, Port)>,
    /// Index of the seat being forwarded, or `None`.
    source: Option<usize>,
    /// A source change is waiting for its first forwarded packet to be announced.
    announce_pending: bool,
    plan: Option<Plan>,
    events: Vec<Event>,
    /// Decrypted inbound packet of a secure source, the translator's input.
    clear_in: Vec<u8>,
    /// The translated packet, before SRTP.
    scratch: Vec<u8>,
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
            announce_pending: false,
            plan: None,
            events: Vec::new(),
            clear_in: Vec::with_capacity(MAX_DATAGRAM),
            scratch: vec![0; MAX_DATAGRAM],
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

    /// The RTP timestamp-unit reading of a microsecond clock, at the room codec's clock rate.
    fn rtp_clock(&self, micros: u64) -> u32 {
        ((u128::from(micros) * u128::from(self.codec.clock_rate_hz())) / 1_000_000) as u32
    }

    fn index_of(&self, tag: &str) -> Option<usize> {
        self.seats.iter().position(|seat| seat.tag == tag)
    }

    /// Seat a member. `now_micros` anchors the seat's egress timestamp line.
    ///
    /// # Errors
    /// [`ForwardError::RoomFull`] or [`ForwardError::DuplicateTag`].
    pub fn add_seat(
        &mut self,
        config: ForwardSeatConfig,
        now_micros: u64,
    ) -> Result<(), ForwardError> {
        if self.seats.len() >= MAX_SEATS {
            return Err(ForwardError::RoomFull);
        }
        if self.index_of(&config.tag).is_some() {
            return Err(ForwardError::DuplicateTag(config.tag));
        }
        let anchor = self.rtp_clock(now_micros);
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
            floor: config.floor.map(FloorStream::new),
            app_events: config.app_events,
            stats: IngressStats::new(self.codec.clock_rate_hz()),
            last_sender_report_ntp_middle: 0,
            last_sender_report_arrival: None,
            last_forward_clock: anchor,
            counters: ForwardSeatStats::default(),
        });
        Ok(())
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
        Ok(())
    }

    fn switch_every_translator(&mut self) {
        for seat in &mut self.seats {
            seat.translator.switch_source();
        }
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
            PlanKind::TelephoneEvent(event.clock_rate_hz)
        } else {
            seat.counters.unknown_payload_type += 1;
            return Ingress::DroppedFromPeer;
        };
        let clock = self.rtp_clock(packet.arrival);
        self.plan = Some(Plan {
            source: index,
            kind,
            in_clear_buffer,
            cursor: 0,
            clock,
        });
        Ingress::Accepted
    }

    /// The next datagram of the fan-out [`Self::ingest`] armed: the receiving seat's endpoint, its
    /// destination, and the bytes, borrowed from the room's scratch. `packet` must be the datagram
    /// that was just ingested. `None` when every seat has been considered.
    ///
    /// A seat is skipped, silently, when it is the source, cannot be reached, has no
    /// telephone-event payload type at the source's clock rate for an event packet (RFC 4733 §2.1),
    /// or the translator drops the packet as a late one of the previous source.
    pub fn next_datagram<'a>(
        &'a mut self,
        packet: &'a RxPacket,
    ) -> Option<(EndpointId, SocketAddr, &'a [u8])> {
        let mut plan = self.plan?;
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
            let payload_type = match plan.kind {
                PlanKind::Audio => receiver.audio_payload_type,
                PlanKind::TelephoneEvent(rate) => match receiver.telephone_event {
                    Some(event) if event.clock_rate_hz == rate => event.payload_type,
                    _ => continue,
                },
            };
            let inbound: &[u8] = if plan.in_clear_buffer {
                &self.clear_in
            } else {
                &packet.data
            };
            let length = match receiver.translator.translate(
                inbound,
                payload_type,
                plan.clock,
                &mut self.scratch,
            ) {
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
            receiver.last_forward_clock = plan.clock;
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

    /// Build one RTCP Sender Report per reachable seat about the stream it is sent, for NTP
    /// wall-clock `ntp_timestamp` and monotonic `now_micros` (RFC 3550 §6.4.1). The SR carries the
    /// translator's packet and octet counts under its egress SSRC, and an RTP timestamp that sits on
    /// the same line as the packets (the last timestamp sent plus the clock elapsed since), so the NTP
    /// to RTP mapping is consistent. A seat that has sent the room RTP also gets a reception report
    /// block about that stream: loss, jitter, and the LSR/DLSR the seat measures its round trip with.
    pub fn build_reports(&mut self, ntp_timestamp: u64, now_micros: u64, out: &mut Vec<Outbound>) {
        let now_clock = self.rtp_clock(now_micros);
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
