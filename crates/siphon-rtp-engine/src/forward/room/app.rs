//! The MCPTT floor-control stream of a forwarding-room seat, and RTCP APP in both directions
//! (3GPP TS 24.380 §8; RFC 3550 §6.7).
//!
//! A seat may carry a second endpoint for `m=application <port> udp MCPTT`, which holds nothing but
//! RTCP APP packets. The room does not interpret them: every APP packet read from the floor stream,
//! or out of the seat's audio RTCP, becomes an [`Event::RtcpApp`] for the controller that seated the
//! seat, and the controller answers with [`ForwardRoom::send_app`]. Floor traffic is never
//! forwarded to another seat.
//!
//! # Why the floor stream has its own latch
//! The audio path learns the seat's reply address with an SSRC-consistent latch (RFC 3550 §8), which
//! cannot work here: the stream carries only RTCP, and `rtp_media_ssrc` reads none from RTCP. A
//! source with no SSRC to prove it is the same stream is accepted once and never moved
//! ([`OpaqueLatch`], docs/security-and-nat.md §4 layer 5h), exactly the T.38 fax posture.

use std::net::SocketAddr;

use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_media::rtcp::{self, AppWriteError};
use siphon_rtp_proto::RtcpAppStream;

use super::{ForwardRoom, ForwardSeatStats, Seat};
use crate::app_events::{surface_app_to_queue, AppEventQueue, AppScope};
use crate::ingress::{Ingress, Refusal, RefusalContext, RefusalLog};
use crate::reply_latch::{OpaqueLatch, ReplyLatch};

/// The floor endpoint of a seat, as the engine resolves it from the offer.
pub struct FloorConfig {
    /// The engine socket the seat's floor stream arrives on and the room sends from.
    pub endpoint: EndpointId,
    /// Where the room sends floor control until the first gated datagram latches the source: the
    /// floor m-line's signalled address, or the `received_from` hint with its port.
    pub destination: SocketAddr,
    /// Layer 2: the sources the floor stream may come from.
    pub accepted_source: SourceFilter,
    /// The filter is open only because ICE decides the transport; [`ForwardRoom::ice_selected`]
    /// narrows it to the selected pair's address.
    pub ice_gated: bool,
}

pub(super) struct FloorStream {
    pub(super) endpoint: EndpointId,
    destination: SocketAddr,
    accepted_source: SourceFilter,
    ice_gated: bool,
    latch: OpaqueLatch,
    refusals: RefusalLog,
}

impl FloorStream {
    pub(super) fn new(config: FloorConfig) -> Self {
        Self {
            endpoint: config.endpoint,
            destination: config.destination,
            accepted_source: config.accepted_source,
            ice_gated: config.ice_gated,
            latch: OpaqueLatch::default(),
            refusals: RefusalLog::default(),
        }
    }

    /// ICE selected a pair for the seat: a floor stream that was held open only for it narrows to
    /// the selected address (the latch has learned nothing yet, because floor is refused until now).
    pub(super) fn ice_selected(&mut self, remote: SocketAddr) {
        if self.ice_gated {
            self.accepted_source = SourceFilter::Exact(remote.ip());
        }
    }
}

/// Which seats a [`ForwardRoom::send_app`] addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppTarget {
    /// One seat, by from-tag.
    Seat(String),
    /// Every seat but those in `except` (tags that name no seat are ignored: the seat may have left).
    Room { except: Vec<String> },
}

/// The RTCP APP packet a controller asks the room to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRequest {
    /// The stream it travels on.
    pub stream: RtcpAppStream,
    /// SSRC written into the packet; `None` is the engine's own SSRC toward each seat, which is the
    /// seat's translator egress SSRC (the SSRC the seat's receive stream is announced under, RFC 3550
    /// §7), so it differs per seat.
    pub ssrc: Option<u32>,
    /// The four-octet name (RFC 3550 §6.7).
    pub name: [u8; 4],
    /// The 5-bit subtype.
    pub subtype: u8,
    /// The application-dependent data, a multiple of four octets.
    pub payload: Vec<u8>,
}

/// Why [`ForwardRoom::send_app`] did not send to every addressed seat.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppSendError {
    /// The packet itself is not a valid RTCP APP packet.
    #[error("{0}")]
    Packet(#[from] AppWriteError),
    /// No seat has this from-tag.
    #[error("no seat {0} in this room")]
    UnknownSeat(String),
    /// Some addressed seats could not be sent to: `tag (reason)` for each. The others were sent.
    #[error("not sent to: {0}")]
    NotSent(String),
}

/// Why one seat cannot be sent an APP packet right now.
fn unreachable_reason(seat: &Seat, stream: RtcpAppStream) -> Option<&'static str> {
    match stream {
        RtcpAppStream::Floor => match (&seat.floor, &seat.floor_channel) {
            (Some(_), _) if seat.secure_pending || seat.ice_pending => {
                Some("floor stream not open yet")
            }
            (Some(floor), _) if !usable(floor.destination) => Some("no floor destination yet"),
            (Some(_), _) => None,
            // A seat with no UDP floor stream but a data channel (a browser seat).
            (None, Some(channel)) if !channel.is_open() => Some("floor data channel not open yet"),
            (None, Some(_)) => None,
            (None, None) => Some("no floor stream"),
        },
        RtcpAppStream::Audio => {
            if seat.reachable() {
                None
            } else {
                Some("audio path not open yet")
            }
        }
    }
}

fn usable(destination: SocketAddr) -> bool {
    !destination.ip().is_unspecified() && destination.port() != 0
}

/// Raise one [`Event::RtcpApp`] for every APP packet in `data`, in order, counting them and any
/// datagram that could not be read to the end into the seat's counters.
fn surface_apps(
    room_id: &str,
    tag: &str,
    queue: Option<&AppEventQueue>,
    counters: &mut ForwardSeatStats,
    stream: RtcpAppStream,
    data: &[u8],
) {
    surface_app_to_queue(
        AppScope::Room(room_id),
        tag,
        queue,
        stream,
        data,
        &mut counters.app_events,
        &mut counters.malformed_app,
    );
}

/// Raise the APP events of a seat's audio RTCP (a compound with an APP part; SR and RR stay with the
/// room).
pub(super) fn surface_audio_apps(room_id: &str, seat: &mut Seat, data: &[u8]) {
    surface_apps(
        room_id,
        &seat.tag,
        seat.app_events.as_ref(),
        &mut seat.counters,
        RtcpAppStream::Audio,
        data,
    );
}

impl ForwardRoom {
    /// Ingress one datagram that arrived on the floor endpoint of seat `index`.
    ///
    /// The floor stream passes the same gate as the seat's audio: layer 2 (the signalled source), a
    /// seat whose DTLS key or ICE pair is still pending is refused, and the learn-once latch stands
    /// in for layer 3. Then each APP packet in it is raised as an event. Anything accepted counts as
    /// the seat being alive, which is what keeps `forward_seat_inactive` from firing for a seat that
    /// only ever sends floor traffic.
    pub(super) fn ingest_floor(&mut self, index: usize, packet: &RxPacket) -> Ingress {
        let seat = &mut self.seats[index];
        let (secure_pending, ice_pending) = (seat.secure_pending, seat.ice_pending);
        let Some(floor) = seat.floor.as_mut() else {
            return Ingress::Refused;
        };
        let context = RefusalContext {
            component: "forward-room-floor",
            call_id: &self.room_id,
            endpoint: packet.endpoint,
            source: packet.source,
            expected: floor.accepted_source,
        };
        // Layer 2 (docs/security-and-nat.md §4): an unsignalled source never reaches the controller.
        if !floor.accepted_source.accepts(packet.source.ip()) {
            floor.refusals.log(Refusal::UnsignalledSource, context);
            return Ingress::Refused;
        }
        // The floor opens when the seat's audio path does (DTLS keyed, ICE pair selected).
        if secure_pending || ice_pending {
            return Ingress::Refused;
        }
        // Layer 5h: learn the reply address once, never move it (RFC 3550 §8 has no SSRC to offer).
        match floor.latch.admit(packet.source) {
            ReplyLatch::Reject => {
                floor.refusals.log(Refusal::NewSource, context);
                return Ingress::Refused;
            }
            ReplyLatch::Accept(Some(destination)) => floor.destination = destination,
            ReplyLatch::Accept(None) => {}
        }
        surface_apps(
            &self.room_id,
            &seat.tag,
            seat.app_events.as_ref(),
            &mut seat.counters,
            RtcpAppStream::Floor,
            &packet.data,
        );
        Ingress::Accepted
    }

    /// Send one RTCP APP packet to the seats `target` names, handing each datagram to `emit` as
    /// (endpoint, destination, bytes) borrowed from the room's scratch. Nothing is allocated.
    ///
    /// A room-wide send addresses every seat that has the requested stream (a seat with no floor
    /// stream has no floor control to send), minus the excepted ones. A seat that has the stream but
    /// cannot be reached yet (never sent into the void: no destination, ICE or DTLS pending) is not
    /// sent to and is named in the error; the rest are still sent. An audio-stream packet is
    /// SRTCP-protected on a secure seat (RFC 3711 §3.4); the floor stream is plain in this build, and
    /// is never protected.
    ///
    /// # Errors
    /// [`AppSendError`]: an invalid packet (nothing sent), an unknown single seat (nothing sent), or
    /// the seats that were not sent to.
    pub fn send_app(
        &mut self,
        target: &AppTarget,
        request: &AppRequest,
        mut emit: impl FnMut(EndpointId, SocketAddr, &[u8]),
    ) -> Result<(), AppSendError> {
        // Validate the packet once, up front: a bad request sends to nobody.
        rtcp::write_app(
            request.subtype,
            0,
            request.name,
            &request.payload,
            &mut self.scratch,
        )?;
        let single = match target {
            AppTarget::Seat(tag) => Some(
                self.index_of(tag)
                    .ok_or_else(|| AppSendError::UnknownSeat(tag.clone()))?,
            ),
            AppTarget::Room { .. } => None,
        };
        let mut failures = String::new();
        for index in 0..self.seats.len() {
            let seat = &mut self.seats[index];
            let addressed = match (&single, target) {
                (Some(only), _) => *only == index,
                (None, AppTarget::Room { except }) => {
                    !except.contains(&seat.tag)
                        // Room-wide floor control skips a seat that has no floor stream at all.
                        && (request.stream == RtcpAppStream::Audio
                            || seat.floor.is_some()
                            || seat.floor_channel.is_some())
                }
                (None, AppTarget::Seat(_)) => false,
            };
            if !addressed {
                continue;
            }
            if let Some(reason) = unreachable_reason(seat, request.stream) {
                push_failure(&mut failures, &seat.tag, reason);
                continue;
            }
            let ssrc = request
                .ssrc
                .unwrap_or_else(|| seat.translator.egress_ssrc());
            let length = rtcp::write_app(
                request.subtype,
                ssrc,
                request.name,
                &request.payload,
                &mut self.scratch,
            )?;
            match request.stream {
                RtcpAppStream::Floor => {
                    if let Some(floor) = seat.floor.as_ref() {
                        emit(floor.endpoint, floor.destination, &self.scratch[..length]);
                    } else if let Some(channel) = seat.floor_channel.as_ref() {
                        // One binary message carrying the packet exactly as it would be on the wire.
                        let message = bytes::Bytes::copy_from_slice(&self.scratch[..length]);
                        match channel.submit(message) {
                            Ok(pending) => self.pending_channel.push((seat.tag.clone(), pending)),
                            Err(error) => {
                                push_failure(&mut failures, &seat.tag, &error.to_string());
                            }
                        }
                    }
                }
                RtcpAppStream::Audio => {
                    let wire: &[u8] = match seat.secure.as_mut() {
                        Some(secure) => {
                            self.secure_out.clear();
                            if secure
                                .protect(&self.scratch[..length], &mut self.secure_out)
                                .is_err()
                            {
                                push_failure(&mut failures, &seat.tag, "SRTCP protect failed");
                                continue;
                            }
                            &self.secure_out
                        }
                        None => &self.scratch[..length],
                    };
                    emit(seat.endpoint, seat.egress_destination, wire);
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(AppSendError::NotSent(failures))
        }
    }
}

impl ForwardRoom {
    /// The floor sends [`Self::send_app`] queued for seats' data channels since the last call. The
    /// caller awaits each one (`PendingSend::wait`) so `ok` means on the wire, as for a UDP seat.
    pub fn take_pending_channel_sends(
        &mut self,
    ) -> Vec<(String, crate::floor_channel::PendingSend)> {
        std::mem::take(&mut self.pending_channel)
    }
}

/// Append `tag (reason)` to a failure list.
pub(crate) fn push_failure(failures: &mut String, tag: &str, reason: &str) {
    if !failures.is_empty() {
        failures.push_str(", ");
    }
    failures.push_str(tag);
    failures.push_str(" (");
    failures.push_str(reason);
    failures.push(')');
}
