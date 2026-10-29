//! How a seat gets into a room and out of it again: the registry's join and its pending variant for
//! a live call's leg (`conference_seat`), the leg's activation and release, and what a seated call
//! carries on its seat — the call it belongs to, its silence and block gates, its recording taps and
//! its own prompts.

use std::net::SocketAddr;

use siphon_rtp_datapath::{Datapath, SourceFilter};
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::playback::{FinishedPlayback, Gain, OverlayBus, MAX_OVERLAY_SLOTS};
use siphon_rtp_proto::{Event, PlayEndReason};
use siphon_rtp_srtp::leg::SecureLeg;

use super::{
    run_conference, Conference, ConferenceControl, ConferenceHandle, ConferenceInput,
    ConferenceMember, ConferenceRegistry, ParticipantConfig, SeatRefusal, DEFAULT_TOP_M,
    ROOM_TICK_MS, SEAT_VERDICT_TIMEOUT,
};
use crate::media_pipeline::PlayRequest;

/// What a seat carries when it is a leg of a **live call** moved into the room by
/// `conference_seat`, rather than a participant that joined: the call it still belongs to, where that
/// call's events go, and whether the leg multiplexes RTCP onto its RTP port.
#[derive(Clone, Debug)]
pub struct SeatedCall {
    /// The engine key of the call the seated leg belongs to. Events the seat raises name this call,
    /// with the room beside it, so the controller's correlation keeps working across the move.
    pub call_id: String,
    /// The call owner's event sink. A seated leg's events go to the client that owns its call, which
    /// need not be the client whose join created the room.
    pub events: Option<flume::Sender<Event>>,
    /// Whether the room may send this leg RTCP on its RTP port. `false` for a leg whose call never
    /// negotiated `a=rtcp-mux` (RFC 5761 §5.1.1): such a peer expects RTCP on its RTCP port only.
    pub rtcp_mux: bool,
}

/// What opens a live call's pending seat ([`Conference::activate_participant`]): what the engine read
/// off the call's previous media owner once it had stopped, so the seat carries on exactly where the
/// call left off.
pub struct SeatActivation {
    /// The leg's SRTP contexts, rollover and replay state included, when the leg is secure.
    pub secure: Option<SecureLeg>,
    /// The source gate that was in force on the leg (RTPBleed defence, docs/security-and-nat.md §4).
    pub accepted_source: SourceFilter,
    /// Where the leg's party receives: the latched source when one was, else the signalled address.
    pub egress_dst: SocketAddr,
}

/// Prompts played to one seat (`play_media` on a seated call): an overlay bus at the seat's native
/// rate, one tick a frame. A non-overlay prompt *replaces* the room's mix while it plays, as a
/// superseding prompt replaces a call's egress; overlays mix under it.
pub(super) struct SeatPlayback {
    bus: OverlayBus,
    finished: Vec<FinishedPlayback>,
    /// The superseding prompt playing now, if any.
    replacing: Option<u64>,
}

/// What a seated participant hands back when it leaves the room ([`Conference::take_participant`]).
pub struct ReleasedSeat {
    /// Its SRTP contexts, rollover and replay state included; `None` for a plaintext seat.
    pub secure: Option<SecureLeg>,
    /// Its recording taps, `true` for one on what it hears, so its call can keep the recordings.
    pub taps: Vec<(bool, Box<dyn MediaSink>)>,
}

/// What a participant carries when it is a live call's seated leg: everything a joined seat leaves
/// empty.
pub(super) struct CallSeatState {
    /// The call this seat is a leg of, when `conference_seat` moved it in.
    pub(super) call: Option<SeatedCall>,
    /// `silence_media` on a seated call: the seat hears encoded silence instead of the mix.
    pub(super) silenced: bool,
    /// `block_media` on a seated call: the room sends the seat nothing (its egress clock still runs,
    /// so the stream resumes with a timestamp jump rather than a rewound clock, RFC 3550 §5.1).
    pub(super) blocked: bool,
    /// Recording taps on what the party sends, at its native rate.
    pub(super) ingress_taps: Vec<Box<dyn MediaSink>>,
    /// Recording taps on what the room sends the party, after its own prompts.
    pub(super) egress_taps: Vec<Box<dyn MediaSink>>,
    /// The seat's own prompts (`play_media` on the call), mixed into what it hears.
    pub(super) playback: Option<Box<SeatPlayback>>,
}

impl CallSeatState {
    /// The call the seat's events name: its call's own id, or the room's for a joined seat.
    pub(super) fn event_call_id(&self, conference_id: &str) -> String {
        self.call
            .as_ref()
            .map_or_else(|| conference_id.to_string(), |call| call.call_id.clone())
    }

    /// The seated call's id, `None` for a joined seat.
    pub(super) fn call_id(&self) -> Option<String> {
        self.call.as_ref().map(|call| call.call_id.clone())
    }

    /// Deliver an event the seat raised ([`route_seat_event`]).
    pub(super) fn route(&self, staged: &mut Vec<Event>, event: Event) {
        route_seat_event(staged, self.call.as_ref(), event);
    }

    /// Whether the room may send this seat RTCP on its RTP port: not a seated leg that never
    /// negotiated `a=rtcp-mux` (RFC 5761 §5.1.1: such a peer expects RTCP on its RTCP port alone).
    pub(super) fn reports_on_rtp_port(&self) -> bool {
        self.call.as_ref().is_none_or(|call| call.rtcp_mux)
    }

    /// Whether what the seat hears is its own (a prompt, or a recording tap on it), so it cannot
    /// share another listener's encode.
    pub(super) fn shapes_egress(&self) -> bool {
        self.playback.is_some() || !self.egress_taps.is_empty()
    }

    pub(super) fn new(call: Option<SeatedCall>) -> Self {
        Self {
            call,
            silenced: false,
            blocked: false,
            ingress_taps: Vec::new(),
            egress_taps: Vec::new(),
            playback: None,
        }
    }
}

/// A seat operation on a live call's leg, its prompts or its recording taps
/// ([`ConferenceControl::Seat`]).
pub enum SeatControl {
    /// Open a pending seat (a live call's leg, `conference_seat`), keying it with the leg's SRTP state
    /// when it has one ([`Conference::activate_participant`]).
    Activate {
        tag: String,
        activation: Box<SeatActivation>,
    },
    /// Remove a participant and hand its SRTP state back ([`Conference::take_participant`]), so a
    /// seated call leg leaving the room keeps its contexts. `reply` carries `None` for an unknown tag.
    Release {
        tag: String,
        reply: tokio::sync::oneshot::Sender<Option<ReleasedSeat>>,
    },
    /// Tap one seat for a recording ([`Conference::add_seat_tap`]).
    AddSeatTap {
        tag: String,
        egress: bool,
        sink: Box<dyn MediaSink>,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Detach a recording's taps from one seat ([`Conference::remove_seat_taps_tagged`]).
    RemoveSeatTapsTagged { tag: String, label: String },
    /// Play a prompt to one seat ([`Conference::start_seat_playback`]).
    SeatPlay {
        tag: String,
        request: Box<PlayRequest>,
        overlay: bool,
        gain: Gain,
        play_id: u64,
        duration_cap_ms: Option<u64>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Stop one seat's prompt, or all of them ([`Conference::stop_seat_playback`]).
    SeatStopPlay {
        tag: String,
        play_id: Option<u64>,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Retune one seat's prompt ([`Conference::set_seat_play_gain`]).
    SeatPlayGain {
        tag: String,
        play_id: u64,
        gain: Gain,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
    /// Gate what the room sends one seat ([`Conference::set_egress_gate`]). `reply` carries whether
    /// the tag was seated.
    EgressGate {
        tag: String,
        silenced: Option<bool>,
        blocked: Option<bool>,
        reply: tokio::sync::oneshot::Sender<bool>,
    },
}

impl Conference {
    /// Apply one [`SeatControl`]. Returns `true` when a release left the room empty, which tears it
    /// down as a leave does.
    pub(super) fn apply_seat_control(&mut self, control: SeatControl) -> bool {
        match control {
            SeatControl::Activate { tag, activation } => {
                self.activate_participant(&tag, *activation);
            }
            SeatControl::Release { tag, reply } => {
                let released = self.take_participant(&tag);
                let _ = reply.send(released);
                return self.is_empty();
            }
            SeatControl::AddSeatTap {
                tag,
                egress,
                sink,
                reply,
            } => {
                let _ = reply.send(self.add_seat_tap(&tag, egress, sink));
            }
            SeatControl::RemoveSeatTapsTagged { tag, label } => {
                self.remove_seat_taps_tagged(&tag, &label);
            }
            SeatControl::SeatPlay {
                tag,
                request,
                overlay,
                gain,
                play_id,
                duration_cap_ms,
                reply,
            } => {
                let _ = reply.send(self.start_seat_playback(
                    &tag,
                    *request,
                    overlay,
                    gain,
                    play_id,
                    duration_cap_ms,
                ));
            }
            SeatControl::SeatStopPlay {
                tag,
                play_id,
                reply,
            } => {
                let _ = reply.send(self.stop_seat_playback(&tag, play_id));
            }
            SeatControl::SeatPlayGain {
                tag,
                play_id,
                gain,
                reply,
            } => {
                let _ = reply.send(self.set_seat_play_gain(&tag, play_id, gain));
            }
            SeatControl::EgressGate {
                tag,
                silenced,
                blocked,
                reply,
            } => {
                let _ = reply.send(self.set_egress_gate(&tag, silenced, blocked));
            }
        }
        false
    }

    /// A seated call's recording hears what its party sent this tick (`produced` samples staged in
    /// `native_in`), or a tick of silence when it sent nothing — never while the seat is still
    /// pending (nothing of its is in the room yet).
    pub(super) fn tap_seat_ingress(&mut self, index: usize, produced: Option<usize>) {
        let participant = &mut self.participants[index];
        if participant.call_seat.ingress_taps.is_empty() || participant.secure_pending {
            return;
        }
        let said: &[i16] = match produced {
            Some(samples) => &self.native_in[..samples],
            None => &self.tap_silence[..participant.tick_samples],
        };
        for tap in &mut participant.call_seat.ingress_taps {
            tap.write_pcm(said);
        }
    }

    /// Tap one seat: `egress` taps what the room sends it, otherwise what it sends. Returns whether
    /// the tag was seated.
    pub fn add_seat_tap(&mut self, tag: &str, egress: bool, sink: Box<dyn MediaSink>) -> bool {
        let Some(participant) = self.participants.iter_mut().find(|seat| seat.tag == tag) else {
            return false;
        };
        if egress {
            participant.call_seat.egress_taps.push(sink);
        } else {
            participant.call_seat.ingress_taps.push(sink);
        }
        true
    }

    /// Detach every tap labelled `label` from one seat (a recording stopping).
    pub fn remove_seat_taps_tagged(&mut self, tag: &str, label: &str) {
        if let Some(participant) = self.participants.iter_mut().find(|seat| seat.tag == tag) {
            participant
                .call_seat
                .ingress_taps
                .retain(|sink| sink.tag() != Some(label));
            participant
                .call_seat
                .egress_taps
                .retain(|sink| sink.tag() != Some(label));
        }
    }

    /// Start a prompt toward one seat at its own rate. A non-overlay prompt supersedes the one
    /// replacing the mix now (reported `superseded`, as on a call); an overlay is refused when every
    /// slot is taken.
    pub fn start_seat_playback(
        &mut self,
        tag: &str,
        request: PlayRequest,
        overlay: bool,
        gain: Gain,
        play_id: u64,
        duration_cap_ms: Option<u64>,
    ) -> Result<(), String> {
        let Some(index) = self.participants.iter().position(|seat| seat.tag == tag) else {
            return Err("the seat has left the room".to_string());
        };
        let participant = &mut self.participants[index];
        let playback = request
            .into_playback_at(
                participant.native_rate,
                ROOM_TICK_MS as u32,
                gain,
                play_id,
                duration_cap_ms,
            )
            .map_err(|error| error.to_string())?;
        let tick_samples = participant.tick_samples;
        let seat = participant.call_seat.playback.get_or_insert_with(|| {
            Box::new(SeatPlayback {
                bus: OverlayBus::new(tick_samples),
                finished: Vec::with_capacity(MAX_OVERLAY_SLOTS),
                replacing: None,
            })
        });
        if !overlay {
            if let Some(previous) = seat.replacing.take() {
                if let Some(finished) = seat.bus.stop(previous) {
                    seat.finished.push(finished);
                }
            }
        }
        let started = seat.bus.start(playback).map_err(|error| error.to_string());
        if started.is_ok() && !overlay {
            seat.replacing = Some(play_id);
        }
        self.report_seat_playbacks(index, PlayEndReason::Superseded);
        started
    }

    /// Stop one of a seat's prompts, or all of them; each reports `stopped`. Returns whether anything
    /// was stopped.
    pub fn stop_seat_playback(&mut self, tag: &str, play_id: Option<u64>) -> bool {
        let Some(index) = self.participants.iter().position(|seat| seat.tag == tag) else {
            return false;
        };
        let Some(seat) = self.participants[index].call_seat.playback.as_mut() else {
            return false;
        };
        let stopped = match play_id {
            Some(play_id) => match seat.bus.stop(play_id) {
                Some(finished) => {
                    seat.finished.push(finished);
                    true
                }
                None => false,
            },
            None => {
                let before = seat.finished.len();
                seat.bus.stop_all(&mut seat.finished);
                seat.finished.len() > before
            }
        };
        if seat
            .replacing
            .is_some_and(|replacing| !seat.bus.contains(replacing))
        {
            seat.replacing = None;
        }
        self.report_seat_playbacks(index, PlayEndReason::Stopped);
        stopped
    }

    /// Retune one of a seat's prompts. Returns whether that prompt is playing.
    pub fn set_seat_play_gain(&mut self, tag: &str, play_id: u64, gain: Gain) -> bool {
        self.participants
            .iter_mut()
            .find(|seat| seat.tag == tag)
            .and_then(|participant| participant.call_seat.playback.as_mut())
            .is_some_and(|seat| seat.bus.set_gain(play_id, gain))
    }

    /// Report a seat's ended prompts as [`Event::PlayFinished`] for its call, with `reason`.
    pub(super) fn report_seat_playbacks(&mut self, index: usize, reason: PlayEndReason) {
        let participant = &mut self.participants[index];
        let Some(seat) = participant.call_seat.playback.as_mut() else {
            return;
        };
        for finished in seat.finished.drain(..) {
            let event = Event::PlayFinished {
                call_id: participant
                    .call_seat
                    .call
                    .as_ref()
                    .map_or_else(|| self.conference_id.clone(), |call| call.call_id.clone()),
                conference_id: None,
                from_tag: participant.tag.clone(),
                to_tag: None,
                play_id: finished.play_id,
                reason,
                played_ms: Some(finished.played_ms),
            };
            route_seat_event(
                &mut self.pending_events,
                participant.call_seat.call.as_ref(),
                event,
            );
        }
    }

    /// What a seat hears this tick, finished in `native_out[..tick_samples]`: its own prompts mixed
    /// in (a superseding one in place of the room's mix), then handed to its recording taps.
    pub(super) fn finish_seat_egress(&mut self, index: usize, tick_samples: usize) {
        let mut ended = false;
        if let Some(seat) = self.participants[index].call_seat.playback.as_mut() {
            if seat.bus.is_active() {
                if seat.replacing.is_some() {
                    self.native_out[..tick_samples].fill(0);
                }
                seat.bus
                    .mix_into(&mut self.native_out[..tick_samples], &mut seat.finished);
                if seat
                    .replacing
                    .is_some_and(|replacing| !seat.bus.contains(replacing))
                {
                    seat.replacing = None;
                }
                ended = !seat.finished.is_empty();
            }
        }
        if ended {
            self.report_seat_playbacks(index, PlayEndReason::Completed);
        }
        let participant = &mut self.participants[index];
        if participant.call_seat.egress_taps.is_empty() {
            return;
        }
        // A blocked seat hears nothing, and that is what its recording holds.
        let heard: &[i16] = if participant.call_seat.blocked {
            &self.tap_silence[..tick_samples]
        } else {
            &self.native_out[..tick_samples]
        };
        for tap in &mut participant.call_seat.egress_taps {
            tap.write_pcm(heard);
        }
    }

    /// Remove a participant by tag and hand back its SRTP state: `Some(leg)` for a seated
    /// participant, whose `leg` is its [`SecureLeg`] (`None` for a plaintext seat). A seated call leg
    /// leaving the room keeps its SRTP contexts this way, so a later seat or a renegotiation does not
    /// restart its rollover counter while the peer's keeps counting (RFC 3711 §3.3.1).
    pub fn take_participant(&mut self, tag: &str) -> Option<ReleasedSeat> {
        let position = self
            .participants
            .iter()
            .position(|participant| participant.tag == tag)?;
        // Prompts still playing to the seat end with it, reported as a leg torn down mid-play.
        if let Some(seat) = self.participants[position].call_seat.playback.as_mut() {
            seat.bus.stop_all(&mut seat.finished);
        }
        self.report_seat_playbacks(position, PlayEndReason::Error);
        let participant = self.participants.remove(position);
        // Keep the text mixer index-aligned with `participants` (removed at the same position).
        self.text_mixer.remove_participant(position);
        self.recompute_room_rate();
        let taps = participant
            .call_seat
            .ingress_taps
            .into_iter()
            .map(|sink| (false, sink))
            .chain(
                participant
                    .call_seat
                    .egress_taps
                    .into_iter()
                    .map(|sink| (true, sink)),
            )
            .collect();
        Some(ReleasedSeat {
            secure: participant.secure,
            taps,
        })
    }

    /// Open a seat that was taken **pending** (a live call's leg, `conference_seat`): install the
    /// leg's SRTP state when it has one and let its audio into the mix and the mix out to it. The
    /// engine activates a seat only once the call's previous media owner has stopped, so two owners
    /// never send toward the party at once (RFC 3550 §5.1) nor encrypt under one key (RFC 3711 §9.1).
    /// Returns whether the tag was seated.
    pub fn activate_participant(&mut self, tag: &str, activation: SeatActivation) -> bool {
        let Some(participant) = self.participants.iter_mut().find(|seat| seat.tag == tag) else {
            return false;
        };
        if activation.secure.is_some() {
            participant.secure = activation.secure;
        }
        participant.accepted_source = activation.accepted_source;
        participant.egress_dst = activation.egress_dst;
        participant.secure_pending = false;
        true
    }

    /// Gate what the room sends one seat: `silenced` replaces the mix with encoded silence, `blocked`
    /// sends nothing. `None` leaves that gate as it is. Returns whether the tag was seated.
    pub fn set_egress_gate(
        &mut self,
        tag: &str,
        silenced: Option<bool>,
        blocked: Option<bool>,
    ) -> bool {
        let Some(participant) = self.participants.iter_mut().find(|seat| seat.tag == tag) else {
            return false;
        };
        if let Some(silenced) = silenced {
            participant.call_seat.silenced = silenced;
        }
        if let Some(blocked) = blocked {
            participant.call_seat.blocked = blocked;
        }
        true
    }
}

impl ConferenceRegistry {
    /// Seat a participant, creating the room actor (over `datapath`, pushing events to `events`) if it
    /// does not yet exist, and wait for the room's verdict (at most [`SEAT_VERDICT_TIMEOUT`]). A
    /// refused participant leaves no member, route or empty room behind.
    pub async fn join<D>(
        &self,
        conference_id: &str,
        config: ParticipantConfig,
        joined_tick: u64,
        held: bool,
        datapath: D,
        events: Option<flume::Sender<Event>>,
    ) -> Result<(), SeatRefusal>
    where
        D: Datapath + Clone + Send + 'static,
    {
        self.seat(
            conference_id,
            config,
            joined_tick,
            held,
            datapath,
            events,
            true,
        )
        .await
    }

    /// Seat a live call's leg **pending** (`conference_seat`): the room takes the seat and answers
    /// its verdict exactly as for a join, so every refusal is known before the call is touched, but
    /// no datagram is routed to it and the room sends it nothing until [`Self::activate_call_seat`].
    /// `config.secure_pending` must be set, which is what holds the seat shut in the actor.
    pub async fn seat_call<D>(
        &self,
        conference_id: &str,
        config: ParticipantConfig,
        joined_tick: u64,
        held: bool,
        datapath: D,
        events: Option<flume::Sender<Event>>,
    ) -> Result<(), SeatRefusal>
    where
        D: Datapath + Clone + Send + 'static,
    {
        self.seat(
            conference_id,
            config,
            joined_tick,
            held,
            datapath,
            events,
            false,
        )
        .await
    }

    /// Open a seat [`Self::seat_call`] took with the leg's SRTP state, source gate and destination,
    /// then route its endpoint to the room. The activation is queued ahead of the first datagram the new
    /// route delivers, so the seat is never handed media it is not yet keyed for. Returns `false`
    /// when the seat or its room is gone, or the room's mailbox would not take the activation.
    pub fn activate_call_seat(
        &self,
        conference_id: &str,
        tag: &str,
        activation: SeatActivation,
    ) -> bool {
        let Some((mailbox, endpoint)) = self.rooms.get(conference_id).and_then(|room| {
            let endpoint = room
                .members
                .iter()
                .find(|member| member.tag == tag)?
                .endpoint;
            Some((room.mailbox.clone(), endpoint))
        }) else {
            return false;
        };
        let activate = ConferenceControl::Seat(SeatControl::Activate {
            tag: tag.to_string(),
            activation: Box::new(activation),
        });
        if mailbox
            .try_send(ConferenceInput::Control(activate))
            .is_err()
        {
            return false;
        }
        self.routes.insert(endpoint, mailbox);
        true
    }

    /// Take a seated call leg back out of the room (`conference_leave` on it, or the call's
    /// `delete`), handing back its SRTP state so the call keeps its contexts. Unlike
    /// [`Self::leave`] it returns no endpoint to free: the leg is still its call's. `None` when no
    /// such seat exists. Tears the room down once its last seat is out.
    pub async fn release_call_seat(&self, conference_id: &str, tag: &str) -> Option<ReleasedSeat> {
        let (mailbox, endpoints, empty) = {
            let mut handle = self.rooms.get_mut(conference_id)?;
            let position = handle.members.iter().position(|member| member.tag == tag)?;
            let member = handle.members.remove(position);
            let mut endpoints = vec![member.endpoint];
            endpoints.extend(member.text_endpoint);
            (handle.mailbox.clone(), endpoints, handle.members.is_empty())
        };
        // Routes first, so nothing more reaches the seat while it is handed back.
        for endpoint in &endpoints {
            self.routes.remove(endpoint);
        }
        let (reply, released) = tokio::sync::oneshot::channel();
        let released = match mailbox.try_send(ConferenceInput::Control(ConferenceControl::Seat(
            SeatControl::Release {
                tag: tag.to_string(),
                reply,
            },
        ))) {
            Ok(()) => match tokio::time::timeout(SEAT_VERDICT_TIMEOUT, released).await {
                Ok(Ok(Some(released))) => Some(released),
                _ => None,
            },
            Err(_) => None,
        };
        let released = released.unwrap_or_else(|| {
            tracing::warn!(
                conference = %conference_id,
                tag,
                "conference did not hand back a released seat's SRTP state and taps"
            );
            ReleasedSeat {
                secure: None,
                taps: Vec::new(),
            }
        });
        if empty {
            if let Some((_, handle)) = self.rooms.remove(conference_id) {
                let _ = handle
                    .mailbox
                    .try_send(ConferenceInput::Control(ConferenceControl::Stop));
                handle.task.abort();
                self.forget_bridges(conference_id, &handle.bridged_with);
            }
        }
        Some(released)
    }

    /// The engine key of the call whose leg is seated as `tag` in `conference_id`, if that seat is a
    /// `conference_seat` leg.
    #[must_use]
    pub fn seated_call(&self, conference_id: &str, tag: &str) -> Option<String> {
        self.rooms.get(conference_id).and_then(|room| {
            room.members
                .iter()
                .find(|member| member.tag == tag)
                .and_then(|member| member.call_id.clone())
        })
    }

    /// Send a seat op that answers on `reply` to a room and wait for the answer (at most
    /// [`SEAT_VERDICT_TIMEOUT`]). `None` when the room is gone or did not answer.
    pub async fn ask<T>(
        &self,
        conference_id: &str,
        control: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> SeatControl,
    ) -> Option<T> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        if !self.control(conference_id, ConferenceControl::Seat(control(reply))) {
            return None;
        }
        tokio::time::timeout(SEAT_VERDICT_TIMEOUT, answer)
            .await
            .ok()?
            .ok()
    }

    /// Gate what the room sends one seat (`silence_media` / `block_media` on a seated call), waiting
    /// for the room to apply it. Returns whether the seat exists.
    pub async fn set_egress_gate(
        &self,
        conference_id: &str,
        tag: &str,
        silenced: Option<bool>,
        blocked: Option<bool>,
    ) -> bool {
        let (reply, applied) = tokio::sync::oneshot::channel();
        if !self.control(
            conference_id,
            ConferenceControl::Seat(SeatControl::EgressGate {
                tag: tag.to_string(),
                silenced,
                blocked,
                reply,
            }),
        ) {
            return false;
        }
        matches!(
            tokio::time::timeout(SEAT_VERDICT_TIMEOUT, applied).await,
            Ok(Ok(true))
        )
    }

    /// Seat a participant (see [`Self::join`]); `route` says whether its endpoints are routed to the
    /// room now (a join) or only on activation (a live call's leg, [`Self::seat_call`]).
    #[allow(clippy::too_many_arguments)]
    async fn seat<D>(
        &self,
        conference_id: &str,
        config: ParticipantConfig,
        joined_tick: u64,
        held: bool,
        datapath: D,
        events: Option<flume::Sender<Event>>,
        route: bool,
    ) -> Result<(), SeatRefusal>
    where
        D: Datapath + Clone + Send + 'static,
    {
        let endpoint = config.ingress_endpoint;
        // A text leg's endpoint is routed to the same room actor (RFC 9071 multiparty text), so a
        // T.140/RED datagram redirected for it reaches this room's `ingest`.
        let text_endpoint = config.text.as_ref().map(|text| text.ingress_endpoint);
        let tag = config.tag.clone();
        let member = ConferenceMember {
            tag: tag.clone(),
            endpoint,
            text_endpoint,
            joined_tick,
            held,
            sip_call_id: config.telemetry.sip_call_id.clone(),
            qos_codec: (config.mos_codec, config.decoder.rtp_clock_rate_hz().max(1)),
            call_id: config.call.as_ref().map(|call| call.call_id.clone()),
            events: events.clone(),
        };
        let mailbox = {
            let mut handle = self
                .rooms
                .entry(conference_id.to_string())
                .or_insert_with(|| {
                    let (mailbox, inbox) = flume::bounded(1024);
                    let mut conference = Conference::new(conference_id.to_string(), DEFAULT_TOP_M);
                    conference.rtcp_tap = datapath.rtcp_tap();
                    let task = tokio::spawn(run_conference(conference, inbox, datapath, events));
                    ConferenceHandle {
                        mailbox,
                        members: Vec::new(),
                        bridged_with: Vec::new(),
                        task,
                    }
                });
            // Refused before the room is asked, so a second join under a seated tag (or one still
            // waiting for its verdict) cannot take the first one's member entry with it.
            if handle.members.iter().any(|seated| seated.tag == tag) {
                return Err(SeatRefusal::DuplicateTag(tag));
            }
            handle.members.push(member);
            handle.mailbox.clone()
        };
        let (reply, verdict) = tokio::sync::oneshot::channel();
        let add = ConferenceControl::Add {
            config: Box::new(config),
            reply,
        };
        // No verdict means the actor is gone, or still has not answered.
        let seated = match mailbox.try_send(ConferenceInput::Control(add)) {
            Ok(()) => match tokio::time::timeout(SEAT_VERDICT_TIMEOUT, verdict).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(_)) | Err(_) => Err(SeatRefusal::NoVerdict),
            },
            Err(_) => Err(SeatRefusal::NoVerdict),
        };
        if let Err(refusal) = seated {
            // `leave` also asks the actor to remove the tag, so a seat it takes after the timeout
            // does not outlive the refused join, and it tears down a room this join created.
            self.leave(conference_id, &tag);
            return Err(refusal);
        }
        if !route {
            return Ok(());
        }
        self.routes.insert(endpoint, mailbox.clone());
        if let Some(text_endpoint) = text_endpoint {
            self.routes.insert(text_endpoint, mailbox);
        }
        Ok(())
    }
}

/// Deliver an event a seat raised: straight to its call owner's sink for a seated call leg, so it
/// reaches the client that owns the call whoever created the room; staged for the room's sink for a
/// joined participant. A full or closed sink drops it, as every event path does — late events are
/// worthless and the room never blocks on a slow consumer.
pub(super) fn route_seat_event(staged: &mut Vec<Event>, call: Option<&SeatedCall>, event: Event) {
    match call.and_then(|call| call.events.as_ref()) {
        Some(sink) => {
            if sink.try_send(event).is_err() {
                tracing::debug!("seated call event dropped (sink full or closed)");
            }
        }
        None => staged.push(event),
    }
}
