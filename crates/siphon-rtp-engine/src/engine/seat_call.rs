//! `conference_seat`: move one leg of a live call into a conference room, in place.
//!
//! A three-way call starts from two calls that are already up. Seating one of their legs through
//! `conference_join` or `conference_offer` would mean re-INVITEing the far party to move its media a
//! few ports along on the same host. This verb seats the leg where it stands instead: same engine
//! endpoint, same latched peer, same codec and payload types, same SRTP contexts or DTLS association,
//! same ICE pair. Nothing the far party was told changes, so nothing is signalled to it.
//!
//! The order is what makes a refusal atomic. Everything that can refuse — the call's shape, the
//! codec, the room's verdict on the seat — is settled while the call still relays as it did. Only
//! then does the engine stop the call's media owner, take the leg's state off it, open the seat with
//! that state, and finally release the leg's former peer. A refusal after the peer was released would
//! be a dropped call, so there is no such refusal.
//!
//! The call stays in the registry with the seated leg as its one (near) leg, which is what keeps the
//! controller's view of it: `delete` returns its summary with counters continuous across the move
//! (they are the endpoint's own), and the seat's events name the call.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction, SourceFilter};
use siphon_rtp_proto::{CmdResult, ConferenceRole, Event, MediaTimeoutReason};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::CryptoAttribute;

use crate::conference::{ParticipantConfig, SeatActivation, SeatTelemetry, SeatedCall};
use crate::dtls_bridge::PipelineTarget;
use crate::sdp;
use crate::srtp_bridge::BridgeLeg;
use siphon_rtp_media::fanout::MediaSink;

use super::negotiate::random_ssrc;
use super::room::{build_seat_codec, routing_of};
use super::{
    error_result, ok_empty, unknown_call, CallerMediaLeg, ClientId, Engine, Leg, NearSecureKey,
    Party, PipelineKind,
};

/// Where a call's leg sits once `conference_seat` has moved it into a room.
#[derive(Debug, Clone)]
pub(super) struct CallSeat {
    /// The room the leg is (or was last) seated in.
    pub(super) conference_id: String,
    /// The seat's tag in the room: the leg's own tag in its call.
    pub(super) tag: String,
    /// `false` once `conference_leave` took the leg back out. The call is then a one-legged call on
    /// the same endpoint that relays nothing, which the controller deletes or seats again.
    pub(super) seated: bool,
    /// The source gate in force on the leg, kept for a later seat of the same leg.
    pub(super) accepted_source: SourceFilter,
    /// Where the leg's party receives, kept for the same reason.
    pub(super) remote: SocketAddr,
    /// Whether the leg's endpoint carries a DTLS association, which the bridge keeps across the move.
    pub(super) dtls: bool,
    /// The activity tick a `media_timeout` was last raised at: a seated leg that stays silent is
    /// reported once per silence, not on every sweep, and fresh media re-arms the report.
    pub(super) timeout_reported_at: Option<u64>,
}

/// Everything read off a call before anything is changed: the leg being seated, the leg being
/// released, and how the call's media is carried today.
struct SeatPlan {
    owner: ClientId,
    leg: Leg,
    /// The leg released once the seat is in. `None` when a leg taken back out by `conference_leave`
    /// is seated again: it has no peer left.
    peer: Option<Leg>,
    party: Party,
    pipeline: PipelineKind,
    relay_flows: Vec<(EndpointId, FlowAction)>,
    codec: CodecSpec,
    telephone_event: Option<sdp::TelephoneEvent>,
    direction: sdp::MediaDirection,
    sip_call_id: Option<String>,
    /// The leg's SDES keys `(engine's, party's)`, when the engine terminates its SRTP.
    sdes: Option<(CryptoAttribute, CryptoAttribute)>,
    /// The leg's party is keyed by a DTLS handshake the engine terminates.
    dtls: bool,
    media_started_at_unix_ms: Option<u64>,
    /// For a leg seated again after `conference_leave`: what its last seat recorded. Its SRTP
    /// contexts, which the room handed back when it left, are taken off the call when the move runs.
    reseat: Option<CallSeat>,
}

/// What the call's previous media owner left for the seat once it stopped.
struct TakenOver {
    secure: Option<SecureLeg>,
    accepted_source: SourceFilter,
    /// The SSRC of the stream the seated party was receiving, for its RTCP `BYE`.
    relayed_ssrc: Option<u32>,
}

/// Clears a call's `seating` flag however the move ends, so a refused or failed seat never leaves the
/// call locked against the next command.
struct SeatingGuard<'a> {
    calls: &'a dashmap::DashMap<String, super::Call>,
    key: String,
}

impl Drop for SeatingGuard<'_> {
    fn drop(&mut self) {
        if let Some(mut call) = self.calls.get_mut(&self.key) {
            call.seating = false;
        }
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Seat one leg of a live call in a conference room, in place ([`Command::ConferenceSeat`]).
    ///
    /// [`Command::ConferenceSeat`]: siphon_rtp_proto::Command::ConferenceSeat
    pub(super) async fn conference_seat(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        conference_id: &str,
        role: ConferenceRole,
    ) -> CmdResult {
        let plan = match self.plan_seat(client, call_id, from_tag) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };
        let _guard = SeatingGuard {
            calls: &self.calls,
            key: call_id.to_string(),
        };
        // The room has to decode the leg and encode the mix back in its own codec, and hold its frame:
        // refused here, before anything is touched, when this build cannot (RFC 3264 leaves the codec
        // as negotiated; the room adapts to it, never the reverse).
        let seat_codec = match build_seat_codec(plan.codec.clone()) {
            Ok(seat_codec) => seat_codec,
            Err(reason) => {
                return error_result(
                    "conference_seat",
                    &format!(
                        "{} payload type {}: {reason}",
                        plan.codec.encoding_name, plan.codec.payload_type
                    ),
                )
            }
        };
        if plan.dtls && !self.dtls_bridge().has_key(plan.leg.rtp.id) {
            return error_result(
                "conference_seat",
                &"the leg's DTLS-SRTP handshake has not completed",
            );
        }
        // Where the party receives: the ICE-validated pair, else the source the call latched, else
        // what it signalled. Read now, while the call's owner still reports it.
        let remote = match plan.reseat.as_ref() {
            Some(seat) => Some(seat.remote),
            None => self
                .datapath
                .ice_validated_source(plan.leg.rtp.id)
                .or_else(|| self.latched_remote(&plan.leg))
                .or(plan.leg.remote_rtp),
        };
        let Some(remote) = remote else {
            return error_result("conference_seat", &"the leg has no known peer address");
        };
        // A decoded recording running on the call carries over: its sinks are rebuilt here, for the
        // seat, before anything moves — they hold the recording's file open across the handover,
        // and a rate this build cannot convert refuses the seat with the call untouched.
        let party_is_a = plan.party == Party::Near;
        let carried = match self.carried_recording_sinks(call_id, party_is_a, &plan.codec) {
            Ok(carried) => carried,
            Err(reason) => return error_result("conference_seat", &reason),
        };

        // The seat goes in pending: the room answers its verdict now — full, tag taken, a frame it
        // cannot hold — while the call still relays exactly as before, and it routes nothing to the
        // seat and sends it nothing until it is activated below.
        let owner_events = self.event_sink(plan.owner);
        let config = ParticipantConfig {
            tag: from_tag.to_string(),
            decoder: seat_codec.decoder,
            encoder: seat_codec.encoder,
            ingress_endpoint: plan.leg.rtp.id,
            egress_endpoint: plan.leg.rtp.id,
            egress_dst: remote,
            accepted_source: SourceFilter::Exact(remote.ip()),
            latch: true,
            // The room originates its own stream toward the party: a new SSRC, sequence and timestamp
            // base, which RFC 3550 §8 permits. The first packet carries the marker bit (§5.1).
            egress_ssrc: random_ssrc(),
            egress_payload_type: plan.codec.payload_type,
            secure_pending: true,
            ice_pending: false,
            mos_codec: crate::conference::hep_codec_for_name(&plan.codec.encoding_name),
            telephone_event_in: plan.telephone_event.map(|event| event.payload_type),
            secure: None,
            text: None,
            routing: routing_of(role),
            telemetry: SeatTelemetry {
                local: Some(plan.leg.rtp.local_addr),
                sip_call_id: plan.sip_call_id.clone(),
            },
            call: Some(SeatedCall {
                call_id: call_id.to_string(),
                events: owner_events.clone(),
                rtcp_mux: plan.leg.rtcp.is_none(),
            }),
        };
        let held = !plan.direction.peer_sends();
        if let Err(refusal) = self
            .conference
            .seat_call(
                conference_id,
                config,
                self.datapath.now_ticks(),
                held,
                self.datapath.clone(),
                self.event_sink(client),
            )
            .await
        {
            return error_result("conference_seat", &refusal);
        }

        // From here on nothing refuses: the room has the seat. Take the leg off its current owner.
        let taken = self
            .take_over_leg(call_id, conference_id, from_tag, &plan)
            .await;
        let taken = match taken {
            Ok(taken) => taken,
            Err(reason) => {
                // Only an internal invariant breaks here (a key held by an owner the engine cannot
                // reach). The previous owner may already be stopped, so say so plainly.
                tracing::error!(
                    target: "siphon_rtp::media",
                    call_id,
                    conference = conference_id,
                    reason,
                    "conference_seat could not take the leg's media over"
                );
                self.conference
                    .release_call_seat(conference_id, from_tag)
                    .await;
                return error_result(
                    "conference_seat",
                    &format!("{reason}; the call's media path is stopped, delete the call"),
                );
            }
        };

        // Say goodbye for the stream the party was receiving, where the leg carries RTCP, before the
        // room's own stream starts (RFC 3550 §6.3.7): the party sees one source end and another begin
        // rather than a silent SSRC change.
        let mut secure = taken.secure;
        if plan.reseat.is_none() {
            self.send_goodbye(&plan.leg, remote, taken.relayed_ssrc, secure.as_mut())
                .await;
        }

        let activated = self.conference.activate_call_seat(
            conference_id,
            from_tag,
            SeatActivation {
                secure,
                accepted_source: taken.accepted_source,
                egress_dst: remote,
            },
        );
        if !activated {
            tracing::error!(
                target: "siphon_rtp::media",
                call_id,
                conference = conference_id,
                "conference_seat: the room closed before the seat opened"
            );
            self.conference
                .release_call_seat(conference_id, from_tag)
                .await;
            return error_result(
                "conference_seat",
                &"the room closed before the seat opened; the call's media path is stopped, \
                  delete the call",
            );
        }
        // The leg's datagrams now go to the dispatcher, which routes them to the room. A DTLS leg's
        // endpoint already redirects to its bridge, which keeps the association and forwards the
        // media on to the room.
        if !plan.dtls {
            if let Err(error) = self
                .datapath
                .install_flow(plan.leg.rtp.id, FlowAction::Redirect)
            {
                tracing::error!(target: "siphon_rtp::media", call_id, %error, "conference_seat: redirect the seated leg");
            }
        }
        // A separate RTCP port: the room multiplexes, so it takes nothing from here (RFC 5761 §5.1.1).
        if let Some(rtcp) = plan.leg.rtcp {
            if let Err(error) = self.datapath.install_flow(rtcp.id, FlowAction::Drop) {
                tracing::debug!(target: "siphon_rtp::media", call_id, %error, "conference_seat: park the seated leg's RTCP port");
            }
        }
        // A seat on an ICE leg keeps following the pair ICE validates.
        self.follow_seat_ice(plan.leg.rtp.id);
        // The recordings go on from the seat, into the same files.
        self.attach_carried_recordings(conference_id, from_tag, party_is_a, carried)
            .await;

        // Only now, with the seat in, is the former peer released.
        if let Some(peer) = plan.peer {
            self.release_peer_leg(&peer).await;
        }

        let seat = CallSeat {
            conference_id: conference_id.to_string(),
            tag: from_tag.to_string(),
            seated: true,
            accepted_source: taken.accepted_source,
            remote,
            dtls: plan.dtls,
            timeout_reported_at: None,
        };
        let recorded = self.calls.get_mut(call_id).map(|mut call| {
            record_seat(&mut call, &plan, seat);
        });
        if recorded.is_none() {
            // Deleted while it moved: `delete` freed the endpoints; take the seat back out too.
            self.conference
                .release_call_seat(conference_id, from_tag)
                .await;
            return unknown_call(call_id);
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            conference = conference_id,
            tag = from_tag,
            "call leg seated in conference"
        );
        ok_empty()
    }

    /// Read everything the seat needs off the call, refusing a call whose leg cannot be seated in
    /// place, and mark the call `seating`.
    fn plan_seat(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
    ) -> Result<SeatPlan, Box<CmdResult>> {
        let refuse = |reason: &str| Err(Box::new(error_result("conference_seat", &reason)));
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return Err(Box::new(unknown_call(call_id)));
        };
        if !call.admits(client, call_id) {
            return Err(Box::new(unknown_call(call_id)));
        }
        if call.seating {
            return refuse("another conference_seat is moving this call's leg");
        }
        // A leg taken back out by `conference_leave` may be seated again; it is the call's near leg.
        if let Some(seat) = call.seat.clone() {
            if seat.seated {
                return refuse(&format!(
                    "the call's leg is already seated in conference {}",
                    seat.conference_id
                ));
            }
            if seat.tag != from_tag {
                return refuse(&format!(
                    "from-tag {from_tag} is not this call's remaining leg ({})",
                    seat.tag
                ));
            }
            let Some(codec) = call.near_codec.clone() else {
                return refuse("the call's leg has no negotiated codec");
            };
            let plan = SeatPlan {
                owner: call.owner,
                leg: call.near,
                peer: None,
                party: Party::Near,
                pipeline: call.pipeline,
                relay_flows: Vec::new(),
                codec,
                telephone_event: call.near_telephone_event,
                direction: call.near_direction,
                sip_call_id: call.near_sip_call_id.clone(),
                sdes: None,
                dtls: seat.dtls,
                media_started_at_unix_ms: call.near_media_started_at_unix_ms,
                reseat: Some(seat),
            };
            call.seating = true;
            return Ok(plan);
        }
        if call.is_single_leg() || call.far_offer_pending() {
            return refuse(
                "only an answered two-party call's leg can be seated (this call has no far party)",
            );
        }
        let Some(far) = call.far else {
            return refuse("only an answered two-party call's leg can be seated");
        };
        let party = if call.from_tag == from_tag {
            Party::Near
        } else if call.to_tag.as_deref() == Some(from_tag) {
            Party::Far
        } else {
            return refuse(&format!(
                "from-tag {from_tag} names neither leg of this call"
            ));
        };
        match call.pipeline {
            PipelineKind::Ws => {
                return refuse(
                    "a WebSocket-takeover call's leg is bridged to its media server; detach the \
                     bridge first",
                )
            }
            PipelineKind::Seated => return refuse("the call's leg is already seated"),
            _ => {}
        }
        if call.fax_passthrough {
            return refuse(
                "the call is pinned to opaque relay (fax_passthrough), and a room decodes the leg",
            );
        }
        // An offerer's SRTP the engine relays end to end without holding a key for it: the room
        // could only mix ciphertext.
        if call.near_secure && call.near_local_crypto.is_none() && call.near_dtls.is_none() {
            return refuse(
                "the call's SRTP runs end to end between the parties; the engine holds no key to \
                 decrypt the leg",
            );
        }
        if call.near.text.is_some()
            || far.text.is_some()
            || call.near.image.is_some()
            || far.image.is_some()
        {
            return refuse(
                "the call carries a text or fax stream besides its audio; a room seats audio only",
            );
        }
        let (leg, peer, codec, telephone_event, direction, sip_call_id, sdes, dtls, started) =
            match party {
                Party::Near => (
                    call.near,
                    far,
                    call.near_codec.clone(),
                    call.near_telephone_event,
                    call.near_direction,
                    call.near_sip_call_id.clone(),
                    call.near_local_crypto.zip(call.near_remote_crypto),
                    call.near_dtls.is_some(),
                    call.near_media_started_at_unix_ms,
                ),
                Party::Far => (
                    far,
                    call.near,
                    call.far_codec.clone(),
                    call.far_telephone_event
                        .map(|payload_type| sdp::TelephoneEvent {
                            payload_type,
                            clock_rate_hz: sdp::TelephoneEvent::DEFAULT_CLOCK_RATE_HZ,
                        }),
                    call.far_direction,
                    call.far_sip_call_id.clone(),
                    call.far_local_crypto.zip(call.far_remote_crypto),
                    call.far_dtls,
                    call.far_media_started_at_unix_ms,
                ),
            };
        let Some(codec) = codec else {
            return refuse("the leg has no negotiated codec");
        };
        if let Some(attached) = self.seat_blocking_attachment(call_id, &call.promotion_reasons) {
            return refuse(&format!(
                "{attached} is attached to the call; stop it first (the room would drop it)"
            ));
        }
        call.seating = true;
        Ok(SeatPlan {
            owner: call.owner,
            leg,
            peer: Some(peer),
            party,
            pipeline: call.pipeline,
            relay_flows: call.relay_flows.clone(),
            codec,
            telephone_event,
            direction,
            sip_call_id,
            sdes,
            dtls,
            media_started_at_unix_ms: started,
            reseat: None,
        })
    }

    /// The first feature attached to the call's current media owner that a seat would silently end,
    /// named for the refusal. A room carries none of them, so the controller decides rather than the
    /// engine quietly dropping an interception, a recording or a stream.
    fn seat_blocking_attachment(
        &self,
        call_id: &str,
        promotion_reasons: &std::collections::HashSet<super::PromotionReason>,
    ) -> Option<&'static str> {
        use super::PromotionReason;
        // A decoded recording carries over to the seat, and a prompt hold only says the call once
        // played one (a prompt still playing ends, reported `stopped`). What is left is named.
        let blocking = |reason: &PromotionReason| match reason {
            PromotionReason::AudioRecording | PromotionReason::MediaOp => None,
            PromotionReason::Recording => Some("a pcap recording (start_recording format pcap)"),
            PromotionReason::DtmfBlock => Some("a DTMF block (block_dtmf)"),
            PromotionReason::Echo => Some("echo mode (echo)"),
            PromotionReason::WsTee => Some("a WebSocket tee (attach_ws_tee)"),
            PromotionReason::X3 => Some("a lawful interception (attach_x3)"),
            PromotionReason::TextEvents | PromotionReason::Secure => {
                Some("a text stream (text_events)")
            }
        };
        if self.x3_sessions.contains_key(call_id) {
            Some("a lawful interception (attach_x3)")
        } else if self.ws_tees.contains_key(call_id) {
            Some("a WebSocket tee (attach_ws_tee)")
        } else if self.ws_bridges.contains_key(call_id) {
            Some("a WebSocket bridge (attach_ws_bridge)")
        } else if self
            .subscriptions
            .get(call_id)
            .is_some_and(|subscriptions| !subscriptions.is_empty())
        {
            Some("a media subscription (subscribe_request)")
        } else {
            promotion_reasons.iter().find_map(blocking)
        }
    }

    /// For each decoded recording running on the call, sinks rebuilt for the seat of the party
    /// `party_is_a` names, converting its native rate into the recording's. What the party says goes
    /// to the channel that carried its voice; what the room sends it, to the channel that carried
    /// what it heard — so a stereo file keeps the party on its own side and the mix on the other.
    #[allow(clippy::type_complexity)]
    fn carried_recording_sinks(
        &self,
        call_id: &str,
        party_is_a: bool,
        codec: &CodecSpec,
    ) -> Result<Vec<(String, Vec<(bool, Box<dyn MediaSink>)>)>, String> {
        use siphon_rtp_media::bridge::tee::WsTeeSink;
        use siphon_rtp_media::bridge::wire_rate::wire_resampler;

        let mut carried = Vec::new();
        for entry in self.recordings.iter() {
            let recording = entry.value();
            if recording.call_id != call_id {
                continue;
            }
            let Some(taps) = recording.taps.as_ref() else {
                continue;
            };
            // Gone: the recording is finishing on its own (a duration or silence limit fired).
            let Some(mixer) = taps.mixer.upgrade() else {
                continue;
            };
            let party_rate = super::record::pcm_rate_of(codec)?;
            let mut sinks: Vec<(bool, Box<dyn MediaSink>)> = Vec::new();
            for (source, channel) in &taps.layout {
                let resampler =
                    wire_resampler(party_rate, taps.rate).map_err(|error| error.to_string())?;
                let sink = WsTeeSink::new(
                    *channel,
                    mixer.clone(),
                    recording.recording_id.clone(),
                    resampler,
                );
                sinks.push((!source.is_voice_of(party_is_a), Box::new(sink)));
            }
            carried.push((recording.recording_id.clone(), sinks));
        }
        Ok(carried)
    }

    /// Put the rebuilt recording sinks on the open seat and record where each recording now lives.
    /// The sinks they replace (on the stopped actor or bridge, or parked on the call) are dropped
    /// here or already were; the file's frame assembler counted the new ones in first, so no channel
    /// closed in between.
    #[allow(clippy::type_complexity)]
    async fn attach_carried_recordings(
        &self,
        conference_id: &str,
        tag: &str,
        party_is_a: bool,
        carried: Vec<(String, Vec<(bool, Box<dyn MediaSink>)>)>,
    ) {
        for (recording_id, sinks) in carried {
            for (egress, sink) in sinks {
                let attached = self
                    .conference
                    .ask(conference_id, |reply| {
                        crate::conference::SeatControl::AddSeatTap {
                            tag: tag.to_string(),
                            egress,
                            sink,
                            reply,
                        }
                    })
                    .await;
                if attached != Some(true) {
                    tracing::error!(
                        target: "siphon_rtp::media",
                        conference = conference_id,
                        recording_id,
                        "a carried recording's sink did not reach the seat"
                    );
                }
            }
            if let Some(mut recording) = self.recordings.get_mut(&recording_id) {
                recording.ingress_legs.clear();
                recording.egress_legs.clear();
                // A bridged call's tap decoders end with the flows the seat removed.
                recording.bridge_taps.clear();
                if let Ok(mut parked) = recording.parked.lock() {
                    parked.clear();
                }
                recording.seat = Some((conference_id.to_string(), tag.to_string()));
                // From here on the seated party is the call's one (near) leg.
                if let Some(taps) = recording.taps.as_mut() {
                    for (source, _) in &mut taps.layout {
                        *source = if source.is_voice_of(party_is_a) {
                            super::record::TapSource::Ingress { source_a: true }
                        } else {
                            super::record::TapSource::Egress { toward_a: true }
                        };
                    }
                }
            }
        }
    }

    /// Stop whatever carries the call's media today and take the seated leg's state off it: its SRTP
    /// contexts, the source gate in force, and the SSRC of the stream its party was receiving.
    async fn take_over_leg(
        &self,
        call_id: &str,
        conference_id: &str,
        tag: &str,
        plan: &SeatPlan,
    ) -> Result<TakenOver, String> {
        let endpoint = plan.leg.rtp.id;
        let conference_target = || PipelineTarget::Conference {
            conference: self.conference.clone(),
            conference_id: conference_id.to_string(),
            tag: tag.to_string(),
        };
        // A leg taken back out by `conference_leave` has no owner but its retained key and, for DTLS,
        // the bridge flow still pointed at the room it left.
        if let Some(seat) = plan.reseat.as_ref() {
            if plan.dtls {
                self.dtls_bridge()
                    .hand_to_conference(endpoint, conference_target())
                    .map_err(str::to_string)?;
            }
            let retained = self
                .calls
                .get_mut(call_id)
                .and_then(|mut call| call.near_secure_key.take());
            let secure = match retained {
                Some(NearSecureKey(leg)) => Some(owned_leg(leg, None)?),
                None => None,
            };
            return Ok(TakenOver {
                secure,
                accepted_source: seat.accepted_source,
                relayed_ssrc: None,
            });
        }
        let peer_endpoint = plan.peer.map(|peer| peer.rtp.id);
        let all_endpoints: Vec<EndpointId> = plan
            .leg
            .endpoint_ids()
            .chain(plan.peer.iter().flat_map(Leg::endpoint_ids))
            .collect();
        let forward_gate =
            plan.relay_flows
                .iter()
                .find_map(|(installed_on, action)| match action {
                    FlowAction::Forward(rule) if *installed_on == endpoint => {
                        Some(rule.accepted_source)
                    }
                    _ => None,
                });
        // A URL prompt still fetching for this call would start playing into a pipeline that is gone.
        self.cancel_pending_fetches_for_call(call_id, siphon_rtp_proto::PlayEndReason::Stopped);

        if self.media.is_media_call(call_id) {
            // The userspace pipeline: a transcode, a secure transcode, a DTLS media leg, or a relay
            // promoted for a feature. It hands each party's SRTP contexts back as it stops.
            // A prompt still playing on the actor ends here, reported as stopped, rather than
            // vanishing with it.
            self.media
                .control(call_id, crate::media_pipeline::MediaControl::StopPlay);
            let surrendered = self.media.surrender(call_id).await.ok_or_else(|| {
                "the call's media pipeline did not hand its legs over".to_string()
            })?;
            // The direction toward the party: B→A for the near party, A→B for the far one.
            let (gate_index, leg_arc, toward_party) = match plan.party {
                Party::Near => (0, surrendered.near_leg, &surrendered.quality.b_to_a),
                Party::Far => (1, surrendered.far_leg, &surrendered.quality.a_to_b),
            };
            // A transcoded direction originates its own stream; a relayed one forwards the other
            // party's verbatim, so its ingress SSRC is what the party was receiving.
            let relayed_ssrc = toward_party.egress_ssrc.or(toward_party.ssrc);
            let accepted_source = surrendered.gates[gate_index].1;
            if plan.dtls {
                // The bridge keeps the association and now forwards the leg's media to the room.
                self.dtls_bridge()
                    .hand_to_conference(endpoint, conference_target())
                    .map_err(str::to_string)?;
            }
            // Drop any bridge flow left on the peer (a DTLS party's handshake side among them).
            self.bridge
                .deregister(plan.peer.iter().flat_map(Leg::endpoint_ids));
            let secure = match leg_arc {
                Some(leg) => Some(owned_leg(leg, plan.sdes.as_ref())?),
                None => None,
            };
            return Ok(TakenOver {
                secure,
                accepted_source,
                relayed_ssrc,
            });
        }
        match plan.pipeline {
            PipelineKind::Srtp | PipelineKind::SrtpOfferer | PipelineKind::SrtpTranscrypt => {
                // The SDES crypto bridge: the party's contexts live in its flows.
                let party = match plan.party {
                    Party::Near => BridgeLeg::Near,
                    Party::Far => BridgeLeg::Far,
                };
                let leg_arc = self.bridge.party_leg(endpoint, party);
                let accepted_source = self
                    .bridge
                    .accepted_source(endpoint)
                    .ok_or_else(|| "the call's SRTP bridge has no flow on the leg".to_string())?;
                let relayed_ssrc = peer_endpoint.and_then(|peer| self.bridge.latched_ssrc(peer));
                self.bridge.deregister(all_endpoints.iter().copied());
                let secure = match leg_arc {
                    Some(leg) => Some(owned_leg(leg, plan.sdes.as_ref())?),
                    None => None,
                };
                Ok(TakenOver {
                    secure,
                    accepted_source,
                    relayed_ssrc,
                })
            }
            PipelineKind::Dtls | PipelineKind::DtlsOfferer => {
                let dtls = self.dtls_bridge();
                let accepted_source = dtls
                    .accepted_source(endpoint)
                    .ok_or_else(|| "the call's DTLS bridge has no flow on the leg".to_string())?;
                if plan.dtls {
                    // The DTLS party: its key moves out of the relaying flow, which becomes the
                    // seat's (the association is untouched), and the plain side goes with the peer.
                    let secure = dtls
                        .hand_to_conference(endpoint, conference_target())
                        .map_err(str::to_string)?;
                    self.bridge
                        .deregister(plan.peer.iter().flat_map(Leg::endpoint_ids));
                    Ok(TakenOver {
                        secure,
                        accepted_source,
                        relayed_ssrc: None,
                    })
                } else {
                    // The plain party: the DTLS side is the peer and leaves with its association.
                    self.bridge.deregister(all_endpoints.iter().copied());
                    Ok(TakenOver {
                        secure: None,
                        accepted_source,
                        relayed_ssrc: None,
                    })
                }
            }
            _ => {
                // The in-kernel (or XDP) relay: the forward rule on the leg is its gate, and the peer's
                // latch knows the stream it relayed. The seat promotes the leg to the decoding path
                // simply by redirecting its endpoint to the dispatcher once the seat is open.
                let accepted_source = forward_gate.unwrap_or_else(|| {
                    plan.leg
                        .remote_rtp
                        .map_or(SourceFilter::Any, |remote| SourceFilter::Exact(remote.ip()))
                });
                let relayed_ssrc = peer_endpoint.and_then(|peer| self.datapath.latched_ssrc(peer));
                Ok(TakenOver {
                    secure: None,
                    accepted_source,
                    relayed_ssrc,
                })
            }
        }
    }

    /// Send the RTCP compound that says `ssrc` is leaving toward the seated party: on its RTCP port
    /// when it does not multiplex, else on its RTP port, SRTCP-protected on a secure leg.
    async fn send_goodbye(
        &self,
        leg: &Leg,
        remote: SocketAddr,
        ssrc: Option<u32>,
        secure: Option<&mut SecureLeg>,
    ) {
        let Some(ssrc) = ssrc else {
            return;
        };
        let mut compound = [0u8; siphon_rtp_media::rtcp::GOODBYE_LEN];
        let Some(len) = siphon_rtp_media::rtcp::write_goodbye(ssrc, &mut compound) else {
            return;
        };
        let mut protected = Vec::new();
        let wire: &[u8] = match secure {
            Some(secure) => {
                if secure.protect(&compound[..len], &mut protected).is_err() {
                    return;
                }
                &protected
            }
            None => &compound[..len],
        };
        let (endpoint, dst) = match (leg.rtcp, leg.remote_rtcp) {
            (Some(rtcp), Some(remote_rtcp)) => (rtcp.id, remote_rtcp),
            _ => (leg.rtp.id, remote),
        };
        if let Err(error) = self.datapath.send(endpoint, dst, wire).await {
            tracing::debug!(target: "siphon_rtp::media", %error, "RTCP BYE for the relayed stream not sent");
        }
    }

    /// Free the leg a seat released: its endpoints, and the consent, ICE and TURN state on them.
    async fn release_peer_leg(&self, peer: &Leg) {
        for endpoint in peer.all_endpoint_ids() {
            if let Some(consent) = &self.consent {
                consent.unregister(endpoint);
            }
            if let Some(agents) = &self.ice_agents {
                agents.unregister(endpoint);
            }
            self.ice_relays.remove(&endpoint);
            self.endpoint_calls.remove(&endpoint);
            self.awaiting_media.remove(&endpoint);
            self.datapath.remove_endpoint(endpoint).await;
        }
    }

    /// `conference_leave` for a seated call leg: take it out of the room and back to its call as a
    /// one-legged call on the same endpoint, keeping its SRTP contexts and DTLS association, so the
    /// controller can delete it or seat it again. `None` when `tag` is not a seated call leg.
    pub(super) async fn unseat_call(
        &self,
        client: ClientId,
        conference_id: &str,
        tag: &str,
    ) -> Option<CmdResult> {
        let call_id = self.conference.seated_call(conference_id, tag)?;
        let admitted = self
            .calls
            .get(&call_id)
            .is_some_and(|call| call.admits(client, &call_id));
        if !admitted {
            return Some(error_result(
                "conference_leave",
                &"no such conference participant",
            ));
        }
        let released = self.conference.release_call_seat(conference_id, tag).await;
        let Some(mut call) = self.calls.get_mut(&call_id) else {
            return Some(ok_empty());
        };
        let endpoint = call.near.rtp.id;
        let dtls = call.seat.as_ref().is_some_and(|seat| seat.dtls);
        if let Some(seat) = call.seat.as_mut() {
            seat.seated = false;
            seat.timeout_reported_at = None;
        }
        let taps = match released {
            Some(released) => {
                if let Some(leg) = released.secure {
                    call.near_secure_key = Some(NearSecureKey(Arc::new(Mutex::new(leg))));
                }
                released.taps
            }
            None => Vec::new(),
        };
        drop(call);
        // A recording running on the seat keeps going on the one-legged call: its sinks are parked
        // with it, holding the file open, until it stops, the call ends or the leg is seated again.
        for (_, sink) in taps {
            let Some(label) = sink.tag().map(str::to_string) else {
                continue;
            };
            if let Some(mut recording) = self.recordings.get_mut(&label) {
                recording.seat = None;
                if let Ok(mut parked) = recording.parked.lock() {
                    parked.push(sink);
                }
            }
        }
        self.stop_seat_ice_follow(&[endpoint]);
        // Nothing owns the leg's media now: it is dropped, counted, and judged by the call sweep. A
        // DTLS leg's endpoint stays with its bridge, which keeps the association for a later seat.
        if !dtls {
            if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Drop) {
                tracing::debug!(target: "siphon_rtp::media", %error, "conference_leave: park the unseated leg");
            }
        }
        Some(ok_empty())
    }

    /// The room a call's leg is seated in, if it is.
    pub(super) fn seated_room(&self, call_id: &str) -> Option<(String, String)> {
        self.calls.get(call_id).and_then(|call| {
            call.seat
                .as_ref()
                .filter(|seat| seat.seated)
                .map(|seat| (seat.conference_id.clone(), seat.tag.clone()))
        })
    }

    /// Take a seated call's leg out of its room as the call ends (`delete`, or a teardown), so the
    /// room's roster — and `siphon_rtp_conference_participants` — drop it with the call.
    pub(super) async fn release_seat_of(&self, call: &super::Call) {
        let Some(seat) = call.seat.as_ref().filter(|seat| seat.seated) else {
            return;
        };
        self.conference
            .release_call_seat(&seat.conference_id, &seat.tag)
            .await;
        self.stop_seat_ice_follow(&[call.near.rtp.id]);
    }

    /// Report a seated call leg whose media went silent, without freeing it: [`Event::MediaTimeout`]
    /// for the call, naming the room, once per silence. Returns whether a report went out.
    pub(super) fn report_seat_timeout(
        &self,
        call_id: &str,
        reason: MediaTimeoutReason,
        last_activity: u64,
    ) -> bool {
        let Some((owner, event)) = self.calls.get_mut(call_id).and_then(|mut call| {
            let owner = call.owner;
            let seat = call.seat.as_mut().filter(|seat| seat.seated)?;
            if seat.timeout_reported_at == Some(last_activity) {
                return None;
            }
            seat.timeout_reported_at = Some(last_activity);
            let event = Event::MediaTimeout {
                call_id: call_id.to_string(),
                from_tag: seat.tag.clone(),
                conference_id: Some(seat.conference_id.clone()),
                reason,
            };
            Some((owner, event))
        }) else {
            return false;
        };
        tracing::warn!(
            target: "siphon_rtp::media",
            call_id,
            ?reason,
            "seated call leg went silent; reported, left allocated for the controller to delete"
        );
        self.push_event(owner, event);
        true
    }
}

/// Rewrite the call as the seat leaves it: one (near) leg, the seated one, and no pipeline of its
/// own. Everything the summary, the events and the sweep read off a call keeps reading true.
fn record_seat(call: &mut super::Call, plan: &SeatPlan, seat: CallSeat) {
    if plan.reseat.is_none() {
        call.near = plan.leg;
        call.far = None;
        call.from_tag = seat.tag.clone();
        call.to_tag = None;
        call.caller_media_leg = CallerMediaLeg::Near;
        call.near_codec = Some(plan.codec.clone());
        call.far_codec = None;
        call.near_telephone_event = plan.telephone_event;
        call.far_telephone_event = None;
        call.near_direction = plan.direction;
        call.far_direction = sdp::MediaDirection::SendRecv;
        call.near_sip_call_id = plan.sip_call_id.clone();
        call.far_sip_call_id = None;
        call.near_media_started_at_unix_ms = plan.media_started_at_unix_ms;
        call.far_media_started_at_unix_ms = None;
        call.relay_flows.clear();
        call.promotion_reasons.clear();
        // The room holds the leg's keys now; the call's copies would only go stale.
        call.near_local_crypto = None;
        call.near_remote_crypto = None;
        call.far_local_crypto = None;
        call.far_remote_crypto = None;
        call.near_dtls = None;
        call.far_dtls = false;
        call.near_secure = plan.sdes.is_some() || plan.dtls;
        call.local_answer = None;
        if plan.party == Party::Far {
            call.near_remote_ice = call.far_remote_ice.take();
        }
        call.far_remote_ice = None;
    }
    call.near_secure_key = None;
    call.pipeline = PipelineKind::Seated;
    call.seat = Some(seat);
}

/// The one owned copy of a leg's SRTP contexts once every other holder has let go of it. Should a
/// holder linger, an SDES leg is rebuilt from its keys and seeded with the live rollover and replay
/// state (RFC 3711 §3.3.1), which is the same state; a DTLS leg has no keys to rebuild from.
fn owned_leg(
    leg: Arc<Mutex<SecureLeg>>,
    sdes: Option<&(CryptoAttribute, CryptoAttribute)>,
) -> Result<SecureLeg, String> {
    match Arc::try_unwrap(leg) {
        Ok(mutex) => mutex
            .into_inner()
            .map_err(|_| "the leg's SRTP contexts are poisoned".to_string()),
        Err(shared) => {
            let Some((local, remote)) = sdes else {
                return Err("the leg's DTLS key is still held by another owner".to_string());
            };
            let rollover = shared
                .lock()
                .map_err(|_| "the leg's SRTP contexts are poisoned".to_string())?
                .rollover_snapshot();
            let mut rebuilt = SecureLeg::new(&local.key, &remote.key);
            rebuilt.seed_rollover(&rollover);
            Ok(rebuilt)
        }
    }
}
