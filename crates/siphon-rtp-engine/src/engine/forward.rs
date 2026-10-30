//! Forwarding-room verbs: `forward_join`, `forward_leave`, `forward_set_source`.
//!
//! A forwarding room is the push-to-talk counterpart of the mixing conference (3GPP TS 24.379): one
//! chosen seat's RTP is forwarded to every other seat through a per-receiver RTP translator, with no
//! mixing. A seat is opened the way a conference seat is ([`Engine::open_seat_transport`]); what is
//! different is the codec rule (the first seat fixes the room codec, later seats must offer it) and
//! that a seat is never freed for silence.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, Command, ProfileFlags};

use crate::dtls_bridge::PipelineTarget;
use crate::forward::{ForwardSeatConfig, RoomCodec};
use crate::sdp::{self, TextRewrite};

use super::answer_local::answer_codec_candidates;
use super::negotiate::{parse_codec_flags, random_ssrc};
use super::{error_result, ok_empty, ok_sdp, ClientId, Engine};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Dispatch a forwarding-room command.
    pub(super) async fn dispatch_forward(&self, client: ClientId, command: Command) -> CmdResult {
        match command {
            Command::ForwardJoin {
                conference_id,
                from_tag,
                sdp,
                profile,
            } => {
                self.forward_join(client, &conference_id, from_tag, &sdp, &profile)
                    .await
            }
            Command::ForwardLeave {
                conference_id,
                from_tag,
            } => self.forward_leave(&conference_id, &from_tag).await,
            Command::ForwardSetSource {
                conference_id,
                from_tag,
            } => {
                self.forward_set_source(client, &conference_id, from_tag)
                    .await
            }
            other => CmdResult::Error {
                reason: format!(
                    "unsupported command: {}",
                    super::dispatch::command_name(&other)
                ),
            },
        }
    }

    /// Seat a member in a forwarding room, creating the room on the first join
    /// ([`Command::ForwardJoin`]). The first seat fixes the room's codec from its offer in RFC 3264
    /// order; a later seat must offer that codec in the same payload format and is answered with its
    /// own payload type for it. Nothing is allocated for a seat the room would refuse.
    pub(super) async fn forward_join(
        &self,
        client: ClientId,
        room_id: &str,
        from_tag: String,
        offer: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        if let Err(reason) = super::validate_sip_call_id(profile) {
            return error_result("forward_join", &reason);
        }
        let info = match sdp::parse(offer) {
            Ok(info) => info,
            Err(error) => return error_result("forward_join: SDP parse", &error),
        };
        if self.conference.contains(room_id) {
            return error_result(
                "forward_join",
                &format!("{room_id} is a mixing conference; use conference_join"),
            );
        }
        // The codec, chosen before anything is allocated. A codec needs neither an encoder nor a
        // decoder here: the room forwards the payload as it came (RFC 3550 §7.1).
        let offered = answer_codec_candidates(&info, &parse_codec_flags(&profile.flags));
        let forward = self.conference.forward();
        let (proposed, spec) = match forward.room_codec(room_id) {
            Some(room) => match room.admit(&offered) {
                Ok(spec) => (room, spec),
                Err(reason) => return error_result("forward_join", &reason),
            },
            None => match RoomCodec::from_offer(&offered) {
                Ok((room, spec)) => (room, spec),
                Err(reason) => return error_result("forward_join", &reason),
            },
        };
        let telephone_event =
            sdp::TelephoneEvent::accompanying(&info.telephone_events(), Some(&spec));
        let mut transport = match self
            .open_seat_transport("forward_join", room_id, &info, profile)
            .await
        {
            Ok(transport) => transport,
            Err(refusal) => return *refusal,
        };
        let endpoint = transport.endpoint;
        let config = ForwardSeatConfig {
            tag: from_tag.clone(),
            endpoint: endpoint.id,
            egress_destination: transport.seat_remote,
            accepted_source: transport.accepted_source,
            latch: true,
            audio_payload_type: spec.payload_type,
            telephone_event,
            secure: transport.secure.take(),
            secure_pending: transport.dtls_pending(),
            ice_pending: transport.ice_pending,
            egress_ssrc: random_ssrc(),
            // RFC 3550 §5.1: the initial sequence number and timestamp are random.
            initial_sequence: random_ssrc() as u16,
            initial_timestamp: random_ssrc(),
        };
        let joined_tick = self.datapath.now_ticks();
        if let Err(refusal) = forward
            .join(
                room_id,
                proposed,
                &spec,
                config,
                joined_tick,
                self.event_sink(client),
                self.datapath.clone(),
            )
            .await
        {
            self.free(&[endpoint]).await;
            return error_result("forward_join", &refusal);
        }
        // Seated: aim the room's egress at whatever ICE validates for this seat.
        self.follow_seat_ice(endpoint.id);
        self.endpoint_calls.insert(endpoint.id, room_id.to_string());

        let target = PipelineTarget::Forward {
            forward: forward.clone(),
            room_id: room_id.to_string(),
            tag: from_tag.clone(),
        };
        if let Err(error) = self.start_seat_dtls(&transport, &info, target) {
            self.release_forward_seat(room_id, &from_tag).await;
            return error_result("forward_join: install DTLS redirect", &error);
        }
        // Answer in the one codec the seat was built for (RFC 3264 §6.1). Every other stream the
        // offer carries (video, the MCPTT floor stream) is declined with port 0.
        match self.answer_seat_sdp(offer, &mut transport, profile, TextRewrite::None) {
            Ok(rewritten) => ok_sdp(
                sdp::force_answer_codec(
                    &sdp::decline_unanswered_media(rewritten, false),
                    &spec,
                    telephone_event,
                ),
                Some(from_tag),
            ),
            Err(error) => {
                self.release_forward_seat(room_id, &from_tag).await;
                error_result("forward_join: SDP rewrite", &error)
            }
        }
    }

    /// Unseat a member ([`Command::ForwardLeave`]), freeing its endpoint, flows, and DTLS and ICE
    /// state. The last leave ends the room.
    pub(super) async fn forward_leave(&self, room_id: &str, from_tag: &str) -> CmdResult {
        if self.release_forward_seat(room_id, from_tag).await {
            ok_empty()
        } else {
            error_result("forward_leave", &"no such forwarding room seat")
        }
    }

    /// Take a seat out of its room and free everything it held. Returns whether it was seated.
    pub(super) async fn release_forward_seat(&self, room_id: &str, from_tag: &str) -> bool {
        let endpoints = self.conference.forward().leave(room_id, from_tag);
        if endpoints.is_empty() {
            return false;
        }
        self.stop_seat_ice_follow(&endpoints);
        self.retire_dtls_endpoints(&endpoints);
        for endpoint in endpoints {
            self.endpoint_calls.remove(&endpoint);
            self.awaiting_media.remove(&endpoint);
            self.datapath.remove_endpoint(endpoint).await;
        }
        true
    }

    /// Choose whose audio the room forwards ([`Command::ForwardSetSource`]): the seat `from_tag`, or
    /// nobody. The asking client receives the room's `forward_source_started` events.
    pub(super) async fn forward_set_source(
        &self,
        client: ClientId,
        room_id: &str,
        from_tag: Option<String>,
    ) -> CmdResult {
        match self
            .conference
            .forward()
            .set_source(room_id, from_tag, self.event_sink(client))
            .await
        {
            Ok(()) => ok_empty(),
            Err(refusal) => error_result("forward_set_source", &refusal),
        }
    }
}
