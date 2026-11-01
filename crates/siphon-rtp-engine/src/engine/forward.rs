//! Forwarding-room verbs: `forward_join`, `forward_leave`, `forward_set_source` (the dial-out pair,
//! `forward_offer` and `forward_answer`, is in [`super::forward_dial_out`]).
//!
//! A forwarding room is the push-to-talk counterpart of the mixing conference (3GPP TS 24.379): one
//! chosen seat's RTP is forwarded to every other seat through a per-receiver RTP translator, with no
//! mixing. A seat is opened the way a conference seat is ([`Engine::open_seat_transport`]); what is
//! different is the codec rule (the first seat fixes the room codec; a later seat either offers it,
//! and is forwarded to untouched, or offers a codec the engine can transcode to and from the room's,
//! and is transcoded for) and that a seat is never freed for silence.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{Datapath, Endpoint, FlowAction, SourceFilter};
use siphon_rtp_proto::{CmdResult, Command, ForwardMedia, ProfileFlags};

use crate::dtls_bridge::PipelineTarget;
use crate::floor_channel::{floor_channel, FloorScope, FloorSink};
use crate::forward::{FloorConfig, ForwardRefusal, ForwardSeatConfig, RoomCodec};
use crate::sdp::{self, EngineMedia, TextRewrite};

use super::answer_local::answer_codec_candidates;
use super::negotiate::{parse_codec_flags, peer_media_address, random_ssrc};
use super::seat_transport::SeatTransport;
use super::{boxed_error_result, error_result, ok_empty, ok_sdp, ClientId, Engine};

/// `floor_keys` are checked (3GPP TS 33.180 §9.4) before anything is allocated.
///
/// `key_mgmt` is refused in a translate room: it sets up end-to-end SRTP between the UEs, which the
/// translator breaks by rewriting the SSRC and sequence number (RFC 3711 §3.3 authenticates both;
/// 3GPP TS 33.180 §7.5.2 NOTE 3). The call would connect and the audio be silently undecryptable.
fn refuse_forward_security(profile: &ProfileFlags, media: ForwardMedia) -> Result<(), String> {
    crate::media_pipeline::refuse_floor_security(profile)?;
    if profile.key_mgmt.is_some() && media == ForwardMedia::Translate {
        return Err("key_mgmt sets up end-to-end SRTP, which a translate room rewrites; use \"media\": \"preserve\"".to_string());
    }
    Ok(())
}

/// Whether a seat can join a room carrying `media`, judged from its offer alone,
/// before anything is allocated.
///
/// * A preserve room forwards SRTP keyed between the UEs (3GPP TS 33.180 §7.5.2 NOTE 3), so a seat
///   whose media the engine would terminate (a=crypto, DTLS-SRTP) cannot be in it.
fn refuse_seat_keying(info: &sdp::MediaInfo, media: ForwardMedia) -> Result<(), String> {
    let preserve = media == ForwardMedia::Preserve;
    if preserve && (info.dtls || info.fingerprint.is_some() || !info.crypto.is_empty()) {
        return Err(super::seat_transport::preserve_keying_refusal(info));
    }
    Ok(())
}

/// How a seat joins its room: the room's codec as it stands (or as this seat fixes it), the codec
/// the seat is answered in, and whether the room transcodes for the seat.
pub(super) struct ForwardAdmission {
    pub(super) room: RoomCodec,
    pub(super) spec: CodecSpec,
    pub(super) transcoded: bool,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Dispatch a forwarding-room command.
    pub(super) async fn dispatch_forward(&self, client: ClientId, command: Command) -> CmdResult {
        match command {
            Command::ForwardJoin {
                conference_id,
                from_tag,
                sdp,
                profile,
                media,
            } => {
                if let Err(reason) = refuse_forward_security(&profile, media) {
                    return error_result("forward_join", &reason);
                }
                self.forward_join(client, &conference_id, from_tag, &sdp, &profile, media)
                    .await
            }
            Command::ForwardOffer {
                conference_id,
                from_tag,
                profile,
                media,
            } => {
                if let Err(reason) = refuse_forward_security(&profile, media) {
                    return error_result("forward_offer", &reason);
                }
                self.forward_offer(&conference_id, from_tag, profile, media)
                    .await
            }
            Command::ForwardAnswer {
                conference_id,
                from_tag,
                sdp,
                received_from,
            } => {
                self.forward_answer(client, &conference_id, &from_tag, &sdp, received_from)
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
    /// order; a later seat that offers that codec in the same payload format is answered with its own
    /// payload type for it, and one that does not is transcoded for if the engine can decode and
    /// encode both codecs ([`Self::forward_admission`]). Nothing is allocated for a seat the room
    /// would refuse.
    pub(super) async fn forward_join(
        &self,
        client: ClientId,
        room_id: &str,
        from_tag: String,
        offer: &str,
        profile: &ProfileFlags,
        media: ForwardMedia,
    ) -> CmdResult {
        if let Err(reason) = super::validate_sip_call_id(profile) {
            return error_result("forward_join", &reason);
        }
        // The controller's floor parameters go into the answer verbatim, so a line break would let
        // them write SDP lines of their own. Refused before anything is allocated.
        if let Some(fmtp) = &profile.floor_fmtp {
            if let Err(error) = sdp::validate_floor_fmtp(fmtp) {
                return error_result("forward_join", &error);
            }
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
        if let Err(reason) = refuse_seat_keying(&info, media) {
            return error_result("forward_join", &reason);
        }
        // The codec, chosen before anything is allocated. A codec needs neither an encoder nor a
        // decoder here: the room forwards the payload as it came (RFC 3550 §7.1).
        let offered = answer_codec_candidates(&info, &parse_codec_flags(&profile.flags));
        let forward = self.conference.forward();
        let admission = match self.forward_admission(room_id, &offered, media) {
            Ok(admission) => admission,
            Err(reason) => return error_result("forward_join", &reason),
        };
        let spec = admission.spec.clone();
        let telephone_event =
            sdp::TelephoneEvent::accompanying(&info.telephone_events(), Some(&spec));
        let mut transport = match self
            .open_seat_transport("forward_join", room_id, &info, profile, media)
            .await
        {
            Ok(transport) => transport,
            Err(refusal) => return *refusal,
        };
        let endpoint = transport.endpoint;
        // The MCPTT floor-control stream (TS 24.380), when the seat offered one: its own endpoint.
        let floor = match self.open_floor_endpoint(&transport, offer, profile).await {
            Ok(floor) => floor,
            Err(refusal) => {
                self.free(&[endpoint]).await;
                return *refusal;
            }
        };
        let floor_endpoint = floor.as_ref().map(|(endpoint, _)| *endpoint);
        let egress_ssrc = random_ssrc();
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
            egress_ssrc,
            // RFC 3550 §5.1: the initial sequence number and timestamp are random.
            initial_sequence: random_ssrc() as u16,
            initial_timestamp: random_ssrc(),
            floor: floor.map(|(_, config)| config),
            app_events: self.app_event_queue(client),
        };
        if let Err(refusal) = self
            .seat_forward_member(client, room_id, admission, config, endpoint, floor_endpoint)
            .await
        {
            return error_result("forward_join", &refusal);
        }
        // A DTLS seat that offered a WebRTC data channel carries its floor control on it (a browser
        // cannot send RTCP APP). The DTLS driver runs the SCTP association; the room sends through
        // the handle.
        let data_channel = transport
            .dtls_pending()
            .then(|| sdp::parse_data_channel(offer))
            .flatten();
        if data_channel.is_some() {
            let (handle, plan) = floor_channel(FloorSink {
                scope: FloorScope::Room(room_id.to_string()),
                tag: from_tag.clone(),
                events: self.app_event_queue(client),
            });
            self.dtls_bridge().attach_floor_channel(endpoint.id, plan);
            if !forward.attach_floor_channel(room_id, &from_tag, handle) {
                tracing::warn!(room_id, tag = %from_tag, "floor data channel for a seat that already left");
            }
        }

        let target = PipelineTarget::Forward {
            forward: forward.clone(),
            room_id: room_id.to_string(),
            tag: from_tag.clone(),
        };
        if let Err(error) = self.start_seat_dtls(
            &transport,
            super::seat_transport::answerer_dtls_role(info.setup),
            target,
        ) {
            self.release_forward_seat(room_id, &from_tag).await;
            return error_result("forward_join: install DTLS redirect", &error);
        }
        // Answer in the one codec the seat was built for (RFC 3264 §6.1), and the floor stream on
        // its own endpoint when it has one (TS 24.380 §14.3.1). Every other stream the offer carries
        // (video, a second floor section) is declined with port 0.
        match self.answer_seat_sdp(
            offer,
            &mut transport,
            profile,
            TextRewrite::None,
            Some(&sdp::OwnSsrc::with_random_cname(egress_ssrc)),
        ) {
            Ok(rewritten) => {
                let anchored = match floor_endpoint {
                    Some(floor) => sdp::anchor_floor(
                        &rewritten,
                        EngineMedia {
                            rtp: floor.local_addr,
                            rtcp: None,
                            advertised_ip: transport.advertised,
                        },
                        profile.floor_fmtp.as_deref(),
                    ),
                    None => rewritten,
                };
                // RFC 8841: the data channel section is answered on the audio's transport (BUNDLE).
                let anchored = if data_channel.is_some() {
                    sdp::anchor_data_channel(&anchored)
                } else {
                    anchored
                };
                ok_sdp(
                    sdp::force_answer_codec(
                        &sdp::decline_unanswered_with_data_channel(
                            anchored,
                            false,
                            floor_endpoint.is_some(),
                            data_channel.is_some(),
                        ),
                        &spec,
                        telephone_event,
                    ),
                    Some(from_tag),
                )
            }
            Err(error) => {
                self.release_forward_seat(room_id, &from_tag).await;
                error_result("forward_join: SDP rewrite", &error)
            }
        }
    }

    /// Allocate the endpoint for the floor-control stream the offer carries, if it carries one the
    /// seat can take: its own redirected socket, gated by the signalled floor address (or the
    /// `received_from` hint), with the learn-once latch the room runs on it
    /// (docs/security-and-nat.md §4 layer 5h). A floor stream in another address family than the
    /// seat's audio is left to be declined rather than bound on a second interface.
    async fn open_floor_endpoint(
        &self,
        transport: &SeatTransport,
        offer: &str,
        profile: &ProfileFlags,
    ) -> Result<Option<(Endpoint, FloorConfig)>, Box<CmdResult>> {
        let Some(offered) = sdp::parse_floor(offer) else {
            return Ok(None);
        };
        if siphon_rtp_datapath::AddressFamily::of(offered.remote.ip()) != transport.family {
            tracing::debug!(
                "the floor stream is in another address family than the seat; declined"
            );
            return Ok(None);
        }
        let endpoint = match self
            .alloc_endpoints(1, transport.family, transport.bind)
            .await
        {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return Err(boxed_error_result("forward_join: floor stream", &reason)),
        };
        if let Err(error) = self
            .datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
        {
            self.free(&[endpoint]).await;
            return Err(boxed_error_result(
                "forward_join: install floor redirect",
                &error,
            ));
        }
        let destination = peer_media_address(offered.remote, profile.received_from);
        let keys = match crate::floor_srtcp::master_keys(&profile.floor_keys) {
            Ok(keys) => keys,
            Err(reason) => {
                self.free(&[endpoint]).await;
                return Err(boxed_error_result("forward_join: floor_keys", &reason));
            }
        };
        // An ICE seat holds the gate open until its pair is selected, then the room narrows it; a
        // `symmetric` seat stays open and the learn-once latch is the only constraint.
        let accepted_source =
            if transport.ice_pending || profile.flags.iter().any(|flag| flag == "symmetric") {
                SourceFilter::Any
            } else {
                SourceFilter::Exact(destination.ip())
            };
        Ok(Some((
            endpoint,
            FloorConfig {
                endpoint: endpoint.id,
                destination,
                accepted_source,
                ice_gated: transport.ice_pending,
                keys,
            },
        )))
    }

    /// Unseat a member ([`Command::ForwardLeave`]), freeing its endpoint, flows, and DTLS and ICE
    /// state. The last leave ends the room. A seat offered by `forward_offer` and not yet answered is
    /// not in the room; leaving drops the offer and frees its endpoints.
    pub(super) async fn forward_leave(&self, room_id: &str, from_tag: &str) -> CmdResult {
        if self.release_forward_seat(room_id, from_tag).await
            || self.drop_pending_forward_seat(room_id, from_tag).await
        {
            ok_empty()
        } else {
            error_result("forward_leave", &"no such forwarding room seat")
        }
    }

    /// Decide how a seat offering `offered` joins `room_id`, before anything is allocated: the first
    /// seat fixes the room's codec; a later seat offering the room's codec in its payload format is
    /// forwarded to untouched; any other is transcoded for when the engine has a decoder and an
    /// encoder for both codecs and the seat's packetization interval is the room's. The refusal
    /// names why the room's codec was not offered and why the engine cannot transcode either.
    pub(super) fn forward_admission(
        &self,
        room_id: &str,
        offered: &[CodecSpec],
        media: ForwardMedia,
    ) -> Result<ForwardAdmission, String> {
        let Some(room) = self.conference.forward().room_codec(room_id) else {
            return RoomCodec::from_offer(offered).map(|(room, spec)| ForwardAdmission {
                room: room.with_media(media),
                spec,
                transcoded: false,
            });
        };
        // The first seat fixed the room's media mode.
        if room.media() != media {
            return Err(crate::forward::media_mismatch(room.media(), media));
        }
        match room.admit(offered) {
            Ok(spec) => Ok(ForwardAdmission {
                room,
                spec,
                transcoded: false,
            }),
            // A preserve room forwards the talker's packets unchanged: another codec or payload
            // type is refused, never transcoded (RFC 3550 §7.1).
            Err(forwarded) if media == ForwardMedia::Preserve => Err(format!(
                "preserve rooms forward the talker's packets unchanged: {forwarded}"
            )),
            Err(forwarded) => match room.admit_cross(offered) {
                Ok(spec) => Ok(ForwardAdmission {
                    room,
                    spec,
                    transcoded: true,
                }),
                Err(transcoded) => Err(format!(
                    "{forwarded}; and it cannot be transcoded to: {transcoded}"
                )),
            },
        }
    }

    /// Put an admitted seat in its room and make it reachable: the room (waiting for its verdict),
    /// then the ICE follower and the endpoint-to-room bookkeeping. A refusal frees the seat's audio
    /// and floor endpoints, so a caller that gets `Err` has nothing left to release.
    pub(super) async fn seat_forward_member(
        &self,
        client: ClientId,
        room_id: &str,
        admission: ForwardAdmission,
        config: ForwardSeatConfig,
        endpoint: Endpoint,
        floor_endpoint: Option<Endpoint>,
    ) -> Result<(), ForwardRefusal> {
        let forward = self.conference.forward();
        let joined_tick = self.datapath.now_ticks();
        let events = self.event_sink(client);
        let datapath = self.datapath.clone();
        let outcome = if admission.transcoded {
            forward
                .join_transcoded(
                    room_id,
                    admission.room,
                    &admission.spec,
                    config,
                    joined_tick,
                    events,
                    datapath,
                )
                .await
        } else {
            forward
                .join(
                    room_id,
                    admission.room,
                    &admission.spec,
                    config,
                    joined_tick,
                    events,
                    datapath,
                )
                .await
        };
        if let Err(refusal) = outcome {
            self.free(&[endpoint]).await;
            if let Some(floor) = floor_endpoint {
                self.free(&[floor]).await;
            }
            return Err(refusal);
        }
        // Seated: aim the room's egress at whatever ICE validates for this seat.
        self.follow_seat_ice(endpoint.id);
        self.endpoint_calls.insert(endpoint.id, room_id.to_string());
        if let Some(floor) = floor_endpoint {
            self.endpoint_calls.insert(floor.id, room_id.to_string());
        }
        Ok(())
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
