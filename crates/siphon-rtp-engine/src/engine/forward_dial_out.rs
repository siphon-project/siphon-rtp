//! Forwarding-room dial-out: the room offers a seat and seats the member on its answer.
//!
//! `forward_join` answers a member who called the room. A group call also fans out the other way:
//! the controller INVITEs each member, so the engine is the offerer (RFC 3264 §5) and
//! `forward_offer` allocates the seat's endpoints and writes the offer, `forward_answer` takes the
//! member's answer and seats it through the same code `forward_join` ends in. It mirrors
//! `conference_offer` / `conference_answer` ([`super::dial_out`]) for a mixing room.
//!
//! Between the two the seat is **pending**: it holds its endpoints but is not in the room, so
//! nothing is forwarded to or from it. A pending seat ends in exactly one of four ways, each of
//! which frees its endpoints: it is answered (and seated, or refused), it leaves (`forward_leave`),
//! or it expires on the sweep after the setup timeout, the same ceiling an offered call gets.
//!
//! # The offer
//! When the room exists the offer lists the room's codec first, with its format parameters (AMR
//! `octet-align` and `mode-set`, G.729 `annexb`), so a member who answers it is forwarded to untouched;
//! then every codec the engine can transcode to and from the room's, so a member that cannot take
//! the room's codec still can be called. When the room does not exist yet the first seat fixes the
//! codec, and the offer lists every codec a room could carry, widest band first, as
//! `conference_offer` does, except that forwarding needs neither a decoder nor an encoder, so a codec
//! this build cannot transcode (AMR without the `amr` feature) is listed too. With
//! `profile.floor_fmtp` set the offer carries an anchored `m=application <port> udp MCPTT` section
//! (3GPP TS 24.380 §14) with `a=fmtp:MCPTT` verbatim.
//!
//! A profile with `transport_protocol: "UDP/TLS/RTP/SAVPF"` offers a browser a WebRTC seat instead
//! ([`super::forward_webrtc`]).

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction, SourceFilter};
use siphon_rtp_proto::{CmdResult, ForwardMedia, ProfileFlags};

use crate::forward::{FloorConfig, ForwardSeatConfig, RoomCodec};
use crate::sdp::{self, TelephoneEvent};

use super::answer_local::order_codec_candidates;
use super::dial_out::{answered_codec, candidate_codecs, offerable_codecs, offered_events};
use super::forward::ForwardAdmission;
use super::forward_webrtc::{self, AnsweredWebrtc, OfferedWebrtc};
use super::negotiate::{parse_codec_flags, peer_media_address, random_ssrc};
use super::offer::far_address_family;
use super::{error_result, ok_empty, ok_sdp, ClientId, Engine};

/// A forwarding-room seat the engine has offered and the member has not yet answered.
pub(super) struct PendingForwardSeat {
    /// The seat's audio endpoint, RTP and RTCP multiplexed (RFC 5761).
    endpoint: Endpoint,
    /// The seat's MCPTT floor-control endpoint, when the offer carried a floor section.
    floor: Option<Endpoint>,
    /// The audio codecs the offer listed, in its order.
    offered: Vec<CodecSpec>,
    /// The telephone-event payload types the offer listed, one per clock rate.
    events: Vec<TelephoneEvent>,
    /// The offer's profile: its `symmetric` flag and dialog `Call-ID` carry over to the seat.
    profile: ProfileFlags,
    /// The logical tick the offer was made at, the baseline its expiry is measured from.
    offered_tick: u64,
    /// How the room the seat is offered for carries media.
    media: ForwardMedia,
    /// The offer's audio transport is `RTP/SAVP` (a preserve room signalling end-to-end SRTP), so
    /// the answer must keep it (RFC 3264 §6).
    offered_secure: bool,
    /// The offer was a WebRTC one ([`super::forward_webrtc`]): DTLS-SRTP, ICE and, with floor, a data
    /// channel. What it fixed is kept for the answer.
    webrtc: Option<OfferedWebrtc>,
}

/// What an answer negotiated for its seat.
struct Negotiated {
    admission: ForwardAdmission,
    telephone_event: Option<TelephoneEvent>,
    remote_rtp: std::net::SocketAddr,
    accepted_source: SourceFilter,
    /// The floor stream, when the answer accepted it.
    floor: Option<FloorConfig>,
    /// What a WebRTC offer's answer settled: the DTLS role, the peer's fingerprint and the channel.
    webrtc: Option<AnsweredWebrtc>,
}

type PendingKey = (String, String);

fn pending_key(room_id: &str, from_tag: &str) -> PendingKey {
    (room_id.to_string(), from_tag.to_string())
}

/// The payload type for a room codec that has no conventional number of its own (RFC 3551 §6: the
/// dynamic range starts at 96). None of the engine's candidates or events use it.
const FALLBACK_DYNAMIC_PAYLOAD_TYPE: u8 = 104;

/// The room's codec as an offer presents it: the engine's conventional payload type for the format
/// (so the number is the one a `conference_offer` would use), else the format's static number, else
/// a free dynamic one. Everything else (the AMR parameters, the `mode-set`) is the room's.
fn room_codec_for_offer(room: &RoomCodec) -> CodecSpec {
    let mut spec = room.spec().clone();
    if room.media() == ForwardMedia::Preserve {
        // The packets are forwarded unchanged, so the member must read the number the talker sends.
        return spec;
    }
    let octet_aligned = |codec: &CodecSpec| codec.amr.is_some_and(|amr| amr.octet_aligned());
    let conventional = candidate_codecs().into_iter().find(|candidate| {
        candidate.encoding_name == spec.encoding_name
            && candidate.clock_rate_hz == spec.clock_rate_hz
            && (!spec.is_amr() || octet_aligned(candidate) == octet_aligned(&spec))
    });
    spec.payload_type = match conventional {
        Some(candidate) => candidate.payload_type,
        None if spec.payload_type < 96 => spec.payload_type,
        None => FALLBACK_DYNAMIC_PAYLOAD_TYPE,
    };
    spec
}

/// The codecs a `forward_offer` lists for a room that exists: its own first, then those a seat can be
/// transcoded in, in the profile's order.
fn codecs_for_existing_room(room: &RoomCodec, profile: &ProfileFlags) -> Vec<CodecSpec> {
    let mut codecs = vec![room_codec_for_offer(room)];
    let taken: Vec<u8> = codecs.iter().map(|codec| codec.payload_type).collect();
    let extras = offerable_codecs(profile).into_iter().filter(|candidate| {
        !taken.contains(&candidate.payload_type)
            && room.admit(std::slice::from_ref(candidate)).is_err()
            && room.admit_cross(std::slice::from_ref(candidate)).is_ok()
    });
    codecs.extend(extras);
    codecs
}

/// The codecs for a room that does not exist yet: every candidate a room could forward, edited by
/// the profile's codec flags the way `conference_offer`'s are.
fn codecs_for_new_room(profile: &ProfileFlags) -> Vec<CodecSpec> {
    order_codec_candidates(candidate_codecs(), &parse_codec_flags(&profile.flags))
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Offer a new seat in the forwarding room `room_id` ([`siphon_rtp_proto::Command::ForwardOffer`]).
    pub(super) async fn forward_offer(
        &self,
        room_id: &str,
        from_tag: String,
        profile: ProfileFlags,
        media: ForwardMedia,
    ) -> CmdResult {
        if let Err(reason) = super::validate_sip_call_id(&profile) {
            return error_result("forward_offer", &reason);
        }
        // The same posture as `conference_offer` (plain RTP/AVP, no ICE) unless the profile asks
        // for a WebRTC offer, which only a translate room can carry.
        let want_webrtc = match forward_webrtc::requested(&profile, media) {
            Ok(webrtc) => webrtc,
            Err(reason) => return error_result("forward_offer", &reason),
        };
        if let Some(fmtp) = &profile.floor_fmtp {
            if let Err(error) = sdp::validate_floor_fmtp(fmtp) {
                return error_result("forward_offer", &error);
            }
        }
        // A forwarding room (push-to-talk) and a mixing room share no seats: the id names one kind.
        if self.conference.contains(room_id) {
            return error_result(
                "forward_offer",
                &format!("{room_id} is a mixing conference; use conference_offer"),
            );
        }
        let forward = self.conference.forward();
        if self.has_pending_forward_seat(room_id, &from_tag) {
            return error_result(
                "forward_offer",
                &format!("from-tag {from_tag} already has an offer awaiting its answer"),
            );
        }
        if forward.seat_endpoint(room_id, &from_tag).is_some() {
            return error_result(
                "forward_offer",
                &format!("from-tag {from_tag} is already seated in this room"),
            );
        }
        let offered = match forward.room_codec(room_id) {
            // The first seat fixed the room's media mode.
            Some(room) if room.media() != media => {
                return error_result(
                    "forward_offer",
                    &crate::forward::media_mismatch(room.media(), media),
                );
            }
            Some(room) => codecs_for_existing_room(&room, &profile),
            None => codecs_for_new_room(&profile),
        };
        if offered.is_empty() {
            return error_result(
                "forward_offer",
                &"no codec is left to offer after the profile's codec flags",
            );
        }
        let events = offered_events(&offered);
        // The seat takes the near (`direction[0]`) interface, as a join does; with no peer address yet
        // it is IPv4 unless the profile's `address_family` asks for IPv6.
        let family = far_address_family(&profile).unwrap_or(AddressFamily::V4);
        let (interface, _) = self.interfaces.resolve_direction(&profile.direction);
        let (bind, advertised_override) = Self::leg_binding(interface, family);
        let endpoint = match self.alloc_endpoints(1, family, bind).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return error_result("forward_offer", &reason),
        };
        // A WebRTC seat carries its floor control on a data channel of the one transport, not on a
        // UDP stream of its own.
        let floor = if profile.floor_fmtp.is_some() && !want_webrtc {
            match self.alloc_endpoints(1, family, bind).await {
                Ok(mut endpoints) => Some(endpoints.remove(0)),
                Err(reason) => {
                    self.free(&[endpoint]).await;
                    return error_result("forward_offer: floor stream", &reason);
                }
            }
        } else {
            None
        };
        let advertised = advertised_override.unwrap_or_else(|| endpoint.local_addr.ip());
        let (mut offer, webrtc) = if want_webrtc {
            match self
                .write_webrtc_offer(
                    endpoint,
                    advertised,
                    &offered,
                    &events,
                    profile.floor_fmtp.is_some(),
                )
                .await
            {
                Ok((offer, webrtc)) => (offer, Some(webrtc)),
                Err(reason) => {
                    self.free(&[endpoint]).await;
                    return error_result("forward_offer", &reason);
                }
            }
        } else {
            let offer = sdp::conference_seat_offer(
                endpoint.local_addr,
                advertised,
                random_ssrc(),
                &offered,
                &events,
            );
            (offer, None)
        };
        // A preserve room signalling end-to-end SRTP (`key_mgmt`, RFC 4567) offers `RTP/SAVP` with no
        // `a=crypto`: the engine holds no key, the UEs agree theirs (3GPP TS 33.180 §7.5.2).
        let offered_secure = media == ForwardMedia::Preserve && profile.key_mgmt.is_some();
        if offered_secure {
            offer = offer.replacen("RTP/AVP", "RTP/SAVP", 1);
        }
        if let Some(floor) = floor {
            offer.push_str(&sdp::floor::floor_offer_section(
                floor.local_addr.port(),
                advertised,
                profile.floor_fmtp.as_deref(),
            ));
        }
        let key_mgmt = profile.key_mgmt.clone();
        let seat = PendingForwardSeat {
            endpoint,
            floor,
            offered,
            events,
            profile,
            offered_tick: self.datapath.now_ticks(),
            media,
            offered_secure,
            webrtc,
        };
        // Inserted only if no concurrent offer took the key while the endpoints were allocated.
        let inserted = match self
            .pending_forward_seats
            .entry(pending_key(room_id, &from_tag))
        {
            dashmap::mapref::entry::Entry::Occupied(_) => false,
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(seat);
                true
            }
        };
        if !inserted {
            self.free(&[endpoint]).await;
            if let Some(floor) = floor {
                self.free(&[floor]).await;
            }
            return error_result(
                "forward_offer",
                &format!("from-tag {from_tag} already has an offer awaiting its answer"),
            );
        }
        // The controller's `a=key-mgmt` (RFC 4567), written verbatim on the audio section.
        let offer = sdp::apply_key_mgmt(&offer, key_mgmt.as_deref());
        ok_sdp(offer, Some(from_tag))
    }

    /// Seat the member a [`siphon_rtp_proto::Command::ForwardOffer`] offered, on its answer
    /// ([`siphon_rtp_proto::Command::ForwardAnswer`]). The pending seat is consumed either way: a
    /// refused answer frees its endpoints.
    pub(super) async fn forward_answer(
        &self,
        client: ClientId,
        room_id: &str,
        from_tag: &str,
        answer: &str,
        received_from: Option<std::net::IpAddr>,
    ) -> CmdResult {
        let Some((_, pending)) = self
            .pending_forward_seats
            .remove(&pending_key(room_id, from_tag))
        else {
            return error_result(
                "forward_answer",
                &format!("no forward_offer for from-tag {from_tag} awaits an answer in this room"),
            );
        };
        let negotiated = match self.negotiate_answer(room_id, answer, received_from, &pending) {
            Ok(negotiated) => negotiated,
            Err(reason) => {
                self.free_pending_forward_seat(&pending).await;
                return error_result("forward_answer", &reason);
            }
        };
        let endpoint = pending.endpoint;
        // A floor stream the answer declined leaves an audio-only seat, and frees the endpoint held
        // for it.
        let floor_endpoint = match (pending.floor, negotiated.floor.is_some()) {
            (Some(floor), true) => Some(floor),
            (Some(floor), false) => {
                self.free(&[floor]).await;
                None
            }
            (None, _) => None,
        };
        for installed in std::iter::once(endpoint).chain(floor_endpoint) {
            if let Err(error) = self
                .datapath
                .install_flow(installed.id, FlowAction::Redirect)
            {
                self.free(&[endpoint]).await;
                if let Some(floor) = floor_endpoint {
                    self.free(&[floor]).await;
                }
                return error_result("forward_answer: install redirect", &error);
            }
        }
        // A WebRTC seat is taken `secure_pending` (and `ice_pending` under a full agent) like a
        // joined browser seat: nothing is forwarded to or from it until the handshake keys it and
        // ICE selects its pair. The ICE agent reads the member's credentials and candidates from the
        // answer, so it is armed now and not when the offer was written (RFC 8445 §6.1.1).
        let mut ice_pending = false;
        if let (Some(offered), Some(answered)) = (&pending.webrtc, &negotiated.webrtc) {
            let ice_config = offered.ice_config();
            ice_pending = self.arm_seat_ice(
                room_id,
                endpoint,
                &answered.info,
                answered.info.is_ice().then_some(&ice_config),
                &offered.candidates,
            );
        }
        let config = ForwardSeatConfig {
            tag: from_tag.to_string(),
            endpoint: endpoint.id,
            egress_destination: negotiated.remote_rtp,
            accepted_source: negotiated.accepted_source,
            latch: true,
            audio_payload_type: negotiated.admission.spec.payload_type,
            telephone_event: negotiated.telephone_event,
            secure: None,
            secure_pending: negotiated.webrtc.is_some(),
            ice_pending,
            egress_ssrc: random_ssrc(),
            // RFC 3550 §5.1: the initial sequence number and timestamp are random.
            initial_sequence: random_ssrc() as u16,
            initial_timestamp: random_ssrc(),
            floor: negotiated.floor,
            app_events: self.app_event_queue(client),
        };
        // From here a refusal frees the endpoints itself.
        if let Err(refusal) = self
            .seat_forward_member(
                client,
                room_id,
                negotiated.admission,
                config,
                endpoint,
                floor_endpoint,
            )
            .await
        {
            return error_result("forward_answer", &refusal);
        }
        if let (Some(offered), Some(answered)) = (pending.webrtc, negotiated.webrtc) {
            if let Err(reason) = self
                .start_webrtc_seat(
                    client,
                    room_id,
                    from_tag,
                    endpoint,
                    negotiated.remote_rtp,
                    negotiated.accepted_source,
                    ice_pending,
                    offered,
                    answered,
                )
                .await
            {
                return error_result("forward_answer", &reason);
            }
        }
        ok_empty()
    }

    /// Read the member's answer into the seat it negotiates, refusing an answer the offer does not
    /// admit. Allocates and frees nothing.
    fn negotiate_answer(
        &self,
        room_id: &str,
        answer: &str,
        received_from: Option<std::net::IpAddr>,
        pending: &PendingForwardSeat,
    ) -> Result<Negotiated, String> {
        let info = sdp::parse(answer).map_err(|error| format!("SDP parse: {error}"))?;
        // RFC 3264 §6: an answerer rejects a stream by answering it with port 0.
        if info.remote_rtp.port() == 0 {
            return Err("the answer rejected the audio stream (port 0)".to_string());
        }
        // RFC 3264 §6: the answer keeps the offer's transport: plain RTP/AVP, or for a preserve room
        // signalling end-to-end SRTP, RTP/SAVP with no key of the engine's to answer (a=crypto or
        // DTLS-SRTP would make the engine terminate media the room forwards unchanged), or for a
        // WebRTC offer, UDP/TLS/RTP/SAVPF with the member's fingerprint and DTLS role.
        let webrtc = match &pending.webrtc {
            Some(offered) => Some(offered.read_answer(info.clone(), answer)?),
            None => None,
        };
        if webrtc.is_some() {
            // ICE decides the address family of a WebRTC seat's transport, not the answer's `c=`
            // (a browser answers `0.0.0.0` and lets the candidates speak, RFC 8839 §4.2.1.2).
        } else if pending.offered_secure {
            if !info.secure || info.dtls || !info.crypto.is_empty() {
                return Err(
                    "the answer must be RTP/SAVP without a=crypto or DTLS-SRTP, as the offer was: \
                     a preserve room forwards end-to-end SRTP the engine does not terminate"
                        .to_string(),
                );
            }
        } else if info.secure || info.dtls {
            return Err("the answer is secure, but the offer was RTP/AVP".to_string());
        }
        let family = AddressFamily::of(pending.endpoint.local_addr.ip());
        if webrtc.is_none() && AddressFamily::of(info.remote_rtp.ip()) != family {
            return Err(format!(
                "the answer's address {} is not in the offered seat's address family",
                info.remote_rtp.ip()
            ));
        }
        // The id may have become a mixing room since the offer.
        if self.conference.contains(room_id) {
            return Err(format!(
                "{room_id} is a mixing conference; use conference_answer"
            ));
        }
        // The first audio format of the answer must be one the offer listed (RFC 3264 §6.1). Then
        // the room decides as it does for a join: its own codec is forwarded to untouched, another
        // is transcoded for, and the first seat fixes the codec.
        let answered = answered_codec(&info, &pending.offered)?;
        let admission =
            self.forward_admission(room_id, std::slice::from_ref(&answered), pending.media)?;
        // The answer's event payload type, when it is one the offer listed.
        let telephone_event =
            TelephoneEvent::accompanying(&info.telephone_events(), Some(&admission.spec))
                .filter(|event| pending.events.contains(event));
        // RTPBleed gate, as on a joined seat: the signalled source only, unless the leg is
        // explicitly symmetric (docs/security-and-nat.md §4). The answerer's `received-from` hint
        // moves the gate and the opening destination off a private `c=` onto its NAT's public
        // address, as on a two-party answer.
        let symmetric = pending.profile.flags.iter().any(|flag| flag == "symmetric");
        let gate = |address: std::net::SocketAddr| {
            if symmetric {
                SourceFilter::Any
            } else {
                SourceFilter::Exact(address.ip())
            }
        };
        // An ICE seat keeps the signalled address and runs the gate open: the connectivity checks,
        // not the SDP, say where media comes from (RFC 8445 §7.3.1.3; docs/security-and-nat.md §4).
        let ice = webrtc.is_some() && info.is_ice();
        let remote_rtp = if ice {
            info.remote_rtp
        } else {
            peer_media_address(info.remote_rtp, received_from)
        };
        // The seat's floor SRTCP keys are the offering profile's own (TS 33.180 §9.4).
        let floor_keys = crate::floor_srtcp::master_keys(&pending.profile.floor_keys)
            .map_err(|reason| format!("floor_keys: {reason}"))?;
        // The floor stream, when the answer accepts it (a port, not 0) in the seat's address family.
        let floor = pending
            .floor
            .zip(sdp::parse_floor(answer))
            .filter(|(_, offered)| AddressFamily::of(offered.remote.ip()) == family)
            .map(|(endpoint, offered)| {
                let destination = peer_media_address(offered.remote, received_from);
                FloorConfig {
                    endpoint: endpoint.id,
                    destination,
                    accepted_source: gate(destination),
                    ice_gated: false,
                    keys: floor_keys,
                }
            });
        Ok(Negotiated {
            admission,
            telephone_event,
            remote_rtp,
            accepted_source: if ice {
                SourceFilter::Any
            } else {
                gate(remote_rtp)
            },
            floor,
            webrtc,
        })
    }

    /// Whether `from_tag` has an offered seat in `room_id` awaiting its answer.
    pub(super) fn has_pending_forward_seat(&self, room_id: &str, from_tag: &str) -> bool {
        self.pending_forward_seats
            .contains_key(&pending_key(room_id, from_tag))
    }

    /// Drop an offered forwarding-room seat that was never answered, freeing its endpoints. `false`
    /// when there is none.
    pub(super) async fn drop_pending_forward_seat(&self, room_id: &str, from_tag: &str) -> bool {
        match self
            .pending_forward_seats
            .remove(&pending_key(room_id, from_tag))
        {
            Some((_, pending)) => {
                self.free_pending_forward_seat(&pending).await;
                true
            }
            None => false,
        }
    }

    async fn free_pending_forward_seat(&self, pending: &PendingForwardSeat) {
        self.free(&[pending.endpoint]).await;
        if let Some(floor) = pending.floor {
            self.free(&[floor]).await;
        }
    }

    /// Expire offered forwarding-room seats whose answer has not come within `budget` ticks (see
    /// [`Self::reap_pending_seats`], which owns the budget). Returns how many expired.
    pub(super) async fn reap_pending_forward_seats(&self, now: u64, budget: u64) -> usize {
        let expired: Vec<PendingKey> = self
            .pending_forward_seats
            .iter()
            .filter(|seat| now.saturating_sub(seat.offered_tick) >= budget)
            .map(|seat| seat.key().clone())
            .collect();
        let mut reaped = 0;
        for key in expired {
            // Re-checked on removal: an answer may have consumed the seat since the scan.
            if let Some((_, pending)) = self.pending_forward_seats.remove_if(&key, |_, seat| {
                now.saturating_sub(seat.offered_tick) >= budget
            }) {
                self.free_pending_forward_seat(&pending).await;
                reaped += 1;
            }
        }
        reaped
    }

    /// Offered forwarding-room seats awaiting their answer.
    pub(super) fn pending_forward_seat_count(&self) -> usize {
        self.pending_forward_seats.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn room_of(text: &str) -> RoomCodec {
        let info = sdp::parse(text).unwrap();
        RoomCodec::from_offer(&info.audio_codecs()).unwrap().0
    }

    fn amr_wb_room(fmtp: &str) -> RoomCodec {
        room_of(&format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP 111\r\na=rtpmap:111 AMR-WB/16000\r\na=fmtp:111 {fmtp}\r\n"
        ))
    }

    fn pcmu_room() -> RoomCodec {
        room_of(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP 0\r\n",
        )
    }

    #[test]
    fn the_room_codec_is_offered_under_the_conventional_number_with_its_own_parameters() {
        // The first seat called it payload type 111; the offer uses the engine's number for
        // octet-aligned AMR-WB, and keeps the room's mode-set.
        let offered = room_codec_for_offer(&amr_wb_room("octet-align=1;mode-set=0,1,2"));
        assert_eq!(offered.encoding_name, "AMR-WB");
        assert_eq!(offered.payload_type, 97);
        assert_eq!(offered.allowed_modes, vec![0, 1, 2]);
        let bandwidth_efficient = room_codec_for_offer(&amr_wb_room("octet-align=0"));
        assert_eq!(bandwidth_efficient.payload_type, 96);
        assert_eq!(room_codec_for_offer(&pcmu_room()).payload_type, 0);
    }

    #[test]
    fn a_codec_with_no_conventional_number_keeps_a_static_one_or_gets_a_free_dynamic_one() {
        let g722_as_dynamic = room_of(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP 9\r\n",
        );
        assert_eq!(room_codec_for_offer(&g722_as_dynamic).payload_type, 9);
        let g726 = room_of(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP 100\r\na=rtpmap:100 G726-24/8000\r\n",
        );
        let number = room_codec_for_offer(&g726).payload_type;
        assert_eq!(number, FALLBACK_DYNAMIC_PAYLOAD_TYPE);
        assert!(
            !candidate_codecs()
                .iter()
                .any(|candidate| candidate.payload_type == number),
            "the fallback number collides with no candidate"
        );
    }

    #[test]
    fn an_existing_room_offers_its_codec_first_then_only_codecs_it_can_transcode() {
        let codecs = codecs_for_existing_room(&pcmu_room(), &ProfileFlags::default());
        let names: Vec<&str> = codecs
            .iter()
            .map(|codec| codec.encoding_name.as_str())
            .collect();
        assert_eq!(names[0], "PCMU", "{names:?}");
        assert_eq!(
            names.iter().filter(|name| **name == "PCMU").count(),
            1,
            "the room codec is not listed twice: {names:?}"
        );
        assert!(
            names.contains(&"PCMA") && names.contains(&"OPUS"),
            "{names:?}"
        );
        let mut numbers: Vec<u8> = codecs.iter().map(|codec| codec.payload_type).collect();
        let listed = numbers.len();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), listed, "distinct payload types: {codecs:?}");
    }

    #[test]
    fn a_room_in_a_codec_this_build_cannot_transcode_offers_only_that_codec() {
        // Without the `amr` feature the room forwards AMR-WB but can decode nothing else into it.
        if cfg!(feature = "amr") {
            return;
        }
        let codecs =
            codecs_for_existing_room(&amr_wb_room("octet-align=1"), &ProfileFlags::default());
        assert_eq!(codecs.len(), 1, "{codecs:?}");
        assert_eq!(codecs[0].encoding_name, "AMR-WB");
    }

    #[test]
    fn a_new_room_offers_every_codec_it_could_forward_widest_band_first() {
        let codecs = codecs_for_new_room(&ProfileFlags::default());
        let names: Vec<&str> = codecs
            .iter()
            .map(|codec| codec.encoding_name.as_str())
            .collect();
        assert_eq!(names[0], "OPUS", "{names:?}");
        // AMR is listed without the `amr` feature: forwarding needs no codec.
        assert!(
            names.contains(&"AMR-WB") && names.contains(&"AMR"),
            "{names:?}"
        );
        assert!(names.contains(&"G729"), "{names:?}");
    }

    #[test]
    fn the_codec_flags_edit_a_new_rooms_offer() {
        let flags = ProfileFlags {
            flags: vec![
                "codec-strip-OPUS".to_string(),
                "codec-offer-PCMA".to_string(),
            ],
            ..Default::default()
        };
        let codecs = codecs_for_new_room(&flags);
        assert_eq!(codecs[0].encoding_name, "PCMA");
        assert!(!codecs.iter().any(|codec| codec.encoding_name == "OPUS"));
    }
}
