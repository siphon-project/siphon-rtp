//! Conference dial-out: the room offers a seat and seats the participant on its answer.
//!
//! `conference_join` answers a participant who called the room. When the room calls a participant
//! instead (RFC 4579 §5.5, a REFER to the focus naming the user; 3GPP TS 24.605 CONF; RFC 5366), the
//! focus sends the INVITE, so the engine is the offerer (RFC 3264 §5): `conference_offer` allocates
//! the seat's endpoint and writes the offer, and `conference_answer` takes the participant's answer
//! and seats it through the same path a join does.
//!
//! Between the two the seat is **pending**: it holds an endpoint but is not in the room, so nothing
//! is mixed to or from it. A pending seat ends in exactly one of four ways, each of which frees its
//! endpoint: it is answered (and seated, or refused), it leaves, or it expires on the sweep after the
//! setup timeout, the same ceiling an offered call awaiting its answer gets.

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction, SourceFilter};
use siphon_rtp_proto::{CmdResult, ConferenceRole, ProfileFlags};

use crate::sdp::{self, TelephoneEvent};

use super::answer_local::order_codec_candidates;
use super::negotiate::{
    ice_directive, parse_codec_flags, peer_media_address, random_ssrc, IceDirective,
    OPUS_DYNAMIC_PAYLOAD_TYPE,
};
use super::offer::far_address_family;
use super::room::{build_seat_codec, SeatRequest};
use super::{error_result, ok_empty, ok_sdp, ClientId, Engine};

/// A seat the engine has offered and the participant has not yet answered.
pub(super) struct PendingSeat {
    /// The seat's one engine endpoint, RTP and RTCP multiplexed (RFC 5761).
    endpoint: Endpoint,
    /// The audio codecs the offer listed, in its order.
    offered: Vec<CodecSpec>,
    /// The telephone-event payload types the offer listed, one per clock rate.
    events: Vec<TelephoneEvent>,
    /// The role the participant takes once seated.
    role: ConferenceRole,
    /// The offer's profile: its `symmetric` flag and dialog `Call-ID` carry over to the seat.
    profile: ProfileFlags,
    /// The logical tick the offer was made at, the baseline its expiry is measured from.
    offered_tick: u64,
}

/// A pending seat's key: the room and the participant's from-tag.
type PendingKey = (String, String);

fn pending_key(conference_id: &str, from_tag: &str) -> PendingKey {
    (conference_id.to_string(), from_tag.to_string())
}

/// Dynamic payload types for the formats the offer lists that have no static one (RFC 3551 §6). The
/// AMR pair follow 3GPP TS 26.114 Table A.1.2's layout (bandwidth-efficient first), Opus keeps the
/// engine's conventional number, and none of them collide.
const AMR_WB_PAYLOAD_TYPES: [u8; 2] = [96, 97];
const AMR_PAYLOAD_TYPES: [u8; 2] = [98, 99];
const G726_32_PAYLOAD_TYPE: u8 = 102;
/// Telephone-event (RFC 4733) payload types, one per clock rate the codecs use.
const TELEPHONE_EVENT_PAYLOAD_TYPES: [(u32, u8); 3] = [(8000, 101), (16_000, 100), (48_000, 110)];

/// Every format a room could seat a participant in, widest band first: full-band Opus, the
/// wideband pair (AMR-WB, G.722), then the narrowband codecs. A format this build cannot decode,
/// encode or hold in a room is filtered out by [`offerable_codecs`], so the list never promises a
/// codec the answer would then fail to seat in.
fn candidate_codecs() -> Vec<CodecSpec> {
    let mut candidates = vec![CodecSpec::new(
        OPUS_DYNAMIC_PAYLOAD_TYPE,
        factory::OPUS_ENCODING_NAME,
        factory::OPUS_CLOCK_RATE_HZ,
        factory::OPUS_RTPMAP_CHANNELS,
        20,
    )];
    candidates.extend(sdp::offered_amr(AMR_WB_PAYLOAD_TYPES, "AMR-WB", 16_000));
    candidates.push(CodecSpec::new(9, "G722", 8000, 1, 20));
    candidates.extend(sdp::offered_amr(AMR_PAYLOAD_TYPES, "AMR", 8000));
    candidates.push(CodecSpec::new(0, "PCMU", 8000, 1, 20));
    candidates.push(CodecSpec::new(8, "PCMA", 8000, 1, 20));
    candidates.push(CodecSpec::new(18, "G729", 8000, 1, 20));
    candidates.push(CodecSpec::new(G726_32_PAYLOAD_TYPE, "G726-32", 8000, 1, 20));
    candidates.push(CodecSpec::new(3, "GSM", 8000, 1, 20));
    candidates
}

/// The codecs a seat is offered in: [`candidate_codecs`] the room can mix in this build (the same
/// [`build_seat_codec`] test a join's codec passes), edited by the profile's codec flags with the
/// rules `conference_join` and `answer_local` apply to an offer's codecs.
fn offerable_codecs(profile: &ProfileFlags) -> Vec<CodecSpec> {
    // Which candidates this build can mix depends only on the build, so it is decided once per
    // process: building every codec (an Opus and an AMR-WB encoder among them) on each offer would
    // cost call setup far more than the offer itself.
    static MIXABLE: std::sync::OnceLock<Vec<bool>> = std::sync::OnceLock::new();
    let mixable = MIXABLE.get_or_init(|| {
        candidate_codecs()
            .into_iter()
            .map(|spec| build_seat_codec(spec).is_ok())
            .collect()
    });
    let offered = candidate_codecs()
        .into_iter()
        .zip(mixable.iter())
        .filter_map(|(spec, mixable)| mixable.then_some(spec))
        .collect();
    order_codec_candidates(offered, &parse_codec_flags(&profile.flags))
}

/// One telephone-event per clock rate among `codecs`, in the order the rates first appear.
fn offered_events(codecs: &[CodecSpec]) -> Vec<TelephoneEvent> {
    let mut events: Vec<TelephoneEvent> = Vec::new();
    for codec in codecs {
        let Some(&(clock_rate_hz, payload_type)) = TELEPHONE_EVENT_PAYLOAD_TYPES
            .iter()
            .find(|(rate, _)| *rate == codec.clock_rate_hz)
        else {
            continue;
        };
        if !events
            .iter()
            .any(|event| event.clock_rate_hz == clock_rate_hz)
        {
            events.push(TelephoneEvent {
                payload_type,
                clock_rate_hz,
            });
        }
    }
    events
}

/// Refuse a profile asking for what an offering seat cannot do. The offer is plain `RTP/AVP` with no
/// ICE: SDES and DTLS-SRTP keying and ICE candidate gathering are all built around answering a
/// peer's offer, and an offer that claimed them would have nothing behind it.
fn refuse_unsupported_profile(profile: &ProfileFlags) -> Result<(), String> {
    if let Some(protocol) = profile.transport_protocol.as_deref() {
        if !protocol.trim().eq_ignore_ascii_case("RTP/AVP") {
            return Err(format!(
                "transport_protocol {protocol} is not supported on an offered seat (only RTP/AVP)"
            ));
        }
    }
    if matches!(ice_directive(profile), Some(IceDirective::Force)) {
        return Err("ICE is not supported on an offered seat".to_string());
    }
    if let Some(dtls) = profile.dtls.as_deref() {
        if !dtls.trim().eq_ignore_ascii_case("off") {
            return Err(format!(
                "dtls {dtls} is not supported on an offered seat (DTLS-SRTP is not offered)"
            ));
        }
    }
    Ok(())
}

/// The seat's codec from the answer: its first audio format (RFC 3264 §6.1, the answerer lists the
/// one it will use first), which must be a payload type the offer listed under the same encoding.
fn answered_codec(info: &sdp::MediaInfo, pending: &PendingSeat) -> Result<CodecSpec, String> {
    let Some(answered) = info.audio_codecs().into_iter().next() else {
        return Err("the answer has no audio codec".to_string());
    };
    let Some(offered) = pending
        .offered
        .iter()
        .find(|offered| offered.payload_type == answered.payload_type)
    else {
        return Err(format!(
            "the answer chose payload type {}, which was not offered",
            answered.payload_type
        ));
    };
    if offered.encoding_name != answered.encoding_name
        || offered.clock_rate_hz != answered.clock_rate_hz
    {
        return Err(format!(
            "the answer maps payload type {} to {}/{}, offered as {}/{}",
            answered.payload_type,
            answered.encoding_name,
            answered.clock_rate_hz,
            offered.encoding_name,
            offered.clock_rate_hz
        ));
    }
    // RFC 4867 §8.3.1: `octet-align` is a payload format parameter, which the answer cannot change
    // for a payload type the offer defined.
    let octet_aligned = |spec: &CodecSpec| spec.amr.and_then(|amr| amr.octet_align) == Some(true);
    if answered.is_amr() && octet_aligned(&answered) != octet_aligned(offered) {
        return Err(format!(
            "the answer changed the payload format (octet-align) of payload type {}",
            answered.payload_type
        ));
    }
    Ok(answered)
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Offer a new seat in `conference_id` ([`siphon_rtp_proto::Command::ConferenceOffer`]).
    pub(super) async fn conference_offer(
        &self,
        conference_id: &str,
        from_tag: String,
        role: ConferenceRole,
        profile: ProfileFlags,
    ) -> CmdResult {
        if let Err(reason) = super::validate_sip_call_id(&profile) {
            return error_result("conference_offer", &reason);
        }
        if let Err(reason) = refuse_unsupported_profile(&profile) {
            return error_result("conference_offer", &reason);
        }
        if self.has_pending_seat(conference_id, &from_tag) {
            return error_result(
                "conference_offer",
                &format!("from-tag {from_tag} already has an offer awaiting its answer"),
            );
        }
        if self
            .conference
            .participant_at_tag(conference_id, &from_tag)
            .is_some()
        {
            return error_result(
                "conference_offer",
                &format!("from-tag {from_tag} is already seated in this room"),
            );
        }
        let offered = offerable_codecs(&profile);
        if offered.is_empty() {
            return error_result(
                "conference_offer",
                &"no codec the room can mix is left after the profile's codec flags",
            );
        }
        let events = offered_events(&offered);
        // The seat is a single leg, so it takes the near (`direction[0]`) interface, as a join does.
        // There is no peer address yet to take the family from, so it is IPv4 unless the profile's
        // `address_family` asks for IPv6.
        let family = far_address_family(&profile).unwrap_or(AddressFamily::V4);
        let (interface, _) = self.interfaces.resolve_direction(&profile.direction);
        let (bind, advertised_override) = Self::leg_binding(interface, family);
        let endpoint = match self.alloc_endpoints(1, family, bind).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return error_result("conference_offer", &reason),
        };
        let advertised = advertised_override.unwrap_or_else(|| endpoint.local_addr.ip());
        let offer = sdp::conference_seat_offer(
            endpoint.local_addr,
            advertised,
            random_ssrc(),
            &offered,
            &events,
        );
        let seat = PendingSeat {
            endpoint,
            offered,
            events,
            role,
            profile,
            offered_tick: self.datapath.now_ticks(),
        };
        // Inserted only if no concurrent offer took the key while the endpoint was allocated.
        let inserted = match self
            .pending_seats
            .entry(pending_key(conference_id, &from_tag))
        {
            dashmap::mapref::entry::Entry::Occupied(_) => false,
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(seat);
                true
            }
        };
        if !inserted {
            self.free(&[endpoint]).await;
            return error_result(
                "conference_offer",
                &format!("from-tag {from_tag} already has an offer awaiting its answer"),
            );
        }
        ok_sdp(offer, Some(from_tag))
    }

    /// Seat the participant a [`siphon_rtp_proto::Command::ConferenceOffer`] offered, on its answer
    /// ([`siphon_rtp_proto::Command::ConferenceAnswer`]). The pending seat is consumed either way: a
    /// refused answer frees its endpoint.
    pub(super) async fn conference_answer(
        &self,
        client: ClientId,
        conference_id: &str,
        from_tag: &str,
        answer: &str,
        received_from: Option<std::net::IpAddr>,
    ) -> CmdResult {
        let Some((_, pending)) = self
            .pending_seats
            .remove(&pending_key(conference_id, from_tag))
        else {
            return error_result(
                "conference_answer",
                &format!(
                    "no conference_offer for from-tag {from_tag} awaits an answer in this room"
                ),
            );
        };
        let endpoint = pending.endpoint;
        let request = match self.answered_seat(from_tag, answer, received_from, pending) {
            Ok(request) => request,
            Err(reason) => {
                self.free(&[endpoint]).await;
                return error_result("conference_answer", &reason);
            }
        };
        if let Err(error) = self
            .datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
        {
            self.free(&[endpoint]).await;
            return error_result("conference_answer: install redirect", &error);
        }
        match self.seat_participant(client, conference_id, request).await {
            Ok(()) => ok_empty(),
            Err(refusal) => error_result("conference_answer", &refusal),
        }
    }

    /// Read the participant's answer into the seat it negotiates, refusing an answer the offer does
    /// not admit.
    fn answered_seat(
        &self,
        from_tag: &str,
        answer: &str,
        received_from: Option<std::net::IpAddr>,
        pending: PendingSeat,
    ) -> Result<SeatRequest, String> {
        let info = sdp::parse(answer).map_err(|error| format!("SDP parse: {error}"))?;
        // RFC 3264 §6: an answerer rejects a stream by answering it with port 0.
        if info.remote_rtp.port() == 0 {
            return Err("the answer rejected the audio stream (port 0)".to_string());
        }
        // RFC 3264 §6: the answer keeps the offer's transport. The offer was plain RTP/AVP.
        if info.secure || info.dtls {
            return Err("the answer is secure, but the offer was RTP/AVP".to_string());
        }
        if AddressFamily::of(info.remote_rtp.ip())
            != AddressFamily::of(pending.endpoint.local_addr.ip())
        {
            return Err(format!(
                "the answer's address {} is not in the offered seat's address family",
                info.remote_rtp.ip()
            ));
        }
        let codec = answered_codec(&info, &pending)?;
        let codec = build_seat_codec(codec)?;
        // The answer's event payload type, when it is one the offer listed.
        let telephone_event =
            TelephoneEvent::accompanying(&info.telephone_events(), Some(&codec.spec))
                .filter(|event| pending.events.contains(event));
        // RTPBleed gate, as on a joined seat: the signalled source only, unless the leg is
        // explicitly symmetric (docs/security-and-nat.md §4).
        //
        // The answerer's `received-from` hint moves the gate and the mix's opening destination off
        // a private `c=` onto its NAT's public address, as on a two-party answer.
        let remote_rtp = peer_media_address(info.remote_rtp, received_from);
        let accepted_source = if pending.profile.flags.iter().any(|flag| flag == "symmetric") {
            SourceFilter::Any
        } else {
            SourceFilter::Exact(remote_rtp.ip())
        };
        Ok(SeatRequest {
            tag: from_tag.to_string(),
            codec,
            telephone_event,
            endpoint: pending.endpoint,
            remote_rtp,
            accepted_source,
            secure: None,
            secure_pending: false,
            ice_pending: false,
            text: None,
            text_endpoint: None,
            role: pending.role,
            sip_call_id: pending.profile.sip_call_id,
            // An answer of `a=recvonly` / `a=inactive` holds the seat, as such an offer does on a
            // join (RFC 4566 §6).
            held: !info.direction.peer_sends(),
        })
    }

    /// Whether `from_tag` has an offered seat in `conference_id` awaiting its answer.
    pub(super) fn has_pending_seat(&self, conference_id: &str, from_tag: &str) -> bool {
        self.pending_seats
            .contains_key(&pending_key(conference_id, from_tag))
    }

    /// Drop an offered seat that was never answered, freeing its endpoint. `false` when there is none.
    pub(super) async fn drop_pending_seat(&self, conference_id: &str, from_tag: &str) -> bool {
        match self
            .pending_seats
            .remove(&pending_key(conference_id, from_tag))
        {
            Some((_, pending)) => {
                self.free(&[pending.endpoint]).await;
                true
            }
            None => false,
        }
    }

    /// Expire offered seats whose answer has not come within `setup_ticks` (`--setup-timeout-secs`,
    /// the ceiling an offered call awaiting its answer gets), freeing their endpoints. With the setup
    /// timeout disabled (`0`) the media timeout `idle_ticks` bounds them instead: a pending seat holds
    /// a port and nothing but its answer, a leave or this sweep ever releases it, so it is never left
    /// unbounded. Driven by the datapath's logical clock. Returns how many expired.
    pub async fn reap_pending_seats(&self, setup_ticks: u64, idle_ticks: u64) -> usize {
        let budget = if setup_ticks > 0 {
            setup_ticks
        } else {
            idle_ticks
        };
        if budget == 0 {
            return 0;
        }
        let now = self.datapath.now_ticks();
        let expired: Vec<PendingKey> = self
            .pending_seats
            .iter()
            .filter(|seat| now.saturating_sub(seat.offered_tick) >= budget)
            .map(|seat| seat.key().clone())
            .collect();
        let mut reaped = 0;
        for key in expired {
            // Re-checked on removal: an answer may have consumed the seat since the scan.
            if let Some((_, pending)) = self.pending_seats.remove_if(&key, |_, seat| {
                now.saturating_sub(seat.offered_tick) >= budget
            }) {
                self.free(&[pending.endpoint]).await;
                reaped += 1;
            }
        }
        reaped
    }

    /// Offered seats awaiting their answer (the leak soak gates on this draining to zero).
    #[must_use]
    pub fn pending_seat_count(&self) -> usize {
        self.pending_seats.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_candidates_have_distinct_payload_types() {
        let mut payload_types: Vec<u8> = candidate_codecs()
            .iter()
            .map(|codec| codec.payload_type)
            .chain(
                TELEPHONE_EVENT_PAYLOAD_TYPES
                    .iter()
                    .map(|(_, payload_type)| *payload_type),
            )
            .collect();
        let listed = payload_types.len();
        payload_types.sort_unstable();
        payload_types.dedup();
        assert_eq!(payload_types.len(), listed, "{payload_types:?}");
    }

    #[test]
    fn only_codecs_a_room_can_seat_are_offered() {
        let offered = offerable_codecs(&ProfileFlags::default());
        assert!(!offered.is_empty());
        for codec in &offered {
            assert!(
                build_seat_codec(codec.clone()).is_ok(),
                "{} is offered but cannot be seated",
                codec.encoding_name
            );
        }
        let names: Vec<&str> = offered
            .iter()
            .map(|codec| codec.encoding_name.as_str())
            .collect();
        // Always built: Opus first, then G.722, then G.711 µ-law and A-law.
        let position = |name: &str| names.iter().position(|offered| *offered == name);
        assert_eq!(position("OPUS"), Some(0), "{names:?}");
        assert!(position("G722") < position("PCMU"), "{names:?}");
        assert!(position("PCMU") < position("PCMA"), "{names:?}");
        assert_eq!(
            position("AMR-WB").is_some(),
            cfg!(feature = "amr"),
            "AMR-WB only with the amr feature: {names:?}"
        );
        assert_eq!(
            position("G729").is_some(),
            cfg!(feature = "g729"),
            "G.729 only with the g729 feature: {names:?}"
        );
    }

    #[test]
    fn the_codec_flags_edit_the_offer() {
        let flags = |flags: &[&str]| ProfileFlags {
            flags: flags.iter().map(|flag| (*flag).to_string()).collect(),
            ..Default::default()
        };
        let names = |profile: &ProfileFlags| -> Vec<String> {
            offerable_codecs(profile)
                .into_iter()
                .map(|codec| codec.encoding_name)
                .collect()
        };
        assert_eq!(
            names(&flags(&["codec-except-PCMA", "codec-except-PCMU"])),
            ["PCMU", "PCMA"]
        );
        assert!(!names(&flags(&["codec-strip-OPUS"])).contains(&"OPUS".to_string()));
        assert_eq!(names(&flags(&["codec-offer-PCMA"]))[0], "PCMA");
        assert!(
            names(&flags(&["codec-except-EVS"])).is_empty(),
            "a keep-list naming nothing mixable leaves nothing to offer"
        );
    }

    #[test]
    fn one_telephone_event_per_clock_rate() {
        let codecs = [
            CodecSpec::new(111, "opus", 48_000, 2, 20),
            CodecSpec::new(9, "G722", 8000, 1, 20),
            CodecSpec::new(0, "PCMU", 8000, 1, 20),
            CodecSpec::new(96, "AMR-WB", 16_000, 1, 20),
        ];
        assert_eq!(
            offered_events(&codecs),
            [
                TelephoneEvent {
                    payload_type: 110,
                    clock_rate_hz: 48_000
                },
                TelephoneEvent {
                    payload_type: 101,
                    clock_rate_hz: 8000
                },
                TelephoneEvent {
                    payload_type: 100,
                    clock_rate_hz: 16_000
                },
            ]
        );
    }

    #[test]
    fn a_profile_asking_for_security_or_ice_is_refused() {
        let refused = |profile: ProfileFlags| refuse_unsupported_profile(&profile).unwrap_err();
        assert!(refused(ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..Default::default()
        })
        .contains("RTP/SAVP"));
        assert!(refused(ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            ..Default::default()
        })
        .contains("only RTP/AVP"));
        assert!(refused(ProfileFlags {
            ice: Some("force".into()),
            ..Default::default()
        })
        .contains("ICE"));
        assert!(refused(ProfileFlags {
            dtls: Some("actpass".into()),
            ..Default::default()
        })
        .contains("DTLS"));
        for allowed in [
            ProfileFlags::default(),
            ProfileFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                ..Default::default()
            },
        ] {
            assert_eq!(refuse_unsupported_profile(&allowed), Ok(()));
        }
    }
}
