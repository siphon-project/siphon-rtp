//! Conference verbs: join, leave, route, bridge, and room-wide playback and recording.

use siphon_rtp_codec::factory;
use siphon_rtp_datapath::{
    AddressFamily, Datapath, FlowAction, IceAgentMode, IceConfig, SourceFilter,
};
use siphon_rtp_dtls::Fingerprint as DtlsFingerprint;
use siphon_rtp_media::mixer::Role;
use siphon_rtp_media::playback::Gain;
use siphon_rtp_media::player::{PcmPlayer, PcmRepeat};
use siphon_rtp_media::tone::ToneSpec;
use siphon_rtp_proto::{
    BridgeDirection, CmdResult, ConferenceRole, Event, PlayMediaSource, PlayRepeat, ProfileFlags,
    RecordingEndReason,
};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use std::sync::Arc;

use crate::conference::{ConferenceControl, ParticipantConfig, ParticipantTextConfig, Routing};
use crate::dtls_bridge::DtlsCallPlan;
use crate::ice;
use crate::media_pipeline::PlayRequest;
use crate::sdp::{self, EngineMedia, IceRewrite, SecurityAdvertisement, TextRewrite};

use super::negotiate::{
    filter_component, ice_directive, ice_tie_breaker, peer_ice_credentials, random_ssrc,
    IceDirective,
};
use super::play::{parse_prompt_wav, PlayOptions, ResolvedPlaySource};
use super::record::AudioRecording;
use super::{error_result, ok_empty, ok_sdp, ClientId, Engine, Leg};

/// What anchoring a conference seat's RFC 9071 text stream leaves for the seat.
struct SeatText {
    /// The seat's text configuration for the room, when a text stream was anchored.
    config: Option<ParticipantTextConfig>,
    /// How the answer presents the participant's `m=text` section.
    rewrite: TextRewrite,
    /// The seat's text endpoint, when one was allocated.
    endpoint: Option<siphon_rtp_datapath::Endpoint>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// A full RFC 8445 agent runs when the operator enabled it and the peer gave us both
    /// credentials and candidates; otherwise the datapath's ice-lite responder answers checks and
    /// adopts the validated source, exactly as on a 2-party leg.
    ///
    /// Only a full agent sets `ice_pending` on the seat, and that is a *room-level* gate for the
    /// window in which a selection is still coming. An ice-lite seat never sets it, because no
    /// selection is coming and a seat left pending forever would never be mixed at all; what
    /// covers an ice-lite seat is the datapath's layer-4 ICE gate on the redirected path, which
    /// hands the room only the source a connectivity check validated (`Inner::ice_gate`;
    /// docs/security-and-nat.md §4 layer 4). Both gates are armed by the credentials installed
    /// below — without them the seat would fall back to its `accepted_source` filter alone, which
    /// an ICE seat deliberately leaves open.
    ///
    /// Returns whether a full agent now runs on the seat, which holds it `ice_pending`.
    fn arm_seat_ice(
        &self,
        conference_id: &str,
        endpoint: siphon_rtp_datapath::Endpoint,
        info: &sdp::MediaInfo,
        ice_config: Option<&IceConfig>,
        ice_candidates: &[siphon_rtp_ice::Candidate],
    ) -> bool {
        let peer_ice = peer_ice_credentials(info);
        let mut ice_pending = false;
        if let Some(config) = ice_config {
            let full_agent = self.ice_agents.as_ref().and_then(|agents| {
                let peer = peer_ice.as_ref()?;
                (!info.candidates.is_empty()).then(|| (agents.clone(), peer.clone()))
            });
            match full_agent {
                Some((agents, peer)) => {
                    let agent_config = siphon_rtp_ice::agent::AgentConfig::new(
                        siphon_rtp_ice::agent::Credentials::new(
                            config.local_ufrag.clone(),
                            config.local_pwd.clone(),
                        ),
                        siphon_rtp_ice::agent::Credentials::new(
                            peer.ufrag.clone(),
                            peer.pwd.clone(),
                        ),
                        // RFC 8445 §6.1.1: the offerer controls. The participant offered, so it
                        // controls — unless it is a lite agent, which can never control.
                        info.ice_lite,
                        ice_tie_breaker(),
                    )
                    .with_candidates(
                        filter_component(ice_candidates, 1),
                        filter_component(&info.candidates, 1),
                    );
                    self.datapath.set_ice_agent(
                        endpoint.id,
                        config.clone(),
                        // The agent owns request handling and is the only thing that may select a
                        // pair; the datapath answers nothing on this endpoint.
                        IceAgentMode::ForwardOnly,
                        agents.events(),
                    );
                    agents.register(
                        endpoint.id,
                        conference_id,
                        endpoint.local_addr,
                        agent_config,
                        0,
                    );
                    ice_pending = true;
                }
                None => self.datapath.set_ice(endpoint.id, Some(config.clone())),
            }
        }
        ice_pending
    }

    /// RFC 9071 conference text: anchor a participant's `m=text` (RFC 4103) stream — its own
    /// redirected endpoint, its own per-stream RTPBleed gate + latch — for a **plaintext**
    /// (`RTP/AVP`) leg *or* a **secure** (SDES-SRTP, `RTP/SAVP` + `a=crypto`) one. A secure text leg
    /// is keyed exactly like the secure audio leg above: mint the engine's own per-participant text
    /// SDES key, answer `RTP/SAVP` + our `a=crypto`, and terminate SRTP on a per-participant
    /// `SecureLeg` — each participant's text is secured independently while the room's text mix stays
    /// internal plaintext, the same model as the conference audio (docs/security-and-nat.md §4). A
    /// secure text section we cannot key/anchor (no usable `t140`, or no usable `a=crypto`) is
    /// declined (`m=text 0`, RFC 3264 §6), never downgraded to plaintext. The room mixes each
    /// participant's text across the others with per-source CSRC identification. Allocated after the
    /// audio SDES/DTLS block so an audio-keying failure above never leaks a text port.
    ///
    /// Frees the seat's endpoints itself on a refusal.
    async fn anchor_seat_text(
        &self,
        info: &sdp::MediaInfo,
        profile: &ProfileFlags,
        family: AddressFamily,
        bind: Option<std::net::IpAddr>,
        endpoint: siphon_rtp_datapath::Endpoint,
        advertised: std::net::IpAddr,
    ) -> Result<SeatText, Box<CmdResult>> {
        let symmetric = profile.flags.iter().any(|flag| flag == "symmetric");
        let (text_config, text_rewrite, text_endpoint) = match info.text.as_ref() {
            Some(text) => {
                let text_remote_crypto = text.crypto.first().copied();
                // Anchorable iff it has a usable `t140` PT and — for a secure leg — a usable peer key.
                match text.t140_payload_type {
                    Some(t140_pt) if !text.secure || text_remote_crypto.is_some() => {
                        let text_endpoint = match self.alloc_endpoints(1, family, bind).await {
                            Ok(mut endpoints) => endpoints.remove(0),
                            Err(reason) => {
                                self.free(&[endpoint]).await;
                                return Err(Box::new(error_result(
                                    "conference_join: text endpoint",
                                    &reason,
                                )));
                            }
                        };
                        if let Err(error) = self
                            .datapath
                            .install_flow(text_endpoint.id, FlowAction::Redirect)
                        {
                            self.free(&[endpoint, text_endpoint]).await;
                            return Err(Box::new(error_result(
                                "conference_join: install text redirect",
                                &error,
                            )));
                        }
                        let text_source = if symmetric {
                            SourceFilter::Any
                        } else {
                            SourceFilter::Exact(text.remote_rtp.ip())
                        };
                        let text_engine = EngineMedia {
                            rtp: text_endpoint.local_addr,
                            rtcp: None,
                            advertised_ip: advertised,
                        };
                        // Secure text: mint the engine's own text SDES key, build the participant's text
                        // `SecureLeg` (decrypt its ingress with theirs, encrypt its egress with ours),
                        // and answer `RTP/SAVP` + our text `a=crypto` (RFC 4568). Plaintext: anchor
                        // plainly.
                        let (text_secure, text_rewrite) = match text_remote_crypto {
                            Some(remote) if text.secure => {
                                let local = match CryptoAttribute::generate(
                                    1,
                                    CryptoSuite::AesCm128HmacSha1_80,
                                ) {
                                    Ok(local) => local,
                                    Err(error) => {
                                        self.free(&[endpoint, text_endpoint]).await;
                                        return Err(Box::new(error_result(
                                            "conference_join: generate text SDES key",
                                            &error,
                                        )));
                                    }
                                };
                                (
                                    Some(SecureLeg::new(&local.key, &remote.key)),
                                    TextRewrite::AnchorSecure {
                                        engine: text_engine,
                                        crypto: local,
                                    },
                                )
                            }
                            _ => (None, TextRewrite::Anchor(text_engine)),
                        };
                        (
                            Some(ParticipantTextConfig {
                                ingress_endpoint: text_endpoint.id,
                                egress_endpoint: text_endpoint.id,
                                egress_dst: text.remote_rtp,
                                accepted_source: text_source,
                                latch: true,
                                t140_payload_type: t140_pt,
                                red_payload_type: text.red_payload_type,
                                egress_ssrc: random_ssrc(),
                                secure: text_secure,
                            }),
                            text_rewrite,
                            Some(text_endpoint),
                        )
                    }
                    // A secure text section we cannot key/anchor (no usable `t140`, or no usable
                    // `a=crypto`) is declined (`m=text 0`), never downgraded to plaintext.
                    _ if text.secure => (None, TextRewrite::Decline, None),
                    // A plaintext `m=text` with no usable `t140` rtpmap is left untouched.
                    _ => (None, TextRewrite::None, None),
                }
            }
            None => (None, TextRewrite::None, None),
        };
        Ok(SeatText {
            config: text_config,
            rewrite: text_rewrite,
            endpoint: text_endpoint,
        })
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Join (or lazily create) an audio conference ([`Command::ConferenceJoin`]). The participant
    /// offers SDP; the engine allocates one endpoint, seats it in the room's mixer, and answers with
    /// the engine endpoint advertising the participant's codec (sendrecv) — the participant then hears
    /// the room's mixed-minus-self audio. Each participant endpoint is a full inbound surface, so the
    /// source gate + constrained latch are enforced on ingress (RTPBleed, docs §4).
    pub(super) async fn conference_join(
        &self,
        client: ClientId,
        conference_id: &str,
        from_tag: String,
        sdp: &str,
        role: ConferenceRole,
        profile: &ProfileFlags,
    ) -> CmdResult {
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => return error_result("conference_join: SDP parse", &error),
        };
        // ICE on a conference leg (RFC 8445). Unlike a relay leg, the room — not a datapath forward
        // rule — owns the seat's egress, so a selection has to reach the room actor as well as the
        // datapath; that is `ConferenceRegistry::ice_selected`, driven from `drive_ice_agents`.
        //
        // RFC 8839 §5.3: an offer whose default destination matches none of its own candidates was
        // rewritten in transit, so ICE describes a topology media no longer follows. Fall back to the
        // signalled address rather than negotiate ICE we cannot trust.
        let ice_mismatch = siphon_rtp_ice::is_ice_mismatch(info.remote_rtp, &info.candidates)
            && ice_directive(profile) != Some(IceDirective::Force);
        let want_ice = match ice_directive(profile) {
            _ if ice_mismatch => false,
            Some(IceDirective::Force) => true,
            Some(IceDirective::Remove) => false,
            None => info.is_ice(),
        };
        let ice_creds = if want_ice {
            ice::generate_credentials()
        } else {
            None
        };
        if want_ice && ice_creds.is_none() {
            return error_result(
                "conference_join",
                &"could not mint ICE credentials (OS RNG unavailable)",
            );
        }
        let Some(codec) = info.primary_codec() else {
            return error_result("conference_join", &"offer has no audio codec");
        };
        // Build the participant's codecs. `encoder_for` rejects a decode-only codec: we can mix in
        // such a leg's audio but cannot encode the room back to it, so the seat is refused.
        let decoder = match factory::decoder_for(&codec) {
            Ok(decoder) => decoder,
            Err(error) => return error_result("conference_join: decoder", &error),
        };
        let encoder = match factory::encoder_for(&codec) {
            Ok(encoder) => encoder,
            Err(_) => {
                return error_result(
                    "conference_join",
                    &format!(
                    "codec {} has no encoder, so the room mix cannot be sent to this participant \
                         (AMR-WB / AMR-NB need the `amr` build feature)",
                    codec.encoding_name
                ),
                )
            }
        };
        // One engine endpoint in the offer's address family, redirected to the conference actor. A
        // participant is a single leg, so it uses the near (`direction[0]`) interface — its bind IP and
        // advertised (public) address — defaulting when the join carries no `direction`.
        let family = AddressFamily::of(info.remote_rtp.ip());
        let (participant_interface, _) = self.interfaces.resolve_direction(&profile.direction);
        let (bind, advertised_override) = Self::leg_binding(participant_interface, family);
        let endpoint = match self.alloc_endpoints(1, family, bind).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return error_result("conference_join", &reason),
        };
        let advertised = advertised_override.unwrap_or_else(|| endpoint.local_addr.ip());
        if let Err(error) = self
            .datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
        {
            self.free(&[endpoint]).await;
            return error_result("conference_join: install redirect", &error);
        }
        // RTPBleed gate: exact signalled-source by default; accept-any only for an explicit symmetric
        // leg. The constrained latch then learns the reply address from the gated source.
        //
        // An ICE seat runs this gate open (`Any`), because the signalled address is not the
        // discriminator on an ICE leg: a connectivity check legitimately arrives from a
        // peer-reflexive transport the SDP never carried (RFC 8445 §7.3.1.3). What actually holds
        // the seat shut is the datapath's **layer-4 ICE gate**, which redirects media to this room
        // only from the source a check authenticated with our own password — for a full-agent seat
        // the room's `ice_pending` below additionally drops everything until the agent selects, and
        // `ice_selected` then narrows this filter to the selected pair.
        // (docs/security-and-nat.md §4 layer 4; RFC 8445 §7.)
        let accepted_source = if want_ice || profile.flags.iter().any(|flag| flag == "symmetric") {
            SourceFilter::Any
        } else {
            SourceFilter::Exact(info.remote_rtp.ip())
        };

        // Gather this seat's candidates before the answer is written — the answer *is* the candidate
        // list. A conference leg is always RTP/RTCP-muxed onto one endpoint, so it has exactly one
        // component (RFC 8445 §4.1.1.1).
        let (ice_candidates, ice_config) = match ice_creds.as_ref() {
            Some(creds) => {
                let config = IceConfig {
                    local_ufrag: creds.ufrag.clone(),
                    local_pwd: creds.pwd.clone(),
                };
                let leg = Leg {
                    rtp: endpoint,
                    rtcp: None,
                    remote_rtp: None,
                    remote_rtcp: None,
                    advertised_ip: advertised,
                    // A conference seat anchors audio only — RFC 9071 multiparty text is a later
                    // phase — so there is no text component to gather candidates for.
                    text: None,
                    text_remote_rtp: None,
                };
                let candidates = self.gather_leg_candidates(&leg, &config).await;
                (candidates, Some(config))
            }
            None => (Vec::new(), None),
        };

        let ice_pending = self.arm_seat_ice(
            conference_id,
            endpoint,
            &info,
            ice_config.as_ref(),
            &ice_candidates,
        );
        // SDES-SRTP (RTP/SAVP): the participant offered a secure leg + its a=crypto. Mint our own key,
        // build the secure leg (decrypt inbound with theirs, encrypt outbound with ours), and answer
        // RTP/SAVP + a=crypto. (DTLS-SRTP / ICE WebRTC legs remain a follow-up — see the is_ice() guard.)
        // DTLS-SRTP (`UDP/TLS/RTP/SAVPF`): there is no key to build here — the RFC 5764 handshake
        // produces it after this command returns — so the seat is taken **pending** and keyed later
        // over `ConferenceControl::AttachSecureLeg`. Until then the room drops its ingress and sends
        // it nothing, so an unkeyed seat can neither inject noise into the mix nor receive the other
        // participants in the clear.
        let dtls_leg = info.dtls;
        // The handshake needs the engine's certificate and the offer's fingerprint. Both are bound
        // here, once, and carried to the answer and to the handshake plan below.
        let dtls_keys = if dtls_leg {
            let Some(certificate) = self.dtls_certificate.clone() else {
                self.free(&[endpoint]).await;
                return error_result("conference_join", &"engine has no DTLS certificate");
            };
            let Some(peer_fingerprint) = info.fingerprint.clone() else {
                self.free(&[endpoint]).await;
                return error_result(
                    "conference_join",
                    &"UDP/TLS/RTP/SAVPF offer without an a=fingerprint",
                );
            };
            Some((certificate, peer_fingerprint))
        } else {
            None
        };
        let (secure, security) = if let Some((certificate, _)) = dtls_keys.as_ref() {
            // The answer advertises the engine's fingerprint and the answerer's DTLS role for the
            // offerer's `a=setup` (RFC 4145 §4.1, RFC 5763 §5).
            let (setup, _) = super::negotiate::answerer_dtls_setup(info.setup, None);
            (
                None,
                Some(SecurityAdvertisement::Dtls {
                    fingerprint: sdp::Fingerprint {
                        hash_function: certificate.fingerprint().hash_function,
                        bytes: certificate.fingerprint().bytes,
                    },
                    setup,
                    // A seat is a new association each time it joins; the offer's `a=tls-id` is not
                    // yet answered here.
                    tls_id: None,
                }),
            )
        } else if info.secure {
            let Some(remote) = info.crypto.first().copied() else {
                self.free(&[endpoint]).await;
                return error_result(
                    "conference_join",
                    &"RTP/SAVP offer without a usable a=crypto",
                );
            };
            let local = match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                Ok(local) => local,
                Err(error) => {
                    self.free(&[endpoint]).await;
                    return error_result("conference_join: generate SDES key", &error);
                }
            };
            (
                Some(SecureLeg::new(&local.key, &remote.key)),
                Some(SecurityAdvertisement::Secure(local)),
            )
        } else {
            (None, None)
        };
        let SeatText {
            config: text_config,
            rewrite: text_rewrite,
            endpoint: text_endpoint,
        } = match self
            .anchor_seat_text(&info, profile, family, bind, endpoint, advertised)
            .await
        {
            Ok(text) => text,
            Err(result) => return *result,
        };
        let config = ParticipantConfig {
            tag: from_tag.clone(),
            decoder,
            encoder,
            ingress_endpoint: endpoint.id,
            egress_endpoint: endpoint.id,
            egress_dst: info.remote_rtp,
            accepted_source,
            latch: true,
            egress_ssrc: random_ssrc(),
            egress_payload_type: codec.payload_type,
            secure_pending: dtls_leg,
            ice_pending,
            mos_codec: crate::conference::hep_codec_for_name(&codec.encoding_name),
            telephone_event_in: info.telephone_event_payload_type(),
            secure,
            text: text_config,
            routing: routing_of(role),
        };
        let events = self.events.get(&client).map(|sink| sink.value().clone());
        let joined_tick = self.datapath.now_ticks();
        // A seat that offered `a=recvonly` / `a=inactive` told us it will not send (RFC 4566 §6), so
        // the idle sweep must not read its silence as a dead path — a held seat and a listen-only
        // attendee are both legitimately quiet for the whole conference.
        let held = !info.direction.peer_sends();
        if !self.conference.join(
            conference_id,
            config,
            joined_tick,
            held,
            self.datapath.clone(),
            events,
        ) {
            let mut to_free = vec![endpoint];
            to_free.extend(text_endpoint);
            self.free(&to_free).await;
            return error_result("conference_join", &"failed to seat participant");
        }
        self.endpoint_calls
            .insert(endpoint.id, conference_id.to_string());
        // The text endpoint is correlated to the same conference, so RTCP telemetry / reap accounting
        // and teardown treat it as this room's (RFC 9071).
        if let Some(text_endpoint) = text_endpoint {
            self.endpoint_calls
                .insert(text_endpoint.id, conference_id.to_string());
        }

        // A DTLS seat needs the handshake in front of its endpoint: the bridge keeps the RFC 7983
        // demux (DTLS records drive the handshake) and forwards accepted media to the room actor
        // still encrypted, which decrypts it on the seat's own `SecureLeg` once keyed. The seat was
        // taken `secure_pending`, so until then it is neither mixed nor sent to.
        if let Some((certificate, peer_fingerprint)) = dtls_keys {
            // The role matching the `a=setup` advertised in the answer above (RFC 4145 §4.1, RFC 5763
            // §5).
            let (_, role) = super::negotiate::answerer_dtls_setup(info.setup, None);
            if let Err(error) = self
                .datapath
                .install_flow(endpoint.id, FlowAction::Redirect)
            {
                self.conference.leave(conference_id, &from_tag);
                let mut to_free = vec![endpoint];
                to_free.extend(text_endpoint);
                if let Some(text_endpoint) = text_endpoint {
                    self.endpoint_calls.remove(&text_endpoint.id);
                }
                self.free(&to_free).await;
                return error_result("conference_join: install DTLS redirect", &error);
            }
            self.dtls_bridge().register_for_pipeline(
                DtlsCallPlan {
                    // A conference seat is one muxed endpoint; the "plain" side is unused in
                    // pipeline mode (the room owns egress), so it mirrors the secure one.
                    plain_endpoint: endpoint.id,
                    plain_source: accepted_source,
                    plain_dst: info.remote_rtp,
                    secure_endpoint: endpoint.id,
                    secure_source: accepted_source,
                    secure_dst: info.remote_rtp,
                    secure_local: endpoint.local_addr,
                    certificate,
                    role,
                    peer_fingerprint: DtlsFingerprint::new(
                        peer_fingerprint.hash_function,
                        peer_fingerprint.bytes,
                    ),
                    // RFC 8445 §12: a DTLS-SRTP seat keys the pair ICE chose, so hold the handshake
                    // until there is a selection — but only when a full agent is actually running on
                    // this seat, since otherwise no selection is coming and waiting would hang it.
                    gate_on_ice: ice_pending,
                    plain_rtcp: None,
                },
                crate::dtls_bridge::PipelineTarget::Conference {
                    conference: self.conference.clone(),
                    conference_id: conference_id.to_string(),
                    tag: from_tag.clone(),
                },
            );
        }

        // Answer: advertise the engine endpoint (the interface's advertised IP), keep the participant's
        // codec, sendrecv, and (for a secure leg) RTP/SAVP + the engine's a=crypto.
        let engine = EngineMedia {
            rtp: endpoint.local_addr,
            rtcp: None,
            advertised_ip: advertised,
        };
        // A conference leg is always RTP/RTCP-muxed onto the one participant endpoint; the mux
        // presentation mirrors the participant's offer (`None`) — the `rtcp-mux` directive is an
        // offer/answer relay concern, not a conference one.
        //
        // ICE (RFC 8839 §5): re-originate with our own credentials and gathered candidates when we
        // minted them; say `a=ice-mismatch` when the offer's ICE was altered in transit, so the peer
        // stops waiting for checks that will never come; strip on `ICE=remove`; else pass through.
        // `text_rewrite` anchors (or declines) the participant's `m=text` section
        // (RFC 9071 multiparty RTT) resolved above.
        let ice_rewrite = match (ice_creds.as_ref(), ice_directive(profile)) {
            (Some(creds), _) => IceRewrite::Reoriginate(sdp::IceAdvertisement {
                ufrag: creds.ufrag.as_str(),
                pwd: creds.pwd.as_str(),
                candidates: &ice_candidates,
            }),
            (None, _) if ice_mismatch => IceRewrite::Mismatch,
            (None, Some(IceDirective::Remove)) => IceRewrite::Strip,
            (None, _) => IceRewrite::Keep,
        };
        match sdp::rewrite(sdp, engine, ice_rewrite, security, None, text_rewrite) {
            Ok(rewritten) => ok_sdp(rewritten.sdp, Some(from_tag)),
            Err(error) => {
                let _ = self.conference.leave(conference_id, &from_tag);
                self.endpoint_calls.remove(&endpoint.id);
                self.datapath.remove_endpoint(endpoint.id).await;
                if let Some(text_endpoint) = text_endpoint {
                    self.endpoint_calls.remove(&text_endpoint.id);
                    self.datapath.remove_endpoint(text_endpoint.id).await;
                }
                error_result("conference_join: SDP rewrite", &error)
            }
        }
    }

    /// Remove a participant from a conference ([`Command::ConferenceLeave`]), freeing its endpoints —
    /// audio plus its text endpoint when it had one (RFC 9071) — and tearing the room down once empty.
    pub(super) async fn conference_leave(&self, conference_id: &str, from_tag: &str) -> CmdResult {
        let endpoints = self.conference.leave(conference_id, from_tag);
        if endpoints.is_empty() {
            return error_result("conference_leave", &"no such conference participant");
        }
        for endpoint in endpoints {
            self.endpoint_calls.remove(&endpoint);
            self.datapath.remove_endpoint(endpoint).await;
        }
        ok_empty()
    }

    /// Live-update a participant's conference role / routing ([`Command::ConferenceRoute`]).
    pub(super) fn conference_route(
        &self,
        conference_id: &str,
        from_tag: &str,
        role: ConferenceRole,
    ) -> CmdResult {
        if self
            .conference
            .route(conference_id, from_tag, routing_of(role))
        {
            ok_empty()
        } else {
            error_result("conference_route", &"no such conference or participant")
        }
    }

    /// Bridge two conferences ([`Command::ConferenceBridge`]) so each room hears the other's
    /// participants, in the requested direction(s).
    pub(super) fn conference_bridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
        direction: BridgeDirection,
    ) -> CmdResult {
        let (a_to_b, b_to_a) = match direction {
            BridgeDirection::Both => (true, true),
            BridgeDirection::AToB => (true, false),
            BridgeDirection::BToA => (false, true),
        };
        if self
            .conference
            .bridge(conference_id_a, conference_id_b, a_to_b, b_to_a)
        {
            ok_empty()
        } else {
            error_result("conference_bridge", &"one or both conferences do not exist")
        }
    }

    /// Play audio into a conference room ([`Command::ConferencePlay`]) — an entry tone, a
    /// "this conference is being recorded" announcement, hold music for a lone participant.
    ///
    /// A room is not a call. The leg-addressed [`Command::PlayMedia`] resolves through `self.calls`,
    /// which a conference never enters, so it answers `unknown call` for a room id; hence a verb of
    /// its own. The audio goes in as a **non-participant source** on the mixer's `external` input,
    /// which is exactly the seam for it: everyone hears it and nobody is mixed-minus-self against it,
    /// so an announcement is never treated as a participant's own audio and subtracted back out.
    pub(super) async fn conference_play(
        &self,
        conference_id: &str,
        source: PlayMediaSource,
        options: PlayOptions,
    ) -> CmdResult {
        if !self.conference.has_room(conference_id) {
            return error_result(
                "conference_play",
                &format!("unknown conference: {conference_id}"),
            );
        }
        // Same mapping a leg playback uses, so `"inf"` means the same thing in a room as on a leg —
        // which is what hold music for a lone participant needs.
        let repeat = match options.repeat_times {
            None => PcmRepeat::Times(0),
            Some(PlayRepeat::Forever) => PcmRepeat::Forever,
            Some(PlayRepeat::Times(times)) => {
                PcmRepeat::Times(times.min(u64::from(u32::MAX)) as u32)
            }
        };
        let start = options.start_pos_ms.unwrap_or(0).min(u64::from(u32::MAX)) as u32;
        // Resolved here, off the room actor: a file read and a RIFF parse have no business on the
        // 20 ms mix tick. A tone is only *parsed* here — it is synthesised at the room rate inside
        // the actor, which is the only place that knows it.
        let resolved = match source {
            PlayMediaSource::Blob { data } => match parse_prompt_wav(&data) {
                Ok(resolved) => resolved,
                Err(error) => return error_result("conference_play: parse WAV", &error),
            },
            // Through the prompt cache, like a leg playback: an entry tone or a "being recorded"
            // announcement is played into every room on the box, so decoding it per room is exactly
            // the waste the cache exists to remove.
            PlayMediaSource::File { path } => {
                match self.prompts.get_or_load(std::path::Path::new(&path)).await {
                    Ok(prompt) => ResolvedPlaySource::Pcm(prompt),
                    Err(error) => return error_result("conference_play", &error),
                }
            }
            PlayMediaSource::Tone { tone } => match ToneSpec::resolve(&tone) {
                Ok(spec) => ResolvedPlaySource::Tone(spec),
                Err(error) => return error_result("conference_play: tone", &error),
            },
            other => {
                return error_result(
                    "conference_play",
                    &format!("media source {other:?} is not supported for a room"),
                )
            }
        };
        let (request, source_duration_ms) = match resolved {
            ResolvedPlaySource::Pcm(prompt) => {
                let player =
                    PcmPlayer::from_shared(prompt.mono, prompt.sample_rate_hz, repeat, start);
                // `None` for an endless bed — there is no length to promise, exactly as on a leg.
                let duration = player.duration_ms();
                (PlayRequest::Pcm(Box::new(player)), duration)
            }
            ResolvedPlaySource::Tone(spec) => {
                let duration = spec.total_duration_ms();
                (PlayRequest::Tone(spec), duration)
            }
        };
        let duration_ms = match (source_duration_ms, options.duration_ms) {
            (Some(source), Some(cap)) => Some(source.min(cap)),
            (Some(source), None) => Some(source),
            (None, cap) => cap,
        };
        let gain = Gain::from_decibels(options.gain_decibels.unwrap_or(0));
        let play_id = self.next_play_id();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if !self.conference.control(
            conference_id,
            ConferenceControl::StartPlay {
                request: Box::new(request),
                gain,
                play_id,
                duration_cap_ms: options.duration_ms,
                reply: sender,
            },
        ) {
            return error_result("conference_play", &"conference is no longer running");
        }
        match receiver.await {
            Ok(Ok(())) => CmdResult::Ok {
                sdp: None,
                duration_ms,
                play_id: Some(play_id),
                recording_id: None,
                to_tag: None,
                stats: None,
            },
            Ok(Err(error)) => error_result("conference_play", &error),
            Err(_) => error_result(
                "conference_play",
                &"conference actor closed before the playback started",
            ),
        }
    }

    /// Stop audio playing into a room ([`Command::ConferenceStopPlay`]).
    pub(super) async fn conference_stop_play(
        &self,
        conference_id: &str,
        play_id: Option<u64>,
    ) -> CmdResult {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if !self.conference.control(
            conference_id,
            ConferenceControl::StopPlay {
                play_id,
                reply: sender,
            },
        ) {
            return error_result(
                "conference_stop_play",
                &format!("unknown conference: {conference_id}"),
            );
        }
        match receiver.await {
            Ok(true) => ok_empty(),
            // An id that is not running is an error, not a hollow success: a controller that believes
            // it stopped a playback and did not has no way to notice.
            Ok(false) => match play_id {
                Some(play_id) => error_result(
                    "conference_stop_play",
                    &format!("no playback {play_id} is running in this conference"),
                ),
                None => ok_empty(),
            },
            Err(_) => error_result("conference_stop_play", &"conference actor closed"),
        }
    }

    /// Retune a running room playback's gain ([`Command::ConferenceSetPlayGain`]).
    pub(super) async fn conference_set_play_gain(
        &self,
        conference_id: &str,
        play_id: u64,
        gain_decibels: i32,
    ) -> CmdResult {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if !self.conference.control(
            conference_id,
            ConferenceControl::SetPlayGain {
                play_id,
                gain: Gain::from_decibels(gain_decibels),
                reply: sender,
            },
        ) {
            return error_result(
                "conference_set_play_gain",
                &format!("unknown conference: {conference_id}"),
            );
        }
        match receiver.await {
            Ok(true) => ok_empty(),
            Ok(false) => error_result(
                "conference_set_play_gain",
                &format!("no playback {play_id} is running in this conference"),
            ),
            Err(_) => error_result("conference_set_play_gain", &"conference actor closed"),
        }
    }

    /// Record a conference room's mix ([`Command::ConferenceStartRecording`]).
    ///
    /// Taps the **listener mix** — what a listener actually hears, including any bridged room and any
    /// room playback — which is the useful definition of "record the conference". The alternative,
    /// the participant-only mix, is what feeds a bridge and deliberately excludes bridged audio.
    ///
    /// From there it is P3's machinery unchanged: a tagged sink into the shared frame assembler, and
    /// the same streaming WAV writer, so a room recording and a call recording produce the same file
    /// and the same completion event.
    pub(super) async fn conference_start_recording(
        &self,
        client: ClientId,
        conference_id: &str,
        path: Option<String>,
        recording_dir: Option<String>,
        limits: crate::recording::RecordingLimits,
    ) -> CmdResult {
        use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
        use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};

        if !self.conference.has_room(conference_id) {
            return error_result(
                "conference_start_recording",
                &format!("unknown conference: {conference_id}"),
            );
        }
        let recording_id = format!(
            "rec-{}",
            self.next_recording_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = match path {
            Some(path) => std::path::PathBuf::from(path),
            None => match recording_dir {
                Some(directory) => std::path::PathBuf::from(directory)
                    .join(format!("{conference_id}-{recording_id}.wav")),
                None => {
                    return error_result(
                        "conference_start_recording",
                        &"no output location (set `path`, or `recording_dir`)",
                    )
                }
            },
        };
        // Opened before a sink is attached, so a bad path fails the verb with the room untouched.
        let file = match tokio::fs::File::create(&path).await {
            Ok(file) => file,
            Err(error) => {
                return error_result(
                    "conference_start_recording",
                    &format!("open {}: {error}", path.display()),
                )
            }
        };

        // The room mixes at its own rate, which moves with membership and bridging. A recording is a
        // file, not a live stream, so it is pinned to one rate for its lifetime and the *room*
        // converts into it — a room that started narrowband and went wideband mid-recording would
        // otherwise change sample rate inside one WAV, which no player handles. Wideband is the pin:
        // it is the widest a room reaches short of a fullband participant, so a conference that goes
        // wideband is recorded at its own quality rather than downsampled to the rate it started at.
        let rate = crate::conference::WIDEBAND_RECORDING_RATE_HZ;
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: rate,
            channels: 1,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        };
        let plan = plan_ws_tee(format, false, false);
        // No resampler on the sink: the room owns that conversion, because the room is the only thing
        // that knows when its own rate moves.
        let sink = WsTeeSink::new(
            TeeChannel::Caller,
            plan.mixer.clone(),
            recording_id.clone(),
            None,
        );
        if !self.conference.control(
            conference_id,
            ConferenceControl::AddRoomTap {
                sink: Box::new(sink),
                rate,
            },
        ) {
            return error_result("conference_start_recording", &"conference actor closed");
        }

        let source_reason = Arc::new(std::sync::Mutex::new(RecordingEndReason::CallEnded));
        let writer = {
            let events = self.events.get(&client).map(|sink| sink.value().clone());
            let conference_id = conference_id.to_string();
            let recording_id = recording_id.clone();
            let path = path.clone();
            let source_reason = source_reason.clone();
            let frames = plan.frames;
            let recycle = plan.recycle;
            tokio::spawn(async move {
                let outcome = crate::recording::run_wav_recorder(
                    file,
                    path.clone(),
                    rate,
                    1,
                    limits,
                    frames,
                    recycle,
                )
                .await;
                let source_reason = source_reason
                    .lock()
                    .map(|reason| *reason)
                    .unwrap_or(RecordingEndReason::CallEnded);
                let reason = outcome.end.into_reason(source_reason);
                if let Some(events) = events {
                    let _ = events.try_send(Event::RecordingFinished {
                        call_id: String::new(),
                        conference_id: Some(conference_id),
                        from_tag: String::new(),
                        to_tag: None,
                        recording_id,
                        path: Some(path.to_string_lossy().into_owned()),
                        duration_ms: outcome.duration_ms,
                        reason,
                    });
                }
            })
        };

        self.recordings.insert(
            recording_id.clone(),
            AudioRecording {
                recording_id: recording_id.clone(),
                call_id: conference_id.to_string(),
                owner: client,
                path,
                ingress_legs: Vec::new(),
                egress_legs: Vec::new(),
                room: Some(conference_id.to_string()),
                source_reason,
                writer,
            },
        );
        CmdResult::Ok {
            sdp: None,
            duration_ms: None,
            play_id: None,
            recording_id: Some(recording_id),
            to_tag: None,
            stats: None,
        }
    }

    /// Stop a room recording ([`Command::ConferenceStopRecording`]).
    pub(super) async fn conference_stop_recording(
        &self,
        conference_id: &str,
        recording_id: Option<&str>,
    ) -> CmdResult {
        match recording_id {
            Some(recording_id) => {
                if !self.recordings.contains_key(recording_id) {
                    return error_result(
                        "conference_stop_recording",
                        &format!("no recording {recording_id} is running on this conference"),
                    );
                }
                self.stop_wav_recording(recording_id, RecordingEndReason::Stopped)
                    .await;
            }
            None => {
                self.stop_wav_recordings_for_call(conference_id, RecordingEndReason::Stopped)
                    .await;
            }
        }
        ok_empty()
    }
}

/// Map a control-plane [`ConferenceRole`] to the conference's internal [`Routing`]. A whisperer stays
/// a talker whose audio is private to one target; a monitor is a listener that hears one target
/// directly (and may also whisper to it).
fn routing_of(role: ConferenceRole) -> Routing {
    match role {
        ConferenceRole::Talker => Routing {
            role: Role::Talker,
            whisper_target: None,
            monitor_target: None,
        },
        ConferenceRole::Listener => Routing {
            role: Role::Listener,
            whisper_target: None,
            monitor_target: None,
        },
        ConferenceRole::Muted => Routing {
            role: Role::Muted,
            whisper_target: None,
            monitor_target: None,
        },
        ConferenceRole::Whisper { target } => Routing {
            role: Role::Talker,
            whisper_target: Some(target),
            monitor_target: None,
        },
        ConferenceRole::Monitor {
            target,
            whisper_target,
        } => Routing {
            role: Role::Listener,
            whisper_target,
            monitor_target: Some(target),
        },
    }
}
