//! The `answer_local` verb: the engine answers a single-leg offer itself (IVR, echo, announcement).

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{AddressFamily, Datapath, IceAgentMode, IceConfig, SourceFilter};
use siphon_rtp_dtls::{DtlsRole, Fingerprint as DtlsFingerprint};
use siphon_rtp_proto::{CmdResult, ProfileFlags};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use std::collections::HashSet;
use std::sync::Arc;

use crate::dtls_bridge::DtlsCallPlan;
use crate::ice;
use crate::media_pipeline::MediaControl;
use crate::sdp::{self, EngineMedia, IceRewrite, SecurityAdvertisement, TextRewrite};

use super::negotiate::{
    bridge_source_filter, filter_component, ice_directive, ice_tie_breaker, parse_codec_flags,
    peer_ice_credentials, resolve_rtcp_mux, IceDirective,
};
use super::takeover::{ws_takeover_media_address, WsBridgeSetup, WsVadConfig};
use super::{
    error_result, ok_sdp, Call, CallerMediaLeg, ClientId, Engine, Leg, PipelineKind, PromoteMode,
    PromotionReason,
};

/// What bridging a single-leg answer to a WebSocket server reads: the negotiated codec and SDP,
/// the caller's keying and ICE, and the endpoint the answer advertised.
struct LocalTakeover<'a> {
    call_id: &'a str,
    ws_uri: String,
    chosen: CodecSpec,
    offerer_security: &'a WsTakeoverSecurity,
    near_local_crypto: Option<CryptoAttribute>,
    ice_config: Option<IceConfig>,
    info: &'a sdp::MediaInfo,
    profile: &'a ProfileFlags,
    near_rtp: siphon_rtp_datapath::Endpoint,
    peer_ice: &'a Option<ice::IceCredentials>,
    ice_candidates: &'a [siphon_rtp_ice::Candidate],
    answer_sdp: String,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Record the half-built call before selecting the codec, so the reject path exercises the same
    /// teardown as a live call (frees the ports + releases the client quota). `to_tag: None` — there
    /// is no far leg. `near_codec` is set to the chosen codec below, right before promotion.
    #[allow(clippy::too_many_arguments)]
    fn register_local_call(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: String,
        near_rtp: siphon_rtp_datapath::Endpoint,
        near_rtcp: Option<siphon_rtp_datapath::Endpoint>,
        near_advertised: std::net::IpAddr,
        info: &sdp::MediaInfo,
        profile: &ProfileFlags,
    ) {
        *self.client_calls.entry(client).or_insert(0) += 1;
        for endpoint in [Some(near_rtp), near_rtcp].into_iter().flatten() {
            self.endpoint_calls.insert(endpoint.id, call_id.to_string());
        }
        self.calls.insert(
            call_id.to_string(),
            Call {
                owner: client,
                created_tick: self.datapath.now_ticks(),
                started_at_unix_ms: super::unix_time_ms(),
                ice: None,
                // A single-leg local answer mints no ICE of its own, so there is no pair to keep
                // consent on either side.
                near_remote_ice: None,
                far_remote_ice: None,
                near_remote_candidates: Vec::new(),
                near_peer_is_lite: false,
                far_local_candidates: Vec::new(),
                near_local_candidates: Vec::new(),
                // No far leg to take ICE off.
                far_ice_removed: false,
                from_tag,
                to_tag: None,
                near: Leg {
                    rtp: near_rtp,
                    rtcp: near_rtcp,
                    remote_rtp: Some(info.remote_rtp),
                    remote_rtcp: Some(info.remote_rtcp),
                    advertised_ip: near_advertised,
                    // A single-leg local answer relays no text stream.
                    text: None,
                    text_remote_rtp: None,
                },
                // No B-facing leg, and never will be: this verb *is* the answer (see the allocation
                // comment above). `answer` refuses to run on such a call rather than inventing one.
                far: None,
                caller_media_leg: CallerMediaLeg::Near,
                far_local_crypto: None,
                far_remote_crypto: None,
                far_dtls: false,
                far_dtls_role: None,
                far_downgraded_to_plain: false,
                // Recorded for symmetry; a single-leg call never reaches `answer`.
                near_secure: info.secure,
                // A single-leg call's keying lives on the takeover leg, not on the two-party pair.
                near_local_crypto: None,
                near_remote_crypto: None,
                near_codec: None,
                // A single-leg local answer never reaches `answer`, so the offered set is unused.
                near_offered_codecs: Vec::new(),
                near_codec_withheld: false,
                far_codec: None,
                // The caller's own direction. A single-leg call has no second party, so the far default
                // never contributes — `legs_expected_to_send` only walks a far leg that exists.
                near_direction: info.direction,
                far_direction: sdp::MediaDirection::default(),
                near_telephone_event: info.telephone_event_payload_type(),
                far_telephone_event: None,
                pipeline: PipelineKind::Passthrough,
                relay_flows: Vec::new(),
                promotion_reasons: HashSet::new(),
                offer_received_from: profile.received_from,
                // No far party, so no far hint and no re-offer from one.
                far_received_from: None,
                pending_far_reoffer: None,
                // Set below once the answered codec is known (a single-leg local answer negotiates CN
                // at the chosen codec's clock rate); left `None` for the reject path.
                comfort_noise_payload_type: None,
                text_t140_payload_type: None,
                text_red_payload_type: None,
                // A single-leg local answer negotiates no text stream.
                text_relay_flows: Vec::new(),
                text_promotion_reasons: HashSet::new(),
                text_events: false,
                text_secure: false,
                near_text_remote_crypto: None,
                far_text_local_crypto: None,
                near_text_local_crypto: None,
            },
        );
    }

    /// WebSocket bridge (mod_audio_stream / voice-AI) on a single-leg answer — the same
    /// `ProfileFlags::ws_uri` takeover `offer` honours, and the shape the voice-AI feature actually
    /// wants: "the AI answers the call". `answer_local` already means *the engine is the far side*,
    /// so `ws_uri` simply replaces the locally-generated far side (prompt / echo) with the WS server.
    /// There is no leg B to reconcile, no `to_tag`, and no ordering question about which side arrives
    /// first — and the answer above already picked exactly ONE encodable codec, so the L16 bridge
    /// format is unambiguous here in a way it is not on the offer path.
    ///
    /// It bridges the call's only endpoint, which is also the one this answer advertised — the same
    /// rule `offer` follows ("bridge what the peer was told to send to") and the same endpoint
    /// `promote_to_processing`'s single-leg branch reflects on.
    ///
    /// A dial failure fails the command: returning `ok` while the requested bridge is not up would
    /// connect a caller to nothing and give the controller no way to notice, so it is torn down and
    /// reported exactly like `no-encodable-codec` (the controller renders a real SIP failure).
    async fn answer_local_takeover(&self, takeover: LocalTakeover<'_>) -> CmdResult {
        let LocalTakeover {
            call_id,
            ws_uri,
            chosen,
            offerer_security,
            near_local_crypto,
            ice_config,
            info,
            profile,
            near_rtp,
            peer_ice,
            ice_candidates,
            answer_sdp,
        } = takeover;
        // Record the negotiated ingress codec + the takeover pipeline before the bridge is built.
        // `far_codec` stays `None`: the WS server is the far side and it speaks L16, not an RTP
        // codec — a `far_codec` here would claim a far RTP party that does not exist (`offer`'s WS
        // arm records the same shape).
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.near_codec = Some(chosen.clone());
            call.pipeline = PipelineKind::Ws;
        }
        // The takeover leg's SRTP state (RFC 3711). SDES is keyed right here — the answer above
        // carries the engine's own key and the offer carried the peer's, so both halves are known
        // synchronously. DTLS starts **unkeyed**: the RFC 5764 handshake only completes after this
        // command has returned, and until it does the registry drops ingress *and* refuses egress
        // rather than emitting anything in the clear.
        let secure = match offerer_security {
            WsTakeoverSecurity::Plain => None,
            WsTakeoverSecurity::Sdes { peer_key } => {
                // Key direction (RFC 4568 / `SecureLeg::new`): encrypt egress with the key this
                // answer advertised, decrypt ingress with the key the offer carried.
                let Some(local) = near_local_crypto else {
                    self.teardown_call(call_id).await;
                    return error_result(
                        "ws bridge",
                        &"ws-takeover-unkeyable: no engine SDES key was minted (internal)",
                    );
                };
                Some(Arc::new(crate::ws_bridge::WsSecureLeg::keyed(
                    SecureLeg::new(&local.key, &peer_key.key),
                )))
            }
            WsTakeoverSecurity::Dtls { .. } => {
                Some(Arc::new(crate::ws_bridge::WsSecureLeg::pending()))
            }
        };
        // An ICE takeover leg starts with the source gate OPEN, because a connectivity check
        // legitimately arrives from a peer-reflexive transport the SDP never carried (RFC 8445
        // §7.3.1.3) — safe only because `ice_pending` drops **all** media until the agent selects,
        // at which point the gate narrows to the selected pair.
        let ice_pending = ice_config.is_some();
        // Aim the downlink at the caller's `received-from` public IP when the control supplied
        // one, and gate its ingress on the same address — identical to the offer path.
        let a_media = ws_takeover_media_address(info.remote_rtp, profile.received_from);
        let accepted_source = if ice_pending {
            SourceFilter::Any
        } else {
            bridge_source_filter(profile, a_media)
        };
        if let Err(reason) = self
            .setup_ws_bridge(WsBridgeSetup {
                call_id,
                ws_uri: &ws_uri,
                endpoint_a: near_rtp.id,
                a_rtp: a_media,
                codec: Some(&chosen),
                accepted_source,
                ice_pending,
                secure,
                noise_suppression: profile.noise_suppression,
                echo: crate::media_pipeline::EchoProfile::from_profile(profile),
                vad_config: WsVadConfig::from_profile(profile),
                wire_sample_rate: profile.ws_sample_rate,
                // Negotiation-time: a fresh egress watch, and no relay displaced (there is none
                // yet) — so there is nothing for a detach to put back either.
                egress: None,
                takeover: None,
                socket: None,
            })
            .await
        {
            self.teardown_call(call_id).await;
            return error_result("ws bridge", &reason);
        }
        // Arm the full RFC 8445 agent on the takeover endpoint. `ForwardOnly`: the agent owns
        // request handling (the §7.3.1.1 role conflict, §7.3.1.3 peer-reflexive discovery and
        // §7.3.1.5 nomination all need state the datapath does not have), so the datapath answers
        // nothing here. Done after the bridge is registered so a selection always finds its route.
        if let Some(config) = ice_config {
            // Both checked before any allocation, so this cannot fail here.
            let (Some(agents), Some(peer)) = (self.ice_agents.clone(), peer_ice.clone()) else {
                self.teardown_call(call_id).await;
                return error_result(
                    "ws bridge",
                    &"ws-takeover-ice-unsupported: no ICE agent available (internal)",
                );
            };
            let agent_config = siphon_rtp_ice::agent::AgentConfig::new(
                siphon_rtp_ice::agent::Credentials::new(
                    config.local_ufrag.clone(),
                    config.local_pwd.clone(),
                ),
                siphon_rtp_ice::agent::Credentials::new(peer.ufrag.clone(), peer.pwd.clone()),
                // RFC 8445 §6.1.1: the offerer controls — unless it is a lite agent, which never can.
                info.ice_lite,
                ice_tie_breaker(),
            )
            .with_candidates(
                filter_component(ice_candidates, 1),
                filter_component(&info.candidates, 1),
            );
            self.datapath.set_ice_agent(
                near_rtp.id,
                config,
                IceAgentMode::ForwardOnly,
                agents.events(),
            );
            agents.register(near_rtp.id, call_id, near_rtp.local_addr, agent_config, 0);
        }
        // A DTLS-SRTP takeover leg needs the handshake in front of its endpoint: the bridge keeps
        // the RFC 7983 demux (DTLS records drive the handshake, media is forwarded on) and hands
        // the derived key to the WS leg, which is the single owner of the crypto — the same shape
        // a DTLS conference seat and a `DtlsMedia` call use. Registered last so the WS route
        // exists before any packet can be released to it.
        if let WsTakeoverSecurity::Dtls {
            peer_fingerprint,
            peer_setup,
        } = offerer_security
        {
            let Some(certificate) = self.dtls_certificate.clone() else {
                self.teardown_call(call_id).await;
                return error_result(
                    "ws bridge",
                    &"ws-takeover-unkeyable: engine has no DTLS certificate",
                );
            };
            // The offerer picks; the engine takes the complement (RFC 5763 §5) — matching the
            // `a=setup` this answer advertised.
            let role = match peer_setup {
                Some(sdp::Setup::Active) => DtlsRole::Server,
                _ => DtlsRole::Client,
            };
            self.dtls_bridge().register_for_pipeline(
                DtlsCallPlan {
                    // A takeover leg is one muxed endpoint; the "plain" side is unused in pipeline
                    // mode (the WS bridge owns egress), so it mirrors the secure one.
                    plain_endpoint: near_rtp.id,
                    plain_source: accepted_source,
                    plain_dst: info.remote_rtp,
                    secure_endpoint: near_rtp.id,
                    secure_source: accepted_source,
                    secure_dst: info.remote_rtp,
                    secure_local: near_rtp.local_addr,
                    certificate,
                    role,
                    peer_fingerprint: DtlsFingerprint::new(
                        peer_fingerprint.hash_function.clone(),
                        peer_fingerprint.bytes.clone(),
                    ),
                    // RFC 8445 §12: key the pair ICE chose, but only when an agent is actually
                    // running — otherwise no selection is coming and the handshake would hang.
                    gate_on_ice: ice_pending,
                    plain_rtcp: None,
                },
                crate::dtls_bridge::PipelineTarget::Ws {
                    ws: self.ws.clone(),
                    call_id: call_id.to_string(),
                },
            );
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            offerer = %info.remote_rtp,
            codec = %chosen.encoding_name,
            role = "uas_local_ws",
            "websocket bridge attached to the single-leg answer"
        );
        // Deliberately no RFC 3389 comfort noise on this path: CN egress is generated by the
        // promoted media actor, which a takeover call does not have. Advertising CN the bridge can
        // never send would be an answer the media path cannot back, so the answer stays silent
        // about it (`force_answer_codec` already dropped it from the m-line).
        ok_sdp(answer_sdp, None)
    }

    /// Key the single-leg pipeline for a secure offerer. The answer above already advertises the
    /// engine's own SDES key or DTLS fingerprint — that part was always correct — and until now it
    /// was the *media path* that had nothing behind it, which is why the verb refused a secure
    /// offerer outright rather than answering keying it could not honour.
    ///
    /// The single-leg shape is its own: both directions face the same caller on the same endpoint,
    /// and the caller is the secure side, so each direction both decrypts what arrives and encrypts
    /// what leaves (`attach_near_secure_leg`). The two-leg method keys A-plaintext/B-secure and
    /// would leave an IVR that decrypted the caller and answered it in the clear.
    async fn key_local_pipeline(
        &self,
        call_id: &str,
        offerer_security: &WsTakeoverSecurity,
        near_local_crypto: Option<CryptoAttribute>,
    ) -> Option<CmdResult> {
        match offerer_security {
            WsTakeoverSecurity::Plain => {}
            WsTakeoverSecurity::Sdes { peer_key } => {
                // SDES is keyed synchronously: this answer carries the engine's key and the offer
                // carried the peer's, so both halves are known now (RFC 4568). Key direction per
                // `SecureLeg::new`: encrypt egress with ours, decrypt ingress with theirs.
                let Some(local) = near_local_crypto else {
                    self.teardown_call(call_id).await;
                    return Some(error_result(
                        "answer_local",
                        &"secure-offerer-unkeyable: no engine SDES key was minted (internal)",
                    ));
                };
                let leg = Arc::new(std::sync::Mutex::new(SecureLeg::new(
                    &local.key,
                    &peer_key.key,
                )));
                if !self
                    .media
                    .control(call_id, MediaControl::AttachNearSecureLeg { leg })
                {
                    self.teardown_call(call_id).await;
                    return Some(error_result(
                        "answer_local",
                        &"secure-offerer-unkeyable: media actor unavailable",
                    ));
                }
            }
            // DTLS-SRTP on the local pipeline is **not** done, and says so rather than answering a
            // fingerprint no media path backs. It needs two things this change does not build: the
            // full ICE agent attached to the promoted (Redirect) leg so the handshake can be gated on
            // the selected pair (RFC 8445 §12), and the `gate_on_ice` / pending-key plumbing that goes
            // with it. A WebRTC caller reaching an IVR is the case, and it is the second half of the
            // secure-offerer work.
            WsTakeoverSecurity::Dtls { .. } => {
                self.teardown_call(call_id).await;
                return Some(error_result(
                    "answer_local",
                    &"secure-offerer-unsupported: a DTLS-SRTP (WebRTC) offerer needs a WebSocket \
                      takeover (ws_uri); SDES-SRTP is terminated on the local pipeline",
                ));
            }
        }
        None
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Single-leg UAS answer ([`Command::AnswerLocal`]): the engine *is* the far side (IVR / echo /
    /// announcement). Given the offerer's SDP and **no** peer, it synthesises an RFC 3264 answer that
    /// advertises **one** audio codec chosen from the offer (plus the telephone-event PT), and engages
    /// the transcoder now so a later PCM prompt / echo encodes to the chosen codec — rather than
    /// waiting for an answer that never comes. When no offered codec is encodable in this build it
    /// tears the half-built session down and returns [`CmdResult::Error`] with reason
    /// `"no-encodable-codec"` (the controller renders SIP 488) — RFC 3264 §6.1: the answer selects only
    /// from the **offered** formats, never a codec the engine cannot produce.
    ///
    /// **One leg, not two.** Unlike [`Self::offer`], which binds a B-facing leg because a B side may
    /// still answer, this verb *is* the answer: there is no `to_tag`, no far party, and no second
    /// socket pair. The call holds only the caller-facing (`near`) leg — the socket this answer
    /// advertises, the source-gate anchor, the endpoint the single-leg pipeline reflects on, and the
    /// one leg its CDR reports. A later [`Self::answer`] on such a call is refused rather than served
    /// from an invented leg, and [`Command::Checkpoint`] likewise (there is no two-party state to
    /// replicate).
    ///
    /// Two profile flags therefore have nothing to act on here and are ignored: `address family`
    /// (which picks the *far* leg's family for v4↔v6 interworking — the answer must reach the caller,
    /// so it stays in the offer's family per RFC 4566 §5.7) and `direction[1]` (the far leg's named
    /// interface). `direction[0]` still selects the caller-facing interface, and the `rtcp-mux`
    /// directive is applied with its near-side meaning: this SDP is an *answer*, and RFC 5761 §5.1.1
    /// only mixes RTCP into the RTP port when both ends agreed.
    ///
    /// When the profile carries [`ProfileFlags::ws_uri`] the *far side is the WebSocket server* rather
    /// than the local prompt/echo pipeline: the engine dials it and bridges the caller's audio to it
    /// (the "AI answers the call" shape), exactly as [`Self::offer`] does for a 2-party call. The
    /// transcoder is not engaged in that mode — the bridge owns the leg — and a failed dial fails the
    /// command rather than answering `ok` with nothing attached.
    pub(super) async fn answer_local(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        // Soft per-client call quota — a new session, gated exactly like `offer` (A3 / DoS, docs §5).
        if self.client_call_count(client) >= self.max_calls_per_client {
            return CmdResult::Error {
                reason: "per-client call quota exceeded".to_string(),
            };
        }
        if let Err(reason) = crate::media_pipeline::validate_echo_delay_search_ms(profile) {
            return CmdResult::Error {
                reason: format!("answer_local: {reason}"),
            };
        }
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer_local SDP parse failed: {error}"),
                }
            }
        };

        // How the caller secured its own media (RFC 3711): SDES-SRTP (RFC 4568, `RTP/SAVP` +
        // `a=crypto`) or DTLS-SRTP (RFC 5764, `UDP/TLS/RTP/SAVP[F]` + `a=fingerprint`). This verb is
        // the only one that can answer a secure offerer, because it *writes A's answer itself* —
        // `offer`/`answer` derive A's answer from B's SDP and so have nowhere to put the engine's own
        // keying (see the guard at the top of `offer`).
        //
        // A secure offerer is supported only in **takeover** mode (`ws_uri`), where the WS server is
        // A's far side and the SRTP terminates on the bridge's own leg. The plaintext single-leg IVR /
        // echo pipeline has no `SecureLeg`, so a secure offer there is refused rather than answered
        // with keying nothing backs (which is what it used to do: it echoed A's own `a=crypto` /
        // `a=fingerprint` straight back).
        let takeover = profile.ws_uri.is_some();
        let offerer_security = match resolve_offerer_security(&info) {
            Ok(security) => security,
            Err(reason) => return CmdResult::Error { reason },
        };
        // ICE on a takeover leg (RFC 8445). The bridge's drain task owns this leg's egress, so a
        // selection has to reach the registry as well as the datapath — `WsRegistry::ice_selected`,
        // driven from `drive_ice_agents`, exactly as a conference seat is.
        //
        // RFC 8839 §5.3: an offer whose default destination matches none of its own candidates was
        // rewritten in transit, so ICE describes a topology the media no longer follows; fall back to
        // the signalled address instead of negotiating ICE we cannot trust.
        let ice_mismatch = siphon_rtp_ice::is_ice_mismatch(info.remote_rtp, &info.candidates)
            && ice_directive(profile) != Some(IceDirective::Force);
        // Still gated on `takeover`, deliberately. An ICE agent is attached only on the takeover arm,
        // so un-gating this would re-originate ICE credentials on a local leg that runs no agent —
        // half a fix, and the half that hides the other. The full ICE agent on the promoted
        // (`Redirect`) local leg is the same missing piece DTLS-SRTP needs; both land together.
        let want_ice = takeover
            && match ice_directive(profile) {
                _ if ice_mismatch => false,
                Some(IceDirective::Force) => true,
                Some(IceDirective::Remove) => false,
                None => info.is_ice(),
            };
        // A takeover leg runs ICE only as a **full** RFC 8445 agent. The ice-lite responder adopts the
        // validated source into the datapath's own latch, which gates a `Forward` rule — and a
        // takeover leg is `Redirect`, so that gate never runs and the bridge's egress would keep going
        // to the signalled `c=`. Rather than ship a leg that is open at layer 2 and deaf at layer 4,
        // refuse: the controller learns it before it commits to the dialog.
        let peer_ice = peer_ice_credentials(&info);
        if want_ice {
            if self.ice_agents.is_none() {
                return CmdResult::Error {
                    reason: "ws-takeover-ice-unsupported: an ICE offerer needs the full RFC 8445 \
                             agent for a WebSocket takeover (start the engine with --ice-full)"
                        .to_string(),
                };
            }
            if peer_ice.is_none() || info.candidates.is_empty() {
                return CmdResult::Error {
                    reason: "ws-takeover-ice-unsupported: the ICE offer carries no usable \
                             credentials or candidates, so no agent can run on the takeover leg"
                        .to_string(),
                };
            }
        }

        // ONE leg, not two. `offer` allocates a near *and* a far because a B side may still answer it;
        // this verb knows from the start that none is coming, so it binds only the socket pair the
        // caller is told about. That leg is `near`, the caller-facing side by the same convention
        // `answer` follows (its SDP goes to A and advertises `near`), and it holds both halves of the
        // one party: the caller's signalled address — the source-gate / reflect target — and the socket
        // the caller sends to. Binding a second, never-advertised pair would idle two ports (four
        // unmuxed) per IVR / announcement / echo / voice-AI call for a leg no packet can ever reach.
        let near_family = AddressFamily::of(info.remote_rtp.ip());
        let (near_mux, _) = resolve_rtcp_mux(info.rtcp_mux, &profile.rtcp_mux);
        let near_per_leg = if near_mux { 1 } else { 2 };
        // `direction[0]` names the caller-facing interface, exactly as it does on a 2-leg call; the
        // second slot has no leg to select here and is ignored.
        let (near_interface, _) = self.interfaces.resolve_direction(&profile.direction);
        let (near_bind, near_advertised_override) = Self::leg_binding(near_interface, near_family);
        let near_endpoints = match self
            .alloc_endpoints(near_per_leg, near_family, near_bind)
            .await
        {
            Ok(endpoints) => endpoints,
            Err(reason) => return CmdResult::Error { reason },
        };
        let near_rtp = near_endpoints[0];
        let near_rtcp = (!near_mux).then(|| near_endpoints[1]);
        let near_advertised = near_advertised_override.unwrap_or_else(|| near_rtp.local_addr.ip());
        let endpoints: Vec<_> = near_endpoints.to_vec();

        // The answer goes back to the offerer and advertises the leg it was allocated for — the socket
        // the caller sends to, and the one the single-leg pipeline listens on.
        let engine = EngineMedia {
            rtp: near_rtp.local_addr,
            rtcp: near_rtcp.map(|endpoint| endpoint.local_addr),
            advertised_ip: near_advertised,
        };
        let mux_override = (!profile.rtcp_mux.is_empty()).then_some(near_mux);
        // The engine's own keying for a secure takeover leg — its SDES key (RFC 4568) or its
        // certificate fingerprint plus the complement of the offerer's `a=setup` (RFC 5763 §5). The
        // SDES key is kept so the `SecureLeg` below encrypts egress with exactly the key this answer
        // told the peer to decrypt with.
        let (security, near_local_crypto) = match &offerer_security {
            WsTakeoverSecurity::Plain => (None, None),
            WsTakeoverSecurity::Sdes { .. } => {
                match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                    Ok(local) => (Some(SecurityAdvertisement::Secure(local)), Some(local)),
                    Err(error) => {
                        self.free(&endpoints).await;
                        return error_result("answer_local: generate SDES key", &error);
                    }
                }
            }
            WsTakeoverSecurity::Dtls { peer_setup, .. } => {
                let Some(certificate) = self.dtls_certificate.as_ref() else {
                    self.free(&endpoints).await;
                    return error_result(
                        "answer_local",
                        &"ws-takeover-unkeyable: engine has no DTLS certificate",
                    );
                };
                // RFC 5763 §5: the answerer takes the role opposite the offerer's — an `active`
                // offerer makes the engine passive (the DTLS server), anything else makes it active.
                let setup = match peer_setup {
                    Some(sdp::Setup::Active) => sdp::Setup::Passive,
                    _ => sdp::Setup::Active,
                };
                let fingerprint = certificate.fingerprint();
                (
                    Some(SecurityAdvertisement::Dtls {
                        fingerprint: sdp::Fingerprint {
                            hash_function: fingerprint.hash_function,
                            bytes: fingerprint.bytes,
                        },
                        setup,
                    }),
                    None,
                )
            }
        };
        // ICE (RFC 8839 §5): re-originate with the engine's own credentials and gathered candidates
        // when the takeover leg runs an agent. The answer *is* the candidate list — there is no second
        // chance without trickle (RFC 8445 §5.1.1) — so gather before it is written. Anything else
        // passes the peer's ICE through untouched, exactly as before.
        let ice_credentials = if want_ice {
            match ice::generate_credentials() {
                Some(credentials) => Some(credentials),
                None => {
                    self.free(&endpoints).await;
                    return error_result(
                        "answer_local",
                        &"could not mint ICE credentials (OS RNG unavailable)",
                    );
                }
            }
        } else {
            None
        };
        let (ice_candidates, ice_config) = match ice_credentials.as_ref() {
            Some(credentials) => {
                let config = IceConfig {
                    local_ufrag: credentials.ufrag.clone(),
                    local_pwd: credentials.pwd.clone(),
                };
                let leg = Leg {
                    rtp: near_rtp,
                    rtcp: near_rtcp,
                    remote_rtp: None,
                    remote_rtcp: None,
                    advertised_ip: near_advertised,
                    text: None,
                    text_remote_rtp: None,
                };
                let candidates = self.gather_leg_candidates(&leg, &config).await;
                (candidates, Some(config))
            }
            None => (Vec::new(), None),
        };
        // The `Mismatch` / `Strip` arms are scoped to a takeover deliberately. A takeover leg is the
        // only single-leg shape whose ICE this verb decides; the plaintext IVR / echo / announcement
        // path keeps its pre-existing `Keep` behaviour byte for byte. (That path has its own, separate,
        // pre-existing gap — it echoes an ICE offerer's credentials back and runs no agent — which is
        // out of scope here; widening the ICE rewrite would half-fix it and hide it.)
        let ice_rewrite = match ice_credentials.as_ref() {
            Some(credentials) => IceRewrite::Reoriginate(sdp::IceAdvertisement {
                ufrag: credentials.ufrag.as_str(),
                pwd: credentials.pwd.as_str(),
                candidates: &ice_candidates,
            }),
            // RFC 8839 §5.3: say why ICE is absent rather than dropping it silently, so the offerer
            // stops waiting for checks that will never come.
            None if takeover && ice_mismatch => IceRewrite::Mismatch,
            // `ICE=remove` on a takeover: the leg runs on the signalled address, so the peer's ICE is
            // stripped rather than echoed back at it (the same thing `offer` does for this directive).
            None if takeover && ice_directive(profile) == Some(IceDirective::Remove) => {
                IceRewrite::Strip
            }
            None => IceRewrite::Keep,
        };
        let mut rewritten =
            // A single-leg local answer (IVR/echo) does not relay a text stream — leave any `m=text`
            // section untouched (text anchoring/relay is a 2-leg concern; PR 1 scope).
            match sdp::rewrite(
                sdp,
                engine,
                ice_rewrite,
                security,
                mux_override,
                TextRewrite::None,
            ) {
                Ok(rewritten) => rewritten,
                Err(error) => {
                    self.free(&endpoints).await;
                    return CmdResult::Error {
                        reason: format!("answer_local SDP rewrite failed: {error}"),
                    };
                }
            };
        // rtpengine `replace: [origin]`: hide the originator's real IP behind the engine's advertised
        // address (topology hiding).
        if profile.replace.iter().any(|field| field == "origin") {
            rewritten.sdp = sdp::rewrite_origin(&rewritten.sdp, engine.advertised_ip);
        }

        self.register_local_call(
            client,
            call_id,
            from_tag,
            near_rtp,
            near_rtcp,
            near_advertised,
            &info,
            profile,
        );

        // Pick the ONE negotiated codec (RFC 3264 §6.1). The candidate set is the offerer's own
        // offered audio codecs, in offer order, edited by the profile's codec policy with answer-side
        // semantics; the winner is the first candidate this build can actually *encode*
        // (`factory::encoder_for` is the single source of truth — G.711/G.722/G.726/GSM always,
        // AMR-WB/AMR only under the `amr` build feature).
        let policy = parse_codec_flags(&profile.flags);
        let candidates = answer_codec_candidates(&info, &policy);
        let Some(chosen) = candidates
            .into_iter()
            .find(|spec| factory::encoder_for(spec).is_ok())
        else {
            // No offered codec is encodable in this build — tear the half-built session down and let
            // the controller render SIP 488. The reason string is matched on by the SIPhon side.
            self.teardown_call(call_id).await;
            return CmdResult::Error {
                reason: "no-encodable-codec".to_string(),
            };
        };

        // Media-plane lifecycle: a single-leg UAS answer (IVR / echo / announcement) — the engine *is*
        // the far side, so there is no peer and no far codec to negotiate; it answers with the one
        // codec it picked from the offer and transcodes prompt/echo into it. Correlated by `call_id`.
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            offerer = %info.remote_rtp,
            codec = %chosen.encoding_name,
            role = "uas_local",
            "call created"
        );

        // Narrow the answer's `m=audio` to the single chosen codec (+ telephone-event) on the already
        // rewritten address (RFC 3264 §6.1 — the answer offers exactly one format back).
        let mut answer_sdp =
            sdp::force_answer_codec(&rewritten.sdp, &chosen, info.telephone_event_payload_type());

        if let Some(ws_uri) = profile.ws_uri.clone() {
            return self
                .answer_local_takeover(LocalTakeover {
                    call_id,
                    ws_uri,
                    chosen,
                    offerer_security: &offerer_security,
                    near_local_crypto,
                    ice_config,
                    info: &info,
                    profile,
                    near_rtp,
                    peer_ice: &peer_ice,
                    ice_candidates: &ice_candidates,
                    answer_sdp,
                })
                .await;
        }

        // When the caller offered RFC 3389 comfort noise at the chosen codec's clock rate, negotiate it
        // back so the single-leg leg can send real CN packets during idle gaps (the caller renders
        // them) rather than looping the caller's audio back (self-echo). No match ⇒ the idle egress
        // falls back to audio-encoded low-level comfort noise on the chosen codec.
        let comfort_noise_payload_type = info.comfort_noise_payload_type(chosen.clock_rate_hz);
        if let Some(cn_pt) = comfort_noise_payload_type {
            answer_sdp = sdp::add_comfort_noise(&answer_sdp, cn_pt, chosen.clock_rate_hz);
        }

        // Engage the transcoder now (single-leg, no far side). After this answer the offerer sends the
        // chosen codec, so set `near_codec = chosen` *before* promoting: `promote_to_processing`'s
        // single-leg branch (far_codec == None) uses `near_codec` for both decode and encode, yielding
        // a processing pipeline that decodes the caller's chosen codec and re-encodes prompt/echo PCM
        // back into it. The negotiated CN payload type rides along so the promote wires comfort-idle.
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.near_codec = Some(chosen.clone());
            call.comfort_noise_payload_type = comfort_noise_payload_type;
        }
        if let Err(reason) = self
            .hold_in_userspace(call_id, PromotionReason::MediaOp, PromoteMode::Processing)
            .await
        {
            self.teardown_call(call_id).await;
            return error_result("answer_local: engage transcoder", &reason);
        }
        // Record the chosen egress codec + the promoted pipeline for observability. Promotion already
        // set `pipeline = Media`; `far_codec` mirrors `near_codec` for a single-leg IVR (encode == the
        // codec the caller will send).
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.far_codec = Some(chosen);
            call.pipeline = PipelineKind::Media;
        }

        if let Some(refusal) = self
            .key_local_pipeline(call_id, &offerer_security, near_local_crypto)
            .await
        {
            return refusal;
        }

        ok_sdp(answer_sdp, None)
    }
}

/// The ordered candidate audio codecs a single-leg [`Command::AnswerLocal`] may answer with, derived
/// from the offer and edited by the profile's [`sdp::CodecPolicy`] with **answer-side** semantics
/// (RFC 3264 §6.1 — the answer may select only from the formats the offer contained, so nothing is
/// ever injected). The caller then takes the first candidate this build can *encode*.
///
/// - `strip` / `mask` / `consume-X` (`policy.remove`) — remove X from the candidate set.
/// - `except` / `accept-X` (`policy.keep`) — a keep-list: when non-empty, only the kept codecs survive.
/// - `offer-X` (`policy.order`) — priority ordering: listed codecs float to the front, in flag order.
/// - `transcode-X` (`policy.add`) — a *preference* among the offered codecs (a candidate whose encoding
///   name matches an `add` entry floats forward). It never injects a codec the caller did not offer.
///
/// The two float operations are a single stable sort (offer order is preserved among equals), with the
/// explicit `offer` ordering taking precedence over the `transcode` preference.
fn answer_codec_candidates(info: &sdp::MediaInfo, policy: &sdp::CodecPolicy) -> Vec<CodecSpec> {
    // The offerer's own audio codecs, in offer order, telephone-event already excluded.
    let mut candidates = info.audio_codecs();
    // `strip`/`mask`/`consume-X`: drop the named codec from the answer candidate set.
    if !policy.remove.is_empty() {
        candidates.retain(|spec| !policy.remove.contains(&spec.encoding_name));
    }
    // `except`/`accept-X`: a keep-list — when present, only these codecs may be answered with.
    if !policy.keep.is_empty() {
        candidates.retain(|spec| policy.keep.contains(&spec.encoding_name));
    }
    // `offer`-order (primary) then `transcode`-preference (secondary): float preferred codecs to the
    // front without dropping any — a stable sort keeps the offered order among equal keys.
    candidates.sort_by_key(|spec| {
        let order_rank = policy
            .order
            .iter()
            .position(|name| name == &spec.encoding_name)
            .unwrap_or(usize::MAX);
        let add_rank = usize::from(
            !policy
                .add
                .iter()
                .any(|added| added.encoding_name == spec.encoding_name),
        );
        (order_rank, add_rank)
    });
    candidates
}

/// How the **offerer's own** media is secured on a WebSocket-takeover leg, resolved from its SDP.
///
/// A takeover call has no leg B — the WS server is A's far side — so the engine is A's cryptographic
/// peer and must terminate whatever A negotiated (RFC 3711). This is the offerer's posture, not the
/// `transport_protocol` far-leg posture the two-leg verbs resolve.
#[derive(Debug, Clone)]
pub(super) enum WsTakeoverSecurity {
    /// Plaintext `RTP/AVP` — no SRTP on the leg.
    Plain,
    /// SDES-SRTP (RFC 4568, `RTP/SAVP` + `a=crypto`): the peer's key, ready to pair with the engine's
    /// own once the answer mints it. Keyed synchronously.
    Sdes { peer_key: CryptoAttribute },
    /// DTLS-SRTP (RFC 5764, `UDP/TLS/RTP/SAVP[F]`): keyed only when the handshake completes, so the
    /// leg starts unkeyed. `peer_setup` decides the engine's own role (RFC 5763 §5).
    Dtls {
        peer_fingerprint: sdp::Fingerprint,
        peer_setup: Option<sdp::Setup>,
    },
}

/// Resolve a single-leg offerer's security posture, refusing every shape the engine cannot actually
/// terminate rather than accepting it and bridging nothing.
///
/// It no longer takes `takeover`. A secure offerer without one used to be refused here, because the
/// single-leg local pipeline carried no `SecureLeg` — it now terminates SDES-SRTP on one, exactly as
/// a conference seat and a takeover leg already did, so the posture is the same question whichever
/// media path will consume it. Which paths can *honour* a resolved posture is the caller's business,
/// and `answer_local` still refuses a DTLS offerer without a takeover for want of an ICE agent on the
/// promoted leg.
///
/// The reason strings lead with a stable token (`ws-takeover-unkeyable`) so a controller can branch
/// on the failure without parsing prose.
pub(super) fn resolve_offerer_security(
    info: &sdp::MediaInfo,
) -> Result<WsTakeoverSecurity, String> {
    if !info.secure {
        return Ok(WsTakeoverSecurity::Plain);
    }
    if info.dtls {
        // RFC 5763 §5: without the peer's certificate fingerprint the handshake cannot be bound to
        // the signalling, so there is nothing to authenticate the DTLS peer against.
        let Some(peer_fingerprint) = info.fingerprint.clone() else {
            return Err(
                "answer_local: ws-takeover-unkeyable: UDP/TLS/RTP/SAVPF offer without an \
                 a=fingerprint"
                    .to_string(),
            );
        };
        return Ok(WsTakeoverSecurity::Dtls {
            peer_fingerprint,
            peer_setup: info.setup,
        });
    }
    // RFC 4568: a secure `RTP/SAVP` offer with no usable `a=crypto` cannot key the inbound context,
    // and downgrading it to plaintext is never an option (docs/security-and-nat.md layer 5).
    let Some(peer_key) = info.crypto.first().copied() else {
        return Err(
            "answer_local: ws-takeover-unkeyable: RTP/SAVP offer without a usable a=crypto"
                .to_string(),
        );
    };
    Ok(WsTakeoverSecurity::Sdes { peer_key })
}
