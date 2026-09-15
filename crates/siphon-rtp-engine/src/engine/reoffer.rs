//! The `reoffer` verb: renegotiate a live call on its existing ports (RFC 3264 §8), restarting ICE
//! when the peer's credentials change (RFC 8445 §9).

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{Datapath, IceAgentMode, IceConfig};
use siphon_rtp_proto::{CmdResult, ProfileFlags};
use siphon_rtp_srtp::sdes::CryptoAttribute;
use std::net::SocketAddr;

use crate::ice::{self, IceCredentials};
use crate::sdp::{self, TextRewrite};

use super::negotiate::{
    answer_ice_rewrite, dtls_directive, far_security, filter_component, ice_directive,
    ice_tie_breaker, near_security, offer_ice_rewrite, offered_dtls_setup, parse_codec_flags,
    peer_ice_credentials, present_leg, same_codec, CodecPresentation, IceDirective,
    LegPresentation,
};
use super::{error_result, ok_sdp, unknown_call, Call, ClientId, Engine, Leg, Party, PipelineKind};

/// What a re-offer needs from its call, copied out from under the registry guard: which party is
/// re-offering, both legs, and everything either leg has already been presented with — a re-offer
/// re-presents a leg, it never re-decides it.
struct ReofferState {
    /// The re-offering party.
    party: Party,
    near: Leg,
    far: Option<Leg>,
    /// The engine's current ICE credentials (one set for both legs).
    ice: Option<IceCredentials>,
    /// The re-offering party's ICE credentials as last signalled — a change is an ICE restart.
    previous_remote_ice: Option<IceCredentials>,
    /// The codec the re-offering party negotiated; a re-offer that no longer lists it is refused.
    previous_codec: Option<CodecSpec>,
    near_local_candidates: Vec<siphon_rtp_ice::Candidate>,
    far_local_candidates: Vec<siphon_rtp_ice::Candidate>,
    /// `ice: remove` took ICE off the far leg (RFC 8839 §4.2.5).
    far_ice_removed: bool,
    far_local_crypto: Option<CryptoAttribute>,
    /// The engine's own SDES key toward A, so a re-offer re-presents the key A already holds rather
    /// than minting a new one (RFC 4568 — a re-offer restates the session, it does not re-key it).
    near_local_crypto: Option<CryptoAttribute>,
    far_dtls: bool,
    far_downgraded_to_plain: bool,
    far_text_local_crypto: Option<CryptoAttribute>,
    near_text_local_crypto: Option<CryptoAttribute>,
    /// Whether the negotiated text stream is SDES-SRTP — presented secure on both legs or not at all.
    text_secure: bool,
    /// Whether B's answer accepted the text stream, so the near leg's text was presented anchored.
    text_relayed: bool,
    near_codec: Option<CodecSpec>,
    near_telephone_event: Option<u8>,
    /// Whether the call transcodes, so each party is presented only its own codec.
    transcoding: bool,
}

impl ReofferState {
    fn capture(call: &Call, party: Party) -> Self {
        let (previous_remote_ice, previous_codec) = match party {
            Party::Near => (call.near_remote_ice.clone(), call.near_codec.clone()),
            Party::Far => (call.far_remote_ice.clone(), call.far_codec.clone()),
        };
        Self {
            party,
            near: call.near,
            far: call.far,
            ice: call.ice.clone(),
            previous_remote_ice,
            previous_codec,
            near_local_candidates: call.near_local_candidates.clone(),
            far_local_candidates: call.far_local_candidates.clone(),
            far_ice_removed: call.far_ice_removed,
            far_local_crypto: call.far_local_crypto,
            near_local_crypto: call.near_local_crypto,
            far_dtls: call.far_dtls,
            far_downgraded_to_plain: call.far_downgraded_to_plain,
            far_text_local_crypto: call.far_text_local_crypto,
            near_text_local_crypto: call.near_text_local_crypto,
            text_secure: call.text_secure,
            text_relayed: call.far.is_some_and(|far| far.text_remote_rtp.is_some()),
            near_codec: call.near_codec.clone(),
            near_telephone_event: call.near_telephone_event,
            transcoding: matches!(
                call.pipeline,
                PipelineKind::Media | PipelineKind::SrtpMedia | PipelineKind::DtlsMedia
            ),
        }
    }
}

/// Why a re-offer from B cannot be taken on a secure far leg, or `None` when it keeps the leg keyed
/// the way it is keyed. The answer that completes the exchange re-presents the engine's own key or
/// fingerprint and re-keys the leg from B's SDP, so B must still offer something that answer can
/// select: an `RTP/SAVP` `a=crypto` in the negotiated suite for SDES (RFC 4568 §5.1.2 — the answer
/// keeps the chosen line's suite), a fingerprint for DTLS-SRTP (RFC 5763 §5). Anything else would
/// mean bridging B in the clear or presenting keying the engine does not hold — never silently
/// (docs/security-and-nat.md Layer 5).
fn far_reoffer_security_refusal(state: &ReofferState, info: &sdp::MediaInfo) -> Option<String> {
    if let Some(local) = state.far_local_crypto {
        let keeps_sdes = info.secure
            && !info.dtls
            && info
                .crypto
                .first()
                .is_some_and(|offered| offered.suite == local.suite);
        if !keeps_sdes {
            return Some(
                "the far leg is SDES-SRTP (RFC 4568) and B's re-offer does not keep it on the \
                 negotiated crypto-suite; not supported on a live call"
                    .to_string(),
            );
        }
    }
    if state.far_dtls && !(info.dtls && info.fingerprint.is_some()) {
        return Some(
            "the far leg is DTLS-SRTP (RFC 5764) and B's re-offer carries no DTLS fingerprint; not \
             supported on a live call"
                .to_string(),
        );
    }
    None
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// A re-offer's ICE candidates: the offering leg's, for its rebuilt agent, and the presented
    /// leg's, for the SDP. Both are the ones already advertised when stored — the ports are unchanged,
    /// which is exactly the property that lets media keep flowing across a restart — and are gathered
    /// only when there is nothing stored (ICE added mid-call, or a call restored from a snapshot). A
    /// far leg `ice: remove` took ICE off presents none, so it gathers none either.
    async fn reoffer_candidates(
        &self,
        state: &ReofferState,
        (offering_leg, presented_leg): (Leg, Leg),
        presented_party: Party,
        creds: &IceCredentials,
        far_ice_removed: bool,
    ) -> (
        Vec<siphon_rtp_ice::Candidate>,
        Vec<siphon_rtp_ice::Candidate>,
    ) {
        let (offering_stored, presented_stored) = match state.party {
            Party::Near => (&state.near_local_candidates, &state.far_local_candidates),
            Party::Far => (&state.far_local_candidates, &state.near_local_candidates),
        };
        let uses_ice = |leg_party: Party| leg_party == Party::Near || !far_ice_removed;
        let offering = if uses_ice(state.party) {
            self.leg_candidates(&offering_leg, offering_stored, creds)
                .await
        } else {
            Vec::new()
        };
        let presented = if presented_party == state.party {
            offering.clone()
        } else if uses_ice(presented_party) {
            self.leg_candidates(&presented_leg, presented_stored, creds)
                .await
        } else {
            Vec::new()
        };
        (offering, presented)
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Handle a **re-offer** on a live call (RFC 3264 §8 — a SIP re-INVITE): renegotiate on the
    /// *existing* media ports, and restart ICE if the peer's credentials changed (RFC 8445 §9).
    ///
    /// The contrast with a repeated [`Self::offer`] is the whole point of the verb. An `Offer` on a
    /// live call-id replaces it: the old call is torn down and the replacement binds fresh ports, so
    /// the peer has to be told a new address. A `Reoffer` keeps every port, so the media path is
    /// undisturbed and the dialog continues — which is what a re-INVITE means, and what makes an ICE
    /// restart possible at all (there is nothing to restart if the call was replaced).
    ///
    /// **Either party may re-offer**, resolved by tag: the call's `from_tag` is A (the near leg), its
    /// `to_tag` is B (the far leg), and anything else — including B's tag before B has answered — is
    /// `unknown_call`. Owner-only first (A3 — docs/security-and-nat.md §5).
    ///
    /// **Which leg the SDP presents.** The offering party's SDP describes *its* leg, so that is where
    /// its new address, ICE credentials and `received-from` hint are recorded. The rewritten SDP is
    /// delivered to the *other* party, so it presents the leg facing that party — the far leg for a
    /// re-offer from A, the near leg for one from B — exactly as that party last saw it (RFC 3264 §8:
    /// a subsequent offer modifies the SDP its recipient last received, and an address in it tells the
    /// recipient where to send). The ports do not move, and presenting the offerer's own leg instead
    /// tells the recipient to send its media into the offerer's socket, where the source gate drops
    /// it. A re-offer from B is completed by A's answer, which [`Self::answer`] accepts with the tags
    /// reversed.
    ///
    /// **Scope, stated rather than silently ignored:** this renegotiates the peer's *transport* — its
    /// signalled address and its ICE credentials/candidates. A re-offer that changes the negotiated
    /// codec is **rejected**, not quietly accepted: rebuilding a live transcode pipeline mid-call is
    /// its own piece of work, and answering "ok" while continuing to run the old codec would be worse
    /// than saying no. For the same reason a re-offer from B that drops the far leg's SRTP keying is
    /// refused rather than bridged in the clear.
    pub(super) async fn reoffer(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("re-offer SDP parse failed: {error}"),
                }
            }
        };

        // Snapshot what we need under the guard: ownership first, then which party is re-offering.
        let Some(state) = self.calls.get(call_id).and_then(|call| {
            if call.owner != client {
                return None;
            }
            let party = if call.from_tag == from_tag {
                Party::Near
            } else if call.to_tag.as_deref() == Some(from_tag) {
                // `to_tag` is only ever set by an answer, so an unanswered call has no B to re-offer.
                Party::Far
            } else {
                return None;
            };
            Some(ReofferState::capture(&call, party))
        }) else {
            return unknown_call(call_id);
        };
        let party = state.party;
        // The leg the re-offering party talks to, and the one the rewritten SDP presents. A call the
        // engine answered itself (`answer_local`) has no far leg: its caller reaches the near socket,
        // and that is the only leg there is to present.
        let (offering_leg, presented_leg, presented_party) = match (party, state.far) {
            (Party::Near, Some(far)) => (state.near, far, Party::Far),
            (Party::Near, None) => (state.near, state.near, Party::Near),
            (Party::Far, Some(far)) => (far, state.near, Party::Near),
            // `Party::Far` is only resolved from a `to_tag`, which only `answer` sets, and `answer`
            // refuses a call with no far leg.
            (Party::Far, None) => return unknown_call(call_id),
        };

        // A codec change needs a pipeline rebuild we do not do here — say so. What counts as a change
        // is whether the re-offer still *lists* the codec this party negotiated, not whether it leads
        // with it: a phone that offered G.729 first and settled on G.711 restates that same preference
        // order on every re-INVITE (RFC 3264 §8 — a re-offer restates the whole session), and holding
        // it to its first entry would reject a re-offer that renegotiates nothing.
        let reoffered_codecs = info.audio_codecs();
        if let Some(previous) = state.previous_codec.as_ref() {
            if !reoffered_codecs.is_empty()
                && !reoffered_codecs
                    .iter()
                    .any(|offered| same_codec(offered, previous))
            {
                return CmdResult::Error {
                    reason: format!(
                        "re-offer drops the negotiated codec ({} → {}); not supported on a live \
                         call — replace it with a fresh offer instead",
                        previous.encoding_name,
                        reoffered_codecs
                            .first()
                            .map_or("none", |offered| offered.encoding_name.as_str()),
                    ),
                };
            }
        }
        // A secure far leg stays secure: B's re-offer must keep keying it the way it is keyed, or the
        // engine would have to bridge B in the clear or invent keying it cannot answer with — never
        // silently (docs/security-and-nat.md Layer 5). The answer to it re-presents the engine's own
        // key or fingerprint, so B must still offer something that answer can select (RFC 4568 §5.1.2:
        // the answer picks one offered `a=crypto` and keeps its suite).
        if party == Party::Far {
            if let Some(reason) = far_reoffer_security_refusal(&state, &info) {
                return CmdResult::Error {
                    reason: format!("re-offer: {reason}"),
                };
            }
        }

        // B's leg carries no ICE once `ice: remove` took it off: at offer, and kept so a re-offer
        // presents B's leg as B last saw it, or by this re-offer toward B restating the directive. A's
        // own leg keeps the engine's ICE either way (RFC 8839 §4.2.5).
        let far_ice_removed = state.far_ice_removed
            || (presented_party == Party::Far
                && ice_directive(profile) == Some(IceDirective::Remove));
        // RFC 8445 §9.1.1.1: an ICE restart is signalled by new credentials on the re-offer. B's are not
        // read on a leg without ICE, so they neither restart ICE nor arm an agent there.
        let new_remote_ice =
            peer_ice_credentials(&info).filter(|_| !(party == Party::Far && far_ice_removed));
        let ice_restart = match (state.previous_remote_ice.as_ref(), new_remote_ice.as_ref()) {
            (Some(previous), Some(new)) => previous != new,
            // Peer added ICE where it had none, or dropped it: both change the ICE session.
            (None, Some(_)) | (Some(_), None) => true,
            (None, None) => false,
        };

        // Fresh local credentials for a restart (§9.1.1.1: a restarting agent MUST use new ones);
        // otherwise keep advertising the ones already in play.
        let ice_creds = if ice_restart && new_remote_ice.is_some() {
            ice::generate_credentials()
        } else {
            state.ice.clone()
        };

        if ice_restart {
            tracing::info!(
                target: "siphon_rtp::media",
                %call_id,
                offered_by = party.label(),
                "ICE restart (RFC 8445 §9): the re-offer carries new peer credentials — new session, \
                 media continues on the current pair until the new one is selected"
            );
        }

        // See `reoffer_candidates`: stored candidates are re-used, and B's leg has none without ICE.
        let (offering_candidates, presented_candidates) = match ice_creds.as_ref() {
            Some(creds) => {
                self.reoffer_candidates(
                    &state,
                    (offering_leg, presented_leg),
                    presented_party,
                    creds,
                    far_ice_removed,
                )
                .await
            }
            None => (Vec::new(), Vec::new()),
        };

        // Rebuild the offering leg's agent against the new session. Crucially the datapath's adopted
        // source is left alone: under the layer-4 gate media keeps flowing on the previously selected
        // pair until the new agent selects one and calls `adopt_source` again (RFC 8445 §9.3 — an
        // agent continues using the old session's pair until the new one completes).
        if let (Some(agents), Some(creds), Some(remote)) = (
            self.ice_agents.as_ref(),
            ice_creds.as_ref(),
            new_remote_ice.as_ref(),
        ) {
            if ice_restart && !info.candidates.is_empty() {
                let config = IceConfig {
                    local_ufrag: creds.ufrag.clone(),
                    local_pwd: creds.pwd.clone(),
                };
                for endpoint in offering_leg.endpoint_ids() {
                    let Some(local_addr) = self.endpoint_address(endpoint) else {
                        continue;
                    };
                    let component = if endpoint == offering_leg.rtp.id {
                        1
                    } else {
                        2
                    };
                    let agent_config = siphon_rtp_ice::agent::AgentConfig::new(
                        siphon_rtp_ice::agent::Credentials::new(
                            creds.ufrag.clone(),
                            creds.pwd.clone(),
                        ),
                        siphon_rtp_ice::agent::Credentials::new(
                            remote.ufrag.clone(),
                            remote.pwd.clone(),
                        ),
                        // §6.1.1: the offerer controls, and here the peer re-offered — unless it is a
                        // lite agent, which can never control.
                        info.ice_lite,
                        ice_tie_breaker(),
                    )
                    .with_candidates(
                        filter_component(&offering_candidates, component),
                        filter_component(&info.candidates, component),
                    );
                    self.datapath.set_ice_agent(
                        endpoint,
                        config.clone(),
                        IceAgentMode::ForwardOnly,
                        agents.events(),
                    );
                    agents.register(endpoint, call_id, local_addr, agent_config, 0);
                }
            }
        }

        // Record the offering party's new state on its own leg. Its `received-from` hint moves with
        // it when the re-offer carries one (an app that switched network re-INVITEs from a new public
        // address) and is kept when it carries none: one proxy-observed address replaces another, and
        // the latch still governs from the first accepted packet (docs/security-and-nat.md §4 layer 2).
        // The media path itself is re-wired by the answer that completes this exchange.
        if let Some(mut call) = self.calls.get_mut(call_id) {
            match party {
                Party::Near => {
                    call.near.remote_rtp = Some(info.remote_rtp);
                    call.near.remote_rtcp = Some(info.remote_rtcp);
                    // A re-offer restates A's codec list, so an `answer` still to come negotiates
                    // against what A last offered rather than what it opened the dialog with (the
                    // guard above already refused a list that drops the negotiated codec). A re-offer
                    // that resolves no codec at all leaves the stored set alone — it tells us nothing.
                    if !reoffered_codecs.is_empty() {
                        call.near_offered_codecs = reoffered_codecs;
                    }
                    call.near_remote_ice = new_remote_ice;
                    call.near_remote_candidates = info.candidates.clone();
                    call.near_peer_is_lite = info.ice_lite;
                    if profile.received_from.is_some() {
                        call.offer_received_from = profile.received_from;
                    }
                    // A re-offer from A supersedes any from B still waiting for an answer.
                    call.pending_far_reoffer = None;
                    // A re-offer restates the offering party's own direction, so this is where hold is
                    // applied *and* where the unhold re-arms the dead-path timer (RFC 3264 §8 — a
                    // subsequent offer modifies the session, and §8.4 makes hold/unhold exactly such an
                    // offer). Taken unconditionally: `sendrecv` is the meaning of an absent attribute,
                    // so "no direction line in this re-offer" genuinely means the party is active again.
                    call.near_direction = info.direction;
                }
                Party::Far => {
                    if let Some(far) = call.far.as_mut() {
                        far.remote_rtp = Some(info.remote_rtp);
                        far.remote_rtcp = Some(info.remote_rtcp);
                    }
                    call.far_remote_ice = new_remote_ice;
                    if profile.received_from.is_some() {
                        call.far_received_from = profile.received_from;
                    }
                    // Held for A's answer, which re-wires the media path against it.
                    call.pending_far_reoffer = Some(sdp.to_string());
                    // As above, for a re-offer the answering party initiated.
                    call.far_direction = info.direction;
                }
            }
            call.ice = ice_creds.clone();
            // Kept for the answer that completes this exchange, which must not arm B's leg either.
            call.far_ice_removed = far_ice_removed;
            // Both legs' candidates, as now advertised or about to be: the presented leg's are what its
            // party is being told, the offering leg's what its rebuilt agent runs on.
            if ice_creds.is_some() {
                let (near_candidates, far_candidates) = match party {
                    Party::Near => (&offering_candidates, &presented_candidates),
                    Party::Far => (&presented_candidates, &offering_candidates),
                };
                call.near_local_candidates = near_candidates.clone();
                if call.far.is_some() {
                    call.far_local_candidates = far_candidates.clone();
                }
            }
        }

        // A secure (SDES-SRTP) text stream is re-presented with the engine's own stored key for the
        // presented leg — the key that party already holds (RFC 4568: a re-offer re-presents the key,
        // it never mints one). That key always exists once the secure text leg registered at answer;
        // fail closed rather than present a secure stream as plaintext if it is somehow absent
        // (docs/security-and-nat.md Layer 5d — never bridge or present secure↔insecure).
        let presented_text_key = match presented_party {
            Party::Far => state.far_text_local_crypto,
            Party::Near => state.near_text_local_crypto,
        };
        if state.text_secure && presented_text_key.is_none() {
            return error_result(
                "re-offer secure text",
                &"secure text stream has no stored engine a=crypto to re-present",
            );
        }
        let presented_media = presented_leg.engine_media();
        // RFC 5761: present the leg's bound mux state when a `rtcp-mux` directive asks for it, or when
        // the re-offering party's SDP disagrees with it, exactly as `answer` does. The presented SDP is
        // rewritten from the other party's, whose `a=rtcp-mux` line says nothing about this leg.
        let presented_muxed = presented_leg.rtcp.is_none();
        let mux_override = (!profile.rtcp_mux.is_empty() || info.rtcp_mux != presented_muxed)
            .then_some(presented_muxed);
        let codec_policy = parse_codec_flags(&profile.flags);
        let presentation = match presented_party {
            // Delivered to B: the far leg, presented as the original offer presented it.
            Party::Far => {
                // RFC 8839 §5.3: the offerer's default destination matches none of its candidates.
                let ice_mismatch =
                    siphon_rtp_ice::is_ice_mismatch(info.remote_rtp, &info.candidates)
                        && ice_directive(profile) != Some(IceDirective::Force);
                let dtls = if state.far_dtls {
                    let Some(fingerprint) = self.engine_fingerprint() else {
                        return error_result(
                            "re-offer DTLS-SRTP",
                            &"engine has no DTLS certificate",
                        );
                    };
                    Some((fingerprint, offered_dtls_setup(dtls_directive(profile))))
                } else {
                    None
                };
                let text = match presented_leg.text_anchor(state.far_text_local_crypto) {
                    Some(anchor) => anchor,
                    // The engine has no text endpoint on this leg to anchor a stream the offerer
                    // added mid-call, and passing it through would hand B the offerer's own (often
                    // private) text address — decline it (RFC 3264 §6/§8.2).
                    None if info.text.is_some() => TextRewrite::Decline,
                    None => TextRewrite::None,
                };
                LegPresentation {
                    engine: presented_media,
                    ice: offer_ice_rewrite(
                        ice_creds.as_ref(),
                        &presented_candidates,
                        ice_mismatch,
                        far_ice_removed,
                    ),
                    security: far_security(
                        state.far_downgraded_to_plain,
                        dtls,
                        state.far_local_crypto,
                    ),
                    mux_override,
                    text,
                    codec: CodecPresentation::Policy(&codec_policy),
                }
            }
            // Delivered to A: the near leg, presented as the answer presented it.
            Party::Near => {
                let text = if state.far.is_none() {
                    // A single-leg call: the near leg's text, if it has any, as its caller knows it.
                    presented_leg
                        .text_anchor(state.near_text_local_crypto)
                        .unwrap_or(TextRewrite::None)
                } else if let Some(secure) = state.near_text_local_crypto {
                    presented_leg
                        .text_anchor(Some(secure))
                        .unwrap_or(TextRewrite::Decline)
                } else if state.text_relayed {
                    presented_leg
                        .text_anchor(None)
                        .unwrap_or(TextRewrite::Decline)
                } else if info.text.is_some() {
                    // A never had a text stream accepted on this call: nothing to anchor it to.
                    TextRewrite::Decline
                } else {
                    TextRewrite::None
                };
                LegPresentation {
                    engine: presented_media,
                    ice: answer_ice_rewrite(ice_creds.as_ref(), &presented_candidates),
                    security: near_security(
                        state.near_local_crypto,
                        state.far_local_crypto.is_some() || state.far_dtls,
                    ),
                    mux_override,
                    text,
                    // A transcoding call sends A its own codec whatever B uses (RFC 3264 §6). A
                    // single-leg call's re-offer keeps the codec list it was sent: the engine is the
                    // far side there, and choosing for it is `answer_local`'s job.
                    codec: match state.near_codec.as_ref() {
                        Some(codec) if state.far.is_some() && state.transcoding => {
                            CodecPresentation::Own {
                                codec,
                                telephone_event: state.near_telephone_event,
                            }
                        }
                        _ => CodecPresentation::AsReceived,
                    },
                }
            }
        };
        // Media-plane lifecycle: which party re-offered and what the other one is being shown — the
        // single line that tells an operator where each side has been told to send.
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            offered_by = party.label(),
            offerer = %info.remote_rtp,
            presented_leg = presented_party.label(),
            presented = %SocketAddr::new(presented_media.advertised_ip, presented_media.rtp.port()),
            ice_restart,
            "re-offer"
        );
        match present_leg(sdp, presentation, &profile.replace, call_id) {
            Ok(presented) => ok_sdp(presented, None),
            Err(error) => error_result("re-offer rewrite", &error),
        }
    }
}
