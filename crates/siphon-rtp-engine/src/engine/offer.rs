//! The `offer` verb: allocate a call's legs and present the far leg to the answerer.

use siphon_rtp_datapath::{AddressFamily, Datapath, IceConfig};
use siphon_rtp_proto::{CmdResult, ProfileFlags};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use std::collections::HashSet;

use crate::ice;
use crate::sdp::{self, SecurityAdvertisement, TextRewrite};

use super::negotiate::{
    bridge_source_filter, dtls_directive, far_security, ice_directive, offer_ice_rewrite,
    offered_dtls_setup, parse_codec_flags, peer_ice_credentials, present_leg, resolve_rtcp_mux,
    same_codec, CodecPresentation, DtlsDirective, IceDirective, LegPresentation,
};
use super::takeover::{ws_takeover_media_address, WsBridgeSetup, WsVadConfig};
use super::{
    error_result, ok_sdp, unknown_call, Call, CallerMediaLeg, ClientId, Engine, Leg, PipelineKind,
};

/// The transport the **far** leg presents when the engine terminates a secure *offerer*.
///
/// A's keying must not reach B. Before this, `far_security` was handed `far_local_crypto` — `None`
/// whenever B's own profile did not ask for a secure far leg — so the rewrite passed A's `a=crypto`
/// straight through to B, handing a third party the offerer's SRTP key while answering A in the
/// clear. Terminating A's SRTP means the far leg is plaintext unless B asked for its own keying.
fn far_security_with_secure_near(
    near_terminated: bool,
    downgraded_to_plain: bool,
    dtls: Option<(sdp::Fingerprint, sdp::Setup)>,
    local_crypto: Option<CryptoAttribute>,
) -> Option<SecurityAdvertisement> {
    match far_security(downgraded_to_plain, dtls, local_crypto) {
        Some(advertisement) => Some(advertisement),
        // B has no keying of its own, and A's must not be forwarded: say plaintext explicitly, which
        // is what forces `RTP/AVP` and strips the `a=crypto` A offered.
        None if near_terminated => Some(SecurityAdvertisement::Plain),
        None => None,
    }
}

/// WebSocket **takeover** (`ws_uri`) on a leg the two-leg verbs cannot bridge. Refuse here, at
/// offer, before a single port is allocated and before the controller commits to the dialog —
/// the failure mode this replaces is the worst one available: a clean `ok` on a call whose
/// media goes nowhere.
///
/// - A **secure offerer** (SDES-SRTP RFC 4568, or DTLS-SRTP RFC 5764). The answer delivered to
///   A on this path is rewritten from *B's* SDP, so there is nowhere to advertise the engine's
///   own `a=crypto` / `a=fingerprint` — and without that the engine is not A's cryptographic
///   far side, so A's SRTP would reach the bridge as ciphertext and the downlink would leave in
///   the clear. `answer_local` writes A's answer itself and does support this; that is where a
///   secure takeover belongs, and the reason string says so.
/// - An **ICE offerer** (RFC 8445). A takeover leg's egress is owned by the bridge's drain
///   task, and only the full agent's selection re-points it; on this path no agent is armed for
///   a takeover leg at all, so the downlink would keep going to the signalled `c=`.
fn offer_takeover_refusal(profile: &ProfileFlags, info: &sdp::MediaInfo) -> Option<CmdResult> {
    if profile.ws_uri.is_some() {
        if info.secure {
            let keying = if info.dtls { "DTLS-SRTP" } else { "SDES-SRTP" };
            return Some(CmdResult::Error {
                reason: format!(
                    "offer: ws-takeover-secure-offerer: a WebSocket takeover (ws_uri) on a \
                     {keying} offerer is not supported on offer/answer — the answer to the \
                     offerer is derived from the far leg's SDP and cannot carry the engine's own \
                     keying; use answer_local, which terminates SRTP on the takeover leg"
                ),
            });
        }
        if info.is_ice() && ice_directive(profile) != Some(IceDirective::Remove) {
            return Some(CmdResult::Error {
                reason: "offer: ws-takeover-ice-offerer: a WebSocket takeover (ws_uri) on an \
                         ICE offerer is not supported on offer/answer — no ICE agent is armed \
                         for a takeover leg here, so its downlink would never follow the \
                         selected pair; use answer_local, or ICE=remove to drop ICE"
                    .to_string(),
            });
        }
    }
    None
}

/// An offer's ICE posture: whether `ice: remove` takes ICE off the far leg, whether the offer's ICE
/// was altered in transit (RFC 8839 §5.3), and the engine's own credentials when a leg uses ICE.
fn offer_ice(
    profile: &ProfileFlags,
    info: &sdp::MediaInfo,
    call_id: &str,
) -> (bool, bool, Option<ice::IceCredentials>) {
    // ICE-lite posture (docs/security-and-nat.md §4 layer 4): mint our own short-term credentials
    // when a leg uses ICE — advertised in the rewritten SDP and installed on the endpoints so
    // the responder can validate the peer's connectivity checks. The control `profile.ice` field
    // overrides the SDP-derived default (RFC 8445): `force`/`force-relay` mint them regardless of
    // the offer, `remove` takes ICE off the far leg only, otherwise mirror whether the offer carried
    // ICE.
    let ice_directive = ice_directive(profile);
    let far_ice_removed = ice_directive == Some(IceDirective::Remove);
    // RFC 8839 §5.3: the offer carried candidates but its default destination is none of them, so
    // the SDP was rewritten in transit (a SIP ALG). ICE describes a topology that no longer
    // matches where media actually goes, so it must not be used — we say `a=ice-mismatch` and both
    // sides fall back to the signalled address. An explicit `ICE=force` still wins: an operator
    // who forces ICE has said they know better than the heuristic.
    let ice_mismatch = siphon_rtp_ice::is_ice_mismatch(info.remote_rtp, &info.candidates)
        && ice_directive != Some(IceDirective::Force);
    if ice_mismatch {
        tracing::info!(
            target: "siphon_rtp::control",
            %call_id,
            signalled = %info.remote_rtp,
            candidates = info.candidates.len(),
            "ICE mismatch (RFC 8839 §5.3): the offer's default destination matches none of its \
             candidates — the SDP was altered in transit; falling back to non-ICE"
        );
    }
    let want_ice = match ice_directive {
        _ if ice_mismatch => false,
        Some(IceDirective::Force) => true,
        // `remove` keeps ICE away from B, not from an ICE offerer: A indicates ICE support by its
        // `a=ice-ufrag`/`a=ice-pwd` and cannot use ICE unless the answer carries ours (RFC 8839
        // §4.2.5), so credentials are still minted for A's leg and only the far presentation strips
        // them. A takeover leg is the exception — no ICE agent runs for it on offer/answer (see
        // `offer_takeover_refusal`), so there `remove` takes ICE off A's leg as well.
        Some(IceDirective::Remove) => info.is_ice() && profile.ws_uri.is_none(),
        None => info.is_ice(),
    };
    let ice_creds = if want_ice {
        ice::generate_credentials()
    } else {
        None
    };
    (far_ice_removed, ice_mismatch, ice_creds)
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The candidates the far leg is offered with, gathered before the offer is written — the offer
    /// *is* the candidate list, and without trickle there is no second chance to add to it (RFC 8445
    /// §5.1.1). Host-only gathering (the default) is instant and touches no socket; with a STUN server
    /// configured this costs one bounded round trip on the control path.
    ///
    /// None without credentials, and none for a far leg `ice: remove` took ICE off: it presents no
    /// candidates, and gathering against a server would install the ICE responder on endpoints whose
    /// peer never runs a check.
    async fn far_offer_candidates(
        &self,
        far_leg: &Leg,
        ice_creds: Option<&ice::IceCredentials>,
        far_ice_removed: bool,
    ) -> Vec<siphon_rtp_ice::Candidate> {
        match ice_creds {
            Some(creds) if !far_ice_removed => {
                self.gather_leg_candidates(
                    far_leg,
                    &IceConfig {
                        local_ufrag: creds.ufrag.clone(),
                        local_pwd: creds.pwd.clone(),
                    },
                )
                .await
            }
            _ => Vec::new(),
        }
    }
}

/// The transport security an offer settles for both legs.
struct OfferSecurity {
    /// `dtls: off` forced the far leg to plaintext `RTP/AVP`.
    far_downgraded_to_plain: bool,
    /// The far leg is DTLS-SRTP.
    far_dtls: bool,
    /// The engine's own SDES key toward B.
    far_local_crypto: Option<CryptoAttribute>,
    /// The engine's own SDES key toward a secure offerer A.
    near_local_crypto: Option<CryptoAttribute>,
    /// A's own SDES key, from its offer.
    near_remote_crypto: Option<CryptoAttribute>,
    /// The fingerprint and `a=setup` a DTLS far leg advertises.
    far_dtls_presentation: Option<(sdp::Fingerprint, sdp::Setup)>,
    /// A DTLS-SRTP offerer the engine terminates, with A's keying from its offer.
    near_dtls: Option<super::NearDtls>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Settle an offer's transport security: the far leg's (DTLS-SRTP, SDES, a `dtls: off`
    /// downgrade, or the offer's own) and the engine's key toward a secure SDES offerer. The caller
    /// frees the offer's endpoints on a refusal.
    fn offer_security(
        &self,
        profile: &ProfileFlags,
        info: &sdp::MediaInfo,
    ) -> Result<OfferSecurity, Box<CmdResult>> {
        // Secure far leg: when the control profile asks for a secure far leg, either DTLS-SRTP
        // (`UDP/TLS/RTP/SAVP[F]`, RFC 5764) — advertise the engine's fingerprint + `a=setup` role,
        // keyed by the handshake at answer — or SDES (`RTP/SAVP[F]`, RFC 4568) — mint an `a=crypto` key.
        // B's answer brings its keying and `answer` wires the bridge. (`UDP/TLS/...` also matches
        // "SAVP", so DTLS is tested first.) The control `profile.dtls` field refines the DTLS case:
        // `off` downgrades the leg to plaintext, `passive`/`active`/`actpass` sets the offerer role.
        let far_transport = profile.transport_protocol.as_deref().unwrap_or_default();
        let dtls_directive = dtls_directive(profile);
        let dtls_transport = far_transport.contains("UDP/TLS");
        // `dtls: off` (rtpengine DTLS=off) forces a plaintext far leg even on a UDP/TLS transport —
        // no DTLS-SRTP and no SDES fallback (SDES applies only to a plain `RTP/SAVP[F]` transport).
        // Downgrading forces AVP and strips the offer's DTLS keying (`a=fingerprint`/`a=setup`).
        let dtls_off = matches!(dtls_directive, Some(DtlsDirective::Off));
        let far_downgraded_to_plain = dtls_transport && dtls_off;
        let far_dtls = dtls_transport && !dtls_off;
        let far_sdes = !dtls_transport && far_transport.contains("SAVP");
        let far_local_crypto = if far_sdes {
            match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                Ok(crypto) => Some(crypto),
                Err(error) => {
                    return Err(Box::new(error_result("generate SDES key", &error)));
                }
            }
        } else {
            None
        };
        // The engine's own key toward **A**, minted when A offered SDES-SRTP. This is what makes the
        // engine A's cryptographic far side, and it is the whole reason a secure offerer can be
        // terminated on this path at all: the answer A receives is rewritten from B's SDP, so without
        // a key of our own there is nothing to advertise and A's own key was passed through to B
        // instead — handing a third party the offerer's SRTP key while answering A in the clear.
        //
        // SDES only here. A DTLS-SRTP offerer is keyed by a handshake, not by a key in the SDP, and is
        // decided below.
        let near_sdes = info.secure && !info.dtls;
        let near_remote_crypto = info.crypto.first().copied();
        let near_local_crypto = if near_sdes {
            match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                Ok(crypto) => Some(crypto),
                Err(error) => {
                    return Err(Box::new(error_result("generate SDES key", &error)));
                }
            }
        } else {
            None
        };
        // A secure offerer with no key to decrypt is refused, never bridged in the clear: answering a
        // `RTP/SAVP` offer that carries no usable `a=crypto` would advertise keying against nothing.
        if near_sdes && near_remote_crypto.is_none() {
            return Err(Box::new(error_result(
                "offer",
                &"secure-offerer-unkeyable: the RTP/SAVP offer carries no usable a=crypto",
            )));
        }
        // A **DTLS-SRTP** offerer (`UDP/TLS/RTP/SAVP[F]`, RFC 5764). With no far-leg transport and no
        // DTLS directive its keying passes through to B untouched, as before: two DTLS peers may run
        // their association end to end through the relay. Asking for a plaintext far leg (`dtls: off`,
        // or a transport that is not a secure profile) terminates it instead: the engine becomes A's
        // DTLS peer, answers A with its own fingerprint, and presents B plain RTP. Asking for a secure
        // far leg is refused: SDES toward B would need a transcrypt between two keys, and a DTLS far leg
        // a second association, and neither exists.
        let near_dtls = if info.dtls {
            if far_sdes || far_dtls {
                return Err(Box::new(error_result(
                    "offer",
                    &"secure-offerer-unsupported: a DTLS-SRTP offerer toward a secure far leg needs a \
                      transcrypt between two keys; a DTLS caller toward a plain callee is supported",
                )));
            }
            let plain_far =
                dtls_off || (!far_transport.is_empty() && !far_transport.contains("SAVP"));
            if plain_far {
                // RFC 5763 §5: "The endpoint MUST use the certificate fingerprint attribute". Without
                // one there is nothing to authenticate the handshake against.
                let Some(peer_fingerprint) = info.fingerprint.clone() else {
                    return Err(Box::new(error_result(
                        "offer",
                        &"secure-offerer-unkeyable: the UDP/TLS/RTP/SAVP offer carries no \
                          a=fingerprint",
                    )));
                };
                // A DTLS-SRTP session protects a single UDP port pair (RFC 5764 §3), and the bridge
                // runs one, on A's RTP port. A caller that does not multiplex RTCP onto it (RFC 5761)
                // would need a second association for its RTCP port, so it is refused rather than
                // answered with an RTCP flow that never gets keyed.
                if !info.rtcp_mux {
                    return Err(Box::new(error_result(
                        "offer",
                        &"secure-offerer-unsupported: a DTLS-SRTP offerer that does not multiplex \
                          RTCP needs a DTLS association per port; offer a=rtcp-mux",
                    )));
                }
                // A's answer has to carry the engine's own fingerprint (RFC 8842 §5.3).
                if self.engine_fingerprint().is_none() {
                    return Err(Box::new(error_result(
                        "DTLS-SRTP offer",
                        &"engine has no DTLS certificate",
                    )));
                }
                Some(super::NearDtls {
                    peer_fingerprint,
                    peer_setup: info.setup,
                    peer_tls_id: info.tls_id.clone(),
                    role: None,
                    local_tls_id: None,
                })
            } else {
                None
            }
        } else {
            None
        };
        let far_dtls_presentation = if far_dtls {
            let Some(fingerprint) = self.engine_fingerprint() else {
                return Err(Box::new(error_result(
                    "DTLS-SRTP offer",
                    &"engine has no DTLS certificate",
                )));
            };
            Some((fingerprint, offered_dtls_setup(dtls_directive)))
        } else {
            None
        };
        Ok(OfferSecurity {
            far_downgraded_to_plain,
            far_dtls,
            far_local_crypto,
            near_local_crypto,
            near_remote_crypto,
            far_dtls_presentation,
            near_dtls,
        })
    }
}

/// What anchoring an offer's RFC 4103 text stream leaves for the call.
struct OfferText {
    /// The offer's text stream is secure (`RTP/SAVP`).
    text_offered_secure: bool,
    /// A's own text SDES key, from a secure text offer.
    near_text_remote_crypto: Option<CryptoAttribute>,
    /// A text stream is anchored, plaintext or secure.
    anchor_text: bool,
    /// A secure text stream is anchored.
    anchor_secure_text: bool,
    near_text_endpoint: Option<siphon_rtp_datapath::Endpoint>,
    far_text_endpoint: Option<siphon_rtp_datapath::Endpoint>,
    /// The engine's own text SDES key toward B.
    far_text_local_crypto: Option<CryptoAttribute>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// An offer for a call-id that already exists.
    ///
    /// Ownership first (A3 — docs/security-and-nat.md §5): only the client that created a call may
    /// affect it. Another client offering the same id must not be able to disturb it, and must not
    /// learn that it exists — so it gets the same `unknown_call` any other cross-client reference
    /// does, and the live call is left completely untouched.
    ///
    /// For the owner, this replaces the call. That was already the effect (the registry entry was
    /// overwritten), but the previous `Call` was dropped without freeing anything: its 2-4 datapath
    /// endpoints leaked their ports and FDs, and its quota slot was never released, so a client
    /// repeating an offer bled both until the node refused new calls. Tear the old one down
    /// properly first — same path as `delete`, so the CDR is emitted and every resource is
    /// released — then build the replacement.
    ///
    /// Note this is *replacement*, not re-negotiation: the new call gets fresh ports, so the peer
    /// must be told the new address. A true re-offer (SIP re-INVITE — renegotiating codecs or
    /// addresses on the *existing* ports, and the trigger an RFC 8445 §9 ICE restart needs) is a
    /// separate control verb that does not exist yet.
    async fn replace_offered_call(&self, client: ClientId, call_id: &str) -> Option<CmdResult> {
        if let Some(existing) = self.calls.get(call_id) {
            if existing.owner != client {
                drop(existing);
                return Some(unknown_call(call_id));
            }
            drop(existing);
            tracing::info!(
                target: "siphon_rtp::control",
                %call_id,
                "offer replaces an existing call with the same id — tearing the old one down first"
            );
            if let Some((_, previous)) = self.calls.remove(call_id) {
                // `finish_call` emits the CDR and frees endpoints, pipelines, subscriptions and the
                // quota slot. No `MediaTimeout` event: the controller caused this, it is not a dead
                // path, and telling it otherwise would be a lie.
                self.finish_call(call_id, &previous, "replaced").await;
            }
        }
        None
    }

    /// Anchor an offer's RFC 4103 text stream: one text endpoint per leg, on each leg's family and
    /// interface, and the engine's own far text key for a secure stream. Adds the text endpoints to
    /// `endpoints`, and frees everything in it on a refusal.
    #[allow(clippy::too_many_arguments)]
    async fn anchor_offer_text(
        &self,
        profile: &ProfileFlags,
        info: &sdp::MediaInfo,
        near_family: AddressFamily,
        near_bind: Option<std::net::IpAddr>,
        far_family: AddressFamily,
        far_bind: Option<std::net::IpAddr>,
        endpoints: &mut Vec<siphon_rtp_datapath::Endpoint>,
    ) -> Result<OfferText, Box<CmdResult>> {
        // RFC 4103 Real-Time Text: when the offer carries an `m=text` stream (and this is not a WS
        // bridge, which has no B leg to relay to), anchor + relay it as a second stream — one text RTP
        // endpoint per leg, sharing each leg's family/interface. A **plaintext** (`RTP/AVP`) stream is a
        // second in-kernel relay. A **secure** (`RTP/SAVP` + `a=crypto`) stream is anchored as an
        // SDES-SRTP text leg: the engine mints its own far text SDES key, advertises `RTP/SAVP` + our
        // `a=crypto` to B, and terminates SRTP in the userspace text processor (docs/security-and-nat.md
        // Layer 5f — mirrors the audio SDES bridge). A secure text stream we cannot key (no usable
        // `a=crypto`) is declined (`m=text 0`, RFC 3264 §6), never downgraded to plaintext. Text RTCP is
        // not separately endpointed (single text port; text SRTCP rides the muxed port).
        let text_offered_secure = info.text.as_ref().is_some_and(|text| text.secure);
        // The near (A) leg's own text SDES key, from a secure text offer — decrypts A's text ingress.
        let near_text_remote_crypto = info
            .text
            .as_ref()
            .filter(|_| text_offered_secure)
            .and_then(|text| text.crypto.first().copied());
        let anchor_plain_text =
            info.text.is_some() && !text_offered_secure && profile.ws_uri.is_none();
        let anchor_secure_text =
            text_offered_secure && near_text_remote_crypto.is_some() && profile.ws_uri.is_none();
        let anchor_text = anchor_plain_text || anchor_secure_text;
        let (near_text_endpoint, far_text_endpoint, far_text_local_crypto) = if anchor_text {
            let near_text = match self.alloc_endpoints(1, near_family, near_bind).await {
                Ok(mut allocated) => allocated.remove(0),
                Err(reason) => {
                    self.free(endpoints).await;
                    return Err(Box::new(CmdResult::Error { reason }));
                }
            };
            let far_text = match self.alloc_endpoints(1, far_family, far_bind).await {
                Ok(mut allocated) => allocated.remove(0),
                Err(reason) => {
                    self.datapath.remove_endpoint(near_text.id).await;
                    self.free(endpoints).await;
                    return Err(Box::new(CmdResult::Error { reason }));
                }
            };
            endpoints.push(near_text);
            endpoints.push(far_text);
            // Mint the engine's own far text SDES key (advertised to B); the near text key is minted
            // at answer, when the near answer advertises `RTP/SAVP` + our `a=crypto` to A.
            let far_text_key = if anchor_secure_text {
                match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                    Ok(crypto) => Some(crypto),
                    Err(error) => {
                        self.free(endpoints).await;
                        return Err(Box::new(error_result("generate text SDES key", &error)));
                    }
                }
            } else {
                None
            };
            (Some(near_text), Some(far_text), far_text_key)
        } else {
            (None, None, None)
        };
        Ok(OfferText {
            text_offered_secure,
            near_text_remote_crypto,
            anchor_text,
            anchor_secure_text,
            near_text_endpoint,
            far_text_endpoint,
            far_text_local_crypto,
        })
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    pub(super) async fn offer(
        &self,
        client: ClientId,
        call_id: String,
        from_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        // Soft per-client call quota (the datapath media-port pool is the hard cap). Reject before
        // allocating anything. (A3 / DoS — docs/security-and-nat.md §5.)
        if self.client_call_count(client) >= self.max_calls_per_client {
            return CmdResult::Error {
                reason: "per-client call quota exceeded".to_string(),
            };
        }
        if let Err(reason) = crate::media_pipeline::validate_echo_delay_search_ms(profile) {
            return CmdResult::Error {
                reason: format!("offer: {reason}"),
            };
        }
        if let Some(refusal) = self.replace_offered_call(client, &call_id).await {
            return refusal;
        }
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("offer SDP parse failed: {error}"),
                }
            }
        };

        if let Some(refusal) = offer_takeover_refusal(profile, &info) {
            return refusal;
        }

        let (far_ice_removed, ice_mismatch, ice_creds) = offer_ice(profile, &info, &call_id);

        // One RTP endpoint per leg, plus a companion RTCP endpoint unless the stream is muxed. The
        // *near* leg binds the family of the offer's signalled `c=` line (RFC 4566 §5.7). The *far*
        // leg binds the same family by default, or the `address family` flag's family for IPv4↔IPv6
        // interworking (a v6 VoLTE access leg bridged to a v4 PSTN core) — the engine anchors media,
        // so a v6 near socket and a v4 far socket relay/transcode through it, and each leg's SDP is
        // rewritten in its own family (`rewrite` emits the endpoint's addrtype).
        let near_family = AddressFamily::of(info.remote_rtp.ip());
        let far_family = far_address_family(profile).unwrap_or(near_family);
        // RFC 5761 rtcp-mux: the controller's `rtcp-mux` directive can override the SDP-derived mux
        // per side (force mux, demux, or reject). This drives the per-leg port count *and* the far
        // SDP's `a=rtcp-mux` presentation — resolved once here so allocation and rewrite agree.
        let (near_mux, far_mux) = resolve_rtcp_mux(info.rtcp_mux, &profile.rtcp_mux);
        let near_per_leg = if near_mux { 1 } else { 2 };
        let far_per_leg = if far_mux { 1 } else { 2 };
        // Named-interface selection (rtpengine `direction`): `direction[0]` picks the near (A) leg's
        // interface and `direction[1]` the far (B) leg's. Each resolves to a bind IP the datapath
        // sources the leg from and an advertised IP put into that leg's rewritten SDP
        // (docs/security-and-nat.md §12.2). Absent/unknown slots fall back to the default interface.
        let (near_interface, far_interface) = self.interfaces.resolve_direction(&profile.direction);
        let (near_bind, near_advertised_override) = Self::leg_binding(near_interface, near_family);
        let (far_bind, far_advertised_override) = Self::leg_binding(far_interface, far_family);
        let near_endpoints = match self
            .alloc_endpoints(near_per_leg, near_family, near_bind)
            .await
        {
            Ok(endpoints) => endpoints,
            Err(reason) => return CmdResult::Error { reason },
        };
        let far_endpoints = match self
            .alloc_endpoints(far_per_leg, far_family, far_bind)
            .await
        {
            Ok(endpoints) => endpoints,
            Err(reason) => {
                self.free(&near_endpoints).await;
                return CmdResult::Error { reason };
            }
        };
        let near_rtp = near_endpoints[0];
        let far_rtp = far_endpoints[0];
        let near_rtcp = (!near_mux).then(|| near_endpoints[1]);
        let far_rtcp = (!far_mux).then(|| far_endpoints[1]);
        // Each leg's advertised IP: the interface override, else the address the datapath actually
        // bound (the pre-interface behaviour). The advertised IP is presentation-only — it never feeds
        // the source gate or latch, so it is not an RTPbleed vector (docs/security-and-nat.md §12.1).
        let near_advertised = near_advertised_override.unwrap_or_else(|| near_rtp.local_addr.ip());
        let far_advertised = far_advertised_override.unwrap_or_else(|| far_rtp.local_addr.ip());
        // Combined list for teardown on any later error path in this offer.
        let mut endpoints: Vec<_> = near_endpoints
            .iter()
            .chain(far_endpoints.iter())
            .copied()
            .collect();

        let OfferText {
            text_offered_secure,
            near_text_remote_crypto,
            anchor_text,
            anchor_secure_text,
            near_text_endpoint,
            far_text_endpoint,
            far_text_local_crypto,
        } = match self
            .anchor_offer_text(
                profile,
                &info,
                near_family,
                near_bind,
                far_family,
                far_bind,
                &mut endpoints,
            )
            .await
        {
            Ok(text) => text,
            Err(result) => return *result,
        };

        // The B-facing leg, as it will be recorded on the call. The rewritten offer is delivered to B,
        // so it presents this leg — its audio and text endpoints on the far interface.
        let far_leg = Leg {
            rtp: far_rtp,
            rtcp: far_rtcp,
            remote_rtp: None,
            remote_rtcp: None,
            advertised_ip: far_advertised,
            text: far_text_endpoint,
            // The far side's text address is unknown until its answer.
            text_remote_rtp: None,
        };
        let text_rewrite = match far_leg.text_anchor(far_text_local_crypto) {
            Some(anchor) => anchor,
            // A secure text stream we cannot key (no usable `a=crypto`) → decline it, never downgrade.
            None if text_offered_secure => TextRewrite::Decline,
            None => TextRewrite::None,
        };
        // ICE rewrite mode (RFC 8839 §5): re-originate ICE-lite when we minted creds; when `ice: remove`
        // took ICE off the far leg, strip the peer's ICE without advertising our own; otherwise pass it
        // through. `IceAdvertisement` borrows `ice_creds`, so it is built here and kept alive to rewrite.
        let far_ice_candidates = self
            .far_offer_candidates(&far_leg, ice_creds.as_ref(), far_ice_removed)
            .await;
        let ice_rewrite = offer_ice_rewrite(
            ice_creds.as_ref(),
            &far_ice_candidates,
            ice_mismatch,
            far_ice_removed,
        );

        let OfferSecurity {
            far_downgraded_to_plain,
            far_dtls,
            far_local_crypto,
            near_local_crypto,
            near_remote_crypto,
            far_dtls_presentation,
            near_dtls,
        } = match self.offer_security(profile, &info) {
            Ok(security) => security,
            Err(result) => {
                self.free(&endpoints).await;
                return *result;
            }
        };

        // RFC 5761: when a `rtcp-mux` directive was given, present the resolved far-side mux to B
        // explicitly (force `a=rtcp-mux` on, or strip it); otherwise mirror the offer (`None`).
        let far_mux_override = (!profile.rtcp_mux.is_empty()).then_some(far_mux);
        // rtpengine codec manipulation on the SDP offered to the far side: strip/mask/consume remove a
        // codec, transcode/offer add or reorder, except/accept keep it (see `parse_codec_flags`). The
        // far side may then select a transcode/offer codec, engaging the transcoder at answer.
        let codec_policy = parse_codec_flags(&profile.flags);
        let rewritten = match present_leg(
            sdp,
            LegPresentation {
                engine: far_leg.engine_media(),
                ice: ice_rewrite,
                security: far_security_with_secure_near(
                    near_local_crypto.is_some() || near_dtls.is_some(),
                    far_downgraded_to_plain,
                    far_dtls_presentation,
                    far_local_crypto,
                ),
                mux_override: far_mux_override,
                text: text_rewrite,
                codec: CodecPresentation::Policy(&codec_policy),
            },
            &profile.replace,
            &call_id,
        ) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                self.free(&endpoints).await;
                return CmdResult::Error {
                    reason: format!("offer SDP rewrite failed: {error}"),
                };
            }
        };

        // WebSocket bridge (mod_audio_stream / voice-AI): a native siphon-rtp extension. When the
        // profile carries `ws_uri`, leg A (the offerer) is bridged to that WS server using A's
        // negotiated (primary) codec — the engine dials the WS as a client and pumps A's audio in
        // both directions. The A↔B relay/transcode path is not wired in this mode (the WS is A's far
        // side). Resolved at offer because A's codec + signalled address are both known here.
        // A's full offered set, kept alongside its first choice: at answer it decides whether B's
        // selection is one A can simply be relayed on (RFC 3264 §6.1) or a genuine divergence that
        // needs the transcoder — see `negotiated_near_codec`.
        let near_offered_codecs = info.audio_codecs();
        let near_codec = near_offered_codecs.first().cloned();
        // Did the codec policy take A's own codec out of the offer B sees? Read off the far offer the
        // policy actually produced rather than re-deriving it from the flags, so `mask`, `consume`, an
        // `offer` whitelist and `strip-all` are all judged by their outcome. B cannot then select that
        // codec, so its answer says nothing about whether A moved — `negotiated_near_codec` leaves A on
        // its own codec and the transcoder engages, which is what those flags ask for. A far offer that
        // will not re-parse (our own rewrite, so a bug rather than input) counts as *not* withheld: the
        // relay that keeps the call up is the better failure mode.
        let near_codec_withheld = match near_codec.as_ref() {
            Some(primary) if !codec_policy.is_noop() => {
                sdp::parse(&rewritten).is_ok_and(|far_offer| {
                    !far_offer
                        .audio_codecs()
                        .iter()
                        .any(|offered| same_codec(offered, primary))
                })
            }
            _ => false,
        };
        let ws_uri = profile.ws_uri.clone();
        // Where the caller's media lands if this call never gets an `answer` follows from the same
        // choice. A WS takeover bridges `near_rtp` (below), so the caller reaches the near socket;
        // otherwise the offer-only UAS shape applies — the controller puts this rewritten offer, which
        // advertises the far leg, into its own 200 OK, so the caller reaches the far socket (the same
        // endpoint `promote_to_processing`'s single-leg arm reflects on). Unread once `answer` lands
        // and both legs face a real party.
        let (pipeline, caller_media_leg) = if ws_uri.is_some() {
            (PipelineKind::Ws, CallerMediaLeg::Near)
        } else {
            (PipelineKind::Passthrough, CallerMediaLeg::Far)
        };

        // Media-plane lifecycle (target `siphon_rtp::media`): the offer allocated ports and is about to
        // record the call — the first line of a call's story, correlated by the same `call_id` the SBC
        // logs. `secure` flags a leg the far side offered as SRTP (SDES) or DTLS-SRTP.
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            from_tag = %from_tag,
            offerer = %info.remote_rtp,
            near_local = %near_rtp.local_addr,
            codec = near_codec.as_ref().map(|codec| codec.encoding_name.as_str()).unwrap_or("-"),
            secure = far_local_crypto.is_some() || far_dtls,
            text = anchor_text,
            text_secure = anchor_secure_text,
            "call created"
        );

        // The near (offerer) leg's signalled text address + the negotiated T.140/RED payload types,
        // captured only when we anchored a plaintext text stream (else `None`).
        let anchored_text = info.text.as_ref().filter(|_| anchor_text);
        let near_text_remote = anchored_text.map(|text| text.remote_rtp);
        let text_t140_payload_type = anchored_text.and_then(|text| text.t140_payload_type);
        let text_red_payload_type = anchored_text.and_then(|text| text.red_payload_type);

        *self.client_calls.entry(client).or_insert(0) += 1;
        // Index this call's endpoints (including the text stream) so observed RTCP can be correlated
        // back to the call-id and every port is released at teardown.
        for endpoint in [
            Some(near_rtp),
            near_rtcp,
            Some(far_rtp),
            far_rtcp,
            near_text_endpoint,
            far_text_endpoint,
        ]
        .into_iter()
        .flatten()
        {
            self.endpoint_calls.insert(endpoint.id, call_id.clone());
        }
        self.calls.insert(
            call_id.clone(),
            Call {
                owner: client,
                created_tick: self.datapath.now_ticks(),
                started_at_unix_ms: super::unix_time_ms(),
                ice: ice_creds,
                // A's own credentials, from the offer — needed to *address* checks to A later
                // (RFC 8445 §7.1.2); B's arrive with its answer.
                near_remote_ice: peer_ice_credentials(&info),
                far_remote_ice: None,
                near_remote_candidates: info.candidates.clone(),
                near_peer_is_lite: info.ice_lite,
                far_local_candidates: far_ice_candidates.clone(),
                // Gathered at answer, when the near leg is first presented to A.
                near_local_candidates: Vec::new(),
                far_ice_removed,
                from_tag,
                to_tag: None,
                near: Leg {
                    rtp: near_rtp,
                    rtcp: near_rtcp,
                    remote_rtp: Some(info.remote_rtp),
                    remote_rtcp: Some(info.remote_rtcp),
                    advertised_ip: near_advertised,
                    text: near_text_endpoint,
                    text_remote_rtp: near_text_remote,
                },
                // An offer always allocates a B-facing leg: a B side may still answer, and the offer
                // being rewritten right here is what would be delivered to it.
                far: Some(far_leg),
                caller_media_leg,
                far_local_crypto,
                far_remote_crypto: None,
                far_dtls,
                // Decided by B's answer.
                far_dtls_role: None,
                far_downgraded_to_plain,
                // A's own posture, for the late-`ws_uri` takeover guard in `answer`.
                near_secure: info.secure,
                near_local_crypto,
                near_remote_crypto,
                // A's DTLS keying when the engine terminates it; the role and the engine's `a=tls-id`
                // are settled by the answer.
                near_dtls,
                near_codec: near_codec.clone(),
                near_offered_codecs,
                near_codec_withheld,
                far_codec: None,
                // A's own direction, for the idle reaper. B's arrives with its answer; until then the
                // far party is not a party yet, so it defaults to sendrecv and contributes nothing.
                near_direction: info.direction,
                far_direction: sdp::MediaDirection::default(),
                near_telephone_event: info.telephone_event_payload_type(),
                far_telephone_event: None,
                pipeline,
                relay_flows: Vec::new(),
                promotion_reasons: HashSet::new(),
                offer_received_from: profile.received_from,
                // B's arrives with its answer.
                far_received_from: None,
                pending_far_reoffer: None,
                // A 2-party offer never idles a single leg on comfort noise.
                comfort_noise_payload_type: None,
                text_t140_payload_type,
                text_red_payload_type,
                // No text flows until `answer()` installs them; no text promotion yet.
                text_relay_flows: Vec::new(),
                text_promotion_reasons: HashSet::new(),
                // Captured at offer, applied at answer (when the text stream is fully negotiated).
                text_events: profile.text_events,
                // Secure text: `text_secure` is confirmed at answer (both legs' keys known); the offer
                // captures A's own text key + the engine's far text key so answer can build both legs.
                text_secure: false,
                near_text_remote_crypto,
                far_text_local_crypto,
                // The near text key is minted at answer (advertised to A), not at offer.
                near_text_local_crypto: None,
            },
        );

        // Stand the WS bridge up now that the call is recorded (so a dispatch can find its route). On
        // any failure (no codec, redirect install, or dial), tear the half-built call back down.
        if let Some(ws_uri) = ws_uri {
            // Aim the downlink at leg A's `received-from` public IP when the offer supplied one, and
            // gate its ingress on the same address — one value for both, see the helper.
            let a_media = ws_takeover_media_address(info.remote_rtp, profile.received_from);
            if let Err(reason) = self
                .setup_ws_bridge(WsBridgeSetup {
                    call_id: &call_id,
                    ws_uri: &ws_uri,
                    endpoint_a: near_rtp.id,
                    a_rtp: a_media,
                    codec: near_codec.as_ref(),
                    accepted_source: bridge_source_filter(profile, a_media),
                    // A two-leg takeover is refused on a secure or ICE offerer (see the guard at the
                    // top of `offer`), so this arm is always a plaintext, non-ICE leg.
                    ice_pending: false,
                    secure: None,
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
                self.teardown_call(&call_id).await;
                return error_result("ws bridge", &reason);
            }
        }

        ok_sdp(rewritten, None)
    }
}

/// The far-leg engine endpoint address family requested by the rtpengine `address family` flag
/// (`IP4`/`IP6`), for IPv4↔IPv6 interworking. `None` when unset (the far leg follows the offer).
pub(super) fn far_address_family(profile: &ProfileFlags) -> Option<AddressFamily> {
    match profile.address_family.as_deref()?.trim() {
        family if family.eq_ignore_ascii_case("IP6") => Some(AddressFamily::V6),
        family if family.eq_ignore_ascii_case("IP4") => Some(AddressFamily::V4),
        _ => None,
    }
}
