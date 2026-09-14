//! The `answer` verb: record B's SDP, install the relay or media pipeline, and present the near
//! leg.

use siphon_rtp_codec::factory::{CodecSpec, OPUS_MAX_PTIME_MS};
use siphon_rtp_datapath::{
    Datapath, EndpointId, FlowAction, ForwardRule, IceAgentMode, IceConfig, LatchPolicy,
    SourceFilter,
};
use siphon_rtp_dtls::DtlsRole;
use siphon_rtp_proto::{CmdResult, ProfileFlags};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use std::sync::{Arc, Mutex};

use crate::sdp::{self, TextRewrite};
use crate::text_pipeline::{TextCall, TextDirectionConfig};

use super::install::AnswerWiring;
use super::negotiate::{
    answer_ice_rewrite, apply_received_from, bridge_source_filter, far_security, filter_component,
    ice_tie_breaker, near_security, peer_ice_credentials, present_leg, same_codec,
    CodecPresentation, LegPresentation,
};
use super::takeover::{WsBridgeSetup, WsVadConfig};
use super::{
    error_result, ok_sdp, unknown_call, ClientId, Engine, Party, PipelineKind, PromotionReason,
};

/// A's answer to a re-offer from B, as [`Engine::answer`] carries it: the far party's SDP (B's
/// re-offer) drives the media wiring as B's answer usually does, A's answer SDP is what gets
/// presented to B, and this is what else the answer needs from A's side.
struct ReversedAnswer {
    /// Whether A's answer carries an `m=text` section at all.
    carries_text: bool,
    /// Whether A's answer kept the text stream (a non-zero `m=text` port).
    near_accepted_text: bool,
    /// The engine's text key toward A, which A was shown when B's re-offer was presented to it and
    /// has now answered against — reused, never re-minted (RFC 4568).
    near_text_local_crypto: Option<CryptoAttribute>,
    /// The engine's DTLS role on the far leg, kept unless B's re-offer forces the other one.
    far_dtls_role: Option<DtlsRole>,
}

/// Move `codec` to the head of `info`'s format list, so the codec machinery reads it as the
/// stream's primary codec. A no-op when `info` does not list it.
fn lead_with_codec(info: &mut sdp::MediaInfo, codec: &CodecSpec) {
    let Some(payload_type) = info
        .audio_codecs()
        .iter()
        .find(|offered| same_codec(offered, codec))
        .map(|offered| offered.payload_type)
    else {
        return;
    };
    if let Some(index) = info
        .payload_types
        .iter()
        .position(|&listed| listed == payload_type)
    {
        let payload_type = info.payload_types.remove(index);
        info.payload_types.insert(0, payload_type);
    }
}

/// The engine's `a=setup` for the DTLS role it plays (RFC 4145 §4): the client is `active`, the
/// server `passive`.
fn setup_for_role(role: DtlsRole) -> sdp::Setup {
    match role {
        DtlsRole::Client => sdp::Setup::Active,
        DtlsRole::Server => sdp::Setup::Passive,
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    #[expect(clippy::too_many_lines, reason = "debt: to be split")]
    pub(super) async fn answer(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        to_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        if let Err(reason) = crate::media_pipeline::validate_echo_delay_search_ms(profile) {
            return CmdResult::Error {
                reason: format!("answer: {reason}"),
            };
        }
        // Which exchange this answer completes. Usually B answering an offer or re-offer from A, with
        // the tags as the call has them. The other is A answering a re-offer from B, which arrives with
        // the dialog's tags reversed (`from_tag` is B's, `to_tag` is A's) and is accepted only while a
        // re-offer from B is outstanding, so a stray reversed answer cannot rewrite a live call. Only
        // the owning client may answer (A3 — docs/security-and-nat.md §5); to anyone else the call is
        // unknown.
        let far_reoffer_sdp = match self.calls.get(call_id) {
            Some(call) if call.owner == client => {
                if call.from_tag == from_tag {
                    None
                } else if call.to_tag.as_deref() == Some(from_tag) && call.from_tag == to_tag {
                    let Some(far_reoffer_sdp) = call.pending_far_reoffer.clone() else {
                        return CmdResult::Error {
                            reason:
                                "answer carries the dialog's tags reversed but no re-offer from \
                                     the far party is outstanding"
                                    .to_string(),
                        };
                    };
                    Some(far_reoffer_sdp)
                } else {
                    return CmdResult::Error {
                        reason: "from_tag mismatch on answer".to_string(),
                    };
                }
            }
            _ => return unknown_call(call_id),
        };
        // The answer's own `to_tag`, echoed back as given; from here on `from_tag`/`to_tag` are the
        // dialog's (A's and B's) whichever party is answering.
        let answer_to_tag = to_tag;
        let dialog_from_tag = if far_reoffer_sdp.is_some() {
            answer_to_tag.clone()
        } else {
            from_tag.to_string()
        };
        let to_tag = if far_reoffer_sdp.is_some() {
            from_tag.to_string()
        } else {
            answer_to_tag.clone()
        };
        let from_tag: &str = &dialog_from_tag;

        let answered = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer SDP parse failed: {error}"),
                }
            }
        };
        // `info` is the **far** party's SDP for the rest of this function, whichever way round the
        // exchange ran: B's answer usually, B's re-offer when A is answering it. Everything below that
        // wires the media path reads B's side from `info` and A's side from the call.
        let (info, reversed) = match far_reoffer_sdp {
            None => (answered, None),
            Some(far_reoffer_sdp) => {
                let mut far = match sdp::parse(&far_reoffer_sdp) {
                    Ok(info) => info,
                    Err(error) => {
                        return error_result("answer: re-offer from the far party", &error);
                    }
                };
                // A's answer is A's new state: record it on A's leg, exactly as a re-offer from A
                // records A's offer. Its `received-from` is the address A's answer arrived from.
                let Some(mut call) = self.calls.get_mut(call_id) else {
                    return unknown_call(call_id);
                };
                call.near.remote_rtp = Some(answered.remote_rtp);
                call.near.remote_rtcp = Some(answered.remote_rtcp);
                let answered_codecs = answered.audio_codecs();
                if !answered_codecs.is_empty() {
                    call.near_offered_codecs = answered_codecs;
                }
                if let Some(telephone_event) = answered.telephone_event_payload_type() {
                    call.near_telephone_event = Some(telephone_event);
                }
                // A's answer states A's own direction — this is how A accepts (or declines) a hold B
                // asked for. `far_direction` needs nothing here: `info` below is B's re-offer, i.e. B's
                // own SDP, so the single write at the end of `answer` is right whichever way round the
                // exchange ran.
                call.near_direction = answered.direction;
                call.near_remote_ice = peer_ice_credentials(&answered);
                call.near_remote_candidates = answered.candidates.clone();
                call.near_peer_is_lite = answered.ice_lite;
                if profile.received_from.is_some() {
                    call.offer_received_from = profile.received_from;
                }
                if let Some(text) = answered
                    .text
                    .as_ref()
                    .filter(|text| text.remote_rtp.port() != 0)
                {
                    call.near.text_remote_rtp = Some(text.remote_rtp);
                    if let Some(key) = text.crypto.first().filter(|_| text.secure) {
                        call.near_text_remote_crypto = Some(*key);
                    }
                }
                // Each party stays on the codec it negotiated. On a relay both share one, and it is
                // the one A's answer selected from B's list (RFC 3264 §6.1); on a transcode A was shown
                // only its own codec, so B's is the one B already had. Leading B's list with it lets
                // the codec machinery below read it as B's primary, so the pipeline decision does not
                // move on a renegotiation that changes no codec.
                let transcoding = matches!(
                    call.pipeline,
                    PipelineKind::Media | PipelineKind::SrtpMedia | PipelineKind::DtlsMedia
                );
                let far_codec = match answered.primary_codec() {
                    Some(selected)
                        if !transcoding
                            && far
                                .audio_codecs()
                                .iter()
                                .any(|offered| same_codec(offered, &selected)) =>
                    {
                        Some(selected)
                    }
                    _ => call.far_codec.clone(),
                };
                if let Some(far_codec) = far_codec.as_ref() {
                    lead_with_codec(&mut far, far_codec);
                }
                let context = ReversedAnswer {
                    carries_text: answered.text.is_some(),
                    near_accepted_text: answered
                        .text
                        .as_ref()
                        .is_some_and(|text| text.remote_rtp.port() != 0),
                    near_text_local_crypto: call.near_text_local_crypto,
                    far_dtls_role: call.far_dtls_role,
                };
                drop(call);
                (far, Some(context))
            }
        };

        // Snapshot the leg endpoints under the guard, then release it.
        let (
            near,
            far,
            ice_creds,
            near_remote_ice,
            near_remote_candidates,
            near_peer_is_lite,
            near_local_candidates,
            far_local_candidates,
            far_local_crypto,
            near_local_crypto,
            near_remote_crypto,
            far_dtls,
            far_downgraded_to_plain,
            near_secure,
            near_codec,
            near_offered_codecs,
            near_codec_withheld,
            near_telephone_event,
            offer_pipeline,
            offer_received_from,
            stored_far_received_from,
            near_text_remote_crypto,
            far_text_local_crypto,
            text_t140_payload_type,
            text_red_payload_type,
            text_events,
        ) = match self.calls.get(call_id) {
            Some(call) if call.owner == client => {
                // A call the engine answered itself (`answer_local`) has no B-facing leg and no second
                // party to answer *with* — the caller is already talking to the single-leg pipeline on
                // the engine's only socket. Refuse plainly: relaying B's media onto that socket would
                // point leg B at the caller's own endpoint and break the live call.
                let Some(far) = call.far else {
                    return CmdResult::Error {
                        reason:
                            "call was answered locally (answer_local) and has no far leg to answer"
                                .to_string(),
                    };
                };
                (
                    call.near,
                    far,
                    call.ice.clone(),
                    call.near_remote_ice.clone(),
                    call.near_remote_candidates.clone(),
                    call.near_peer_is_lite,
                    call.near_local_candidates.clone(),
                    call.far_local_candidates.clone(),
                    call.far_local_crypto,
                    call.near_local_crypto,
                    call.near_remote_crypto,
                    call.far_dtls,
                    call.far_downgraded_to_plain,
                    call.near_secure,
                    call.near_codec.clone(),
                    call.near_offered_codecs.clone(),
                    call.near_codec_withheld,
                    call.near_telephone_event,
                    call.pipeline,
                    call.offer_received_from,
                    call.far_received_from,
                    call.near_text_remote_crypto,
                    call.far_text_local_crypto,
                    call.text_t140_payload_type,
                    call.text_red_payload_type,
                    call.text_events,
                )
            }
            _ => return unknown_call(call_id),
        };
        // The owner's async event sink (DTMF events flow here from the media actor), if registered.
        let owner_events = self.events.get(&client).map(|sink| sink.value().clone());
        // Cloned up front for the secure text actor: `owner_events` is moved into the audio pipeline's
        // actor registration below, so the secure-text branch (which registers its own text actor after
        // that) takes its event sink here. `Event::Text` flows only when the controller asked for it.
        let secure_text_events_sink = if text_events {
            owner_events.clone()
        } else {
            None
        };

        // RFC 3264 §6.1: B's answer selects the format, and that answer is relayed to A unmodified on
        // every non-transcoding pipeline — so if B picked something A offered, A sends it too and the
        // call is a plain relay. Adopt it as A's codec here, before anything reads `near_codec`: the
        // pipeline decision, the WebSocket bridge, the answer-side codec presentation and the CDR all
        // then name the codec A is really sending, instead of whichever one A happened to list first.
        let near_codec = negotiated_near_codec(
            &near_offered_codecs,
            near_codec,
            info.primary_codec().as_ref(),
            near_codec_withheld,
        );

        // rtpengine `received-from`: the real post-NAT source the SIP proxy saw each request come
        // from. A's hint (stored on the call: from its offer, refreshed by its re-offer or by its
        // answer to B's) tightens the near (A) leg's ingress gate; B's tightens the far (B) leg's. B's
        // is this answer's when B is answering and it carries one, and otherwise the one stored from B's
        // earlier answer or re-offer — so a renegotiation that omits it keeps gating a NATed B on its
        // public address instead of falling back to the private `c=` it signalled. Both keep the
        // signalled port and only override the gated source IP — every gate path below uses these
        // effective addresses so the source gate is uniform (docs/security-and-nat.md §4 layer 2).
        // `None` ⇒ the signalled address is used unchanged. The same pair is what the relay *aims* at
        // before the latch forms — see the destination bindings below.
        let far_received_from = if reversed.is_some() {
            stored_far_received_from
        } else {
            profile.received_from.or(stored_far_received_from)
        };
        let near_gate_rtp = apply_received_from(near.remote_rtp, offer_received_from);
        let near_gate_rtcp = apply_received_from(near.remote_rtcp, offer_received_from);
        let far_gate_rtp = apply_received_from(Some(info.remote_rtp), far_received_from)
            .unwrap_or(info.remote_rtp);
        let far_gate_rtcp = apply_received_from(Some(info.remote_rtcp), far_received_from)
            .unwrap_or(info.remote_rtcp);

        // Where each peer's media is *aimed* until its own first packet moves the latch — the same
        // (hint IP, signalled port) pair the gate keys on, deliberately. A `received-from` hint is the
        // proxy telling us the peer's signalling really arrived from that public address, so its media
        // almost certainly will too, while the private `c=` it advertised is unroutable: aiming there
        // put the answering party's audio into the void for the whole pre-latch window (~400 ms of a
        // NATed call at 20 ms ptime) and leaked RFC 1918 datagrams off the node.
        //
        // It is a better opening guess, not a guarantee — behind a symmetric NAT the public media port
        // need not be the signalled one, and that port on the NAT may even belong to another device.
        // That is precisely why it stays confined to the pre-latch window and never becomes a latch
        // substitute: the latch still governs from the first *accepted* packet onward, and the gate is
        // unchanged, so nothing here widens what the engine will accept (docs/security-and-nat.md §4
        // layer 2). Without a hint these are the signalled addresses unchanged.
        let near_media_dst = near_gate_rtp;
        let near_rtcp_dst = near_gate_rtcp;
        let far_media_dst = far_gate_rtp;
        let far_rtcp_dst = far_gate_rtcp;

        // Resolve how this call's media is carried — an SRTP bridge (secure far leg), the userspace
        // media slow path (transcode / record), or the in-datapath plain relay — before the SDP is
        // presented, because a transcoding call presents each party only its own codec.
        let pipeline = resolve_pipeline(
            near_codec.as_ref(),
            &info,
            profile,
            far_local_crypto,
            near_local_crypto,
            far_dtls,
        );
        // A secure offerer is terminated only in the crypto-bridge shape. Every other combination
        // would have to thread A's `SecureLeg` onto the A-facing directions of the media actor — the
        // other half of this work — and until it exists the honest answer is a refusal, not a call
        // that answers `ok` and relays A's audio somewhere it should not go. `resolve_pipeline`
        // already picked the shape, so this reads its verdict rather than re-deriving the conditions.
        if near_local_crypto.is_some() && pipeline != PipelineKind::SrtpOfferer {
            let why = if far_dtls || far_local_crypto.is_some() {
                "both parties are secure, which needs a transcrypt between two different keys"
            } else {
                "the two legs' codecs differ, which needs the secure offerer's leg threaded into \
                 the transcoding pipeline"
            };
            return CmdResult::Error {
                reason: format!(
                    "answer: secure-offerer-unsupported: {why}; a secure caller toward a plain \
                     callee on a shared codec is supported"
                ),
            };
        }
        // rtpengine `ptime=<N>` override: force the packetization of the synthesized (transcoded)
        // egress toward both parties. Overriding the negotiated codec ptime here is the single source
        // of truth — it flows to the egress encoder's frame size and the repacketizer (the RTP cadence,
        // RFC 3550 §5.1), to the SDP `a=ptime` presented on a transcoding call, and to the HA snapshot
        // (so a restore rebuilds at the same ptime). Inert on a plain relay / bridge (which forward RTP
        // verbatim and never re-encode); only a transcoding pipeline can re-frame.
        let ptime_override = parse_ptime_override(&profile.flags);
        // A WS-bridged call has no B leg to relay to (the WS server is A's far side); it never
        // transcodes A↔B, so its answer is never codec-rewritten.
        let becoming_ws = offer_pipeline == PipelineKind::Ws || profile.ws_uri.is_some();
        let transcoding = !becoming_ws
            && matches!(
                pipeline,
                PipelineKind::Media | PipelineKind::SrtpMedia | PipelineKind::DtlsMedia
            );

        // Each leg's ICE candidates: the near leg's are what A was (or is now being) shown, the far
        // leg's what B was offered. Gathered the first time a leg is presented — for the same reason
        // the far leg's were at offer, the SDP carrying them is the complete list that party will ever
        // see from us — and re-used after that, since the ports never move.
        let (near_ice_candidates, far_ice_candidates) = match ice_creds.as_ref() {
            Some(creds) => (
                self.leg_candidates(&near, &near_local_candidates, creds)
                    .await,
                self.leg_candidates(&far, &far_local_candidates, creds)
                    .await,
            ),
            None => (Vec::new(), Vec::new()),
        };
        // RFC 4103 text: relay the stream when it was anchored at offer (both legs hold a text
        // endpoint) AND both parties kept a matching stream (a non-zero `m=text` port). A party
        // declining (port 0), or a secure/plaintext mismatch, declines the text in the SDP this answer
        // presents too (`m=text 0`, RFC 3264 §6) — never bridged. A call turning into a WS leg here
        // declines any text anchored at offer rather than advertising a text port it will not serve.
        //
        // Whether A offered a secure (SDES-SRTP) text stream we anchored: both its own text key (A's,
        // from the offer) and the engine's far text key (minted at offer) are present iff we did.
        let a_offered_secure_text =
            near_text_remote_crypto.is_some() && far_text_local_crypto.is_some();
        // When A is the one answering (B's re-offer), A must have kept the stream too.
        let near_kept_text = reversed
            .as_ref()
            .is_none_or(|reversed| reversed.near_accepted_text);
        // Secure text is accepted only when A offered it AND B's SDP carries a secure text stream with
        // a usable `a=crypto` on a non-zero port. A mixed case (A secure / B plaintext, or A plaintext /
        // B secure) is refused below (declined), never bridged — the "never silently bridge
        // secure↔insecure" rule (docs/security-and-nat.md Layer 5/5d).
        let secure_text_accepted = !becoming_ws
            && near_kept_text
            && a_offered_secure_text
            && near.text.is_some()
            && far.text.is_some()
            && info.text.as_ref().is_some_and(|text| {
                text.secure && !text.crypto.is_empty() && text.remote_rtp.port() != 0
            });
        // Plaintext text is accepted only when A did NOT offer secure text (else it would be a downgrade
        // of A's secure offer) and B's SDP carries a plaintext stream on a non-zero port.
        let text_accepted = !becoming_ws
            && near_kept_text
            && !a_offered_secure_text
            && info
                .text
                .as_ref()
                .is_some_and(|text| !text.secure && text.remote_rtp.port() != 0);
        // The engine's own near text SDES key (RFC 4568), used below to build the near text
        // `SecureLeg`. Minted for an answer to A, which advertises it as `RTP/SAVP` + `a=crypto`; when
        // A is answering B's re-offer, A was already shown the stored one and answered against it, so
        // that one is kept — failing closed rather than keying a stream A cannot decrypt.
        let near_text_local_crypto = match (reversed.as_ref(), secure_text_accepted) {
            (_, false) => None,
            (Some(reversed), true) => match reversed.near_text_local_crypto {
                Some(crypto) => Some(crypto),
                None => {
                    return error_result(
                        "answer secure text",
                        &"the re-offer A answered carried no engine near text a=crypto",
                    )
                }
            },
            (None, true) => match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                Ok(crypto) => Some(crypto),
                Err(error) => return error_result("answer: generate text SDES key", &error),
            },
        };
        // The engine's DTLS role on a DTLS-SRTP far leg. Answering B, the engine is the offerer and
        // takes the complement of B's `a=setup` (RFC 5763 §5): a `passive` peer makes it the client,
        // anything else the server. A answering B's re-offer makes the engine B's answerer: to
        // `active` or `passive` it takes the complement (RFC 4145 §4.1), and to `actpass` it keeps the
        // role in force — a change of negotiated roles is a new association (RFC 8842 §3.1).
        let dtls_role = match (reversed.as_ref(), info.setup) {
            (None, Some(sdp::Setup::Passive)) => DtlsRole::Client,
            (None, _) => DtlsRole::Server,
            (Some(_), Some(sdp::Setup::Active)) => DtlsRole::Server,
            (Some(_), Some(sdp::Setup::Passive)) => DtlsRole::Client,
            (Some(reversed), _) => reversed.far_dtls_role.unwrap_or(DtlsRole::Server),
        };
        // RFC 5761: each leg's mux state was fixed at offer — its companion RTCP endpoint exists iff it
        // is non-muxed. When a `rtcp-mux` directive drove that decision, present it explicitly so the
        // SDP matches the ports the engine actually bound; otherwise mirror the input (`None`).
        let mux_directive = !profile.rtcp_mux.is_empty();
        // A transcoding call sends each party its own codec, so the SDP it is presented must advertise
        // that codec, never leak the other party's (RFC 3264 §6). A plain relay / SRTP bridge / WS leg
        // shares one codec across both sides, so its SDP already presents it — left untouched.
        let presented_codec = match reversed.as_ref() {
            None => near_codec.as_ref().map(|codec| {
                (
                    with_ptime_override(codec, ptime_override),
                    near_telephone_event,
                )
            }),
            Some(_) => info.primary_codec().map(|codec| {
                (
                    with_ptime_override(&codec, ptime_override),
                    info.telephone_event_payload_type(),
                )
            }),
        };
        let codec = match presented_codec.as_ref() {
            Some((codec, telephone_event)) if transcoding => CodecPresentation::Own {
                codec,
                telephone_event: *telephone_event,
            },
            _ => CodecPresentation::AsReceived,
        };

        let presentation = match reversed.as_ref() {
            // B answered: this SDP is delivered to A, so it presents the near leg — with the same
            // advertised IP the offer picked for it (the near interface's advertised address). On a
            // secure (SDES or DTLS) far leg A's side is plain.
            None => LegPresentation {
                engine: near.engine_media(),
                ice: answer_ice_rewrite(ice_creds.as_ref(), &near_ice_candidates),
                security: near_security(near_local_crypto, far_local_crypto.is_some() || far_dtls),
                mux_override: mux_directive.then_some(near.rtcp.is_none()),
                text: if near.text.is_none() {
                    TextRewrite::None
                } else if secure_text_accepted {
                    near.text_anchor(near_text_local_crypto)
                        .unwrap_or(TextRewrite::Decline)
                } else if text_accepted && far.text.is_some() {
                    near.text_anchor(None).unwrap_or(TextRewrite::Decline)
                } else {
                    // A was offered text but B did not accept a matching stream (declined, mixed, or
                    // WS) — decline it back to A (`m=text 0`, RFC 3264 §6), never downgraded or mixed.
                    TextRewrite::Decline
                },
                codec,
            },
            // A answered B's re-offer: this SDP is delivered to B, so it presents the far leg as the
            // original offer did, in an answer's terms — the engine's DTLS role in force rather than
            // `actpass`, and its own SDES key under the tag of the line B's re-offer is keyed from
            // (RFC 4568 §5.1.2: the answer echoes the chosen line's tag).
            Some(reversed) => {
                let dtls = if far_dtls {
                    let Some(fingerprint) = self.engine_fingerprint() else {
                        return error_result("DTLS-SRTP answer", &"engine has no DTLS certificate");
                    };
                    Some((fingerprint, setup_for_role(dtls_role)))
                } else {
                    None
                };
                let under_offered_tag =
                    |local: CryptoAttribute, offered: Option<&CryptoAttribute>| CryptoAttribute {
                        tag: offered.map_or(local.tag, |offered| offered.tag),
                        ..local
                    };
                let far_crypto =
                    far_local_crypto.map(|local| under_offered_tag(local, info.crypto.first()));
                let far_text_crypto = far_text_local_crypto.map(|local| {
                    under_offered_tag(
                        local,
                        info.text.as_ref().and_then(|text| text.crypto.first()),
                    )
                });
                LegPresentation {
                    engine: far.engine_media(),
                    ice: answer_ice_rewrite(ice_creds.as_ref(), &far_ice_candidates),
                    security: far_security(far_downgraded_to_plain, dtls, far_crypto),
                    mux_override: mux_directive.then_some(far.rtcp.is_none()),
                    text: if far.text.is_none() {
                        // No far text endpoint to anchor A's text to, and passing it through would
                        // hand B A's own text address.
                        if reversed.carries_text {
                            TextRewrite::Decline
                        } else {
                            TextRewrite::None
                        }
                    } else if secure_text_accepted {
                        far.text_anchor(far_text_crypto)
                            .unwrap_or(TextRewrite::Decline)
                    } else if text_accepted && near.text.is_some() {
                        far.text_anchor(None).unwrap_or(TextRewrite::Decline)
                    } else {
                        TextRewrite::Decline
                    },
                    codec,
                }
            }
        };
        let rewritten = match present_leg(sdp, presentation, &profile.replace, call_id) {
            Ok(rewritten) => rewritten,
            Err(error) => {
                return CmdResult::Error {
                    reason: format!("answer SDP rewrite failed: {error}"),
                }
            }
        };

        // WebSocket bridge: if this call is (or is now being) bridged to a WS media server, leg A's
        // audio is already (or now) pumped to the WS — the A↔B relay/transcode path is deliberately
        // not wired (the WS server is A's far side). The bridge is normally stood up at offer; honour
        // `ws_uri` arriving first at answer too (set it up against A's stored codec/address).
        let already_ws = offer_pipeline == PipelineKind::Ws;
        if already_ws || profile.ws_uri.is_some() {
            if !already_ws {
                let Some(signalled) = near.remote_rtp else {
                    return error_result("ws bridge", &"near leg has no signalled address");
                };
                // Aim the downlink at leg A's offer `received-from` public IP when one was supplied,
                // and gate its ingress on the same address — identical to the offer path.
                let a_rtp = near_gate_rtp.unwrap_or(signalled);
                if let Some(ws_uri) = profile.ws_uri.clone() {
                    // The same refusal the offer path makes, for a `ws_uri` that arrives first at
                    // answer: this answer is rewritten from B's SDP, so a secure offerer would get no
                    // engine keying and an ICE offerer no agent to re-point the bridge's egress —
                    // either way the takeover would terminate nothing. (`near_secure` and the near
                    // leg's ICE credentials were both captured at offer.)
                    if near_secure {
                        return CmdResult::Error {
                            reason: "answer: ws-takeover-secure-offerer: a WebSocket takeover \
                                     (ws_uri) on a secure (SRTP) offerer is not supported on \
                                     offer/answer — the answer to the offerer cannot carry the \
                                     engine's own keying; use answer_local"
                                .to_string(),
                        };
                    }
                    if ice_creds.is_some() {
                        return CmdResult::Error {
                            reason:
                                "answer: ws-takeover-ice-offerer: a WebSocket takeover (ws_uri) \
                                     on an ICE offerer is not supported on offer/answer — no ICE \
                                     agent is armed for a takeover leg here, so its downlink would \
                                     never follow the selected pair; use answer_local, or \
                                     ICE=remove to drop ICE"
                                    .to_string(),
                        };
                    }
                    if let Err(reason) = self
                        .setup_ws_bridge(WsBridgeSetup {
                            call_id,
                            ws_uri: &ws_uri,
                            endpoint_a: near.rtp.id,
                            a_rtp,
                            codec: near_codec.as_ref(),
                            accepted_source: bridge_source_filter(profile, a_rtp),
                            // Refused above for both shapes that would need them.
                            ice_pending: false,
                            secure: None,
                            noise_suppression: profile.noise_suppression,
                            echo: crate::media_pipeline::EchoProfile::from_profile(profile),
                            vad_config: WsVadConfig::from_profile(profile),
                            wire_sample_rate: profile.ws_sample_rate,
                            egress: None,
                            takeover: None,
                            socket: None,
                        })
                        .await
                    {
                        return error_result("ws bridge", &reason);
                    }
                }
            }
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.to_tag = Some(to_tag.clone());
                // The far leg is present — this path ran only because the guard above unwrapped it.
                if let Some(far) = call.far.as_mut() {
                    far.remote_rtp = Some(info.remote_rtp);
                    far.remote_rtcp = Some(info.remote_rtcp);
                }
                call.pipeline = PipelineKind::Ws;
                call.far_received_from = far_received_from;
                call.pending_far_reoffer = None;
                call.near_local_candidates = near_ice_candidates;
            }
            return ok_sdp(rewritten, Some(answer_to_tag));
        }

        // ICE applies to a leg only when both ends use it: `near` faces A (which offered ICE iff we
        // minted creds), `far` faces B (ICE iff its answer carries ICE).
        let near_ice = ice_creds.is_some();
        let far_ice = ice_creds.is_some() && info.is_ice();

        // Enable the ICE connectivity-check responder on the endpoints facing an ICE peer *before*
        // any relay flow is installed, so an ICE leg is STUN-gated from its first packet — the
        // datapath's layer-4 gate then forwards media only from a validated source and a Forward flow
        // is never live with a blind-latch window (docs/security-and-nat.md §4 layer 4; RFC 8445).
        // Endpoints on which a full ICE agent ends up running — consulted later by the DTLS plan,
        // which must hold its handshake for a selection only when one is actually coming.
        let mut agent_endpoints: Vec<EndpointId> = Vec::new();
        if let Some(creds) = &ice_creds {
            let config = IceConfig {
                local_ufrag: creds.ufrag.clone(),
                local_pwd: creds.pwd.clone(),
            };
            // `near` faces A (which offered ICE); enable the responder on its RTP and, under
            // non-mux, its companion RTCP endpoint. `far` faces B; enable only when B also offered
            // ICE. With consent freshness on, each side is promoted to the datapath's **full-agent**
            // seam instead (responder + STUN forwarding) and registered with the credentials of the
            // peer *that* side faces — an outbound check is signed with the peer's password, so the
            // two legs are not interchangeable (RFC 8445 §7.1.2).
            let far_remote_ice = if info.ice_mismatch {
                // RFC 8839 §5.3: B says our offer's ICE reached it altered, so ICE is unusable on that
                // leg. Treat B as non-ICE — the endpoints below are cleared and the leg falls back to
                // the signalled-source gate.
                tracing::info!(
                    target: "siphon_rtp::control",
                    %call_id,
                    "peer answered a=ice-mismatch (RFC 8839 §5.3) — running the far leg without ICE"
                );
                None
            } else {
                peer_ice_credentials(&info)
            };
            if !info.is_ice() || info.ice_mismatch {
                // B answered without ICE. Gathering at offer time installed the responder on the far
                // endpoints (that is how it received its own Binding responses), and leaving it there
                // would arm the layer-4 gate — which forwards media *only* from a STUN-validated
                // source — on a leg that will never send a check, blackholing B's media. Clear it, so
                // the far leg falls back to the signalled-source gate like any non-ICE leg.
                for endpoint in far.endpoint_ids() {
                    self.datapath.set_ice(endpoint, None);
                }
            }
            let sides = [
                (near.endpoint_ids().collect::<Vec<_>>(), &near_remote_ice),
                (
                    if info.is_ice() && !info.ice_mismatch {
                        far.endpoint_ids().collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    },
                    &far_remote_ice,
                ),
            ];
            // RFC 8445 §6.1.1: the offerer of the exchange controls, unless it is a lite agent, which
            // never can. B answering: A offered, so A controls the near leg (we control it only when A
            // is lite), and we offered to B, so we control the far leg either way. A answering B's
            // re-offer is the same rule the other way round: B controls the far leg unless it is lite,
            // and we offered B's re-offer to A, so we control the near leg.
            let (near_controlling, far_controlling) = if reversed.is_some() {
                (true, info.ice_lite)
            } else {
                (near_peer_is_lite, true)
            };
            // Full RFC 8445 agent, when the operator enabled it and this side's peer gave us both
            // credentials and candidates. It supersedes consent on that side: a full agent runs its
            // own checks, and RFC 7675 consent is what a *lite* agent does instead.
            let full_ice_sides = [
                (
                    near.endpoint_ids().collect::<Vec<_>>(),
                    &near_remote_ice,
                    &near_remote_candidates,
                    &near_ice_candidates,
                    near_controlling,
                ),
                (
                    if info.is_ice() && !info.ice_mismatch {
                        far.endpoint_ids().collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    },
                    &far_remote_ice,
                    &info.candidates,
                    &far_ice_candidates,
                    far_controlling,
                ),
            ];
            if let Some(agents) = &self.ice_agents {
                for (endpoints, remote, remote_candidates, local_candidates, controlling) in
                    full_ice_sides
                {
                    let (Some(remote), false) = (remote, remote_candidates.is_empty()) else {
                        continue;
                    };
                    for endpoint in endpoints {
                        let Some(local_addr) = self.endpoint_address(endpoint) else {
                            continue;
                        };
                        // Only this endpoint's own component takes part in its checklist.
                        let component = if endpoint == near.rtp.id || endpoint == far.rtp.id {
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
                            controlling,
                            ice_tie_breaker(),
                        )
                        .with_candidates(
                            filter_component(local_candidates, component),
                            filter_component(remote_candidates, component),
                        );
                        self.datapath.set_ice_agent(
                            endpoint,
                            config.clone(),
                            // The agent owns request handling: answering needs the role (§7.3.1.1),
                            // the checklist (§7.3.1.3) and the nomination flag (§7.3.1.5), none of
                            // which the datapath has. It is also then the only thing that may adopt a
                            // source, so media cannot start before ICE has chosen a pair.
                            IceAgentMode::ForwardOnly,
                            agents.events(),
                        );
                        agents.register(endpoint, call_id, local_addr, agent_config, 0);
                        agent_endpoints.push(endpoint);
                    }
                }
            }

            for (endpoints, remote) in sides {
                for endpoint in endpoints {
                    if agent_endpoints.contains(&endpoint) {
                        continue; // a full agent already owns this endpoint
                    }
                    match (&self.consent, remote) {
                        (Some(consent), Some(remote)) => {
                            self.datapath.set_ice_agent(
                                endpoint,
                                config.clone(),
                                // Consent is a lite-agent behaviour: the datapath keeps answering
                                // checks, and the sink exists only so Binding *responses* reach the
                                // checker (RFC 7675 §4).
                                IceAgentMode::RespondAndForward,
                                consent.events(),
                            );
                            consent.register(
                                endpoint,
                                call_id,
                                &creds.ufrag,
                                &remote.ufrag,
                                &remote.pwd,
                            );
                        }
                        // Consent is off, or this peer signalled ICE without usable credentials:
                        // the ice-lite responder alone (RFC 7675 §4 — a lite agent answers checks
                        // and never initiates them).
                        _ => self.datapath.set_ice(endpoint, Some(config.clone())),
                    }
                }
            }
        }

        // The `ptime=<N>` override (resolved with the pipeline, above) applied to A's codec from here on.
        let near_codec = near_codec.map(|codec| with_ptime_override(&codec, ptime_override));
        let wiring = AnswerWiring {
            call_id,
            from_tag,
            to_tag: &to_tag,
            profile,
            info: &info,
            near,
            far,
            near_gate_rtp,
            near_gate_rtcp,
            far_gate_rtp,
            far_gate_rtcp,
            near_media_dst,
            near_rtcp_dst,
            far_media_dst,
            far_rtcp_dst,
            near_ice,
            far_ice,
            near_codec: near_codec.as_ref(),
            near_telephone_event,
            ptime_override,
            dtls_role,
            agent_endpoints: &agent_endpoints,
        };
        // For a passthrough relay, remember the installed forward actions so `block` can flip the
        // endpoints to `Drop` and `unblock` can restore them.
        let relay_flows = match self.install_answer_pipeline(
            pipeline,
            &wiring,
            far_local_crypto,
            near_local_crypto,
            near_remote_crypto,
            owner_events,
        ) {
            Ok(flows) => flows,
            Err(result) => return *result,
        };

        // RFC 4103 text relay — a second stream, wired independently of the audio pipeline kind (its
        // endpoints are distinct, so it relays whether audio is a plain relay, transcode, or SRTP
        // bridge). When both legs hold a text endpoint and B accepted a plaintext stream, install the
        // in-datapath Forward flows `near.text ↔ far.text`. Each direction carries its OWN RTPBleed
        // source-gate + symmetric latch (`ingress_rule` — the same defence the audio relay uses; the
        // gate is per-stream, docs/security-and-nat.md §4). Text is forwarded verbatim (RED/T.140 is
        // not parsed in PR 1). Text does not use ICE here (`ice = false`).
        let mut far_text_remote = None;
        // The two installed text `Forward` flows (near text, then far text), kept so a text-observability
        // feature can promote the text stream to userspace and demote it back to these (mirrors the audio
        // `relay_flows`). Empty when no plaintext text stream was negotiated.
        let mut text_relay_flows: Vec<(EndpointId, FlowAction)> = Vec::new();
        if let (Some(near_text), Some(far_text), Some(b_text)) =
            (near.text, far.text, info.text.as_ref())
        {
            // `text_accepted` already excludes a secure-text offer (no plaintext downgrade) and a WS
            // takeover; only a genuine plaintext↔plaintext stream installs the in-kernel `Forward` relay.
            if text_accepted && !b_text.secure && b_text.remote_rtp.port() != 0 {
                let b_text_rtp = b_text.remote_rtp;
                far_text_remote = Some(b_text_rtp);
                // Gate each side's text ingress to its signalled source, tightened to the
                // `received-from` public IP when the proxy supplied one, and aim each direction at
                // that same effective address until the latch forms (the audio-leg posture).
                let near_text_gate = apply_received_from(near.text_remote_rtp, offer_received_from);
                let far_text_gate = apply_received_from(Some(b_text_rtp), profile.received_from)
                    .unwrap_or(b_text_rtp);
                let near_text_action = FlowAction::Forward(ingress_rule(
                    far_text.id,
                    Some(far_text_gate),
                    near_text_gate,
                    profile,
                    false,
                ));
                if let Err(error) = self.datapath.install_flow(near_text.id, near_text_action) {
                    return error_result("install near->far text flow", &error);
                }
                let far_text_action = FlowAction::Forward(ingress_rule(
                    near_text.id,
                    near_text_gate,
                    Some(far_text_gate),
                    profile,
                    false,
                ));
                if let Err(error) = self.datapath.install_flow(far_text.id, far_text_action) {
                    return error_result("install far->near text flow", &error);
                }
                text_relay_flows.push((near_text.id, near_text_action));
                text_relay_flows.push((far_text.id, far_text_action));
            }
        }

        // RFC 4103 SECURE text (SDES-SRTP) — the per-leg `SecureLeg` bridge. Unlike the plaintext relay
        // it cannot run in-kernel (SRTP must be terminated in userspace), so it is registered on the
        // text processor from the start: both text endpoints `Redirect`ed, one `SecureLeg` per leg with
        // its OWN SDES keys (near = engine↔A, far = engine↔B), and held there for the call's life
        // (docs/security-and-nat.md Layer 5d — mirrors the audio SDES bridge). A→B text is decrypted on
        // the near leg and re-encrypted on the far leg (and B→A the reverse), so the two sides re-key
        // independently and no plaintext ever crosses to a secure peer. A mixed secure/plaintext text
        // bridge was refused above (declined), never keyed here.
        let mut secure_text_registered = false;
        if secure_text_accepted {
            if let (
                Some(near_text),
                Some(far_text),
                Some(b_text),
                Some(near_local),
                Some(near_remote),
                Some(far_local),
                Some(a_text_dst),
            ) = (
                near.text,
                far.text,
                info.text.as_ref(),
                near_text_local_crypto,
                near_text_remote_crypto,
                far_text_local_crypto,
                near.text_remote_rtp,
            ) {
                if let Some(far_remote) = b_text.crypto.first().copied() {
                    let b_text_rtp = b_text.remote_rtp;
                    far_text_remote = Some(b_text_rtp);
                    // Same per-stream source gate + symmetric-latch posture as the plaintext text relay
                    // and the audio SDES bridge: gate each side to its signalled source, tightened to the
                    // `received-from` public IP when the proxy supplied one, and aim each direction at
                    // that same effective address until the latch forms (docs/security-and-nat.md §4).
                    let near_text_gate =
                        apply_received_from(near.text_remote_rtp, offer_received_from);
                    let far_text_gate =
                        apply_received_from(Some(b_text_rtp), profile.received_from)
                            .unwrap_or(b_text_rtp);
                    let near_rule = ingress_rule(
                        far_text.id,
                        Some(far_text_gate),
                        near_text_gate,
                        profile,
                        false,
                    );
                    let far_rule = ingress_rule(
                        near_text.id,
                        Some(near_text_gate.unwrap_or(a_text_dst)),
                        Some(far_text_gate),
                        profile,
                        false,
                    );
                    let latch =
                        near_rule.latch != LatchPolicy::Off || far_rule.latch != LatchPolicy::Off;
                    // One `SecureLeg` per text leg (its own SDES keys), each shared by both directions —
                    // exactly as the audio bridge shares a leg's contexts (single-owner actor ⇒ the
                    // `Mutex` is uncontended).
                    // Carry the live legs' SRTP rollover into the rebuilt ones (RFC 3711 §3.3.1) — a
                    // renegotiation re-registers the text actor, and restarting either counter at 0
                    // breaks a stream that has already run past a sequence wrap, exactly as it does
                    // on the audio legs above.
                    let previous_rollover = self.text.rollover_snapshots(call_id);
                    let mut near_secure = SecureLeg::new(&near_local.key, &near_remote.key);
                    let mut far_secure = SecureLeg::new(&far_local.key, &far_remote.key);
                    if let Some((near_rollover, far_rollover)) = previous_rollover.as_ref() {
                        near_secure.seed_rollover(near_rollover);
                        far_secure.seed_rollover(far_rollover);
                    }
                    let near_leg = Arc::new(Mutex::new(near_secure));
                    let far_leg = Arc::new(Mutex::new(far_secure));
                    // Redirect both text endpoints so the dispatcher routes them to the text actor.
                    for endpoint in [near_text.id, far_text.id] {
                        if let Err(error) =
                            self.datapath.install_flow(endpoint, FlowAction::Redirect)
                        {
                            return error_result("install secure text redirect", &error);
                        }
                    }
                    let a_to_b = TextDirectionConfig {
                        ingress_endpoint: near_text.id,
                        accepted_source: near_rule.accepted_source,
                        egress_endpoint: far_text.id,
                        egress_dst: b_text_rtp,
                        t140_payload_type: text_t140_payload_type,
                        red_payload_type: text_red_payload_type,
                        secure_ingress: Some(near_leg.clone()), // decrypt A's ingress
                        secure_egress: Some(far_leg.clone()),   // encrypt egress toward B
                    };
                    let b_to_a = TextDirectionConfig {
                        ingress_endpoint: far_text.id,
                        accepted_source: far_rule.accepted_source,
                        egress_endpoint: near_text.id,
                        egress_dst: a_text_dst,
                        t140_payload_type: text_t140_payload_type,
                        red_payload_type: text_red_payload_type,
                        secure_ingress: Some(far_leg), // decrypt B's ingress
                        secure_egress: Some(near_leg), // encrypt egress toward A
                    };
                    let text_call = TextCall::new(
                        call_id,
                        from_tag,
                        Some(to_tag.clone()),
                        a_to_b,
                        b_to_a,
                        latch,
                    );
                    // Event::Text flows only when the controller asked for it (parity with the plaintext
                    // path); the CDR content QoS accrues regardless (read via `final_counters`).
                    self.text
                        .register(text_call, self.datapath.clone(), secure_text_events_sink);
                    secure_text_registered = true;
                }
            }
        }

        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.to_tag = Some(to_tag.clone());
            // The far leg is present — this path ran only because the guard above unwrapped it.
            if let Some(far) = call.far.as_mut() {
                far.remote_rtp = Some(info.remote_rtp);
                far.remote_rtcp = Some(info.remote_rtcp);
                // The far side's signalled text address (its answer's `m=text`/`c=`), for the text
                // relay's reverse forward destination + gate anchor. `None` when no text was relayed.
                far.text_remote_rtp = far_text_remote;
            }
            // Store the *effective* (ptime-overridden) codecs so an HA checkpoint captures the override
            // and a restore rebuilds the transcode at the same packetization (inert for a plain relay).
            call.near_codec = near_codec.clone();
            call.far_codec = info
                .primary_codec()
                .map(|codec| with_ptime_override(&codec, ptime_override));
            // The far leg's RFC 4733 telephone-event PT from its answer, so `block DTMF` can gate leg
            // B's telephone-event even on a plain relay.
            call.far_telephone_event = info.telephone_event_payload_type();
            // B's own direction, for the idle reaper. This is where hold becomes visible on an answered
            // call: A offers `sendonly` and B answers `recvonly` (RFC 3264 §8.4), so neither party is
            // expected to send and the call is held rather than dead.
            call.far_direction = info.direction;
            call.pipeline = pipeline;
            call.relay_flows = relay_flows;
            // The in-kernel text `Forward` flows, kept so text observability can promote/demote the
            // text stream while the audio relay stays on its own fast path. Empty for a secure text
            // stream (it never runs in-kernel).
            call.text_relay_flows = text_relay_flows;
            // A secure (SDES-SRTP) text stream is now registered on the userspace text processor and
            // stays there for the call's life (SRTP cannot relay in-kernel): mark it and take a
            // permanent promotion hold so `release_text_hold` never demotes it back to the kernel.
            call.text_secure = secure_text_registered;
            if secure_text_registered {
                call.text_promotion_reasons.insert(PromotionReason::Secure);
                // Keep the engine's own near text SDES key (the one advertised to A in this answer) so a
                // re-offer from B re-presents the SAME `a=crypto` to A, never minting a new one (RFC
                // 4568). `near_text_local_crypto` is always `Some` once the secure text leg registered.
                call.near_text_local_crypto = near_text_local_crypto;
            }
            // The peer's SDES key (secure answer), kept so an HA checkpoint can re-key the bridge.
            call.far_remote_crypto = info.crypto.first().copied();
            // B's ICE credentials from its answer — what an outbound consent check to B is addressed
            // and signed with (RFC 8445 §7.1.2).
            call.far_remote_ice = peer_ice_credentials(&info);
            // B's hint as this answer resolved it, for the next renegotiation to keep or refresh.
            call.far_received_from = far_received_from;
            // What A has now been shown for the near leg, re-presented on a re-offer from B.
            call.near_local_candidates = near_ice_candidates;
            if far_dtls {
                call.far_dtls_role = Some(dtls_role);
            }
            // This answer completes whatever exchange was outstanding.
            call.pending_far_reoffer = None;
        }

        // Text observability trigger: if the controller asked for control-plane text events and a
        // plaintext text stream was negotiated, promote ONLY the text stream to the userspace text
        // processor now (the audio relay/transcode/SRTP path is untouched). Recording promotes text
        // independently at `start recording`. Best-effort — a promotion failure is logged and the call
        // still relays text in-kernel (PR-1 behaviour).
        self.maybe_promote_text_for_events(call_id).await;
        // Media-plane lifecycle: negotiation is complete — the call now relays or transcodes. The
        // pipeline kind tells an operator at a glance how the media is handled (Media/SrtpMedia
        // transcode, SRTP bridge, WS leg, or a plain Passthrough relay). Pairs with "call created".
        // `answered_by` is `near` when A answered a re-offer from B.
        let near_codec_name = near_codec
            .as_ref()
            .map(|codec| codec.encoding_name.as_str())
            .unwrap_or("-");
        let far_codec_name = info.primary_codec().map(|codec| codec.encoding_name);
        let (answered_by, answerer) = match reversed {
            Some(_) => (Party::Near, near.remote_rtp),
            None => (Party::Far, Some(info.remote_rtp)),
        };
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            to_tag = %to_tag,
            answered_by = answered_by.label(),
            answerer = %answerer.map_or_else(|| "-".to_string(), |address| address.to_string()),
            near_codec = near_codec_name,
            far_codec = far_codec_name.as_deref().unwrap_or("-"),
            pipeline = ?pipeline,
            "answer applied"
        );
        ok_sdp(rewritten, Some(answer_to_tag))
    }
}

/// Upper bound on a control-`ptime` override, in milliseconds.
///
/// The **same** ceiling the negotiated (SDP `a=ptime`) path uses, deliberately: the engine must not
/// answer one number to `a=ptime:60` and a different one to `ptime=60` on the control flag. It was
/// previously 40, justified by keeping the egress frame inside the transcode scratch buffer — that
/// rationale went away when those buffers were sized from [`OPUS_MAX_PTIME_MS`] (48 kHz × 120 ms ×
/// 2 channels), so all that remained was a second, lower, silent ceiling.
///
/// 120 ms is RFC 7587 §6.1's `maxptime` default for Opus and comfortably legal elsewhere (G.711 at
/// 120 ms is a 960-byte payload, well inside an MTU). RFC 4566 §6 makes ptime advisory in any case,
/// and how much one-way latency to trade for packet-rate is the operator's call — which is what the
/// control flag exists to express.
pub(super) const MAX_PTIME_OVERRIDE_MS: u8 = OPUS_MAX_PTIME_MS;

/// Parse rtpengine's `ptime=<N>` flag into an egress packetization override in milliseconds, clamped
/// to `1..=MAX_PTIME_OVERRIDE_MS`. `None` when the flag is absent or unparseable — the negotiated
/// (SDP `a=ptime`) packetization then stands. The first well-formed `ptime=` flag wins.
///
/// A clamp is logged rather than applied silently: a controller that asked for 200 ms and got 120
/// otherwise has no way to tell its request was not honoured.
pub(super) fn parse_ptime_override(flags: &[String]) -> Option<u8> {
    flags.iter().find_map(|flag| {
        flag.strip_prefix("ptime=")
            .and_then(|value| value.trim().parse::<u16>().ok())
            .filter(|&value| value >= 1)
            .map(|value| {
                if value > u16::from(MAX_PTIME_OVERRIDE_MS) {
                    tracing::warn!(
                        target: "siphon_rtp::control",
                        requested_ms = value,
                        clamped_ms = MAX_PTIME_OVERRIDE_MS,
                        "ptime override above the ceiling; clamping"
                    );
                }
                (value.min(u16::from(MAX_PTIME_OVERRIDE_MS))) as u8
            })
    })
}

/// Apply a `ptime` override to a codec: `Some(ms)` returns a clone repacketized to `ms`, `None`
/// leaves the negotiated ptime. Sample-based codecs (G.711/G.722/G.726/L16/CN) honour any ptime;
/// a frame-based codec (AMR) keeps its native 20 ms frame regardless (its encoder emits one fixed
/// frame), so the override is inert there — building the encoder from the returned spec is what
/// re-frames the codecs that honour it.
pub(super) fn with_ptime_override(codec: &CodecSpec, override_ms: Option<u8>) -> CodecSpec {
    match override_ms {
        Some(ptime_ms) => {
            let mut overridden = codec.clone();
            overridden.ptime_ms = ptime_ms.max(1);
            overridden
        }
        None => codec.clone(),
    }
}

/// The codec leg A ends up actually sending, given the codecs A offered (`offered`, captured at offer),
/// A's first-listed one (`primary`) and the one B selected in its answer (`answered`).
///
/// RFC 3264 §6.1: the **answerer** picks the format for the stream. Every non-transcoding pipeline
/// relays B's answer to A byte-for-byte, so when B selects a codec A offered, both parties end up on
/// *that* codec and the call is a plain relay — the payload type, clock rate and parameters A will use
/// are precisely the ones in the answer, which is why the answer's spec is adopted wholesale rather
/// than A's own entry for the same codec.
///
/// Holding A to the codec it happened to list first instead would force a needless transcode on any
/// call whose answerer picked a lower preference (a G.722-first offer answered as G.711 is transcoded
/// for nothing), and would fail the call outright when A's first choice is a codec the engine has no
/// implementation for (a G.729-first offer answered as G.711: `decoder_for("G729")` is `Unsupported`,
/// so the whole answer is rejected even though nothing needed to be decoded).
///
/// The transcoder engages only where the two sides genuinely diverge: B answered a codec A never
/// offered (reachable only when `codec-transcode` put a codec in the far offer that was not in A's),
/// or `withheld_from_far` says the profile removed A's own codec from what B saw (`codec-mask` /
/// `codec-consume`). There A keeps its own primary codec and the engine bridges the two, which is what
/// those flags exist to ask for.
pub(super) fn negotiated_near_codec(
    offered: &[CodecSpec],
    primary: Option<CodecSpec>,
    answered: Option<&CodecSpec>,
    withheld_from_far: bool,
) -> Option<CodecSpec> {
    // `codec-mask-X` / `codec-consume-X` (and a `codec-offer` whitelist that omits X) mean exactly
    // "keep A on X and transcode it" — the operator removed A's own codec from what B was offered, so
    // B could not have selected it and its answer is not evidence that A moved. Honour that: the
    // transcoder is what those flags are for.
    if withheld_from_far {
        return primary;
    }
    let Some(answered) = answered else {
        return primary;
    };
    if offered.iter().any(|spec| same_codec(spec, answered)) {
        return Some(answered.clone());
    }
    primary
}

fn resolve_pipeline(
    near_codec: Option<&CodecSpec>,
    info: &sdp::MediaInfo,
    profile: &ProfileFlags,
    far_local_crypto: Option<CryptoAttribute>,
    near_local_crypto: Option<CryptoAttribute>,
    far_dtls: bool,
) -> PipelineKind {
    // Transcode when the two legs' primary codecs differ in encoding or clock rate.
    let transcode = match (near_codec, info.primary_codec()) {
        (Some(near), Some(far)) => !same_codec(near, &far),
        _ => false,
    };
    if far_dtls {
        // DTLS-SRTP far leg. Route it through the media pipeline when something actually needs the
        // decoded audio — a codec mismatch, recording, noise suppression, echo cancellation or
        // record-tone (beep) detection — and through the plain crypto bridge otherwise, which stays
        // cheaper (no decode/re-encode) and is all a same-codec WebRTC↔SIP call needs.
        return if transcode
            || profile.record_call
            || profile.noise_suppression
            || profile.echo_cancellation
            || profile.beep_detection
        {
            PipelineKind::DtlsMedia
        } else {
            PipelineKind::Dtls
        };
    }
    // A secure **offerer** toward a plain callee: the mirror of the secure-far-leg bridge below. Only
    // the crypto-bridge shape is wired, so this yields `SrtpOfferer` exactly when nothing needs the
    // decoded audio. Anything that does — a codec mismatch, recording, NS, AEC, beep detection —
    // falls through to a media pipeline that has no A-facing `SecureLeg` threaded into it, which the
    // caller then refuses rather than silently relaying the caller's audio undecrypted or unencrypted.
    if near_local_crypto.is_some()
        && far_local_crypto.is_none()
        && !far_dtls
        && !transcode
        && !profile.record_call
        && !profile.noise_suppression
        && !profile.echo_cancellation
        && !profile.beep_detection
    {
        return PipelineKind::SrtpOfferer;
    }
    if far_local_crypto.is_some() {
        // Secure far leg: the plain SRTP bridge when both legs share a codec and nothing needs the
        // decoded audio (crypto only), or the secure transcoding media slow path otherwise —
        // decrypt → transcode → encrypt (BGCF/SBC: a secure AMR-WB access leg ↔ a plaintext G.711
        // PSTN leg). Record-tone detection needs the PCM, so it takes the same slow path.
        return if transcode || profile.beep_detection {
            PipelineKind::SrtpMedia
        } else {
            PipelineKind::Srtp
        };
    }
    if profile.record_call
        || profile.noise_suppression
        || profile.echo_cancellation
        || profile.beep_detection
        || transcode
    {
        // Recording, noise suppression, echo cancellation, record-tone (beep) detection, or a codec
        // mismatch all need the decoded audio, so force the userspace media slow path instead of the
        // in-kernel passthrough.
        PipelineKind::Media
    } else {
        PipelineKind::Passthrough
    }
}

/// Build the relay rule for one ingress endpoint: gate its incoming source to the SDP-signalled
/// peer and latch `SignalledOnly` by default, or accept-any + `Symmetric` when the `symmetric`
/// profile flag is set (or the peer address is not yet known). The RTPBleed-safe default —
/// see `docs/security-and-nat.md` §4.7.
pub(super) fn ingress_rule(
    out_endpoint: EndpointId,
    out_dst: Option<std::net::SocketAddr>,
    expected_source: Option<std::net::SocketAddr>,
    profile: &ProfileFlags,
    ice: bool,
) -> ForwardRule {
    if ice {
        // ICE (RFC 8445) validates the source via STUN connectivity checks — the datapath's STUN
        // responder adopts the validated candidate as the media path and is the *only* thing that
        // latches an ICE endpoint. So media must never blind-latch here (the B1 hole): accept any
        // source at the rule level, but never move the latch from media (`LatchPolicy::Off`). The
        // datapath's layer-4 ICE-media gate then forwards only STUN-validated media and drops
        // everything else — docs/security-and-nat.md §4 layer 4.
        return ForwardRule {
            out_endpoint,
            out_dst,
            accepted_source: SourceFilter::Any,
            latch: LatchPolicy::Off,
        };
    }
    let symmetric = profile.flags.iter().any(|flag| flag == "symmetric");
    let Some(addr) = expected_source.filter(|_| !symmetric) else {
        // Symmetric leg, or the peer's address is not yet known: accept any source and latch.
        return ForwardRule::symmetric(out_endpoint, out_dst);
    };
    // Default: exact source-IP gate (the tightest RTPBleed defence). `subnet-source` loosens it to
    // the signalled IP's /24 (v4) or /64 (v6) for carriers that re-NAT or split RTP/RTCP within a
    // block (docs/security-and-nat.md §9).
    let accepted_source = if profile.flags.iter().any(|flag| flag == "subnet-source") {
        let prefix = if addr.is_ipv4() { 24 } else { 64 };
        SourceFilter::Subnet(addr.ip(), prefix)
    } else {
        SourceFilter::Exact(addr.ip())
    };
    ForwardRule {
        out_endpoint,
        out_dst,
        accepted_source,
        latch: LatchPolicy::SignalledOnly,
    }
}
