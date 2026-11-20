//! Handing a single-leg call between a WebSocket bot and the engine's own pipeline: a bot joining
//! a call the engine answered, and a negotiated takeover returning its caller to the engine. The
//! caller's transport and keying outlive each hand-over (an SDES context, a DTLS association, an
//! ICE agent and its selected pair), so the peer sees neither a new handshake nor a new path.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::WsBridgeEndReason;
use std::sync::Arc;

use super::super::{Engine, PipelineKind, PromoteMode, PromotionReason};
use super::{ws_takeover_media_address, WsBridgeProcessing, WsBridgeSetup};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Hand a single-leg call from the engine's own pipeline to a WebSocket takeover: a bot joins a
    /// call the engine answered itself, and a later detach gives the leg back
    /// ([`Self::return_takeover_to_anchor`]).
    ///
    /// Everything that can fail cleanly does so first, with the pipeline still carrying the call:
    /// the refusals, then the dial. Only then is the pipeline stopped — and **awaited**, because the
    /// bridge must never run alongside it: two senders on one endpoint interleave two RTP sequence
    /// series toward one peer (RFC 3550 §5.1), and on a secure leg two owners of one SDES context
    /// would encrypt under the same index (RFC 3711 §9.1). The context itself moves to the bridge
    /// once the actor has let go of it, so the rollover counter and replay window carry on. The
    /// gate is drawn exactly as the pipeline's was — the call's stored posture around its
    /// `received-from`-seeded address — and the downlink starts where the pipeline's latch last saw
    /// the caller. If the bridge cannot be installed after all, the call is put back on the pipeline
    /// rather than left with no media path.
    ///
    /// Refused while anything else lives on the pipeline — a recording, a tee, a SIPREC
    /// subscription, an interception, a DTMF block, echo — since stopping the pipeline would stop it
    /// silently. A prompt still playing is ended with `play_finished{error}`, as on any teardown.
    ///
    /// `processing` is what the attach's profile resolved to — [`WsBridgeProcessing::default`] when
    /// it named none, which runs the bot at the leg's own rate with every uplink stage off.
    pub(super) async fn attach_to_anchor(
        &self,
        call_id: &str,
        ws_uri: &str,
        processing: WsBridgeProcessing,
    ) -> Result<(), String> {
        let Some((codec, caller, signalled, received_from, posture, secure, others)) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.near_codec.clone(),
                    call.caller_leg().rtp.id,
                    call.near.remote_rtp,
                    call.offer_received_from,
                    call.caller_source_posture,
                    (call.near_secure, call.near_secure_key.is_some()),
                    // A decoded recording moves with the leg (below), and so does a lawful
                    // interception, so neither is a reason to refuse; anything else on the pipeline
                    // would be stopped silently.
                    call.promotion_reasons.iter().any(|reason| {
                        !matches!(
                            reason,
                            PromotionReason::MediaOp
                                | PromotionReason::AudioRecording
                                | PromotionReason::X3
                        )
                    }),
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };
        let (near_secure, sdes_keyed) = secure;
        let has_ice = self.runs_ice_agent(caller);
        // A DTLS leg's key lives with the bridge that ran its handshake, not on the call.
        let dtls = self.dtls_bridge().owns(caller);
        let keyed = sdes_keyed || (dtls && self.dtls_bridge().is_keyed(caller));
        if others
            || self.multi_source_attachment(call_id).is_some()
            || self.ws_tees.contains_key(call_id)
            || self
                .subscriptions
                .get(call_id)
                .is_some_and(|list| !list.is_empty())
        {
            return Err(
                "ws-takeover-anchor-busy: a pcap recording, WebSocket tee, SIPREC subscription, \
                 DTMF block or echo runs on the engine's pipeline for this call, and handing the leg \
                 to a bot would stop it; stop it first"
                    .to_string(),
            );
        }
        let Some(codec) = codec else {
            return Err("the call has no negotiated codec".to_string());
        };
        let Some(signalled) = signalled else {
            return Err("the caller's leg has no signalled address".to_string());
        };
        if near_secure && !keyed {
            return Err(
                "ws-takeover-unkeyable: the caller's leg is secure but its key material is not \
                 held by the engine's pipeline"
                    .to_string(),
            );
        }
        let expected = ws_takeover_media_address(signalled, received_from);
        // Under ICE the posture is `Ice`, whose gate is open (the datapath's layer-4 gate admits only
        // the validated pair), and the downlink starts at the pair already selected.
        let accepted_source = posture.gate(expected);
        let selected = if has_ice {
            self.datapath.ice_validated_source(caller)
        } else {
            None
        };
        let a_rtp = selected
            .or_else(|| self.media.latched_source(caller))
            .unwrap_or(expected);

        // Nothing has changed yet, so a dial failure is a clean refusal on a call still anchored.
        let socket = self.dial_ws(call_id, ws_uri).await?;

        // A decoded recording's sinks come off the actor before it stops — taken, not dropped, so
        // the file stays open — and go onto the bridge once it is up: one recording across the
        // hand-over, with only the frames in flight during the swap missing from it.
        let recordings = self.take_pipeline_recordings(call_id).await;
        // A plain leg has no key to move, so the bridge is registered (and tapped) while the actor
        // still owns the leg, and the actor stops only once the bridge is live: the dispatcher
        // offers a packet to the actor before the bridge, so each packet takes one path and an
        // intercepted caller's ingress has no gap. A secure leg's one SRTP context has exactly one
        // owner at a time (RFC 3711 §9.1), so it must leave the actor first and cannot be inverted.
        let overlap = !near_secure;
        if !overlap {
            self.media.stop(call_id).await;
        }
        // Taken, not cloned, and only now: with the actor gone the call's handle is the last one, so
        // the leg can be unwrapped rather than shared between two owners. A DTLS leg's is the copy
        // the bridge retained for the pipeline.
        let key = if dtls {
            self.dtls_bridge()
                .take_retained(caller)
                .map(super::super::NearSecureKey)
        } else {
            self.calls
                .get_mut(call_id)
                .and_then(|mut call| call.near_secure_key.take())
        };
        let secure = match key {
            None => None,
            Some(super::super::NearSecureKey(shared)) => match Arc::try_unwrap(shared) {
                Ok(mutex) => match mutex.into_inner() {
                    Ok(leg) => Some(Arc::new(crate::ws_bridge::WsSecureLeg::keyed(leg))),
                    Err(_) => {
                        return self
                            .reanchor_carrying(
                                call_id,
                                None,
                                "the secure leg's mutex is poisoned",
                                recordings,
                            )
                            .await;
                    }
                },
                Err(still_shared) => {
                    return self
                        .reanchor_carrying(
                            call_id,
                            Some(still_shared),
                            "the secure leg is still held elsewhere",
                            recordings,
                        )
                        .await;
                }
            },
        };
        let mut had_media_op = false;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.near_secure_key = None;
            had_media_op = call.promotion_reasons.remove(&PromotionReason::MediaOp);
        }
        let installed = self
            .setup_ws_bridge(WsBridgeSetup {
                call_id,
                ws_uri,
                endpoint_a: caller,
                a_rtp,
                codec: Some(&codec),
                accepted_source,
                // An ICE leg's downlink is the agent's to move, never the latch's; the selection
                // below releases it.
                ice_pending: has_ice,
                secure: secure.clone(),
                processing,
                egress: None,
                // Nothing displaced: a detach returns the leg to the anchor, not to a relay.
                takeover: None,
                socket: Some(socket),
            })
            .await;
        if overlap {
            if let Err(reason) = &installed {
                // Nothing was stopped: the actor still carries the call, with its taps.
                if had_media_op {
                    if let Some(mut call) = self.calls.get_mut(call_id) {
                        call.promotion_reasons.insert(PromotionReason::MediaOp);
                    }
                }
                self.give_pipeline_recordings(call_id, recordings);
                return Err(reason.clone());
            }
            // Awaited, so what the actor had queued is processed and delivered before it exits.
            self.media.stop(call_id).await;
        }
        // The DTLS flow now feeds the WebSocket leg, which holds the key already. Keyed was checked
        // before anything stopped, so this cannot meet a running handshake.
        let installed = installed.and_then(|()| {
            if !dtls {
                return Ok(());
            }
            let target = crate::dtls_bridge::PipelineTarget::Ws {
                ws: self.ws.clone(),
                call_id: call_id.to_string(),
            };
            self.dtls_bridge()
                .retarget(caller, target, None)
                .map_err(str::to_string)
        });
        if let Err(reason) = installed {
            self.stop_ws_bridge(call_id, WsBridgeEndReason::Detached)
                .await;
            let key = secure
                .and_then(|secure| secure.take_leg())
                .map(|leg| Arc::new(std::sync::Mutex::new(leg)));
            return self
                .reanchor_carrying(call_id, key, &reason, recordings)
                .await;
        }
        self.give_bridge_recordings(call_id, recordings).await;
        // Read again now the route exists: a selection landing while neither the pipeline nor the
        // bridge had a route reached neither through the sweep.
        if has_ice {
            if let Some(remote) = self.datapath.ice_validated_source(caller) {
                self.ws.ice_selected(caller, remote);
            }
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            // The WS server is the far side now, as on a negotiated takeover.
            call.far_codec = None;
            call.pipeline = PipelineKind::Ws;
        }
        // The interception follows the leg onto the bridge (already tapped at registration; this is
        // the locked pass that settles a concurrent attach and ends the deliveries if it fails).
        self.carry_x3_across_answer(call_id).await;
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            ws_uri,
            "ws bridge attached to the engine's own leg"
        );
        Ok(())
    }

    /// [`Self::reanchor`], then put back the recordings taken off the stopped pipeline, so a takeover
    /// that did not happen leaves a recording running exactly as it found it.
    async fn reanchor_carrying(
        &self,
        call_id: &str,
        key: Option<Arc<std::sync::Mutex<siphon_rtp_srtp::leg::SecureLeg>>>,
        reason: &str,
        recordings: siphon_rtp_media::bridge::taps::TakenRecordingTaps,
    ) -> Result<(), String> {
        let outcome = self.reanchor(call_id, key, reason).await;
        self.give_pipeline_recordings(call_id, recordings);
        // The pipeline is a new actor: an interception on the call is tapped onto it again.
        self.carry_x3_across_answer(call_id).await;
        outcome
    }

    /// Put a call whose pipeline was stopped for a takeover back on it, keyed with `key` when the
    /// leg is secure, and report why the takeover did not happen. A failure here leaves the call with
    /// no media path, so it is logged at ERROR and named in the error.
    pub(in crate::engine) async fn reanchor(
        &self,
        call_id: &str,
        key: Option<Arc<std::sync::Mutex<siphon_rtp_srtp::leg::SecureLeg>>>,
        reason: &str,
    ) -> Result<(), String> {
        let endpoint = self
            .owned_call_internal(call_id, |call| call.caller_leg().rtp.id)
            .ok_or_else(|| format!("ws-takeover-anchor: {reason}; the call is gone"))?;
        let has_ice = self.runs_ice_agent(endpoint);
        if let Some(mut call) = self.calls.get_mut(call_id) {
            // The state `promote_to_processing` builds a single-leg anchor from: no far codec (a
            // far codec selects its two-leg branch) and a passthrough pipeline to promote.
            call.pipeline = PipelineKind::Passthrough;
            call.far_codec = None;
        }
        let restored = self
            .hold_in_userspace(call_id, PromotionReason::MediaOp, PromoteMode::Processing)
            .await
            .and_then(|()| {
                if let Some(mut call) = self.calls.get_mut(call_id) {
                    call.far_codec = call.near_codec.clone();
                    call.pipeline = PipelineKind::Media;
                }
                if has_ice {
                    self.follow_ice_selection(endpoint);
                }
                let Some(leg) = key else { return Ok(()) };
                self.key_anchor(call_id, endpoint, leg)
            });
        match restored {
            Ok(()) => Err(format!(
                "ws-takeover-anchor: {reason}; the call is back on the engine's pipeline"
            )),
            Err(error) => {
                tracing::error!(
                    target: "siphon_rtp::media",
                    call_id,
                    %reason,
                    %error,
                    "a takeover of the engine's own leg failed and the leg could not be re-anchored; \
                     it has no media path"
                );
                Err(format!(
                    "ws-takeover-anchor: {reason}; re-anchoring failed too ({error})"
                ))
            }
        }
    }

    /// Hand a negotiated single-leg takeover's leg to the engine's own pipeline: the anchor
    /// `answer_local` builds without a `ws_uri`, reached here by the same promotion.
    ///
    /// The gate needs no carrying: the anchor draws it from the call's stored posture and
    /// `received-from` hint, the same inputs the bridge's was drawn from. An SDES leg's key material
    /// *is* carried — taken out of the bridge's leg and attached to the pipeline — so the peer's
    /// rollover counter and the replay window survive the hand-over (RFC 3711 §3.3.1).
    ///
    /// An ICE leg keeps its agent, which the hand-over does not touch: the pipeline takes the `Ice`
    /// posture and is told the pair already selected, so its egress goes where the bridge's did (RFC
    /// 8445 §12), and a later selection reaches it through the sweep. A DTLS-SRTP leg keeps its
    /// association: the bridge's flow is retargeted from the WebSocket leg to the pipeline and the
    /// key moves with it, so the peer sees no new handshake (RFC 8842 §5.5).
    ///
    /// Refused, before anything is stopped, on a two-leg call (see [`Self::detach_ws_bridge`]) and on
    /// a DTLS leg whose handshake has not completed, whose session would key the bridge it is about
    /// to lose.
    pub(super) async fn return_takeover_to_anchor(&self, call_id: &str) -> Result<(), String> {
        let (single_leg, endpoint) = self
            .owned_call_internal(call_id, |call| {
                (call.is_single_leg(), call.caller_leg().rtp.id)
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        // Asked of the agent supervisor, not of `call.ice`: `answer_local` arms the agent without
        // recording credentials on the call, which is how a detach of an ICE leg once went through
        // unnoticed and aimed the pipeline at the signalled `c=`.
        let has_ice = self.runs_ice_agent(endpoint);
        if !single_leg {
            return Err(
                "ws-bridge-negotiated-two-leg: this bridge was negotiated on a two-leg call, which \
                 never wired A to B, so there is no media path to return it to; re-point it with \
                 attach_ws_bridge, or end the call with delete"
                    .to_string(),
            );
        }
        let dtls = self.dtls_bridge().owns(endpoint);
        if dtls && !self.dtls_bridge().is_keyed(endpoint) {
            return Err(
                "ws-bridge-detach-dtls-pending: the leg's DTLS-SRTP handshake has not completed, \
                 and it would key the bridge being detached; retry once media flows"
                    .to_string(),
            );
        }
        let secure = self.ws.route_state(call_id).and_then(|state| state.secure);
        // Off the bridge before it stops, onto the anchor once it is up — the same move as an
        // attach, the other way.
        let recordings = self.take_bridge_recordings(call_id).await;
        // A plain leg has no key to move: the pipeline is built (already tapped, if the call is
        // intercepted) while the bridge still holds the leg, and the bridge stops once the pipeline
        // is live. The dispatcher offers a packet to the pipeline before the bridge, so each packet
        // takes one path and the caller's ingress has no gap. A secure leg's one SRTP context has
        // exactly one owner at a time (RFC 3711 §9.1), so it leaves the bridge first.
        if secure.is_none() && !dtls {
            return self
                .hand_plain_bridge_to_anchor(call_id, endpoint, has_ice, recordings)
                .await;
        }
        self.stop_ws_bridge(call_id, WsBridgeEndReason::Detached)
            .await;
        // After the stop: the bridge and its drain have been joined, so nothing crypts with it any
        // more and the key material can be moved rather than copied.
        let key = secure.and_then(|secure| secure.take_leg());
        if dtls && key.is_none() {
            // The handshake keyed the leg (checked above), so the WebSocket leg held the key. Its
            // absence is an engine invariant broken, and the pipeline would sit pending forever.
            tracing::error!(
                target: "siphon_rtp::media",
                call_id,
                "a detached DTLS takeover leg had no key to hand over; it has no media path"
            );
            return Err("ws-bridge-detach-anchor: the DTLS leg's key was not held".to_string());
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Passthrough;
            if has_ice {
                call.caller_source_posture = super::super::negotiate::SourcePosture::Ice;
            }
        }
        if let Err(reason) = self
            .hold_in_userspace(call_id, PromotionReason::MediaOp, PromoteMode::Processing)
            .await
        {
            tracing::error!(
                target: "siphon_rtp::media",
                call_id,
                %reason,
                "a detached takeover leg could not be anchored; it has no media path"
            );
            self.end_x3_unservable(call_id, &reason).await;
            return Err(format!("ws-bridge-detach-anchor: {reason}"));
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            // A single-leg pipeline encodes back into the codec the caller sends, as `answer_local`
            // records it.
            call.far_codec = call.near_codec.clone();
            call.pipeline = PipelineKind::Media;
        }
        self.give_pipeline_recordings(call_id, recordings);
        if let Some(key) = key {
            let leg = Arc::new(std::sync::Mutex::new(key));
            if let Err(reason) = self.key_anchor(call_id, endpoint, leg) {
                self.end_x3_unservable(call_id, &reason).await;
                return Err(format!("ws-bridge-detach-anchor: {reason}"));
            }
        }
        if has_ice {
            self.follow_ice_selection(endpoint);
        }
        // The caller is on the engine's pipeline again: the interception goes back onto it.
        self.carry_x3_across_answer(call_id).await;
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            "ws bridge detached; the caller is on the engine's own pipeline"
        );
        Ok(())
    }

    /// [`Self::return_takeover_to_anchor`] for a plain leg, in the order that misses nothing: pipeline
    /// first, then the bridge. If the pipeline cannot be built the bridge keeps the call, as it was.
    async fn hand_plain_bridge_to_anchor(
        &self,
        call_id: &str,
        endpoint: siphon_rtp_datapath::EndpointId,
        has_ice: bool,
        recordings: siphon_rtp_media::bridge::taps::TakenRecordingTaps,
    ) -> Result<(), String> {
        let posture = self
            .owned_call_internal(call_id, |call| call.caller_source_posture)
            .ok_or_else(|| "call no longer exists".to_string())?;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Passthrough;
            if has_ice {
                call.caller_source_posture = super::super::negotiate::SourcePosture::Ice;
            }
        }
        if let Err(reason) = self
            .hold_in_userspace(call_id, PromotionReason::MediaOp, PromoteMode::Processing)
            .await
        {
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.pipeline = PipelineKind::Ws;
                call.caller_source_posture = posture;
            }
            self.give_bridge_recordings(call_id, recordings).await;
            return Err(format!("ws-bridge-detach-anchor: {reason}"));
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            // A single-leg pipeline encodes back into the codec the caller sends, as `answer_local`
            // records it.
            call.far_codec = call.near_codec.clone();
            call.pipeline = PipelineKind::Media;
        }
        self.stop_ws_bridge(call_id, WsBridgeEndReason::Detached)
            .await;
        self.give_pipeline_recordings(call_id, recordings);
        if has_ice {
            self.follow_ice_selection(endpoint);
        }
        // The locked pass that settles a concurrent attach and ends the deliveries if it fails.
        self.carry_x3_across_answer(call_id).await;
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            "ws bridge detached; the caller is on the engine's own pipeline"
        );
        Ok(())
    }

    /// Key a single-leg anchor's pipeline with the caller's `leg`: through the DTLS bridge when the
    /// leg is keyed by a handshake (the flow is retargeted at the pipeline, which keeps the
    /// association and retains the key for a renegotiation), else directly, keeping the key on the
    /// call for a later takeover.
    pub(super) fn key_anchor(
        &self,
        call_id: &str,
        endpoint: siphon_rtp_datapath::EndpointId,
        leg: Arc<std::sync::Mutex<siphon_rtp_srtp::leg::SecureLeg>>,
    ) -> Result<(), String> {
        if self.dtls_bridge().owns(endpoint) {
            let target = crate::dtls_bridge::PipelineTarget::Call {
                media: self.media.clone(),
                call_id: call_id.to_string(),
                party: crate::dtls_bridge::KeyedParty::SoleParty,
            };
            return self
                .dtls_bridge()
                .retarget(endpoint, target, Some(leg))
                .map_err(str::to_string);
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.near_secure_key = Some(super::super::NearSecureKey(leg.clone()));
        }
        if self.media.control(
            call_id,
            crate::media_pipeline::MediaControl::AttachNearSecureLeg { leg },
        ) {
            Ok(())
        } else {
            Err("media actor unavailable".to_string())
        }
    }

    /// Whether an RFC 8445 agent owns `endpoint`'s transport.
    pub(super) fn runs_ice_agent(&self, endpoint: siphon_rtp_datapath::EndpointId) -> bool {
        self.ice_agents
            .as_ref()
            .is_some_and(|agents| agents.runs(endpoint))
    }

    /// Tell the pipeline on `endpoint` the pair its RFC 8445 agent has already selected, if any. A
    /// selection that lands later reaches it through the sweep, like any other.
    pub(super) fn follow_ice_selection(&self, endpoint: siphon_rtp_datapath::EndpointId) {
        if let Some(remote) = self.datapath.ice_validated_source(endpoint) {
            self.media.ice_selected(endpoint, remote);
        }
    }
}
