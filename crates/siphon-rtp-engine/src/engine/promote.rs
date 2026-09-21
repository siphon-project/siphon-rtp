//! Moving a call between the in-kernel relay and the userspace media pipeline.

use siphon_rtp_datapath::{
    Datapath, EndpointId, FlowAction, ForwardRule, LatchPolicy, SourceFilter,
};

use crate::media_pipeline::{MediaCall, RelayConfig};
use crate::text_pipeline::{TextCall, TextDirectionConfig};

use super::negotiate::{apply_received_from, build_direction};
use super::{Engine, PipelineKind, PromoteMode, PromotionReason};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Promote a plain passthrough relay (the in-kernel `FlowAction::Forward` fast path) to a
    /// userspace **relay-only** [`MediaCall`], so a SIPREC raw tee has an actor to attach to. The
    /// in-kernel `Forward` path has no userspace tap; here we switch each RTP endpoint from `Forward`
    /// to `Redirect`, and run a lightweight raw relay that re-enforces the exact same source gate +
    /// symmetric latch the `Forward` rule did (RTPBleed defence — `Redirect` bypasses the datapath
    /// gate, docs/security-and-nat.md §4) and forwards each packet verbatim to the original peer, plus
    /// the raw tee. Reconstructs both relay directions from the call's stored `relay_flows`.
    pub(super) async fn promote_passthrough(&self, call_id: &str) -> Result<(), String> {
        // Read the two RTP forward rules + leg identity out of the stored relay flows. `relay_flows`
        // for a passthrough call is [near.rtp, far.rtp, (near.rtcp, far.rtcp)] — we tee/relay only RTP.
        // Also carry each leg's negotiated telephone-event PT so a later `block DTMF` can gate it on
        // this promoted (still untranscoded) relay: leg A's ingress uses `near_telephone_event`, leg
        // B's uses `far_telephone_event`.
        let Some((from_tag, to_tag, relay_flows, near_telephone_event, far_telephone_event)) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.from_tag.clone(),
                    call.to_tag.clone(),
                    call.relay_flows.clone(),
                    call.near_telephone_event,
                    call.far_telephone_event,
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };

        // Reconstruct the per-direction wiring from the stored `Forward` rules (near then far).
        // `near_rule` is installed on near.rtp: it gates A's source and forwards toward far/out_dst (B).
        // Build the relay-only directions: A→B forwards out far's endpoint to B; B→A out near's to A.
        let layout = relay_layout_from_flows(&relay_flows)?;
        let a_to_b = RelayConfig {
            ingress_endpoint: layout.near_endpoint,
            accepted_source: layout.near_rule.accepted_source,
            egress_endpoint: layout.near_rule.out_endpoint,
            egress_dst: layout.b_dst,
            telephone_event: near_telephone_event, // leg A's ingress
        };
        let b_to_a = RelayConfig {
            ingress_endpoint: layout.far_endpoint,
            accepted_source: layout.far_rule.accepted_source,
            egress_endpoint: layout.far_rule.out_endpoint,
            egress_dst: layout.a_dst,
            telephone_event: far_telephone_event, // leg B's ingress
        };

        // Switch both RTP endpoints to Redirect so the dispatcher routes them to the media actor.
        for endpoint in [layout.near_endpoint, layout.far_endpoint] {
            self.datapath
                .install_flow(endpoint, FlowAction::Redirect)
                .map_err(|error| format!("install relay redirect: {error}"))?;
        }
        let call = MediaCall::new_relay(
            call_id.to_string(),
            from_tag,
            to_tag,
            a_to_b,
            b_to_a,
            layout.latch,
        );
        self.media.register(call, self.datapath.clone(), None);

        // Record the promotion on the Call so demotion can restore the in-kernel Forward rules.
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Media;
        }
        Ok(())
    }

    /// Promote a plain passthrough relay (the in-kernel `Forward` fast path) to a userspace
    /// **processing** [`MediaCall`] (decode → re-encode), so echo has a real reflect path: a relay-only
    /// promotion forwards opaque payloads to the peer and cannot loop a party's audio back to itself.
    /// The reflect path takes one of two shapes, decided by whether the call was answered:
    ///
    /// * **offer + answer** (both codecs known) → a **2-leg** echo: build A→B and B→A over the same
    ///   endpoints / source gates / egress targets the stored `Forward` rules used, so each party hears
    ///   itself. A passthrough relay always shares one codec across both legs (a codec *mismatch*
    ///   answers as a transcode call, not a relay), so the near/far codecs are the same here.
    /// * **offer only** (no `answer` — a UAS IVR/echo that never dials a B leg, so `far_codec` is
    ///   `None`) → a **single-leg** self-echo: decode the caller's ingress (`near_codec`) and re-encode
    ///   it back out the *same* endpoint the caller reaches (`near_codec` on both sides). The caller
    ///   sends to the engine's far socket — the offer's rewritten SDP advertises the far leg and the UAS
    ///   put that SDP in its 200 OK — so the reflect runs on that socket; the never-advertised near
    ///   socket stays idle. No `Forward` rule was ever installed on it (an offer-only endpoint drops
    ///   inbound media, having no negotiated peer), so a `Drop` restore is recorded in `relay_flows` for
    ///   demotion to return it to that state.
    ///
    /// Either way the RTPBleed defence is unchanged (`Redirect` bypasses the datapath gate, so the
    /// directions re-enforce the exact same per-leg source filter, docs/security-and-nat.md §4);
    /// building errors only if a codec has no encoder (e.g. AMR-WB without the `amr` build feature). The
    /// owner's event sink is wired so DTMF still surfaces (the SBC ends the echo test on `#`).
    ///
    /// `echo` builds the actor with echo-test mode already on, for a promotion the `echo` verb asked
    /// for; see the construction below for why that cannot be left to a control message.
    pub(super) async fn promote_to_processing(
        &self,
        call_id: &str,
        echo: bool,
    ) -> Result<(), String> {
        let Some((
            owner,
            from_tag,
            to_tag,
            relay_flows,
            near_codec,
            far_codec,
            near_te,
            far_te,
            caller_facing_endpoint,
            caller_signalled_rtp,
            offer_received_from,
            comfort_noise_pt,
            near_secure,
        )) = self.owned_call_internal(call_id, |call| {
            (
                call.owner,
                call.from_tag.clone(),
                call.to_tag.clone(),
                call.relay_flows.clone(),
                call.near_codec.clone(),
                call.far_codec.clone(),
                call.near_telephone_event,
                call.far_telephone_event,
                // The engine socket the caller reaches for a single-leg (offer-only) echo — recorded on
                // the call when its legs were allocated, because only the verb that wrote the SDP knows
                // which socket it advertised (see [`CallerMediaLeg`]). Unused by the 2-leg arm.
                call.caller_leg().rtp.id,
                // The caller's own signalled RTP address (the near/offerer leg's remote) — what the
                // single-leg source gate keys on and reflects back toward.
                call.near.remote_rtp,
                call.offer_received_from,
                // The negotiated RFC 3389 CN egress payload type for a single-leg local answer (`None`
                // for the echo/play promote paths and 2-leg calls). Wires the comfort-idle egress.
                call.comfort_noise_payload_type,
                // Whether the offerer's own media is secure. The actor must start **gated** in that
                // case — see the `with_near_secure_pending` call below.
                call.near_secure,
            )
        })
        else {
            return Err("call no longer exists".to_string());
        };
        let Some(near_codec) = near_codec else {
            return Err(
                "call has no negotiated codec to echo (offer/answer not complete)".to_string(),
            );
        };

        // Two echo shapes, chosen by whether the call was answered (see the doc comment): a 2-leg echo
        // (far codec known) or an offer-only single-leg self-echo. Each builds its directions, the RTP
        // endpoints it must `Redirect`, the latch flag, and — for the single-leg case only — a `Drop`
        // restore recorded in `relay_flows` (the offer-only caller-facing endpoint had no `Forward`
        // rule, so it dropped inbound media; demotion returns it there, and a non-empty `relay_flows` is
        // what makes `demote_if_idle` tear the single-leg actor down when `echo enabled=false`).
        let (a_to_b, b_to_a, redirect_endpoints, latch, offer_only_restore) = match far_codec {
            Some(far_codec) => {
                // 2-leg echo: reconstruct the wiring from the answer-installed `Forward` rules and cross
                // the codecs the way `answer`'s Media arm does — A→B decodes A's codec / encodes B's,
                // B→A decodes B's / encodes A's — so each party's echo (decode on its ingress, re-encode
                // on the reverse egress that faces it) round-trips in that party's own codec.
                // `build_direction` gives each egress a fresh random SSRC + real timestamp increment
                // (RFC 3550 §5.1 / §8), so the reflected stream is well-formed — which a relay-only
                // direction's zeroed egress params are not.
                let layout = relay_layout_from_flows(&relay_flows)?;
                let a_to_b = build_direction(
                    layout.near_endpoint,
                    layout.near_rule.accepted_source,
                    layout.near_rule.out_endpoint,
                    layout.b_dst,
                    &near_codec,
                    &far_codec,
                    near_te,
                    far_te,
                    None,
                    // Echo promotion is a runtime control action, not an offer/answer profile, so
                    // neither NS nor beep detection is armed here. An already-armed *transcoding* call
                    // switched into echo mode with `MediaControl::Echo` keeps its detector — that path
                    // reuses the existing directions rather than rebuilding them.
                    false,                                         // noise_suppression
                    crate::media_pipeline::EchoProfile::default(), // echo (a reflect path wants the echo)
                    false, // beep_detection (the echo verb carries no offer/answer profile)
                    None,  // beep_cadence_guard_ms
                )?;
                let b_to_a = build_direction(
                    layout.far_endpoint,
                    layout.far_rule.accepted_source,
                    layout.far_rule.out_endpoint,
                    layout.a_dst,
                    &far_codec,
                    &near_codec,
                    far_te,
                    near_te,
                    None,
                    false,                                         // noise_suppression
                    crate::media_pipeline::EchoProfile::default(), // echo (a reflect path wants the echo)
                    false, // beep_detection (the echo verb carries no offer/answer profile)
                    None,  // beep_cadence_guard_ms
                )?;
                (
                    a_to_b,
                    b_to_a,
                    vec![layout.near_endpoint, layout.far_endpoint],
                    layout.latch,
                    None,
                )
            }
            None => {
                // Single-leg self-echo (offer only, no B): reflect the caller's audio back out the very
                // endpoint it reaches — the caller-facing (far) socket the offer's rewritten SDP
                // advertised, which the UAS put in its 200 OK. Both directions face the caller on that
                // one endpoint — `a_to_b` decodes the caller's ingress, `b_to_a` re-encodes it home
                // (`MediaCall::process` routes the packet through `a_to_b.echo_into(b_to_a)`; the shared
                // ingress means the `b_to_a` arm is shadowed and never processes a packet twice). There
                // is no B leg — the near (A-facing) socket the offer never advertised stays unused.
                //
                // Gate ingress to the caller's real source IP (RTPBleed defence, docs §4 layer 2): the
                // offer's `received-from` public IP when the SIP proxy supplied one, else the signalled
                // `c=` address. The initial egress destination is that same address; the `SignalledOnly`
                // latch (default on, below) then refines it to the caller's observed source (symmetric
                // RTP), so the loop follows a NATed caller.
                let Some(caller) = apply_received_from(caller_signalled_rtp, offer_received_from)
                else {
                    return Err(
                        "echo: offer-only call has no signalled caller address to reflect to"
                            .to_string(),
                    );
                };
                let accepted_source = SourceFilter::Exact(caller.ip());
                let a_to_b = build_direction(
                    caller_facing_endpoint,
                    accepted_source,
                    caller_facing_endpoint,
                    caller,
                    &near_codec,
                    &near_codec,
                    near_te,
                    near_te,
                    None,
                    false,                                         // noise_suppression
                    crate::media_pipeline::EchoProfile::default(), // echo (a reflect path wants the echo)
                    false, // beep_detection (the echo verb carries no offer/answer profile)
                    None,  // beep_cadence_guard_ms
                )?;
                let b_to_a = build_direction(
                    caller_facing_endpoint,
                    accepted_source,
                    caller_facing_endpoint,
                    caller,
                    &near_codec,
                    &near_codec,
                    near_te,
                    near_te,
                    None,
                    false,                                         // noise_suppression
                    crate::media_pipeline::EchoProfile::default(), // echo (a reflect path wants the echo)
                    false, // beep_detection (the echo verb carries no offer/answer profile)
                    None,  // beep_cadence_guard_ms
                )?;
                (
                    a_to_b,
                    b_to_a,
                    vec![caller_facing_endpoint],
                    true,
                    Some(vec![(caller_facing_endpoint, FlowAction::Drop)]),
                )
            }
        };

        // Switch the RTP endpoint(s) to Redirect so the dispatcher routes them to the media actor.
        for endpoint in &redirect_endpoints {
            self.datapath
                .install_flow(*endpoint, FlowAction::Redirect)
                .map_err(|error| format!("install processing redirect: {error}"))?;
        }
        let owner_events = self.event_sink(owner);
        let call = MediaCall::new(
            call_id.to_string(),
            from_tag,
            to_tag,
            a_to_b,
            b_to_a,
            latch,
            None,
        );
        // Single-leg local answer / IVR (`offer_only_restore.is_some()` is the single-leg discriminator
        // — the 2-leg echo arm leaves it `None`): its idle egress is a continuous comfort-noise stream,
        // never the caller's own audio looped back (self-echo). CN packets on the negotiated PT when
        // the caller offered CN, else audio-encoded low-level noise. The `echo` verb still reflects.
        let call = if offer_only_restore.is_some() {
            call.with_comfort_idle(comfort_noise_pt)
        } else {
            call
        };
        // A secure offerer's actor starts **gated**, before it is registered and can tick.
        //
        // `answer_local` keys this leg by sending `AttachNearSecureLeg` *after* the promote returns,
        // and the actor is already running by then — so its comfort-idle playout tick could emit a
        // frame in the window before the key lands, and on a secure leg that frame would go out in
        // the clear. Which is exactly the leak the whole secure-offerer path exists to prevent, and
        // it is not a theoretical window: it is what a parallel test run actually caught.
        //
        // Gating here rather than with a control message is what closes it completely — a message
        // would race the very tick it is meant to beat.
        let mut call = if near_secure {
            call.with_near_secure_pending()
        } else {
            call
        };
        // The same race for the `echo` verb: the actor's playout tick fires the moment it runs, and on
        // a comfort-idle single-leg call it emits comfort noise unless echo is on. Echo turned on by a
        // control message after this returns would send the caller that noise ahead of its own
        // reflected audio, so the actor starts in echo mode instead.
        if echo {
            call.set_echo(true);
        }
        self.media
            .register(call, self.datapath.clone(), owner_events);

        // Record the promotion on the Call so demotion can restore the pre-promote datapath state: the
        // 2-leg case keeps its answer-installed `Forward` rules (already in `relay_flows`); the
        // single-leg case records a `Drop` restore for its lone caller-facing endpoint.
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Media;
            if let Some(restore) = offer_only_restore {
                call.relay_flows = restore;
            }
        }
        Ok(())
    }

    /// Demote a *promoted passthrough* relay back to the in-kernel `FlowAction::Forward` fast path once
    /// nothing holds it in userspace: deregister the [`MediaCall`] actor (relay-only or processing) and
    /// reinstall the stored `Forward` rules (the same ones promotion redirected away from). Best-effort
    /// — on any install error the call is left redirected (still relaying through the actor), which is
    /// correct if slower, and logged.
    async fn demote_to_passthrough(&self, call_id: &str) {
        let Some(relay_flows) = self.owned_call_internal(call_id, |call| call.relay_flows.clone())
        else {
            return;
        };
        // Tear down the relay-only actor (drops its routes), then restore the kernel Forward rules.
        self.media.deregister(call_id);
        for (endpoint, action) in &relay_flows {
            if let Err(error) = self.datapath.install_flow(*endpoint, *action) {
                tracing::warn!(%error, call_id, "demote: failed to reinstall Forward rule; leg stays redirected");
                return;
            }
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Passthrough;
        }
    }

    /// Ensure `call_id` runs in the userspace media pipeline so a per-packet feature (pcap recording,
    /// DTMF block, echo) can attach to it: promote a plain passthrough relay off the in-kernel `Forward`
    /// fast path if it is not already promoted, and record `reason` so the relay is not demoted while
    /// the feature is active. `mode` selects the promotion — [`PromoteMode::RelayOnly`] (verbatim
    /// forward, for recording / DTMF-block) or [`PromoteMode::Processing`] (decode → re-encode, for
    /// echo). A call set up as a transcoding/secure Media call already has an actor — no promotion
    /// happens, but the reason is still recorded (harmlessly; demotion is gated on the presence of
    /// stored `relay_flows`, so a genuine media call is never demoted). Ownership must already be
    /// validated.
    pub(super) async fn hold_in_userspace(
        &self,
        call_id: &str,
        reason: PromotionReason,
        mode: PromoteMode,
    ) -> Result<(), String> {
        let pipeline = self
            .owned_call_internal(call_id, |call| call.pipeline)
            .ok_or_else(|| "call no longer exists".to_string())?;
        // Mirror `subscribe_request`'s guard: promote only a plain relay not already in the pipeline.
        // After promotion the call's pipeline is `Media`, so a second hold skips this and just records.
        if pipeline == PipelineKind::Passthrough && !self.media.is_media_call(call_id) {
            match mode {
                PromoteMode::RelayOnly => self.promote_passthrough(call_id).await?,
                PromoteMode::Processing => {
                    self.promote_to_processing(call_id, matches!(reason, PromotionReason::Echo))
                        .await?;
                }
            }
        } else if mode == PromoteMode::Processing && self.media.is_relay_call(call_id) {
            // A relay-only promotion (recording / DTMF-block on a plain relay) is already up, but echo
            // needs a decode → re-encode path a relay-only actor cannot provide. Reject clearly rather
            // than silently apply an Echo control that would forward opaque payloads to the peer.
            return Err(
                "echo is unsupported while a plain relay is held in userspace for recording or a \
                 DTMF block; stop those first"
                    .to_string(),
            );
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.promotion_reasons.insert(reason);
        }
        Ok(())
    }

    /// Release a userspace hold taken by [`Self::hold_in_userspace`] and demote the relay back to the
    /// `Forward` fast path if nothing else holds it up. Safe on a genuine Media call: demotion is gated
    /// on the presence of stored `relay_flows`, so only a promoted passthrough relay is ever demoted.
    pub(super) async fn release_userspace_hold(&self, call_id: &str, reason: PromotionReason) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.promotion_reasons.remove(&reason);
        }
        self.demote_if_idle(call_id).await;
    }

    /// Whether a promoted passthrough relay must stay in the userspace media pipeline — it has at
    /// least one active hold: a SIPREC subscription, a recording, or a DTMF block.
    pub(super) fn call_has_userspace_hold(&self, call_id: &str) -> bool {
        let has_subscription = self
            .subscriptions
            .get(call_id)
            .is_some_and(|list| !list.is_empty());
        let has_reason = self
            .calls
            .get(call_id)
            .is_some_and(|call| !call.promotion_reasons.is_empty());
        has_subscription || has_reason
    }

    /// Demote a *promoted passthrough* relay back to the in-kernel `Forward` fast path once no reason
    /// (subscription, recording, DTMF block, echo) holds it in userspace any more. A promoted relay is
    /// identified by its stored `relay_flows` (non-empty only for a passthrough; empty for a genuine
    /// transcoding/secure `Media` call, which must never be demoted) — not by `is_relay_call`, because
    /// echo promotes to a **processing** (non-relay-only) actor that must still demote when it clears.
    pub(super) async fn demote_if_idle(&self, call_id: &str) {
        if self.call_has_userspace_hold(call_id) {
            return;
        }
        let promoted_from_passthrough = self.media.is_media_call(call_id)
            && self
                .owned_call_internal(call_id, |call| !call.relay_flows.is_empty())
                .unwrap_or(false);
        if promoted_from_passthrough {
            self.demote_to_passthrough(call_id).await;
        }
    }

    // ---- RFC 4103 text-observability promotion (parallel to the audio hold machinery above) ----
    //
    // A call's `m=text` stream defaults to the in-kernel `Forward` relay (PR 1). A text-observability
    // feature — control-plane `text_events`, or a runtime recording — promotes ONLY the text endpoints
    // to the userspace [`crate::text_pipeline`], leaving the audio relay/transcode/SRTP path exactly as
    // it was (the maintainer's hard constraint). These functions never touch the audio flows.

    /// Promote a call's text stream for control-plane events if the controller asked for them
    /// (`ProfileFlags.text_events`) and a plaintext text stream was negotiated. Called at the end of
    /// `answer()`. A no-op when text was not negotiated, `text_events` is unset, or the owner has no
    /// event sink (nothing to deliver to). Best-effort — a promotion failure is logged; the text stream
    /// keeps relaying in-kernel (PR-1 behaviour).
    pub(super) async fn maybe_promote_text_for_events(&self, call_id: &str) {
        let Some((wants_events, has_text)) = self.owned_call_internal(call_id, |call| {
            (call.text_events, !call.text_relay_flows.is_empty())
        }) else {
            return;
        };
        if !wants_events || !has_text {
            return;
        }
        if let Err(reason) = self
            .hold_text_in_userspace(call_id, PromotionReason::TextEvents)
            .await
        {
            tracing::warn!(
                target: "siphon_rtp::text",
                call_id,
                reason,
                "failed to promote the text stream for events; it stays on the in-kernel relay"
            );
        }
    }

    /// Ensure `call_id`'s text stream runs in the userspace text processor so a text-observability
    /// feature (`text_events` or recording) can attach, and record `reason` so it is not demoted while
    /// the feature is active. Idempotent — a second hold on an already-promoted text stream just records
    /// the reason. A no-op (with the reason still recorded) when the call negotiated no text stream.
    pub(super) async fn hold_text_in_userspace(
        &self,
        call_id: &str,
        reason: PromotionReason,
    ) -> Result<(), String> {
        let has_text = self
            .owned_call_internal(call_id, |call| !call.text_relay_flows.is_empty())
            .ok_or_else(|| "call no longer exists".to_string())?;
        if has_text && !self.text.is_text_call(call_id) {
            self.promote_text_to_userspace(call_id).await?;
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.text_promotion_reasons.insert(reason);
        }
        Ok(())
    }

    /// Release a text hold taken by [`Self::hold_text_in_userspace`] and demote the text stream back to
    /// the in-kernel `Forward` relay if nothing else holds it (no remaining `text_promotion_reasons`).
    pub(super) async fn release_text_hold(&self, call_id: &str, reason: PromotionReason) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.text_promotion_reasons.remove(&reason);
        }
        let idle = self
            .owned_call_internal(call_id, |call| call.text_promotion_reasons.is_empty())
            .unwrap_or(true);
        if idle {
            self.demote_text_to_kernel(call_id).await;
        }
    }

    /// Promote the text stream off the in-kernel `Forward` relay to the userspace text processor: switch
    /// both text endpoints from `Forward` to `Redirect`, reconstruct the two userspace [`TextDirection`]s
    /// from the stored text `Forward` rules (the exact same RTPBleed source-gate + symmetric latch —
    /// `Redirect` bypasses the datapath gate, docs/security-and-nat.md §4), and register the text actor
    /// with the owner's event sink. The audio relay is untouched.
    async fn promote_text_to_userspace(&self, call_id: &str) -> Result<(), String> {
        let Some((owner, from_tag, to_tag, text_relay_flows, t140_pt, red_pt)) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.owner,
                    call.from_tag.clone(),
                    call.to_tag.clone(),
                    call.text_relay_flows.clone(),
                    call.text_t140_payload_type,
                    call.text_red_payload_type,
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };
        // Reconstruct the A→B and B→A wiring from the two stored text `Forward` rules (near then far),
        // exactly as the audio promotion does from `relay_flows`.
        let layout = relay_layout_from_flows(&text_relay_flows)?;
        let a_to_b = TextDirectionConfig {
            ingress_endpoint: layout.near_endpoint,
            accepted_source: layout.near_rule.accepted_source,
            egress_endpoint: layout.near_rule.out_endpoint,
            egress_dst: layout.b_dst,
            t140_payload_type: t140_pt,
            red_payload_type: red_pt,
            // Plaintext promotion (from an in-kernel `Forward` relay) — no SRTP on either side.
            secure_ingress: None,
            secure_egress: None,
        };
        let b_to_a = TextDirectionConfig {
            ingress_endpoint: layout.far_endpoint,
            accepted_source: layout.far_rule.accepted_source,
            egress_endpoint: layout.far_rule.out_endpoint,
            egress_dst: layout.a_dst,
            t140_payload_type: t140_pt,
            red_payload_type: red_pt,
            secure_ingress: None,
            secure_egress: None,
        };
        // Switch both text endpoints to Redirect so the dispatcher routes them to the text actor.
        for endpoint in [layout.near_endpoint, layout.far_endpoint] {
            self.datapath
                .install_flow(endpoint, FlowAction::Redirect)
                .map_err(|error| format!("install text redirect: {error}"))?;
        }
        let call = TextCall::new(call_id, from_tag, to_tag, a_to_b, b_to_a, layout.latch);
        let owner_events = self.event_sink(owner);
        self.text
            .register(call, self.datapath.clone(), owner_events);
        Ok(())
    }

    /// Demote a promoted text stream back to the in-kernel `Forward` relay once no text-observability
    /// feature holds it: deregister the text actor (drops its routes) and reinstall the two stored text
    /// `Forward` rules (the ones promotion redirected away from). Best-effort — on an install error the
    /// text leg is left redirected (still relaying + observing through the actor), which is correct if
    /// heavier, and logged.
    async fn demote_text_to_kernel(&self, call_id: &str) {
        if !self.text.is_text_call(call_id) {
            return;
        }
        // A secure (SDES-SRTP) text stream can never run in-kernel (SRTP is terminated in userspace), so
        // it is never demoted — it has no `text_relay_flows` to reinstall and its `SecureLeg`s live in
        // the text actor. Bail rather than deregister the actor and strand the redirected endpoints.
        if self
            .owned_call_internal(call_id, |call| call.text_secure)
            .unwrap_or(false)
        {
            return;
        }
        let Some(text_relay_flows) =
            self.owned_call_internal(call_id, |call| call.text_relay_flows.clone())
        else {
            return;
        };
        self.text.deregister(call_id);
        for (endpoint, action) in &text_relay_flows {
            if let Err(error) = self.datapath.install_flow(*endpoint, *action) {
                tracing::warn!(
                    target: "siphon_rtp::text",
                    %error,
                    call_id,
                    "demote text: failed to reinstall Forward rule; text leg stays redirected"
                );
                return;
            }
        }
    }
}

/// The per-direction endpoints, source gates, egress targets and latch reconstructed from a promoted
/// passthrough relay's stored `Forward` rules (`Call::relay_flows`). Shared by the relay-only promote
/// ([`Engine::promote_passthrough`]) and the processing promote ([`Engine::promote_to_processing`]) so
/// both derive the datapath wiring from the exact same rules the in-kernel fast path installed.
struct PassthroughRelayLayout {
    /// The A-facing (near) RTP endpoint and its `Forward` rule (gates A's source, forwards toward B).
    near_endpoint: EndpointId,
    near_rule: ForwardRule,
    /// The B-facing (far) RTP endpoint and its `Forward` rule (gates B's source, forwards toward A).
    far_endpoint: EndpointId,
    far_rule: ForwardRule,
    /// Egress destination toward B (`near_rule.out_dst`) and toward A (`far_rule.out_dst`).
    b_dst: std::net::SocketAddr,
    a_dst: std::net::SocketAddr,
    /// Whether either side's rule latches (the passthrough default is SignalledOnly/Symmetric).
    latch: bool,
}

/// Reconstruct a promoted passthrough relay's [`PassthroughRelayLayout`] from its stored `relay_flows`
/// (the two installed RTP `Forward` rules — near then far, per `answer`'s passthrough arm; any
/// companion RTCP rules are ignored, RTCP is not transcoded/relayed on the promote path). Errors — never
/// panics — if the two RTP rules or their egress destinations are missing.
fn relay_layout_from_flows(
    relay_flows: &[(EndpointId, FlowAction)],
) -> Result<PassthroughRelayLayout, String> {
    let rtp_flows: Vec<(EndpointId, ForwardRule)> = relay_flows
        .iter()
        .filter_map(|(endpoint, action)| match action {
            FlowAction::Forward(rule) => Some((*endpoint, *rule)),
            _ => None,
        })
        .collect();
    let (Some((near_endpoint, near_rule)), Some((far_endpoint, far_rule))) =
        (rtp_flows.first().copied(), rtp_flows.get(1).copied())
    else {
        return Err("passthrough call has no installed RTP relay flows".to_string());
    };
    let Some(b_dst) = near_rule.out_dst else {
        return Err("passthrough relay has no destination toward B".to_string());
    };
    let Some(a_dst) = far_rule.out_dst else {
        return Err("passthrough relay has no destination toward A".to_string());
    };
    // Latch when either side's policy latches (the passthrough default is SignalledOnly/Symmetric).
    let latch = near_rule.latch != LatchPolicy::Off || far_rule.latch != LatchPolicy::Off;
    Ok(PassthroughRelayLayout {
        near_endpoint,
        near_rule,
        far_endpoint,
        far_rule,
        b_dst,
        a_dst,
        latch,
    })
}
