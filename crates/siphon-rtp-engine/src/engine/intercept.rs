//! Lawful-interception content delivery over X3 (ETSI TS 103 221-2).

use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_proto::{CmdResult, Event, X3EndReason, X3TargetLeg, Xid};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::media_pipeline::MediaControl;
use crate::x3::{
    build_tls_client_config, ingress_directions, run_x3_delivery, split_delivery_address,
    x3_channel, X3Config, X3Counters, X3Delivery, X3DeliveryEnd, X3DeliveryTask, X3Error,
    X3TapFactory,
};

use super::{
    error_result, ok_empty, unknown_call, ClientId, Engine, PipelineKind, PromoteMode,
    PromotionReason,
};

/// One live lawful interception (ETSI TS 103 221-2 X3): the delivery task and everything teardown
/// needs after the call itself is gone.
pub(super) struct X3Session {
    /// The call's offerer tag and owning control client, copied here at attach time: teardown runs
    /// *after* `delete` has removed the call from the registry, so the end event cannot look them up.
    pub(super) from_tag: String,
    pub(super) owner: ClientId,
    /// Endpoints carrying a crypto-bridge tap, so detach clears exactly those. Empty for a call
    /// tapped in the media pipeline or in a conference room instead.
    pub(super) bridged_endpoints: Vec<EndpointId>,
    /// Builds the taps over this interception's one delivery channel. Held by the session, not by
    /// one pipeline: the interception belongs to the call, so the channel (and with it the delivery
    /// connection, the Correlation ID and the PDU sequence counter) outlives every pipeline, bridge
    /// or room the call is rebuilt with, and the taps are simply installed again on the new one.
    pub(super) factory: X3TapFactory,
    /// Whether the warrant names the caller leg, which fixes each tap's target-relative direction.
    /// A conference room ignores it: there the target is always the seated party.
    pub(super) target_is_caller: bool,
    /// Delivered/dropped counts, read at teardown for [`Event::X3Ended`]. Shared with the taps.
    pub(super) counters: Arc<X3Counters>,
    /// The delivery task (connect → drain → reconnect). Aborted on detach; it ends on its own when
    /// the taps are dropped and the buffer has drained.
    pub(super) transport: tokio::task::JoinHandle<()>,
    /// Set once an end event has been emitted, so the controller sees exactly one `x3_ended`
    /// whichever of detach and transport failure won the race.
    pub(super) ended: Arc<std::sync::atomic::AtomicBool>,
    /// The engine endpoint of a conference seat that joined its room (no call behind it), so the
    /// session ends with that seat and never carries over to a later seat under the same tag. `None`
    /// for a call's interception.
    pub(super) joined_endpoint: Option<EndpointId>,
    /// Set for the whole of a re-answer of the dialog (from the old call's teardown to the new
    /// call's registration): the session stays in the map, the old call's teardown leaves it alone,
    /// and a `detach_x3` that lands meanwhile is recorded below instead of being lost.
    pub(super) handing_over: std::sync::atomic::AtomicBool,
    /// A `detach_x3` arrived during the hand-over; honoured the moment it ends.
    pub(super) detach_requested: std::sync::atomic::AtomicBool,
}

/// What [`Engine::spawn_x3_transport`] needs to run one interception's delivery task.
pub(super) struct X3TransportSpec<'a> {
    pub(super) delivery_channel: X3Delivery,
    pub(super) tls: Arc<rustls::ClientConfig>,
    pub(super) config: &'a X3Config,
    pub(super) delivery: &'a str,
    pub(super) xid: Xid,
    pub(super) correlation_id: u64,
    pub(super) owner: ClientId,
    /// What the interception's events name: the call, or the room of a joined seat.
    pub(super) call_id: &'a str,
    pub(super) from_tag: &'a str,
    pub(super) counters: Arc<X3Counters>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// `attach_x3`: begin lawful-interception content delivery (ETSI TS 103 221-2 X3) on a call.
    ///
    /// Additive — the call keeps relaying, recording and teeing. The engine delivers what it
    /// **accepted**: after SRTP decryption and after the authentication and replay checks, so a
    /// secure leg yields plaintext RTP and a forged packet yields nothing.
    ///
    /// A seat that joined a conference room has no call. It is addressed by naming the room as
    /// `call_id` and the seat's tag as `from_tag` ([`Self::attach_x3_seat`]).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attach_x3(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        delivery: &str,
        xid: Xid,
        correlation_id: u64,
        target_leg: X3TargetLeg,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            if self
                .conference
                .joined_seat_endpoint(call_id, from_tag)
                .is_some()
            {
                return self
                    .attach_x3_seat(
                        client,
                        call_id,
                        from_tag,
                        delivery,
                        xid,
                        correlation_id,
                        target_leg,
                    )
                    .await;
            }
            return unknown_call(call_id);
        }
        match self
            .start_x3(call_id, delivery, xid, correlation_id, target_leg)
            .await
        {
            Ok(()) => ok_empty(),
            Err(reason) => error_result("attach_x3", &reason),
        }
    }

    /// What an `attach_x3` must satisfy whatever it names, before anything is installed. The node
    /// must be provisioned, and the request must carry what a Mediation Function can attach the
    /// content to.
    pub(super) fn validate_x3_request(
        &self,
        delivery: &str,
        xid: Xid,
        correlation_id: u64,
    ) -> Result<Arc<X3Config>, String> {
        // The node must be provisioned. Refusing here is the whole point: an interception accepted
        // on a node with no delivery PKI reads as done and delivers nothing.
        let Some(config) = self.x3_config.clone() else {
            return Err(X3Error::NotConfigured.to_string());
        };
        // TS 103 221-2 clause 6: the correlation ties this session's X3 content to the X2 records
        // the signalling plane emits. A zero correlation produces content no Mediation Function can
        // attach to anything, so it is refused at the command rather than discovered at the agency.
        if correlation_id == 0 {
            return Err(
                "correlation_id must be non-zero so the delivered content can be correlated \
                 with its X2 records (TS 103 221-2 clause 6)"
                    .to_string(),
            );
        }
        if xid.is_nil() {
            return Err("xid must not be the all-zero identifier".to_string());
        }
        // Validate the delivery address before promoting or dialling anything.
        split_delivery_address(delivery).map_err(|error| error.to_string())?;
        Ok(config)
    }

    /// Stand an interception up on `call_id`. Split out from [`Self::attach_x3`], which has already
    /// validated ownership.
    ///
    /// Everything that can be refused is refused **before** anything is installed, so a rejected
    /// interception leaves the call exactly as it was — and, more importantly, a controller that
    /// gets an error knows no content is flowing rather than having to guess.
    async fn start_x3(
        &self,
        call_id: &str,
        delivery: &str,
        xid: Xid,
        correlation_id: u64,
        target_leg: X3TargetLeg,
    ) -> Result<(), String> {
        let config = self.validate_x3_request(delivery, xid, correlation_id)?;

        let Some((pipeline, echo, has_far_leg, answered, seated, single_leg)) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.pipeline,
                    call.promotion_reasons.contains(&PromotionReason::Echo),
                    call.far.is_some(),
                    call.far
                        .as_ref()
                        .is_some_and(|far| far.remote_rtp.is_some()),
                    call.seat.as_ref().is_some_and(|seat| seat.seated),
                    call.is_single_leg_answer(),
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };

        // A WebSocket-takeover call's far side is a media server, not a party: there is no second
        // leg whose content a warrant covers, and the leg's media never reaches the pipeline.
        if self.ws.is_ws_call(call_id) || pipeline == PipelineKind::Ws {
            return Err(
                "a WebSocket-takeover call (ws_uri) has no relayed second party to intercept"
                    .to_string(),
            );
        }
        // Echo mode reflects a party's audio back to itself through `Direction::echo_into`, which
        // bypasses `Direction::handle` — and therefore bypasses the X3 tap and the decrypt that
        // precedes it. Rather than deliver nothing (or, worse, ciphertext), refuse and say so.
        if echo {
            return Err(
                "an echo-test call has no second party to intercept and bypasses the X3 tap"
                    .to_string(),
            );
        }
        // A call whose leg is seated in a conference room is intercepted in the room, where the
        // seated party is the target. Once the leg has left the room the call relays nothing, so
        // there is no media to intercept until it is seated again.
        let in_room = pipeline == PipelineKind::Seated;
        if in_room && !seated {
            return Err(
                "the call's leg left its conference room and relays nothing; seat it again \
                 (conference_seat) to intercept it"
                    .to_string(),
            );
        }
        // An engine-answered call (a local answer, with or without a far leg offered on it) is
        // intercepted on its one party, the engine standing in for the callee ([`Self::install_single_leg_x3`]). A far
        // leg that is offered but not answered yet is a warrant that can match at the INVITE, and
        // content (early media included) flows from the first answer on. What is left without any
        // far leg is not a call the engine answered, so there is nothing to tap.
        if !has_far_leg && !in_room && !single_leg {
            return Err("the call has no second leg to intercept".to_string());
        }

        // Build the delivery TLS once, before anything is installed: bad PKI must fail here rather
        // than leave an interception attached to a connection that can never come up.
        let tls = self.x3_tls_config_for(&config)?;

        if self
            .x3_sessions
            .get(call_id)
            .is_some_and(|session| session.handing_over.load(Ordering::SeqCst))
        {
            return Err("the call is being re-answered; retry the attach once it is".to_string());
        }
        // Replacing an existing interception: stop the old one **first**. Doing it after the new
        // taps were installed made its `StopX3` / `clear_x3_tap` remove the very taps just
        // installed, so a re-attach ended at once with nothing delivered.
        if self.x3_sessions.contains_key(call_id) {
            self.stop_x3(call_id, X3EndReason::Detached).await;
        }

        let (factory, delivery_channel) = x3_channel(config.buffer_packets);
        let target_is_caller = matches!(target_leg, X3TargetLeg::Caller);
        // Before the first answer there is no media path to tap yet. The session (and with it the
        // delivery connection, the Correlation ID and the sequence counter) is stood up now, and
        // every answer, the first one included, puts the taps onto whatever it installed
        // ([`Self::carry_x3_across_answer`]), so a 183's early media and the final answer share one
        // delivery.
        let bridged_endpoints = if answered || in_room || single_leg {
            self.install_x3_taps(call_id, &factory, target_is_caller)
                .await?
        } else {
            Vec::new()
        };

        let Some((owner, from_tag)) =
            self.owned_call_internal(call_id, |call| (call.owner, call.from_tag.clone()))
        else {
            return Err("call no longer exists".to_string());
        };
        let counters = factory.counters().clone();
        let (transport, ended) = self.spawn_x3_transport(X3TransportSpec {
            delivery_channel,
            tls,
            config: &config,
            delivery,
            xid,
            correlation_id,
            owner,
            call_id,
            from_tag: &from_tag,
            counters: counters.clone(),
        });

        self.x3_sessions.insert(
            call_id.to_string(),
            X3Session {
                from_tag: from_tag.clone(),
                owner,
                bridged_endpoints,
                factory,
                target_is_caller,
                counters,
                transport,
                ended,
                joined_endpoint: None,
                handing_over: Default::default(),
                detach_requested: Default::default(),
            },
        );
        self.emit_call_event(
            call_id,
            Event::X3Started {
                call_id: call_id.to_string(),
                from_tag,
                delivery: delivery.to_string(),
                xid,
                correlation_id,
                target_leg,
            },
        );
        // Deliberately terse: the call-id and the task id are the correlators an audit needs, and
        // the media itself is never logged.
        tracing::info!(
            target: "siphon_rtp::li",
            call_id,
            delivery,
            %xid,
            "lawful-interception content delivery attached"
        );
        Ok(())
    }

    /// Spawn the delivery task of an interception: it connects to the Mediation Function, drains the
    /// taps' buffer into the connection, reconnects when it drops and reports loss. Returns the
    /// task and the flag that makes `x3_ended` fire exactly once.
    ///
    /// Shared by a call's interception and a joined seat's, so the two cannot diverge in what the
    /// controller is told.
    pub(super) fn spawn_x3_transport(
        &self,
        spec: X3TransportSpec<'_>,
    ) -> (
        tokio::task::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let X3TransportSpec {
            delivery_channel,
            tls,
            config,
            delivery,
            xid,
            correlation_id,
            owner,
            call_id,
            from_tag,
            counters,
        } = spec;
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let events = self.event_sink(owner);
        let task = X3DeliveryTask {
            delivery: delivery_channel,
            address: delivery.to_string(),
            xid,
            correlation_id,
            network_function_id: config.network_function_id.clone(),
            interception_point_id: config.interception_point_id.clone(),
            keepalive: config.keepalive,
            connect_timeout: crate::x3::DEFAULT_CONNECT_TIMEOUT,
            tls,
        };
        let call_id = call_id.to_string();
        let from_tag = from_tag.to_string();
        let started = std::time::Instant::now();
        let flag = ended.clone();
        let handle = tokio::spawn(async move {
            let loss_events = events.clone();
            let loss_call_id = call_id.clone();
            let loss_from_tag = from_tag.clone();
            let outcome = run_x3_delivery(task, move |dropped, delivered| {
                // Warranted content did not reach the agency. The controller raises the
                // destination-level report toward the Administration Function from this.
                emit_event(
                    loss_events.as_ref(),
                    Event::X3Loss {
                        call_id: loss_call_id.clone(),
                        from_tag: loss_from_tag.clone(),
                        dropped,
                        delivered,
                        dropped_since_ms: started.elapsed().as_millis() as u64,
                    },
                );
            })
            .await;
            let reason = match outcome {
                // The session holds the tap factory for the life of the interception, so the
                // source only closes once the session itself has been removed: a detach or a
                // replacement, never a pipeline being rebuilt. `CallEnded` is reserved for the
                // call really being torn down (`teardown_call` / `finish_call`).
                X3DeliveryEnd::SourceClosed => X3EndReason::Detached,
                X3DeliveryEnd::MediationClosed => X3EndReason::MediationClosed,
            };
            emit_x3_ended(
                events.as_ref(),
                &flag,
                &call_id,
                &from_tag,
                reason,
                &counters,
            );
        });
        (handle, ended)
    }

    /// Install `factory`'s taps wherever the call's accepted plaintext lives **now**, returning the
    /// bridge endpoints that carry one (empty when the media pipeline does).
    ///
    /// Used at attach and again whenever the call's pipeline or bridge has been rebuilt
    /// ([`Self::carry_x3_across_answer`]), so the two can never disagree about where a tap sits.
    async fn install_x3_taps(
        &self,
        call_id: &str,
        factory: &X3TapFactory,
        target_is_caller: bool,
    ) -> Result<Vec<EndpointId>, String> {
        let Some((pipeline, a_local, b_local, a_endpoint, b_endpoint, single_leg)) = self
            .owned_call_internal(call_id, |call| {
                let caller = call.caller_leg();
                (
                    call.pipeline,
                    call.near.rtp.local_addr,
                    call.far
                        .as_ref()
                        .map_or(caller.rtp.local_addr, |far| far.rtp.local_addr),
                    call.near.rtp.id,
                    call.far.as_ref().map(|far| far.rtp.id),
                    call.is_single_leg_answer(),
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };
        // An engine-answered caller with no far party answering (yet): its own pipeline carries the
        // media, with an ingress and an egress tap on the one party.
        if single_leg {
            self.install_single_leg_x3(call_id, factory, target_is_caller)
                .await?;
            return Ok(Vec::new());
        }
        // §5.2.6 is target-relative, and only the warrant knows which leg is the target.
        let (direction_a, direction_b) = ingress_directions(target_is_caller);
        let tap_a = factory.tap(a_local, direction_a);
        let tap_b = factory.tap(b_local, direction_b);

        match pipeline {
            // A leg seated in a conference room is tapped by the room that owns its media: the seated
            // party is the target there, so the warrant's `target_leg` has no say in a room.
            PipelineKind::Seated => {
                let Some((conference_id, tag)) = self.seated_room(call_id) else {
                    return Err(
                        "the call's leg left its conference room and relays nothing; seat it \
                         again (conference_seat) to intercept it"
                            .to_string(),
                    );
                };
                self.install_room_x3(&conference_id, &tag, factory).await?;
                Ok(Vec::new())
            }
            // A crypto bridge relays without decoding, so its media never reaches the pipeline. This
            // is the ordinary same-codec WebRTC / SDES shape, so it is a tap site rather than a
            // rejection — a warrant has to be servable on any call.
            // A terminated DTLS offerer taps the same way: each tap sits on its own party's ingress
            // endpoint, and the bridge hands it the plaintext side of that endpoint's transform.
            // A **transcrypt** belongs here for the same reason and needs it most: both sides of the
            // wire are ciphertext, so the intermediate plaintext the bridge taps is the only place
            // the content exists in the clear anywhere in the engine.
            //
            // `SrtpTranscryptMedia` is deliberately **not** here: it is a media pipeline, so its
            // plaintext reaches the actor and it taps with the other media shapes below.
            PipelineKind::Srtp
            | PipelineKind::SrtpOfferer
            | PipelineKind::SrtpTranscrypt
            | PipelineKind::Dtls
            | PipelineKind::DtlsOfferer => {
                let Some(b_endpoint) = b_endpoint else {
                    return Err("the call has no answered second leg to intercept".to_string());
                };
                if !self.bridge.set_x3_tap(a_endpoint, tap_a)
                    || !self.bridge.set_x3_tap(b_endpoint, tap_b)
                {
                    self.bridge.clear_x3_tap(a_endpoint);
                    self.bridge.clear_x3_tap(b_endpoint);
                    return Err("the call's crypto bridge is no longer installed".to_string());
                }
                // Not also in a pipeline actor, which would deliver everything twice.
                self.media.control(call_id, MediaControl::StopX3);
                Ok(vec![a_endpoint, b_endpoint])
            }
            // Everything else decodes (or at least relays) through the media pipeline, where the tap
            // sits inside `Direction::handle` on the decrypted, authenticated slice. A plain relay is
            // held in userspace for the interception's lifetime — relay-only, so an intercepted call
            // is not forced into a transcode it did not need.
            PipelineKind::Passthrough
            | PipelineKind::Media
            | PipelineKind::SrtpMedia
            | PipelineKind::SrtpTranscryptMedia
            | PipelineKind::SrtpOffererMedia
            | PipelineKind::DtlsMedia
            | PipelineKind::DtlsOffererMedia => {
                self.hold_in_userspace(call_id, PromotionReason::X3, PromoteMode::RelayOnly)
                    .await?;
                if !self
                    .media
                    .control(call_id, MediaControl::StartX3(Box::new((tap_a, tap_b))))
                {
                    self.release_userspace_hold(call_id, PromotionReason::X3)
                        .await;
                    return Err("media actor unavailable".to_string());
                }
                Ok(Vec::new())
            }
            PipelineKind::Ws => Err(
                "a WebSocket-takeover call (ws_uri) has no relayed second party to intercept"
                    .to_string(),
            ),
        }
    }

    /// Carry a live interception onto the media path an answer has just (re)installed.
    ///
    /// The answer to a re-offer (a hold, a resume, a session refresh) rebuilds the call's pipeline
    /// or bridge, and the taps on the old one go with it. The interception belongs to the call, so
    /// the session's own tap factory builds a fresh pair onto whatever carries the call now: same
    /// delivery channel, same connection, same Correlation ID, sequence counter unbroken.
    ///
    /// A no-op on a call that is not intercepted. If the taps cannot be put back, the interception is
    /// ended loudly (`x3_ended` with `transport_error`, the nearest reason there is) rather than left
    /// attached and silent.
    pub(super) async fn carry_x3_across_answer(&self, call_id: &str) {
        let Some((factory, target_is_caller, previous)) =
            self.x3_sessions.get(call_id).map(|session| {
                (
                    session.factory.clone(),
                    session.target_is_caller,
                    session.bridged_endpoints.clone(),
                )
            })
        else {
            return;
        };
        match self
            .install_x3_taps(call_id, &factory, target_is_caller)
            .await
        {
            Ok(bridged) => {
                // A bridge endpoint that no longer carries a tap must not keep a stale one.
                for endpoint in previous
                    .iter()
                    .filter(|endpoint| !bridged.contains(endpoint))
                {
                    self.bridge.clear_x3_tap(*endpoint);
                }
                if let Some(mut session) = self.x3_sessions.get_mut(call_id) {
                    session.bridged_endpoints = bridged;
                }
            }
            Err(reason) => {
                tracing::error!(
                    target: "siphon_rtp::li",
                    call_id,
                    reason,
                    "lawful-interception taps could not be carried onto the renegotiated media \
                     path; ending the interception rather than leaving it silently deaf"
                );
                self.stop_x3(call_id, X3EndReason::TransportError).await;
            }
        }
    }

    /// `detach_x3`: stop lawful-interception content delivery. Idempotent — detaching a call that is
    /// not intercepted is not an error.
    pub(super) async fn detach_x3(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
    ) -> CmdResult {
        // A re-answer is replacing the call: the withdrawal is recorded and honoured the moment the
        // replacement is registered, so delivery never outlives a withdrawn warrant.
        if let Some(session) = self.x3_sessions.get(call_id) {
            if session.owner == client && session.handing_over.load(Ordering::SeqCst) {
                session.detach_requested.store(true, Ordering::SeqCst);
                return ok_empty();
            }
        }
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return self.detach_x3_seat(client, call_id, from_tag).await;
        }
        self.stop_x3(call_id, X3EndReason::Detached).await;
        ok_empty()
    }

    /// Tear an interception down: remove its taps, let the delivery task drain what is buffered,
    /// emit [`Event::X3Ended`] with the delivery counts, and release the userspace hold. A no-op
    /// when the call is not intercepted.
    pub(super) async fn stop_x3(&self, call_id: &str, reason: X3EndReason) {
        // The old call of a re-answer going away is not the end of the interception it hands over.
        if self
            .x3_sessions
            .get(call_id)
            .is_some_and(|session| session.handing_over.load(Ordering::SeqCst))
        {
            return;
        }
        let Some((_, session)) = self.x3_sessions.remove(call_id) else {
            return;
        };
        // Drop the taps first. That closes the packet channel, which is what lets the delivery task
        // finish sending whatever is still buffered instead of losing it.
        for endpoint in &session.bridged_endpoints {
            self.bridge.clear_x3_tap(*endpoint);
        }
        self.media.control(call_id, MediaControl::StopX3);
        // …and the room's, when the call's leg is seated in one.
        if let Some((conference_id, tag)) = self.seated_room(call_id) {
            self.clear_room_x3(&conference_id, &tag).await;
        }
        self.finish_x3_session(call_id, session, reason).await;
        self.release_userspace_hold(call_id, PromotionReason::X3)
            .await;
    }

    /// Finish an interception whose taps are already off: let the delivery task go and tell the
    /// controller, once, with the delivery counts.
    pub(super) async fn finish_x3_session(
        &self,
        call_id: &str,
        session: X3Session,
        reason: X3EndReason,
    ) {
        // Abort **and wait**, for the same reason the WS tee does: `abort()` only schedules
        // cancellation, so returning here would leave the task holding its TLS socket and its buffer.
        session.transport.abort();
        let _ = session.transport.await;
        let events = self.event_sink(session.owner);
        emit_x3_ended(
            events.as_ref(),
            &session.ended,
            call_id,
            &session.from_tag,
            reason,
            &session.counters,
        );
    }

    /// Put an interception's taps on a seat of a conference room, and say why when the room cannot
    /// take them. The room builds them from the session's own factory, so the delivery connection,
    /// Correlation ID and sequence counter carry straight on.
    pub(super) async fn install_room_x3(
        &self,
        conference_id: &str,
        tag: &str,
        factory: &X3TapFactory,
    ) -> Result<(), String> {
        let installed = self
            .conference
            .ask(conference_id, |reply| {
                crate::conference::SeatControl::SetX3 {
                    tag: tag.to_string(),
                    factory: factory.clone(),
                    reply,
                }
            })
            .await;
        match installed {
            Some(true) => Ok(()),
            Some(false) => Err(format!(
                "conference {conference_id} has no seat {tag} that can be tapped"
            )),
            None => Err(format!("conference {conference_id} did not answer")),
        }
    }

    /// Take an interception's taps off a seat of a conference room. Best effort by nature: a seat
    /// that already left took its taps with it.
    pub(super) async fn clear_room_x3(&self, conference_id: &str, tag: &str) {
        let _ = self
            .conference
            .ask(conference_id, |reply| {
                crate::conference::SeatControl::ClearX3 {
                    tag: tag.to_string(),
                    reply,
                }
            })
            .await;
    }

    /// Build (once) the ring-backed mutual-TLS client configuration for X3 delivery.
    pub(super) fn x3_tls_config_for(
        &self,
        config: &X3Config,
    ) -> Result<Arc<rustls::ClientConfig>, String> {
        if let Some(built) = self.x3_tls_config.get() {
            return Ok(built.clone());
        }
        let built = build_tls_client_config(config).map_err(|error| error.to_string())?;
        // A concurrent attach may have won the race; either instance is equivalent.
        let _ = self.x3_tls_config.set(built.clone());
        Ok(built)
    }
}

/// Emit [`Event::X3Ended`] exactly once for an interception, whichever of detach and transport
/// failure got there first, carrying the delivery counts the compliance record needs.
///
/// A non-zero `dropped` is logged at `warn!`: warranted content did not reach the agency, which is a
/// reportable failure rather than a degraded recording.
pub(super) fn emit_x3_ended(
    events: Option<&flume::Sender<Event>>,
    ended: &std::sync::atomic::AtomicBool,
    call_id: &str,
    from_tag: &str,
    reason: X3EndReason,
    counters: &X3Counters,
) {
    if ended.swap(true, Ordering::SeqCst) {
        return; // already reported
    }
    let delivered = counters.delivered();
    let dropped = counters.dropped();
    if dropped > 0 {
        tracing::warn!(
            target: "siphon_rtp::li",
            call_id,
            ?reason,
            delivered,
            dropped,
            "lawful-interception delivery ended having dropped warranted content"
        );
    } else {
        tracing::info!(
            target: "siphon_rtp::li",
            call_id,
            ?reason,
            delivered,
            "lawful-interception content delivery ended"
        );
    }
    if let Some(sender) = events {
        let _ = sender.try_send(Event::X3Ended {
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            reason,
            delivered,
            dropped,
        });
    }
}

/// Send one event to a control client's sink, if it still has one.
fn emit_event(events: Option<&flume::Sender<Event>>, event: Event) {
    if let Some(sender) = events {
        let _ = sender.try_send(event);
    }
}
