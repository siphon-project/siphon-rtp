//! The control entry point: client registration, event delivery, and routing commands to verbs.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, Command, Event};
use std::sync::Arc;

use super::play::PlayOptions;
use super::record::{decoded_format, DecodedRecordingRequest};
use super::{
    error_result, ok_empty, ClientGeneration, ClientId, ClientSink, ControllerAttachError,
    ControllerAttachment, ControllerIdentity, Engine,
};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Register `client`'s async event sink and return the receiver the control server drains to
    /// the wire. Bounded: events are dropped under backpressure rather than blocking the engine on
    /// a slow control consumer.
    ///
    /// For a caller that keeps the receiver for its own lifetime. A control connection uses
    /// [`Self::register_client_generation`] instead, because it has to be able to release its own
    /// registration without touching a successor's.
    pub fn register_client(&self, client: ClientId) -> flume::Receiver<Event> {
        self.register_client_generation(client).1
    }

    /// Register `client`'s async event sink, returning the generation stamped on this registration
    /// alongside the receiver. Pass the generation back to [`Self::deregister_client`]: a
    /// reconnecting controller resolves to the same `ClientId`, so an unconditional release would
    /// let the connection being replaced silence the one replacing it.
    ///
    /// Re-registering an existing `ClientId` (a controller reconnect) keeps its channel and hands
    /// back a clone of the same receiver, so events a live pipeline emits follow the controller to
    /// its new connection.
    pub fn register_client_generation(
        &self,
        client: ClientId,
    ) -> (ClientGeneration, flume::Receiver<Event>) {
        let generation = ClientGeneration(
            self.next_client_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let mut sink = self.events.entry(client).or_insert_with(|| {
            let (sender, receiver) = flume::bounded(64);
            ClientSink {
                generation,
                sender,
                receiver,
                app: crate::app_events::AppEventQueue::new(
                    crate::app_events::APP_EVENT_QUEUE_CAPACITY,
                    self.metrics.clone(),
                ),
            }
        });
        sink.generation = generation;
        (generation, sink.receiver.clone())
    }

    /// A clone of `client`'s event sender, for a slow-path actor that emits events for the life of
    /// a pipeline rather than once. `None` when the client has no registered channel.
    pub(super) fn event_sink(&self, client: ClientId) -> Option<flume::Sender<Event>> {
        self.events.get(&client).map(|sink| sink.sender.clone())
    }

    /// The `rtcp_app` queue of `client`, for a room actor that raises APP events for the life of a
    /// seat. `None` when the client has no registered channel.
    pub(super) fn app_event_queue(
        &self,
        client: ClientId,
    ) -> Option<crate::app_events::AppEventQueue> {
        self.events.get(&client).map(|sink| sink.app.clone())
    }

    /// The end of `client`'s `rtcp_app` queue its control connection drains alongside the ordinary
    /// event receiver. Re-read it after the client's registration changes (a controller identity
    /// claim): the queue itself is kept across a reconnect, like the ordinary one.
    #[must_use]
    pub fn app_event_receiver(&self, client: ClientId) -> Option<flume::Receiver<Event>> {
        self.events.get(&client).map(|sink| sink.app.receiver())
    }

    /// Release the event-sink registration a control connection made at `generation`.
    ///
    /// Conditional on the generation: a sink registered by a *later* connection on the same
    /// `ClientId` is left alone, or the connection being replaced would silence the one replacing
    /// it. And for a `ClientId` that stands for a stable controller identity the channel itself is
    /// kept — the calls it owns are still relaying and their pipelines still hold senders cloned
    /// from it, so the events they emit across the blip wait for the reconnect instead of
    /// disappearing into a channel nothing drains. The channel goes when the identity itself is
    /// reaped — once no connection is attached and no call is left under it.
    pub fn deregister_client(&self, client: ClientId, generation: ClientGeneration) {
        if self.controller_ids.contains_key(&client) {
            return;
        }
        self.events
            .remove_if(&client, |_, sink| sink.generation == generation);
    }

    /// Resolve the stable `controller_id` a control connection presents to the [`ClientId`] the
    /// engine keys call ownership, the per-client quota and event delivery on — minting it from
    /// `proposed` (the connection's own ordinal) the first time the identity is seen, and returning
    /// the one already minted on every later connection.
    ///
    /// That is what makes a control reconnect re-attach to the calls it already owns instead of
    /// stranding them under an identity that can never be presented again
    /// (docs/security-and-nat.md §5). Every ownership scope stays exactly as it was: `list` and
    /// `delete` remain owner-scoped, and a connection presenting a different id (or none) still
    /// cannot see these calls.
    ///
    /// The connection's event sink is re-registered under the resolved id as part of the attach, so
    /// the caller must release its previous registration first.
    ///
    /// Two live connections on one identity: **newest wins** — the older one's
    /// [`Shutdown`](crate::shutdown::Shutdown) is tripped and it closes. A genuine controller pool
    /// sharing an identity needs the event sink to become a set, which is deliberately not part of
    /// this.
    pub fn attach_controller(
        &self,
        controller_id: &str,
        proposed: ClientId,
    ) -> Result<ControllerAttachment, ControllerAttachError> {
        if controller_id.is_empty() {
            return Err(ControllerAttachError::Empty);
        }
        if controller_id.len() > siphon_rtp_proto::MAX_CONTROLLER_ID_LEN {
            return Err(ControllerAttachError::TooLong);
        }
        // Re-keying a connection that already owns calls would strand them under an identity
        // nothing can present — the exact failure this mechanism exists to prevent.
        if self.client_call_count(proposed) > 0 {
            return Err(ControllerAttachError::CallsAlreadyOwned);
        }

        let key: Arc<str> = Arc::from(controller_id);
        let (trigger, evicted) = crate::shutdown::channel();
        // One `entry` so two connections racing the same first sight cannot mint two ids for it.
        let mut row = self
            .controllers
            .entry(Arc::clone(&key))
            .or_insert(ControllerIdentity {
                client: proposed,
                attached: None,
            });
        let client = row.client;
        let (generation, events) = self.register_client_generation(client);
        let superseded = row.attached.replace((generation, trigger));
        drop(row);
        self.controller_ids.insert(client, key);

        if let Some((_, superseded)) = superseded {
            tracing::warn!(
                target: "siphon_rtp::control",
                controller_id,
                client = client.0,
                "a second control connection claimed this controller identity; closing the older one"
            );
            superseded.trigger();
        }
        tracing::info!(
            target: "siphon_rtp::control",
            controller_id,
            client = client.0,
            "control connection attached to its controller identity"
        );
        Ok(ControllerAttachment {
            client,
            generation,
            events,
            evicted,
        })
    }

    /// Release the attachment a connection made at `generation`. A newer connection may already
    /// have taken the identity, in which case this is a no-op — only the connection still attached
    /// may detach it.
    ///
    /// The identity row itself survives while its client still owns calls; that retention is the
    /// whole point, since the next connection presenting the same id resolves to the same
    /// `ClientId` and re-attaches to them.
    pub fn detach_controller(&self, controller_id: &str, generation: ClientGeneration) {
        let client = {
            let Some(mut row) = self.controllers.get_mut(controller_id) else {
                return;
            };
            if row
                .attached
                .as_ref()
                .is_none_or(|(attached, _)| *attached != generation)
            {
                return;
            }
            row.attached = None;
            row.client
        };
        self.reap_detached_controller(client);
    }

    /// Drop a controller identity once nothing depends on it: no connection attached, and no calls
    /// left under its `ClientId`.
    pub(super) fn reap_detached_controller(&self, client: ClientId) {
        if self.client_call_count(client) > 0 {
            return;
        }
        let key = match self.controller_ids.get(&client) {
            Some(entry) => Arc::clone(entry.value()),
            None => return,
        };
        // The predicate runs under the shard lock, so a connection that attached in the meantime
        // keeps its row rather than racing the reap.
        let removed = self.controllers.remove_if(&key, |_, row| {
            row.client == client && row.attached.is_none()
        });
        if removed.is_some() {
            self.controller_ids.remove(&client);
            // The channel is kept alive for the identity's sake alone (see
            // [`Self::deregister_client`]), so it goes at the same moment the identity does.
            self.events.remove(&client);
        }
    }

    /// Push an asynchronous event to `client`, dropping it if the client is gone or its queue is
    /// full (late events are worthless — never block the engine on a slow consumer).
    pub(super) fn push_event(&self, client: ClientId, event: Event) {
        if let Some(sink) = self.events.get(&client) {
            if sink.sender.try_send(event).is_err() {
                tracing::debug!(?client, "control event dropped (queue full or closed)");
            }
        }
    }

    /// The refusal for a verb a seated (or seated-then-left) call cannot take, or `None` when the
    /// command is not addressed to such a call or is one it answers: `delete`, `query`, a further
    /// `conference_seat`, `stop_recording`, and — while seated — `silence_media` / `block_media` and
    /// their reverses, `play_media` / `stop_media` / `set_play_gain` and `start_recording`, which
    /// act on the seat.
    fn seated_call_refusal(&self, client: ClientId, command: &Command) -> Option<CmdResult> {
        let call_id = command_call_id(command)?;
        if command.is_conference() {
            return None;
        }
        let (conference_id, seated) = self
            .owned_call(client, call_id, |call| {
                call.seat
                    .as_ref()
                    .map(|seat| (seat.conference_id.clone(), seat.seated))
            })
            .flatten()?;
        let allowed = match command {
            Command::Delete { .. } | Command::Query { .. } | Command::ConferenceSeat { .. } => true,
            Command::SilenceMedia { .. }
            | Command::UnsilenceMedia { .. }
            | Command::BlockMedia { .. }
            | Command::UnblockMedia { .. }
            | Command::PlayMedia { .. }
            | Command::StopMedia { .. }
            | Command::SetPlayGain { .. }
            | Command::StartRecording { .. } => seated,
            // A recording kept running across a leave can still be stopped.
            Command::StopRecording { .. } => true,
            _ => false,
        };
        if allowed {
            return None;
        }
        let reason = if seated {
            format!(
                "{}: conference-seated: the call's leg is seated in conference {conference_id}; \
                 address the room with the conference_* verbs, or conference_leave first",
                command_name(command)
            )
        } else {
            format!(
                "{}: the call's leg left conference {conference_id} and relays nothing; seat it \
                 again (conference_seat) or delete it",
                command_name(command)
            )
        };
        Some(CmdResult::Error { reason })
    }

    /// Push an asynchronous event to whichever client owns `call_id` (a no-op for an unknown call).
    pub(super) fn emit_call_event(&self, call_id: &str, event: Event) {
        if let Some(owner) = self.owned_call_internal(call_id, |call| call.owner) {
            self.push_event(owner, event);
        }
    }

    /// Handle one control command from `client`, producing the result to return to the caller.
    ///
    /// The command addresses the unscoped call of its `call_id`. This is the entry every front end
    /// that has no scope to offer uses (the NG front end, an embedder), and it is exactly
    /// [`Self::handle_scoped`] with no scope.
    pub async fn handle(&self, client: ClientId, command: Command) -> CmdResult {
        self.handle_scoped(client, None, command).await
    }

    /// Handle one control command that addresses the call `(scope, call_id)`.
    ///
    /// `scope` is as the frame carried it: absent or empty for the unscoped call, otherwise a name
    /// that must pass [`siphon_rtp_proto::validate_scope`]. A malformed one is refused before any
    /// work, on every verb.
    ///
    /// Increments the operational counters as a side effect: per-command totals (offer/answer/
    /// delete) before dispatch, and `control_errors_total` whenever the result is an error — so the
    /// `/metrics` surface reflects every command this engine processed (including over the NG and WS
    /// front-ends, which all funnel through here).
    pub async fn handle_scoped(
        &self,
        client: ClientId,
        scope: Option<&str>,
        mut command: Command,
    ) -> CmdResult {
        match &command {
            Command::Offer { .. } => self.metrics.record_offer(),
            Command::Answer { .. } => self.metrics.record_answer(),
            Command::Delete { .. } => self.metrics.record_delete(),
            Command::ConferenceJoin { .. } => self.metrics.record_conference_join(),
            Command::ConferenceOffer { .. } => self.metrics.record_conference_offer(),
            Command::ConferenceAnswer { .. } => self.metrics.record_conference_answer(),
            Command::ConferenceLeave { .. } => self.metrics.record_conference_leave(),
            _ => {}
        }
        // Per-command control-plane visibility (target `siphon_rtp::control`), correlated by the
        // `call_id`/`conference_id` the command addresses — the same key the SBC logs, so a single
        // grep reconstructs a call across both processes. `call_id` is captured before `dispatch`
        // consumes `command`; the clone is a control-path (call-setup) allocation, never hot-path.
        // The `scope` field is recorded only when the frame named one.
        let verb = command_name(&command);
        let call_id = command_call_id(&command).map(str::to_owned);
        let call_id_field = call_id.as_deref().unwrap_or("-");
        let chatty = is_chatty_command(&command);
        // A `received` breadcrumb at DEBUG so a hung or panicking handler still shows the command's
        // arrival before its completion line; the INFO story is the single `handled` line below.
        tracing::debug!(target: "siphon_rtp::control", verb, call_id = call_id_field, scope, client = client.0, "control command received");

        let anchors = matches!(command, Command::Offer { .. } | Command::AnswerLocal { .. });
        let started = std::time::Instant::now();
        // From here on the command names its call by key (see [`super::scope`]).
        let result = match key_command(scope, &mut command) {
            Ok(scope) => self.dispatch(client, scope, command).await,
            Err(reason) => CmdResult::Error { reason },
        };
        if scope.is_some_and(|scope| !scope.is_empty()) && anchors && !is_error(&result) {
            self.metrics.record_scoped_offer();
        }
        let elapsed_us = started.elapsed().as_micros() as u64;

        if let CmdResult::Error { reason } = &result {
            self.metrics.record_control_error();
            tracing::warn!(target: "siphon_rtp::control", verb, call_id = call_id_field, scope, client = client.0, elapsed_us, reason = reason.as_str(), "control command failed");
        } else if chatty {
            tracing::debug!(target: "siphon_rtp::control", verb, call_id = call_id_field, scope, client = client.0, elapsed_us, "control command handled");
        } else {
            tracing::info!(target: "siphon_rtp::control", verb, call_id = call_id_field, scope, client = client.0, elapsed_us, "control command handled");
        }
        result
    }

    /// Dispatch one control command to its handler (the metric-free inner of [`Self::handle`]).
    ///
    /// `scope` is the validated scope of the frame. Every verb that names a call already carries it
    /// in the call's key; it is passed on only for `list`, which names none.
    async fn dispatch(&self, client: ClientId, scope: Option<&str>, command: Command) -> CmdResult {
        // Drain gate: a draining node runs its live calls to completion but admits no new session, so
        // it can be taken out of a rolling upgrade cleanly. Reject the session-creating verbs (an
        // offered conference seat is one; its `conference_answer` completes a setup already admitted);
        // everything else — query/delete/media-control on existing calls, and the cluster/census
        // verbs — still works. (Matching without binding does not move `command`.)
        if self.cluster.is_draining()
            && matches!(
                command,
                Command::Offer { .. }
                    | Command::AnswerLocal { .. }
                    | Command::ConferenceJoin { .. }
                    | Command::ForwardJoin { .. }
                    | Command::ForwardOffer { .. }
                    | Command::ConferenceOffer { .. }
                    // A seat is a new conference participant, even though its call is not new.
                    | Command::ConferenceSeat { .. }
            )
        {
            return CmdResult::Error {
                reason: "node is draining; not accepting new sessions".to_string(),
            };
        }
        // A call whose leg sits in a room answers only the verbs that mean something for a seat. The
        // rest would rebuild a media path the room owns now, so each is refused naming the room.
        if let Some(refusal) = self.seated_call_refusal(client, &command) {
            return refusal;
        }
        match command {
            Command::ConferenceSeat {
                call_id,
                from_tag,
                conference_id,
                role,
            } => {
                self.conference_seat(client, &call_id, &from_tag, &conference_id, role)
                    .await
            }
            Command::Reoffer {
                call_id,
                from_tag,
                sdp,
                profile,
            } => {
                // A far leg `offer_far` offered has no party behind it yet, and the caller already
                // holds the answer the local pipeline gave it; there is nothing to renegotiate toward.
                if self.owned_call(client, &call_id, super::Call::far_offer_pending) == Some(true) {
                    return CmdResult::Error {
                        reason: "reoffer: far-offer-pending: the far leg offer_far offered is not \
                                 answered yet; answer it or delete it first"
                            .to_string(),
                    };
                }
                self.reoffer(client, &call_id, &from_tag, &sdp, &profile)
                    .await
            }
            Command::IceCandidate {
                call_id,
                from_tag,
                to_tag,
                candidates,
                end_of_candidates,
            } => self.ice_candidate(
                client,
                &call_id,
                &from_tag,
                to_tag.as_deref(),
                &candidates,
                end_of_candidates,
            ),
            Command::Ping => CmdResult::Pong,
            Command::List => self.list(client, scope),
            Command::Statistics => self.statistics(),
            Command::Load => self.load_snapshot(),
            Command::NodeInfo => self.node_info(),
            Command::Drain => {
                self.cluster.set_draining(true);
                ok_empty()
            }
            Command::Undrain => {
                self.cluster.set_draining(false);
                ok_empty()
            }
            Command::Checkpoint { call_id, .. } => self.checkpoint(client, &call_id),
            Command::Restore { snapshot } => self.restore(client, &snapshot).await,
            Command::Offer {
                call_id,
                from_tag,
                sdp,
                profile,
            } => self.offer(client, call_id, from_tag, &sdp, &profile).await,
            Command::Answer {
                call_id,
                from_tag,
                to_tag,
                sdp,
                profile,
            } => {
                let result = self
                    .answer_or_complete_far(client, &call_id, &from_tag, to_tag, &sdp, &profile)
                    .await;
                self.apply_profile_ws_tee(&call_id, &profile, result).await
            }
            Command::AnswerLocal {
                call_id,
                from_tag,
                sdp,
                profile,
            } => {
                let result = self
                    .answer_local(client, &call_id, from_tag, &sdp, &profile)
                    .await;
                self.apply_profile_ws_tee(&call_id, &profile, result).await
            }
            Command::OfferFar {
                call_id,
                from_tag,
                profile,
            } => self.offer_far(client, &call_id, &from_tag, &profile).await,
            Command::Delete {
                call_id,
                to_tag: Some(to_tag),
                ..
            } => match self.delete_far_leg(client, &call_id, &to_tag).await {
                Some(result) => result,
                None => self.delete(client, &call_id).await,
            },
            Command::Delete { call_id, .. } => self.delete(client, &call_id).await,
            Command::Query { call_id, .. } => self.query(client, &call_id),
            Command::BlockMedia { call_id, .. } => self.set_block(client, &call_id, true).await,
            Command::UnblockMedia { call_id, .. } => self.set_block(client, &call_id, false).await,
            Command::BlockDtmf {
                call_id,
                from_tag,
                to_tag,
            } => {
                self.block_dtmf(client, &call_id, &from_tag, to_tag.as_deref(), true)
                    .await
            }
            Command::UnblockDtmf {
                call_id,
                from_tag,
                to_tag,
            } => {
                self.block_dtmf(client, &call_id, &from_tag, to_tag.as_deref(), false)
                    .await
            }
            Command::SilenceMedia { call_id, .. } => self.set_silence(client, &call_id, true).await,
            Command::UnsilenceMedia { call_id, .. } => {
                self.set_silence(client, &call_id, false).await
            }
            command @ (Command::PlayMedia { .. }
            | Command::StopMedia { .. }
            | Command::SetPlayGain { .. }
            | Command::PlayDtmf { .. }
            | Command::SubscribeRequest { .. }
            | Command::SubscribeAnswer { .. }
            | Command::Unsubscribe { .. }
            | Command::Echo { .. }
            | Command::StartRecording { .. }
            | Command::StopRecording { .. }) => self.dispatch_call_media(client, command).await,
            command @ (Command::ConferenceJoin { .. }
            | Command::ConferenceOffer { .. }
            | Command::ConferenceAnswer { .. }
            | Command::ConferenceLeave { .. }
            | Command::ConferenceRoute { .. }
            | Command::ConferenceBridge { .. }
            | Command::ConferenceUnbridge { .. }
            | Command::ConferencePlay { .. }
            | Command::ConferenceStopPlay { .. }
            | Command::ConferenceSetPlayGain { .. }
            | Command::ConferenceStartRecording { .. }
            | Command::ConferenceStopRecording { .. }) => {
                self.dispatch_conference(client, command).await
            }
            command @ (Command::ForwardJoin { .. }
            | Command::ForwardOffer { .. }
            | Command::ForwardAnswer { .. }
            | Command::ForwardLeave { .. }
            | Command::ForwardSetSource { .. }) => self.dispatch_forward(client, command).await,
            Command::SendRtcpApp {
                call_id,
                conference_id,
                from_tag,
                except_from_tags,
                stream,
                ssrc,
                name,
                subtype,
                payload,
            } => {
                self.send_rtcp_app(
                    client,
                    super::rtcp_app::AppSend {
                        call_id,
                        conference_id,
                        from_tag,
                        except_from_tags,
                        stream,
                        ssrc,
                        name,
                        subtype,
                        payload,
                    },
                )
                .await
            }
            Command::SetFloorKeys {
                call_id,
                conference_id,
                from_tag,
                keys,
            } => {
                self.set_floor_keys(client, call_id, conference_id, &from_tag, &keys)
                    .await
            }
            Command::AttachWsTee {
                call_id,
                ws_uri,
                direction,
                channels,
                sample_rate,
                ..
            } => {
                self.attach_ws_tee(client, &call_id, &ws_uri, direction, channels, sample_rate)
                    .await
            }
            Command::DetachWsTee { call_id, .. } => self.detach_ws_tee(client, &call_id).await,
            Command::AttachWsBridge {
                call_id,
                ws_uri,
                profile,
                ..
            } => {
                self.attach_ws_bridge(client, &call_id, &ws_uri, profile.as_ref())
                    .await
            }
            Command::DetachWsBridge { call_id, .. } => {
                self.detach_ws_bridge(client, &call_id).await
            }
            Command::AttachX3 {
                call_id,
                delivery,
                xid,
                correlation_id,
                target_leg,
                ..
            } => {
                self.attach_x3(client, &call_id, &delivery, xid, correlation_id, target_leg)
                    .await
            }
            Command::DetachX3 { call_id, .. } => self.detach_x3(client, &call_id).await,
            other => CmdResult::Error {
                reason: format!("unsupported command: {}", command_name(&other)),
            },
        }
    }

    /// Dispatch a call's media-control command: playback, DTMF injection, SIPREC subscriptions, echo
    /// and recording. [`Self::dispatch`] routes only those verbs here.
    async fn dispatch_call_media(&self, client: ClientId, command: Command) -> CmdResult {
        match command {
            Command::PlayMedia {
                call_id,
                from_tag,
                source,
                repeat_times,
                start_pos_ms,
                duration_ms,
                overlay,
                gain_decibels,
                to_tag,
            } => {
                self.play_media(
                    client,
                    &call_id,
                    &from_tag,
                    source,
                    PlayOptions {
                        repeat_times,
                        start_pos_ms,
                        duration_ms,
                        overlay,
                        gain_decibels,
                    },
                    to_tag.as_deref(),
                )
                .await
            }
            Command::StopMedia {
                call_id,
                from_tag,
                play_id,
            } => self.stop_media(client, &call_id, &from_tag, play_id).await,
            Command::SetPlayGain {
                call_id,
                from_tag,
                play_id,
                gain_decibels,
                ..
            } => {
                self.set_play_gain(client, &call_id, &from_tag, play_id, gain_decibels)
                    .await
            }
            Command::PlayDtmf {
                call_id,
                from_tag,
                code,
                duration_ms,
                volume_dbm0,
                pause_ms,
                to_tag,
            } => {
                self.play_dtmf(
                    client,
                    &call_id,
                    &from_tag,
                    &code,
                    duration_ms,
                    volume_dbm0,
                    pause_ms,
                    to_tag.as_deref(),
                )
                .await
            }
            Command::SubscribeRequest {
                call_id,
                from_tags,
                sdp,
                profile,
            } => {
                self.subscribe_request(client, &call_id, &from_tags, sdp.as_deref(), &profile)
                    .await
            }
            Command::SubscribeAnswer {
                call_id,
                from_tag,
                to_tag,
                sdp,
                ..
            } => {
                self.subscribe_answer(client, &call_id, &from_tag, &to_tag, &sdp)
                    .await
            }
            Command::Unsubscribe {
                call_id,
                from_tag,
                to_tag,
            } => self.unsubscribe(client, &call_id, &from_tag, &to_tag).await,
            Command::Echo {
                call_id,
                from_tag,
                to_tag,
                enabled,
            } => {
                self.set_echo(client, &call_id, &from_tag, to_tag.as_deref(), enabled)
                    .await
            }
            Command::StartRecording {
                call_id,
                from_tag,
                recording_dir,
                format,
                direction,
                channels,
                max_duration_ms,
                silence_ms,
                path,
                bitrate_bps,
            } => {
                let format = format.unwrap_or_default();
                let decoded = match decoded_format(format, bitrate_bps) {
                    Ok(decoded) => decoded,
                    Err(reason) => return error_result("start_recording", &reason),
                };
                match decoded {
                    None => self.start_recording(client, &call_id, recording_dir).await,
                    Some(decoded) => {
                        self.start_wav_recording(
                            client,
                            &call_id,
                            &from_tag,
                            DecodedRecordingRequest {
                                format: decoded,
                                direction: direction.unwrap_or_default(),
                                channels: channels.unwrap_or_default(),
                                limits: crate::recording::RecordingLimits {
                                    max_duration_ms,
                                    silence_ms,
                                },
                                path,
                                recording_dir,
                            },
                        )
                        .await
                    }
                }
            }
            Command::StopRecording {
                call_id,
                recording_id,
                ..
            } => {
                self.stop_recording(client, &call_id, recording_id.as_deref())
                    .await
            }
            other => CmdResult::Error {
                reason: format!("unsupported command: {}", command_name(&other)),
            },
        }
    }

    /// Dispatch a conference command: seating, routing, bridging, and room-wide playback and
    /// recording. [`Self::dispatch`] routes only those verbs here.
    async fn dispatch_conference(&self, client: ClientId, command: Command) -> CmdResult {
        match command {
            Command::ConferenceJoin {
                conference_id,
                from_tag,
                sdp,
                role,
                profile,
            } => {
                self.conference_join(client, &conference_id, from_tag, &sdp, role, &profile)
                    .await
            }
            Command::ConferenceOffer {
                conference_id,
                from_tag,
                role,
                profile,
            } => {
                self.conference_offer(&conference_id, from_tag, role, profile)
                    .await
            }
            Command::ConferenceAnswer {
                conference_id,
                from_tag,
                sdp,
                received_from,
            } => {
                self.conference_answer(client, &conference_id, &from_tag, &sdp, received_from)
                    .await
            }
            Command::ConferenceLeave {
                conference_id,
                from_tag,
            } => {
                self.conference_leave(client, &conference_id, &from_tag)
                    .await
            }
            Command::ConferenceRoute {
                conference_id,
                from_tag,
                role,
            } => self.conference_route(&conference_id, &from_tag, role),
            Command::ConferenceBridge {
                conference_id_a,
                conference_id_b,
                direction,
            } => self.conference_bridge(&conference_id_a, &conference_id_b, direction),
            Command::ConferenceUnbridge {
                conference_id_a,
                conference_id_b,
            } => self.conference_unbridge(&conference_id_a, &conference_id_b),
            Command::ConferencePlay {
                conference_id,
                source,
                repeat_times,
                start_pos_ms,
                duration_ms,
                gain_decibels,
            } => {
                self.conference_play(
                    &conference_id,
                    source,
                    PlayOptions {
                        repeat_times,
                        start_pos_ms,
                        duration_ms,
                        overlay: true,
                        gain_decibels,
                    },
                )
                .await
            }
            Command::ConferenceStopPlay {
                conference_id,
                play_id,
            } => self.conference_stop_play(&conference_id, play_id).await,
            Command::ConferenceSetPlayGain {
                conference_id,
                play_id,
                gain_decibels,
            } => {
                self.conference_set_play_gain(&conference_id, play_id, gain_decibels)
                    .await
            }
            Command::ConferenceStartRecording {
                conference_id,
                path,
                recording_dir,
                max_duration_ms,
                silence_ms,
            } => {
                self.conference_start_recording(
                    client,
                    &conference_id,
                    path,
                    recording_dir,
                    crate::recording::RecordingLimits {
                        max_duration_ms,
                        silence_ms,
                    },
                )
                .await
            }
            Command::ConferenceStopRecording {
                conference_id,
                recording_id,
            } => {
                self.conference_stop_recording(&conference_id, recording_id.as_deref())
                    .await
            }
            other => CmdResult::Error {
                reason: format!("unsupported command: {}", command_name(&other)),
            },
        }
    }
}

/// Turn the `call_id` a command names into the key of the call it addresses under `scope`, and
/// return the scope as validated (`None` for an absent or an empty one).
///
/// A conference verb names a room by an id its controller chose, not by a SIP Call-ID, so a scope
/// has nothing to tell apart there. One is refused rather than dropped: a controller that believes
/// two functions' rooms are separate when they are one room would otherwise find out in the mix.
fn key_command<'a>(
    scope: Option<&'a str>,
    command: &mut Command,
) -> Result<Option<&'a str>, String> {
    let scope = siphon_rtp_proto::normalize_scope(scope).map_err(|error| error.to_string())?;
    if scope.is_some() && command.is_conference() {
        return Err(
            "scope does not apply to conference verbs; put the function in the conference_id"
                .to_string(),
        );
    }
    if let Some(call_id) = command.call_id_mut() {
        *call_id = super::scope::compose(scope, call_id)?;
    }
    Ok(scope)
}

fn is_error(result: &CmdResult) -> bool {
    matches!(result, CmdResult::Error { .. })
}

pub(super) fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Offer { .. } => "offer",
        Command::Reoffer { .. } => "reoffer",
        Command::IceCandidate { .. } => "ice_candidate",
        Command::Answer { .. } => "answer",
        Command::AnswerLocal { .. } => "answer_local",
        Command::OfferFar { .. } => "offer_far",
        Command::Delete { .. } => "delete",
        Command::Query { .. } => "query",
        Command::Ping => "ping",
        Command::List => "list",
        Command::Statistics => "statistics",
        Command::Load => "load",
        Command::NodeInfo => "node_info",
        Command::Drain => "drain",
        Command::Undrain => "undrain",
        Command::Checkpoint { .. } => "checkpoint",
        Command::Restore { .. } => "restore",
        Command::PlayMedia { .. } => "play_media",
        Command::StopMedia { .. } => "stop_media",
        Command::SetPlayGain { .. } => "set_play_gain",
        Command::PlayDtmf { .. } => "play_dtmf",
        Command::SilenceMedia { .. } => "silence_media",
        Command::UnsilenceMedia { .. } => "unsilence_media",
        Command::Echo { .. } => "echo",
        Command::BlockMedia { .. } => "block_media",
        Command::UnblockMedia { .. } => "unblock_media",
        Command::BlockDtmf { .. } => "block_dtmf",
        Command::UnblockDtmf { .. } => "unblock_dtmf",
        Command::StartRecording { .. } => "start_recording",
        Command::StopRecording { .. } => "stop_recording",
        Command::SubscribeRequest { .. } => "subscribe_request",
        Command::SubscribeAnswer { .. } => "subscribe_answer",
        Command::Unsubscribe { .. } => "unsubscribe",
        Command::ConferenceJoin { .. } => "conference_join",
        Command::ConferenceSeat { .. } => "conference_seat",
        Command::ConferenceOffer { .. } => "conference_offer",
        Command::ConferenceAnswer { .. } => "conference_answer",
        Command::ConferenceLeave { .. } => "conference_leave",
        Command::ConferenceRoute { .. } => "conference_route",
        Command::ConferenceBridge { .. } => "conference_bridge",
        Command::ConferenceUnbridge { .. } => "conference_unbridge",
        Command::ConferencePlay { .. } => "conference_play",
        Command::ConferenceStopPlay { .. } => "conference_stop_play",
        Command::ConferenceSetPlayGain { .. } => "conference_set_play_gain",
        Command::ConferenceStartRecording { .. } => "conference_start_recording",
        Command::ConferenceStopRecording { .. } => "conference_stop_recording",
        Command::AttachWsTee { .. } => "attach_ws_tee",
        Command::DetachWsTee { .. } => "detach_ws_tee",
        Command::AttachWsBridge { .. } => "attach_ws_bridge",
        Command::DetachWsBridge { .. } => "detach_ws_bridge",
        Command::AttachX3 { .. } => "attach_x3",
        Command::DetachX3 { .. } => "detach_x3",
        Command::Authenticate { .. } => "authenticate",
        Command::ForwardJoin { .. } => "forward_join",
        Command::ForwardOffer { .. } => "forward_offer",
        Command::ForwardAnswer { .. } => "forward_answer",
        Command::ForwardLeave { .. } => "forward_leave",
        Command::ForwardSetSource { .. } => "forward_set_source",
        Command::SendRtcpApp { .. } => "send_rtcp_app",
        Command::SetFloorKeys { .. } => "set_floor_keys",
        // [`Command`] is `#[non_exhaustive]`. A verb this engine has no arm for still has to be
        // *named* in the log line and in the `unsupported command: …` error the dispatch returns,
        // so it gets a stable placeholder rather than nothing. The dispatch refuses it; this only
        // decides what the refusal is called.
        _ => "unknown",
    }
}

/// The correlation id to log for a control command: the `call_id` it addresses, or the
/// `conference_id` for the conference verbs. `None` for verbs that address no specific call
/// (ping / census / cluster). Kept in step with [`command_name`] and the [`Command`] variants.
pub(super) fn command_call_id(command: &Command) -> Option<&str> {
    match command {
        Command::Offer { call_id, .. }
        | Command::Reoffer { call_id, .. }
        | Command::IceCandidate { call_id, .. }
        | Command::Answer { call_id, .. }
        | Command::AnswerLocal { call_id, .. }
        | Command::OfferFar { call_id, .. }
        | Command::Delete { call_id, .. }
        | Command::Query { call_id, .. }
        | Command::Checkpoint { call_id, .. }
        | Command::PlayMedia { call_id, .. }
        | Command::StopMedia { call_id, .. }
        | Command::SetPlayGain { call_id, .. }
        | Command::PlayDtmf { call_id, .. }
        | Command::SilenceMedia { call_id, .. }
        | Command::UnsilenceMedia { call_id, .. }
        | Command::Echo { call_id, .. }
        | Command::BlockMedia { call_id, .. }
        | Command::UnblockMedia { call_id, .. }
        | Command::BlockDtmf { call_id, .. }
        | Command::UnblockDtmf { call_id, .. }
        | Command::StartRecording { call_id, .. }
        | Command::StopRecording { call_id, .. }
        | Command::SubscribeRequest { call_id, .. }
        | Command::SubscribeAnswer { call_id, .. }
        | Command::Unsubscribe { call_id, .. }
        | Command::AttachWsTee { call_id, .. }
        | Command::DetachWsTee { call_id, .. }
        | Command::AttachWsBridge { call_id, .. }
        | Command::DetachWsBridge { call_id, .. }
        | Command::AttachX3 { call_id, .. }
        | Command::DetachX3 { call_id, .. }
        | Command::ConferenceSeat { call_id, .. } => Some(call_id),
        Command::ConferenceJoin { conference_id, .. }
        | Command::ConferenceOffer { conference_id, .. }
        | Command::ConferenceAnswer { conference_id, .. }
        | Command::ConferenceLeave { conference_id, .. }
        | Command::ConferenceRoute { conference_id, .. }
        | Command::ForwardJoin { conference_id, .. }
        | Command::ForwardOffer { conference_id, .. }
        | Command::ForwardAnswer { conference_id, .. }
        | Command::ForwardLeave { conference_id, .. }
        | Command::ForwardSetSource { conference_id, .. } => Some(conference_id),
        Command::SendRtcpApp {
            call_id,
            conference_id,
            ..
        }
        | Command::SetFloorKeys {
            call_id,
            conference_id,
            ..
        } => call_id.as_deref().or(conference_id.as_deref()),
        Command::ConferenceBridge {
            conference_id_a, ..
        }
        | Command::ConferenceUnbridge {
            conference_id_a, ..
        } => Some(conference_id_a),
        Command::Ping
        | Command::List
        | Command::Statistics
        | Command::Load
        | Command::NodeInfo
        | Command::Drain
        | Command::Undrain
        | Command::Restore { .. }
        | Command::Authenticate { .. } => None,
        // [`Command`] is `#[non_exhaustive]`. A correct no-op: this function only picks the
        // correlation id for the control log line, and there is no field to read on a variant this
        // build does not know. The command itself is refused by the dispatch's wildcard arm, so
        // nothing is silently accepted here — only logged with `call_id = "-"`.
        _ => None,
    }
}

/// Read-only / health-probe verbs a controller polls frequently (the RTPEngine health probe pings
/// every few seconds). These log the per-command breadcrumb at DEBUG so the default INFO stream
/// stays a clean per-call story (offer / answer / delete and the media-control verbs).
pub(super) fn is_chatty_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Ping
            | Command::List
            | Command::Statistics
            | Command::Load
            | Command::NodeInfo
            | Command::Query { .. }
    )
}
