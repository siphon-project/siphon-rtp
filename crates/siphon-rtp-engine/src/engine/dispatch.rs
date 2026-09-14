//! The control entry point: client registration, event delivery, and routing commands to verbs.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, Command, Event, RecordingFormat};

use super::play::PlayOptions;
use super::record::WavRecordingRequest;
use super::{ok_empty, ClientId, Engine};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Register `client`'s async event sink — one persistent control connection — and return the
    /// receiver the control server drains to the wire. Bounded: events are dropped under
    /// backpressure rather than blocking the engine on a slow control consumer.
    pub fn register_client(&self, client: ClientId) -> flume::Receiver<Event> {
        let (sender, receiver) = flume::bounded(64);
        self.events.insert(client, sender);
        receiver
    }

    /// Drop `client`'s event sink when its control connection closes.
    pub fn deregister_client(&self, client: ClientId) {
        self.events.remove(&client);
    }

    /// Push an asynchronous event to `client`, dropping it if the client is gone or its queue is
    /// full (late events are worthless — never block the engine on a slow consumer).
    pub(super) fn push_event(&self, client: ClientId, event: Event) {
        if let Some(sender) = self.events.get(&client) {
            if sender.try_send(event).is_err() {
                tracing::debug!(?client, "control event dropped (queue full or closed)");
            }
        }
    }

    /// Push an asynchronous event to whichever client owns `call_id` (a no-op for an unknown call).
    pub(super) fn emit_call_event(&self, call_id: &str, event: Event) {
        if let Some(owner) = self.owned_call_internal(call_id, |call| call.owner) {
            self.push_event(owner, event);
        }
    }

    /// Handle one control command from `client`, producing the result to return to the caller.
    ///
    /// Increments the operational counters as a side effect: per-command totals (offer/answer/
    /// delete) before dispatch, and `control_errors_total` whenever the result is an error — so the
    /// `/metrics` surface reflects every command this engine processed (including over the NG and WS
    /// front-ends, which all funnel through here).
    pub async fn handle(&self, client: ClientId, command: Command) -> CmdResult {
        match &command {
            Command::Offer { .. } => self.metrics.record_offer(),
            Command::Answer { .. } => self.metrics.record_answer(),
            Command::Delete { .. } => self.metrics.record_delete(),
            Command::ConferenceJoin { .. } => self.metrics.record_conference_join(),
            Command::ConferenceLeave { .. } => self.metrics.record_conference_leave(),
            _ => {}
        }
        // Per-command control-plane visibility (target `siphon_rtp::control`), correlated by the
        // `call_id`/`conference_id` the command addresses — the same key the SBC logs, so a single
        // grep reconstructs a call across both processes. `call_id` is captured before `dispatch`
        // consumes `command`; the clone is a control-path (call-setup) allocation, never hot-path.
        let verb = command_name(&command);
        let call_id = command_call_id(&command).map(str::to_owned);
        let call_id_field = call_id.as_deref().unwrap_or("-");
        let chatty = is_chatty_command(&command);
        // A `received` breadcrumb at DEBUG so a hung or panicking handler still shows the command's
        // arrival before its completion line; the INFO story is the single `handled` line below.
        tracing::debug!(target: "siphon_rtp::control", verb, call_id = call_id_field, client = client.0, "control command received");

        let started = std::time::Instant::now();
        let result = self.dispatch(client, command).await;
        let elapsed_us = started.elapsed().as_micros() as u64;

        if let CmdResult::Error { reason } = &result {
            self.metrics.record_control_error();
            tracing::warn!(target: "siphon_rtp::control", verb, call_id = call_id_field, client = client.0, elapsed_us, reason = reason.as_str(), "control command failed");
        } else if chatty {
            tracing::debug!(target: "siphon_rtp::control", verb, call_id = call_id_field, client = client.0, elapsed_us, "control command handled");
        } else {
            tracing::info!(target: "siphon_rtp::control", verb, call_id = call_id_field, client = client.0, elapsed_us, "control command handled");
        }
        result
    }

    /// Dispatch one control command to its handler (the metric-free inner of [`Self::handle`]).
    async fn dispatch(&self, client: ClientId, command: Command) -> CmdResult {
        // Drain gate: a draining node runs its live calls to completion but admits no new session, so
        // it can be taken out of a rolling upgrade cleanly. Reject the two session-creating verbs;
        // everything else — query/delete/media-control on existing calls, and the cluster/census
        // verbs — still works. (Matching without binding does not move `command`.)
        if self.cluster.is_draining()
            && matches!(
                command,
                Command::Offer { .. }
                    | Command::AnswerLocal { .. }
                    | Command::ConferenceJoin { .. }
            )
        {
            return CmdResult::Error {
                reason: "node is draining; not accepting new sessions".to_string(),
            };
        }
        match command {
            Command::Reoffer {
                call_id,
                from_tag,
                sdp,
                profile,
            } => {
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
            Command::List => self.list(client),
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
                    .answer(client, &call_id, &from_tag, to_tag, &sdp, &profile)
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
            Command::SilenceMedia { call_id, .. } => self.set_silence(client, &call_id, true),
            Command::UnsilenceMedia { call_id, .. } => self.set_silence(client, &call_id, false),
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
            | Command::ConferenceLeave { .. }
            | Command::ConferenceRoute { .. }
            | Command::ConferenceBridge { .. }
            | Command::ConferencePlay { .. }
            | Command::ConferenceStopPlay { .. }
            | Command::ConferenceSetPlayGain { .. }
            | Command::ConferenceStartRecording { .. }
            | Command::ConferenceStopRecording { .. }) => {
                self.dispatch_conference(client, command).await
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
                call_id, ws_uri, ..
            } => self.attach_ws_bridge(client, &call_id, &ws_uri).await,
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
            } => match format.unwrap_or_default() {
                RecordingFormat::Pcap => {
                    self.start_recording(client, &call_id, recording_dir).await
                }
                RecordingFormat::Wav => {
                    self.start_wav_recording(
                        client,
                        &call_id,
                        &from_tag,
                        WavRecordingRequest {
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
            },
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
            Command::ConferenceLeave {
                conference_id,
                from_tag,
            } => self.conference_leave(&conference_id, &from_tag).await,
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

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Offer { .. } => "offer",
        Command::Reoffer { .. } => "reoffer",
        Command::IceCandidate { .. } => "ice_candidate",
        Command::Answer { .. } => "answer",
        Command::AnswerLocal { .. } => "answer_local",
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
        Command::ConferenceLeave { .. } => "conference_leave",
        Command::ConferenceRoute { .. } => "conference_route",
        Command::ConferenceBridge { .. } => "conference_bridge",
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
        | Command::DetachX3 { call_id, .. } => Some(call_id),
        Command::ConferenceJoin { conference_id, .. }
        | Command::ConferenceLeave { conference_id, .. }
        | Command::ConferenceRoute { conference_id, .. } => Some(conference_id),
        Command::ConferenceBridge {
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
