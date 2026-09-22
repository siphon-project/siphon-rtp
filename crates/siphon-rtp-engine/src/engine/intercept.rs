//! Lawful-interception content delivery over X3 (ETSI TS 103 221-2).

use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_proto::{CmdResult, Event, X3EndReason, X3TargetLeg, Xid};
use std::sync::Arc;

use crate::media_pipeline::MediaControl;
use crate::x3::{
    build_tls_client_config, ingress_directions, run_x3_delivery, split_delivery_address,
    x3_channel, X3Config, X3Counters, X3DeliveryEnd, X3DeliveryTask, X3Error,
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
    from_tag: String,
    owner: ClientId,
    /// Endpoints carrying a crypto-bridge tap, so detach clears exactly those. Empty for a call
    /// tapped in the media pipeline instead.
    bridged_endpoints: Vec<EndpointId>,
    /// Delivered/dropped counts, read at teardown for [`Event::X3Ended`]. Shared with the taps.
    counters: Arc<X3Counters>,
    /// The delivery task (connect → drain → reconnect). Aborted on detach; it ends on its own when
    /// the taps are dropped and the buffer has drained.
    transport: tokio::task::JoinHandle<()>,
    /// Set once an end event has been emitted, so the controller sees exactly one `x3_ended`
    /// whichever of detach and transport failure won the race.
    ended: Arc<std::sync::atomic::AtomicBool>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// `attach_x3`: begin lawful-interception content delivery (ETSI TS 103 221-2 X3) on a call.
    ///
    /// Additive — the call keeps relaying, recording and teeing. The engine delivers what it
    /// **accepted**: after SRTP decryption and after the authentication and replay checks, so a
    /// secure leg yields plaintext RTP and a forged packet yields nothing.
    pub(super) async fn attach_x3(
        &self,
        client: ClientId,
        call_id: &str,
        delivery: &str,
        xid: Xid,
        correlation_id: u64,
        target_leg: X3TargetLeg,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
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

        let Some((pipeline, a_local, b_local, a_endpoint, b_endpoint, echo, two_leg)) = self
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
                    call.promotion_reasons.contains(&PromotionReason::Echo),
                    call.far
                        .as_ref()
                        .is_some_and(|far| far.remote_rtp.is_some()),
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
        if !two_leg {
            return Err("the call has no answered second leg to intercept".to_string());
        }

        // Build the delivery TLS once, before anything is installed: bad PKI must fail here rather
        // than leave an interception attached to a connection that can never come up.
        let tls = self.x3_tls_client_config(&config)?;

        let (factory, delivery_channel) = x3_channel(config.buffer_packets);
        // §5.2.6 is target-relative, and only the warrant knows which leg is the target.
        let (direction_a, direction_b) =
            ingress_directions(matches!(target_leg, X3TargetLeg::Caller));
        let tap_a = factory.tap(a_local, direction_a);
        let tap_b = factory.tap(b_local, direction_b);

        // Install the taps wherever this call's accepted plaintext actually lives.
        let mut bridged_endpoints = Vec::new();
        match pipeline {
            // A crypto bridge relays without decoding, so its media never reaches the pipeline. This
            // is the ordinary same-codec WebRTC / SDES shape, so it is a tap site rather than a
            // rejection — a warrant has to be servable on any call.
            // A terminated DTLS offerer taps the same way: each tap sits on its own party's ingress
            // endpoint, and the bridge hands it the plaintext side of that endpoint's transform.
            // A **transcrypt** belongs here for the same reason and needs it most: both sides of the
            // wire are ciphertext, so the intermediate plaintext the bridge taps is the only place
            // the content exists in the clear anywhere in the engine.
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
                bridged_endpoints = vec![a_endpoint, b_endpoint];
            }
            // Everything else decodes (or at least relays) through the media pipeline, where the tap
            // sits inside `Direction::handle` on the decrypted, authenticated slice. A plain relay is
            // held in userspace for the interception's lifetime — relay-only, so an intercepted call
            // is not forced into a transcode it did not need.
            PipelineKind::Passthrough
            | PipelineKind::Media
            | PipelineKind::SrtpMedia
            | PipelineKind::SrtpMediaTranscrypt
            | PipelineKind::DtlsMedia => {
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
            }
            PipelineKind::Ws => unreachable!("rejected above"),
        }

        // Replacing an existing interception: stop the old one first so its taps and task go away.
        if self.x3_sessions.contains_key(call_id) {
            self.stop_x3(call_id, X3EndReason::Detached).await;
        }

        let Some((owner, from_tag)) =
            self.owned_call_internal(call_id, |call| (call.owner, call.from_tag.clone()))
        else {
            return Err("call no longer exists".to_string());
        };
        let counters = factory.counters().clone();
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport = {
            let events = self.events.get(&owner).map(|sink| sink.value().clone());
            let task = X3DeliveryTask {
                delivery: delivery_channel,
                address: delivery.to_string(),
                xid,
                correlation_id,
                network_function_id: config.network_function_id.clone(),
                interception_point_id: config.interception_point_id.clone(),
                keepalive: config.keepalive,
                tls,
            };
            let call_id = call_id.to_string();
            let loss_call_id = call_id.clone();
            let loss_from_tag = from_tag.clone();
            let loss_events = events.clone();
            let started = std::time::Instant::now();
            let ended = ended.clone();
            let from_tag = from_tag.clone();
            let counters = counters.clone();
            tokio::spawn(async move {
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
                    X3DeliveryEnd::SourceClosed => X3EndReason::CallEnded,
                    X3DeliveryEnd::MediationClosed => X3EndReason::MediationClosed,
                };
                emit_x3_ended(
                    events.as_ref(),
                    &ended,
                    &call_id,
                    &from_tag,
                    reason,
                    &counters,
                );
            })
        };

        self.x3_sessions.insert(
            call_id.to_string(),
            X3Session {
                from_tag: from_tag.clone(),
                owner,
                bridged_endpoints,
                counters,
                transport,
                ended,
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

    /// `detach_x3`: stop lawful-interception content delivery. Idempotent — detaching a call that is
    /// not intercepted is not an error.
    pub(super) async fn detach_x3(&self, client: ClientId, call_id: &str) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        self.stop_x3(call_id, X3EndReason::Detached).await;
        ok_empty()
    }

    /// Tear an interception down: remove its taps, let the delivery task drain what is buffered,
    /// emit [`Event::X3Ended`] with the delivery counts, and release the userspace hold. A no-op
    /// when the call is not intercepted.
    pub(super) async fn stop_x3(&self, call_id: &str, reason: X3EndReason) {
        let Some((_, session)) = self.x3_sessions.remove(call_id) else {
            return;
        };
        // Drop the taps first. That closes the packet channel, which is what lets the delivery task
        // finish sending whatever is still buffered instead of losing it.
        for endpoint in &session.bridged_endpoints {
            self.bridge.clear_x3_tap(*endpoint);
        }
        self.media.control(call_id, MediaControl::StopX3);

        // Abort **and wait**, for the same reason the WS tee does: `abort()` only schedules
        // cancellation, so returning here would leave the task holding its TLS socket and its buffer.
        session.transport.abort();
        let _ = session.transport.await;
        let events = self
            .events
            .get(&session.owner)
            .map(|sink| sink.value().clone());
        emit_x3_ended(
            events.as_ref(),
            &session.ended,
            call_id,
            &session.from_tag,
            reason,
            &session.counters,
        );
        self.release_userspace_hold(call_id, PromotionReason::X3)
            .await;
    }

    /// Build (once) the ring-backed mutual-TLS client configuration for X3 delivery.
    fn x3_tls_client_config(&self, config: &X3Config) -> Result<Arc<rustls::ClientConfig>, String> {
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
fn emit_x3_ended(
    events: Option<&flume::Sender<Event>>,
    ended: &std::sync::atomic::AtomicBool,
    call_id: &str,
    from_tag: &str,
    reason: X3EndReason,
    counters: &X3Counters,
) {
    use std::sync::atomic::Ordering;
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
