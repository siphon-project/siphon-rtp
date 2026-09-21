//! WebSocket tees: send-only streaming of a relaying call's decoded audio.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_media::bridge::protocol::MediaFormat;
use siphon_rtp_proto::{CmdResult, Event, ProfileFlags, WsTeeDirection, WsTeeEndReason};
use std::sync::Arc;

use crate::media_pipeline::{MediaControl, RawTee};

use super::record::pcm_rate_of;
use super::{
    error_result, ok_empty, unknown_call, ClientId, Engine, PipelineKind, PromoteMode,
    PromotionReason,
};

pub(super) struct WsTee {
    /// The tee's stream id — also the fork tag on every leg it taps, and the event correlator.
    stream_id: String,
    /// The call's offerer tag and owning control client, copied here at attach time: teardown runs
    /// *after* `delete` has already removed the call from the registry, so the end event cannot look
    /// them up any more.
    from_tag: String,
    owner: ClientId,
    /// Shared frame assembler; read at teardown for the `frames_sent` / `frames_dropped` on
    /// [`Event::WsTeeEnded`].
    pub(super) mixer: Arc<std::sync::Mutex<siphon_rtp_media::bridge::tee::TeeMixer>>,
    /// Which legs carry a sink for this tee (`true` = leg A / caller), so detach targets exactly them.
    tapped_legs: Vec<bool>,
    /// The transport task (dial → `start` → drain). Aborted on detach; it emits
    /// [`Event::WsTeeEnded`] itself when the *server* ends the stream first.
    transport: tokio::task::JoinHandle<()>,
    /// Set once an end event has been emitted for this tee, so the controller sees exactly one
    /// `ws_tee_ended` whether the server or the detach won the race.
    ended: Arc<std::sync::atomic::AtomicBool>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Attach a **WebSocket tee** to an established call ([`Command::AttachWsTee`]): stream the call's
    /// decoded audio to a WS server *while it keeps relaying*.
    ///
    /// The tee is a [`siphon_rtp_media::fanout::MediaSink`] on the same post-decode tap SIPREC forking
    /// uses, so one decode of each stream feeds the peer, the recorder, any SIPREC fork **and** the WS
    /// consumer — never a second [`siphon_rtp_media::leg::MediaLeg`] (two jitter buffers on one stream
    /// make two different concealment decisions, and the consumer would hear artefacts the call never
    /// had). A plain in-kernel relay is promoted to a **processing** media call for the tee's lifetime
    /// (a relay-only promotion never decodes, so it would tee nothing) and demoted again on detach.
    ///
    /// This is *not* `ProfileFlags::ws_uri`: takeover makes the WS server leg A's far side and leaves
    /// A↔B unwired, while a tee is send-only and additive. A takeover call therefore cannot be teed —
    /// its media never reaches the media pipeline — and is rejected rather than silently ignored.
    pub(super) async fn attach_ws_tee(
        &self,
        client: ClientId,
        call_id: &str,
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        match self
            .start_ws_tee(call_id, ws_uri, direction, channels, sample_rate)
            .await
        {
            Ok(()) => ok_empty(),
            Err(reason) => error_result("attach_ws_tee", &reason),
        }
    }

    /// Stand a tee up on `call_id` (shared by [`Self::attach_ws_tee`] and the `ProfileFlags::ws_tee`
    /// answer-time path, which has already validated ownership).
    ///
    /// `sample_rate` is the requested L16 wire rate, independent of either leg's codec rate; `None`
    /// follows the tapped leg's own PCM rate. It is validated before the call is promoted, before the
    /// server is dialled and before a single sink is attached, so a bad rate leaves the relay exactly
    /// as it was.
    async fn start_ws_tee(
        &self,
        call_id: &str,
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> Result<(), String> {
        use siphon_rtp_media::bridge::protocol::{Encoding, Endianness};
        use siphon_rtp_media::bridge::tee::{
            plan_ws_tee, tee_start_message, TeeChannel, WsTeeSink,
        };
        use siphon_rtp_media::bridge::wire_rate::{validate_wire_sample_rate, wire_resampler};

        // A WS-takeover call's media is bridged to its own server and never reaches the pipeline, and a
        // secure (SRTP-bridge) call's Redirect path is crypto-only — neither has a fan-out to tap.
        // Reject clearly instead of attaching a sink that would never fire (mirrors `subscribe_request`).
        let pipeline = self
            .owned_call_internal(call_id, |call| call.pipeline)
            .ok_or_else(|| "call no longer exists".to_string())?;
        if self.ws.is_ws_call(call_id) || pipeline == PipelineKind::Ws {
            return Err(
                "a WebSocket-takeover call (ws_uri) has no relay path to tee; use one or the other"
                    .to_string(),
            );
        }
        if pipeline.is_crypto_bridge() {
            // The crypto *bridges* relay ciphertext without ever decoding it, so there is no
            // post-decode fan-out to tap. Note this rejects only the bridge kinds: a secure call that
            // runs through the media pipeline (`SrtpMedia` / `DtlsMedia`) decodes like any other and
            // tees fine — for DTLS that is exactly what WP-R4 unlocked.
            return Err(
                "teeing a secure crypto-bridge call is not supported — the bridge relays \
                 ciphertext without decoding; a transcoded secure call can be teed"
                    .to_string(),
            );
        }

        // Which legs feed the tee. A single-leg (offer-only / local-answer) call has no callee, so a
        // `both` request degrades to the caller's monologue rather than stalling on a channel that
        // will never produce a frame (a stereo frame needs *both* rings full). A callee exists only
        // once a far leg has an answered peer address — the discriminator that works *before* promotion
        // (the media registry's equal-endpoints test only exists once an actor is up), and it covers
        // both single-leg shapes: `answer_local` has no far leg at all, an unanswered offer has one
        // with no peer.
        let (near_codec, far_codec, two_leg) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.far
                        .as_ref()
                        .is_some_and(|far| far.remote_rtp.is_some()),
                )
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        let (tap_caller, tap_callee) = match direction {
            WsTeeDirection::Caller => (true, false),
            WsTeeDirection::Callee => (false, true),
            WsTeeDirection::Both => (true, two_leg),
        };
        if tap_callee && !two_leg {
            return Err("the call has no callee leg to tee".to_string());
        }
        let stereo_source = tap_caller && tap_callee;

        // The default wire rate is the *caller* leg's decoded PCM rate (the RTP clock is not it —
        // G.722 samples at 16 kHz and clocks RTP at 8 kHz, RFC 3551 §4.5.2), so the common case (both
        // legs on one codec) needs no conversion at all. A callee-only tee follows the callee's rate
        // instead. A controller-requested `sample_rate` overrides both: it is the rate the consumer
        // wants to receive, and every tapped leg is resampled into it.
        let caller_rate = near_codec.as_ref().map(pcm_rate_of).transpose()?;
        let callee_rate = far_codec.as_ref().map(pcm_rate_of).transpose()?;
        let default_wire_rate = if tap_caller {
            caller_rate.ok_or_else(|| "the caller leg has no negotiated codec".to_string())?
        } else {
            callee_rate.ok_or_else(|| "the callee leg has no negotiated codec".to_string())?
        };
        let wire_rate = match sample_rate {
            Some(requested) => {
                validate_wire_sample_rate(requested).map_err(|error| error.to_string())?
            }
            None => default_wire_rate,
        };
        let ptime = near_codec
            .as_ref()
            .map_or(20, |codec| codec.ptime_ms.max(1));
        let wire_channels = match channels {
            Some(requested) if stereo_source => requested.clamp(1, 2),
            Some(_) => 1, // a single-leg tee is mono whatever was asked for
            None if stereo_source => 2,
            None => 1,
        };

        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: wire_rate,
            channels: wire_channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime,
        };

        // Build every conversion **before** the dial and the promotion, so a rate this engine cannot
        // serve fails while the call is still untouched — no socket to close, no promoted pipeline to
        // demote, no sink to unwind. A leg already at the wire rate yields `None` and costs nothing.
        let mut tap_plan: Vec<(
            bool,
            TeeChannel,
            Option<siphon_rtp_dsp::resample::Resampler>,
        )> = Vec::new();
        for (source_a, channel, leg_rate, wanted) in [
            (true, TeeChannel::Caller, caller_rate, tap_caller),
            (false, TeeChannel::Callee, callee_rate, tap_callee),
        ] {
            if !wanted {
                continue;
            }
            let resampler = match leg_rate {
                Some(rate) => wire_resampler(rate, wire_rate).map_err(|error| error.to_string())?,
                None => None,
            };
            tap_plan.push((source_a, channel, resampler));
        }

        let plan = plan_ws_tee(format, stereo_source, !tap_caller);
        let stream_id = format!("tee-{call_id}");

        // Dial before attaching anything, so a bad URI fails cleanly with nothing to unwind.
        let connector = tokio_tungstenite::Connector::Rustls(self.ws_tls_client_config());
        let (socket, _response) =
            tokio_tungstenite::connect_async_tls_with_config(ws_uri, None, false, Some(connector))
                .await
                .map_err(|error| format!("dial {ws_uri}: {error}"))?;

        // A SIPREC subscription (or a pcap recording / DTMF block) may already hold this relay in
        // userspace with a **relay-only** actor, which forwards RTP verbatim and never decodes — the
        // post-decode fan-out a tee taps would stay dry. Rebuild it as a processing actor first. The
        // raw SIPREC tee is copied in `Direction::handle` *before* the relay/transcode split, so it is
        // unaffected by the decode; the subscriptions' tees are re-attached to the new actor.
        if self.media.is_relay_call(call_id) {
            self.upgrade_relay_to_processing(call_id).await?;
        }
        // Hold the call in a *processing* media pipeline for the tee's lifetime.
        self.hold_in_userspace(call_id, PromotionReason::WsTee, PromoteMode::Processing)
            .await?;

        // Attach one sink per tapped leg, carrying the conversion into the wire rate built above.
        let mut tapped_legs = Vec::new();
        for (source_a, channel, resampler) in tap_plan {
            let sink = WsTeeSink::new(channel, plan.mixer.clone(), stream_id.clone(), resampler);
            if !self.media.control(
                call_id,
                MediaControl::AddFork {
                    source_a,
                    sink: Box::new(sink),
                },
            ) {
                // Unwind: drop whatever we already attached and release the hold.
                for attached in &tapped_legs {
                    self.media.control(
                        call_id,
                        MediaControl::RemoveForkTagged {
                            source_a: *attached,
                            tag: stream_id.clone(),
                        },
                    );
                }
                self.release_userspace_hold(call_id, PromotionReason::WsTee)
                    .await;
                return Err("media actor unavailable".to_string());
            }
            tapped_legs.push(source_a);
        }

        // Replacing an existing tee: detach the old one first so its sinks and task go away.
        if self.ws_tees.contains_key(call_id) {
            self.stop_ws_tee(call_id, WsTeeEndReason::Detached).await;
        }

        let (owner, from_tag) = self
            .owned_call_internal(call_id, |call| (call.owner, call.from_tag.clone()))
            .ok_or_else(|| "call no longer exists".to_string())?;
        // Announced before the transport task is spawned, for the same reason the takeover bridge is
        // (see `setup_ws_bridge`): the task can end — a server that closes on the handshake — before
        // a later announcement would have been enqueued, and `ws_tee_ended` for a stream that was
        // never announced started is not something a consumer keyed on `ws_tee_started` can act on.
        self.emit_call_event(
            call_id,
            Event::WsTeeStarted {
                call_id: call_id.to_string(),
                from_tag: from_tag.clone(),
                stream_id: stream_id.clone(),
                ws_uri: ws_uri.to_string(),
                direction,
                channels: wire_channels,
                sample_rate: wire_rate,
            },
        );
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let start = tee_start_message(&stream_id, call_id, plan.format, plan.tracks.clone());
        let transport = {
            let events = self.event_sink(owner);
            let frames = plan.frames;
            let recycle = plan.recycle;
            let mixer = plan.mixer.clone();
            let call_id = call_id.to_string();
            let from_tag = from_tag.clone();
            let stream_id = stream_id.clone();
            let ended = ended.clone();
            tokio::spawn(async move {
                let outcome =
                    siphon_rtp_media::bridge::run_ws_tee(socket, start, frames, recycle).await;
                let reason = match outcome {
                    Ok(siphon_rtp_media::bridge::TeeEndReason::ServerClosed) => {
                        WsTeeEndReason::ServerClosed
                    }
                    Ok(siphon_rtp_media::bridge::TeeEndReason::ServerStopped) => {
                        WsTeeEndReason::ServerStopped
                    }
                    Ok(siphon_rtp_media::bridge::TeeEndReason::CallEnded) => {
                        WsTeeEndReason::CallEnded
                    }
                    Err(error) => {
                        tracing::debug!(%error, call_id, "ws tee transport ended with an error");
                        WsTeeEndReason::TransportError
                    }
                };
                // The server (or the transport) ended it first — report that, once.
                emit_ws_tee_ended(
                    events.as_ref(),
                    &ended,
                    &call_id,
                    &from_tag,
                    &stream_id,
                    reason,
                    &mixer,
                );
            })
        };

        self.ws_tees.insert(
            call_id.to_string(),
            WsTee {
                stream_id,
                from_tag,
                owner,
                mixer: plan.mixer,
                tapped_legs,
                transport,
                ended,
            },
        );
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            ws_uri,
            channels = wire_channels,
            sample_rate = wire_rate,
            "ws tee attached"
        );
        Ok(())
    }

    /// Rebuild a **relay-only** promoted call as a **processing** one, keeping every SIPREC raw tee it
    /// carries. A relay-only actor (the promotion `start recording` / `block DTMF` / `subscribe_request`
    /// take) forwards ingress RTP verbatim and never decodes, so nothing reaches the post-decode
    /// fan-out a WS tee taps; a processing actor decodes and re-encodes, and still copies each raw tee
    /// **before** the relay/transcode split, so the SRS keeps receiving the leg's original bytes.
    ///
    /// The old actor is deregistered first so its task is aborted rather than orphaned, and each
    /// answered subscription's tee is re-installed on the new one. The call stays processing for the
    /// rest of its life (a detach releases the tee's hold but does not rebuild the cheaper relay-only
    /// actor) — the extra decode is the price of having asked for both features at once.
    pub(super) async fn upgrade_relay_to_processing(&self, call_id: &str) -> Result<(), String> {
        // Rebuilding the actor rebuilds its *state*, and only the SIPREC raw tees can be reconstructed
        // from what the engine still holds. A live pcap capture's channel (whose drain task owns the
        // file) and a per-direction `block DTMF` gate would both be silently lost, so refuse instead of
        // quietly turning either off — the same posture `echo` already takes on a relay-only promotion.
        let blocking = self
            .owned_call_internal(call_id, |call| {
                let mut blocking = Vec::new();
                if call.promotion_reasons.contains(&PromotionReason::Recording) {
                    blocking.push("a pcap recording");
                }
                if call.promotion_reasons.contains(&PromotionReason::DtmfBlock) {
                    blocking.push("a DTMF block");
                }
                blocking
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        if !blocking.is_empty() {
            return Err(format!(
                "a WebSocket tee needs the call decoded, but {} holds this relay in a \
                 forward-only pipeline; stop it first",
                blocking.join(" and ")
            ));
        }
        self.media.deregister(call_id);
        self.promote_to_processing(call_id, false).await?;
        // Re-attach every answered subscription's raw tee to the new actor.
        let tees: Vec<(bool, RawTee)> = self
            .subscriptions
            .get(call_id)
            .map(|list| {
                list.iter()
                    .filter_map(|subscription| {
                        // A subscription still awaiting its `subscribe_answer` has no SRS address yet —
                        // nothing to re-attach; `subscribe_answer` will install it on the new actor.
                        let srs_dst = subscription.srs_rtp?;
                        let tee = RawTee {
                            subscriber_endpoint: subscription.subscriber_endpoint.id,
                            srs_dst,
                        };
                        Some(
                            subscription
                                .taps
                                .iter()
                                .map(move |source_a| (*source_a, tee))
                                .collect::<Vec<_>>(),
                        )
                    })
                    .flatten()
                    .collect()
            })
            .unwrap_or_default();
        for (source_a, tee) in tees {
            self.media
                .control(call_id, MediaControl::AddRawTee { source_a, tee });
        }
        Ok(())
    }

    /// Apply `ProfileFlags::ws_tee` after an `answer` / `answer_local` succeeded — the declarative twin
    /// of [`Command::AttachWsTee`], so a controller gets a teed call in one round-trip. Attaching only
    /// *after* the answer means the call's media path (and therefore the fan-out to tap) exists.
    ///
    /// A failing tee fails the answer, rather than returning a call that silently is not being streamed:
    /// the controller asked for both, so half of it is not success. The answer's own SDP is preserved on
    /// the success path untouched.
    pub(super) async fn apply_profile_ws_tee(
        &self,
        call_id: &str,
        profile: &ProfileFlags,
        result: CmdResult,
    ) -> CmdResult {
        let Some(ws_tee) = profile.ws_tee.as_deref() else {
            return result;
        };
        if matches!(result, CmdResult::Error { .. }) {
            return result;
        }
        match self
            .start_ws_tee(
                call_id,
                ws_tee,
                profile.ws_tee_direction.unwrap_or_default(),
                profile.ws_tee_channels,
                profile.ws_tee_sample_rate,
            )
            .await
        {
            Ok(()) => result,
            Err(reason) => error_result("ws_tee", &reason),
        }
    }

    /// Detach a call's WebSocket tee ([`Command::DetachWsTee`]). Idempotent — detaching a call with no
    /// tee succeeds, so a controller may call it unconditionally on hangup.
    pub(super) async fn detach_ws_tee(&self, client: ClientId, call_id: &str) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        self.stop_ws_tee(call_id, WsTeeEndReason::Detached).await;
        ok_empty()
    }

    /// Tear a call's tee down: remove exactly this tee's sinks (by tag, so a SIPREC subscription on the
    /// same leg is untouched), abort the transport, emit [`Event::WsTeeEnded`] if the transport has not
    /// already, and release the userspace hold — demoting a promoted relay back to the kernel fast path
    /// when nothing else holds it. A no-op when the call has no tee.
    pub(super) async fn stop_ws_tee(&self, call_id: &str, reason: WsTeeEndReason) {
        let Some((_, tee)) = self.ws_tees.remove(call_id) else {
            return;
        };
        for source_a in &tee.tapped_legs {
            self.media.control(
                call_id,
                MediaControl::RemoveForkTagged {
                    source_a: *source_a,
                    tag: tee.stream_id.clone(),
                },
            );
        }
        // Abort **and wait**. `abort()` only schedules cancellation, so returning here would leave the
        // transport task alive for an unbounded moment still holding its WebSocket socket, the queued
        // wire frames (up to the channel depth) and the recycle pool — memory and a file descriptor
        // that teardown is supposed to have released. Awaiting the handle makes detach deterministic,
        // which the project's structured-concurrency rule asks for ("tearing down a leg frees its
        // actor, its sockets and its datapath flow — zero orphan tasks") and which a caller that
        // deletes a call and immediately re-offers on the same ports depends on. The task is a
        // cancel-safe select loop, so this resolves promptly with `JoinError::Cancelled`.
        tee.transport.abort();
        let _ = tee.transport.await;
        let events = self.event_sink(tee.owner);
        emit_ws_tee_ended(
            events.as_ref(),
            &tee.ended,
            call_id,
            &tee.from_tag,
            &tee.stream_id,
            reason,
            &tee.mixer,
        );
        self.release_userspace_hold(call_id, PromotionReason::WsTee)
            .await;
    }
}

/// Emit a tee's [`Event::WsTeeEnded`] **exactly once**, whichever of the transport task or a detach
/// gets there first (`ended` is the shared latch they race on). Carries the mixer's lifetime counters
/// so a controller can see whether the consumer kept up.
fn emit_ws_tee_ended(
    events: Option<&flume::Sender<Event>>,
    ended: &std::sync::atomic::AtomicBool,
    call_id: &str,
    from_tag: &str,
    stream_id: &str,
    reason: WsTeeEndReason,
    mixer: &std::sync::Mutex<siphon_rtp_media::bridge::tee::TeeMixer>,
) {
    use std::sync::atomic::Ordering;
    if ended.swap(true, Ordering::SeqCst) {
        return; // already reported
    }
    let (frames_sent, frames_dropped) = match mixer.lock() {
        Ok(guard) => (Some(guard.forwarded()), Some(guard.dropped())),
        Err(_) => (None, None),
    };
    tracing::info!(
        target: "siphon_rtp::media",
        call_id,
        stream_id,
        ?reason,
        frames_sent = frames_sent.unwrap_or(0),
        frames_dropped = frames_dropped.unwrap_or(0),
        "ws tee ended"
    );
    if let Some(sender) = events {
        let _ = sender.try_send(Event::WsTeeEnded {
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            stream_id: stream_id.to_string(),
            reason,
            frames_sent,
            frames_dropped,
        });
    }
}
