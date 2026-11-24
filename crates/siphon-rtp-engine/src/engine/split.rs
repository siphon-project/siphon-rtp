//! The **split bridge** verb: both legs of a live two-party call on one duplex stereo WebSocket,
//! the parties isolated from each other ([`siphon_rtp_proto::ws_split`]).
//!
//! The split rides the call's media actor, which keeps single ownership of every leg. Attaching
//!
//! 1. validates everything that can be validated while the call is untouched (the refusals, the wire
//!    rate, the conversions both ways, the uplink options),
//! 2. dials the bot ([`Engine::dial_ws`], bounded),
//! 3. holds the call in the decoding actor ([`PromotionReason::WsSplit`]): a plain relay is promoted,
//!    a crypto bridge hands over its legs, keys and stream positions (promote/secure_hold.rs),
//! 4. isolates the parties, attaches the uplink forks and the playout queues, and
//! 5. announces `ws_split_started` and starts the transport.
//!
//! A failure after step 2 undoes what was done, so a refused attach leaves the call as it was.
//! Detaching reverses it: transport stopped, forks removed, isolation ended, hold released (the
//! bridge gets its legs back where the actor left them, so there is no re-INVITE and no seam in the
//! media streams), `ws_split_ended{detached}`.
//!
//! **An end nobody asked for** (the bot closes the socket, sends `stop`, or the transport fails)
//! emits `ws_split_ended` once and leaves the call exactly as it is: isolated, and silent in both
//! directions, until the controller sends `detach_ws_split`, which restores the direct path. The
//! engine does not restore it by itself: a controller that wants direct audio back says so, and one
//! that wants to reconnect detaches and attaches again. A re-offer is followed ([`Engine::retap_ws_split`]);
//! a DTLS re-handshake ends the split with `renegotiated` and puts the call back on its bridge.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_media::bridge::protocol::{Direction, Encoding, Endianness, MediaFormat};
use siphon_rtp_media::bridge::split::{playout, run_ws_split, PlayoutReader, SplitEndReason};
use siphon_rtp_media::bridge::tee::{plan_ws_tee, start_message, TeeChannel, WsTeeSink};
use siphon_rtp_media::bridge::wire_resampler;
use siphon_rtp_proto::{
    resolve_ws_split_sample_rate, CmdResult, Event, ProfileFlags, WsSplitAttach, WsSplitEndReason,
    WsSplitEnded, WsSplitStarted,
};

use crate::media_pipeline::{DetachOutcome, MediaControl, SplitAttach};

use super::record::pcm_rate_of;
use super::tee::TeeMixerHandle;
use super::{
    error_result, ok_empty, unknown_call, ClientId, Engine, PipelineKind, PromoteMode,
    PromotionReason,
};

/// The refusal token of a call that is a source of a multi-source tee, which holds it.
const SECONDARY_SOURCE: &str = "ws-split-secondary-source";

/// A live split, kept for as long as the call is held for it.
pub(super) struct WsSplit {
    /// The `streamId` of the `start` frame: the event correlator.
    stream_id: String,
    /// The label on both uplink forks, so a detach removes exactly them.
    tap_tag: String,
    /// The call's offerer tag and owner, copied here: teardown runs after the call record is gone.
    from_tag: String,
    owner: ClientId,
    /// The L16 rate of the stream, both ways.
    wire_rate: u32,
    /// Which parties' uplinks run noise suppression.
    noise_suppression: [bool; 2],
    /// The uplink's frame assembler, kept so a re-offer's new actor feeds the same stream.
    mixer: TeeMixerHandle,
    /// The playout queues, kept so a re-offer's new actor plays the same ones.
    readers: [PlayoutReader; 2],
    /// The transport task (`start`, uplink frames, downlink frames). It emits the end event itself
    /// when the bot ends the stream first.
    transport: Option<tokio::task::JoinHandle<()>>,
    /// Latch: exactly one `ws_split_ended` per started split, whoever gets there first.
    pub(super) ended: Arc<AtomicBool>,
}

/// What a split needs of each party's leg, built before anything is touched.
struct SplitPlan {
    /// The uplink conversion of each party into the wire rate (`None` when it already runs at it).
    uplink: [Option<siphon_rtp_dsp::resample::Resampler>; 2],
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Attach a split ([`siphon_rtp_proto::Command::AttachWsSplit`]).
    pub(super) async fn attach_ws_split(
        &self,
        client: ClientId,
        attach: &WsSplitAttach,
    ) -> CmdResult {
        if self.owned_call(client, &attach.call_id, |_| ()).is_none() {
            return unknown_call(&attach.call_id);
        }
        match self.start_ws_split(attach).await {
            Ok(()) => ok_empty(),
            Err(reason) => error_result("attach_ws_split", &reason),
        }
    }

    /// The conversions a split runs on `call_id`'s legs as they stand now: each party's decoded PCM
    /// into the wire rate. Also proves the way back (wire rate into each leg's rate) can be built, so
    /// a codec this engine cannot serve is a refusal while the call is untouched.
    fn split_plan(&self, call_id: &str, wire_rate: u32) -> Result<SplitPlan, String> {
        let (near, far) = self
            .owned_call_internal(call_id, |call| {
                (call.near_codec.clone(), call.far_codec.clone())
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        let mut uplink = [None, None];
        for (slot, (codec, party)) in uplink
            .iter_mut()
            .zip([(near, "offerer"), (far, "answerer")])
        {
            let codec = codec.ok_or_else(|| format!("the {party} leg has no negotiated codec"))?;
            let rate = pcm_rate_of(&codec)?;
            *slot = wire_resampler(rate, wire_rate).map_err(|error| error.to_string())?;
            wire_resampler(wire_rate, rate).map_err(|error| error.to_string())?;
        }
        Ok(SplitPlan { uplink })
    }

    async fn start_ws_split(&self, attach: &WsSplitAttach) -> Result<(), String> {
        let call_id = attach.call_id.as_str();
        let wire_rate = resolve_ws_split_sample_rate(attach.sample_rate)
            .map_err(|error| format!("ws-split-sample-rate: {error}"))?;
        let noise_suppression = [
            uplink_noise_suppression(attach.offerer_profile.as_deref(), "offerer")?,
            uplink_noise_suppression(attach.answerer_profile.as_deref(), "answerer")?,
        ];
        if self.is_secondary_tee_source(call_id) {
            return Err(format!(
                "{SECONDARY_SOURCE}: the call is a source of a multi-source WebSocket tee, which \
                 holds it; detach that tee first"
            ));
        }
        // The refusals that carry a token, before a socket is dialled for a call that cannot split.
        self.ws_split_refusal(call_id)?;
        let plan = self.split_plan(call_id, wire_rate)?;
        self.check_noise_suppression(call_id, noise_suppression)?;

        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: wire_rate,
            channels: 2,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        };
        let uplink = plan_ws_tee(format, true, false);
        let (downlink, readers) = playout(wire_rate);
        let stream_id = format!("split-{}", super::scope::external(call_id));
        // One split per call, so the stream id is also the label of its forks: a detach can remove
        // them without a registry entry (an attach that could not undo itself leaves none).
        let tap_tag = stream_id.clone();

        // Dial first, so a bot that is not there costs the call nothing. Bounded: see `ws_dial`.
        let socket = self.dial_ws(call_id, &attach.ws_uri).await?;

        // From here the call changes, and every failure puts it back. An actor the call already has
        // is isolated first of all, so there is no moment between the decision and the isolation in
        // which the parties hear each other; one the hold is about to build starts isolated.
        let epoch = self.media.mark_split(call_id);
        if self.media.is_media_call(call_id) {
            if let Err(error) = self
                .media
                .control_confirmed(
                    call_id,
                    vec![MediaControl::SplitIsolate {
                        epoch: epoch.clone(),
                    }],
                )
                .await
            {
                // Whether the isolation was applied is not known, so it is not assumed away.
                return Err(self
                    .abandon_attach(
                        call_id,
                        &tap_tag,
                        format!("the call could not be isolated: {error}"),
                    )
                    .await);
            }
        }
        if let Err(reason) = self
            .hold_in_userspace(call_id, PromotionReason::WsSplit, PromoteMode::Processing)
            .await
        {
            return Err(self.abandon_attach(call_id, &tap_tag, reason).await);
        }
        if let Err(reason) = self
            .attach_split_media(
                call_id,
                &tap_tag,
                &uplink.mixer,
                plan.uplink,
                (&readers, wire_rate, noise_suppression),
            )
            .await
        {
            if let Err(undo) = self.undo_split(call_id, &tap_tag).await {
                // The actor did not confirm the undo, so the call is left as it is: isolated and
                // silent, which is the safe side. A detach finishes the job.
                return Err(format!(
                    "{reason}; the call is left isolated and silent ({undo}), send detach_ws_split"
                ));
            }
            return Err(reason);
        }

        let (owner, from_tag) = self
            .owned_call_internal(call_id, |call| (call.owner, call.from_tag.clone()))
            .ok_or_else(|| "call no longer exists".to_string())?;
        // Announced before the transport exists, like every other stream: the transport can end (a
        // bot that closes on the handshake) before a later announcement would be queued, and an end
        // for a stream never announced is not something a controller can act on.
        self.emit_call_event(
            call_id,
            Event::WsSplitStarted(WsSplitStarted {
                call_id: call_id.to_string(),
                from_tag: from_tag.clone(),
                stream_id: stream_id.clone(),
                ws_uri: attach.ws_uri.clone(),
                sample_rate: wire_rate,
            }),
        );
        let ended = Arc::new(AtomicBool::new(false));
        let start = start_message(
            &stream_id,
            super::scope::call_id(call_id),
            uplink.format,
            uplink.tracks,
            Direction::Duplex,
        );
        let transport = {
            let events = self.event_sink(owner);
            let (call_id, from_tag, stream_id) =
                (call_id.to_string(), from_tag.clone(), stream_id.clone());
            let ended = ended.clone();
            tokio::spawn(async move {
                let reason = match run_ws_split(
                    socket,
                    start,
                    uplink.frames,
                    uplink.recycle,
                    downlink,
                )
                .await
                {
                    Ok(SplitEndReason::ServerClosed) => WsSplitEndReason::WsClosed,
                    Ok(SplitEndReason::ServerStopped) => WsSplitEndReason::WsStopped,
                    Ok(SplitEndReason::CallEnded) => WsSplitEndReason::CallDeleted,
                    Err(error) => {
                        tracing::debug!(%error, call_id, "ws split transport ended with an error");
                        WsSplitEndReason::WsError
                    }
                };
                emit_ws_split_ended(
                    events.as_ref(),
                    &ended,
                    &call_id,
                    &from_tag,
                    &stream_id,
                    reason,
                );
            })
        };
        self.ws_splits.insert(
            call_id.to_string(),
            WsSplit {
                stream_id,
                tap_tag,
                from_tag,
                owner,
                wire_rate,
                noise_suppression,
                mixer: uplink.mixer,
                readers,
                transport: Some(transport),
                ended,
            },
        );
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            ws_uri = attach.ws_uri,
            sample_rate = wire_rate,
            "ws split attached"
        );
        Ok(())
    }

    /// Refuse a noise-suppression request a leg's rate cannot serve, before anything is touched.
    fn check_noise_suppression(&self, call_id: &str, wanted: [bool; 2]) -> Result<(), String> {
        let codecs = self
            .owned_call_internal(call_id, |call| {
                (call.near_codec.clone(), call.far_codec.clone())
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        for (wanted, codec, party) in [
            (wanted[0], codecs.0, "offerer"),
            (wanted[1], codecs.1, "answerer"),
        ] {
            let Some(codec) = codec.filter(|_| wanted) else {
                continue;
            };
            let rate = pcm_rate_of(&codec)?;
            if siphon_rtp_dsp::NoiseSuppressor::new(rate).is_err() {
                return Err(format!(
                    "ws-split-profile: noise suppression is not available on the {party} leg at {rate} Hz"
                ));
            }
        }
        Ok(())
    }

    /// Put a split on the call's actor: the uplink forks of both parties, then the isolation and the
    /// playout queues. On any failure the forks added so far are removed again.
    ///
    /// Confirmed: this returns `Ok` only once the actor has applied all of it, because the isolation
    /// and the uplink are not allowed to be lost to a full mailbox.
    async fn attach_split_media(
        &self,
        call_id: &str,
        tap_tag: &str,
        mixer: &TeeMixerHandle,
        uplink: [Option<siphon_rtp_dsp::resample::Resampler>; 2],
        (readers, wire_rate, noise_suppression): (&[PlayoutReader; 2], u32, [bool; 2]),
    ) -> Result<(), String> {
        let channels = [TeeChannel::Caller, TeeChannel::Callee];
        let epoch = self
            .media
            .split_epoch(call_id)
            .ok_or_else(|| "the call is not marked for a split".to_string())?;
        let mut controls: Vec<MediaControl> = Vec::with_capacity(3);
        for (index, (resampler, channel)) in uplink.into_iter().zip(channels).enumerate() {
            let sink = WsTeeSink::new(channel, mixer.clone(), tap_tag.to_string(), resampler);
            controls.push(MediaControl::AddFork {
                source_a: index == 0,
                sink: Box::new(sink),
            });
        }
        let [toward_a, toward_b] = readers.clone();
        controls.push(MediaControl::SplitAttach(Box::new(SplitAttach {
            toward_a,
            toward_b,
            wire_rate_hz: wire_rate,
            noise_suppression,
            epoch,
        })));
        self.media
            .control_confirmed(call_id, controls)
            .await
            .map_err(|error| format!("the split could not be put on the call: {error}"))
    }

    /// Take a split's forks and isolation off the actor, which answers on the control itself having
    /// checked the split's generation and lifted the isolation in one step. `Ok` means the parties are
    /// no longer isolated on the actor (this control lifted it, or an earlier one already had).
    ///
    /// `Err` means that is not known: the answer was not heard, or the control was ignored as stale.
    /// The generation moves on before this returns, so a control the actor still has queued cannot
    /// take effect after the caller has been told it failed. The state is then reconciled by asking
    /// again, not assumed: the actor answers [`DetachOutcome::AlreadyOpen`] if it did apply the first.
    async fn remove_split_from_actor(&self, call_id: &str, tap_tag: &str) -> Result<(), String> {
        match self.media.split_detach(call_id, tap_tag).await {
            Ok(DetachOutcome::Lifted | DetachOutcome::AlreadyOpen) => Ok(()),
            Ok(DetachOutcome::Stale) => {
                self.media.bump_split_epoch(call_id);
                Err("the split moved on while the detach was in flight".to_string())
            }
            Err(error) => {
                self.media.bump_split_epoch(call_id);
                Err(error.to_string())
            }
        }
    }

    /// Give up an attach before the hold was taken: take the isolation back off an actor the call
    /// already had. If the actor does not confirm that, the call is left marked and held for the
    /// split with no registry entry, isolated and silent, which a `detach_ws_split` cleans up (it
    /// finds the hold and removes by the stream's own label). Returns the error text for the caller.
    async fn abandon_attach(&self, call_id: &str, tap_tag: &str, reason: String) -> String {
        if self.media.is_media_call(call_id) {
            if let Err(error) = self.remove_split_from_actor(call_id, tap_tag).await {
                if let Some(mut call) = self.calls.get_mut(call_id) {
                    call.promotion_reasons.insert(PromotionReason::WsSplit);
                }
                return format!(
                    "{reason}; the actor did not confirm the undo ({error}), the call is left \
                     isolated and silent: send detach_ws_split"
                );
            }
        }
        self.media.unmark_split(call_id);
        reason
    }

    /// Take a split that did not get as far as being registered off the call again. `Err` means the
    /// actor did not confirm, and nothing was released: the call is as isolated as it was.
    async fn undo_split(&self, call_id: &str, tap_tag: &str) -> Result<(), String> {
        if self.media.is_media_call(call_id) {
            self.remove_split_from_actor(call_id, tap_tag).await?;
        }
        self.media.unmark_split(call_id);
        self.release_userspace_hold(call_id, PromotionReason::WsSplit)
            .await;
        Ok(())
    }

    /// Detach a call's split ([`siphon_rtp_proto::Command::DetachWsSplit`]). Idempotent: a call
    /// with no split is not an error, so a controller may send it unconditionally on a toggle.
    ///
    /// **The only thing that ends an isolation.** The actor has to confirm it applied the removal
    /// before anything else changes. If it does not (its mailbox stayed full, or it is gone), `Err`
    /// comes back, the split stays exactly as it was, registry entry, transport and isolation, and
    /// the generation moves on so that the removal, should the actor apply it late, is ignored.
    /// The controller sends the detach again.
    pub(super) async fn detach_ws_split(&self, client: ClientId, call_id: &str) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        match self.detach_split(call_id).await {
            Ok(()) => ok_empty(),
            Err(reason) => error_result("detach_ws_split", &reason),
        }
    }

    async fn detach_split(&self, call_id: &str) -> Result<(), String> {
        let held_orphan = self.is_split_held(call_id) && !self.ws_splits.contains_key(call_id);
        if !self.ws_splits.contains_key(call_id) && !held_orphan {
            return Ok(());
        }
        let tap_tag = self.ws_splits.get(call_id).map_or_else(
            || format!("split-{}", super::scope::external(call_id)),
            |split| split.tap_tag.clone(),
        );
        if self.media.is_media_call(call_id) {
            if let Err(error) = self.remove_split_from_actor(call_id, &tap_tag).await {
                return Err(format!(
                    "the media actor did not confirm ({error}); the split is still on the call, \
                     send detach_ws_split again"
                ));
            }
        }
        if let Some((_, split)) = self.ws_splits.remove(call_id) {
            if let Some(transport) = split.transport {
                // Abort and wait, so nothing is left holding the socket or the queues.
                transport.abort();
                let _ = transport.await;
            }
            split.readers.iter().for_each(PlayoutReader::flush);
            let events = self.event_sink(split.owner);
            emit_ws_split_ended(
                events.as_ref(),
                &split.ended,
                call_id,
                &split.from_tag,
                &split.stream_id,
                WsSplitEndReason::Detached,
            );
        }
        self.media.unmark_split(call_id);
        self.release_userspace_hold(call_id, PromotionReason::WsSplit)
            .await;
        Ok(())
    }

    /// End a split's **stream** and leave the call isolated and silent: the transport stopped, the
    /// end reported once, and everything else as it was (registry entry, mark, hold, isolation) until
    /// the controller detaches. For what the engine itself cannot carry on with (a re-offer that the
    /// split cannot follow): nothing but a detach the controller sent may reconnect the parties.
    pub(super) async fn end_ws_split_isolated(&self, call_id: &str, reason: WsSplitEndReason) {
        let Some(mut split) = self.ws_splits.get_mut(call_id) else {
            return;
        };
        let transport = split.transport.take();
        let readers = split.readers.clone();
        let (events, ended, from_tag, stream_id) = (
            self.event_sink(split.owner),
            split.ended.clone(),
            split.from_tag.clone(),
            split.stream_id.clone(),
        );
        drop(split);
        if let Some(transport) = transport {
            transport.abort();
            let _ = transport.await;
        }
        // The queues outlive the transport that filled them: what the bot had sent and the actor had
        // not played must not play on after the end is reported.
        readers.iter().for_each(PlayoutReader::flush);
        emit_ws_split_ended(
            events.as_ref(),
            &ended,
            call_id,
            &from_tag,
            &stream_id,
            reason,
        );
    }

    /// A call is being deleted: drop the split with it, **without lifting anything**. The isolation
    /// stays on the actor until the actor stops, so no audio crosses while the rest of the teardown
    /// (recordings, interception) finishes; only the transport and the registry entry go, and the
    /// end is reported as `call_deleted`. The mark is cleared by the teardown once the actor is
    /// deregistered ([`crate::media_pipeline::MediaRegistry::unmark_split`]).
    pub(super) async fn drop_ws_split_for_delete(&self, call_id: &str) {
        let Some((_, split)) = self.ws_splits.remove(call_id) else {
            return;
        };
        if let Some(transport) = split.transport {
            transport.abort();
            let _ = transport.await;
        }
        split.readers.iter().for_each(PlayoutReader::flush);
        let events = self.event_sink(split.owner);
        emit_ws_split_ended(
            events.as_ref(),
            &split.ended,
            call_id,
            &split.from_tag,
            &split.stream_id,
            WsSplitEndReason::CallDeleted,
        );
    }

    /// Move a call's split onto the media path an answer just installed (RFC 3264 §8: the answer to
    /// a re-offer re-installs the call's media path, and the actor the split was on is gone). The
    /// split keeps its socket, its stream id, its wire format and its queues; only its forks and its
    /// attachment to the new actor are rebuilt, from the codecs the legs carry now. The new actor was
    /// registered already isolated ([`crate::media_pipeline::MediaRegistry::mark_split`]), so no
    /// party's audio reached the other in between. A call the split cannot follow ends it with
    /// [`WsSplitEndReason::Renegotiated`].
    pub(super) async fn retap_ws_split(&self, call_id: &str) {
        let Some((tap_tag, wire_rate, noise, mixer, readers)) =
            self.ws_splits.get(call_id).map(|split| {
                (
                    split.tap_tag.clone(),
                    split.wire_rate,
                    split.noise_suppression,
                    split.mixer.clone(),
                    split.readers.clone(),
                )
            })
        else {
            return;
        };
        // The new actor has none of this split's forks yet, so there is nothing to remove first.
        let attached = match self.split_plan(call_id, wire_rate) {
            Ok(plan) => {
                self.attach_split_media(
                    call_id,
                    &tap_tag,
                    &mixer,
                    plan.uplink,
                    (&readers, wire_rate, noise),
                )
                .await
            }
            Err(reason) => Err(reason),
        };
        match attached {
            Ok(()) => tracing::info!(
                target: "siphon_rtp::media",
                call_id,
                "ws split re-attached after renegotiation"
            ),
            Err(reason) => {
                tracing::warn!(
                    target: "siphon_rtp::media",
                    call_id,
                    reason,
                    "ws split cannot follow the renegotiated media path; ending it"
                );
                self.end_ws_split_isolated(call_id, WsSplitEndReason::Renegotiated)
                    .await;
            }
        }
    }

    /// A call restored from a checkpoint taken while it was split: its actor was registered isolated
    /// (the mark is set), and from here the call is held for the split, in the ended-and-not-detached
    /// state. There is no socket; the controller learns it from one `ws_split_ended` (`restored`) and
    /// detaches, or detaches and attaches again.
    pub(super) fn adopt_restored_split(&self, client: ClientId, call_id: &str, from_tag: &str) {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return;
        };
        call.promotion_reasons.insert(PromotionReason::WsSplit);
        drop(call);
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: 16_000,
            channels: 2,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        };
        // Nothing feeds or drains these; they let a later re-offer attach the same silent isolation.
        let uplink = plan_ws_tee(format, true, false);
        let (_writer, readers) = playout(16_000);
        let stream_id = format!("split-{}", super::scope::external(call_id));
        let ended = Arc::new(AtomicBool::new(false));
        emit_ws_split_ended(
            self.event_sink(client).as_ref(),
            &ended,
            call_id,
            from_tag,
            &stream_id,
            WsSplitEndReason::Restored,
        );
        self.ws_splits.insert(
            call_id.to_string(),
            WsSplit {
                tap_tag: stream_id.clone(),
                stream_id,
                from_tag: from_tag.to_string(),
                owner: client,
                wire_rate: 16_000,
                noise_suppression: [false, false],
                mixer: uplink.mixer,
                readers,
                transport: None,
                ended,
            },
        );
    }

    /// Whether a split **verb** is on `call_id`: attached, ended and not yet detached, or left by an
    /// attach that could not undo itself. A bare hold ([`PromotionReason::WsSplit`] taken without the
    /// verb) is not one, and keeps its release-on-re-key behaviour.
    pub(super) fn has_split_verb(&self, call_id: &str) -> bool {
        self.ws_splits.contains_key(call_id) || self.media.is_split_marked(call_id)
    }

    /// Whether a split holds `call_id`: attached, or ended and not yet detached. Either way the call
    /// stays isolated.
    pub(super) fn is_split_held(&self, call_id: &str) -> bool {
        self.owned_call_internal(call_id, |call| {
            call.promotion_reasons.contains(&PromotionReason::WsSplit)
        })
        .unwrap_or(false)
    }

    /// The kind a split call takes from an answer that resolved to `resolved`: a crypto bridge that
    /// the split call did not start on becomes the decoding actor's twin of it, so the isolation holds.
    pub(super) fn keep_split_on_actor(
        &self,
        call_id: &str,
        resolved: PipelineKind,
    ) -> PipelineKind {
        if resolved.is_crypto_bridge() && self.has_split_verb(call_id) {
            return resolved.held_twin().unwrap_or(resolved);
        }
        resolved
    }

    /// Chunks of the bot's audio waiting to be played to the two parties of `call_id`'s split.
    #[must_use]
    pub fn ws_split_queued(&self, call_id: &str) -> Option<usize> {
        self.ws_splits
            .get(call_id)
            .map(|split| split.readers.iter().map(PlayoutReader::queued).sum())
    }

    /// Whether `call_id` has a split attached (live, or ended and waiting for a detach).
    #[must_use]
    pub fn ws_split_count(&self) -> usize {
        self.ws_splits.len()
    }
}

/// The uplink option of one party's profile: whether to suppress noise. Echo cancellation and the
/// `ws_vad*` turn-taking belong to a bridge that is a leg's far side and are refused rather than
/// accepted and ignored.
fn uplink_noise_suppression(profile: Option<&ProfileFlags>, party: &str) -> Result<bool, String> {
    let Some(profile) = profile else {
        return Ok(false);
    };
    if profile.echo_cancellation
        || profile.ws_vad
        || profile.ws_barge_in
        || profile.ws_uri.is_some()
        || profile.ws_sample_rate.is_some()
    {
        return Err(format!(
            "ws-split-profile: the {party} profile asks for more than a split runs (only \
             noise_suppression applies; the wire rate is the command's sample_rate)"
        ));
    }
    Ok(profile.noise_suppression)
}

/// Emit a split's [`Event::WsSplitEnded`] **exactly once**, whichever of the transport task or a
/// detach gets there first (`ended` is the latch they race on).
///
/// Logged at warn for an end nobody asked for: the call is isolated and silent from then on, which a
/// node with no event consumer must still leave a trace of.
pub(super) fn emit_ws_split_ended(
    events: Option<&flume::Sender<Event>>,
    ended: &AtomicBool,
    call_id: &str,
    from_tag: &str,
    stream_id: &str,
    reason: WsSplitEndReason,
) {
    if ended.swap(true, Ordering::SeqCst) {
        return;
    }
    if matches!(
        reason,
        WsSplitEndReason::Detached | WsSplitEndReason::CallDeleted | WsSplitEndReason::Renegotiated
    ) {
        tracing::info!(target: "siphon_rtp::media", call_id, stream_id, ?reason, "ws split ended");
    } else {
        tracing::warn!(
            target: "siphon_rtp::media",
            call_id,
            stream_id,
            ?reason,
            "ws split ended without a detach: both parties stay isolated and silent until it is detached"
        );
    }
    if let Some(sender) = events {
        let _ = sender.try_send(Event::WsSplitEnded(WsSplitEnded {
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            stream_id: stream_id.to_string(),
            reason,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_noise_suppression_of_a_leg_profile_applies() {
        assert_eq!(uplink_noise_suppression(None, "offerer"), Ok(false));
        let profile = ProfileFlags {
            noise_suppression: true,
            ..Default::default()
        };
        assert_eq!(
            uplink_noise_suppression(Some(&profile), "offerer"),
            Ok(true)
        );
        for refused in [
            ProfileFlags {
                echo_cancellation: true,
                ..Default::default()
            },
            ProfileFlags {
                ws_vad: true,
                ..Default::default()
            },
            ProfileFlags {
                ws_barge_in: true,
                ..Default::default()
            },
            ProfileFlags {
                ws_sample_rate: Some(16_000),
                ..Default::default()
            },
        ] {
            let error = uplink_noise_suppression(Some(&refused), "answerer").expect_err("refused");
            assert!(error.starts_with("ws-split-profile:"), "{error}");
            assert!(error.contains("answerer"), "{error}");
        }
    }

    #[test]
    fn an_end_is_emitted_once_whoever_gets_there_first() {
        let (sender, receiver) = flume::unbounded();
        let ended = AtomicBool::new(false);
        for reason in [WsSplitEndReason::WsClosed, WsSplitEndReason::Detached] {
            emit_ws_split_ended(Some(&sender), &ended, "c1", "a", "split-c1", reason);
        }
        let events: Vec<Event> = receiver.try_iter().collect();
        assert_eq!(events.len(), 1, "one end event: {events:?}");
        match &events[0] {
            Event::WsSplitEnded(event) => {
                assert_eq!(event.reason, WsSplitEndReason::WsClosed);
                assert_eq!(event.stream_id, "split-c1");
            }
            other => panic!("expected ws_split_ended, got {other:?}"),
        }
    }

    #[test]
    fn an_end_with_nobody_listening_is_still_latched() {
        let ended = AtomicBool::new(false);
        emit_ws_split_ended(None, &ended, "c1", "a", "s", WsSplitEndReason::WsError);
        assert!(ended.load(Ordering::SeqCst));
    }
}
