//! A recording or a WebSocket tee fed by **several calls** (SIPREC, RFC 7866: each recorded stream is
//! answered on a call of its own, and one recording has to carry all of them, a channel each).
//!
//! The media side is [`siphon_rtp_media::bridge::multi_source`]: one aligning mixer actor, a
//! [`MultiSourceSink`] on each source call's post-decode fan-out. What lives here is the bookkeeping
//! that makes several calls one recording: validating the sources, the userspace hold on each, ending
//! the recording or tee when **any** source call goes (and detaching the sinks on all the others
//! first, so a delete never waits on a live call), following a re-offer on any source, and keeping
//! the other features that would silently end a multi-source attachment (a seat, a bot takeover) off
//! a source call.
//!
//! A source is identified by its `call_id`. A SIPREC recorder answers every stream under the one
//! `from_tag` of the session, so the tag cannot tell sources apart; nothing here keys on it.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_media::bridge::multi_source::{
    plan_multi_source, MultiSourceControl, MultiSourceSink, MultiSourceStats,
};
use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
use siphon_rtp_media::bridge::wire_rate::{validate_wire_sample_rate, wire_resampler};
use siphon_rtp_proto::{
    CmdResult, RecordingChannels, RecordingDirection, RecordingEndReason, RecordingSource,
    WsTeeDirection, WsTeeEndReason, MAX_RECORDING_SOURCES,
};
use std::sync::Arc;

use super::record::{
    new_source_reason, open_recording_output, pcm_rate_of, settle_writer, AudioRecording,
    DecodedRecordingRequest, RecordingWriter,
};
use super::tee::{TeeCounters, TeeOutput, TeeShape};
use super::{error_result, ok_empty, ClientId, Engine, PipelineKind, PromoteMode, PromotionReason};

/// Where one source's audio comes from, and the channel it is: its position in
/// [`MultiSourceFeed::sources`].
pub(super) struct SourceCall {
    pub(super) call_id: String,
}

/// What feeds one multi-source recording or tee: where its sources are, the mixer task, and the
/// handle that ends it. Dropping the feed ends the mixer, which flushes and closes the output.
pub(super) struct MultiSourceFeed {
    /// The sources in channel order; the first is the call the verb named.
    pub(super) sources: Vec<SourceCall>,
    control: MultiSourceControl,
    task: tokio::task::JoinHandle<()>,
    /// The sample rate every source is converted into.
    rate: u32,
}

impl MultiSourceFeed {
    /// The channel of `call_id`, when it is one of the sources.
    fn index_of(&self, call_id: &str) -> Option<usize> {
        self.sources
            .iter()
            .position(|source| source.call_id == call_id)
    }

    /// Whether `call_id` is one of the sources.
    pub(super) fn involves(&self, call_id: &str) -> bool {
        self.index_of(call_id).is_some()
    }
}

/// A source call that passed validation.
struct ResolvedSource {
    call_id: String,
    /// The PCM rate its leg decodes at.
    rate: u32,
    ptime: u8,
    to_tag: Option<String>,
    owner: ClientId,
}

/// What a multi-source recording or tee needs, whichever of the two it is.
struct Prepared {
    sources: Vec<ResolvedSource>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Validate every source of a multi-source verb: the count, no call twice, each one owned by the
    /// requester, and each one a call whose decoded audio can be tapped. Touches nothing.
    fn resolve_sources(
        &self,
        client: ClientId,
        call_id: &str,
        additional: &[RecordingSource],
    ) -> Result<Prepared, String> {
        let total = 1 + additional.len();
        if total > MAX_RECORDING_SOURCES {
            return Err(format!(
                "{total} sources: a multi-source stream takes 2 to {MAX_RECORDING_SOURCES}"
            ));
        }
        let ids = std::iter::once(call_id).chain(additional.iter().map(|s| s.call_id.as_str()));
        let mut sources: Vec<ResolvedSource> = Vec::with_capacity(total);
        for id in ids {
            // A call is one source however many times it is listed (its tag does not matter: a
            // SIPREC session shares one across all its calls), and tapping it twice would put its
            // audio on two channels.
            if sources.iter().any(|source| source.call_id == id) {
                return Err(format!("call {id} is listed as a source twice"));
            }
            let Some((pipeline, codec, ptime, to_tag, owner)) =
                self.owned_call(client, id, |call| {
                    (
                        call.pipeline,
                        call.near_codec.clone(),
                        call.near_codec
                            .as_ref()
                            .map_or(20, |codec| codec.ptime_ms.max(1)),
                        call.to_tag.clone(),
                        call.owner,
                    )
                })
            else {
                return Err(format!("unknown call: {}", super::scope::Key(id)));
            };
            if pipeline == PipelineKind::Seated {
                return Err(format!(
                    "call {id} is seated in a conference room, whose audio is the room's, not a \
                     stream a multi-source recording can take"
                ));
            }
            if pipeline.is_crypto_bridge() {
                return Err(format!(
                    "call {id} relays through a crypto bridge, which decodes nothing to tap"
                ));
            }
            if pipeline == PipelineKind::Ws
                || self.ws.is_ws_call(id)
                || self.bridge_recording_target(id).is_some()
            {
                return Err(format!(
                    "call {id} is taken over by a WebSocket bridge, so its audio does not reach \
                     the media pipeline; a multi-source stream cannot tap it"
                ));
            }
            let codec =
                codec.ok_or_else(|| format!("call {id} has no negotiated codec to record"))?;
            sources.push(ResolvedSource {
                call_id: id.to_string(),
                rate: pcm_rate_of(&codec)?,
                ptime,
                to_tag,
                owner,
            });
        }
        Ok(Prepared { sources })
    }

    /// Hold every source in userspace for `reason`, or none: a failure releases what was held.
    async fn hold_sources(
        &self,
        sources: &[ResolvedSource],
        reason: PromotionReason,
    ) -> Result<(), String> {
        for (index, source) in sources.iter().enumerate() {
            if let Err(error) = self
                .hold_in_userspace(&source.call_id, reason, PromoteMode::RelayOnly)
                .await
            {
                for held in &sources[..index] {
                    self.release_userspace_hold(&held.call_id, reason).await;
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Put each source's sink on its call, or none: a failure takes off what was put on and releases
    /// every hold. `Err` names the reason.
    async fn attach_sources(
        &self,
        sources: &[ResolvedSource],
        control: &MultiSourceControl,
        rate: u32,
        tag: &str,
        reason: PromotionReason,
    ) -> Result<(), String> {
        // Every conversion is built before anything is attached, so a rate this engine cannot serve
        // is a refusal on calls as they were.
        let mut sinks = Vec::with_capacity(sources.len());
        for (index, source) in sources.iter().enumerate() {
            let resampler = wire_resampler(source.rate, rate).map_err(|error| error.to_string())?;
            sinks.push(
                control
                    .sink(index, resampler, tag)
                    .ok_or_else(|| "a source has no channel".to_string())?,
            );
        }
        for (index, sink) in sinks.into_iter().enumerate() {
            let attached = self
                .attach_recording_sink(&sources[index].call_id, true, true, Box::new(sink))
                .await;
            if !attached {
                for done in &sources[..index] {
                    self.detach_source(&done.call_id, tag).await;
                }
                for source in sources {
                    self.release_userspace_hold(&source.call_id, reason).await;
                }
                return Err("media actor unavailable".to_string());
            }
        }
        Ok(())
    }

    /// Take the sink labelled `tag` off `call_id`'s ingress.
    async fn detach_source(&self, call_id: &str, tag: &str) {
        self.detach_recording_sinks(call_id, tag, &[true], &[])
            .await;
    }

    /// Start a decoded recording fed by several calls ([`Command::StartRecording`] with
    /// `additional_sources`). Everything is validated before any call is touched.
    pub(super) async fn start_multi_source_recording(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        additional: &[RecordingSource],
        request: DecodedRecordingRequest,
    ) -> CmdResult {
        match self
            .begin_multi_source_recording(client, call_id, from_tag, additional, request)
            .await
        {
            Ok(recording_id) => CmdResult::Ok {
                sdp: None,
                duration_ms: None,
                play_id: None,
                recording_id: Some(recording_id),
                to_tag: None,
                stats: None,
            },
            Err(reason) => error_result("start_recording", &reason),
        }
    }

    async fn begin_multi_source_recording(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        additional: &[RecordingSource],
        request: DecodedRecordingRequest,
    ) -> Result<String, String> {
        // Each source contributes what its call received, which is what a SIPREC stream is.
        if request.direction != RecordingDirection::Ingress {
            return Err(
                "a multi-source recording takes the audio each source call received, so \
                 direction must be ingress (egress and both are refused)"
                    .to_string(),
            );
        }
        let Prepared { sources } = self.resolve_sources(client, call_id, additional)?;
        let channels: u8 = match request.channels {
            RecordingChannels::Stereo if sources.len() == 2 => 2,
            RecordingChannels::Stereo => {
                return Err(format!(
                    "a stereo recording carries exactly 2 sources, not {}; use mono to mix",
                    sources.len()
                ))
            }
            RecordingChannels::Mono => 1,
        };
        let rate = sources[0].rate;
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: rate,
            channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: sources[0].ptime,
        };
        let plan = plan_multi_source(format, sources.len()).map_err(|error| error.to_string())?;
        let encoding = request.format.encoding(rate, channels)?;
        let recording_id = self.next_recording_id();
        let (path, file) = open_recording_output(
            call_id,
            &recording_id,
            request.format.extension(),
            request.path,
            request.recording_dir,
        )
        .await?;

        self.hold_sources(&sources, PromotionReason::AudioRecording)
            .await?;
        self.attach_sources(
            &sources,
            &plan.control,
            rate,
            &recording_id,
            PromotionReason::AudioRecording,
        )
        .await?;

        let task = tokio::spawn(plan.mixer.run());
        let source_reason = new_source_reason();
        let writer = self.spawn_recording_writer(RecordingWriter {
            owner: sources[0].owner,
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            to_tag: sources[0].to_tag.clone(),
            recording_id: recording_id.clone(),
            path: path.clone(),
            file,
            rate,
            channels,
            encoding,
            limits: request.limits,
            frames: plan.frames,
            recycle: plan.recycle,
            source_reason: source_reason.clone(),
            rename_to: None,
        });
        let owner = sources[0].owner;
        self.recordings.insert(
            recording_id.clone(),
            AudioRecording {
                recording_id: recording_id.clone(),
                call_id: call_id.to_string(),
                owner,
                path,
                ingress_legs: Vec::new(),
                egress_legs: Vec::new(),
                room: None,
                bridge_taps: Vec::new(),
                source_reason,
                writer,
                taps: None,
                seat: None,
                parked: std::sync::Mutex::new(Vec::new()),
                multi: Some(MultiSourceFeed {
                    sources: sources
                        .iter()
                        .map(|source| SourceCall {
                            call_id: source.call_id.clone(),
                        })
                        .collect(),
                    control: plan.control,
                    task,
                    rate,
                }),
            },
        );
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            recording_id,
            sources = sources.len(),
            channels,
            sample_rate = rate,
            "multi-source recording started"
        );
        Ok(recording_id)
    }

    /// End a multi-source recording that has already left the registry: stop its mixer (which
    /// flushes and closes the writer's input), take the sinks off **every** source call, wait for the
    /// file to be closed, and release the userspace hold on each source nothing else taps.
    pub(super) async fn stop_multi_source_recording(
        &self,
        recording_id: &str,
        recording: AudioRecording,
        reason: RecordingEndReason,
    ) {
        if let Ok(mut stored) = recording.source_reason.lock() {
            *stored = reason;
        }
        let Some(feed) = recording.multi else {
            return;
        };
        let MultiSourceFeed {
            sources,
            control,
            task,
            ..
        } = feed;
        // The mixer ends on its handle, so the writer finalizes whatever the sinks are doing.
        drop(control);
        // Off every source first, then the writer: a delete of one source must not wait on another
        // call's actor. Each detach is a queued message to that actor.
        for source in &sources {
            self.detach_source(&source.call_id, recording_id).await;
        }
        let _ = task.await;
        settle_writer(recording.writer, &recording.call_id, recording_id).await;
        for source in &sources {
            let another_still_taps = self.recordings.iter().any(|entry| {
                let other = entry.value();
                other.call_id_matches(&source.call_id)
                    && other.room.is_none()
                    && other.bridge_taps.is_empty()
            });
            if !another_still_taps {
                self.release_userspace_hold(&source.call_id, PromotionReason::AudioRecording)
                    .await;
            }
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %recording.call_id,
            recording_id,
            path = %recording.path.display(),
            owner = recording.owner.0,
            sources = sources.len(),
            ?reason,
            "multi-source recording stopped"
        );
    }

    /// Whether `client` owns every source of the recording `recording_id` (a single-call recording
    /// has one, the call the verb named, which the caller already checked). A source call that is
    /// gone is not owned by anyone, but a recording outlives none of its sources.
    pub(super) fn owns_every_source(&self, client: ClientId, recording_id: &str) -> bool {
        let sources: Vec<String> = match self.recordings.get(recording_id) {
            Some(recording) => match recording.multi.as_ref() {
                Some(multi) => multi
                    .sources
                    .iter()
                    .map(|source| source.call_id.clone())
                    .collect(),
                None => return true,
            },
            None => return true,
        };
        sources
            .iter()
            .all(|call_id| self.owned_call(client, call_id, |_| ()).is_some())
    }

    /// Attach a WebSocket tee fed by several calls ([`Command::AttachWsTee`] with
    /// `additional_sources`).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attach_multi_source_ws_tee(
        &self,
        client: ClientId,
        call_id: &str,
        additional: &[RecordingSource],
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> CmdResult {
        match self
            .begin_multi_source_ws_tee(
                client,
                call_id,
                additional,
                ws_uri,
                direction,
                channels,
                sample_rate,
            )
            .await
        {
            Ok(()) => ok_empty(),
            Err(reason) => error_result("attach_ws_tee", &reason),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn begin_multi_source_ws_tee(
        &self,
        client: ClientId,
        call_id: &str,
        additional: &[RecordingSource],
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> Result<(), String> {
        if direction == WsTeeDirection::Callee {
            return Err(
                "a multi-source tee streams what each source call received; direction callee is \
                 refused (use caller, or both, which on a source call is its caller)"
                    .to_string(),
            );
        }
        let Prepared { sources } = self.resolve_sources(client, call_id, additional)?;
        for source in &sources {
            if self.tee_involves(&source.call_id) {
                return Err(format!(
                    "call {} already carries a WebSocket tee",
                    source.call_id
                ));
            }
        }
        let wire_channels: u8 = match channels {
            Some(2) | None if sources.len() == 2 => channels.unwrap_or(2),
            Some(2) => {
                return Err(format!(
                    "a stereo tee carries exactly 2 sources, not {}; use channels 1 to mix",
                    sources.len()
                ))
            }
            Some(1) | None => 1,
            Some(other) => {
                return Err(format!("channels {other}: a tee is mono (1) or stereo (2)"))
            }
        };
        let wire_rate = match sample_rate {
            Some(requested) => {
                validate_wire_sample_rate(requested).map_err(|error| error.to_string())?
            }
            None => sources[0].rate,
        };
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: wire_rate,
            channels: wire_channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: sources[0].ptime,
        };
        let plan = plan_multi_source(format, sources.len()).map_err(|error| error.to_string())?;
        let stream_id = format!("tee-{}", super::scope::external(call_id));
        let tap_tag = format!(
            "{stream_id}#{}",
            self.next_tee_attach
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        // Dial before anything is attached, so a bad URI fails with nothing to unwind.
        let socket = self.dial_ws(call_id, ws_uri).await?;
        self.hold_sources(&sources, PromotionReason::WsTee).await?;
        self.attach_sources(
            &sources,
            &plan.control,
            wire_rate,
            &tap_tag,
            PromotionReason::WsTee,
        )
        .await?;

        let stats: Arc<MultiSourceStats> = plan.stats.clone();
        let task = tokio::spawn(plan.mixer.run());
        let output = TeeOutput {
            frames: plan.frames,
            recycle: plan.recycle,
            format: plan.format,
            tracks: plan.tracks,
            counters: TeeCounters::Multi(stats),
            multi: Some(MultiSourceFeed {
                sources: sources
                    .iter()
                    .map(|source| SourceCall {
                        call_id: source.call_id.clone(),
                    })
                    .collect(),
                control: plan.control,
                task,
                rate: wire_rate,
            }),
        };
        let announced = self.announce_ws_tee(
            call_id,
            ws_uri,
            TeeShape {
                direction,
                channels: wire_channels,
                sample_rate: wire_rate,
            },
            (socket, output, stream_id, tap_tag.clone()),
            (vec![true], Vec::new()),
        );
        if let Err(reason) = announced {
            // The first source's call vanished under the attach. Its output (and with it the
            // mixer's handle) is gone; take the rest off the other sources.
            for source in &sources {
                self.detach_source(&source.call_id, &tap_tag).await;
                self.release_userspace_hold(&source.call_id, PromotionReason::WsTee)
                    .await;
            }
            return Err(reason);
        }
        Ok(())
    }

    /// Take a multi-source tee's feed down after the tee left the registry: stop the mixer, take the
    /// sinks off every source but the first (whose sink and hold the shared teardown releases), and
    /// release their holds.
    pub(super) async fn release_multi_source_tee(
        &self,
        call_id: &str,
        tap_tag: &str,
        feed: MultiSourceFeed,
    ) {
        let MultiSourceFeed {
            sources,
            control,
            task,
            ..
        } = feed;
        drop(control);
        for source in sources.iter().filter(|source| source.call_id != call_id) {
            self.detach_source(&source.call_id, tap_tag).await;
            self.release_userspace_hold(&source.call_id, PromotionReason::WsTee)
                .await;
        }
        let _ = task.await;
    }

    /// Whether `call_id` is the first source of a tee, or a source of a multi-source one.
    fn tee_involves(&self, call_id: &str) -> bool {
        self.ws_tees.contains_key(call_id)
            || self.ws_tees.iter().any(|tee| {
                tee.value()
                    .multi
                    .as_ref()
                    .is_some_and(|multi| multi.involves(call_id))
            })
    }

    /// Whether `call_id` is a source of a multi-source tee **other than** its first (which is keyed
    /// by the call and replaced the way any tee is): a single-call tee there would share its hold.
    pub(super) fn is_secondary_tee_source(&self, call_id: &str) -> bool {
        !self.ws_tees.contains_key(call_id) && self.tee_involves(call_id)
    }

    /// End the multi-source tees `call_id` is a source of, because it was deleted: the tee reports
    /// [`WsTeeEndReason::CallEnded`] (a single call's tee torn down with its call reports
    /// `detached`, as it always has). The first source's call is the tee's key, so this reaches it
    /// from any source.
    pub(super) async fn end_multi_source_tees_for_call(&self, call_id: &str) {
        let keys: Vec<String> = self
            .ws_tees
            .iter()
            .filter(|tee| {
                tee.value()
                    .multi
                    .as_ref()
                    .is_some_and(|multi| multi.involves(call_id))
            })
            .map(|tee| tee.key().clone())
            .collect();
        for key in keys {
            self.end_ws_tee(&key, WsTeeEndReason::CallEnded, true).await;
        }
    }

    /// The feature `call_id` carries that a seat or a bot takeover would silently end: a multi-source
    /// recording or tee it is a source of. Refused rather than dropped, so the controller decides.
    pub(super) fn multi_source_attachment(&self, call_id: &str) -> Option<&'static str> {
        if self.recordings.iter().any(|entry| {
            entry
                .value()
                .multi
                .as_ref()
                .is_some_and(|m| m.involves(call_id))
        }) {
            return Some("a multi-source recording (start_recording additional_sources)");
        }
        if self.tee_involves(call_id) && !self.ws_tees.contains_key(call_id) {
            return Some("a multi-source WebSocket tee (attach_ws_tee additional_sources)");
        }
        self.ws_tees
            .get(call_id)
            .filter(|tee| tee.multi.is_some())
            .map(|_| "a multi-source WebSocket tee (attach_ws_tee additional_sources)")
    }

    /// Move the multi-source recordings and tees `call_id` is a source of onto the media path an
    /// answer just installed (RFC 3264 §8: the answer to a re-offer replaces the call's media actor
    /// and the sinks on it). The mixer, the file and the other sources go on untouched; only this
    /// source's sink is rebuilt, from the codec the call carries now. One that cannot follow ends as
    /// `call_ended`, which says why in the log.
    pub(super) async fn retap_multi_source(&self, call_id: &str) {
        let recordings: Vec<String> = self
            .recordings
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .multi
                    .as_ref()
                    .is_some_and(|multi| multi.involves(call_id))
            })
            .map(|entry| entry.key().clone())
            .collect();
        for recording_id in recordings {
            let sink = self.recordings.get(&recording_id).map(|recording| {
                recording
                    .multi
                    .as_ref()
                    .map(|feed| self.rebuilt_sink(call_id, feed, &recording_id))
            });
            let Some(Some(sink)) = sink else {
                continue;
            };
            if let Err(reason) = self
                .move_source(
                    call_id,
                    &recording_id,
                    PromotionReason::AudioRecording,
                    sink,
                )
                .await
            {
                tracing::warn!(
                    target: "siphon_rtp::media",
                    call_id,
                    recording_id,
                    reason,
                    "recording cannot follow the renegotiated media path; ending it"
                );
                self.stop_wav_recording(&recording_id, RecordingEndReason::CallEnded)
                    .await;
            }
        }
        let tees: Vec<String> = self
            .ws_tees
            .iter()
            .filter(|tee| {
                tee.value()
                    .multi
                    .as_ref()
                    .is_some_and(|multi| multi.involves(call_id))
            })
            .map(|tee| tee.key().clone())
            .collect();
        for key in tees {
            let rebuilt = self.ws_tees.get(&key).and_then(|tee| {
                let tag = tee.tap_tag.clone();
                tee.multi
                    .as_ref()
                    .map(|feed| (self.rebuilt_sink(call_id, feed, &tag), tag))
            });
            let Some((sink, tag)) = rebuilt else {
                continue;
            };
            if let Err(reason) = self
                .move_source(call_id, &tag, PromotionReason::WsTee, sink)
                .await
            {
                tracing::warn!(
                    target: "siphon_rtp::media",
                    call_id,
                    reason,
                    "ws tee cannot follow the renegotiated media path; ending it"
                );
                self.end_ws_tee(&key, WsTeeEndReason::CallEnded, true).await;
            }
        }
    }

    /// A fresh sink for `call_id`'s channel of `feed`, converting what its leg decodes to *now* into
    /// the feed's rate.
    fn rebuilt_sink(
        &self,
        call_id: &str,
        feed: &MultiSourceFeed,
        tag: &str,
    ) -> Result<MultiSourceSink, String> {
        let index = feed
            .index_of(call_id)
            .ok_or_else(|| "not a source of this stream".to_string())?;
        let codec = self
            .owned_call_internal(call_id, |call| call.near_codec.clone())
            .flatten()
            .ok_or_else(|| "the call has no negotiated codec any more".to_string())?;
        let resampler =
            wire_resampler(pcm_rate_of(&codec)?, feed.rate).map_err(|error| error.to_string())?;
        feed.control
            .sink(index, resampler, tag)
            .ok_or_else(|| "a source has no channel".to_string())
    }

    /// Replace the sink tagged `tag` on `call_id` with `sink`, holding the call in userspace again for
    /// `reason` first (an answer may have turned a promoted relay back into an in-kernel forward).
    async fn move_source(
        &self,
        call_id: &str,
        tag: &str,
        reason: PromotionReason,
        sink: Result<MultiSourceSink, String>,
    ) -> Result<(), String> {
        let sink = sink?;
        let pipeline = self
            .owned_call_internal(call_id, |call| call.pipeline)
            .ok_or_else(|| "call no longer exists".to_string())?;
        if pipeline.is_crypto_bridge() {
            return Err("the call is now a crypto bridge, which decodes nothing".to_string());
        }
        self.hold_in_userspace(call_id, reason, PromoteMode::RelayOnly)
            .await?;
        // Off whichever actor still holds the old sink first, so a re-tap never leaves two on one
        // source (the mailbox keeps the order).
        self.detach_source(call_id, tag).await;
        if !self
            .attach_recording_sink(call_id, true, true, Box::new(sink))
            .await
        {
            return Err("media actor unavailable".to_string());
        }
        Ok(())
    }
}
