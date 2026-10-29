//! The `record_call` profile recording, and keeping every decoded recording on a call across the
//! answer to a re-offer.
//!
//! `record_call` asks for one file per party, named `{call}-a.wav` (what the offerer, leg A, sent)
//! and `{call}-b.wav` (what the answerer, leg B, sent), mono at each party's decoded rate. It used
//! to buffer each direction in the media actor and write both files from the actor's teardown,
//! with no event: a recording server watching the directory could not tell a file still being
//! written from a party that never spoke from a file lost to the teardown grace. Each party is now
//! an ordinary decoded recording, streamed to disk and reported by `recording_finished` once the
//! file is in place, with a predictable id, `{call}-a` / `{call}-b`.

use std::sync::Arc;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_media::bridge::taps::TakenRecordingTaps;
use siphon_rtp_media::bridge::tee::{TeeChannel, TeeMixer, WsTeeSink};
use siphon_rtp_media::bridge::wire_rate::wire_resampler;
use siphon_rtp_proto::RecordingEndReason;

use super::record::{pcm_rate_of, StandUp};
use super::{Engine, PromoteMode, PromotionReason};

/// A recording's frame assembler, held strongly across a re-answer — see
/// [`Engine::pin_call_recordings`].
pub(super) type PinnedRecordings = Vec<Arc<std::sync::Mutex<TeeMixer>>>;

/// One party of a `record_call` recording: its leg, the suffix its file and id carry, and the
/// codec its PCM is decoded from.
struct Party {
    source_a: bool,
    suffix: &'static str,
}

const PARTIES: [Party; 2] = [
    Party {
        source_a: true,
        suffix: "a",
    },
    Party {
        source_a: false,
        suffix: "b",
    },
];

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Start the `record_call` streams for an answered call, one per party, into the profile's
    /// `record_path`. A no-op unless the answer asked for `record_call` and the call decodes (the
    /// flag forces the decode, so a call without a media actor here could not be recorded anyway).
    ///
    /// Idempotent: a party already being recorded under its id is left alone, so the answer to a
    /// re-offer does not start a second file over the first (the running streams were carried onto
    /// the new media path by [`Self::retap_call_recordings`]). A party that cannot be recorded is
    /// logged and skipped; the call itself is never failed for it, which is what the buffered
    /// recorder did too.
    pub(super) async fn start_record_call_streams(
        &self,
        call_id: &str,
        profile: &siphon_rtp_proto::ProfileFlags,
    ) {
        let Some(directory) = profile
            .record_call
            .then_some(profile.record_path.as_deref())
            .flatten()
        else {
            return;
        };
        if !self.media.is_media_call(call_id) {
            return;
        }
        let Some((near_codec, far_codec, from_tag, to_tag, owner)) =
            self.owned_call_internal(call_id, |call| {
                (
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.from_tag.clone(),
                    call.to_tag.clone(),
                    call.owner,
                )
            })
        else {
            return;
        };
        let stem = super::scope::external(call_id);
        for party in PARTIES {
            let recording_id = format!("{stem}-{}", party.suffix);
            if self.recordings.contains_key(&recording_id) {
                continue;
            }
            let codec = if party.source_a {
                near_codec.as_ref()
            } else {
                far_codec.as_ref()
            };
            let Some(codec) = codec else {
                continue;
            };
            let started = async {
                let rate = pcm_rate_of(codec)?;
                let final_path =
                    std::path::Path::new(directory).join(format!("{recording_id}.wav"));
                let mut partial = final_path.clone().into_os_string();
                partial.push(".partial");
                let partial = std::path::PathBuf::from(partial);
                let file = tokio::fs::File::create(&partial)
                    .await
                    .map_err(|error| format!("open {}: {error}", partial.display()))?;
                self.stand_up_recording(
                    call_id,
                    StandUp {
                        recording_id: recording_id.clone(),
                        from_tag: from_tag.clone(),
                        to_tag: to_tag.clone(),
                        owner,
                        path: partial,
                        file,
                        rename_to: Some(final_path),
                        rate,
                        ptime: codec.ptime_ms.max(1),
                        channels: 1,
                        encoding: crate::recording::RecordingEncoding::Wav,
                        limits: crate::recording::RecordingLimits::default(),
                        // One party per file, on the assembler's first ring whichever leg it is.
                        taps: vec![(true, party.source_a, TeeChannel::Caller, None)],
                    },
                )
                .await
            };
            match started.await {
                Ok(()) => tracing::debug!(
                    target: "siphon_rtp::media",
                    call_id,
                    recording_id,
                    "record_call stream started"
                ),
                Err(reason) => tracing::warn!(
                    target: "siphon_rtp::media",
                    call_id,
                    recording_id,
                    reason,
                    "record_call stream could not start; this party is not recorded"
                ),
            }
        }
    }

    /// Hold every pipeline recording on `call_id` open across an answer that may re-install its
    /// media path.
    ///
    /// Re-registering a call id replaces its media actor, and the old one drops its sinks as soon
    /// as it stops. A recording's sinks are the only strong references to its frame assembler, so
    /// without this the writer would see its input close and finalize the file before
    /// [`Self::retap_call_recordings`] got to move it. Drop the returned handles once that has run.
    /// `None` on a first answer (`answered_before` false): there is no earlier media path, so
    /// nothing can be running yet, and [`Self::settle_answered_media`] has nothing to carry.
    pub(super) fn pin_call_recordings(
        &self,
        call_id: &str,
        answered_before: bool,
    ) -> Option<PinnedRecordings> {
        answered_before.then(|| {
            self.recordings
                .iter()
                .filter(|entry| entry.value().call_id == call_id)
                .filter(|entry| entry.value().on_media_actor())
                .filter_map(|entry| {
                    entry
                        .value()
                        .taps
                        .as_ref()
                        .and_then(|taps| taps.mixer.upgrade())
                })
                .collect()
        })
    }

    /// Put every pipeline recording on `call_id` back onto the media path the answer to a re-offer
    /// installed: the same file and assembler, fresh sinks decoding from each leg's codec as it now
    /// is, resampled into the file's rate (RFC 3264 §8 lets the answer change the codec).
    ///
    /// A recording whose path cannot carry it any more — the call became a crypto bridge, which has
    /// no decode fan-out — is ended as `call_ended`, and says why in the log, the way a tee that
    /// cannot follow is.
    pub(super) async fn retap_call_recordings(&self, call_id: &str) {
        let running: Vec<String> = self
            .recordings
            .iter()
            .filter(|entry| entry.value().call_id == call_id && entry.value().on_media_actor())
            .map(|entry| entry.key().clone())
            .collect();
        for recording_id in running {
            if let Err(reason) = self.retap_recording(call_id, &recording_id).await {
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
    }

    async fn retap_recording(&self, call_id: &str, recording_id: &str) -> Result<(), String> {
        let Some((mixer, rate, taps, ingress_legs, egress_legs)) =
            self.recordings.get(recording_id).and_then(|recording| {
                let taps = recording.taps.as_ref()?;
                Some((
                    taps.mixer.upgrade(),
                    taps.rate,
                    taps.layout.clone(),
                    recording.ingress_legs.clone(),
                    recording.egress_legs.clone(),
                ))
            })
        else {
            return Ok(());
        };
        // The writer already finished (a limit was reached): nothing left to carry.
        let Some(mixer) = mixer else {
            return Ok(());
        };
        // A bot has the leg: the recording's sinks are on its bridge session, which an answer does
        // not replace, so they are still where they were.
        if self.bridge_recording_target(call_id).is_some() {
            return Ok(());
        }
        let (pipeline, near_codec, far_codec) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.pipeline,
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                )
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        if pipeline.is_crypto_bridge() {
            return Err("the call is now a crypto bridge, which decodes nothing".to_string());
        }
        // A relay the answer turned back into an in-kernel forward has already been promoted again
        // by `carry_holds_across_answer`, on the strength of this recording's hold; this only
        // asserts it, and promotes when nothing else had.
        self.hold_in_userspace(
            call_id,
            PromotionReason::AudioRecording,
            PromoteMode::RelayOnly,
        )
        .await?;
        let caller_rate = near_codec.as_ref().map(pcm_rate_of).transpose()?;
        let callee_rate = far_codec.as_ref().map(pcm_rate_of).transpose()?;

        // Off whichever actor still holds them first — the answer may have kept the old one — so
        // a re-tap never leaves two sinks on one ring (the mailbox keeps the order).
        self.detach_recording_sinks(call_id, recording_id, &ingress_legs, &egress_legs)
            .await;
        for (source, channel) in taps {
            let (is_ingress, source_a) = source.parts();
            // The callee's own ingress is the only tap fed at the callee's rate; the caller's
            // ingress and everything sent toward the caller run at the caller's.
            let leg_rate = if is_ingress && !source_a {
                callee_rate
            } else {
                caller_rate
            };
            let leg_rate = leg_rate
                .ok_or_else(|| "a recorded leg has no negotiated codec any more".to_string())?;
            let resampler = wire_resampler(leg_rate, rate).map_err(|error| error.to_string())?;
            let sink = WsTeeSink::new(channel, mixer.clone(), recording_id.to_string(), resampler);
            if !self
                .attach_recording_sink(call_id, is_ingress, source_a, Box::new(sink))
                .await
            {
                return Err("media actor unavailable".to_string());
            }
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            recording_id,
            "recording re-tapped after renegotiation"
        );
        Ok(())
    }
}

// ---- carrying recordings across a hand-over to and from a voice bot ----

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Whether any decoded recording is running on `call_id`.
    fn records(&self, call_id: &str) -> bool {
        self.recordings
            .iter()
            .any(|entry| entry.value().call_id == call_id && entry.value().room.is_none())
    }

    /// Take every recording sink off `call_id`'s media actor, **unfinished**, so the recording can
    /// move with the leg instead of ending with the actor. Empty when nothing records the call.
    ///
    /// Only recording sinks can be there: an anchor carrying a tee, a subscription, an interception
    /// or a pcap capture refuses the hand-over before this runs.
    pub(super) async fn take_pipeline_recordings(&self, call_id: &str) -> TakenRecordingTaps {
        if !self.records(call_id) {
            return TakenRecordingTaps::default();
        }
        let (reply, taken) = tokio::sync::oneshot::channel();
        if !self.media.control(
            call_id,
            crate::media_pipeline::MediaControl::TakeAttachments { reply },
        ) {
            return TakenRecordingTaps::default();
        }
        let Ok(carried) = taken.await else {
            return TakenRecordingTaps::default();
        };
        // On a single-leg anchor the caller's audio is leg A's ingress and what the caller hears
        // goes out on `a_to_b`; whichever slot a sink came from, it is one of those two.
        let [forks_a, forks_b] = carried.forks;
        let [egress_toward_a, egress_toward_b] = carried.egress_taps;
        (
            forks_a.into_iter().chain(forks_b).collect(),
            egress_toward_b.into_iter().chain(egress_toward_a).collect(),
        )
    }

    /// Put recording sinks taken from a pipeline or a bridge onto `call_id`'s single-leg media
    /// actor: the caller's on leg A's ingress, what the caller heard on the egress that reaches it.
    /// A sink that finds no actor is dropped, which ends its recording as the call ending would.
    pub(super) fn give_pipeline_recordings(&self, call_id: &str, taps: TakenRecordingTaps) {
        use crate::media_pipeline::MediaControl;
        let (caller, heard) = taps;
        for sink in caller {
            self.media.control(
                call_id,
                MediaControl::AddFork {
                    source_a: true,
                    sink,
                },
            );
        }
        for sink in heard {
            self.media.control(
                call_id,
                MediaControl::AddEgressFork {
                    toward_a: false,
                    sink,
                },
            );
        }
    }

    /// Take every recording sink off `call_id`'s running bridge, unfinished. Empty when it has none
    /// or there is no bridge.
    pub(super) async fn take_bridge_recordings(&self, call_id: &str) -> TakenRecordingTaps {
        use siphon_rtp_media::bridge::ws::BridgeControl;
        if !self.records(call_id) {
            return TakenRecordingTaps::default();
        }
        let Some(bridge) = self.bridge_recording_target(call_id) else {
            return TakenRecordingTaps::default();
        };
        let (reply, taken) = tokio::sync::oneshot::channel();
        if bridge
            .control
            .send_async(BridgeControl::TakeRecordingTaps { reply })
            .await
            .is_err()
        {
            return TakenRecordingTaps::default();
        }
        taken.await.unwrap_or_default()
    }

    /// Put recording sinks onto `call_id`'s running bridge. A sink with no bridge to take it is
    /// dropped, which ends its recording.
    pub(super) async fn give_bridge_recordings(&self, call_id: &str, taps: TakenRecordingTaps) {
        use siphon_rtp_media::bridge::taps::TapSide;
        use siphon_rtp_media::bridge::ws::BridgeControl;
        let (caller, heard) = taps;
        let Some(bridge) = self.bridge_recording_target(call_id) else {
            return;
        };
        let sides = caller
            .into_iter()
            .map(|sink| (TapSide::Caller, sink))
            .chain(heard.into_iter().map(|sink| (TapSide::Heard, sink)));
        for (side, sink) in sides {
            let _ = bridge
                .control
                .send_async(BridgeControl::AddRecordingTap { side, sink })
                .await;
        }
    }
}
