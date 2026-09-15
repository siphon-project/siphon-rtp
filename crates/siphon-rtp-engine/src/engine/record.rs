//! Runtime recording: raw-RTP pcap and decoded-audio WAV.

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::Datapath;
use siphon_rtp_media::pcap::{self, CapturedPacket};
use siphon_rtp_proto::{
    CmdResult, Event, RecordingChannels, RecordingDirection, RecordingEndReason,
};
use std::sync::Arc;

use crate::conference::ConferenceControl;
use crate::media_pipeline::{MediaControl, PcapCapture};
use crate::text_pipeline::TextControl;

use super::{
    error_result, ok_empty, unknown_call, ClientId, Engine, PipelineKind, PromoteMode,
    PromotionReason,
};

/// A live WebSocket tee on one call: the shared mixer (for its counters), its transport task, and the
/// per-leg fork tags so a detach removes exactly this tee's sinks and nothing else.
/// A live decoded-audio recording, as the engine tracks it.
///
/// Mirrors [`WsTee`], and for the same reasons — the correlation ids are copied in at start because
/// teardown runs *after* `delete` has removed the call, so the completion event cannot look them up.
///
/// Note what is deliberately **not** here: the shared frame assembler. Only the sinks hold it, so
/// detaching them drops the last reference, closes the frame channel, and the writer task finalizes
/// the file on its own. That is the whole stop mechanism — there is no separate kill signal to race
/// the finalize, and a call torn down underneath a recording ends it exactly the same way.
pub(super) struct AudioRecording {
    /// Also the fork tag on every leg it taps, and the event correlator.
    pub(super) recording_id: String,
    pub(super) call_id: String,
    pub(super) owner: ClientId,
    pub(super) path: std::path::PathBuf,
    /// Ingress taps: which source legs carry a sink (`true` = leg A / caller).
    pub(super) ingress_legs: Vec<bool>,
    /// Egress taps: which directions carry a sink (`true` = toward A).
    pub(super) egress_legs: Vec<bool>,
    /// The conference this recording taps, when it is a room recording rather than a call one. The
    /// detach then targets the room actor's own tap list instead of a call's fan-out.
    pub(super) room: Option<String>,
    /// Why the recording ended when the *source* simply went away. Set by an explicit stop before it
    /// detaches; left at `CallEnded` otherwise, because a writer cannot tell a stop from a hangup —
    /// both are just "the sinks are gone" — and guessing would report one as the other.
    pub(super) source_reason: Arc<std::sync::Mutex<RecordingEndReason>>,
    /// The writer task. **Never aborted**: aborting it would skip the header finalize and leave a
    /// file declaring zero samples. It is ended by closing its input, and then awaited.
    pub(super) writer: tokio::task::JoinHandle<()>,
}

impl AudioRecording {
    /// Whether this recording belongs to `call_id` — how an unnamed `stop_recording` (and a call
    /// teardown) finds every recording it must end.
    fn call_id_matches(&self, call_id: &str) -> bool {
        self.call_id == call_id
    }
}

/// The decoded-recording knobs, grouped so the start path takes one parameter rather than six.
pub(super) struct WavRecordingRequest {
    pub(super) direction: RecordingDirection,
    pub(super) channels: RecordingChannels,
    pub(super) limits: crate::recording::RecordingLimits,
    /// Explicit output path, overriding the directory + generated name.
    pub(super) path: Option<String>,
    /// Output directory, when no explicit path was given.
    pub(super) recording_dir: Option<String>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Begin a runtime raw-RTP pcap recording of an established call ([`Command::StartRecording`] /
    /// rtpengine `start recording`). A plain passthrough relay is promoted to the userspace media
    /// pipeline (so its packets can be tapped) and each accepted RTP/RTCP datagram is captured
    /// byte-for-byte — the source leg's negotiated codec, no decode — into `{recording_dir}/{call}.pcap`
    /// wrapped in synthetic Ethernet/IP/UDP so it dissects as RTP. Rejected on a secure (SRTP) or
    /// WebSocket-bridged call, whose on-the-wire bytes are ciphertext / off to a WS server rather than
    /// the clear media (mirrors `subscribe_request`; SRTP decrypt-then-record is a follow-up).
    pub(super) async fn start_recording(
        &self,
        client: ClientId,
        call_id: &str,
        recording_dir: Option<String>,
    ) -> CmdResult {
        // Snapshot the pipeline + each leg's engine-local RTP address under the ownership guard (A3),
        // plus each leg's text endpoint local address (for the text pcap capture) when text was
        // negotiated — recording captures the RFC 4103 text stream too.
        let Some((pipeline, a_local, b_local, text_locals)) =
            self.owned_call(client, call_id, |call| {
                // A text stream is relayed only between two legs, so `text_relay_flows` is empty (and
                // this `None`) whenever there is no far leg.
                let text_locals = (!call.text_relay_flows.is_empty())
                    .then(|| {
                        call.near
                            .text
                            .zip(call.far.as_ref().and_then(|far| far.text))
                            .map(|(near, far)| (near.local_addr, far.local_addr))
                    })
                    .flatten();
                // The pcap stamps each direction's capture destination with the engine socket that
                // datagram arrived on. A single-leg call has one socket carrying both directions, so
                // both stamps are that socket — which is what the wire actually looks like.
                let caller_local = call.caller_leg().rtp.local_addr;
                (
                    call.pipeline,
                    call.near.rtp.local_addr,
                    call.far
                        .as_ref()
                        .map_or(caller_local, |far| far.rtp.local_addr),
                    text_locals,
                )
            })
        else {
            return unknown_call(call_id);
        };
        // Every crypto bridge carries ciphertext on the wire (the SDES and DTLS bridges, facing either
        // party), as does a secure transcode, and a WS-bridged call carries no two-party media at all.
        if pipeline.is_crypto_bridge()
            || matches!(pipeline, PipelineKind::SrtpMedia | PipelineKind::Ws)
        {
            return error_result(
                "start_recording",
                &"recording a secure (SRTP) or WebSocket-bridged call is not supported yet",
            );
        }
        let Some(directory) = recording_dir else {
            return error_result(
                "start_recording",
                &"no recording directory (set recording-dir)",
            );
        };
        // Open the pcap up front so a bad path fails cleanly before we promote or spawn anything.
        let path = format!("{directory}/{call_id}.pcap");
        let file = match tokio::fs::File::create(&path).await {
            Ok(file) => file,
            Err(error) => return error_result("start_recording: open pcap", &error),
        };
        // Promote a plain relay to userspace (idempotent) and hold it for the duration of recording.
        if let Err(reason) = self
            .hold_in_userspace(call_id, PromotionReason::Recording, PromoteMode::RelayOnly)
            .await
        {
            return error_result("start_recording: promote relay", &reason);
        }
        // Hand the actor the capture sink; the engine owns the drain task that frames + streams to disk.
        let (sender, receiver) = flume::bounded::<CapturedPacket>(PCAP_CAPTURE_QUEUE);
        let capture = PcapCapture {
            sender: sender.clone(),
            a_local,
            b_local,
        };
        if !self
            .media
            .control(call_id, MediaControl::StartRecording { capture })
        {
            // The actor vanished between promote and control — release the hold and report.
            self.release_userspace_hold(call_id, PromotionReason::Recording)
                .await;
            return error_result("start_recording", &"media actor unavailable");
        }
        // Capture the RFC 4103 text stream too, into the SAME pcap sink: promote only the text endpoints
        // to the userspace text processor (the audio path is already promoted for its own recording) and
        // hand it a capture keyed on the text endpoints' local addresses. Best-effort — a text-promotion
        // failure leaves audio recording intact; the text stream keeps relaying in-kernel.
        if let Some((text_a_local, text_b_local)) = text_locals {
            if let Err(reason) = self
                .hold_text_in_userspace(call_id, PromotionReason::Recording)
                .await
            {
                tracing::warn!(
                    target: "siphon_rtp::text",
                    call_id,
                    reason,
                    "recording could not promote the text stream; text is not captured"
                );
            } else {
                let text_capture = PcapCapture {
                    sender,
                    a_local: text_a_local,
                    b_local: text_b_local,
                };
                if !self.text.control(
                    call_id,
                    TextControl::StartRecording {
                        capture: text_capture,
                    },
                ) {
                    self.release_text_hold(call_id, PromotionReason::Recording)
                        .await;
                    tracing::warn!(
                        target: "siphon_rtp::text",
                        call_id,
                        "text actor unavailable for recording; text is not captured"
                    );
                }
            }
        }
        tokio::spawn(run_pcap_recorder(file, receiver, path));
        ok_empty()
    }

    /// Stop a runtime recording started with [`Self::start_recording`] ([`Command::StopRecording`] /
    /// rtpengine `stop recording`): tell the actor to drop its capture sink (the drain task then
    /// finalizes the `.pcap`) and release the recording hold, demoting the relay back to the in-kernel
    /// `Forward` fast path if no other hold (a SIPREC subscription) remains.
    pub(super) async fn stop_recording(
        &self,
        client: ClientId,
        call_id: &str,
        recording_id: Option<&str>,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // A named recording is a decoded-audio one: stop exactly it and leave everything else — the
        // pcap, another recording on the same call — running.
        if let Some(recording_id) = recording_id {
            if !self.recordings.contains_key(recording_id) {
                return error_result(
                    "stop_recording",
                    &format!("no recording {recording_id} is running on this call"),
                );
            }
            self.stop_wav_recording(recording_id, RecordingEndReason::Stopped)
                .await;
            return ok_empty();
        }
        // Unnamed: stop everything this call is recording, which is what rtpengine's `stop recording`
        // means and the only thing the NG front-end can express.
        let running: Vec<String> = self
            .recordings
            .iter()
            .filter(|entry| entry.value().call_id_matches(call_id))
            .map(|entry| entry.key().clone())
            .collect();
        for recording_id in running {
            self.stop_wav_recording(&recording_id, RecordingEndReason::Stopped)
                .await;
        }
        // No-op in the actor if not recording; ignored if the call has no actor (never promoted).
        self.media.control(call_id, MediaControl::StopRecording);
        self.release_userspace_hold(call_id, PromotionReason::Recording)
            .await;
        // Stop capturing the text stream too; the text leg stays promoted only if `text_events` still
        // holds it, else it demotes back to the in-kernel relay.
        self.text.control(call_id, TextControl::StopRecording);
        self.release_text_hold(call_id, PromotionReason::Recording)
            .await;
        ok_empty()
    }

    /// Begin a runtime **decoded-audio** recording ([`Command::StartRecording`] with
    /// `format: "wav"`).
    ///
    /// The point of the verb: a voicemail box answers locally, plays a greeting and a beep, and only
    /// *then* records the caller — so recording has to start at a moment the controller picks, capture
    /// decoded audio (the file is emailed, transcribed and played back on handsets), work on a
    /// single-leg call, and tell the controller when the file is complete. None of `record_call`
    /// (offer/answer-time, two legs, buffered in RAM, flushed at teardown) or the pcap recorder (raw
    /// wire bytes) does any of that.
    ///
    /// It attaches the **same** sinks a WebSocket tee does, onto the same post-decode fan-out, feeding
    /// the same shared frame assembler — which already interleaves two legs, hands off over a bounded
    /// channel and recycles its buffers with no per-frame allocation. Its wire frames are little-endian
    /// 16-bit PCM, i.e. exactly a WAV `data` payload, so the writer appends them verbatim.
    pub(super) async fn start_wav_recording(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        request: WavRecordingRequest,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        match self.begin_wav_recording(call_id, from_tag, request).await {
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

    /// Stand the recording up. Split out so every failure returns `Err` with the call untouched —
    /// nothing is promoted, no file is created and no sink is attached until every input has been
    /// validated, exactly as `start_ws_tee` does.
    async fn begin_wav_recording(
        &self,
        call_id: &str,
        from_tag: &str,
        request: WavRecordingRequest,
    ) -> Result<String, String> {
        use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
        use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};
        use siphon_rtp_media::bridge::wire_rate::wire_resampler;

        // Same exclusions the tee has, and for the same reason: a WS-takeover call's media never
        // reaches the pipeline, and a crypto *bridge* relays ciphertext without decoding, so neither
        // has a post-decode fan-out to tap. A secure call that runs through the media pipeline
        // (`SrtpMedia` / `DtlsMedia`) decodes like any other and records fine — which is the case the
        // pcap recorder has to refuse and this one does not.
        let pipeline = self
            .owned_call_internal(call_id, |call| call.pipeline)
            .ok_or_else(|| "call no longer exists".to_string())?;
        if self.ws.is_ws_call(call_id) || pipeline == PipelineKind::Ws {
            return Err(
                "a WebSocket-takeover call (ws_uri) has no relay path to record".to_string(),
            );
        }
        if pipeline.is_crypto_bridge() {
            return Err(
                "recording a secure crypto-bridge call is not supported — the bridge relays \
                 ciphertext without decoding; a transcoded secure call records fine"
                    .to_string(),
            );
        }

        let (near_codec, far_codec, two_leg, to_tag, owner) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.far
                        .as_ref()
                        .is_some_and(|far| far.remote_rtp.is_some()),
                    call.to_tag.clone(),
                    call.owner,
                )
            })
            .ok_or_else(|| "call no longer exists".to_string())?;

        let caller_rate = near_codec.as_ref().map(pcm_rate_of).transpose()?;
        let callee_rate = far_codec.as_ref().map(pcm_rate_of).transpose()?;
        // The recording rate is the caller leg's decoded PCM rate — not its RTP clock, which for G.722
        // is half of it (RFC 3551 §4.5.2) and would replay the file at the wrong pitch. A second leg at
        // another rate is resampled into it.
        let rate = caller_rate
            .or(callee_rate)
            .ok_or_else(|| "the call has no negotiated codec to record".to_string())?;
        let ptime = near_codec
            .as_ref()
            .map_or(20, |codec| codec.ptime_ms.max(1));

        // Which taps. Ingress is what the parties *sent* (a voicemail message); egress is what the
        // engine sent them (its prompts), which on a single-leg call is the only way to capture the
        // engine's own audio at all — there is no second party whose ingress it would be.
        let (want_ingress, want_egress) = match request.direction {
            RecordingDirection::Ingress => (true, false),
            RecordingDirection::Egress => (false, true),
            RecordingDirection::Both => (true, true),
        };
        // Two sources exist only on an answered two-party call. A single-leg call records mono
        // whatever was asked for, rather than stalling on a stereo frame whose second ring never
        // fills — the same degradation the tee applies.
        let two_sources = two_leg && !(want_ingress && want_egress);
        let stereo = matches!(request.channels, RecordingChannels::Stereo) && two_sources;
        let channels: u8 = if stereo { 2 } else { 1 };

        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: rate,
            channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime,
        };

        // Every conversion is built before anything is touched, so a rate this engine cannot serve
        // fails with the call exactly as it was.
        let mut taps: Vec<(
            bool,
            bool,
            TeeChannel,
            Option<siphon_rtp_dsp::resample::Resampler>,
        )> = Vec::new();
        for (is_ingress, source_a, channel, leg_rate, wanted) in [
            (true, true, TeeChannel::Caller, caller_rate, want_ingress),
            (
                true,
                false,
                TeeChannel::Callee,
                callee_rate,
                want_ingress && two_leg,
            ),
            // Egress toward A is the engine's audio for the caller; on a two-party call it is what B
            // sent, already covered by B's ingress, so only the caller-facing side is tapped unless
            // both directions were asked for.
            (false, true, TeeChannel::Callee, caller_rate, want_egress),
        ] {
            if !wanted {
                continue;
            }
            // A stereo recording puts the caller left and everything else right; a mono one folds
            // every source into ring 0 so the assembler sums them.
            let channel = if stereo { channel } else { TeeChannel::Caller };
            let resampler = match leg_rate {
                Some(leg_rate) => {
                    wire_resampler(leg_rate, rate).map_err(|error| error.to_string())?
                }
                None => None,
            };
            taps.push((is_ingress, source_a, channel, resampler));
        }
        if taps.is_empty() {
            return Err("the call has no leg matching the requested direction".to_string());
        }

        let recording_id = format!(
            "rec-{}",
            self.next_recording_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = match request.path {
            Some(path) => std::path::PathBuf::from(path),
            None => {
                let directory = request.recording_dir.ok_or_else(|| {
                    "no output location (set `path`, or `recording_dir`)".to_string()
                })?;
                std::path::PathBuf::from(directory).join(format!("{call_id}-{recording_id}.wav"))
            }
        };

        // Open the output up front, exactly as the pcap path does: a bad path must fail the verb with
        // the call untouched — nothing promoted, no sink attached — rather than being reported minutes
        // later as a `RecordingFinished{Error}` for a recording the controller believes is running.
        let file = tokio::fs::File::create(&path)
            .await
            .map_err(|error| format!("open {}: {error}", path.display()))?;

        // A relay-only actor (a pcap recording, a DTMF block) forwards RTP verbatim and never decodes,
        // so the fan-out this taps would stay dry. Rebuild it as a processing actor, then hold it for
        // the recording's lifetime.
        if self.media.is_relay_call(call_id) {
            self.upgrade_relay_to_processing(call_id).await?;
        }
        self.hold_in_userspace(
            call_id,
            PromotionReason::AudioRecording,
            PromoteMode::Processing,
        )
        .await?;

        let plan = plan_ws_tee(format, stereo, false);
        let mut ingress_legs = Vec::new();
        let mut egress_legs = Vec::new();
        for (is_ingress, source_a, channel, resampler) in taps {
            let sink = WsTeeSink::new(channel, plan.mixer.clone(), recording_id.clone(), resampler);
            let attached = if is_ingress {
                self.media.control(
                    call_id,
                    MediaControl::AddFork {
                        source_a,
                        sink: Box::new(sink),
                    },
                )
            } else {
                self.media.control(
                    call_id,
                    MediaControl::AddEgressFork {
                        toward_a: source_a,
                        sink: Box::new(sink),
                    },
                )
            };
            if !attached {
                self.detach_recording_sinks(call_id, &recording_id, &ingress_legs, &egress_legs);
                self.release_userspace_hold(call_id, PromotionReason::AudioRecording)
                    .await;
                return Err("media actor unavailable".to_string());
            }
            if is_ingress {
                ingress_legs.push(source_a);
            } else {
                egress_legs.push(source_a);
            }
        }

        // `CallEnded` is the default because it is the truthful answer when nothing set it: the sinks
        // went away and nobody asked them to.
        let source_reason = Arc::new(std::sync::Mutex::new(RecordingEndReason::CallEnded));
        let writer = {
            let events = self.events.get(&owner).map(|sink| sink.value().clone());
            let call_id = call_id.to_string();
            let from_tag = from_tag.to_string();
            let to_tag = to_tag.clone();
            let recording_id = recording_id.clone();
            let path = path.clone();
            let source_reason = source_reason.clone();
            let frames = plan.frames;
            let recycle = plan.recycle;
            tokio::spawn(async move {
                let outcome = crate::recording::run_wav_recorder(
                    file,
                    path.clone(),
                    rate,
                    u16::from(channels),
                    request.limits,
                    frames,
                    recycle,
                )
                .await;
                let source_reason = source_reason
                    .lock()
                    .map(|reason| *reason)
                    .unwrap_or(RecordingEndReason::CallEnded);
                let reason = outcome.end.into_reason(source_reason);
                // Emitted only now — after the header has been finalized and the file flushed — so a
                // consumer that acts on this event never opens a half-written file. That is the whole
                // reason the event exists.
                if let Some(events) = events {
                    let _ = events.try_send(Event::RecordingFinished {
                        conference_id: None,
                        call_id,
                        from_tag,
                        to_tag,
                        recording_id,
                        path: Some(path.to_string_lossy().into_owned()),
                        duration_ms: outcome.duration_ms,
                        reason,
                    });
                }
            })
        };

        self.recordings.insert(
            recording_id.clone(),
            AudioRecording {
                recording_id: recording_id.clone(),
                call_id: call_id.to_string(),
                owner,
                path,
                ingress_legs,
                egress_legs,
                room: None,
                source_reason,
                writer,
            },
        );
        Ok(recording_id)
    }

    /// Detach every sink a recording attached, without touching anything else on the same legs.
    fn detach_recording_sinks(
        &self,
        call_id: &str,
        recording_id: &str,
        ingress_legs: &[bool],
        egress_legs: &[bool],
    ) {
        for source_a in ingress_legs {
            self.media.control(
                call_id,
                MediaControl::RemoveForkTagged {
                    source_a: *source_a,
                    tag: recording_id.to_string(),
                },
            );
        }
        for toward_a in egress_legs {
            self.media.control(
                call_id,
                MediaControl::RemoveEgressForkTagged {
                    toward_a: *toward_a,
                    tag: recording_id.to_string(),
                },
            );
        }
    }

    /// End one decoded-audio recording and wait for its file to be closed.
    ///
    /// The stop **is** the detach: dropping the sinks drops the last reference to the shared frame
    /// assembler, which closes the writer's input, which makes it finalize the header and emit
    /// [`Event::RecordingFinished`]. The writer is never aborted — that would skip the finalize and
    /// leave a valid-but-empty WAV — and awaiting it is what makes the event ordering a guarantee
    /// rather than a race for a controller that stops a recording and immediately reads the file.
    pub(super) async fn stop_wav_recording(&self, recording_id: &str, reason: RecordingEndReason) {
        let Some((_, recording)) = self.recordings.remove(recording_id) else {
            return;
        };
        if let Ok(mut stored) = recording.source_reason.lock() {
            *stored = reason;
        }
        match recording.room.as_deref() {
            // A room recording detaches from the room actor, which holds nothing else to release —
            // a conference is always in userspace, so there is no promotion hold behind it.
            Some(conference_id) => {
                self.conference.control(
                    conference_id,
                    ConferenceControl::RemoveRoomTapTagged {
                        tag: recording.recording_id.clone(),
                    },
                );
                let _ = recording.writer.await;
            }
            None => {
                self.detach_recording_sinks(
                    &recording.call_id,
                    &recording.recording_id,
                    &recording.ingress_legs,
                    &recording.egress_legs,
                );
                let _ = recording.writer.await;
                self.release_userspace_hold(&recording.call_id, PromotionReason::AudioRecording)
                    .await;
            }
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %recording.call_id,
            recording_id,
            path = %recording.path.display(),
            owner = recording.owner.0,
            ?reason,
            "decoded recording stopped"
        );
    }

    /// End every decoded recording on a call, for a teardown that is not an operator stop.
    pub(super) async fn stop_wav_recordings_for_call(
        &self,
        call_id: &str,
        reason: RecordingEndReason,
    ) {
        let running: Vec<String> = self
            .recordings
            .iter()
            .filter(|entry| entry.value().call_id_matches(call_id))
            .map(|entry| entry.key().clone())
            .collect();
        for recording_id in running {
            self.stop_wav_recording(&recording_id, reason).await;
        }
    }
}

/// The decoded-PCM sample rate of `codec` — what the media pipeline's fan-out actually hands a sink.
/// This is **not** the RTP clock rate: G.722 samples at 16 kHz while clocking RTP at 8 kHz (RFC 3551
/// §4.5.2), so reading `clock_rate_hz` would size a tee's wire frame wrong. Built by asking the codec
/// factory for a decoder, exactly as the WS-takeover bridge does.
pub(super) fn pcm_rate_of(codec: &CodecSpec) -> Result<u32, String> {
    factory::decoder_for(codec)
        .map(|decoder| decoder.params().sample_rate_hz)
        .map_err(|error| format!("no decoder for {}: {error}", codec.encoding_name))
}

/// Bounded depth of a recording's capture channel. At telephony rates (~50 packets/s per leg) this
/// buffers several seconds per leg before the actor drops packets under a stalled disk — a recording
/// is best-effort and must never backpressure the media path.
const PCAP_CAPTURE_QUEUE: usize = 1024;

/// Drain task for a runtime pcap recording: write the libpcap global header, then one framed record
/// per captured datagram, streaming to disk with async I/O (so the actor never blocks). Exits when
/// the actor drops its capture sink (`stop recording` / teardown closes the channel), then flushes
/// and closes the file.
async fn run_pcap_recorder(
    mut file: tokio::fs::File,
    receiver: flume::Receiver<CapturedPacket>,
    path: String,
) {
    use tokio::io::AsyncWriteExt;
    if let Err(error) = file.write_all(&pcap::global_header()).await {
        tracing::warn!(%error, path, "pcap recorder: failed to write header");
        return;
    }
    while let Ok(packet) = receiver.recv_async().await {
        if let Err(error) = file.write_all(&pcap::frame(&packet)).await {
            tracing::warn!(%error, path, "pcap recorder: write failed, stopping");
            break;
        }
    }
    if let Err(error) = file.flush().await {
        tracing::warn!(%error, path, "pcap recorder: final flush failed");
    } else {
        tracing::info!(path, "pcap recording finalized");
    }
}
