//! Runtime recording: raw-RTP pcap, and decoded audio as WAV or Ogg Opus.

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_media::pcap::{self, CapturedPacket};
use siphon_rtp_proto::{
    CmdResult, Event, RecordingChannels, RecordingDirection, RecordingEndReason, RecordingFormat,
    RECORDING_OPUS_BITRATE_BPS_MAX, RECORDING_OPUS_BITRATE_BPS_MIN,
    RECORDING_OPUS_BITRATE_BPS_PER_CHANNEL_DEFAULT,
};
use std::sync::Arc;

use crate::conference::ConferenceControl;
use crate::media_pipeline::{MediaControl, PcapCapture};
use crate::text_pipeline::TextControl;

use super::tee::{run_bridge_tap_decoder, BRIDGE_TAP_QUEUE};
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
    /// On a crypto-bridged call: each tapped endpoint and the task decoding its plaintext for the
    /// recording. Empty on a pipeline call, whose sinks sit on the actor's own post-decode fan-out.
    pub(super) bridge_taps: Vec<(EndpointId, tokio::task::JoinHandle<()>)>,
    /// Why the recording ended when the *source* simply went away. Set by an explicit stop before it
    /// detaches; left at `CallEnded` otherwise, because a writer cannot tell a stop from a hangup —
    /// both are just "the sinks are gone" — and guessing would report one as the other.
    pub(super) source_reason: Arc<std::sync::Mutex<RecordingEndReason>>,
    /// The writer task. **Never aborted**: aborting it would skip the close and leave a WAV
    /// declaring zero samples, or an Ogg file missing its last page. It is ended by closing its
    /// input, and then awaited.
    pub(super) writer: tokio::task::JoinHandle<()>,
    /// What it takes to put this recording's sinks back on a media path a renegotiation
    /// re-installed. `None` for a room or crypto-bridge recording, which do not sit on a call's
    /// media actor.
    pub(super) retap: Option<Retap>,
}

/// How to re-attach a pipeline recording after the answer to a re-offer replaced the media actor
/// its sinks lived on (RFC 3264 §8). The fresh actor starts with no sinks, so without this a
/// recording ends at the first re-INVITE, with a short file and no stop from anyone.
pub(super) struct Retap {
    /// The recording's frame assembler, held **weakly**: the sinks hold it strongly, and dropping
    /// them is still what ends the recording (see [`AudioRecording`]). A weak handle that no longer
    /// upgrades means the writer has already finished, so there is nothing to re-attach.
    pub(super) mixer: std::sync::Weak<std::sync::Mutex<siphon_rtp_media::bridge::tee::TeeMixer>>,
    /// The file's sample rate, which every re-attached sink resamples into from its leg's rate.
    pub(super) rate: u32,
    /// Each sink: `(is_ingress, source_a, channel)`, as [`Engine::begin_wav_recording`] chose them.
    pub(super) taps: Vec<(bool, bool, siphon_rtp_media::bridge::tee::TeeChannel)>,
}

impl AudioRecording {
    /// Whether this recording belongs to `call_id` — how an unnamed `stop_recording` (and a call
    /// teardown) finds every recording it must end.
    fn call_id_matches(&self, call_id: &str) -> bool {
        self.call_id == call_id
    }
}

/// What a call recording's writer task needs to finish the file and report it.
struct RecordingWriter {
    owner: ClientId,
    call_id: String,
    from_tag: String,
    to_tag: Option<String>,
    recording_id: String,
    path: std::path::PathBuf,
    file: tokio::fs::File,
    rate: u32,
    channels: u8,
    encoding: crate::recording::RecordingEncoding,
    limits: crate::recording::RecordingLimits,
    frames: flume::Receiver<Vec<u8>>,
    recycle: flume::Sender<Vec<u8>>,
    source_reason: Arc<std::sync::Mutex<RecordingEndReason>>,
    /// `Some(final path)`: the file is being written at `path` (a `.partial` name) and is renamed
    /// over the final one once closed, **before** the event — so a consumer that watches the
    /// directory instead of the events never sees a half-written file under the real name. An
    /// empty one is removed and reported as [`RecordingEndReason::NoAudio`]. Used by the
    /// `record_call` streams; `start_recording` writes in place, as it always has.
    rename_to: Option<std::path::PathBuf>,
}

/// How a decoded recording stores its audio, as validated from the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DecodedFormat {
    Wav,
    /// `bitrate_bps` absent ⇒ the per-channel default, resolved once the channel count is known.
    OggOpus {
        bitrate_bps: Option<u32>,
    },
}

/// Opus' input rates (RFC 6716 §2). A recording at any other rate is refused, never resampled.
const OPUS_INPUT_RATES: [u32; 5] = [8_000, 12_000, 16_000, 24_000, 48_000];

impl DecodedFormat {
    /// The generated file name's extension: RFC 7845 §9 registers `.opus` for Ogg Opus.
    fn extension(self) -> &'static str {
        match self {
            DecodedFormat::Wav => "wav",
            DecodedFormat::OggOpus { .. } => "opus",
        }
    }

    /// Build the sink's encoding for a recording at `rate` with `channels`. Runs before anything on
    /// the call is touched, so a rate Opus cannot take fails the verb with the call as it was.
    fn encoding(
        self,
        rate: u32,
        channels: u8,
    ) -> Result<crate::recording::RecordingEncoding, String> {
        use crate::recording::RecordingEncoding;
        use siphon_rtp_media::ogg_opus::{OggOpusConfig, OggOpusWriter};
        let DecodedFormat::OggOpus { bitrate_bps } = self else {
            return Ok(RecordingEncoding::Wav);
        };
        if !OPUS_INPUT_RATES.contains(&rate) {
            return Err(format!(
                "an ogg_opus recording needs an Opus input rate (8, 12, 16, 24 or 48 kHz), and \
                 this call decodes at {rate} Hz"
            ));
        }
        let bitrate_bps = bitrate_bps
            .unwrap_or(RECORDING_OPUS_BITRATE_BPS_PER_CHANNEL_DEFAULT * u32::from(channels));
        // RFC 3533 §6: the serial number tells logical streams apart, so it is random rather than
        // a counter that would repeat across engines and restarts.
        let mut serial = [0u8; 4];
        getrandom::fill(&mut serial)
            .map_err(|error| format!("no randomness for the Ogg stream serial: {error}"))?;
        let writer = OggOpusWriter::new(OggOpusConfig {
            sample_rate_hz: rate,
            channels,
            bitrate_bps,
            serial: u32::from_le_bytes(serial),
            vendor: OGG_OPUS_VENDOR,
        })
        .map_err(|error| format!("ogg_opus: {error}"))?;
        Ok(RecordingEncoding::OggOpus(Box::new(writer)))
    }
}

/// Validate a `start_recording`'s format against its `bitrate_bps`: `None` for a pcap recording,
/// the decoded format otherwise.
///
/// A bitrate is meaningful only to `ogg_opus`. Given with any other format it is refused rather
/// than ignored — the controller asked for something it will not get — and outside Opus' own range
/// (RFC 6716 §2.1.1) it is refused rather than clamped, for the same reason.
pub(super) fn decoded_format(
    format: RecordingFormat,
    bitrate_bps: Option<u32>,
) -> Result<Option<DecodedFormat>, String> {
    match (format, bitrate_bps) {
        (RecordingFormat::OggOpus, bitrate_bps) => {
            if let Some(bitrate) = bitrate_bps {
                if !(RECORDING_OPUS_BITRATE_BPS_MIN..=RECORDING_OPUS_BITRATE_BPS_MAX)
                    .contains(&bitrate)
                {
                    return Err(format!(
                        "bitrate_bps {bitrate} is outside \
                         {RECORDING_OPUS_BITRATE_BPS_MIN}..={RECORDING_OPUS_BITRATE_BPS_MAX}"
                    ));
                }
            }
            Ok(Some(DecodedFormat::OggOpus { bitrate_bps }))
        }
        (other, Some(_)) => Err(format!(
            "bitrate_bps applies only to an ogg_opus recording, not {}",
            match other {
                RecordingFormat::Pcap => "pcap",
                RecordingFormat::Wav => "wav",
                RecordingFormat::OggOpus => "ogg_opus",
            }
        )),
        (RecordingFormat::Pcap, None) => Ok(None),
        (RecordingFormat::Wav, None) => Ok(Some(DecodedFormat::Wav)),
    }
}

/// The `OpusTags` vendor string (RFC 7845 §5.2). Deliberately nothing else: the call's identifiers
/// stay out of a file that may travel, and the controller has them from the event anyway.
const OGG_OPUS_VENDOR: &str = concat!("siphon-rtp ", env!("CARGO_PKG_VERSION"));

/// Everything [`Engine::stand_up_recording`] needs, validated and with the file already open.
pub(super) struct StandUp {
    pub(super) recording_id: String,
    pub(super) from_tag: String,
    pub(super) to_tag: Option<String>,
    pub(super) owner: ClientId,
    /// Where the open `file` is.
    pub(super) path: std::path::PathBuf,
    pub(super) file: tokio::fs::File,
    /// See [`RecordingWriter::rename_to`].
    pub(super) rename_to: Option<std::path::PathBuf>,
    pub(super) rate: u32,
    pub(super) ptime: u8,
    pub(super) channels: u8,
    pub(super) encoding: crate::recording::RecordingEncoding,
    pub(super) limits: crate::recording::RecordingLimits,
    /// Each sink: `(is_ingress, source_a, channel, resampler into rate)`. At most two, never two on
    /// one channel.
    pub(super) taps: Vec<(
        bool,
        bool,
        siphon_rtp_media::bridge::tee::TeeChannel,
        Option<siphon_rtp_dsp::resample::Resampler>,
    )>,
}

/// The decoded-recording knobs, grouped so the start path takes one parameter rather than six.
pub(super) struct DecodedRecordingRequest {
    pub(super) format: DecodedFormat,
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
        let path = format!("{directory}/{}.pcap", super::scope::external(call_id));
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
    /// `format: "wav"` or `format: "ogg_opus"`).
    ///
    /// The point of the verb: a voicemail box answers locally, plays a greeting and a beep, and only
    /// *then* records the caller — so recording has to start at a moment the controller picks, capture
    /// decoded audio (the file is emailed, transcribed and played back on handsets), work on a
    /// single-leg call, and tell the controller when the file is complete. None of `record_call`
    /// (offer/answer-time, two legs, buffered in RAM, flushed at teardown) or the pcap recorder (raw
    /// wire bytes) does any of that.
    ///
    /// It attaches the **same** sinks a WebSocket tee does, onto the same post-decode fan-out,
    /// feeding the same shared frame assembler — which already interleaves two legs, hands off over
    /// a bounded channel and recycles its buffers with no per-frame allocation. Its wire frames are
    /// little-endian 16-bit PCM, i.e. exactly a WAV `data` payload, so a WAV writer appends them
    /// verbatim and an Ogg Opus writer encodes them in its own task.
    pub(super) async fn start_wav_recording(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        request: DecodedRecordingRequest,
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
        request: DecodedRecordingRequest,
    ) -> Result<String, String> {
        use siphon_rtp_media::bridge::tee::TeeChannel;
        use siphon_rtp_media::bridge::wire_rate::wire_resampler;

        // A secure call that runs through the media pipeline (`SrtpMedia` / `DtlsMedia`) decodes
        // like any other and records fine — which is the case the pcap recorder has to refuse and
        // this one does not.
        let pipeline = self
            .owned_call_internal(call_id, |call| call.pipeline)
            .ok_or_else(|| "call no longer exists".to_string())?;
        // A takeover call's media never reaches the pipeline — the WS server is the caller's far
        // side — so the recording taps the bridge session instead, which decodes the caller and
        // renders the bot in one task (see `siphon_rtp_media::bridge::taps`).
        let bridge = if self.ws.is_ws_call(call_id) || pipeline == PipelineKind::Ws {
            let bridge = self.bridge_recording_target(call_id).ok_or_else(|| {
                "the call's WebSocket bridge is not running, so there is no audio to record"
                    .to_string()
            })?;
            if bridge.relay_takeover {
                // Giving the leg back restores an in-kernel relay, which has no decoded audio to
                // carry the recording on, so it could only end at the hand-over.
                return Err(
                    "recording-needs-an-anchored-takeover: this bot took over a relayed \
                            two-party call, and handing the leg back would end the recording; \
                            record a call the engine answered (answer_local) or one negotiated \
                            with ws_uri"
                        .to_string(),
                );
            }
            Some(bridge)
        } else {
            None
        };
        // A crypto *bridge* relays without decoding, so it has no post-decode fan-out to tap. It
        // does hold each party's plaintext between its two transforms — where the tee and lawful
        // interception tap too — so the recording decodes a copy of that instead.
        if pipeline.is_crypto_bridge() {
            return self
                .begin_bridged_wav_recording(call_id, from_tag, request)
                .await;
        }

        let (mut near_codec, mut far_codec, mut two_leg, to_tag, owner) = self
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
        if let Some(bridge) = bridge {
            // One party, in the codec the bridge decodes; the bot is what that party hears.
            near_codec = Some(bridge.codec);
            far_codec = None;
            two_leg = false;
        }

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
        // Every conversion is built before anything is touched, so a rate this engine cannot serve
        // fails with the call exactly as it was.
        //
        // At most two sources, one per channel of the frame assembler, and never two on one
        // channel: two writers into one ring are laid end to end, not mixed. The caller's side is
        // what the caller sent. The other side is what the caller was *sent* when egress is asked
        // for — on a two-party call that already is the callee's audio as the caller heard it, plus
        // any prompt played to the caller, so the callee's own ingress is not tapped as well — and
        // the callee's ingress otherwise.
        let mut taps: Vec<(
            bool,
            bool,
            TeeChannel,
            Option<siphon_rtp_dsp::resample::Resampler>,
        )> = Vec::new();
        // What is sent *toward the caller* is `b_to_a`'s egress on a two-party call, but on a
        // single-leg call both directions face the caller and the one whose egress reaches it is
        // `a_to_b` — where `play_media` injects its prompts on such a call too. Tapping `b_to_a`
        // there recorded nothing the caller heard.
        let toward_caller = two_leg;
        for (is_ingress, source_a, channel, leg_rate, wanted) in [
            (true, true, TeeChannel::Caller, caller_rate, want_ingress),
            (
                false,
                toward_caller,
                TeeChannel::Callee,
                caller_rate,
                want_egress,
            ),
            (
                true,
                false,
                TeeChannel::Callee,
                callee_rate,
                want_ingress && !want_egress && two_leg,
            ),
        ] {
            if !wanted {
                continue;
            }
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
        // Two sources are summed into a mono file, or laid out caller-left / other-right when stereo
        // was asked for. One source is mono whatever was asked for. On a single-leg call the right
        // channel is what the caller heard: the engine's prompts, or the bot once one has taken the
        // leg over — it has to be honoured there too, because a recording started before the
        // hand-over cannot change its channel count halfway through the file.
        let two_sources = taps.len() == 2;
        let channels: u8 = if two_sources && matches!(request.channels, RecordingChannels::Stereo) {
            2
        } else {
            1
        };

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
        self.stand_up_recording(
            call_id,
            StandUp {
                recording_id: recording_id.clone(),
                from_tag: from_tag.to_string(),
                to_tag,
                owner,
                path,
                file,
                rename_to: None,
                rate,
                ptime,
                channels,
                encoding,
                limits: request.limits,
                taps,
            },
        )
        .await?;
        Ok(recording_id)
    }

    /// Hold `call_id` in userspace, attach a recording's sinks to its media actor, start the
    /// writer and register the recording. Shared by `start_recording` and the `record_call`
    /// streams, so both stop, report and follow a renegotiation the same way.
    ///
    /// Every input has been validated and the file opened before this runs; a failure here
    /// detaches whatever it attached and releases the hold, leaving the call as it was.
    pub(super) async fn stand_up_recording(
        &self,
        call_id: &str,
        stand_up: StandUp,
    ) -> Result<(), String> {
        use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
        use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};
        let StandUp {
            recording_id,
            from_tag,
            to_tag,
            owner,
            path,
            file,
            rename_to,
            rate,
            ptime,
            channels,
            encoding,
            limits,
            taps,
        } = stand_up;
        let two_sources = taps.len() == 2;
        let callee_only =
            !two_sources && taps.first().is_some_and(|tap| tap.2 == TeeChannel::Callee);
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: rate,
            channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime,
        };

        // Hold the call in userspace for the recording's lifetime. A plain relay is promoted
        // **relay-only**, like a tee: every packet is still forwarded as it arrived, and a copy is
        // decoded for the recording beside the forward, so a frame the recording cannot decode is
        // missing from the file and not from the call. A takeover call is already decoded, by its
        // bridge; the reason is still recorded, so a hand-back to the engine rebuilds an actor that
        // keeps decoding for it.
        if self.bridge_recording_target(call_id).is_some() {
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.promotion_reasons
                    .insert(PromotionReason::AudioRecording);
            }
        } else {
            self.hold_in_userspace(
                call_id,
                PromotionReason::AudioRecording,
                PromoteMode::RelayOnly,
            )
            .await?;
        }

        let plan = plan_ws_tee(format, two_sources, callee_only);
        let mut ingress_legs = Vec::new();
        let mut egress_legs = Vec::new();
        let mut retap_taps = Vec::new();
        for (is_ingress, source_a, channel, resampler) in taps {
            let sink = WsTeeSink::new(channel, plan.mixer.clone(), recording_id.clone(), resampler);
            if !self
                .attach_recording_sink(call_id, is_ingress, source_a, Box::new(sink))
                .await
            {
                self.detach_recording_sinks(call_id, &recording_id, &ingress_legs, &egress_legs)
                    .await;
                self.release_userspace_hold(call_id, PromotionReason::AudioRecording)
                    .await;
                return Err("media actor unavailable".to_string());
            }
            if is_ingress {
                ingress_legs.push(source_a);
            } else {
                egress_legs.push(source_a);
            }
            retap_taps.push((is_ingress, source_a, channel));
        }

        let source_reason = new_source_reason();
        let retap = Retap {
            mixer: Arc::downgrade(&plan.mixer),
            rate,
            taps: retap_taps,
        };
        let writer = self.spawn_recording_writer(RecordingWriter {
            owner,
            call_id: call_id.to_string(),
            from_tag,
            to_tag,
            recording_id: recording_id.clone(),
            path: path.clone(),
            file,
            rate,
            channels,
            encoding,
            limits,
            frames: plan.frames,
            recycle: plan.recycle,
            source_reason: source_reason.clone(),
            rename_to: rename_to.clone(),
        });

        self.recordings.insert(
            recording_id.clone(),
            AudioRecording {
                recording_id,
                call_id: call_id.to_string(),
                owner,
                // The name the consumer is told about: the final one, not the `.partial`.
                path: rename_to.unwrap_or(path),
                ingress_legs,
                egress_legs,
                room: None,
                bridge_taps: Vec::new(),
                source_reason,
                writer,
                retap: Some(retap),
            },
        );
        Ok(())
    }

    /// Hand one recording sink to whatever decodes the call: on the source leg's post-decode
    /// fan-out (`is_ingress`), or on what the engine sends toward a leg. On a takeover call that is
    /// the bridge session — the caller's ingress is its `Caller` tap and what is sent toward the
    /// caller its `Heard` one, which is why a recording's taps mean the same thing on either path.
    /// `false` when neither is there to take it.
    pub(super) async fn attach_recording_sink(
        &self,
        call_id: &str,
        is_ingress: bool,
        source_a: bool,
        sink: Box<dyn siphon_rtp_media::fanout::MediaSink>,
    ) -> bool {
        use siphon_rtp_media::bridge::taps::TapSide;
        use siphon_rtp_media::bridge::ws::BridgeControl;
        if let Some(bridge) = self.bridge_recording_target(call_id) {
            let side = if is_ingress {
                TapSide::Caller
            } else {
                TapSide::Heard
            };
            return bridge
                .control
                .send_async(BridgeControl::AddRecordingTap { side, sink })
                .await
                .is_ok();
        }
        if is_ingress {
            self.media
                .control(call_id, MediaControl::AddFork { source_a, sink })
        } else {
            self.media.control(
                call_id,
                MediaControl::AddEgressFork {
                    toward_a: source_a,
                    sink,
                },
            )
        }
    }

    /// Stand a decoded recording up on a **crypto-bridged** call: one plaintext tap per recorded
    /// party on the bridge, each decoded by a task of its own into the recording's frame assembler.
    ///
    /// The bridge keeps relaying untouched — nothing is re-keyed, the call is not rebuilt and no
    /// media actor is created — so recording a same-codec secure call costs the relay one copy per
    /// packet and nothing else. The taps sit after the source gate, the latch and the SRTP
    /// authentication (docs/security-and-nat.md §10a), so a forged or replayed packet is never
    /// recorded.
    ///
    /// A bridge originates no audio of its own: what reaches one party is exactly what the other
    /// sent. `egress` (what the caller was sent) is therefore the callee's stream, and `both` is each
    /// party once.
    async fn begin_bridged_wav_recording(
        &self,
        call_id: &str,
        from_tag: &str,
        request: DecodedRecordingRequest,
    ) -> Result<String, String> {
        use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
        use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};
        use siphon_rtp_media::bridge::wire_rate::wire_resampler;

        let (near_codec, far_codec, near_endpoint, far_endpoint, to_tag, owner) = self
            .owned_call_internal(call_id, |call| {
                (
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.near.rtp.id,
                    call.far.as_ref().map(|far| far.rtp.id),
                    call.to_tag.clone(),
                    call.owner,
                )
            })
            .ok_or_else(|| "call no longer exists".to_string())?;

        let record_caller = !matches!(request.direction, RecordingDirection::Egress);
        // Every tapped party gets its decoder before anything is touched, so a codec this build
        // cannot decode is a clean refusal on an untouched call.
        let mut parties = Vec::new();
        for (wanted, channel, codec, endpoint) in [
            (
                record_caller,
                TeeChannel::Caller,
                near_codec.as_ref(),
                Some(near_endpoint),
            ),
            (true, TeeChannel::Callee, far_codec.as_ref(), far_endpoint),
        ] {
            if !wanted {
                continue;
            }
            let (Some(codec), Some(endpoint)) = (codec, endpoint) else {
                return Err("a recorded leg has no negotiated codec".to_string());
            };
            let decoder = factory::decoder_for(codec)
                .map_err(|error| format!("no decoder for {}: {error}", codec.encoding_name))?;
            parties.push((channel, endpoint, decoder, codec.payload_type));
        }
        // The recording rate is the first recorded party's decoded PCM rate (the caller's when it is
        // recorded), exactly as on a pipeline call; a party at another rate is resampled into it.
        let rate = parties
            .first()
            .map(|(_, _, decoder, _)| decoder.params().sample_rate_hz)
            .ok_or_else(|| "the call has no leg matching the requested direction".to_string())?;
        let ptime = near_codec
            .as_ref()
            .map_or(20, |codec| codec.ptime_ms.max(1));
        let mut taps = Vec::new();
        for (channel, endpoint, decoder, payload_type) in parties {
            let resampler = wire_resampler(decoder.params().sample_rate_hz, rate)
                .map_err(|error| error.to_string())?;
            taps.push((channel, endpoint, decoder, payload_type, resampler));
        }

        // Two parties are mixed into a mono file or laid out caller-left / callee-right; one party
        // is mono whatever was asked for, rather than a stereo frame whose other half never fills.
        let two_parties = taps.len() == 2;
        let channels: u8 = if two_parties && matches!(request.channels, RecordingChannels::Stereo) {
            2
        } else {
            1
        };
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: rate,
            channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime,
        };
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

        let plan = plan_ws_tee(format, two_parties, !record_caller);
        let mut bridge_taps = Vec::new();
        for (channel, endpoint, decoder, payload_type, resampler) in taps {
            let sink = WsTeeSink::new(channel, plan.mixer.clone(), recording_id.clone(), resampler);
            let (packets, received) = flume::bounded(BRIDGE_TAP_QUEUE);
            if !self.bridge.add_plain_tap(endpoint, &recording_id, packets) {
                self.remove_bridge_taps(&recording_id, bridge_taps).await;
                return Err("the call's crypto bridge is no longer installed".to_string());
            }
            let task = tokio::spawn(run_bridge_tap_decoder(
                received,
                decoder,
                payload_type,
                sink,
            ));
            bridge_taps.push((endpoint, task));
        }

        let source_reason = new_source_reason();
        let writer = self.spawn_recording_writer(RecordingWriter {
            owner,
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            to_tag,
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
        self.recordings.insert(
            recording_id.clone(),
            AudioRecording {
                recording_id: recording_id.clone(),
                call_id: call_id.to_string(),
                owner,
                path,
                ingress_legs: Vec::new(),
                egress_legs: Vec::new(),
                retap: None,
                room: None,
                bridge_taps,
                source_reason,
                writer,
            },
        );
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            recording_id,
            channels,
            sample_rate = rate,
            "decoded recording started on a crypto bridge"
        );
        Ok(recording_id)
    }

    /// Take a recording's taps off the bridge and wait for their decoders, which end once the tap
    /// that fed them is gone.
    async fn remove_bridge_taps(
        &self,
        recording_id: &str,
        bridge_taps: Vec<(EndpointId, tokio::task::JoinHandle<()>)>,
    ) {
        for (endpoint, task) in bridge_taps {
            self.bridge.remove_plain_tap(endpoint, recording_id);
            let _ = task.await;
        }
    }

    /// The next recording id — also the tag on everything the recording attaches.
    fn next_recording_id(&self) -> String {
        format!(
            "rec-{}",
            self.next_recording_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    /// Spawn the task that streams a call recording to disk and reports it finished.
    fn spawn_recording_writer(&self, writer: RecordingWriter) -> tokio::task::JoinHandle<()> {
        let events = self.event_sink(writer.owner);
        tokio::spawn(async move {
            let outcome = crate::recording::run_recorder(
                crate::recording::RecordingOutput {
                    file: writer.file,
                    path: writer.path.clone(),
                    sample_rate: writer.rate,
                    channels: u16::from(writer.channels),
                    encoding: writer.encoding,
                },
                writer.limits,
                writer.frames,
                writer.recycle,
            )
            .await;
            let source_reason = writer
                .source_reason
                .lock()
                .map(|reason| *reason)
                .unwrap_or(RecordingEndReason::CallEnded);
            let mut reason = outcome.end.into_reason(source_reason);
            let mut path = Some(writer.path.clone());
            if let Some(final_path) = writer.rename_to {
                (path, reason) =
                    settle_partial(&writer.path, final_path, outcome.duration_ms, reason).await;
            }
            // Emitted only now — after the file has been closed, synced and (for a `record_call`
            // stream) renamed — so a consumer that acts on this event never opens a half-written
            // file. That is the whole reason the event exists.
            if let Some(events) = events {
                let _ = events.try_send(Event::RecordingFinished {
                    conference_id: None,
                    call_id: writer.call_id,
                    from_tag: writer.from_tag,
                    to_tag: writer.to_tag,
                    recording_id: writer.recording_id,
                    path: path.map(|path| path.to_string_lossy().into_owned()),
                    duration_ms: outcome.duration_ms,
                    reason,
                });
            }
        })
    }

    /// Detach every sink a recording attached, without touching anything else on the same legs —
    /// from the call's bridge when a bot has the leg, from its media actor otherwise. Returns once a
    /// bridge has let go of them, so the writer's input is known to be closing.
    pub(super) async fn detach_recording_sinks(
        &self,
        call_id: &str,
        recording_id: &str,
        ingress_legs: &[bool],
        egress_legs: &[bool],
    ) {
        use siphon_rtp_media::bridge::ws::BridgeControl;
        if let Some(bridge) = self.bridge_recording_target(call_id) {
            let (done, removed) = tokio::sync::oneshot::channel();
            let sent = bridge
                .control
                .send_async(BridgeControl::RemoveRecordingTaps {
                    tag: recording_id.to_string(),
                    done,
                })
                .await;
            if sent.is_ok() {
                // A bridge that ends first drops `done`, and its sinks with it: either way they
                // are gone.
                let _ = removed.await;
            }
            return;
        }
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
    /// leave a valid-but-empty WAV, or an Ogg file without its last second and end-of-stream page —
    /// and awaiting it is what makes the event ordering a guarantee
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
                // A bridged call's recording: the taps come off the bridge, which ends each
                // decoder's feed. No hold was taken, so none is released below.
                let bridged = !recording.bridge_taps.is_empty();
                self.remove_bridge_taps(&recording.recording_id, recording.bridge_taps)
                    .await;
                self.detach_recording_sinks(
                    &recording.call_id,
                    &recording.recording_id,
                    &recording.ingress_legs,
                    &recording.egress_legs,
                )
                .await;
                let _ = recording.writer.await;
                // The hold is one reason per call, not per recording. Released while another
                // recording still taps the call, a promoted relay would be demoted under it and that
                // recording would end with the actor — the `record_call` streams are two recordings
                // on one call by construction.
                let another_still_taps = self.recordings.iter().any(|entry| {
                    let other = entry.value();
                    other.call_id_matches(&recording.call_id)
                        && other.room.is_none()
                        && other.bridge_taps.is_empty()
                });
                if !bridged && !another_still_taps {
                    self.release_userspace_hold(
                        &recording.call_id,
                        PromotionReason::AudioRecording,
                    )
                    .await;
                }
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

/// Put a finished `.partial` file where it belongs, returning what the event reports.
///
/// A file that holds no audio is removed rather than kept as a bare header, and reported as
/// [`RecordingEndReason::NoAudio`] with no path: there is nothing to index, and saying so is the
/// only way a consumer waiting on every party's file can stop waiting for this one. A writer that
/// already failed keeps its reason; a rename that fails reports `Error` and names the partial file,
/// which still holds whatever was written.
async fn settle_partial(
    partial: &std::path::Path,
    final_path: std::path::PathBuf,
    duration_ms: u64,
    reason: RecordingEndReason,
) -> (Option<std::path::PathBuf>, RecordingEndReason) {
    if duration_ms == 0 && reason != RecordingEndReason::Error {
        if let Err(error) = tokio::fs::remove_file(partial).await {
            tracing::warn!(
                target: "siphon_rtp::media",
                path = %partial.display(),
                %error,
                "could not remove an empty recording"
            );
        }
        return (None, RecordingEndReason::NoAudio);
    }
    match tokio::fs::rename(partial, &final_path).await {
        Ok(()) => (Some(final_path), reason),
        Err(error) => {
            tracing::warn!(
                target: "siphon_rtp::media",
                from = %partial.display(),
                to = %final_path.display(),
                %error,
                "could not move a finished recording into place"
            );
            (Some(partial.to_path_buf()), RecordingEndReason::Error)
        }
    }
}

/// Why a recording ended when nothing said otherwise. `CallEnded` is the truthful default: the
/// sources went away and nobody asked them to.
fn new_source_reason() -> Arc<std::sync::Mutex<RecordingEndReason>> {
    Arc::new(std::sync::Mutex::new(RecordingEndReason::CallEnded))
}

/// Resolve and open a call recording's output file: `path` exactly, or a generated name under
/// `recording_dir` ending in `extension`.
///
/// Opened up front, exactly as the pcap path does: a bad path must fail the verb with the call
/// untouched — nothing promoted, no sink attached — rather than being reported minutes later as a
/// `RecordingFinished{Error}` for a recording the controller believes is running.
async fn open_recording_output(
    call_id: &str,
    recording_id: &str,
    extension: &str,
    path: Option<String>,
    recording_dir: Option<String>,
) -> Result<(std::path::PathBuf, tokio::fs::File), String> {
    let path = match path {
        Some(path) => std::path::PathBuf::from(path),
        None => {
            let directory = recording_dir
                .ok_or_else(|| "no output location (set `path`, or `recording_dir`)".to_string())?;
            let stem = super::scope::external(call_id);
            std::path::PathBuf::from(directory).join(format!("{stem}-{recording_id}.{extension}"))
        }
    };
    let file = tokio::fs::File::create(&path)
        .await
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    Ok((path, file))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bitrate_is_accepted_only_with_ogg_opus_and_only_in_range() {
        assert_eq!(decoded_format(RecordingFormat::Pcap, None), Ok(None));
        assert_eq!(
            decoded_format(RecordingFormat::Wav, None),
            Ok(Some(DecodedFormat::Wav))
        );
        assert_eq!(
            decoded_format(RecordingFormat::OggOpus, None),
            Ok(Some(DecodedFormat::OggOpus { bitrate_bps: None }))
        );
        for bitrate in [
            RECORDING_OPUS_BITRATE_BPS_MIN,
            RECORDING_OPUS_BITRATE_BPS_MAX,
        ] {
            assert_eq!(
                decoded_format(RecordingFormat::OggOpus, Some(bitrate)),
                Ok(Some(DecodedFormat::OggOpus {
                    bitrate_bps: Some(bitrate)
                }))
            );
        }
        for bitrate in [
            0,
            RECORDING_OPUS_BITRATE_BPS_MIN - 1,
            RECORDING_OPUS_BITRATE_BPS_MAX + 1,
            u32::MAX,
        ] {
            let refused = decoded_format(RecordingFormat::OggOpus, Some(bitrate))
                .expect_err("out of range is refused, not clamped");
            assert_eq!(
                refused,
                format!("bitrate_bps {bitrate} is outside 6000..=510000")
            );
        }
        assert_eq!(
            decoded_format(RecordingFormat::Wav, Some(16_000)),
            Err("bitrate_bps applies only to an ogg_opus recording, not wav".to_string())
        );
        assert_eq!(
            decoded_format(RecordingFormat::Pcap, Some(16_000)),
            Err("bitrate_bps applies only to an ogg_opus recording, not pcap".to_string())
        );
    }

    #[test]
    fn a_generated_name_carries_the_format_extension() {
        assert_eq!(DecodedFormat::Wav.extension(), "wav");
        assert_eq!(
            DecodedFormat::OggOpus { bitrate_bps: None }.extension(),
            "opus"
        );
    }

    #[test]
    fn the_encoding_is_built_before_the_call_is_touched_and_refuses_non_opus_rates() {
        assert!(matches!(
            DecodedFormat::Wav.encoding(11_025, 1),
            Ok(crate::recording::RecordingEncoding::Wav)
        ));
        for rate in OPUS_INPUT_RATES {
            assert!(
                matches!(
                    DecodedFormat::OggOpus { bitrate_bps: None }.encoding(rate, 2),
                    Ok(crate::recording::RecordingEncoding::OggOpus(_))
                ),
                "{rate} Hz"
            );
        }
        for rate in [11_025, 22_050, 32_000, 44_100] {
            let refused = DecodedFormat::OggOpus { bitrate_bps: None }
                .encoding(rate, 1)
                .expect_err("not an Opus input rate");
            assert!(
                refused.contains(&format!("decodes at {rate} Hz")),
                "{refused}"
            );
        }
    }

    #[test]
    fn the_vendor_string_names_the_engine_and_nothing_about_the_call() {
        assert_eq!(
            OGG_OPUS_VENDOR,
            concat!("siphon-rtp ", env!("CARGO_PKG_VERSION"))
        );
    }
}
