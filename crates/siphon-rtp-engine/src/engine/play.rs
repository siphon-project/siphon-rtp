//! Prompt playback toward a leg: WAV files, cached and fetched prompts, and tones.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_media::playback::Gain;
use siphon_rtp_media::player::{PcmPlayer, PcmRepeat, WavError, WavSource};
use siphon_rtp_media::tone::ToneSpec;
use siphon_rtp_proto::{CmdResult, Event, PlayEndReason, PlayMediaSource, PlayRepeat};
use std::sync::Arc;

use crate::media_fetch::{self, MediaFetchLimits};
use crate::media_pipeline::{MediaControl, MediaRegistry, PlayRequest};

use super::inject::resolve_toward_a;
use super::{error_result, ok_empty, unknown_call, ClientId, Engine, PromoteMode, PromotionReason};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Draw the next monotonic `play_media` playback id.
    pub(super) fn next_play_id(&self) -> u64 {
        self.play_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Shared `play_media` setup: validate ownership, promote an offer-only single-leg IVR call (or a
    /// plain relay) to a **processing** MediaCall so it owns an egress codec, read + parse the WAV,
    /// build the player, resolve the target direction, and start the injection. On success returns
    /// `(duration_ms, play_id)` — the prompt's total playout duration and the playback id the actor
    /// carries on the eventual [`Event::PlayFinished`]; on failure a `CmdResult::Error`.
    ///
    /// Promotion mirrors `set_echo`: an already-transcoding call is used as-is; an offer-only
    /// single-leg call is promoted via [`Self::promote_to_processing`] (the `a47c657` self-echo build)
    /// and held with [`PromotionReason::MediaOp`] for the dialog. That build puts both directions on
    /// the one caller-facing endpoint, and [`MediaCall::process`] always runs the `a_to_b` branch for
    /// that shared endpoint, so the prompt must inject on `a_to_b` (`toward_a = false`) for its
    /// injection to suppress the self-echo and reach the caller — hence the `call_to.is_none()`
    /// override of `resolve_toward_a` (which otherwise returns `true` for an unanswered call).
    async fn start_play(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        source: PlayMediaSource,
        options: PlayOptions,
        to_tag: Option<&str>,
    ) -> Result<(Option<u64>, u64), Box<CmdResult>> {
        let Some(call_to) = self.owned_call(client, call_id, |call| call.to_tag.clone()) else {
            return Err(Box::new(unknown_call(call_id)));
        };
        // Promote an offer-only single-leg IVR call (or a plain relay) to a processing MediaCall so a
        // prompt can play with no B leg — the same promote `set_echo` uses. Idempotent on an
        // already-transcoding call. Rejected only when a relay is held for recording / a DTMF block
        // (a relay-only actor cannot synthesize decoded audio — same guard as echo).
        if !self.media.is_transcoding_call(call_id) {
            if let Err(reason) = self
                .hold_in_userspace(call_id, PromotionReason::MediaOp, PromoteMode::Processing)
                .await
            {
                return Err(Box::new(error_result("play_media: promote call", &reason)));
            }
        }
        // `repeat_times` is the total play count; 0/None plays once (PcmRepeat treats 0/1 alike), and
        // `"inf"` plays until stopped — what music on hold, queue music and park music need.
        let repeat = match options.repeat_times {
            None => PcmRepeat::Times(0),
            Some(PlayRepeat::Forever) => PcmRepeat::Forever,
            Some(PlayRepeat::Times(times)) => {
                PcmRepeat::Times(times.min(u64::from(u32::MAX)) as u32)
            }
        };
        let start = options.start_pos_ms.unwrap_or(0).min(u64::from(u32::MAX)) as u32;
        // Resolve the source into something the media actor can play. A recorded prompt is decoded
        // here (the source rate is a property of the file, not of the leg); a tone is only *parsed*
        // here — it is synthesised at the leg's egress rate inside the actor, which is the only place
        // that knows it, so a tone is never resampled.
        let resolved = match source {
            // An inline blob is the controller's own bytes, different on every request by
            // construction, so there is nothing to cache: decode it here.
            PlayMediaSource::Blob { data } => parse_prompt_wav(&data)
                .map_err(|error| error_result("play_media: parse WAV", &error))?,
            // A host file is the case worth caching — a queue with thirty waiting callers plays the
            // same hold music thirty times. Keyed by path + mtime + length, so re-recording a prompt
            // takes effect on the next play with no cache-clearing step.
            PlayMediaSource::File { path } => {
                match self.prompts.get_or_load(std::path::Path::new(&path)).await {
                    Ok(prompt) => ResolvedPlaySource::Pcm(prompt),
                    Err(error) => {
                        return Err(Box::new(error_result("play_media", &error)));
                    }
                }
            }
            PlayMediaSource::Tone { tone } => match ToneSpec::resolve(&tone) {
                Ok(spec) => ResolvedPlaySource::Tone(spec),
                Err(error) => return Err(Box::new(error_result("play_media: tone", &error))),
            },
            PlayMediaSource::Http { url } => {
                // A URL playback cannot be resolved synchronously without blocking the control
                // connection for the whole fetch deadline, so it accepts now and fetches on its own
                // task. What *is* checked synchronously is everything that needs no network — the
                // scheme, the host and the allow-list — so an unusable URL is a plain control error
                // rather than an accepted playback that fails a moment later.
                if let Err(error) = media_fetch::validate_media_url(&url, &self.media_fetch_limits)
                {
                    return Err(Box::new(error_result("play_media: url", &error)));
                }
                let toward_a = if call_to.is_none() {
                    false
                } else {
                    resolve_toward_a(from_tag, call_to.as_deref(), to_tag)
                };
                let play_id = self.next_play_id();
                self.spawn_media_fetch(MediaFetchRequest {
                    client,
                    call_id: call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    to_tag: to_tag.map(str::to_string),
                    url,
                    toward_a,
                    options,
                    repeat,
                    start_pos_ms: start,
                    play_id,
                });
                // The length is not known until the body has arrived, so the accept reports none.
                return Ok((None, play_id));
            }
            PlayMediaSource::DbId { .. } => {
                return Err(Box::new(error_result(
                    "play_media",
                    &"db-id media source is not supported",
                )))
            }
            // [`PlayMediaSource`] is `#[non_exhaustive]`, so a source added to the contract after
            // this resolver was written lands here. Refuse it exactly as `db_id` is refused —
            // accepting the play would hand the controller a `play_id` and then never emit the
            // `play_finished` it waits on, which is the failure mode this release just removed
            // elsewhere. The error is logged at `warn` by the dispatch wrapper.
            _ => {
                return Err(Box::new(error_result(
                    "play_media",
                    &"media source is not supported by this engine",
                )))
            }
        };
        let (request, source_duration_ms) = match resolved {
            ResolvedPlaySource::Pcm(prompt) => {
                let player =
                    PcmPlayer::from_shared(prompt.mono, prompt.sample_rate_hz, repeat, start);
                let duration = player.duration_ms();
                (PlayRequest::Pcm(Box::new(player)), duration)
            }
            ResolvedPlaySource::Tone(spec) => {
                let duration = spec.total_duration_ms();
                (PlayRequest::Tone(spec), duration)
            }
        };
        // The accepted duration is the source's own length bounded by the `duration_ms` cap; a cap
        // on an endless source *is* the duration, and an uncapped endless one — a `*inf` tone or a
        // `"repeat_times": "inf"` prompt — reports none.
        let duration_ms = match (source_duration_ms, options.duration_ms) {
            (Some(source), Some(cap)) => Some(source.min(cap)),
            (Some(source), None) => Some(source),
            (None, cap) => cap,
        };
        // Offer-only single-leg call: both directions face the caller on one endpoint and `process`
        // always runs the `a_to_b` branch, so inject on `a_to_b` (toward_a = false) — see the doc
        // comment. A normal 2-leg call resolves the target leg from `from_tag` as usual.
        let toward_a = if call_to.is_none() {
            false
        } else {
            resolve_toward_a(from_tag, call_to.as_deref(), to_tag)
        };
        let play_id = self.next_play_id();
        let gain = Gain::from_decibels(options.gain_decibels.unwrap_or(0));
        // An overlay start can be rejected (all four slots busy), and that rejection has to reach the
        // controller — so it waits for the actor's answer. A superseding start cannot be rejected on
        // capacity grounds, so it stays fire-and-forget exactly as it always was.
        let mut receiver = None;
        let sender = if options.overlay {
            let (sender, reply) = tokio::sync::oneshot::channel();
            receiver = Some(reply);
            Some(sender)
        } else {
            None
        };
        // A call with no media actor — a crypto bridge (`Srtp` / `Dtls`) or a WebSocket takeover — is
        // never promoted by the guard above, so the control message lands nowhere. Report that instead
        // of returning an accepted `play_id` for a prompt no one will ever hear and a `PlayFinished`
        // that will never arrive; the same honesty `play_dtmf` and `silence_media` already keep.
        if !self.media.control(
            call_id,
            MediaControl::PlayAudio {
                toward_a,
                request: Box::new(request),
                overlay: options.overlay,
                gain,
                duration_cap_ms: options.duration_ms,
                play_id,
                reply: sender,
            },
        ) {
            return Err(Box::new(error_result(
                "play_media",
                &"call is not a media-processing call (a secure bridge or a WebSocket takeover \
                   has no pipeline to inject into)",
            )));
        }
        if let Some(receiver) = receiver {
            match receiver.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(Box::new(error_result("play_media: overlay", &error)))
                }
                Err(_) => {
                    return Err(Box::new(error_result(
                        "play_media",
                        &"media actor closed before the overlay started",
                    )))
                }
            }
        }
        Ok((duration_ms, play_id))
    }

    /// Fetch a URL playback's WAV on its own task, then start it on the media actor.
    ///
    /// Off the media path by construction: the media tick never waits on this, and neither does the
    /// control connection — `play_media` has already accepted by the time this runs. The fetch is
    /// bounded by [`Self::media_fetch_limits`], so the task always terminates. Every failure —
    /// timeout, bad status, oversized body, non-WAV bytes, an actor that has gone away — resolves
    /// the playback with `PlayFinished{Error}` under the accepted `play_id`, so a controller
    /// awaiting it is never left hanging.
    fn spawn_media_fetch(&self, request: MediaFetchRequest) {
        let media = self.media.clone();
        let limits = self.media_fetch_limits.clone();
        let tls = self.ws_tls_client_config();
        let events = self.event_sink(request.client);
        let pending = PendingFetch {
            call_id: request.call_id.clone(),
            from_tag: request.from_tag.clone(),
            to_tag: request.to_tag.clone(),
            client: request.client,
            // Filled in by `with_abort` once the task exists.
            abort: None,
        };
        let play_id = request.play_id;
        let failure_event = pending.play_finished(play_id, PlayEndReason::Error);
        let pending_key = self.pending_fetches.clone();

        let task = tokio::spawn(async move {
            let outcome = fetch_and_start(&media, &limits, tls, &request).await;
            // The entry is consumed either way: a completed fetch is no longer cancellable, and a
            // failed one has just reported. Removing it here is what keeps the map bounded.
            pending_key.remove(&play_id);
            if let Err(reason) = outcome {
                tracing::warn!(
                    target: "siphon_rtp::control",
                    call_id = %request.call_id,
                    play_id,
                    %reason,
                    "play_media url fetch failed — the playback ends as PlayFinished error"
                );
                if let Some(sender) = events {
                    if sender.try_send(failure_event).is_err() {
                        tracing::debug!(
                            target: "siphon_rtp::control",
                            play_id,
                            "PlayFinished dropped (control queue full or closed)"
                        );
                    }
                }
            }
        });
        self.pending_fetches
            .insert(play_id, pending.with_abort(task.abort_handle()));
    }

    /// Cancel a still-running URL fetch for `play_id`, reporting it as `reason`. Returns whether a
    /// pending fetch was cancelled.
    fn cancel_pending_fetch(&self, play_id: u64, reason: PlayEndReason) -> bool {
        let Some((_, pending)) = self.pending_fetches.remove(&play_id) else {
            return false;
        };
        if let Some(abort) = &pending.abort {
            abort.abort();
        }
        self.push_event(pending.client, pending.play_finished(play_id, reason));
        true
    }

    /// Cancel every still-running URL fetch on a call, reporting each as `reason`. Returns how many
    /// were cancelled. Called by a call-wide `stop_media` and by call teardown, so a fetch can never
    /// outlive the call it was started for and start playing into a torn-down actor.
    pub(super) fn cancel_pending_fetches_for_call(
        &self,
        call_id: &str,
        reason: PlayEndReason,
    ) -> usize {
        let ids: Vec<u64> = self
            .pending_fetches
            .iter()
            .filter(|entry| entry.value().call_id == call_id)
            .map(|entry| *entry.key())
            .collect();
        ids.into_iter()
            .filter(|play_id| self.cancel_pending_fetch(*play_id, reason))
            .count()
    }

    /// Inject a prompt / announcement / tone toward a leg ([`Command::PlayMedia`]). Answers
    /// immediately (accept-on-start) with the playback's `play_id` and total `duration_ms`; the
    /// playback's end is reported asynchronously as an [`Event::PlayFinished`] carrying the same
    /// `play_id`. A controller that wants to sequence a following action awaits that event's
    /// `Completed` reason. The NG front-end takes this same entry and never consumes the event
    /// (fire-and-forget).
    ///
    /// `duration_ms` is absent from the accept only when the source is endless and no cap was given
    /// (an `*inf` tone) — there is no finite length to report.
    pub(super) async fn play_media(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        source: PlayMediaSource,
        options: PlayOptions,
        to_tag: Option<&str>,
    ) -> CmdResult {
        match self
            .start_play(client, call_id, from_tag, source, options, to_tag)
            .await
        {
            Ok((duration_ms, play_id)) => CmdResult::Ok {
                sdp: None,
                duration_ms,
                play_id: Some(play_id),
                recording_id: None,
                to_tag: None,
                stats: None,
            },
            Err(error) => *error,
        }
    }

    /// Stop playback on a call ([`Command::StopMedia`]).
    ///
    /// With no `play_id` this stops everything — the superseding prompt, any DTMF burst and every
    /// overlay — which is the original behaviour. With one, it stops only that playback and leaves
    /// the rest running, and an id no playback holds is an error rather than a hollow success.
    pub(super) async fn stop_media(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        play_id: Option<u64>,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        let Some(play_id) = play_id else {
            // A URL playback whose fetch is still in flight has no actor state to stop, so cancel it
            // here — otherwise it would start playing seconds after the controller stopped the call.
            let cancelled =
                self.cancel_pending_fetches_for_call(call_id, PlayEndReason::Stopped) > 0;
            return if self.media.control(call_id, MediaControl::StopPlay) || cancelled {
                ok_empty()
            } else {
                error_result("stop_media", &"call has no active media playback")
            };
        };
        // Same window, targeted: the id may name a fetch that has not produced audio yet.
        if self.cancel_pending_fetch(play_id, PlayEndReason::Stopped) {
            return ok_empty();
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if !self.media.control(
            call_id,
            MediaControl::StopPlayId {
                play_id,
                reply: sender,
            },
        ) {
            return error_result("stop_media", &"call has no active media playback");
        }
        match receiver.await {
            Ok(true) => ok_empty(),
            Ok(false) => error_result(
                "stop_media",
                &format!("no playback {play_id} is running on this call"),
            ),
            Err(_) => error_result(
                "stop_media",
                &"media actor closed before the stop was applied",
            ),
        }
    }

    /// Retune a running playback's playout gain ([`Command::SetPlayGain`]) — how a controller ducks
    /// an overlay bed under a prompt and lifts it again. Addressed by the `play_id` the playback's
    /// accept returned; an id no playback holds is an error, never a hollow success.
    pub(super) async fn set_play_gain(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        play_id: u64,
        gain_decibels: i32,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if !self.media.control(
            call_id,
            MediaControl::SetPlayGain {
                play_id,
                gain: Gain::from_decibels(gain_decibels),
                reply: sender,
            },
        ) {
            return error_result("set_play_gain", &"call has no active media playback");
        }
        match receiver.await {
            Ok(true) => ok_empty(),
            Ok(false) => error_result(
                "set_play_gain",
                &format!("no playback {play_id} is running on this call"),
            ),
            Err(_) => error_result(
                "set_play_gain",
                &"media actor closed before the gain was applied",
            ),
        }
    }
}

/// The optional knobs on [`Command::PlayMedia`], grouped so the play path carries one parameter
/// rather than six positional ones (and so a new knob is an added field, not another argument to
/// thread through three call sites).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct PlayOptions {
    /// How many times to play a recorded prompt: a total play count (`0`/`None` plays it once), or
    /// [`PlayRepeat::Forever`] to play until stopped.
    pub(super) repeat_times: Option<PlayRepeat>,
    /// Seek into a recorded prompt before the first frame (and the point each loop rewinds to).
    pub(super) start_pos_ms: Option<u64>,
    /// Hard playout cap. The only bound on an endless source short of a stop — a `*inf` tone or a
    /// `PlayRepeat::Forever` prompt.
    pub(super) duration_ms: Option<u64>,
    /// Mix under the party's live egress instead of replacing it.
    pub(super) overlay: bool,
    /// Playout gain in whole decibels; `None` ⇒ 0 dB (the source's own level).
    pub(super) gain_decibels: Option<i32>,
}

/// A `play_media` source after it has been fetched/read and validated, but before the media actor
/// has turned it into a playback on the leg's egress clock.
pub(super) enum ResolvedPlaySource {
    /// Decoded, downmixed mono samples plus their native rate — from the prompt cache for a host
    /// file, or decoded on the spot for an inline blob or a fetched body. Shared rather than owned,
    /// so a hold bed playing to thirty callers is one buffer and thirty cursors.
    Pcm(crate::prompt_cache::CachedPrompt),
    /// A parsed tone cadence, synthesised later at the leg's own rate.
    Tone(ToneSpec),
}

/// Everything the background fetch task needs to start a URL playback once the bytes arrive.
struct MediaFetchRequest {
    client: ClientId,
    call_id: String,
    from_tag: String,
    to_tag: Option<String>,
    url: String,
    toward_a: bool,
    options: PlayOptions,
    /// How many times to play the fetched prompt (`0`/`1` play it once, `Forever` until stopped).
    repeat: PcmRepeat,
    /// Seek into the fetched prompt before the first frame.
    start_pos_ms: u32,
    play_id: u64,
}

/// A URL playback whose fetch has not finished. Holds what a cancellation needs: the call it
/// belongs to, the identifiers its `PlayFinished` is keyed by, and the task to abort.
pub(super) struct PendingFetch {
    call_id: String,
    from_tag: String,
    to_tag: Option<String>,
    client: ClientId,
    abort: Option<tokio::task::AbortHandle>,
}

impl PendingFetch {
    /// Attach the spawned task's abort handle (built before the task exists, so it is set after).
    fn with_abort(mut self, abort: tokio::task::AbortHandle) -> Self {
        self.abort = Some(abort);
        self
    }

    /// The completion event for this playback, keyed the same way the media actor keys its own.
    fn play_finished(&self, play_id: u64, reason: PlayEndReason) -> Event {
        Event::PlayFinished {
            conference_id: None,
            call_id: self.call_id.clone(),
            from_tag: self.from_tag.clone(),
            to_tag: self.to_tag.clone(),
            play_id,
            reason,
            // A fetch that never produced audio played nothing — say so rather than omit it.
            played_ms: Some(0),
        }
    }
}

/// Fetch a URL playback's WAV and hand it to the media actor.
///
/// Every step is bounded by `limits`, so this future always resolves; the error string it returns
/// on failure is what the control plane logs and what the playback's `PlayFinished{Error}` stands
/// for. Runs on its own task — never on the media path, never on a control connection.
async fn fetch_and_start(
    media: &Arc<MediaRegistry>,
    limits: &MediaFetchLimits,
    tls: Arc<rustls::ClientConfig>,
    request: &MediaFetchRequest,
) -> Result<(), String> {
    let bytes = media_fetch::fetch_media(&request.url, limits, tls)
        .await
        .map_err(|error| error.to_string())?;
    // The fetched bytes are as untrusted as anything else off the network: validated through the
    // same pure-Rust RIFF/WAVE reader every other source uses, which errors rather than panics.
    let wav = WavSource::parse(&bytes).map_err(|error| format!("parse WAV: {error}"))?;
    // Not cached: a fetched body is keyed by a URL whose freshness this engine does not own, and
    // caching it would serve a stale prompt after the origin changed with no way to notice.
    let player = PcmPlayer::from_shared(
        wav.to_mono(),
        wav.sample_rate_hz(),
        request.repeat,
        request.start_pos_ms,
    );
    let gain = Gain::from_decibels(request.options.gain_decibels.unwrap_or(0));

    let (sender, receiver) = tokio::sync::oneshot::channel();
    if !media.control(
        &request.call_id,
        MediaControl::PlayAudio {
            toward_a: request.toward_a,
            request: Box::new(PlayRequest::Pcm(Box::new(player))),
            overlay: request.options.overlay,
            gain,
            duration_cap_ms: request.options.duration_ms,
            play_id: request.play_id,
            // The fetch always waits for the actor's verdict — unlike a synchronous start, there is
            // no control response left to carry a rejection, so the only way an over-cap overlay can
            // be reported at all is through this reply turning into a `PlayFinished{Error}`.
            reply: Some(sender),
        },
    ) {
        return Err("call has no media-processing actor".to_string());
    }
    match receiver.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("media actor closed before the playback started".to_string()),
    }
}

/// Parse a WAV buffer for playback. Every source that yields bytes — inline blob, host file,
/// fetched body — validates through this one point, so a malformed buffer is a typed error rather
/// than something each source handles its own way.
pub(super) fn parse_prompt_wav(bytes: &[u8]) -> Result<ResolvedPlaySource, WavError> {
    WavSource::parse(bytes).map(|source| {
        ResolvedPlaySource::Pcm(crate::prompt_cache::CachedPrompt {
            mono: source.to_mono(),
            sample_rate_hz: source.sample_rate_hz(),
        })
    })
}
