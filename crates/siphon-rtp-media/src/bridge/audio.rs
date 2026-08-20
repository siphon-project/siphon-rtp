//! The bridge session's **PCM audio core**: everything a WS bridge does to audio once the RTP layer
//! is out of the way — uplink cleaning (noise suppression, echo cancellation), local-VAD turn
//! taking / barge-in, the bounded downlink playout queue, and the WS control protocol.
//!
//! [`BridgeCore`]'s audio boundary is **linear PCM**, not RTP:
//!
//! - uplink (call → server): [`BridgeCore::on_pcm_uplink`] stages one decoded frame, and
//!   [`BridgeCore::tick`] cleans it and frames it as little-endian L16 for the socket;
//! - downlink (server → call): [`BridgeCore::on_ws_binary`] enqueues L16 playout, and each
//!   [`BridgeCore::tick`] dequeues at most one frame, handed back by
//!   [`BridgeCore::take_downlink_pcm`] for the caller to render.
//!
//! Who *produces* the uplink PCM is the caller's business. In **takeover** mode
//! ([`super::session::BridgeSession`]) a [`crate::leg::MediaLeg`] decodes leg A's RTP in front of the
//! core; on a **teed** call the media pipeline has already decoded the frame and hands it straight in
//! — no second jitter buffer, no second PLC state, no second concealment decision on the same stream.
//! That separation is the whole point of the split: decoding a stream twice makes the WS consumer
//! hear artefacts the call itself never had.
//!
//! # Which rate domain the core runs in
//!
//! **The core runs entirely in the negotiated WS *wire* rate** — [`BridgeCore::format`]'s
//! `sample_rate` — not the leg's codec rate. Those were the same thing until the wire rate became
//! selectable ([`super::wire_rate`]); now the RTP shell converts on the way in and on the way back
//! out ([`super::session::BridgeSession::with_rate_conversion`]) and everything inside this module —
//! the staged uplink, the L16 the transport writes, the playout queue, the noise suppressor and both
//! sides of the echo canceller — is wire-domain.
//!
//! That choice is not arbitrary. The wire rate is **the domain the far side actually hears**, so
//! cleaning the audio there is cleaning what the server receives rather than an intermediate the
//! conversion will then re-filter; 16 kHz, the common reason to raise the rate above a G.711 leg, is
//! also a rate the suppressor and canceller are validated at. Above all it is the only placement that
//! keeps the echo canceller coherent: its **near-end** input is the staged uplink and its **far-end
//! reference** is the downlink frame this same tick renders, and those two must be in one domain and
//! one frame length or the canceller is subtracting a signal that is not the echo. Putting the
//! conversion inside the core would split them — uplink at the leg rate, downlink from the server at
//! the wire rate — and the canceller would silently degrade to noise injection.
//!
//! The suppressor and canceller only exist at 8 or 16 kHz. A wire rate outside those leaves both
//! **off** (logged once at `warn`) and the wire rate **unchanged** — degrading the feature, never
//! silently overriding what the controller negotiated. The turn-taking VAD is unaffected either way:
//! [`EnergyVad`] thresholds on *mean-square* energy, which is per-sample and so rate-independent, and
//! its hangover is counted in ptime frames, which are a duration, not a sample count.

use std::collections::VecDeque;

use crate::bridge::pcm_to_l16_le;
use crate::bridge::protocol::{
    ControlMessage, Direction, ErrorData, MarkData, MediaFormat, PlaySource, SpeechData, StartData,
};
use siphon_rtp_dsp::{EchoCanceller, NoiseSuppressor, SpeechRunGate, VoiceDetector};

/// Longest packetization a leg on this path can negotiate, in milliseconds. Single-sourced from
/// [`siphon_rtp_codec::factory::OPUS_MAX_PTIME_MS`] — the RFC 7587 §6.1 `maxptime` ceiling, which is
/// also what the engine clamps its control-flag ptime to and what bounds the media pipeline's frame
/// buffers — so the bridge's idea of "the longest frame" can never drift from the rest of the engine's.
pub const MAX_PTIME_MS: usize = siphon_rtp_codec::factory::OPUS_MAX_PTIME_MS as usize;
/// Highest native sample rate any codec on this path runs at, in Hz: RFC 7587 §4.1 pins Opus at
/// 48 kHz, and every other codec here samples at 8 or 16 kHz. Also the ceiling on a **selectable WS
/// wire rate** ([`super::wire_rate::MAX_WIRE_SAMPLE_RATE_HZ`]) — every buffer below is sized against it.
pub const MAX_SAMPLE_RATE_HZ: usize = 48_000;
/// Audio channels in the longest **decoded** frame. RFC 7587 §6.1 makes an Opus RTP stream mono or
/// stereo (`sprop-stereo`); Opus multistream / surround (RFC 7845) is out of scope and every other
/// codec here is mono.
const MAX_CHANNELS: usize = 2;

/// Samples **per channel** in the longest frame a leg can hand the bridge — 48 kHz × 120 ms = 5760.
/// Sizes every *mono* buffer on the bridge: the staged uplink frame after the channel fold, the echo
/// reference, and (through it) the L16 uplink the transport writes.
pub const MAX_FRAME_SAMPLES: usize = MAX_SAMPLE_RATE_HZ / 1000 * MAX_PTIME_MS;

/// Largest decoded frame in **interleaved `i16` values** — 5760 × 2 = 11520 (see the channel contract
/// in `siphon_rtp_codec`: [`crate::leg::MediaLeg::frame_samples`] is the interleaved count, so this,
/// not [`MAX_FRAME_SAMPLES`], is what a decode output buffer must measure). Only the staging slot is
/// this long; the fold at the codec boundary means everything downstream is bounded by
/// [`MAX_FRAME_SAMPLES`].
pub const MAX_FRAME_VALUES: usize = MAX_FRAME_SAMPLES * MAX_CHANNELS;

/// The PCM-domain core of a WS bridge session. See the module docs for the uplink/downlink contract.
pub struct BridgeCore {
    format: MediaFormat,
    stream_id: String,
    call_id: String,
    direction: Direction,
    /// Downlink PCM frames awaiting render to the call (drop-oldest bounded).
    playout: VecDeque<Vec<i16>>,
    playout_cap: usize,
    stopped: bool,
    /// Single-channel noise suppression on the uplink (call → server) audio, so the voice-AI receives
    /// cleaned speech. `Some` only when requested *and* the uplink rate is 8/16 kHz (see
    /// [`BridgeCore::with_noise_suppression`]); introduces the suppressor's WOLA latency on uplink.
    noise_suppressor: Option<NoiseSuppressor>,
    /// Local voice-activity detection on the uplink, driving `speech_started`/`speech_stopped` turn
    /// signals (and barge-in when `barge_in`). `Some` only when requested — see
    /// [`BridgeCore::with_vad`] for the energy gate and [`BridgeCore::with_voice_detector`] to hand
    /// in a detector the caller chose (the neural one).
    vad: Option<VoiceDetector>,
    /// Leading minimum-speech-run gate over the detector's raw decision: the speech-start edge only
    /// fires once speech has run for this many consecutive frames, so a cough, a door or one burst
    /// of echo does not barge in. A one-frame gate is a pass-through, which is what the historical
    /// `with_vad` path installs.
    speech_gate: SpeechRunGate,
    /// When `vad` fires a speech-start edge, flush the queued downlink playout in the same tick — a
    /// local barge-in that skips the server round-trip. No effect unless `vad` is set.
    barge_in: bool,
    /// Latched VAD state, so `tick` emits a turn signal only on an edge (silence↔speech transition).
    speaking: bool,
    /// Tick-originated control messages awaiting the socket (turn signals). Populated on VAD edges
    /// only, so the steady-state per-frame path never touches (or allocates) it; drained by the
    /// transport via [`BridgeCore::next_control`].
    pending_control: Vec<ControlMessage>,
    /// Optional acoustic echo canceller for the **uplink** (call → server) PCM (the `echo_cancellation`
    /// profile flag). Its far-end **reference** is the *downlink* frame played toward the call this
    /// tick (server → call), so the phone's echo of the voice-AI audio is cancelled off the uplink
    /// before the server hears it — otherwise the model would transcribe its own reflected speech.
    /// Built at the **wire** rate, which is what both of its inputs are in: the near-end is the staged
    /// uplink (already converted from the leg's codec rate by the RTP shell) and the far-end reference
    /// is the downlink frame the server sent at that same wire rate. Keeping one domain for both is
    /// the canceller's correctness precondition — see this module's "Which rate domain the core runs
    /// in". `None` when the leg was stood up without the flag or the wire rate is unsupported.
    /// Preallocated ⇒ its per-frame `cancel` does zero heap allocation.
    echo_canceller: Option<EchoCanceller>,
    /// Preallocated far-end reference for `echo_canceller` — the downlink frame this tick plays,
    /// zero-padded to the near-end frame length. Allocated **once**, with the canceller, rather than
    /// being a per-tick stack array: at the ptime ceiling that array would be 11 KB to zero on every
    /// tick, which costs more than the cancellation it feeds. Empty when the core does not cancel.
    echo_reference: Vec<i16>,
    /// Uplink PCM staged by [`BridgeCore::on_pcm_uplink`], consumed by the next [`BridgeCore::tick`].
    /// A fixed buffer, so staging a frame allocates nothing. [`MAX_FRAME_VALUES`] long, because a
    /// producer decodes **into** it ([`BridgeCore::uplink_slot`]) and a decoder writes interleaved
    /// values; only the first `uplink_samples` (mono, post-fold) are ever read back out.
    uplink: Box<[i16; MAX_FRAME_VALUES]>,
    /// Valid **mono** sample count in `uplink`, or `None` when no frame was staged for this tick.
    uplink_samples: Option<usize>,
    /// The frame [`BridgeCore::tick`] dequeued from `playout` for the caller to render this tick.
    downlink: Option<Vec<i16>>,
}

impl BridgeCore {
    /// A core for `(stream_id, call_id)` advertising `format`. `playout_cap` bounds the downlink queue
    /// (drop-oldest on overflow — late audio is worthless).
    pub fn new(
        format: MediaFormat,
        stream_id: impl Into<String>,
        call_id: impl Into<String>,
        direction: Direction,
        playout_cap: usize,
    ) -> Self {
        Self {
            format,
            stream_id: stream_id.into(),
            call_id: call_id.into(),
            direction,
            playout: VecDeque::new(),
            playout_cap: playout_cap.max(1),
            stopped: false,
            noise_suppressor: None,
            vad: None,
            speech_gate: SpeechRunGate::new(1),
            barge_in: false,
            speaking: false,
            pending_control: Vec::new(),
            echo_canceller: None,
            echo_reference: Vec::new(),
            uplink: Box::new([0i16; MAX_FRAME_VALUES]),
            uplink_samples: None,
            downlink: None,
        }
    }

    /// Enable single-channel noise suppression on the uplink audio (call → voice-AI server). Built
    /// from the negotiated **wire** sample rate (see the module docs); a no-op unless `enabled` is set
    /// *and* that rate is 8 or 16 kHz — the suppressor's supported rates, so a 24 kHz wire (or a
    /// 48 kHz Opus leg) leaves it off. An unsupported rate is **logged** rather than silently
    /// swallowed, and never changes the wire rate: degrading the feature is right, quietly
    /// renegotiating the stream behind the controller's back is not.
    #[must_use]
    pub fn with_noise_suppression(mut self, enabled: bool) -> Self {
        if !enabled {
            self.noise_suppressor = None;
            return self;
        }
        match NoiseSuppressor::new(self.format.sample_rate) {
            Ok(suppressor) => self.noise_suppressor = Some(suppressor),
            Err(error) => {
                tracing::warn!(
                    target: "siphon_rtp::media",
                    %error,
                    sample_rate_hz = self.format.sample_rate,
                    "noise suppression requested but unsupported at the websocket wire rate; \
                     leaving the uplink unsuppressed (the wire rate is unchanged)"
                );
                self.noise_suppressor = None;
            }
        }
        self
    }

    /// Enable local energy-VAD turn-taking on the uplink. Each tick the raw (pre-noise-suppression)
    /// staged frame is classified; on a silence→speech edge the core emits `speech_started` (and, when
    /// `barge_in`, flushes the downlink playout in that same tick — no server round-trip), and on the
    /// speech→silence edge past `hangover_frames` it emits `speech_stopped` (the turn endpoint).
    /// `threshold` is the mean-square energy for speech; `hangover_frames` is the trailing hold in
    /// ptime frames (see [`siphon_rtp_dsp::EnergyVad`]). The leading minimum-speech-run gate is left
    /// transparent, so this is exactly the pre-detector-selection behaviour; use
    /// [`BridgeCore::with_voice_detector`] to require one. Turn signals are drained via
    /// [`BridgeCore::next_control`].
    #[must_use]
    pub fn with_vad(self, threshold: i64, hangover_frames: u32, barge_in: bool) -> Self {
        // One required frame == a pass-through gate, so this path is bit-identical to the one that
        // predates detector selection.
        self.with_voice_detector(
            VoiceDetector::energy(threshold, hangover_frames),
            1,
            barge_in,
        )
    }

    /// Enable turn-taking with a detector the caller built — the neural classifier, or an energy
    /// gate with non-default settings — plus a **leading** minimum-speech run.
    ///
    /// The caller owns the choice because it owns the policy: the engine knows the leg's sample
    /// rate and ptime, and building the neural detector is fallible (see
    /// `siphon_rtp_dsp::VoiceDetector::neural`), so a configuration it cannot honour is refused at
    /// call setup rather than silently downgraded here.
    ///
    /// `minimum_speech_frames` is the leading run in ptime frames: the speech-start edge (and
    /// barge-in) waits until the detector has read speech that many frames running. `1` is a
    /// pass-through. It adds `minimum_speech_frames - 1` frames to turn-start latency, which is the
    /// trade being made against interrupting on a cough.
    #[must_use]
    pub fn with_voice_detector(
        mut self,
        detector: VoiceDetector,
        minimum_speech_frames: u32,
        barge_in: bool,
    ) -> Self {
        self.vad = Some(detector);
        self.speech_gate = SpeechRunGate::new(minimum_speech_frames);
        self.barge_in = barge_in;
        self
    }

    /// Attach an echo canceller to the uplink (call → server) audio (the `echo_cancellation` profile
    /// flag). Each tick the phone's uplink is echo-cancelled in place against the downlink frame the
    /// bridge is rendering toward the call (the far-end reference — the audio the phone plays and its
    /// mic re-captures), after noise suppression and before it is framed as L16, so the voice-AI server
    /// does not hear its own reflected speech. `None` leaves the uplink unchanged. The canceller must
    /// be built for the **wire** rate — the rate both the staged uplink and the server's downlink are
    /// in — so its frame length matches the per-tick frame (no per-frame reallocation) and its two
    /// signals are the same signal domain.
    #[must_use]
    pub fn with_echo_canceller(mut self, echo_canceller: Option<EchoCanceller>) -> Self {
        // Only a cancelling core ever reads a far-end frame; sized to the longest near-end frame it
        // will be subtracted from, so the per-tick slice is always in bounds without a bounds check.
        self.echo_reference = if echo_canceller.is_some() {
            vec![0i16; MAX_FRAME_SAMPLES]
        } else {
            Vec::new()
        };
        self.echo_canceller = echo_canceller;
        self
    }

    /// The negotiated binary audio format this core advertises.
    #[must_use]
    pub fn format(&self) -> MediaFormat {
        self.format
    }

    /// Whether the uplink is actually being noise-suppressed. `false` after
    /// [`BridgeCore::with_noise_suppression(true)`](BridgeCore::with_noise_suppression) means the
    /// wire rate is outside the suppressor's supported 8/16 kHz — the feature degraded, the stream
    /// did not.
    #[must_use]
    pub fn suppresses_uplink_noise(&self) -> bool {
        self.noise_suppressor.is_some()
    }

    /// Whether the uplink is actually being echo-cancelled against the downlink. Same "did the
    /// feature survive this rate" question as [`BridgeCore::suppresses_uplink_noise`].
    #[must_use]
    pub fn cancels_uplink_echo(&self) -> bool {
        self.echo_canceller.is_some()
    }

    /// Take the next tick-originated control message to send to the server (turn signals), or `None`.
    /// Drained FIFO by the transport after each [`BridgeCore::tick`]; returns `None` with no work
    /// (and no allocation) on the steady-state path.
    pub fn next_control(&mut self) -> Option<ControlMessage> {
        if self.pending_control.is_empty() {
            None
        } else {
            Some(self.pending_control.remove(0))
        }
    }

    /// The `start` message to send as the first text frame.
    pub fn start_message(&self) -> ControlMessage {
        ControlMessage::Start(StartData {
            stream_id: self.stream_id.clone(),
            call_id: self.call_id.clone(),
            direction: self.direction,
            media: self.format,
            tracks: Vec::new(),
            metadata: None,
        })
    }

    /// Whether a `stop` has been received/sent (the driver should close the socket).
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Frames currently queued for downlink playout.
    #[must_use]
    pub fn playout_depth(&self) -> usize {
        self.playout.len()
    }

    /// Stage one decoded uplink PCM frame for the next [`BridgeCore::tick`] (call → server). Copies
    /// into the preallocated staging buffer — no heap allocation — truncating anything past
    /// [`MAX_FRAME_SAMPLES`]. Staging twice before a tick keeps the **later** frame (the tick's
    /// cadence is the stream's clock; a doubled frame would otherwise stretch the timeline).
    ///
    /// A producer that can write the frame itself should decode straight into
    /// [`BridgeCore::uplink_slot`] instead and skip this copy.
    pub fn on_pcm_uplink(&mut self, pcm: &[i16]) {
        let count = pcm.len().min(MAX_FRAME_SAMPLES);
        self.uplink[..count].copy_from_slice(&pcm[..count]);
        self.uplink_samples = Some(count);
    }

    /// Borrow the staging slot for one uplink frame of `values` **interleaved** `i16` values, to
    /// decode **directly into** — takeover mode's [`crate::leg::MediaLeg`] does this so the per-tick
    /// path carries no extra frame copy at all. `values` is the decoder's buffer contract
    /// ([`crate::leg::MediaLeg::frame_samples`], an interleaved count), so it is measured against
    /// [`MAX_FRAME_VALUES`], not [`MAX_FRAME_SAMPLES`]. Commit what was actually written with
    /// [`BridgeCore::commit_uplink`]; without a commit the next tick sees no staged frame.
    ///
    /// A slot shorter than the decoder needs makes the decode fail rather than silently truncate, so
    /// the constant above has to cover every legitimate leg — see [`MAX_FRAME_VALUES`].
    pub fn uplink_slot(&mut self, values: usize) -> &mut [i16] {
        let count = values.min(MAX_FRAME_VALUES);
        &mut self.uplink[..count]
    }

    /// Mark the first `values` **interleaved** values of [`BridgeCore::uplink_slot`] as this tick's
    /// staged uplink frame, folding them to mono in place when `channels > 1`.
    ///
    /// The fold happens here, once, at the codec boundary — the same place the transcode pipeline
    /// does it — because everything downstream of it (VAD, noise suppression, echo cancellation, the
    /// L16 wire frame the server is told is mono) is single-channel. Staging interleaved stereo as
    /// mono would read channel pairs as consecutive samples and play back at double speed with the
    /// channels smeared: audible garbage with no error anywhere. A mono leg (`channels <= 1`) pays
    /// nothing — the fold is a no-op returning the same count.
    pub fn commit_uplink(&mut self, values: usize, channels: u8) {
        let values = values.min(MAX_FRAME_VALUES);
        let samples = siphon_rtp_codec::downmix_to_mono(&mut self.uplink[..values], channels);
        self.uplink_samples = Some(samples.min(MAX_FRAME_SAMPLES));
    }

    /// Feed an inbound binary WS frame (downlink playout audio, L16 little-endian).
    pub fn on_ws_binary(&mut self, bytes: &[u8]) {
        let mut pcm = vec![0i16; bytes.len() / 2];
        let samples = crate::bridge::l16_le_to_pcm(bytes, &mut pcm);
        pcm.truncate(samples);
        if pcm.is_empty() {
            return;
        }
        if self.playout.len() >= self.playout_cap {
            self.playout.pop_front(); // drop-oldest backpressure
        }
        self.playout.push_back(pcm);
    }

    /// Handle an inbound control message, returning a message to send back when one is warranted
    /// (e.g. an `error` for an unsupported request).
    pub fn on_control(&mut self, message: ControlMessage) -> Option<ControlMessage> {
        match message {
            ControlMessage::Clear(data) => {
                self.playout.clear();
                // Surface the flush as a mark so the server can resynchronize turn boundaries.
                Some(ControlMessage::Mark(MarkData {
                    stream_id: self.stream_id.clone(),
                    play_id: data.play_id,
                    name: "cleared".to_string(),
                }))
            }
            ControlMessage::Stop(_) => {
                self.stopped = true;
                None
            }
            ControlMessage::PlayStart(data) if data.source == PlaySource::Inline => {
                // Inline base64 playout is a later addition; binary-frame playout works today.
                Some(ControlMessage::Error(ErrorData {
                    stream_id: self.stream_id.clone(),
                    code: "unsupported_source".to_string(),
                    message: "inline play_start not yet supported; use source=binary".to_string(),
                    fatal: false,
                }))
            }
            _ => None,
        }
    }

    /// Advance one ptime: dequeue one downlink playout frame (retrievable with
    /// [`BridgeCore::take_downlink_pcm`]) and clean + frame the staged uplink into `uplink_out` as
    /// little-endian L16. Returns the uplink bytes written, or 0 when no frame was staged.
    ///
    /// Order matters and is load-bearing: the downlink frame is taken **first** so it can serve as the
    /// echo canceller's far-end reference for this tick's uplink, and so a local barge-in can drop it
    /// along with the rest of the queue before it is ever rendered.
    pub fn tick(&mut self, uplink_out: &mut [u8]) -> usize {
        // The downlink frame this tick renders toward the call is also the echo canceller's far-end
        // reference for the uplink (the audio the phone plays and its mic re-captures). Take it up front
        // so the uplink can cancel against it; the caller renders it after this returns. A barge-in
        // below drops it along with the rest of the queue, so no bot audio plays that tick.
        let mut downlink_frame = self.playout.pop_front();
        let mut uplink_bytes = 0;

        if let Some(written) = self.uplink_samples.take() {
            let pcm = &mut self.uplink[..written];
            // Turn-taking VAD runs on the *raw* staged frame, before noise suppression can swallow
            // low-energy speech onsets. Emits a signal only on an edge; barge-in flushes here.
            let raw_speech = self.vad.as_mut().map(|vad| vad.is_speech(pcm));
            // The leading run gate sits between the detector and the edge, so a single noisy frame
            // never opens a turn. At its default of one frame it is the identity.
            let speaking = raw_speech.map(|speech| self.speech_gate.update(speech));
            if let Some(speaking) = speaking {
                if speaking && !self.speaking {
                    // Silence → speech: local barge-in (flush queued playout, no round-trip) + notify.
                    if self.barge_in {
                        self.playout.clear();
                        // Also drop the frame already taken this tick, so no bot audio plays on barge-in.
                        downlink_frame = None;
                    }
                    self.pending_control
                        .push(ControlMessage::SpeechStarted(SpeechData {
                            stream_id: self.stream_id.clone(),
                        }));
                } else if !speaking && self.speaking {
                    // Speech → silence past hangover: the turn endpoint.
                    self.pending_control
                        .push(ControlMessage::SpeechStopped(SpeechData {
                            stream_id: self.stream_id.clone(),
                        }));
                }
                self.speaking = speaking;
            }

            // Clean the uplink audio in place before framing it toward the server, when enabled.
            if let Some(suppressor) = self.noise_suppressor.as_mut() {
                suppressor.process(pcm);
            }
            // Echo cancellation on the uplink, referenced against the downlink played this tick: the
            // canceller's GCC-PHAT delay estimate aligns the reference to the returned echo, so the
            // model does not hear its own speech reflected by the phone. A silent (absent) downlink
            // yields a zero reference — nothing to cancel. In place, zero per-frame heap.
            if let Some(echo_canceller) = self.echo_canceller.as_mut() {
                // Preallocated (see `echo_reference`), so only the *tail* past the downlink frame is
                // zeroed each tick — not the whole ceiling-sized buffer. `written` is bounded by
                // `MAX_FRAME_SAMPLES`, which is exactly the reference's length.
                let reference = &mut self.echo_reference[..written];
                let carried = downlink_frame.as_ref().map_or(0, |frame| {
                    let count = frame.len().min(written);
                    reference[..count].copy_from_slice(&frame[..count]);
                    count
                });
                reference[carried..].fill(0);
                echo_canceller.cancel(pcm, reference);
            }
            uplink_bytes = pcm_to_l16_le(pcm, uplink_out);
        }

        self.downlink = downlink_frame;
        uplink_bytes
    }

    /// Take the downlink PCM frame [`BridgeCore::tick`] dequeued for this tick, or `None` when the
    /// playout queue was empty (or a barge-in flushed it). The caller renders it toward the call — an
    /// RTP encode in takeover mode. Taking it a second time in the same tick yields `None`.
    pub fn take_downlink_pcm(&mut self) -> Option<Vec<i16>> {
        self.downlink.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::protocol::{ClearData, Encoding, Endianness, StopData};
    use crate::bridge::{l16_le_to_pcm, pcm_to_l16_le};

    fn core() -> BridgeCore {
        BridgeCore::new(
            MediaFormat::telephony_default(),
            "str_1",
            "call_1",
            Direction::Duplex,
            8,
        )
    }

    #[test]
    fn start_message_carries_the_format_and_identity() {
        match core().start_message() {
            ControlMessage::Start(data) => {
                assert_eq!(data.stream_id, "str_1");
                assert_eq!(data.call_id, "call_1");
                assert_eq!(data.media.sample_rate, 8000);
                assert_eq!(data.direction, Direction::Duplex);
            }
            other => panic!("expected start, got {other:?}"),
        }
    }

    #[test]
    fn staged_uplink_pcm_is_framed_as_little_endian_l16() {
        let mut core = core();
        core.on_pcm_uplink(&[0x1234i16, -2, 0]);
        let mut uplink = [0u8; 64];
        assert_eq!(core.tick(&mut uplink), 6);
        assert_eq!(&uplink[..2], &[0x34, 0x12], "little-endian on the wire");
    }

    #[test]
    fn a_tick_without_a_staged_frame_emits_nothing() {
        let mut core = core();
        let mut uplink = [0xAAu8; 64];
        assert_eq!(core.tick(&mut uplink), 0);
        assert_eq!(uplink[0], 0xAA, "buffer untouched");
    }

    #[test]
    fn a_staged_frame_is_consumed_by_exactly_one_tick() {
        let mut core = core();
        core.on_pcm_uplink(&[7i16; 160]);
        let mut uplink = [0u8; 1024];
        assert_eq!(core.tick(&mut uplink), 320);
        assert_eq!(core.tick(&mut uplink), 0, "not replayed on the next tick");
    }

    #[test]
    fn staging_twice_before_a_tick_keeps_the_later_frame() {
        // The tick cadence is the stream clock: a doubled stage must not stretch the timeline.
        let mut core = core();
        core.on_pcm_uplink(&[1i16; 160]);
        core.on_pcm_uplink(&[2i16; 160]);
        let mut uplink = [0u8; 1024];
        assert_eq!(core.tick(&mut uplink), 320);
        let mut back = [0i16; 160];
        l16_le_to_pcm(&uplink[..320], &mut back);
        assert_eq!(back[0], 2, "the later stage wins");
    }

    #[test]
    fn an_oversized_staged_frame_is_truncated_not_panicking() {
        let mut core = core();
        core.on_pcm_uplink(&vec![3i16; MAX_FRAME_SAMPLES * 2]);
        let mut uplink = vec![0u8; MAX_FRAME_SAMPLES * 4];
        assert_eq!(core.tick(&mut uplink), MAX_FRAME_SAMPLES * 2);
    }

    #[test]
    fn the_frame_bounds_are_derived_from_the_engines_ptime_ceiling() {
        // 48 kHz × 120 ms = 5760 samples per channel, 11520 interleaved values. Asserted against the
        // arithmetic rather than a literal so a change to the ceiling moves both together.
        let ceiling = usize::from(siphon_rtp_codec::factory::OPUS_MAX_PTIME_MS);
        assert_eq!(MAX_FRAME_SAMPLES, 48 * ceiling);
        assert_eq!(MAX_FRAME_VALUES, MAX_FRAME_SAMPLES * 2);
    }

    #[test]
    fn a_committed_stereo_frame_is_folded_to_mono() {
        // A stereo Opus ingress (RFC 7587 §6.1 `sprop-stereo=1`) decodes interleaved L,R,L,R… Staged
        // as-is it would frame twice the samples at double speed; the fold at commit makes it mono.
        let mut core = core();
        let slot = core.uplink_slot(8);
        slot.copy_from_slice(&[100, 300, 200, 400, -100, -300, 0, 2]);
        core.commit_uplink(8, 2);

        let mut uplink = [0u8; 64];
        assert_eq!(core.tick(&mut uplink), 8, "4 mono samples = 8 bytes");
        let mut back = [0i16; 4];
        l16_le_to_pcm(&uplink[..8], &mut back);
        assert_eq!(
            back,
            [200, 300, -200, 1],
            "per-instant mean of the two channels"
        );
    }

    #[test]
    fn a_committed_mono_frame_is_unchanged_by_the_fold() {
        let mut core = core();
        let slot = core.uplink_slot(3);
        slot.copy_from_slice(&[7, -9, 11]);
        core.commit_uplink(3, 1);

        let mut uplink = [0u8; 16];
        assert_eq!(core.tick(&mut uplink), 6);
        let mut back = [0i16; 3];
        l16_le_to_pcm(&uplink[..6], &mut back);
        assert_eq!(back, [7, -9, 11]);
    }

    #[test]
    fn downlink_frames_are_dequeued_one_per_tick() {
        let mut core = core();
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[4096i16; 160], &mut l16);
        core.on_ws_binary(&l16);
        core.on_ws_binary(&l16);
        assert_eq!(core.playout_depth(), 2);

        let mut uplink = [0u8; 1024];
        core.tick(&mut uplink);
        let frame = core.take_downlink_pcm().expect("one frame this tick");
        assert_eq!(frame.len(), 160);
        assert_eq!(frame[0], 4096);
        assert_eq!(core.playout_depth(), 1);
        assert!(
            core.take_downlink_pcm().is_none(),
            "a frame is taken exactly once"
        );
    }

    #[test]
    fn playout_queue_drops_oldest_on_overflow() {
        let mut core = core(); // cap 8
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[7i16; 160], &mut l16);
        for _ in 0..12 {
            core.on_ws_binary(&l16);
        }
        assert_eq!(core.playout_depth(), 8, "bounded at cap, oldest dropped");
    }

    #[test]
    fn clear_flushes_playout_and_marks() {
        let mut core = core();
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[1i16; 160], &mut l16);
        core.on_ws_binary(&l16);
        core.on_ws_binary(&l16);

        let reply = core.on_control(ControlMessage::Clear(ClearData {
            stream_id: "str_1".into(),
            play_id: None,
            reason: Some("barge_in".into()),
        }));
        assert_eq!(core.playout_depth(), 0, "barge-in flushed playout");
        assert!(matches!(reply, Some(ControlMessage::Mark(_))));
    }

    #[test]
    fn stop_marks_the_core_stopped() {
        let mut core = core();
        assert!(!core.is_stopped());
        core.on_control(ControlMessage::Stop(StopData {
            stream_id: "str_1".into(),
            reason: "call_ended".into(),
        }));
        assert!(core.is_stopped());
    }

    #[test]
    fn barge_in_drops_the_frame_already_taken_this_tick() {
        let mut core = core().with_vad(1_000_000, 3, true);
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[1000i16; 160], &mut l16);
        core.on_ws_binary(&l16);
        core.on_ws_binary(&l16);

        core.on_pcm_uplink(&[4000i16; 160]); // loud → speech edge
        let mut uplink = [0u8; 1024];
        core.tick(&mut uplink);
        assert_eq!(core.playout_depth(), 0, "queue flushed within the tick");
        assert!(
            core.take_downlink_pcm().is_none(),
            "the frame taken this tick is dropped too — no bot audio on barge-in"
        );
        assert!(matches!(
            core.next_control(),
            Some(ControlMessage::SpeechStarted(_))
        ));
    }

    #[test]
    fn without_vad_no_turn_signals_are_emitted() {
        let mut core = core();
        let mut uplink = [0u8; 1024];
        for _ in 0..5 {
            core.on_pcm_uplink(&[4000i16; 160]);
            core.tick(&mut uplink);
            assert!(core.next_control().is_none());
        }
    }

    /// Push one frame through and report the control message it produced, if any.
    fn tick_with(core: &mut BridgeCore, frame: &[i16]) -> Option<ControlMessage> {
        let mut uplink = [0u8; 1024];
        core.on_pcm_uplink(frame);
        core.tick(&mut uplink);
        core.next_control()
    }

    #[test]
    fn a_single_loud_frame_does_not_barge_in_when_a_leading_run_is_required() {
        // The cough / door / echo-burst case. Three frames of continuous speech are required, so a
        // lone loud frame must neither emit `speech_started` nor flush the playout.
        let mut core = core().with_voice_detector(VoiceDetector::energy(1_000_000, 1), 3, true);
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[1000i16; 160], &mut l16);
        for _ in 0..5 {
            core.on_ws_binary(&l16);
        }

        assert!(tick_with(&mut core, &[0i16; 160]).is_none());
        assert!(
            tick_with(&mut core, &[4000i16; 160]).is_none(),
            "one loud frame must not open a turn"
        );
        assert!(tick_with(&mut core, &[0i16; 160]).is_none());
        // Three ticks dequeued three frames; a barge-in would have flushed the other two as well.
        assert_eq!(core.playout_depth(), 2, "barge-in must not have fired");
    }

    #[test]
    fn a_run_at_the_required_length_barges_in_on_that_frame() {
        let mut core = core().with_voice_detector(VoiceDetector::energy(1_000_000, 1), 3, true);
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[1000i16; 160], &mut l16);
        for _ in 0..5 {
            core.on_ws_binary(&l16);
        }

        assert!(tick_with(&mut core, &[4000i16; 160]).is_none());
        assert!(tick_with(&mut core, &[4000i16; 160]).is_none());
        assert!(
            matches!(
                tick_with(&mut core, &[4000i16; 160]),
                Some(ControlMessage::SpeechStarted(_))
            ),
            "the third consecutive speech frame opens the turn"
        );
        assert_eq!(core.playout_depth(), 0, "and barge-in flushed the playout");
    }

    #[test]
    fn a_one_frame_run_gate_behaves_exactly_like_the_historical_path() {
        // `with_vad` must stay a pass-through, or the committed takeover golden digest moves.
        let mut legacy = core().with_vad(1_000_000, 3, true);
        let mut explicit = core().with_voice_detector(VoiceDetector::energy(1_000_000, 3), 1, true);
        for frame in [
            [0i16; 160],
            [4000i16; 160],
            [0i16; 160],
            [0i16; 160],
            [0i16; 160],
            [0i16; 160],
            [4000i16; 160],
        ] {
            let from_legacy = tick_with(&mut legacy, &frame);
            let from_explicit = tick_with(&mut explicit, &frame);
            assert_eq!(
                format!("{from_legacy:?}"),
                format!("{from_explicit:?}"),
                "the two construction paths must produce identical turn signals"
            );
        }
    }

    #[test]
    fn the_neural_detector_drives_the_same_turn_signals() {
        // A wideband core so the detector runs at its native rate. Digital silence must never open
        // a turn, and speech-like broadband energy eventually must — the point is that the enum
        // variant is wired through `tick`, not that the network is accurate (that is the dsp
        // crate's conformance suite).
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: 16_000,
            channels: 1,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        };
        let mut core = BridgeCore::new(format, "str_1", "call_1", Direction::Duplex, 4)
            .with_voice_detector(VoiceDetector::neural(16_000).expect("build"), 1, true);
        for _ in 0..20 {
            assert!(
                tick_with(&mut core, &[0i16; 320]).is_none(),
                "silence must never open a turn"
            );
        }
    }
}
