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

use std::collections::VecDeque;

use crate::bridge::pcm_to_l16_le;
use crate::bridge::protocol::{
    ControlMessage, Direction, ErrorData, MarkData, MediaFormat, PlaySource, SpeechData, StartData,
};
use siphon_rtp_dsp::{EchoCanceller, EnergyVad, NoiseSuppressor};

/// Largest frame the scratch PCM buffers hold (48 kHz × 20 ms).
pub const MAX_FRAME_SAMPLES: usize = 960;

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
    /// Local energy VAD on the uplink, driving `speech_started`/`speech_stopped` turn signals (and
    /// barge-in when `barge_in`). `Some` only when requested (see [`BridgeCore::with_vad`]).
    vad: Option<EnergyVad>,
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
    /// Built at the leg's native rate (decode == encode rate on a bridge leg, so uplink and downlink
    /// share it); `None` when the leg was stood up without the flag or its rate is unsupported.
    /// Preallocated ⇒ its per-frame `cancel` does zero heap allocation.
    echo_canceller: Option<EchoCanceller>,
    /// Uplink PCM staged by [`BridgeCore::on_pcm_uplink`], consumed by the next [`BridgeCore::tick`].
    /// A fixed buffer, so staging a frame allocates nothing.
    uplink: Box<[i16; MAX_FRAME_SAMPLES]>,
    /// Valid sample count in `uplink`, or `None` when no frame was staged for this tick.
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
            barge_in: false,
            speaking: false,
            pending_control: Vec::new(),
            echo_canceller: None,
            uplink: Box::new([0i16; MAX_FRAME_SAMPLES]),
            uplink_samples: None,
            downlink: None,
        }
    }

    /// Enable single-channel noise suppression on the uplink audio (call → voice-AI server). Built
    /// from the advertised uplink sample rate; a no-op unless `enabled` is set *and* that rate is
    /// 8 or 16 kHz (the suppressor's supported rates — e.g. a 48 kHz Opus leg leaves it off).
    #[must_use]
    pub fn with_noise_suppression(mut self, enabled: bool) -> Self {
        self.noise_suppressor = enabled
            .then(|| NoiseSuppressor::new(self.format.sample_rate).ok())
            .flatten();
        self
    }

    /// Enable local energy-VAD turn-taking on the uplink. Each tick the raw (pre-noise-suppression)
    /// staged frame is classified; on a silence→speech edge the core emits `speech_started` (and, when
    /// `barge_in`, flushes the downlink playout in that same tick — no server round-trip), and on the
    /// speech→silence edge past `hangover_frames` it emits `speech_stopped` (the turn endpoint).
    /// `threshold` is the mean-square energy for speech; `hangover_frames` is the trailing hold in
    /// ptime frames (see [`EnergyVad`]). Turn signals are drained via [`BridgeCore::next_control`].
    #[must_use]
    pub fn with_vad(mut self, threshold: i64, hangover_frames: u32, barge_in: bool) -> Self {
        self.vad = Some(EnergyVad::new(threshold, hangover_frames));
        self.barge_in = barge_in;
        self
    }

    /// Attach an echo canceller to the uplink (call → server) audio (the `echo_cancellation` profile
    /// flag). Each tick the phone's uplink is echo-cancelled in place against the downlink frame the
    /// bridge is rendering toward the call (the far-end reference — the audio the phone plays and its
    /// mic re-captures), after noise suppression and before it is framed as L16, so the voice-AI server
    /// does not hear its own reflected speech. `None` leaves the uplink unchanged. The canceller must
    /// be built for the leg's native rate so its frame length matches the per-tick frame (no per-frame
    /// reallocation).
    #[must_use]
    pub fn with_echo_canceller(mut self, echo_canceller: Option<EchoCanceller>) -> Self {
        self.echo_canceller = echo_canceller;
        self
    }

    /// The negotiated binary audio format this core advertises.
    #[must_use]
    pub fn format(&self) -> MediaFormat {
        self.format
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

    /// Borrow the staging slot for one `samples`-sample uplink frame, to decode **directly into** —
    /// takeover mode's [`crate::leg::MediaLeg`] does this so the per-tick path carries no extra frame
    /// copy at all. Commit what was actually written with [`BridgeCore::commit_uplink`]; without a
    /// commit the next tick sees no staged frame. Truncated to [`MAX_FRAME_SAMPLES`].
    pub fn uplink_slot(&mut self, samples: usize) -> &mut [i16] {
        let count = samples.min(MAX_FRAME_SAMPLES);
        &mut self.uplink[..count]
    }

    /// Mark the first `samples` samples of [`BridgeCore::uplink_slot`] as this tick's staged uplink
    /// frame.
    pub fn commit_uplink(&mut self, samples: usize) {
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
            let speaking = self
                .vad
                .as_mut()
                .map(|vad| vad.is_speech_with_energy(EnergyVad::energy(pcm)));
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
                let mut reference = [0i16; MAX_FRAME_SAMPLES];
                if let Some(frame) = downlink_frame.as_ref() {
                    let count = frame.len().min(written);
                    reference[..count].copy_from_slice(&frame[..count]);
                }
                echo_canceller.cancel(pcm, &reference[..written]);
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
    use crate::bridge::protocol::{ClearData, StopData};
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
        let mut uplink = [0u8; 4096];
        assert_eq!(core.tick(&mut uplink), MAX_FRAME_SAMPLES * 2);
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
}
