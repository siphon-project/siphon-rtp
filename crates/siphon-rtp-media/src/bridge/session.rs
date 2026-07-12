//! The bridge session: a synchronous, deterministic pump between a [`MediaLeg`] and the WS
//! message stream. The async transport (tokio-tungstenite) drives it; keeping the state machine
//! sync makes the audio logic — uplink, downlink playout, barge-in flush — unit-testable without
//! sockets or a wall clock (the driver's tick cadence is the logical sample-tick clock).
//!
//! - **Uplink** (call → server): RTP in → [`MediaLeg`] jitter/decode → L16 → WS binary frame.
//! - **Downlink** (server → call): WS binary frame → L16 → PCM enqueued → one frame/tick →
//!   [`MediaLeg`] encode → RTP to the call.
//! - **Barge-in**: `clear` drops the queued playout within one tick.

use std::collections::VecDeque;

use crate::bridge::protocol::{
    ControlMessage, Direction, ErrorData, MarkData, MediaFormat, PlaySource, SpeechData, StartData,
};
use crate::bridge::{l16_le_to_pcm, pcm_to_l16_le};
use crate::leg::{MediaLeg, PcmFrame};
use siphon_rtp_dsp::{EchoCanceller, EnergyVad, NoiseSuppressor};

/// Largest frame the scratch PCM buffer holds (48 kHz × 20 ms).
const MAX_FRAME_SAMPLES: usize = 960;

/// What one [`BridgeSession::tick`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TickResult {
    /// Bytes written to the uplink (WS binary) buffer, or 0 if nothing to send this tick.
    pub uplink_bytes: usize,
    /// Bytes written to the downlink (RTP-to-call) buffer, or 0 if the playout queue was empty.
    pub downlink_bytes: usize,
}

/// A bidirectional WS↔leg bridge session for one call leg.
pub struct BridgeSession {
    leg: MediaLeg,
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
    /// [`BridgeSession::with_noise_suppression`]); introduces the suppressor's WOLA latency on uplink.
    noise_suppressor: Option<NoiseSuppressor>,
    /// Local energy VAD on the uplink, driving `speech_started`/`speech_stopped` turn signals (and
    /// barge-in when `barge_in`). `Some` only when requested (see [`BridgeSession::with_vad`]).
    vad: Option<EnergyVad>,
    /// When `vad` fires a speech-start edge, flush the queued downlink playout in the same tick — a
    /// local barge-in that skips the server round-trip. No effect unless `vad` is set.
    barge_in: bool,
    /// Latched VAD state, so `tick` emits a turn signal only on an edge (silence↔speech transition).
    speaking: bool,
    /// Tick-originated control messages awaiting the socket (turn signals). Populated on VAD edges
    /// only, so the steady-state per-frame path never touches (or allocates) it; drained by the
    /// transport via [`BridgeSession::next_control`].
    pending_control: Vec<ControlMessage>,
    /// Optional acoustic echo canceller for the **uplink** (call → server) PCM (the `echo_cancellation`
    /// profile flag). Its far-end **reference** is the *downlink* frame played toward the call this
    /// tick (server → call), so the phone's echo of the voice-AI audio is cancelled off the uplink
    /// before the server hears it — otherwise the model would transcribe its own reflected speech.
    /// Built at the leg's native rate (decode == encode rate on a bridge leg, so uplink and downlink
    /// share it); `None` when the leg was stood up without the flag or its rate is unsupported.
    /// Preallocated ⇒ its per-frame `cancel` does zero heap allocation.
    echo_canceller: Option<EchoCanceller>,
}

impl BridgeSession {
    /// Create a session over `leg` for `(stream_id, call_id)` advertising `format`. `playout_cap`
    /// bounds the downlink queue (drop-oldest on overflow — late audio is worthless).
    pub fn new(
        leg: MediaLeg,
        format: MediaFormat,
        stream_id: impl Into<String>,
        call_id: impl Into<String>,
        direction: Direction,
        playout_cap: usize,
    ) -> Self {
        Self {
            leg,
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
    /// decoded frame is classified; on a silence→speech edge the session emits `speech_started` (and,
    /// when `barge_in`, flushes the downlink playout in that same tick — no server round-trip), and on
    /// the speech→silence edge past `hangover_frames` it emits `speech_stopped` (the turn endpoint).
    /// `threshold` is the mean-square energy for speech; `hangover_frames` is the trailing hold in
    /// ptime frames (see [`EnergyVad`]). Turn signals are drained via [`BridgeSession::next_control`].
    #[must_use]
    pub fn with_vad(mut self, threshold: i64, hangover_frames: u32, barge_in: bool) -> Self {
        self.vad = Some(EnergyVad::new(threshold, hangover_frames));
        self.barge_in = barge_in;
        self
    }

    /// Attach an echo canceller to the uplink (call → server) audio (the `echo_cancellation` profile
    /// flag). Each tick the phone's decoded uplink is echo-cancelled in place against the downlink
    /// frame the bridge is rendering toward the call (the far-end reference — the audio the phone plays
    /// and its mic re-captures), after noise suppression and before it is framed as L16, so the
    /// voice-AI server does not hear its own reflected speech. `None` leaves the uplink unchanged. The
    /// canceller must be built for the leg's native rate so its frame length matches the per-tick frame
    /// (no per-frame reallocation).
    #[must_use]
    pub fn with_echo_canceller(mut self, echo_canceller: Option<EchoCanceller>) -> Self {
        self.echo_canceller = echo_canceller;
        self
    }

    /// Take the next tick-originated control message to send to the server (turn signals), or `None`.
    /// Drained FIFO by the transport after each [`BridgeSession::tick`]; returns `None` with no work
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

    /// Feed an inbound RTP packet from the call (uplink ingress).
    pub fn on_rtp(&mut self, packet: &[u8]) {
        if let Err(error) = self.leg.ingest_rtp(packet) {
            tracing::debug!(%error, "bridge dropped malformed ingress RTP");
        }
    }

    /// Feed an inbound binary WS frame (downlink playout audio, L16 little-endian).
    pub fn on_ws_binary(&mut self, bytes: &[u8]) {
        let mut pcm = vec![0i16; bytes.len() / 2];
        let samples = l16_le_to_pcm(bytes, &mut pcm);
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

    /// Advance one ptime: emit an uplink WS audio frame (if the leg has audio) and render one
    /// queued downlink frame to an RTP packet for the call.
    pub fn tick(&mut self, uplink_out: &mut [u8], downlink_rtp_out: &mut [u8]) -> TickResult {
        let mut result = TickResult::default();

        // The downlink frame this tick renders toward the call is also the echo canceller's far-end
        // reference for the uplink (the audio the phone plays and its mic re-captures). Take it up front
        // so the uplink can cancel against it; it is rendered to RTP below (unchanged when AEC is off).
        // A barge-in below drops it along with the rest of the queue, so no bot audio plays that tick.
        let mut downlink_frame = self.playout.pop_front();

        // Uplink: pop one PCM frame from the leg and frame it as little-endian L16.
        let mut pcm = [0i16; MAX_FRAME_SAMPLES];
        let frame_samples = self.leg.frame_samples().min(MAX_FRAME_SAMPLES);
        if let Ok(PcmFrame::Decoded(written) | PcmFrame::Concealed(written)) =
            self.leg.next_pcm(&mut pcm[..frame_samples])
        {
            // Turn-taking VAD runs on the *raw* decoded frame, before noise suppression can swallow
            // low-energy speech onsets. Emits a signal only on an edge; barge-in flushes here.
            let speaking = self
                .vad
                .as_mut()
                .map(|vad| vad.is_speech_with_energy(EnergyVad::energy(&pcm[..written])));
            if let Some(speaking) = speaking {
                if speaking && !self.speaking {
                    // Silence → speech: local barge-in (flush queued playout, no round-trip) + notify.
                    if self.barge_in {
                        self.playout.clear();
                        // Also drop the frame already taken this tick, so no bot audio plays on barge-in
                        // (matching the pre-AEC order where the downlink was popped after this flush).
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
                suppressor.process(&mut pcm[..written]);
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
                echo_canceller.cancel(&mut pcm[..written], &reference[..written]);
            }
            result.uplink_bytes = pcm_to_l16_le(&pcm[..written], uplink_out);
        }

        // Downlink: render the frame taken above to the call.
        if let Some(frame) = downlink_frame {
            match self.leg.encode_rtp(&frame, downlink_rtp_out) {
                Ok(len) => result.downlink_bytes = len,
                Err(error) => tracing::debug!(%error, "bridge downlink encode failed"),
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::protocol::{ClearData, StopData};
    use crate::jitter::JitterBuffer;
    use crate::rtp::{write_packet, RtpHeader, RtpPacket};
    use siphon_rtp_codec::g711::G711;

    fn ulaw_session() -> BridgeSession {
        let leg = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x5555_6666,
            0,
        );
        BridgeSession::new(
            leg,
            MediaFormat::telephony_default(),
            "str_1",
            "call_1",
            Direction::Duplex,
            8,
        )
    }

    fn ulaw_packet(sequence: u16, byte: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 1,
        };
        let payload = [byte; 160];
        let mut buffer = vec![0u8; 172];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn start_message_carries_format() {
        let session = ulaw_session();
        match session.start_message() {
            ControlMessage::Start(data) => {
                assert_eq!(data.stream_id, "str_1");
                assert_eq!(data.call_id, "call_1");
                assert_eq!(data.media.sample_rate, 8000);
            }
            other => panic!("expected start, got {other:?}"),
        }
    }

    #[test]
    fn uplink_frames_call_audio_to_ws() {
        let mut session = ulaw_session();
        session.on_rtp(&ulaw_packet(0, 0xFF)); // µ-law 0xFF decodes to 0
        let mut uplink = [0u8; 1024];
        let mut downlink = [0u8; 1024];
        let result = session.tick(&mut uplink, &mut downlink);
        assert_eq!(result.uplink_bytes, 320, "8k/20ms L16 = 320 bytes");
        // Decoded silence → all-zero L16.
        assert!(uplink[..320].iter().all(|&byte| byte == 0));
    }

    fn ulaw_packet_pcm(sequence: u16, pcm: &[i16]) -> Vec<u8> {
        use siphon_rtp_codec::Encoder as _;
        let mut encoder = G711::ulaw();
        let mut payload = [0u8; 160];
        let len = encoder.encode(pcm, &mut payload).expect("encode");
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 1,
        };
        let mut buffer = vec![0u8; 12 + len];
        let written = write_packet(&header, &payload[..len], &mut buffer).expect("write");
        buffer.truncate(written);
        buffer
    }

    #[test]
    fn noise_suppression_attenuates_uplink_audio() {
        // Deterministic white-noise PCM frames, identical for both runs.
        let mut state = 0x2247_9BEFu32;
        let mut noise_sample = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (((state >> 8) as f32 / (1u32 << 24) as f32) - 0.5) * 2.0 * 2000.0
        };
        let frames: Vec<Vec<i16>> = (0..160)
            .map(|_| (0..160).map(|_| noise_sample() as i16).collect())
            .collect();

        // Total L16-uplink energy over the converged region (past the suppressor's WOLA startup).
        let uplink_energy = |noise_suppression: bool| -> f64 {
            let leg = MediaLeg::new(
                Box::new(G711::ulaw()),
                Box::new(G711::ulaw()),
                JitterBuffer::new(1, 16),
                0x5555_6666,
                0,
            );
            let mut session = BridgeSession::new(
                leg,
                MediaFormat::telephony_default(),
                "str_1",
                "call_1",
                Direction::Duplex,
                8,
            )
            .with_noise_suppression(noise_suppression);

            let mut uplink = [0u8; 1024];
            let mut downlink = [0u8; 1024];
            let mut energy = 0.0f64;
            for (index, frame) in frames.iter().enumerate() {
                session.on_rtp(&ulaw_packet_pcm(index as u16, frame));
                let result = session.tick(&mut uplink, &mut downlink);
                if index < 30 || result.uplink_bytes == 0 {
                    continue;
                }
                let mut pcm = vec![0i16; result.uplink_bytes / 2];
                let count = l16_le_to_pcm(&uplink[..result.uplink_bytes], &mut pcm);
                energy += pcm[..count]
                    .iter()
                    .map(|&sample| f64::from(sample) * f64::from(sample))
                    .sum::<f64>();
            }
            energy
        };

        let off = uplink_energy(false);
        let on = uplink_energy(true);
        assert!(off > 0.0, "sanity: the uplink carries the noise through");
        assert!(
            on < 0.7 * off,
            "noise suppression must attenuate the uplink: on {on:.3e} vs off {off:.3e}"
        );
    }

    #[test]
    fn downlink_renders_ws_audio_to_rtp() {
        let mut session = ulaw_session();
        // One 160-sample frame of L16 little-endian downlink audio.
        let pcm = [4096i16; 160];
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&pcm, &mut l16);
        session.on_ws_binary(&l16);
        assert_eq!(session.playout_depth(), 1);

        let mut uplink = [0u8; 1024];
        let mut downlink = [0u8; 1024];
        let result = session.tick(&mut uplink, &mut downlink);
        assert!(result.downlink_bytes > 0);
        let packet = RtpPacket::parse(&downlink[..result.downlink_bytes]).expect("parse");
        assert_eq!(packet.payload_type, 0);
        assert_eq!(packet.ssrc, 0x5555_6666);
        assert_eq!(packet.sequence, 0);
        assert_eq!(packet.payload.len(), 160);
        assert_eq!(session.playout_depth(), 0, "frame rendered");
    }

    #[test]
    fn clear_flushes_playout_and_marks() {
        let mut session = ulaw_session();
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[1i16; 160], &mut l16);
        session.on_ws_binary(&l16);
        session.on_ws_binary(&l16);
        assert_eq!(session.playout_depth(), 2);

        let reply = session.on_control(ControlMessage::Clear(ClearData {
            stream_id: "str_1".into(),
            play_id: None,
            reason: Some("barge_in".into()),
        }));
        assert_eq!(session.playout_depth(), 0, "barge-in flushed playout");
        assert!(matches!(reply, Some(ControlMessage::Mark(_))));
    }

    #[test]
    fn playout_queue_drops_oldest_on_overflow() {
        let mut session = ulaw_session(); // cap 8
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[7i16; 160], &mut l16);
        for _ in 0..12 {
            session.on_ws_binary(&l16);
        }
        assert_eq!(session.playout_depth(), 8, "bounded at cap, oldest dropped");
    }

    #[test]
    fn stop_marks_session_stopped() {
        let mut session = ulaw_session();
        assert!(!session.is_stopped());
        session.on_control(ControlMessage::Stop(StopData {
            stream_id: "str_1".into(),
            reason: "call_ended".into(),
        }));
        assert!(session.is_stopped());
    }

    fn vad_session(threshold: i64, hangover_frames: u32, barge_in: bool) -> BridgeSession {
        let leg = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x5555_6666,
            0,
        );
        BridgeSession::new(
            leg,
            MediaFormat::telephony_default(),
            "str_1",
            "call_1",
            Direction::Duplex,
            8,
        )
        .with_vad(threshold, hangover_frames, barge_in)
    }

    /// Feed one PCM frame as an uplink RTP packet, advance one tick, and collect the turn signals it
    /// emitted (the sample-tick logical clock — no wall clock).
    fn step(session: &mut BridgeSession, sequence: u16, pcm: &[i16]) -> Vec<ControlMessage> {
        session.on_rtp(&ulaw_packet_pcm(sequence, pcm));
        let mut uplink = [0u8; 1024];
        let mut downlink = [0u8; 1024];
        session.tick(&mut uplink, &mut downlink);
        let mut signals = Vec::new();
        while let Some(message) = session.next_control() {
            signals.push(message);
        }
        signals
    }

    #[test]
    fn vad_emits_turn_signals_on_speech_edges() {
        // threshold 1e6, hangover 3 frames (~60 ms at 20 ms ptime).
        let mut session = vad_session(1_000_000, 3, false);
        let loud = [4000i16; 160]; // mean-square energy 16e6 ≫ threshold
        let silence = [0i16; 160];
        let mut sequence = 0u16;

        // A leading silent frame: no edge, no signal.
        assert!(step(&mut session, sequence, &silence).is_empty());
        sequence += 1;

        // Silence → speech: exactly one speech_started.
        let started = step(&mut session, sequence, &loud);
        sequence += 1;
        assert!(
            matches!(started.as_slice(), [ControlMessage::SpeechStarted(_)]),
            "expected speech_started, got {started:?}"
        );

        // Continued speech emits nothing (signal only on an edge).
        let held = step(&mut session, sequence, &loud);
        sequence += 1;
        assert!(held.is_empty(), "no repeat on sustained speech: {held:?}");

        // Three silent frames are held as speech by the hangover — still no endpoint.
        for _ in 0..3 {
            assert!(step(&mut session, sequence, &silence).is_empty());
            sequence += 1;
        }

        // The frame that exhausts the hangover is the turn endpoint: one speech_stopped.
        let stopped = step(&mut session, sequence, &silence);
        assert!(
            matches!(stopped.as_slice(), [ControlMessage::SpeechStopped(_)]),
            "expected speech_stopped at the endpoint, got {stopped:?}"
        );
    }

    #[test]
    fn barge_in_flushes_playout_within_one_tick_on_speech_start() {
        let mut session = vad_session(1_000_000, 3, true);
        // The bot is speaking: two downlink frames queued for playout.
        let mut l16 = [0u8; 320];
        pcm_to_l16_le(&[1000i16; 160], &mut l16);
        session.on_ws_binary(&l16);
        session.on_ws_binary(&l16);
        assert_eq!(session.playout_depth(), 2);

        // The caller starts talking: a single loud uplink frame flushes the queued playout in this
        // very tick (no server round-trip) and notifies the server.
        let signals = step(&mut session, 0, &[4000i16; 160]);
        assert_eq!(
            session.playout_depth(),
            0,
            "barge-in must flush the queued playout in one tick"
        );
        assert!(
            matches!(signals.as_slice(), [ControlMessage::SpeechStarted(_)]),
            "expected speech_started on barge-in, got {signals:?}"
        );
    }

    #[test]
    fn default_session_emits_no_turn_signals() {
        // No `with_vad` → the turn-taking path is inert and never emits control.
        let mut session = ulaw_session();
        for sequence in 0..5 {
            assert!(
                step(&mut session, sequence, &[4000i16; 160]).is_empty(),
                "no VAD configured must mean no turn signals"
            );
        }
    }

    /// Deterministic LCG (fixed seed) — reproducible white noise, never `rand` / the wall clock.
    struct Lcg(u32);
    impl Lcg {
        fn next_bipolar(&mut self) -> f32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (self.0 >> 8) as f32 / (1u32 << 23) as f32 - 1.0
        }
    }

    /// A µ-law session with the uplink echo canceller attached at 8 kHz — the engine's default backend
    /// (MDF partitioned-block + GCC-PHAT delay estimation + two-path DTD).
    fn ulaw_session_with_echo_canceller() -> BridgeSession {
        let leg = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x5555_6666,
            0,
        );
        BridgeSession::new(
            leg,
            MediaFormat::telephony_default(),
            "str_1",
            "call_1",
            Direction::Duplex,
            8,
        )
        .with_echo_canceller(Some(
            EchoCanceller::with_mdf_delay_estimation(8_000, 512, 1_024)
                .expect("build 8k aec")
                .with_two_path_dtd(),
        ))
    }

    /// Mean per-sample energy of the converged uplink L16 tail when the phone's uplink is a *pure echo*
    /// of the downlink the bridge plays toward it — the far-end reference. Each tick feeds the downlink
    /// (server → call, L16 over WS) and the echo of it as the uplink RTP (call → server, µ-law), then
    /// ticks; a canceller wired to the downlink reference must return far less energy than a plain leg.
    fn converged_uplink_echo_energy(session: &mut BridgeSession) -> f64 {
        const FRAMES: usize = 400;
        const N: usize = 160; // 20 ms @ 8 kHz
        const DELAY: usize = 16; // echo-path delay (samples), recovered by GCC-PHAT
        const RIR: [f32; 5] = [0.20, 0.0, -0.10, 0.0, 0.05]; // fixed, ~12 dB ERL (Geigel-safe)
        let mut rng = Lcg(0x0EC0_B00B);
        let total = FRAMES * N;
        // Committed white far-end (downlink) stream and its echo (the uplink the phone returns).
        let far: Vec<i16> = (0..total)
            .map(|_| (4000.0 * rng.next_bipolar()) as i16)
            .collect();
        let echo: Vec<i16> = (0..total)
            .map(|i| {
                let mut acc = 0.0f32;
                for (k, &tap) in RIR.iter().enumerate() {
                    if let Some(idx) = i.checked_sub(DELAY + k) {
                        acc += tap * f32::from(far[idx]);
                    }
                }
                acc.round().clamp(-32768.0, 32767.0) as i16
            })
            .collect();

        let mut uplink = [0u8; 1024];
        let mut downlink = [0u8; 1024];
        let mut downlink_bytes = [0u8; 2 * N];
        let (mut energy, mut samples) = (0.0f64, 0u64);
        for frame in 0..FRAMES {
            let window = frame * N..(frame + 1) * N;
            // Downlink toward the phone (the far-end reference), as an L16-little-endian WS binary frame.
            let downlink_len = pcm_to_l16_le(&far[window.clone()], &mut downlink_bytes);
            session.on_ws_binary(&downlink_bytes[..downlink_len]);
            // Uplink from the phone = the echo of that downlink, as a µ-law RTP packet.
            session.on_rtp(&ulaw_packet_pcm(frame as u16, &echo[window]));

            let result = session.tick(&mut uplink, &mut downlink);
            if frame < FRAMES / 2 {
                continue; // convergence lead-in (delay lock + MDF settle)
            }
            for chunk in uplink[..result.uplink_bytes].chunks_exact(2) {
                let value = f64::from(i16::from_le_bytes([chunk[0], chunk[1]]));
                energy += value * value;
                samples += 1;
            }
        }
        if samples == 0 {
            0.0
        } else {
            energy / samples as f64
        }
    }

    #[test]
    fn echo_canceller_cancels_the_uplink_echo_on_the_bridge_datapath() {
        // The canceller must actually run on the uplink using the downlink as its reference: the same
        // echo-laden uplink comes out measurably quieter through a session with the canceller attached
        // than through a plain one — proving the downlink→uplink reference is wired into `tick`.
        let plain_energy = converged_uplink_echo_energy(&mut ulaw_session());
        let cancelled_energy =
            converged_uplink_echo_energy(&mut ulaw_session_with_echo_canceller());

        assert!(plain_energy > 0.0, "plain uplink must carry the echo");
        assert!(
            cancelled_energy < 0.5 * plain_energy,
            "uplink echo not cancelled: {cancelled_energy:.1} vs plain {plain_energy:.1} \
             (canceller did not run on the bridge datapath)"
        );
    }
}
