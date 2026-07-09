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

use siphon_rtp_dsp::NoiseSuppressor;

use crate::bridge::protocol::{
    ControlMessage, Direction, ErrorData, MarkData, MediaFormat, PlaySource, StartData,
};
use crate::bridge::{l16_le_to_pcm, pcm_to_l16_le};
use crate::leg::{MediaLeg, PcmFrame};

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
    /// Optional single-channel noise suppressor for the **uplink** (call → server) PCM. Built at the
    /// leg's native decode rate (8/16 kHz) and applied in place per tick to the decoded frame before
    /// it is framed as L16, so the voice-AI server hears a de-noised stream. `None` when the leg was
    /// stood up without the `noise_suppression` profile flag (or its codec rate is unsupported), in
    /// which case the uplink is byte-for-byte the decoded audio (unchanged behaviour). Preallocated —
    /// its per-frame `process` does zero heap allocation.
    noise_suppressor: Option<NoiseSuppressor>,
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
        }
    }

    /// Attach a noise suppressor to the uplink (call → server) audio (the `noise_suppression` profile
    /// flag). Each tick's decoded PCM frame is cleaned in place before it is framed as L16, so the
    /// voice-AI server receives a de-noised stream. `None` leaves the uplink unchanged. The suppressor
    /// must be built for the leg's native decode rate so its frame length matches the per-tick frame
    /// (no per-frame reallocation).
    #[must_use]
    pub fn with_noise_suppressor(mut self, noise_suppressor: Option<NoiseSuppressor>) -> Self {
        self.noise_suppressor = noise_suppressor;
        self
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

        // Uplink: pop one PCM frame from the leg and frame it as little-endian L16.
        let mut pcm = [0i16; MAX_FRAME_SAMPLES];
        let frame_samples = self.leg.frame_samples().min(MAX_FRAME_SAMPLES);
        if let Ok(PcmFrame::Decoded(written) | PcmFrame::Concealed(written)) =
            self.leg.next_pcm(&mut pcm[..frame_samples])
        {
            // Post-decode noise suppression on the uplink toward the voice-AI server: clean the
            // decoded near-end PCM in place at the leg's native rate before it is framed as L16. The
            // suppressor is preallocated for this exact frame length, so `process` allocates nothing.
            if let Some(noise_suppressor) = self.noise_suppressor.as_mut() {
                noise_suppressor.process(&mut pcm[..written]);
            }
            result.uplink_bytes = pcm_to_l16_le(&pcm[..written], uplink_out);
        }

        // Downlink: render one queued playout frame to the call.
        if let Some(frame) = self.playout.pop_front() {
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
    use siphon_rtp_codec::Encoder;

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

    /// A µ-law session with the uplink noise suppressor attached at the leg's 8 kHz native rate.
    fn ulaw_session_with_noise_suppression() -> BridgeSession {
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
        .with_noise_suppressor(Some(
            siphon_rtp_dsp::NoiseSuppressor::new(8_000).expect("build 8k suppressor"),
        ))
    }

    /// Deterministic LCG (fixed seed) — reproducible white noise, never `rand` / the wall clock.
    struct Lcg(u32);
    impl Lcg {
        fn next_bipolar(&mut self) -> f32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (self.0 >> 8) as f32 / (1u32 << 23) as f32 - 1.0
        }
    }

    /// One 20 ms µ-law RTP packet of deterministic white noise at `sequence`.
    fn noisy_ulaw_packet(sequence: u16, rng: &mut Lcg) -> Vec<u8> {
        let mut pcm = [0i16; 160];
        for sample in pcm.iter_mut() {
            *sample = (2000.0 * rng.next_bipolar()) as i16;
        }
        let mut payload = [0u8; 160];
        G711::ulaw().encode(&pcm, &mut payload).expect("encode");
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 1,
        };
        let mut buffer = vec![0u8; 172];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    /// Mean per-sample energy of the converged uplink L16 tail produced by ticking `session` over a
    /// stream of identically-seeded noisy µ-law packets — the datapath-observable uplink signal.
    fn converged_uplink_energy(session: &mut BridgeSession) -> f64 {
        let mut rng = Lcg(0x51A9_2E17);
        let mut uplink = [0u8; 1024];
        let mut downlink = [0u8; 1024];
        let mut energy = 0.0f64;
        let mut samples = 0u64;
        // ~120 frames: a lead-in for the minimum-statistics tracker to converge, scoring only the tail.
        for sequence in 0..120u16 {
            session.on_rtp(&noisy_ulaw_packet(sequence, &mut rng));
            let result = session.tick(&mut uplink, &mut downlink);
            if sequence < 60 {
                continue; // skip the convergence lead-in
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
    fn noise_suppressor_cleans_the_uplink_on_the_datapath() {
        // The suppressor must actually run on the uplink: an identical noisy µ-law stream comes out
        // measurably quieter through a session with the suppressor attached than through a plain one.
        let plain_energy = converged_uplink_energy(&mut ulaw_session());
        let suppressed_energy = converged_uplink_energy(&mut ulaw_session_with_noise_suppression());

        assert!(plain_energy > 0.0, "plain uplink must carry the noise");
        assert!(
            suppressed_energy < 0.5 * plain_energy,
            "uplink noise not suppressed: {suppressed_energy:.1} vs plain {plain_energy:.1} \
             (suppressor did not run on the datapath)"
        );
    }
}
