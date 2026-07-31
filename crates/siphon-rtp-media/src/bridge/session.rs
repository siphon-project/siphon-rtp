//! The bridge session: **takeover mode's** RTP shell around the PCM core.
//!
//! In takeover mode the WS server *is* leg A's far side, so the session owns a [`MediaLeg`] and the
//! RTP boundary sits here: leg A's inbound RTP is jitter-buffered and decoded into the
//! [`BridgeCore`]'s uplink, and the core's downlink playout frame is encoded back into an RTP packet
//! for the call. Everything that is not RTP — uplink cleaning, VAD/barge-in, the playout queue, the
//! WS control protocol — lives in [`BridgeCore`], so a **teed** call (whose media pipeline has
//! already decoded the frame) reuses the identical audio logic without a second jitter buffer.
//!
//! - **Uplink** (call → server): RTP in → [`MediaLeg`] jitter/decode → [`BridgeCore`] → L16 WS frame.
//! - **Downlink** (server → call): WS binary frame → [`BridgeCore`] playout → one frame/tick →
//!   [`MediaLeg`] encode → RTP to the call.
//! - **Barge-in**: `clear` (or the local VAD) drops the queued playout within one tick.

use crate::bridge::audio::{BridgeCore, MAX_FRAME_SAMPLES};
use crate::bridge::protocol::{ControlMessage, Direction, MediaFormat};
use crate::leg::{MediaLeg, PcmFrame};
use siphon_rtp_dsp::EchoCanceller;

/// What one [`BridgeSession::tick`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TickResult {
    /// Bytes written to the uplink (WS binary) buffer, or 0 if nothing to send this tick.
    pub uplink_bytes: usize,
    /// Bytes written to the downlink (RTP-to-call) buffer, or 0 if the playout queue was empty.
    pub downlink_bytes: usize,
}

/// A bidirectional WS↔leg bridge session for one call leg (takeover mode).
pub struct BridgeSession {
    leg: MediaLeg,
    core: BridgeCore,
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
            core: BridgeCore::new(format, stream_id, call_id, direction, playout_cap),
        }
    }

    /// Enable single-channel noise suppression on the uplink audio — see
    /// [`BridgeCore::with_noise_suppression`].
    #[must_use]
    pub fn with_noise_suppression(mut self, enabled: bool) -> Self {
        self.core = self.core.with_noise_suppression(enabled);
        self
    }

    /// Enable local energy-VAD turn-taking (and optional barge-in) on the uplink — see
    /// [`BridgeCore::with_vad`].
    #[must_use]
    pub fn with_vad(mut self, threshold: i64, hangover_frames: u32, barge_in: bool) -> Self {
        self.core = self.core.with_vad(threshold, hangover_frames, barge_in);
        self
    }

    /// Attach an echo canceller to the uplink audio — see [`BridgeCore::with_echo_canceller`].
    #[must_use]
    pub fn with_echo_canceller(mut self, echo_canceller: Option<EchoCanceller>) -> Self {
        self.core = self.core.with_echo_canceller(echo_canceller);
        self
    }

    /// Take the next tick-originated control message to send to the server (turn signals), or `None`.
    pub fn next_control(&mut self) -> Option<ControlMessage> {
        self.core.next_control()
    }

    /// The `start` message to send as the first text frame.
    pub fn start_message(&self) -> ControlMessage {
        self.core.start_message()
    }

    /// Whether a `stop` has been received/sent (the driver should close the socket).
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.core.is_stopped()
    }

    /// Frames currently queued for downlink playout.
    #[must_use]
    pub fn playout_depth(&self) -> usize {
        self.core.playout_depth()
    }

    /// Feed an inbound RTP packet from the call (uplink ingress).
    pub fn on_rtp(&mut self, packet: &[u8]) {
        if let Err(error) = self.leg.ingest_rtp(packet) {
            tracing::debug!(%error, "bridge dropped malformed ingress RTP");
        }
    }

    /// Feed an inbound binary WS frame (downlink playout audio, L16 little-endian).
    pub fn on_ws_binary(&mut self, bytes: &[u8]) {
        self.core.on_ws_binary(bytes);
    }

    /// Handle an inbound control message, returning a message to send back when one is warranted.
    pub fn on_control(&mut self, message: ControlMessage) -> Option<ControlMessage> {
        self.core.on_control(message)
    }

    /// Advance one ptime: decode one frame off the leg into the core's uplink, emit the cleaned L16
    /// uplink frame, and render the core's downlink playout frame to an RTP packet for the call.
    ///
    /// The leg decode and the core's playout dequeue touch disjoint state, so the RTP shell may pull
    /// its frame before the core ticks — the echo canceller still references the very downlink frame
    /// this tick renders, and a barge-in still drops it before it is encoded.
    pub fn tick(&mut self, uplink_out: &mut [u8], downlink_rtp_out: &mut [u8]) -> TickResult {
        // Uplink: decode one PCM frame off the leg's jitter buffer straight into the core's staging
        // slot — no intermediate frame buffer, so the split costs the per-tick path nothing.
        let frame_samples = self.leg.frame_samples().min(MAX_FRAME_SAMPLES);
        let decoded = self.leg.next_pcm(self.core.uplink_slot(frame_samples));
        if let Ok(PcmFrame::Decoded(written) | PcmFrame::Concealed(written)) = decoded {
            self.core.commit_uplink(written);
        }

        let mut result = TickResult {
            uplink_bytes: self.core.tick(uplink_out),
            downlink_bytes: 0,
        };

        // Downlink: render the frame the core dequeued (absent after a barge-in) toward the call.
        if let Some(frame) = self.core.take_downlink_pcm() {
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
    use crate::bridge::{l16_le_to_pcm, pcm_to_l16_le};
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

    /// The pre-refactor takeover-mode output, captured from the build that owned the RTP decode
    /// inside [`BridgeSession`] itself. See `takeover_path_matches_the_pre_refactor_golden_vector`.
    const GOLDEN_DIGEST: u64 = 1_009_670_988_991_603_878;
    const GOLDEN_UPLINK_FRAMES: usize = 60;
    /// 57, not 60: three downlink frames were dropped by the local barge-in on a speech edge.
    const GOLDEN_DOWNLINK_FRAMES: usize = 57;
    const GOLDEN_CONTROLS: usize = 5;

    /// FNV-1a (64-bit) over a byte stream — a stable, dependency-free digest for the golden vector
    /// below. Deterministic across platforms (no hashing-state randomization).
    fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
        let mut hash = seed;
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// Run the full takeover-mode datapath over a fixed input vector and digest everything it
    /// produced: the uplink L16 bytes, the rendered downlink RTP packets, and the control messages.
    /// Every audio stage is engaged (VAD + barge-in, noise suppression, echo cancellation) so the
    /// digest covers the whole per-tick order of operations, not just the framing.
    fn takeover_golden_digest() -> (u64, usize, usize, usize) {
        const FRAMES: usize = 60;
        const N: usize = 160; // 20 ms @ 8 kHz

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
            "str_golden",
            "call_golden",
            Direction::Duplex,
            8,
        )
        .with_noise_suppression(true)
        .with_vad(1_000_000, 3, true)
        .with_echo_canceller(Some(
            EchoCanceller::with_mdf_delay_estimation(8_000, 512, 1_024)
                .expect("build 8k aec")
                .with_two_path_dtd(),
        ));

        // Committed pseudo-random uplink and downlink streams (fixed seeds — never `rand`/wall clock).
        let mut uplink_rng = Lcg(0x1234_5678);
        let mut downlink_rng = Lcg(0x9ABC_DEF0);

        let mut uplink = [0u8; 1024];
        let mut downlink = [0u8; 1024];
        let mut downlink_bytes = [0u8; 2 * N];
        let mut digest = 0xcbf2_9ce4_8422_2325u64;
        let (mut uplink_frames, mut downlink_frames, mut controls) = (0usize, 0usize, 0usize);

        for frame in 0..FRAMES {
            // A downlink L16 frame every tick, and an uplink RTP packet whose level alternates between
            // loud (speech) and quiet every 12 frames, so the VAD crosses both edges several times.
            let far: Vec<i16> = (0..N)
                .map(|_| (3000.0 * downlink_rng.next_bipolar()) as i16)
                .collect();
            let length = pcm_to_l16_le(&far, &mut downlink_bytes);
            session.on_ws_binary(&downlink_bytes[..length]);

            let gain = if (frame / 12) % 2 == 0 { 5000.0 } else { 20.0 };
            let near: Vec<i16> = (0..N)
                .map(|_| (gain * uplink_rng.next_bipolar()) as i16)
                .collect();
            session.on_rtp(&ulaw_packet_pcm(frame as u16, &near));

            let result = session.tick(&mut uplink, &mut downlink);
            if result.uplink_bytes > 0 {
                uplink_frames += 1;
                digest = fnv1a(&uplink[..result.uplink_bytes], digest);
            }
            if result.downlink_bytes > 0 {
                downlink_frames += 1;
                digest = fnv1a(&downlink[..result.downlink_bytes], digest);
            }
            while let Some(control) = session.next_control() {
                controls += 1;
                digest = fnv1a(control.to_json().expect("json").as_bytes(), digest);
            }
        }
        (digest, uplink_frames, downlink_frames, controls)
    }

    /// The takeover path is byte-for-byte what it was before the PCM-core split: same uplink L16, same
    /// rendered downlink RTP, same control messages, in the same per-tick order. The constants below
    /// were captured from the pre-refactor build — a change to any of them is a behaviour change on
    /// the shipped voice-AI bridge, not a refactor.
    #[test]
    fn takeover_path_matches_the_pre_refactor_golden_vector() {
        let (digest, uplink_frames, downlink_frames, controls) = takeover_golden_digest();
        assert_eq!(uplink_frames, GOLDEN_UPLINK_FRAMES, "uplink frame count");
        assert_eq!(
            downlink_frames, GOLDEN_DOWNLINK_FRAMES,
            "downlink frame count"
        );
        assert_eq!(controls, GOLDEN_CONTROLS, "turn-signal count");
        assert_eq!(
            digest, GOLDEN_DIGEST,
            "takeover-mode output changed — this is a behaviour change, not a refactor"
        );
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
