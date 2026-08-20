//! The **WebSocket tee**: stream a live call's decoded audio to a WS server while the call keeps
//! relaying — the send-only counterpart to the takeover bridge ([`super::session::BridgeSession`]).
//!
//! Where takeover mode makes the WS server leg A's far side (A↔B is not wired), a tee is a
//! [`MediaSink`] on a normally-relaying call: it plugs into the same post-decode
//! [`crate::fanout::FanOut`] tap SIPREC forking uses, so **one** decode of a stream feeds the peer,
//! the recorder, the SIPREC fork *and* the WS consumer. There is no second [`crate::leg::MediaLeg`]
//! and no second jitter buffer — two playout buffers on one stream would make two different
//! concealment decisions, and the WS consumer would hear artefacts the call never had.
//!
//! **Clock.** A tee has no clock of its own: [`WsTeeSink::write_pcm`] is called from the media
//! pipeline's actor thread once per decoded ingress frame. That is the better clock — the receiving
//! jitter buffer has already smoothed arrival and concealed loss. It follows that a silent or gapped
//! leg produces *no* tee frames (unlike the takeover ticker, which emits silence); comfort-filling a
//! tee is a follow-up, not a v1 requirement.
//!
//! **Hot-path rule.** `write_pcm` runs on the per-packet path and must never block or allocate. The
//! sink frames PCM into a **pooled** buffer and pushes it onto a **bounded** channel with a
//! drop-on-full policy and a `dropped` counter — the same contract [`crate::fork::RtpForkSink`]
//! holds. A slow or stalled WS server drops tee frames; it never touches the call. The transport task
//! returns each drained buffer through a recycle channel, so the media path allocates nothing at all
//! in steady state (the transport's own copy into the WebSocket frame is off the media path).
//!
//! **Channels.** One WS connection can carry one leg's monologue, both legs mixed to mono, or both
//! legs interleaved as **stereo** L16 (channel 0 = caller, channel 1 = callee) — speaker separation
//! on a single connection, rather than one socket per leg. Both legs feed one shared [`TeeMixer`]
//! through a `Mutex` that is uncontended by construction: a call's two directions are owned by the
//! *same* pipeline actor, so the two sinks are never on different threads.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::bridge::audio::{MAX_FRAME_SAMPLES, MAX_PTIME_MS};
use crate::bridge::pcm_to_l16_le;
use crate::bridge::protocol::{ControlMessage, Direction, MediaFormat, StartData};
use crate::bridge::ws::BridgeError;
use crate::fanout::MediaSink;

/// How many wire frames the tee buffers between the sink and the socket. Bounded: a stalled server
/// drops frames rather than growing a queue (late media is worthless).
const CHANNEL_DEPTH: usize = 16;

/// Headroom on the resample scratch for the polyphase filter's fractional remainder, which can put
/// one extra sample in a frame when the rate ratio is not an integer.
const RESAMPLE_SLACK_SAMPLES: usize = 8;

/// How many wire frames' worth of samples each channel's ring holds before dropping the oldest. Sized
/// so a modest producer/consumer skew (one leg quiet for a few frames) is absorbed, while a
/// permanently silent opposite channel can never grow the tee without bound.
const RING_FRAMES: usize = 8;

/// Which of a call's two legs a [`WsTeeSink`] carries — the tee's wire channel index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeChannel {
    /// The caller's (leg A's) audio — wire channel 0, and the only channel of a caller-only tee.
    Caller,
    /// The callee's (leg B's) audio — wire channel 1 of a stereo tee.
    Callee,
}

impl TeeChannel {
    /// Wire channel index (0 = caller, 1 = callee).
    fn index(self) -> usize {
        match self {
            Self::Caller => 0,
            Self::Callee => 1,
        }
    }
}

/// Why a tee stream ended, reported once when its transport task exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeEndReason {
    /// The WS server closed the connection (or the underlying stream ended).
    ServerClosed,
    /// The WS server sent a `stop` control frame.
    ServerStopped,
    /// The call side went away — every sink was dropped, so no more frames can arrive.
    CallEnded,
}

/// A bounded, drop-oldest FIFO of PCM samples for one tee channel. Preallocated: `push` and
/// `read_into` are copy loops, so the hot path allocates nothing. (Same shape as the media pipeline's
/// echo-reference ring — a stalled consumer must never pin stale audio or grow the buffer.)
struct SampleRing {
    buffer: Box<[i16]>,
    head: usize,
    length: usize,
}

impl SampleRing {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0i16; capacity.max(1)].into_boxed_slice(),
            head: 0,
            length: 0,
        }
    }

    /// Append `samples`, overwriting the oldest first once full (drop-oldest — keep the newest audio).
    /// Returns how many samples were dropped to make room.
    fn push(&mut self, samples: &[i16]) -> usize {
        let capacity = self.buffer.len();
        let mut dropped = 0;
        for &sample in samples {
            if self.length == capacity {
                self.buffer[self.head] = sample;
                self.head = (self.head + 1) % capacity;
                dropped += 1;
            } else {
                let tail = (self.head + self.length) % capacity;
                self.buffer[tail] = sample;
                self.length += 1;
            }
        }
        dropped
    }

    /// Drain exactly `out.len()` samples into `out` — the caller checks [`Self::len`] first.
    fn read_into(&mut self, out: &mut [i16]) {
        let capacity = self.buffer.len();
        for slot in out.iter_mut() {
            *slot = self.buffer[self.head];
            self.head = (self.head + 1) % capacity;
        }
        self.length -= out.len();
    }

    fn len(&self) -> usize {
        self.length
    }
}

/// The shared frame assembler behind a call's tee sinks: per-channel rings in, L16 wire frames out on
/// a bounded channel. A one-leg tee reads one ring; a stereo tee waits until **both** rings hold a
/// full frame and interleaves them; a `channels = 1` tee over both legs mixes them (saturating sum).
pub struct TeeMixer {
    /// Per-channel sample rings, indexed by [`TeeChannel::index`].
    rings: [SampleRing; 2],
    /// Wire channel count (1 = mono/mixed, 2 = caller/callee interleaved).
    channels: u8,
    /// Whether both legs feed this tee. `false` ⇒ a single-leg monologue.
    stereo_source: bool,
    /// When only one leg feeds it, whether that leg is the callee (so the tee reads ring 1).
    callee_only: bool,
    /// Samples **per channel** in one wire frame.
    frame_samples: usize,
    /// Scratch for one ring read (preallocated).
    channel_scratch: Vec<i16>,
    /// Interleaved/mixed PCM scratch for one wire frame (preallocated).
    wire_scratch: Vec<i16>,
    /// Bytes in one wire frame.
    frame_bytes: usize,
    /// The bounded outbound frame channel the transport task drains.
    out: flume::Sender<Vec<u8>>,
    /// Buffers the transport task returns after writing them to the socket.
    recycle: flume::Receiver<Vec<u8>>,
    /// Free-list of wire buffers (primed at construction so steady state never allocates).
    spare: Vec<Vec<u8>>,
    forwarded: u64,
    dropped: u64,
}

impl TeeMixer {
    /// Assemble frames of `frame_samples` samples per channel across `channels` wire channels.
    /// Returns the mixer plus the frame receiver and the buffer-return sender for the transport.
    fn new(
        frame_samples: usize,
        channels: u8,
        stereo_source: bool,
        callee_only: bool,
    ) -> (Self, flume::Receiver<Vec<u8>>, flume::Sender<Vec<u8>>) {
        // The ceiling is 48 kHz × the engine's ptime cap, shared with the takeover bridge so the two
        // shells around the same PCM core cannot disagree about "the longest frame". It bounds the
        // *negotiated* length only — everything below sizes itself from the tee's own frame, so a
        // 20 ms tee allocates exactly what a 20 ms tee needs. Clamping at one 20 ms frame (as this
        // did) silently halved the wire frame of any tee that negotiated a longer `a=ptime`, so the
        // server received frames that did not match the `start` message's format.
        let frame_samples = frame_samples.clamp(1, MAX_FRAME_SAMPLES);
        let channels = channels.clamp(1, 2);
        let frame_bytes = frame_samples * usize::from(channels) * 2;
        let (out, frames) = flume::bounded(CHANNEL_DEPTH);
        let (recycle_tx, recycle) = flume::unbounded();
        // Prime the pool with one buffer per queued slot plus a couple in flight, so the steady-state
        // acquire always pops a recycled buffer and `write_pcm` never allocates.
        let pool_size = CHANNEL_DEPTH + 2;
        let mut spare = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            spare.push(Vec::with_capacity(frame_bytes));
        }
        let mixer = Self {
            rings: [
                SampleRing::new(frame_samples * RING_FRAMES),
                SampleRing::new(frame_samples * RING_FRAMES),
            ],
            channels,
            stereo_source,
            callee_only,
            frame_samples,
            channel_scratch: vec![0i16; frame_samples],
            wire_scratch: vec![0i16; frame_samples * usize::from(channels)],
            frame_bytes,
            out,
            recycle,
            spare,
            forwarded: 0,
            dropped: 0,
        };
        (mixer, frames, recycle_tx)
    }

    /// Wire frames handed to the transport so far.
    #[must_use]
    pub fn forwarded(&self) -> u64 {
        self.forwarded
    }

    /// Frames dropped because the outbound channel was full or closed, plus samples overwritten in a
    /// channel ring because the opposite channel stalled. Never a reason to stall the call.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Take a wire buffer from the pool, recycling anything the transport returned. Allocates only if
    /// the pool is momentarily empty (a transport that has not drained yet) — never in steady state.
    fn acquire(&mut self) -> Vec<u8> {
        if let Some(buffer) = self.spare.pop() {
            return buffer;
        }
        while self.spare.len() < self.spare.capacity() {
            match self.recycle.try_recv() {
                Ok(buffer) => self.spare.push(buffer),
                Err(_) => break,
            }
        }
        self.spare
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.frame_bytes))
    }

    /// Return a buffer to the pool (after a send that failed), without ever growing it.
    fn release(&mut self, buffer: Vec<u8>) {
        if self.spare.len() < self.spare.capacity() {
            self.spare.push(buffer);
        }
    }

    /// Whether every fed channel holds a full wire frame.
    fn frame_ready(&self) -> bool {
        if self.stereo_source {
            self.rings[0].len() >= self.frame_samples && self.rings[1].len() >= self.frame_samples
        } else {
            self.rings[usize::from(self.callee_only)].len() >= self.frame_samples
        }
    }

    /// Push one decoded frame for `channel` and emit every wire frame it completed.
    fn push(&mut self, channel: TeeChannel, pcm: &[i16]) {
        let index = channel.index();
        // Ignore a channel this tee never negotiated (e.g. a callee frame on a caller-only tee) rather
        // than silently folding it into the wrong slot.
        if !self.stereo_source && index != usize::from(self.callee_only) {
            return;
        }
        self.dropped += self.rings[index].push(pcm) as u64;
        while self.frame_ready() {
            self.emit();
        }
    }

    /// Assemble one wire frame from the rings and hand it to the transport.
    fn emit(&mut self) {
        let samples = self.frame_samples;
        if self.stereo_source {
            self.rings[0].read_into(&mut self.channel_scratch[..samples]);
            if self.channels == 2 {
                // Caller → even wire slots.
                for (index, &sample) in self.channel_scratch[..samples].iter().enumerate() {
                    self.wire_scratch[index * 2] = sample;
                }
            } else {
                self.wire_scratch[..samples].copy_from_slice(&self.channel_scratch[..samples]);
            }
            self.rings[1].read_into(&mut self.channel_scratch[..samples]);
            if self.channels == 2 {
                // Callee → odd wire slots.
                for (index, &sample) in self.channel_scratch[..samples].iter().enumerate() {
                    self.wire_scratch[index * 2 + 1] = sample;
                }
            } else {
                // Mono mix of both legs: saturating sum, never a wrap (a wrap would read as a click).
                for (slot, &other) in self.wire_scratch[..samples]
                    .iter_mut()
                    .zip(self.channel_scratch[..samples].iter())
                {
                    *slot = slot.saturating_add(other);
                }
            }
        } else {
            let fed = usize::from(self.callee_only);
            self.rings[fed].read_into(&mut self.wire_scratch[..samples]);
        }

        let wire_samples = samples * usize::from(self.channels);
        let mut buffer = self.acquire();
        buffer.clear();
        buffer.resize(self.frame_bytes, 0);
        let written = pcm_to_l16_le(&self.wire_scratch[..wire_samples], &mut buffer);
        buffer.truncate(written);
        match self.out.try_send(buffer) {
            Ok(()) => self.forwarded += 1,
            Err(flume::TrySendError::Full(buffer) | flume::TrySendError::Disconnected(buffer)) => {
                self.dropped += 1;
                self.release(buffer);
            }
        }
    }
}

/// One leg's [`MediaSink`] into a shared [`TeeMixer`]: frames the decoded PCM that leg produced onto
/// the tee's wire channel. Resamples first when the leg's codec rate differs from the tee's advertised
/// rate (a stereo tee over an AMR-WB access leg and a G.711 PSTN leg needs one common rate).
pub struct WsTeeSink {
    channel: TeeChannel,
    mixer: Arc<Mutex<TeeMixer>>,
    /// Detach label — the tee's stream id, so a tagged fork removal drops the tee without touching a
    /// SIPREC fork attached to the same leg.
    tag: String,
    /// Rate conversion into the tee's wire rate; `None` when this leg already runs at it.
    resampler: Option<siphon_rtp_dsp::resample::Resampler>,
    /// Reusable resample output (cleared, not reallocated, per frame).
    resampled: Vec<i16>,
}

impl WsTeeSink {
    /// A sink for `channel` feeding `mixer`, labelled `tag` for selective detach. `resampler` converts
    /// this leg's PCM into the tee's wire rate (`None` when the rates already match).
    #[must_use]
    pub fn new(
        channel: TeeChannel,
        mixer: Arc<Mutex<TeeMixer>>,
        tag: impl Into<String>,
        resampler: Option<siphon_rtp_dsp::resample::Resampler>,
    ) -> Self {
        // The scratch only ever holds one converted frame, so size it from the *output* rate and the
        // ptime ceiling — 960 samples for an 8 kHz tee, not the 48 kHz worst case — plus a sample of
        // slack for the polyphase remainder. A sink with no resampler never touches it, so it stays
        // empty rather than reserving for a conversion that will not happen.
        let resampled = match resampler.as_ref() {
            Some(resampler) => Vec::with_capacity(
                resampler.output_rate() as usize / 1000 * MAX_PTIME_MS + RESAMPLE_SLACK_SAMPLES,
            ),
            None => Vec::new(),
        };
        Self {
            channel,
            mixer,
            tag: tag.into(),
            resampler,
            resampled,
        }
    }
}

impl MediaSink for WsTeeSink {
    fn write_pcm(&mut self, pcm: &[i16]) {
        let frame: &[i16] = match self.resampler.as_mut() {
            Some(resampler) => {
                self.resampled.clear();
                resampler.process(pcm, &mut self.resampled);
                &self.resampled
            }
            None => pcm,
        };
        if frame.is_empty() {
            return;
        }
        // Uncontended by construction (one actor owns both of a call's directions), and the critical
        // section is a copy plus a `try_send` — never an `.await`, never a blocking call.
        if let Ok(mut mixer) = self.mixer.lock() {
            mixer.push(self.channel, frame);
        }
    }

    fn tag(&self) -> Option<&str> {
        Some(&self.tag)
    }
}

/// A tee's wire plan: the shared mixer plus what the transport needs to announce and drain it.
pub struct WsTeePlan {
    /// The shared frame assembler both sinks push into (also the `dropped` / `forwarded` counters).
    pub mixer: Arc<Mutex<TeeMixer>>,
    /// The bounded frame stream the transport writes to the socket.
    pub frames: flume::Receiver<Vec<u8>>,
    /// Where the transport returns drained buffers, so the sinks recycle them.
    pub recycle: flume::Sender<Vec<u8>>,
    /// The negotiated wire format, announced in the tee's `start` message.
    pub format: MediaFormat,
    /// Informational track labels for `start`: `inbound` (caller), `outbound` (callee), or both.
    pub tracks: Vec<String>,
}

/// Build a tee's mixer + channels for `format` (whose `sample_rate`, `channels` and `ptime` size the
/// wire frame). `stereo_source` says both legs feed it; `callee_only` picks the fed leg when only one
/// does.
#[must_use]
pub fn plan_ws_tee(format: MediaFormat, stereo_source: bool, callee_only: bool) -> WsTeePlan {
    let frame_samples = (format.sample_rate as usize / 1000) * usize::from(format.ptime.max(1));
    let (mixer, frames, recycle) =
        TeeMixer::new(frame_samples, format.channels, stereo_source, callee_only);
    let tracks = if stereo_source {
        vec!["inbound".to_string(), "outbound".to_string()]
    } else if callee_only {
        vec!["outbound".to_string()]
    } else {
        vec!["inbound".to_string()]
    };
    WsTeePlan {
        mixer: Arc::new(Mutex::new(mixer)),
        frames,
        recycle,
        format,
        tracks,
    }
}

/// The `start` message a tee sends as its first text frame. `direction` is always
/// [`Direction::Send`]: a v1 tee is send-only, so a server must not expect its audio to reach the call
/// (that is the duplex tee, a later addition).
#[must_use]
pub fn tee_start_message(
    stream_id: &str,
    call_id: &str,
    format: MediaFormat,
    tracks: Vec<String>,
) -> ControlMessage {
    ControlMessage::Start(StartData {
        stream_id: stream_id.to_string(),
        call_id: call_id.to_string(),
        direction: Direction::Send,
        media: format,
        tracks,
        metadata: None,
    })
}

/// Run a tee's transport until the server closes, sends `stop`, or the call side goes away: announce
/// `start`, then write each assembled wire frame as a binary frame and hand its buffer back to the
/// sink pool. Inbound binary frames are ignored — a v1 tee is send-only.
///
/// The copy into the WebSocket frame happens **here**, on the transport task, never on the media
/// pipeline's per-packet path. Generic over the socket IO so it tests over an in-memory duplex.
pub async fn run_ws_tee<S>(
    socket: WebSocketStream<S>,
    start: ControlMessage,
    frames: flume::Receiver<Vec<u8>>,
    recycle: flume::Sender<Vec<u8>>,
) -> Result<TeeEndReason, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = socket.split();
    sink.send(Message::text(start.to_json()?)).await?;

    let reason = loop {
        tokio::select! {
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(text))) => match ControlMessage::from_json(text.as_str()) {
                    Ok(ControlMessage::Stop(_)) => break TeeEndReason::ServerStopped,
                    Ok(_) => {} // a send-only tee has nothing to act on
                    Err(error) => tracing::debug!(%error, "ws tee ignoring malformed control frame"),
                },
                Some(Ok(Message::Close(_))) | None => break TeeEndReason::ServerClosed,
                Some(Ok(_)) => {} // inbound audio / ping / pong: ignored on a send-only tee
                Some(Err(error)) => return Err(error.into()),
            },
            received = frames.recv_async() => match received {
                Ok(frame) => {
                    let result = sink.send(Message::binary(Bytes::copy_from_slice(&frame))).await;
                    // Recycle the pooled buffer whatever the send outcome, so the sink keeps its
                    // allocation-free steady state. A closed channel just drops it.
                    let _ = recycle.send(frame);
                    result?;
                }
                Err(_) => break TeeEndReason::CallEnded, // every sink dropped — the call is gone
            },
        }
    };

    let _ = sink.send(Message::Close(None)).await;
    Ok(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::l16_le_to_pcm;
    use crate::bridge::protocol::{Encoding, Endianness, StopData};
    use crate::fanout::FanOut;
    use std::time::Duration;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::protocol::Role;

    fn format(sample_rate: u32, channels: u8) -> MediaFormat {
        MediaFormat {
            encoding: Encoding::L16,
            sample_rate,
            channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        }
    }

    fn samples(bytes: &[u8]) -> Vec<i16> {
        let mut pcm = vec![0i16; bytes.len() / 2];
        let count = l16_le_to_pcm(bytes, &mut pcm);
        pcm.truncate(count);
        pcm
    }

    #[test]
    fn a_caller_only_tee_streams_the_monologue_frame_by_frame() {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        sink.write_pcm(&[1234i16; 160]);

        let frame = plan.frames.try_recv().expect("one wire frame");
        assert_eq!(frame.len(), 320, "8k/20ms mono L16");
        assert_eq!(samples(&frame)[0], 1234);
        assert!(plan.frames.try_recv().is_err(), "exactly one frame");
    }

    /// A tee that negotiated a long `a=ptime` must assemble the wire frame it announced in `start`.
    /// The mixer used to clamp the frame at one 20 ms frame at 48 kHz, so a 48 kHz / 60 ms tee sent
    /// 960-sample frames while telling the server they were 2880 — a framing mismatch on every frame.
    #[test]
    fn a_long_ptime_tee_assembles_the_frame_length_it_announced() {
        let mut wire = format(48_000, 1);
        wire.ptime = 60;
        let plan = plan_ws_tee(wire, false, false);
        assert_eq!(
            plan.format.frame_bytes(),
            2 * 2880,
            "48 kHz × 60 ms mono L16"
        );

        let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        sink.write_pcm(&[321i16; 2880]);
        let frame = plan.frames.try_recv().expect("one wire frame");
        assert_eq!(
            frame.len(),
            plan.format.frame_bytes(),
            "the wire frame must match the announced format"
        );
        assert!(plan.frames.try_recv().is_err(), "exactly one frame");
    }

    #[test]
    fn a_caller_only_tee_ignores_callee_audio() {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let mut callee = WsTeeSink::new(TeeChannel::Callee, plan.mixer.clone(), "tee-1", None);
        callee.write_pcm(&[7i16; 160]);
        assert!(
            plan.frames.try_recv().is_err(),
            "a channel the tee did not negotiate must not surface"
        );
    }

    #[test]
    fn a_callee_only_tee_streams_the_callee_monologue() {
        let plan = plan_ws_tee(format(8000, 1), false, true);
        let mut callee = WsTeeSink::new(TeeChannel::Callee, plan.mixer.clone(), "tee-1", None);
        callee.write_pcm(&[-9i16; 160]);
        let frame = plan.frames.try_recv().expect("one wire frame");
        assert_eq!(samples(&frame)[0], -9);
    }

    #[test]
    fn a_stereo_tee_interleaves_caller_and_callee() {
        let plan = plan_ws_tee(format(8000, 2), true, false);
        let mut caller = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        let mut callee = WsTeeSink::new(TeeChannel::Callee, plan.mixer.clone(), "tee-1", None);

        // Only the caller has spoken: nothing yet — a stereo frame needs both channels.
        caller.write_pcm(&[100i16; 160]);
        assert!(
            plan.frames.try_recv().is_err(),
            "a stereo frame waits for both channels"
        );

        callee.write_pcm(&[-100i16; 160]);
        let frame = plan.frames.try_recv().expect("one stereo frame");
        assert_eq!(frame.len(), 640, "8k/20ms stereo L16 = 2 × 320");
        let pcm = samples(&frame);
        assert_eq!(pcm[0], 100, "channel 0 = caller");
        assert_eq!(pcm[1], -100, "channel 1 = callee");
        assert_eq!(pcm[2], 100);
        assert_eq!(pcm[3], -100);
    }

    #[test]
    fn a_both_legs_mono_tee_mixes_them_with_saturation() {
        let plan = plan_ws_tee(format(8000, 1), true, false);
        let mut caller = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        let mut callee = WsTeeSink::new(TeeChannel::Callee, plan.mixer.clone(), "tee-1", None);
        caller.write_pcm(&[30000i16; 160]);
        callee.write_pcm(&[30000i16; 160]);

        let frame = plan.frames.try_recv().expect("one mixed frame");
        assert_eq!(frame.len(), 320, "mixed to mono");
        assert_eq!(
            samples(&frame)[0],
            i16::MAX,
            "saturating sum, never wrapping"
        );
    }

    #[test]
    fn a_stalled_server_drops_frames_and_never_blocks() {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        // Nothing drains `plan.frames`; push far past the bounded depth. Must return every time.
        for _ in 0..(CHANNEL_DEPTH + 40) {
            sink.write_pcm(&[1i16; 160]);
        }
        let mixer = plan.mixer.lock().expect("lock");
        assert_eq!(
            mixer.forwarded() as usize,
            CHANNEL_DEPTH,
            "only the bounded capacity made it through"
        );
        assert!(mixer.dropped() > 0, "the rest were dropped, not queued");
    }

    #[test]
    fn a_silent_opposite_channel_bounds_the_ring_instead_of_growing_it() {
        // The callee never speaks: the caller's ring must stop at its cap, dropping the oldest.
        let plan = plan_ws_tee(format(8000, 2), true, false);
        let mut caller = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        for _ in 0..(RING_FRAMES + 20) {
            caller.write_pcm(&[5i16; 160]);
        }
        let mixer = plan.mixer.lock().expect("lock");
        assert_eq!(mixer.forwarded(), 0, "no stereo frame without the callee");
        assert!(
            mixer.dropped() >= 20 * 160,
            "the ring dropped the oldest samples rather than growing: {}",
            mixer.dropped()
        );
    }

    #[test]
    fn a_disconnected_transport_drops_without_panicking() {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        drop(plan.frames); // transport task gone
        sink.write_pcm(&[1i16; 160]); // must not panic
        assert_eq!(plan.mixer.lock().expect("lock").dropped(), 1);
    }

    #[test]
    fn a_sink_resamples_a_mismatched_leg_into_the_tee_rate() {
        // A 16 kHz leg teed at 8 kHz: a 320-sample ingress frame yields one 160-sample wire frame.
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let resampler =
            siphon_rtp_dsp::resample::Resampler::new(16_000, 8_000).expect("build resampler");
        let mut sink = WsTeeSink::new(
            TeeChannel::Caller,
            plan.mixer.clone(),
            "tee-1",
            Some(resampler),
        );
        sink.write_pcm(&[2000i16; 320]);
        let frame = plan.frames.try_recv().expect("one 8 kHz wire frame");
        assert_eq!(frame.len(), 320, "160 samples at 8 kHz");
    }

    /// A narrowband leg **upsampled** into a wider wire: an 8 kHz frame teed at 16 kHz must produce
    /// the 16 kHz frame the `start` envelope announces (320 samples = 640 bytes), not the leg's 160.
    #[test]
    fn an_8k_leg_teed_at_16k_frames_the_wire_rate_not_the_codec_rate() {
        use crate::bridge::wire_rate::wire_resampler;
        let plan = plan_ws_tee(format(16_000, 1), false, false);
        assert_eq!(plan.format.frame_bytes(), 640, "16 kHz × 20 ms mono L16");

        let resampler = wire_resampler(8_000, 16_000)
            .expect("serviceable")
            .expect("a conversion into the wider wire");
        let mut sink = WsTeeSink::new(
            TeeChannel::Caller,
            plan.mixer.clone(),
            "tee-1",
            Some(resampler),
        );
        sink.write_pcm(&[1500i16; 160]); // one 20 ms frame at the leg's 8 kHz

        let frame = plan.frames.try_recv().expect("one 16 kHz wire frame");
        assert_eq!(
            frame.len(),
            640,
            "320 samples at the negotiated 16 kHz wire rate"
        );
        assert!(plan.frames.try_recv().is_err(), "exactly one frame");

        match tee_start_message("tee-1", "call-1", plan.format, plan.tracks) {
            ControlMessage::Start(data) => assert_eq!(
                data.media.sample_rate, 16_000,
                "the start envelope must announce the wire rate, never the codec rate"
            ),
            other => panic!("expected start, got {other:?}"),
        }
    }

    /// The same, stereo: both 8 kHz legs upsampled into one 16 kHz interleaved wire frame.
    #[test]
    fn a_stereo_tee_at_16k_interleaves_two_upsampled_legs() {
        use crate::bridge::wire_rate::wire_resampler;
        let plan = plan_ws_tee(format(16_000, 2), true, false);
        let conversion = || {
            wire_resampler(8_000, 16_000)
                .expect("serviceable")
                .expect("a conversion")
        };
        let mut caller = WsTeeSink::new(
            TeeChannel::Caller,
            plan.mixer.clone(),
            "tee-1",
            Some(conversion()),
        );
        let mut callee = WsTeeSink::new(
            TeeChannel::Callee,
            plan.mixer.clone(),
            "tee-1",
            Some(conversion()),
        );

        caller.write_pcm(&[4000i16; 160]);
        assert!(
            plan.frames.try_recv().is_err(),
            "a stereo frame still waits for both channels"
        );
        callee.write_pcm(&[-4000i16; 160]);

        let frame = plan.frames.try_recv().expect("one stereo 16 kHz frame");
        assert_eq!(
            frame.len(),
            1280,
            "2 channels × 320 samples × 2 bytes at 16 kHz / 20 ms"
        );
        // Past the filter's start-up ramp the two channels stay separated and opposite in sign.
        let pcm = samples(&frame);
        let (caller_channel, callee_channel) = (pcm[200], pcm[201]);
        assert!(caller_channel > 0, "channel 0 carries the caller");
        assert!(callee_channel < 0, "channel 1 carries the callee");
    }

    /// A tee whose wire rate is the leg's own rate builds no resampler, so it pays nothing at all for
    /// having been asked explicitly for the rate it was already going to use.
    #[test]
    fn a_tee_at_the_leg_rate_builds_no_resampler_and_is_byte_identical() {
        use crate::bridge::wire_rate::wire_resampler;
        assert!(
            wire_resampler(8_000, 8_000).expect("identity").is_none(),
            "no conversion for a wire rate the leg already runs at"
        );

        let pcm: Vec<i16> = (0..160).map(|n| ((n * 211) % 6000) as i16 - 3000).collect();
        let render = || -> Vec<u8> {
            let plan = plan_ws_tee(format(8000, 1), false, false);
            let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
            sink.write_pcm(&pcm);
            plan.frames.try_recv().expect("one frame")
        };
        let baseline = render();
        assert_eq!(baseline.len(), 320);
        assert_eq!(
            samples(&baseline),
            pcm,
            "an identity tee copies the PCM through"
        );
    }

    #[test]
    fn the_sink_reports_its_detach_tag() {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer, "tee-abc", None);
        assert_eq!(MediaSink::tag(&sink), Some("tee-abc"));
    }

    #[test]
    fn a_tee_coexists_with_another_sink_on_the_same_fanout() {
        // The tee is just another `MediaSink`: the SIPREC fork beside it keeps receiving frames.
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let (fork_tx, fork_rx) = flume::bounded(4);
        let mut fanout = FanOut::new();
        fanout.add(Box::new(crate::fork::RtpForkSink::new(
            Box::new(siphon_rtp_codec::g711::G711::ulaw()),
            fork_tx,
            0xFEED_BEEF,
            0,
        )));
        fanout.add(Box::new(WsTeeSink::new(
            TeeChannel::Caller,
            plan.mixer.clone(),
            "tee-1",
            None,
        )));
        fanout.write_pcm(&[321i16; 160]);
        assert!(fork_rx.try_recv().is_ok(), "the SIPREC fork still fires");
        assert!(plan.frames.try_recv().is_ok(), "and so does the tee");
    }

    #[test]
    fn the_start_message_announces_a_send_only_stereo_stream() {
        let plan = plan_ws_tee(format(16_000, 2), true, false);
        match tee_start_message("tee-1", "call-1", plan.format, plan.tracks) {
            ControlMessage::Start(data) => {
                assert_eq!(data.direction, Direction::Send, "a v1 tee is send-only");
                assert_eq!(data.media.channels, 2);
                assert_eq!(data.media.sample_rate, 16_000);
                assert_eq!(data.tracks, vec!["inbound", "outbound"]);
            }
            other => panic!("expected start, got {other:?}"),
        }
    }

    /// The wire-buffer pool is recycled rather than regrown: a drained tee returns every buffer, so the
    /// free list stays at its primed size no matter how many frames pass through. (The *allocation*
    /// invariant itself is proven under a counting global allocator in
    /// `tests/ws_tee_zero_alloc.rs`.)
    #[test]
    fn the_wire_buffer_pool_is_recycled_not_regrown() {
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
        // Cycle far more frames than the pool holds, draining and recycling as the transport would.
        for _ in 0..500 {
            sink.write_pcm(&[42i16; 160]);
            let frame = plan.frames.try_recv().expect("drained");
            plan.recycle.send(frame).expect("recycle");
        }
        let mixer = plan.mixer.lock().expect("lock");
        assert_eq!(mixer.forwarded(), 500, "every frame made it through");
        assert_eq!(mixer.dropped(), 0, "no drops with a draining transport");
        assert_eq!(
            mixer.spare.len() + mixer.recycle.len(),
            CHANNEL_DEPTH + 2,
            "the pool holds exactly its primed buffer count: {} spare + {} returning",
            mixer.spare.len(),
            mixer.recycle.len()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_transport_announces_start_then_streams_binary_frames() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_ws = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let client_ws = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;

        let plan = plan_ws_tee(format(8000, 1), false, false);
        let start = tee_start_message("tee-1", "call-1", plan.format, plan.tracks.clone());
        let mixer = plan.mixer.clone();
        let transport = tokio::spawn(run_ws_tee(server_ws, start, plan.frames, plan.recycle));

        let (mut client_tx, mut client_rx) = client_ws.split();

        // 1. `start` first, announcing a send-only stream.
        let first = timeout(Duration::from_secs(2), client_rx.next())
            .await
            .expect("no timeout")
            .expect("some")
            .expect("ok");
        match first {
            Message::Text(text) => match ControlMessage::from_json(text.as_str()) {
                Ok(ControlMessage::Start(data)) => {
                    assert_eq!(data.direction, Direction::Send);
                    assert_eq!(data.stream_id, "tee-1");
                }
                other => panic!("expected start, got {other:?}"),
            },
            other => panic!("expected a text frame, got {other:?}"),
        }

        // 2. A decoded frame on the sink surfaces as a binary WS frame.
        let mut sink = WsTeeSink::new(TeeChannel::Caller, mixer, "tee-1", None);
        sink.write_pcm(&[555i16; 160]);
        let audio = timeout(Duration::from_secs(2), client_rx.next())
            .await
            .expect("no timeout")
            .expect("some")
            .expect("ok");
        match audio {
            Message::Binary(bytes) => {
                assert_eq!(bytes.len(), 320);
                assert_eq!(samples(&bytes)[0], 555);
            }
            other => panic!("expected a binary frame, got {other:?}"),
        }

        // 3. `stop` from the server ends the tee with that reason.
        let stop = ControlMessage::Stop(StopData {
            stream_id: "tee-1".into(),
            reason: "done".into(),
        });
        client_tx
            .send(Message::text(stop.to_json().expect("json")))
            .await
            .expect("send stop");
        let outcome = timeout(Duration::from_secs(2), transport)
            .await
            .expect("join")
            .expect("task");
        assert_eq!(outcome.expect("clean exit"), TeeEndReason::ServerStopped);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_transport_reports_the_call_ending() {
        let (_client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_ws = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let plan = plan_ws_tee(format(8000, 1), false, false);
        let start = tee_start_message("tee-1", "call-1", plan.format, plan.tracks.clone());
        let frames = plan.frames;
        let transport = tokio::spawn(run_ws_tee(server_ws, start, frames, plan.recycle));
        // Dropping the mixer drops the sender half of the frame channel — the call side is gone.
        drop(plan.mixer);
        let outcome = timeout(Duration::from_secs(2), transport)
            .await
            .expect("join")
            .expect("task");
        assert_eq!(outcome.expect("clean exit"), TeeEndReason::CallEnded);
    }
}
