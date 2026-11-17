//! The **multi-source mixer**: several independent calls feeding one recording or one WebSocket tee,
//! a channel per call, kept on one clock.
//!
//! SIPREC (RFC 7866) hands a recorder each recorded stream as its own RTP session, so on this engine
//! each is a call of its own with its own media actor. [`super::tee::TeeMixer`] cannot join them: it
//! is fed by the *two directions of one call*, which one actor owns, and it waits for a frame on both
//! channels. Streams from separate calls start at different moments, pause at different moments
//! (silence suppression, hold) and arrive on separate threads, so the frame assembler here is an
//! actor of its own and the sources reach it only through bounded queues:
//!
//! * Each source call gets a [`MultiSourceSink`], a [`MediaSink`] on that call's post-decode fan-out.
//!   `write_pcm` converts into the recording rate, copies the frame into a pooled buffer and `try_send`s
//!   it on a **bounded** per-source queue, dropping the newest frame (and counting it) when full. No
//!   lock is shared between calls and nothing on the media path blocks or allocates in steady state.
//! * [`MultiSourceMixer`] owns one sample ring per source and runs on **its own clock**: every
//!   `ptime` it takes one frame from each source and emits the interleaved (stereo) or summed (mono)
//!   result. A source with nothing to give contributes silence for that tick, which is what keeps a
//!   source that starts late, or goes quiet, on the same timeline as the others instead of sliding
//!   against them. The clock starts when the first source has audio, so a recording is not preceded
//!   by silence while no media has arrived.
//! * **Jitter allowance.** A source starts playing once it holds `PRIME_FRAMES` frames (or after
//!   `PRIME_TIMEOUT_TICKS` ticks with something buffered, so a short blip is not stranded), which
//!   absorbs the phase difference between a source's own packet clock and the mixer's. When its ring
//!   runs dry it falls back to priming, so a resumed talkspurt is buffered again. Each ring holds
//!   `RING_FRAMES` frames and drops the oldest beyond that: late audio is worthless.
//! * **Missed ticks.** The interval uses [`tokio::time::MissedTickBehavior::Burst`]: after a stall the
//!   mixer catches up, emitting the frames it owes back to back. Audio that queued during the stall is
//!   played, in order, and every source is advanced together; `Delay` or `Skip` would leave a backlog
//!   in the rings that is then dropped, losing audio and shifting it later than real time.
//! * **Ending.** The mixer ends when its [`MultiSourceControl`] is dropped (or a source's queue
//!   disconnects): it drains what the sources queued, emits what its rings still hold, and drops its
//!   output, which is what tells the writer behind it to finalize.
//!
//! The output is the same shape [`super::tee::TeeMixer`] produces (bounded channel of little-endian
//! L16 wire frames, buffers returned through a recycle channel), so the recorder and the tee
//! transport behind it are the ones a single-call recording and tee already use.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_dsp::resample::Resampler;

use crate::bridge::audio::{MAX_FRAME_SAMPLES, MAX_PTIME_MS};
use crate::bridge::pcm_to_l16_le;
use crate::bridge::protocol::MediaFormat;
use crate::bridge::tee::SampleRing;
use crate::fanout::MediaSink;

/// The most sources one mixer takes (the same ceiling as the control contract's
/// `MAX_RECORDING_SOURCES`).
pub const MAX_SOURCES: usize = 8;

/// Frames a source's queue holds between its sink and the mixer. Bounded: a stalled mixer drops the
/// newest frames rather than growing a queue.
const SOURCE_QUEUE_DEPTH: usize = 16;

/// Buffers circulating per source: one per queue slot plus a couple in flight.
const SOURCE_POOL: usize = SOURCE_QUEUE_DEPTH + 2;

/// Wire frames the output holds between the mixer and the writer.
const OUTPUT_QUEUE_DEPTH: usize = 16;

/// Frames a source must hold before it starts to play out (the jitter allowance).
const PRIME_FRAMES: usize = 2;

/// Frames of audio a source's ring holds; beyond it the oldest is dropped.
const RING_FRAMES: usize = 8;

/// Ticks a source with something buffered waits for [`PRIME_FRAMES`] before it plays anyway.
const PRIME_TIMEOUT_TICKS: u32 = 3;

/// Headroom on the resample scratch for the polyphase filter's fractional remainder.
const RESAMPLE_SLACK_SAMPLES: usize = 8;

/// Why a mixer could not be planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MultiSourceError {
    /// A mixer takes 2 to [`MAX_SOURCES`] sources.
    #[error("{0} sources: a multi-source stream takes 2 to {MAX_SOURCES}")]
    SourceCount(usize),
    /// Stereo has two channels, so it can carry exactly two sources.
    #[error("a stereo stream carries exactly 2 sources, not {0}")]
    StereoSourceCount(usize),
    /// Only mono and stereo are wire channel counts.
    #[error("{0} channels: a stream is mono (1) or stereo (2)")]
    Channels(u8),
}

/// Lifetime counters of one mixer, shared with whoever reports them.
#[derive(Debug, Default)]
pub struct MultiSourceStats {
    forwarded: AtomicU64,
    dropped: AtomicU64,
}

impl MultiSourceStats {
    /// Wire frames handed to the writer or transport.
    #[must_use]
    pub fn forwarded(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    /// Frames lost: a source queue or the output was full, a ring overflowed, or a leg frame could not
    /// be decoded. Never a reason to stall a call.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn note_dropped(&self, frames: u64) {
        self.dropped.fetch_add(frames, Ordering::Relaxed);
    }
}

/// Everything [`plan_multi_source`] builds: the mixer to run, the handle that feeds and ends it, and
/// the output the writer or transport drains.
pub struct MultiSourcePlan {
    /// The actor. Run it with [`MultiSourceMixer::run`].
    pub mixer: MultiSourceMixer,
    /// Makes the sinks and, dropped, ends the mixer.
    pub control: MultiSourceControl,
    /// The bounded wire-frame stream the writer or transport drains.
    pub frames: flume::Receiver<Vec<u8>>,
    /// Where the consumer returns drained buffers.
    pub recycle: flume::Sender<Vec<u8>>,
    /// The mixer's counters.
    pub stats: Arc<MultiSourceStats>,
    /// The wire format of `frames`.
    pub format: MediaFormat,
    /// Informational track labels for a tee's `start` message, one per source.
    pub tracks: Vec<String>,
}

/// Plan a mixer for `sources` calls producing `format` (its rate, channel count and `ptime` size the
/// frame). Stereo carries exactly two sources, source 0 on the left; mono sums them all.
///
/// # Errors
///
/// A source count outside 2 to [`MAX_SOURCES`], stereo with other than two, or a channel count that
/// is neither 1 nor 2.
pub fn plan_multi_source(
    format: MediaFormat,
    sources: usize,
) -> Result<MultiSourcePlan, MultiSourceError> {
    if !(2..=MAX_SOURCES).contains(&sources) {
        return Err(MultiSourceError::SourceCount(sources));
    }
    match format.channels {
        1 => {}
        2 if sources == 2 => {}
        2 => return Err(MultiSourceError::StereoSourceCount(sources)),
        other => return Err(MultiSourceError::Channels(other)),
    }
    let ptime = format.ptime.max(1);
    // The ceiling is the engine's ptime cap, shared with the tee, so the two cannot disagree about
    // "the longest frame"; everything below sizes itself from this mixer's own frame.
    let frame_samples =
        ((format.sample_rate as usize / 1000) * usize::from(ptime)).clamp(1, MAX_FRAME_SAMPLES);
    let frame_bytes = frame_samples * usize::from(format.channels) * 2;
    let (out, frames) = flume::bounded(OUTPUT_QUEUE_DEPTH);
    let (recycle_tx, recycle) = flume::unbounded();
    let mut spare = Vec::with_capacity(OUTPUT_QUEUE_DEPTH + 2);
    for _ in 0..OUTPUT_QUEUE_DEPTH + 2 {
        spare.push(Vec::with_capacity(frame_bytes));
    }
    let stats = Arc::new(MultiSourceStats::default());
    let (stop_tx, stop) = flume::bounded(1);

    let mut states = Vec::with_capacity(sources);
    let mut senders = Vec::with_capacity(sources);
    let mut recycles = Vec::with_capacity(sources);
    for _ in 0..sources {
        let (queue_tx, queue) = flume::bounded(SOURCE_QUEUE_DEPTH);
        let (return_tx, return_rx) = flume::unbounded();
        states.push(SourceState {
            queue,
            returned: return_tx,
            ring: SampleRing::new(frame_samples * RING_FRAMES),
            playing: false,
            waiting_ticks: 0,
        });
        senders.push(queue_tx);
        recycles.push(return_rx);
    }
    let mixer = MultiSourceMixer {
        frame_samples,
        channels: format.channels,
        period: Duration::from_millis(u64::from(ptime)),
        sources: states,
        stop,
        wire: vec![0i16; frame_samples * usize::from(format.channels)],
        scratch: vec![0i16; frame_samples],
        frame_bytes,
        out,
        recycle,
        spare,
        stats: stats.clone(),
        started: false,
    };
    let control = MultiSourceControl {
        senders,
        recycles,
        rate: format.sample_rate,
        stats: stats.clone(),
        _stop: stop_tx,
    };
    let tracks = (0..sources)
        .map(|index| format!("source-{index}"))
        .collect();
    Ok(MultiSourcePlan {
        mixer,
        control,
        frames,
        recycle: recycle_tx,
        stats,
        format,
        tracks,
    })
}

/// The handle on a running mixer: builds the sinks that feed it, and **ends it when dropped**.
///
/// It holds a sender for every source, so a source whose call is re-negotiated can be given a fresh
/// sink (the old one goes with the actor the answer replaced) without the mixer ever seeing the
/// source close in between. The mixer therefore ends on this handle, not on a sink being dropped.
pub struct MultiSourceControl {
    senders: Vec<flume::Sender<Vec<i16>>>,
    recycles: Vec<flume::Receiver<Vec<i16>>>,
    rate: u32,
    stats: Arc<MultiSourceStats>,
    /// Never sent on: the mixer reads this channel disconnecting as "end".
    _stop: flume::Sender<()>,
}

impl MultiSourceControl {
    /// A sink feeding `source`, labelled `tag` for a tagged detach, converting its leg's PCM with
    /// `resampler` (`None` when the leg already runs at the mixer's rate). `None` when `source` is not
    /// one of this mixer's.
    #[must_use]
    pub fn sink(
        &self,
        source: usize,
        resampler: Option<Resampler>,
        tag: impl Into<String>,
    ) -> Option<MultiSourceSink> {
        let queue = self.senders.get(source)?.clone();
        let returned = self.recycles.get(source)?.clone();
        // One converted frame at the mixer's rate and the engine's ptime ceiling, plus the polyphase
        // remainder: a leg frame never outgrows the buffer it is copied into.
        let capacity = self.rate as usize / 1000 * MAX_PTIME_MS + RESAMPLE_SLACK_SAMPLES;
        let mut spare = Vec::with_capacity(SOURCE_POOL);
        for _ in 0..SOURCE_POOL {
            spare.push(Vec::with_capacity(capacity));
        }
        let resampled = match resampler {
            Some(_) => Vec::with_capacity(capacity),
            None => Vec::new(),
        };
        Some(MultiSourceSink {
            tag: tag.into(),
            queue,
            returned,
            spare,
            resampler,
            resampled,
            stats: self.stats.clone(),
        })
    }

    /// How many sources the mixer has.
    #[must_use]
    pub fn sources(&self) -> usize {
        self.senders.len()
    }
}

/// One source call's [`MediaSink`] into a [`MultiSourceMixer`].
pub struct MultiSourceSink {
    tag: String,
    queue: flume::Sender<Vec<i16>>,
    /// Buffers the mixer has drained, coming back to be reused.
    returned: flume::Receiver<Vec<i16>>,
    spare: Vec<Vec<i16>>,
    resampler: Option<Resampler>,
    /// Reusable resample output (cleared, not reallocated, per frame).
    resampled: Vec<i16>,
    stats: Arc<MultiSourceStats>,
}

impl MediaSink for MultiSourceSink {
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
        // A buffer from the sink's own pool, else one the mixer returned; none when every buffer is
        // queued, which is the queue being full.
        let Some(mut buffer) = self.spare.pop().or_else(|| self.returned.try_recv().ok()) else {
            self.stats.note_dropped(1);
            return;
        };
        buffer.clear();
        buffer.extend_from_slice(frame);
        match self.queue.try_send(buffer) {
            Ok(()) => {}
            // The newest frame is the one dropped: what is queued is older and closer to being
            // played, and late audio is worthless.
            Err(flume::TrySendError::Full(buffer) | flume::TrySendError::Disconnected(buffer)) => {
                self.stats.note_dropped(1);
                if self.spare.len() < self.spare.capacity() {
                    self.spare.push(buffer);
                }
            }
        }
    }

    fn frame_undecodable(&mut self) {
        self.stats.note_dropped(1);
    }

    fn tag(&self) -> Option<&str> {
        Some(&self.tag)
    }
}

/// One source's state inside the mixer.
struct SourceState {
    queue: flume::Receiver<Vec<i16>>,
    /// Drained buffers go back to the sink through here.
    returned: flume::Sender<Vec<i16>>,
    ring: SampleRing,
    /// Whether the source is being played out (primed), as opposed to waiting to be.
    playing: bool,
    /// Ticks spent not playing with something buffered.
    waiting_ticks: u32,
}

/// The aligning frame assembler. See the [module documentation](self).
pub struct MultiSourceMixer {
    frame_samples: usize,
    channels: u8,
    period: Duration,
    sources: Vec<SourceState>,
    /// Disconnects when the [`MultiSourceControl`] is dropped.
    stop: flume::Receiver<()>,
    /// Interleaved / mixed PCM for one wire frame (preallocated).
    wire: Vec<i16>,
    /// One source's frame (preallocated).
    scratch: Vec<i16>,
    frame_bytes: usize,
    out: flume::Sender<Vec<u8>>,
    /// Buffers the consumer returned.
    recycle: flume::Receiver<Vec<u8>>,
    spare: Vec<Vec<u8>>,
    stats: Arc<MultiSourceStats>,
    /// Whether the clock has started (some source has had audio).
    started: bool,
}

impl MultiSourceMixer {
    /// Run the mixer's clock until it ends. Ends when the [`MultiSourceControl`] is dropped.
    ///
    /// Cancellation-safe: dropping the future between ticks loses nothing the rings hold beyond what
    /// dropping the mixer does.
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(self.period);
        // See the module documentation: catch up after a stall rather than shed audio.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.stop.recv_async() => {}
            }
            if !self.tick() {
                break;
            }
        }
    }

    /// One tick of the clock: drain what the sources queued and emit one frame. `false` once the
    /// mixer has ended and flushed, after which it has nothing more to do.
    ///
    /// Public so a benchmark and a logical-clock test can drive the clock themselves.
    pub fn tick(&mut self) -> bool {
        let ended = self.drain() || self.stop.is_disconnected();
        if ended {
            // One more look: a frame queued between the drain and the stop is not lost.
            self.drain();
            self.flush();
            return false;
        }
        self.update_playing();
        if !self.started {
            if !self.sources.iter().any(|source| source.playing) {
                return true;
            }
            self.started = true;
        }
        self.emit_frame();
        true
    }

    /// Move everything the sources queued into their rings. `true` when a source's queue has
    /// disconnected.
    fn drain(&mut self) -> bool {
        let frame_samples = self.frame_samples;
        let stats = &self.stats;
        let mut disconnected = false;
        for source in &mut self.sources {
            loop {
                match source.queue.try_recv() {
                    Ok(buffer) => {
                        let overflow = source.ring.push(&buffer);
                        if overflow > 0 {
                            stats.note_dropped(overflow.div_ceil(frame_samples) as u64);
                        }
                        // The sink may be gone; the buffer is then just dropped.
                        let _ = source.returned.send(buffer);
                    }
                    Err(flume::TryRecvError::Empty) => break,
                    Err(flume::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        disconnected
    }

    /// Start playing the sources that have buffered enough.
    fn update_playing(&mut self) {
        let frame_samples = self.frame_samples;
        for source in &mut self.sources {
            if source.playing {
                continue;
            }
            let buffered = source.ring.len();
            if buffered >= PRIME_FRAMES * frame_samples {
                source.playing = true;
            } else if buffered > 0 {
                source.waiting_ticks += 1;
                source.playing = source.waiting_ticks >= PRIME_TIMEOUT_TICKS;
            } else {
                source.waiting_ticks = 0;
            }
            if source.playing {
                source.waiting_ticks = 0;
            }
        }
    }

    /// Emit what every ring still holds, the last partial frame padded with silence.
    fn flush(&mut self) {
        for source in &mut self.sources {
            source.playing = source.ring.len() > 0;
        }
        while self.sources.iter().any(|source| source.ring.len() > 0) {
            self.emit_frame();
        }
    }

    /// Assemble one wire frame: one frame from each playing source, silence from the others.
    fn emit_frame(&mut self) {
        let samples = self.frame_samples;
        let stereo = self.channels == 2;
        if !stereo {
            self.wire[..samples].fill(0);
        }
        for (index, source) in self.sources.iter_mut().enumerate() {
            if source.playing {
                // A ring short of a frame is a talkspurt that has ended: its tail goes out padded
                // with silence, and the source waits to be primed again.
                if source.ring.len() < samples {
                    source.playing = false;
                    source.ring.pad_to(samples);
                }
                source.ring.read_into(&mut self.scratch[..samples]);
            } else {
                self.scratch[..samples].fill(0);
            }
            if stereo {
                for (slot, &sample) in self.scratch[..samples].iter().enumerate() {
                    self.wire[slot * 2 + index] = sample;
                }
            } else {
                // Saturating sum, never a wrap (a wrap would read as a click).
                for (slot, &sample) in self.wire[..samples]
                    .iter_mut()
                    .zip(self.scratch[..samples].iter())
                {
                    *slot = slot.saturating_add(sample);
                }
            }
        }
        let wire_samples = samples * usize::from(self.channels);
        let mut buffer = self.acquire();
        buffer.clear();
        buffer.resize(self.frame_bytes, 0);
        let written = pcm_to_l16_le(&self.wire[..wire_samples], &mut buffer);
        buffer.truncate(written);
        match self.out.try_send(buffer) {
            Ok(()) => {
                self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            Err(flume::TrySendError::Full(buffer) | flume::TrySendError::Disconnected(buffer)) => {
                self.stats.note_dropped(1);
                if self.spare.len() < self.spare.capacity() {
                    self.spare.push(buffer);
                }
            }
        }
    }

    /// A wire buffer from the pool, recycling what the consumer returned. Allocates only if the pool
    /// is momentarily empty (a consumer that has not drained yet), never in steady state.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::l16_le_to_pcm;
    use crate::bridge::protocol::{Encoding, Endianness};

    const FRAME: usize = 160;

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

    /// Every frame the output holds, as samples.
    fn drained(plan: &MultiSourcePlan) -> Vec<Vec<i16>> {
        let mut frames = Vec::new();
        while let Ok(frame) = plan.frames.try_recv() {
            frames.push(samples(&frame));
            let _ = plan.recycle.send(frame);
        }
        frames
    }

    /// One tick of the logical clock, after each `(source, level)` queued a frame.
    fn step(
        plan: &mut MultiSourcePlan,
        sinks: &mut [MultiSourceSink],
        speaking: &[(usize, i16)],
    ) -> Vec<Vec<i16>> {
        for &(source, level) in speaking {
            sinks[source].write_pcm(&[level; FRAME]);
        }
        assert!(plan.mixer.tick(), "the mixer is still running");
        drained(plan)
    }

    fn sinks_of(plan: &MultiSourcePlan) -> Vec<MultiSourceSink> {
        (0..plan.control.sources())
            .map(|index| plan.control.sink(index, None, "rec-1").expect("sink"))
            .collect()
    }

    #[test]
    fn the_source_count_and_channel_count_are_validated() {
        for sources in [0, 1, 9, 100] {
            assert!(matches!(
                plan_multi_source(format(8000, 1), sources),
                Err(MultiSourceError::SourceCount(count)) if count == sources
            ));
        }
        assert!(matches!(
            plan_multi_source(format(8000, 2), 3),
            Err(MultiSourceError::StereoSourceCount(3))
        ));
        assert!(matches!(
            plan_multi_source(format(8000, 3), 2),
            Err(MultiSourceError::Channels(3))
        ));
        assert!(plan_multi_source(format(8000, 2), 2).is_ok());
        assert!(plan_multi_source(format(8000, 1), MAX_SOURCES).is_ok());
        let display = MultiSourceError::SourceCount(9).to_string();
        assert!(display.contains("2 to 8"), "{display}");
    }

    #[test]
    fn nothing_is_emitted_until_a_source_has_audio() {
        let mut plan = plan_multi_source(format(8000, 2), 2).expect("plan");
        for _ in 0..10 {
            assert!(plan.mixer.tick());
        }
        assert!(drained(&plan).is_empty(), "no silence before any media");
    }

    #[test]
    fn a_stereo_frame_has_source_zero_left_and_source_one_right() {
        let mut plan = plan_multi_source(format(8000, 2), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        let both = [(0, 1000), (1, -2000)];
        let mut out = Vec::new();
        for _ in 0..4 {
            out.extend(step(&mut plan, &mut sinks, &both));
        }
        assert!(!out.is_empty());
        for frame in &out {
            assert_eq!(frame.len(), 2 * FRAME, "stereo 8 kHz 20 ms");
            for pair in frame.chunks(2) {
                assert_eq!(pair, [1000, -2000], "left is source 0, right is source 1");
            }
        }
    }

    #[test]
    fn a_mono_stream_sums_every_source_and_saturates() {
        let mut plan = plan_multi_source(format(8000, 1), 3).expect("plan");
        let mut sinks = sinks_of(&plan);
        let all = [(0, 100), (1, 200), (2, 300)];
        let mut out = Vec::new();
        for _ in 0..4 {
            out.extend(step(&mut plan, &mut sinks, &all));
        }
        assert!(out.iter().all(|frame| frame.iter().all(|&s| s == 600)));

        let mut plan = plan_multi_source(format(8000, 1), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        let loud = [(0, i16::MAX), (1, i16::MAX)];
        let mut out = Vec::new();
        for _ in 0..4 {
            out.extend(step(&mut plan, &mut sinks, &loud));
        }
        assert!(
            out.iter().all(|frame| frame.iter().all(|&s| s == i16::MAX)),
            "a sum past full scale clamps instead of wrapping"
        );
    }

    /// Output frame `n` is tick `start + n`. A source that begins later is silent until it does, and
    /// then lands at the same output position it would have had on a shared clock.
    #[test]
    fn a_source_that_starts_late_stays_aligned_to_the_clock() {
        const LATE: usize = 15;
        let mut plan = plan_multi_source(format(8000, 2), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        let mut out = Vec::new();
        for tick in 0..40 {
            let speaking: &[(usize, i16)] = if tick < LATE {
                &[(0, 1000)]
            } else {
                &[(0, 1000), (1, -2000)]
            };
            out.extend(step(&mut plan, &mut sinks, speaking));
        }
        let right_start = out
            .iter()
            .position(|frame| frame.chunks(2).any(|pair| pair[1] != 0))
            .expect("the late source is heard");
        assert!(
            right_start.abs_diff(LATE) <= 1,
            "the late source starts at output frame {right_start}, expected {LATE} (+/- 1)"
        );
        // Before it starts the right channel is exactly silent and the left is already speaking.
        for frame in &out[..right_start] {
            assert!(frame.chunks(2).all(|pair| pair[0] == 1000 && pair[1] == 0));
        }
        // After it starts, both are there, with nothing missing in between.
        for frame in &out[right_start + 1..] {
            assert!(frame.chunks(2).all(|pair| pair == [1000, -2000]));
        }
    }

    #[test]
    fn a_source_that_goes_quiet_is_silent_for_the_gap_and_resumes_in_place() {
        const QUIET_FROM: usize = 10;
        const QUIET_UNTIL: usize = 25;
        let mut plan = plan_multi_source(format(8000, 2), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        let mut out = Vec::new();
        for tick in 0..45 {
            let speaking: &[(usize, i16)] = if (QUIET_FROM..QUIET_UNTIL).contains(&tick) {
                &[(1, -2000)]
            } else {
                &[(0, 1000), (1, -2000)]
            };
            out.extend(step(&mut plan, &mut sinks, speaking));
        }
        // Source 1 never stops, so its channel is the clock: it is present in every frame, and
        // source 0 is heard again at the position the clock gives it after the gap.
        assert!(out
            .iter()
            .skip(2)
            .all(|frame| frame.chunks(2).all(|pair| pair[1] == -2000)));
        let gap: Vec<bool> = out
            .iter()
            .map(|frame| frame.chunks(2).all(|pair| pair[0] == 0))
            .collect();
        let first_silent = gap.iter().position(|&silent| silent).expect("a gap");
        let resumed = gap
            .iter()
            .enumerate()
            .skip(first_silent)
            .find(|(_, &silent)| !silent)
            .map(|(index, _)| index)
            .expect("it resumes");
        assert!(
            first_silent.abs_diff(QUIET_FROM) <= 2,
            "the gap starts at {first_silent}, expected {QUIET_FROM} (+/- 2)"
        );
        assert!(
            resumed.abs_diff(QUIET_UNTIL) <= 2,
            "the source resumes at {resumed}, expected {QUIET_UNTIL} (+/- 2)"
        );
    }

    #[test]
    fn a_ring_that_overflows_keeps_the_newest_audio_and_counts_the_loss() {
        let mut plan = plan_multi_source(format(8000, 1), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        // Far more than the queue (16) and the ring (8) hold, in one burst.
        for level in 1..=30i16 {
            sinks[0].write_pcm(&[level; FRAME]);
        }
        assert!(plan.mixer.tick());
        assert!(
            plan.stats.dropped() > 0,
            "the frames that did not fit were counted"
        );
        let frame = &drained(&plan)[0];
        // The queue refused the newest 14 (levels 17..=30); the ring kept the last 8 of the 16 it
        // was given (levels 9..=16), so playout starts at 9 and never at the oldest, level 1.
        assert_eq!(frame[0], 9, "the oldest queued audio was the first dropped");
    }

    #[test]
    fn a_stalled_consumer_drops_output_frames_instead_of_growing_a_queue() {
        let mut plan = plan_multi_source(format(8000, 1), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        for _ in 0..(OUTPUT_QUEUE_DEPTH * 3) {
            sinks[0].write_pcm(&[5; FRAME]);
            assert!(plan.mixer.tick());
        }
        assert_eq!(plan.frames.len(), OUTPUT_QUEUE_DEPTH, "bounded");
        assert!(plan.stats.dropped() > 0);
        assert_eq!(plan.stats.forwarded(), OUTPUT_QUEUE_DEPTH as u64);
    }

    #[test]
    fn ending_emits_what_the_rings_hold_and_closes_the_output() {
        let mut plan = plan_multi_source(format(8000, 2), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        let both = [(0, 1000), (1, -2000)];
        let mut out = Vec::new();
        for _ in 0..3 {
            out.extend(step(&mut plan, &mut sinks, &both));
        }
        let before = out.len();
        // Queued but not yet ticked: the tail a deleted call must not lose.
        sinks[0].write_pcm(&[1000; FRAME]);
        sinks[1].write_pcm(&[-2000; FRAME]);
        let MultiSourcePlan {
            mut mixer,
            control,
            frames,
            recycle,
            ..
        } = plan;
        drop(control);
        assert!(!mixer.tick(), "the mixer ends once its handle is dropped");
        drop(mixer);
        let mut tail = Vec::new();
        while let Ok(frame) = frames.try_recv() {
            tail.push(samples(&frame));
            let _ = recycle.send(frame);
        }
        assert!(
            tail.iter()
                .any(|frame| frame.chunks(2).all(|pair| pair == [1000, -2000])),
            "the queued frame was flushed ({before} frames earlier, {} in the tail)",
            tail.len()
        );
        assert!(
            frames.recv().is_err(),
            "the output is closed, which is what tells a writer to finalize"
        );
    }

    #[test]
    fn a_long_talkspurt_end_pads_the_tail_and_waits_to_be_primed_again() {
        let mut plan = plan_multi_source(format(8000, 1), 2).expect("plan");
        let mut sinks = sinks_of(&plan);
        // A half frame of tail after the last full one.
        for _ in 0..3 {
            step(&mut plan, &mut sinks, &[(0, 7)]);
        }
        sinks[0].write_pcm(&[7; FRAME / 2]);
        let mut out = Vec::new();
        for _ in 0..6 {
            out.extend(step(&mut plan, &mut sinks, &[]));
        }
        let loud: Vec<usize> = out
            .iter()
            .map(|frame| frame.iter().filter(|&&sample| sample == 7).count())
            .collect();
        assert!(
            loud.contains(&(FRAME / 2)),
            "the half frame goes out once, padded: {loud:?}"
        );
        assert!(out
            .last()
            .is_some_and(|frame| frame.iter().all(|&s| s == 0)));
    }

    #[test]
    fn a_sink_converts_into_the_mixer_rate() {
        let mut plan = plan_multi_source(format(16_000, 1), 2).expect("plan");
        let resampler = Resampler::new(8_000, 16_000).expect("resampler");
        let mut upsampled = plan
            .control
            .sink(0, Some(resampler), "rec-1")
            .expect("sink");
        for _ in 0..4 {
            upsampled.write_pcm(&[1000; FRAME]);
            assert!(plan.mixer.tick());
        }
        let frames = drained(&plan);
        assert!(!frames.is_empty());
        assert!(
            frames.iter().all(|frame| frame.len() == 320),
            "16 kHz x 20 ms"
        );
    }

    #[test]
    fn a_sink_names_its_tag_and_an_unknown_source_has_no_sink() {
        let plan = plan_multi_source(format(8000, 1), 2).expect("plan");
        let sink = plan.control.sink(1, None, "rec-7").expect("sink");
        assert_eq!(sink.tag(), Some("rec-7"));
        assert!(plan.control.sink(2, None, "rec-7").is_none());
        assert_eq!(plan.tracks, ["source-0", "source-1"]);
    }

    #[test]
    fn a_replacement_sink_keeps_the_source_open() {
        let mut plan = plan_multi_source(format(8000, 1), 2).expect("plan");
        let first = plan.control.sink(0, None, "rec-1").expect("sink");
        let mut second = plan.control.sink(0, None, "rec-1").expect("sink");
        drop(first);
        for _ in 0..4 {
            second.write_pcm(&[9; FRAME]);
            assert!(plan.mixer.tick(), "the source never closed");
        }
        assert!(!drained(&plan).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_running_mixer_paces_frames_on_its_own_clock_and_ends_with_its_handle() {
        let MultiSourcePlan {
            mixer,
            control,
            frames,
            recycle,
            stats,
            ..
        } = plan_multi_source(format(8000, 2), 2).expect("plan");
        let mut near = control.sink(0, None, "rec-1").expect("sink");
        let mut far = control.sink(1, None, "rec-1").expect("sink");
        let task = tokio::spawn(mixer.run());
        let mut count = 0u64;
        for _ in 0..20 {
            near.write_pcm(&[1000; FRAME]);
            far.write_pcm(&[-1000; FRAME]);
            tokio::time::sleep(Duration::from_millis(20)).await;
            while let Ok(frame) = frames.try_recv() {
                count += 1;
                let _ = recycle.send(frame);
            }
        }
        let started = tokio::time::Instant::now();
        drop(control);
        task.await.expect("the mixer ends");
        assert!(
            started.elapsed() <= Duration::from_millis(20),
            "ending does not wait for a tick"
        );
        while let Ok(frame) = frames.try_recv() {
            count += 1;
            let _ = recycle.send(frame);
        }
        assert!((15..=20).contains(&count), "{count} frames for 400 ms");
        assert_eq!(stats.forwarded(), count);
        assert_eq!(stats.dropped(), 0);
    }
}
